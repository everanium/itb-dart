// The worker: its isolate body (its own handles opened from the Init
// blob, one warmup iteration, the warmup gate, the main loop), one
// iteration, the session pump loop the stream shape drives, and the
// round-trip comparison that decides between a worker error and a
// data mismatch.

import 'dart:typed_data';

import 'package:libitb3/itb.dart';

import 'ops.dart';
import 'payload.dart';
import 'size.dart';
import 'state.dart';

/// Pump loop. The Go harness hands ITB an io.Reader / io.Writer pair
/// and ITB drives the chunk loop internally; the C ABI has no reader /
/// writer entry, so the caller drives it: open a session, feed slices
/// of at most 1 MiB, drain whatever the session has produced after
/// every write (a read before end never blocks), end, then drain until
/// the session reports finished (after end, a read on an empty spool
/// blocks until the terminal bytes arrive). The loop is written here
/// rather than delegated to the binding's pump convenience so it
/// stands in the utility, at the same place, in every language.
Uint8List _pump(Pipeline pipe, bool encrypt, Uint8List src, Uint8List slice) {
  final session = encrypt ? pipe.encryptStream() : pipe.decryptStream();
  try {
    final parts = BytesBuilder(copy: true);
    var off = 0;
    while (off < src.length) {
      final end = off + pumpSlice < src.length ? off + pumpSlice : src.length;
      session.write(Uint8List.sublistView(src, off, end));
      off = end;
      for (;;) {
        final r = session.read(slice);
        if (r.n == 0) break;
        parts.add(Uint8List.sublistView(slice, 0, r.n));
      }
    }
    session.end();
    for (;;) {
      final r = session.read(slice);
      if (r.n > 0) parts.add(Uint8List.sublistView(slice, 0, r.n));
      if (r.finished) break;
    }
    return parts.takeBytes();
  } finally {
    session.free();
  }
}

/// First offset at which a and b differ; the shorter length when one
/// is a prefix of the other.
int _firstDifference(Uint8List a, Uint8List b) {
  final n = a.length < b.length ? a.length : b.length;
  for (var i = 0; i < n; i++) {
    if (a[i] != b[i]) return i;
  }
  return n;
}

/// Up to 16 bytes of buf from off as lowercase hex, or "-" when buf
/// has no bytes there.
String _hexWindow(Uint8List buf, int off) {
  if (off >= buf.length) return '-';
  final end = off + 16 < buf.length ? off + 16 : buf.length;
  final out = StringBuffer();
  for (var i = off; i < end; i++) {
    out.write(buf[i].toRadixString(16).padLeft(2, '0'));
  }
  return out.toString();
}

/// Records a worker error for a failed cipher call.
void _cipherFail(
    WorkerState w, int iter, int shape, String direction, Object e) {
  workerFail(
      w,
      'g${w.id} iter $iter shape=${shapeName(shape)}: '
      '$direction: ${statusDetail(e)}');
}

/// One iteration. In order: refill the plaintext under rotating mode;
/// pick the surface; encrypt (timed); decrypt (timed); compare the
/// round-trip with the plaintext; bump the counters. A shared-handle
/// binding runs the whole round-trip under a read lock so that
/// handle-mutating maintenance never lands between an encrypt and its
/// matching decrypt; this binding runs independent-handles, so the
/// handles belong to this isolate alone and the same guarantee holds
/// without a lock — maintenance runs after this returns, from the
/// worker loop, on handles no other isolate can reach. Returns false
/// after recording the worker error.
bool _iterate(WorkerState w, int iter, Uint8List slice) {
  final cfg = w.cfg;

  if (w.payloadMode == payloadRotating) {
    try {
      w.rng = fillPayload(w.plaintext, payloadRotating, w.seeded, w.rng);
    } catch (e) {
      workerFail(w, 'g${w.id} iter $iter: payload refill: csprng');
      return false;
    }
  }

  // Shape dispatch. message is one whole-buffer call on the Single
  // Message Pipeline; stream_one_shot is one whole-buffer call on the
  // streaming Pipeline (the C ABI's ITB_Triple_EncryptStream, which
  // routes to the same one-shot stream entry the Go harness calls
  // by name); stream opens a session on the same streaming Pipeline
  // and drives the chunk loop from here. Under both the three rotate
  // by iteration number so the session path and the whole-buffer path
  // alternate on one handle inside every worker — the cross-path
  // state-reuse hazard this harness exists to catch.
  var shape = cfg.shape;
  if (shape == shapeBoth) {
    switch (iter % 3) {
      case 0:
        shape = shapeStream;
      case 1:
        shape = shapeMessage;
      default:
        shape = shapeStreamOneShot;
    }
  }

  Uint8List got;
  var t0 = nowNs();
  switch (shape) {
    case shapeStream:
      Uint8List wire;
      try {
        wire = _pump(w.streamPipe!, true, w.plaintext, slice);
      } catch (e) {
        _cipherFail(w, iter, shape, 'encrypt', e);
        return false;
      }
      w.nanosEnc += nowNs() - t0;
      t0 = nowNs();
      try {
        got = _pump(w.streamPipe!, false, wire, slice);
      } catch (e) {
        _cipherFail(w, iter, shape, 'decrypt', e);
        return false;
      }
      w.nanosDec += nowNs() - t0;
    case shapeStreamOneShot:
      Uint8List wire;
      try {
        wire = w.streamPipe!.encryptStreamOneShot(w.plaintext);
      } catch (e) {
        _cipherFail(w, iter, shape, 'encrypt', e);
        return false;
      }
      w.nanosEnc += nowNs() - t0;
      t0 = nowNs();
      try {
        got = w.streamPipe!.decryptStreamOneShot(wire);
      } catch (e) {
        _cipherFail(w, iter, shape, 'decrypt', e);
        return false;
      }
      w.nanosDec += nowNs() - t0;
    default:
      Uint8List wire;
      try {
        wire = w.msgPipe!.encryptMessage(w.plaintext);
      } catch (e) {
        _cipherFail(w, iter, shape, 'encrypt', e);
        return false;
      }
      w.nanosEnc += nowNs() - t0;
      t0 = nowNs();
      try {
        got = w.msgPipe!.decryptMessage(wire);
      } catch (e) {
        _cipherFail(w, iter, shape, 'decrypt', e);
        return false;
      }
      w.nanosDec += nowNs() - t0;
  }

  // Failure model. A cipher call that returns a non-OK status is a
  // worker error: it is recorded, the run is asked to stop, the other
  // workers finish their in-flight iteration, and the error is listed
  // in the summary with the FAIL verdict. A round-trip that returns OK
  // with different bytes is a data mismatch: the process terminates
  // here, without summary or cleanup, because the Pipeline state that
  // produced the wrong bytes is the evidence and nothing that runs
  // afterwards may touch it.
  if (got.length != w.plaintext.length ||
      _firstDifference(w.plaintext, got) != w.plaintext.length) {
    final off = _firstDifference(w.plaintext, got);
    errRaw('loop: DATA MISMATCH g${w.id} iter $iter '
        'shape=${shapeName(shape)}: want ${w.plaintext.length} bytes, '
        'got ${got.length} bytes, first difference at offset $off: '
        'want ${_hexWindow(w.plaintext, off)} got ${_hexWindow(got, off)}\n');
    hardExit(3);
  }

  w.iters++;
  w.bytesEnc += w.plaintext.length;
  w.bytesDec += got.length;
  return true;
}

/// Opens this worker's own handles from the blobs the launcher sent.
bool _openHandles(WorkerState w, WorkerJob job) {
  final streamBlob = job.streamBlob;
  if (streamBlob != null) {
    try {
      w.streamPipe = Itb.load(streamBlob);
    } catch (e) {
      workerFail(
          w, 'g${w.id} iter 0: Load(${w.streamProfile}): ${statusDetail(e)}');
      return false;
    }
    w.streamBlob = streamBlob;
  }
  final msgBlob = job.msgBlob;
  if (msgBlob != null) {
    try {
      w.msgPipe = Itb.load(msgBlob);
    } catch (e) {
      workerFail(
          w, 'g${w.id} iter 0: Load(${w.msgProfile}): ${statusDetail(e)}');
      return false;
    }
    w.msgBlob = msgBlob;
  }
  return true;
}

/// The worker isolate body: its own handles, one warmup iteration, the
/// warmup gate, then the main loop until a stop is requested or the
/// fixed per-worker iteration budget (warmup included) is spent. A
/// failing warmup still reports at the gate so the launcher never
/// waits on a worker that has already given up.
///
/// Concurrency mode. This binding runs independent-handles: an isolate
/// shares no memory with another, and the binding's `Pipeline` owns
/// its handle through a `Finalizer` and owns a native buffer pool
/// whose only serialisation is single ownership, so a handle cannot be
/// adopted by a second wrapper without two finalizers racing to free
/// it and two isolates writing one pool. The public surface offers no
/// adopting entry either. So each worker loads its own handle from the
/// Init blob the launcher sent, and --goroutines is the isolate count
/// verbatim, never clamped.
void workerEntry(WorkerJob job) {
  final shared = Shared(job.sharedAddr);
  final cfg = job.cfg;
  final w = WorkerState(job.id, cfg, shared, job.port);
  w.streamProfile = job.streamProfile;
  w.msgProfile = job.msgProfile;
  w.payloadMode = cfg.payloadMode;
  w.seeded = cfg.seed != 0;
  w.rng = seedWorker(cfg.seed, job.id);

  var ok = _openHandles(w, job);
  // Allocation posture. The plaintext is allocated once per worker and
  // held for the whole run (rotating mode refills it in place); the
  // pump drains through one reused slice allocated here beside it; the
  // wire and round-trip buffers are the ones the binding returns per
  // call, and the runtime reclaims them when the iteration drops them.
  // Under the default fixed CSPRNG mode every worker's buffer is
  // distinct, so cross-worker data crossover is detectable; pattern
  // modes trade that property for content edge-case coverage.
  var slice = Uint8List(0);
  if (ok) {
    try {
      w.plaintext = Uint8List(cfg.payload);
      slice = Uint8List(pumpSlice);
      w.rng = fillPayload(w.plaintext, cfg.payloadMode, w.seeded, w.rng);
    } catch (e) {
      workerFail(w, 'g${w.id} iter 0: payload alloc: $e');
      ok = false;
    }
  }

  // Warmup iteration — counted in the totals; its completion feeds the
  // post-warmup baselines. Anything that escapes an iteration other
  // than a library status becomes a worker error rather than a lost
  // isolate: the launcher waits for one warmup report per worker, so a
  // worker that unwound past it would leave the launcher waiting for a
  // rendezvous that can no longer happen.
  if (ok) {
    try {
      ok = _iterate(w, 0, slice);
    } catch (e) {
      workerFail(w, 'g${w.id} iter 0: $e');
      ok = false;
    }
  }
  job.port.send(WarmupMsg(w.id));
  shared.waitForGate();

  if (ok) {
    var iter = 1;
    for (;;) {
      if (cfg.iterations > 0 && iter >= cfg.iterations) break;
      if (shared.stopRequested()) break;
      try {
        if (!_iterate(w, iter, slice)) break;
        if (!workerMaintenance(w, iter)) break;
      } catch (e) {
        workerFail(w, 'g${w.id} iter $iter: $e');
        break;
      }
      iter++;
    }
  }

  final report = WorkerReport(
    id: w.id,
    iters: w.iters,
    bytesEnc: w.bytesEnc,
    bytesDec: w.bytesDec,
    nanosEnc: w.nanosEnc,
    nanosDec: w.nanosDec,
    finishNs: nowNs(),
    failed: w.failed,
    error: w.error,
  );
  w.streamPipe?.free();
  w.msgPipe?.free();
  job.port.send(report);
}
