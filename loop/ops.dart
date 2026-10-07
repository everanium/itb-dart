// The maintenance operations that mutate a live Pipeline handle
// between iterations: master rotation (--rekey-every) and blob reopen
// (--blob-cycle-every).

import 'dart:typed_data';

import 'package:libitb3/itb.dart';

import 'payload.dart';
import 'state.dart';

/// Byte length of each fresh master drawn for a rotation. Matches the
/// size Init auto-generates for both the parallax and the wrapper
/// master.
const int _rekeyMasterSize = 32;

final Uint8List _noMaster = Uint8List(0);

/// Master rotation. Rotates the parallax + wrapper masters on every
/// active Pipeline this worker owns and retains the refreshed blob for
/// subsequent blob reopens. Masters are drawn fresh from the OS CSPRNG
/// on every rotation regardless of --seed (master rotation is pipeline
/// keying, not plaintext content); a disabled layer passes no bytes,
/// which Rekey ignores. The eight inner seeds and the MAC key are
/// untouched by design — Rekey targets only the two outer-layer master
/// secrets.
bool _rekeyPipes(WorkerState w, int iter) {
  var perm = _noMaster;
  var wrap = _noMaster;
  if (w.cfg.parallax) {
    perm = Uint8List(_rekeyMasterSize);
    fillRandom(perm);
  }
  if (w.cfg.wrapper) {
    wrap = Uint8List(_rekeyMasterSize);
    fillRandom(wrap);
  }

  final stream = w.streamPipe;
  if (stream != null) {
    try {
      w.streamBlob = stream.rekey(perm, wrap);
    } catch (e) {
      workerFail(w,
          'g${w.id} iter $iter: Rekey(${w.streamProfile}): ${statusDetail(e)}');
      return false;
    }
  }
  final msg = w.msgPipe;
  if (msg != null) {
    try {
      w.msgBlob = msg.rekey(perm, wrap);
    } catch (e) {
      workerFail(
          w, 'g${w.id} iter $iter: Rekey(${w.msgProfile}): ${statusDetail(e)}');
      return false;
    }
  }
  w.port.send(MaintenanceMsg(true, w.id, iter));
  return true;
}

/// Blob reopen. Reopens every active Pipeline this worker owns from
/// its retained blob: a fresh handle is loaded from the blob, the
/// running handle is freed, and the fresh one is swapped in, so every
/// later iteration round-trips through seeds and masters that survived
/// a blob crossing. The input is the blob Init or the latest Rekey
/// handed out, not a fresh Save: that is what a receiver holds, and
/// reopening from it proves the handed-out bytes rather than the live
/// state. The blob carries the Pipeline's full shape, so no override
/// reaches the reopen. On a Load failure the running handle stays and
/// the failure aborts the run.
bool _blobCyclePipes(WorkerState w, int iter) {
  if (w.streamPipe != null) {
    Pipeline fresh;
    try {
      fresh = Itb.load(w.streamBlob);
    } catch (e) {
      workerFail(w,
          'g${w.id} iter $iter: Load(${w.streamProfile}): ${statusDetail(e)}');
      return false;
    }
    w.streamPipe!.free();
    w.streamPipe = fresh;
  }
  if (w.msgPipe != null) {
    Pipeline fresh;
    try {
      fresh = Itb.load(w.msgBlob);
    } catch (e) {
      workerFail(
          w, 'g${w.id} iter $iter: Load(${w.msgProfile}): ${statusDetail(e)}');
      return false;
    }
    w.msgPipe!.free();
    w.msgPipe = fresh;
  }
  w.port.send(MaintenanceMsg(false, w.id, iter));
  return true;
}

/// Handle mutation. Runs the periodic Pipeline-mutating operations
/// after a completed iteration: master rotation (--rekey-every) and
/// blob reopen (--blob-cycle-every). Both intervals count per-worker
/// iterations; the warmup iteration (iter 0) never triggers because
/// the worker loop calls this for iter >= 1 only. Rekey rewrites the
/// outer-layer keying of a live handle and a blob reopen replaces the
/// handle outright. A shared-handle binding guards both with a write
/// lock so in-flight cipher calls on other workers drain before
/// anything changes; this binding runs independent-handles, so the
/// handles either operation touches belong to the one isolate that is
/// between its own iterations, no other isolate can have a call in
/// flight on them, and no encrypt can be separated from its decrypt by
/// either. The two counts the log lines carry are still run-wide, so
/// the launcher owns them and prints the line. Returns false after
/// recording a worker error.
bool workerMaintenance(WorkerState w, int iter) {
  final cfg = w.cfg;
  if (cfg.rekeyEvery > 0 && iter % cfg.rekeyEvery == 0) {
    if (!_rekeyPipes(w, iter)) return false;
  }
  if (cfg.blobCycleEvery > 0 && iter % cfg.blobCycleEvery == 0) {
    if (!_blobCyclePipes(w, iter)) return false;
  }
  return true;
}
