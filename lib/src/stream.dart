// Incremental stream sessions over an open Pipeline.
//
// A session is a dumb byte pump: [StreamEncryptor] takes plaintext in
// through `write` and yields wire through `read` / `drainAll`;
// [StreamDecryptor] is the mirror (wire in, plaintext out). All
// chunking, MAC, envelope, and wire-format decisions stay inside
// libitb3. The session keeps a reference to its parent Pipeline so the
// Pipeline handle cannot be finalized while a session is live.

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'errors.dart';
import 'ffi_bridge.dart';
import 'pipeline.dart';

/// Drain slice size used by [StreamSession.drainAll] and the pump
/// helpers.
const int _pumpBuf = 4 << 20;

final Finalizer<int> _finalizer = Finalizer<int>((handle) {
  if (handle != 0) {
    FfiBridge.instance.streamFree(handle);
  }
});

/// Result of one [StreamSession.read] drain.
typedef ReadResult = ({int n, bool finished});

/// Shared body of [StreamEncryptor] / [StreamDecryptor].
abstract class StreamSession {
  StreamSession._(this._parent, {required bool encrypt}) {
    final begin = encrypt
        ? FfiBridge.instance.encryptStreamBegin
        : FfiBridge.instance.decryptStreamBegin;
    final out = malloc<UintPtr>();
    try {
      out.value = 0;
      check(begin(_parent.handle, out));
      _handle = out.value;
    } finally {
      malloc.free(out);
    }
    _finalizer.attach(this, _handle, detach: this);
    scratchFinalizer.attach(this, _scratch, detach: this);
  }

  // Keeps the parent Pipeline reachable for the session's lifetime,
  // so the Pipeline finalizer cannot free the Go-side handle while
  // the session still dispatches against it.
  final Pipeline _parent;
  int _handle = 0;
  bool _ended = false;

  /// Grow-only pooled native buffers reused by every write / read /
  /// pump call on this session (single-isolate ownership serializes
  /// access).
  final NativeScratch _scratch = NativeScratch();

  /// Feeds [src] into the session. Blocks until the cipher chain
  /// accepts the bytes; errors are sticky. Runs on the session's
  /// pooled input buffer — no per-call native allocation.
  void write(Uint8List src) {
    Pointer<Uint8> srcP = nullptr;
    if (src.isNotEmpty) {
      srcP = _scratch.ensureIn(src.length);
      srcP.asTypedList(src.length).setAll(0, src);
    }
    check(FfiBridge.instance.streamWrite(_handle, srcP, src.length));
  }

  /// [write] against a caller-managed native buffer already holding
  /// [n] bytes (the pump fast path — no per-call allocation).
  void _writeNative(Pointer<Uint8> src, int n) {
    check(FfiBridge.instance.streamWrite(_handle, n > 0 ? src : nullptr, n));
  }

  /// [read] against a caller-managed native buffer (the pump fast
  /// path — no per-call allocation, no intermediate copy).
  ReadResult _readNative(
      Pointer<Uint8> buf, int cap, Pointer<Size> outLen, Pointer<Int32> fin) {
    outLen.value = 0;
    fin.value = 0;
    check(FfiBridge.instance.streamRead(_handle, buf, cap, outLen, fin));
    return (n: outLen.value, finished: fin.value != 0);
  }

  /// Signals end-of-input. Idempotent; [write] after [end] fails with
  /// [Status.badInput].
  void end() {
    check(FfiBridge.instance.streamEnd(_handle));
    _ended = true;
  }

  /// Drains up to [cap] produced bytes into [dst] (default
  /// `dst.length`); returns `(n: bytesWritten, finished:
  /// terminalDrainDone)`. Partial drains are normal. After [end], an
  /// empty-spool read blocks until the terminal bytes arrive or the
  /// session errors. Runs on the session's pooled output buffer —
  /// no per-call native allocation; [dst] is reusable across calls,
  /// and bytes past the returned count are unspecified. An
  /// [ArgumentError] is thrown when [cap] is negative or exceeds
  /// `dst.length`.
  ReadResult read(Uint8List dst, [int? cap]) {
    final ceiling = cap ?? dst.length;
    if (ceiling < 0 || ceiling > dst.length) {
      throw ArgumentError('cap $ceiling out of range for buffer length ${dst.length}');
    }
    final buf = _scratch.ensureOut(ceiling);
    final r = _readNative(buf, ceiling, _scratch.len, _scratch.fin);
    if (r.n > 0) {
      dst.setRange(0, r.n, buf.asTypedList(r.n));
    }
    return r;
  }

  /// Calls [end] (if not yet called) and returns every remaining
  /// output byte as one buffer.
  Uint8List drainAll() {
    if (!_ended) {
      end();
    }
    final parts = BytesBuilder(copy: true);
    final buf = _scratch.ensureOut(_pumpBuf);
    final outLen = _scratch.len;
    final fin = _scratch.fin;
    for (;;) {
      final r = _readNative(buf, _pumpBuf, outLen, fin);
      if (r.n > 0) {
        parts.add(Uint8List.fromList(buf.asTypedList(r.n)));
      }
      if (r.finished) {
        return parts.takeBytes();
      }
    }
  }

  /// Pumps [chunks] through the session into [sink] with bounded
  /// memory: feed a chunk, drain whatever the chain has produced so
  /// far (a read before [end] never blocks), repeat; end + final
  /// drain after the last chunk. The session's pooled native buffer
  /// pair is reused across the whole pump, so the per-chunk cost is
  /// a single copy each way.
  void pump(Iterable<Uint8List> chunks, void Function(Uint8List) sink) {
    final outBuf = _scratch.ensureOut(_pumpBuf);
    final outLen = _scratch.len;
    final fin = _scratch.fin;
    for (final chunk in chunks) {
      Pointer<Uint8> inBuf = nullptr;
      if (chunk.isNotEmpty) {
        inBuf = _scratch.ensureIn(chunk.length);
        inBuf.asTypedList(chunk.length).setAll(0, chunk);
      }
      _writeNative(inBuf, chunk.length);
      for (;;) {
        final r = _readNative(outBuf, _pumpBuf, outLen, fin);
        if (r.n == 0) break;
        sink(Uint8List.fromList(outBuf.asTypedList(r.n)));
      }
    }
    end();
    for (;;) {
      final r = _readNative(outBuf, _pumpBuf, outLen, fin);
      if (r.n > 0) {
        sink(Uint8List.fromList(outBuf.asTypedList(r.n)));
      }
      if (r.finished) return;
    }
  }

  /// Cancels (if still running) and releases the session. Safe to
  /// call from any state; safe to call more than once.
  void free() {
    if (_handle == 0) return;
    _finalizer.detach(this);
    scratchFinalizer.detach(this);
    _scratch.release();
    FfiBridge.instance.streamFree(_handle);
    _handle = 0;
  }
}

/// Incremental encrypt session: plaintext in, wire out.
class StreamEncryptor extends StreamSession {
  StreamEncryptor._(super.parent) : super._(encrypt: true);

  /// Internal constructor used by `Pipeline.encryptStream`.
  static StreamEncryptor begin(Pipeline parent) => StreamEncryptor._(parent);
}

/// Incremental decrypt session: wire in, plaintext out.
class StreamDecryptor extends StreamSession {
  StreamDecryptor._(super.parent) : super._(encrypt: false);

  /// Internal constructor used by `Pipeline.decryptStream`.
  static StreamDecryptor begin(Pipeline parent) => StreamDecryptor._(parent);
}
