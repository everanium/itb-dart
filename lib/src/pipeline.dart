// Handle-lifetime wrapper around the Triple Pipeline.

import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'errors.dart';
import 'ffi_bridge.dart';
import 'opts.dart';
import 'profile.dart';
import 'stream.dart';

export 'opts.dart';
export 'profile.dart' show Profile;

/// Floor capacity for blob output buffers (create / save / rekey).
const int _blobCap = 64 * 1024;

/// Floor capacity for profile-JSON output buffers (inspect / lookup /
/// profiles).
const int _jsonCap = 4 * 1024;

/// Pre-allocation formula for Message / one-shot stream outputs:
/// 1.25x the payload plus a 64 KiB envelope allowance.
int _outCap(int payload) => payload + (payload >> 2) + 65536;

/// Single retry-once dispatch site for every variable-size output
/// buffer: pre-allocate [cap], and on `bufferTooSmall` retry once
/// with the exact size the FFI reported through the length
/// out-param. Returns a right-sized copy so the caller does not pin
/// the pre-allocation slack.
Uint8List _retryOnce(
    int cap, int Function(Pointer<Uint8> out, int outCap, Pointer<Size>) call) {
  var buf = malloc<Uint8>(cap);
  final outLen = malloc<Size>();
  try {
    outLen.value = 0;
    var rc = call(buf, cap, outLen);
    if (rc == Status.bufferTooSmall && outLen.value > cap) {
      malloc.free(buf);
      cap = outLen.value;
      buf = malloc<Uint8>(cap);
      outLen.value = 0;
      rc = call(buf, cap, outLen);
    }
    check(rc);
    return Uint8List.fromList(buf.asTypedList(outLen.value));
  } finally {
    malloc.free(buf);
    malloc.free(outLen);
  }
}

final Finalizer<int> _finalizer = Finalizer<int>((handle) {
  if (handle != 0) {
    FfiBridge.instance.tripleFree(handle);
  }
});

/// A Triple Pipeline session.
///
/// [save] exports the self-describing session blob the receiver
/// feeds to [Pipeline.load] / [Pipeline.loadF]; [rekey] refreshes
/// it. Release the handle deterministically via [free]; a
/// [Finalizer] backstop frees on GC (libitb3 zeroes key material
/// internally).
///
/// Streaming-decrypt caveat: chunked Streaming AEAD verifies per
/// chunk, so plaintext of verified chunks is released before a later
/// chunk can fail authentication.
class Pipeline {
  Pipeline._(this._handle) {
    _finalizer.attach(this, _handle, detach: this);
    scratchFinalizer.attach(this, _scratch, detach: this);
  }

  int _handle;

  /// Grow-only pooled native buffers reused by every cipher call on
  /// this Pipeline (single-isolate ownership serializes access).
  final NativeScratch _scratch = NativeScratch();

  /// Internal handle accessor for the stream sessions.
  int get handle => _handle;

  /// Constructs a fresh Pipeline against the named profile. On a
  /// blob-buffer retry the create re-runs and yields a fresh session
  /// (the undersized attempt is closed by libitb3 before returning).
  /// The session blob is available through [save].
  factory Pipeline.create(String profile, [Opts? opts]) {
    final bridge = FfiBridge.instance;
    final profileP = profile.toNativeUtf8(allocator: malloc);
    final optsP = (opts ?? Opts()).build().toNativeUtf8(allocator: malloc);
    final handleP = malloc<UintPtr>();
    try {
      handleP.value = 0;
      _retryOnce(
          _blobCap,
          (buf, cap, len) =>
              bridge.tripleInit(profileP, optsP, buf, cap, len, handleP));
      return Pipeline._(handleP.value);
    } finally {
      malloc.free(profileP);
      malloc.free(optsP);
      malloc.free(handleP);
    }
  }

  /// Reconstructs a Pipeline from a blob produced by [save] or
  /// [rekey]. The blob's embedded profile record is the sole
  /// structural source. [permMaster] / [wrapMaster] are null to use
  /// the blob-embedded masters, or both non-empty to override them.
  factory Pipeline.load(Uint8List blob,
      {Uint8List? permMaster, Uint8List? wrapMaster}) {
    final overriding = _checkMasters(permMaster, wrapMaster);
    final bridge = FfiBridge.instance;
    final blobP = copyIn(blob);
    final permP = overriding ? copyIn(permMaster!) : nullptr;
    final wrapP = overriding ? copyIn(wrapMaster!) : nullptr;
    final handleP = malloc<UintPtr>();
    try {
      handleP.value = 0;
      check(bridge.tripleLoad(
        blobP,
        blob.length,
        permP,
        overriding ? permMaster!.length : 0,
        wrapP,
        overriding ? wrapMaster!.length : 0,
        overriding ? 2 : 0,
        handleP,
      ));
      return Pipeline._(handleP.value);
    } finally {
      freeIn(blobP);
      freeIn(permP);
      freeIn(wrapP);
      malloc.free(handleP);
    }
  }

  /// [Pipeline.load] for a blob stored in a file; the file is read
  /// inside the library. Same masters semantics.
  factory Pipeline.loadF(String path,
      {Uint8List? permMaster, Uint8List? wrapMaster}) {
    final overriding = _checkMasters(permMaster, wrapMaster);
    final bridge = FfiBridge.instance;
    final pathP = path.toNativeUtf8(allocator: malloc);
    final permP = overriding ? copyIn(permMaster!) : nullptr;
    final wrapP = overriding ? copyIn(wrapMaster!) : nullptr;
    final handleP = malloc<UintPtr>();
    try {
      handleP.value = 0;
      check(bridge.tripleLoadF(
        pathP,
        permP,
        overriding ? permMaster!.length : 0,
        wrapP,
        overriding ? wrapMaster!.length : 0,
        overriding ? 2 : 0,
        handleP,
      ));
      return Pipeline._(handleP.value);
    } finally {
      malloc.free(pathP);
      freeIn(permP);
      freeIn(wrapP);
      malloc.free(handleP);
    }
  }

  /// Folds the optional master pair into the CAPI arity flag.
  static bool _checkMasters(Uint8List? permMaster, Uint8List? wrapMaster) {
    final overriding = permMaster != null || wrapMaster != null;
    if (overriding &&
        (permMaster == null ||
            wrapMaster == null ||
            permMaster.isEmpty ||
            wrapMaster.isEmpty)) {
      throw ItbException(Status.badInput, 'master overrides must be non-empty');
    }
    return overriding;
  }

  /// The current self-describing session blob: the bytes
  /// [Pipeline.create] produced, the bytes [Pipeline.load]
  /// re-marshalled, or the bytes of the latest [rekey].
  Uint8List save() => _retryOnce(
      _blobCap,
      (buf, cap, len) =>
          FfiBridge.instance.tripleSave(_handle, buf, cap, len));

  /// Writes [save] to [path] inside the library with mode 0600; the
  /// containing directory must exist.
  void saveF(String path) {
    final pathP = path.toNativeUtf8(allocator: malloc);
    try {
      check(FfiBridge.instance.tripleSaveF(_handle, pathP));
    } finally {
      malloc.free(pathP);
    }
  }

  /// Sets the worker cap for every subsequent cipher call. [n] is
  /// clamped, never rejected: `n <= 0` selects auto (CPU count),
  /// `n > 256` is treated as 256. Only the handle statuses throw.
  void maxWorkers(int n) {
    check(FfiBridge.instance.tripleMaxWorkers(_handle, n));
  }

  /// Rotates the parallax + wrapper masters and returns the fresh
  /// session blob (also available through [save]). Must not run
  /// concurrently with cipher calls or open stream sessions on the
  /// same Pipeline.
  Uint8List rekey(Uint8List permMaster, Uint8List wrapMaster) {
    final bridge = FfiBridge.instance;
    final permP = copyIn(permMaster);
    final wrapP = copyIn(wrapMaster);
    try {
      return _retryOnce(
          _blobCap,
          (buf, cap, len) => bridge.tripleRekey(_handle, permP,
              permMaster.length, wrapP, wrapMaster.length, buf, cap, len));
    } finally {
      freeIn(permP);
      freeIn(wrapP);
    }
  }

  /// Zeroes the Pipeline's key material and marks it closed.
  /// Idempotent; subsequent cipher calls fail with
  /// [Status.tripleClosed].
  void close() {
    check(FfiBridge.instance.tripleClose(_handle));
  }

  /// Single Message encrypt: one call, one self-contained wire.
  Uint8List encryptMessage(Uint8List plain) =>
      _cipher(FfiBridge.instance.tripleEncryptMessage, plain);

  /// Receive-side counterpart of [encryptMessage].
  Uint8List decryptMessage(Uint8List wire) =>
      _cipher(FfiBridge.instance.tripleDecryptMessage, wire);

  /// Allocation-free sibling of [encryptMessage]: writes the wire
  /// into the caller-supplied [dst] (reusable across calls) and
  /// returns the wire byte count. [cap] is the write ceiling libitb3
  /// honours (default `dst.length`); an [ArgumentError] is thrown
  /// when it exceeds `dst.length`. Throws [ItbException] with
  /// [Status.bufferTooSmall] when [cap] is insufficient — there is
  /// no retry, the caller owns capacity policy. The pre-allocation
  /// formula `payload * 5 / 4 + 65536` typically suffices for large
  /// payloads, but small payloads may still expand past it; on
  /// [Status.bufferTooSmall] re-issue with a larger [dst] or fall
  /// back to [encryptMessage] (whose retry path absorbs the
  /// expansion). Bytes past the returned count are unspecified.
  int encryptMessageInto(Uint8List plain, Uint8List dst, [int? cap]) =>
      _cipherInto(FfiBridge.instance.tripleEncryptMessage, plain, dst,
          cap ?? dst.length);

  /// Receive-side counterpart of [encryptMessageInto]: fills [dst]
  /// with plaintext and returns the byte count.
  int decryptMessageInto(Uint8List wire, Uint8List dst, [int? cap]) =>
      _cipherInto(FfiBridge.instance.tripleDecryptMessage, wire, dst,
          cap ?? dst.length);

  /// One-shot stream encrypt for callers holding the whole plaintext
  /// in memory. For bounded-memory streaming use [encryptStream].
  Uint8List encryptStreamOneShot(Uint8List plain) =>
      _cipher(FfiBridge.instance.tripleEncryptStream, plain);

  /// Receive-side counterpart of [encryptStreamOneShot].
  Uint8List decryptStreamOneShot(Uint8List wire) =>
      _cipher(FfiBridge.instance.tripleDecryptStream, wire);

  /// Opens an incremental encrypt session (plaintext in, wire out).
  StreamEncryptor encryptStream() => StreamEncryptor.begin(this);

  /// Opens an incremental decrypt session (wire in, plaintext out).
  StreamDecryptor decryptStream() => StreamDecryptor.begin(this);

  /// Releases the handle (libitb3 closes the Pipeline first, zeroing
  /// key material). Safe to call more than once.
  void free() {
    if (_handle == 0) return;
    _finalizer.detach(this);
    scratchFinalizer.detach(this);
    _scratch.release();
    FfiBridge.instance.tripleFree(_handle);
    _handle = 0;
  }

  /// Copies [src] into the pooled input-side native buffer; returns
  /// [nullptr] for an empty input (libitb3 accepts a null pointer
  /// with a zero length).
  Pointer<Uint8> _stageSrc(Uint8List src) {
    if (src.isEmpty) return nullptr;
    final p = _scratch.ensureIn(src.length);
    p.asTypedList(src.length).setAll(0, src);
    return p;
  }

  /// Shared body for the four buffer-in / buffer-out cipher entries.
  /// Both sides run on the Pipeline's pooled native buffers
  /// (grow-only, retry-once on `bufferTooSmall`); only the returned
  /// right-sized copy is a fresh allocation.
  Uint8List _cipher(
      int Function(int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Size>)
          f,
      Uint8List src) {
    final srcP = _stageSrc(src);
    var cap = _outCap(src.length);
    var buf = _scratch.ensureOut(cap);
    final outLen = _scratch.len;
    outLen.value = 0;
    var rc = f(_handle, srcP, src.length, buf, cap, outLen);
    if (rc == Status.bufferTooSmall && outLen.value > cap) {
      cap = outLen.value;
      buf = _scratch.ensureOut(cap);
      outLen.value = 0;
      rc = f(_handle, srcP, src.length, buf, cap, outLen);
    }
    check(rc);
    return Uint8List.fromList(buf.asTypedList(outLen.value));
  }

  /// Shared body for the caller-buffer Message entries: one FFI call
  /// through the pooled native buffers, no retry (the caller owns
  /// capacity policy), byte count out. [cap] is the write ceiling
  /// libitb3 honours, so it must never exceed the real length of
  /// [dst].
  int _cipherInto(
      int Function(int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Size>)
          f,
      Uint8List src,
      Uint8List dst,
      int cap) {
    if (cap < 0 || cap > dst.length) {
      throw ArgumentError('cap $cap out of range for buffer length ${dst.length}');
    }
    final srcP = _stageSrc(src);
    final buf = _scratch.ensureOut(cap);
    final outLen = _scratch.len;
    outLen.value = 0;
    check(f(_handle, srcP, src.length, buf, cap, outLen));
    final n = outLen.value;
    if (n > 0) {
      dst.setRange(0, n, buf.asTypedList(n));
    }
    return n;
  }
}

/// Decodes the blob's embedded profile record without opening a
/// Pipeline. No registry read, no primitive probe.
Profile inspect(Uint8List blob) {
  final blobP = copyIn(blob);
  try {
    final json = _retryOnce(
        _jsonCap,
        (buf, cap, len) => FfiBridge.instance
            .tripleInspect(blobP, blob.length, buf, cap, len));
    return Profile.fromJson(utf8.decode(json));
  } finally {
    freeIn(blobP);
  }
}

/// Registers [profile] under [name] so subsequent [Pipeline.create] /
/// [lookup] calls resolve it. Every field rule is validated by Go; a
/// duplicate name fails with [Status.profileExists].
void register(String name, Profile profile) {
  final nameP = name.toNativeUtf8(allocator: malloc);
  final jsonP = profile.toJson().toNativeUtf8(allocator: malloc);
  try {
    check(FfiBridge.instance.tripleRegister(nameP, jsonP));
  } finally {
    malloc.free(nameP);
    malloc.free(jsonP);
  }
}

/// Looks up a registered profile (shipped or [register]ed) by name;
/// an unknown name fails with [Status.unknownProfile].
Profile lookup(String name) {
  final nameP = name.toNativeUtf8(allocator: malloc);
  try {
    final json = _retryOnce(
        _jsonCap,
        (buf, cap, len) =>
            FfiBridge.instance.tripleLookup(nameP, buf, cap, len));
    return Profile.fromJson(utf8.decode(json));
  } finally {
    malloc.free(nameP);
  }
}

/// The sorted names of every registered profile.
List<String> profiles() {
  final json = _retryOnce(_jsonCap,
      (buf, cap, len) => FfiBridge.instance.tripleProfiles(buf, cap, len));
  return stringsFromJson(utf8.decode(json));
}
