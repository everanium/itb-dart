// Runtime binding to the libitb3 shared library (dart:ffi).
//
// Every `ITB_*` symbol used by the package is looked up once, lazily,
// from a process-wide [DynamicLibrary]. The library file is resolved
// in this order:
//
//   1. `ITB_LIBITB3_PATH` environment variable (path to the shared
//      library file).
//   2. `<repo>/dist/<os>-<arch>/libitb3.<ext>` found by walking up
//      from the current working directory (in-repo builds).
//   3. The OS default loader path (`LD_LIBRARY_PATH`, `ld.so.cache`,
//      `DYLD_LIBRARY_PATH`, `PATH`).

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

// ---------------------------------------------------------------------------
// Library resolution
// ---------------------------------------------------------------------------

String _libFileName() {
  if (Platform.isMacOS) return 'libitb3.dylib';
  if (Platform.isWindows) return 'libitb3.dll';
  return 'libitb3.so';
}

String _distDirName() {
  final os = Platform.isMacOS
      ? 'darwin'
      : Platform.isWindows
          ? 'windows'
          : 'linux';
  final abi = Abi.current().toString(); // e.g. "linux_x64"
  final arch = abi.endsWith('_arm64')
      ? 'arm64'
      : abi.endsWith('_x64')
          ? 'amd64'
          : abi.split('_').last;
  return '$os-$arch';
}

DynamicLibrary _openLibrary() {
  final env = Platform.environment['ITB_LIBITB3_PATH'];
  if (env != null && env.isNotEmpty) {
    return DynamicLibrary.open(env);
  }
  // Walk up from the working directory looking for the in-repo dist
  // artifact (tests / benches / eitb all run from bindings/dart).
  var dir = Directory.current;
  for (var depth = 0; depth < 8; depth++) {
    final candidate = File(
      '${dir.path}${Platform.pathSeparator}dist'
      '${Platform.pathSeparator}${_distDirName()}'
      '${Platform.pathSeparator}${_libFileName()}',
    );
    if (candidate.existsSync()) {
      return DynamicLibrary.open(candidate.path);
    }
    final parent = dir.parent;
    if (parent.path == dir.path) break;
    dir = parent;
  }
  return DynamicLibrary.open(_libFileName());
}

// ---------------------------------------------------------------------------
// Native signatures
// ---------------------------------------------------------------------------

typedef _VersionC = Int32 Function(
    Pointer<Uint8> out, Size capBytes, Pointer<Size> outLen);
typedef VersionDart = int Function(
    Pointer<Uint8> out, int capBytes, Pointer<Size> outLen);

typedef _SetMemoryLimitC = Int64 Function(Int64 limit);
typedef SetMemoryLimitDart = int Function(int limit);

typedef _SetGCPercentC = Int32 Function(Int32 pct);
typedef SetGCPercentDart = int Function(int pct);

typedef _TripleInitC = Int32 Function(
    Pointer<Utf8> profile,
    Pointer<Utf8> opts,
    Pointer<Uint8> blobOut,
    Size blobCap,
    Pointer<Size> blobLen,
    Pointer<UintPtr> outHandle);
typedef TripleInitDart = int Function(
    Pointer<Utf8> profile,
    Pointer<Utf8> opts,
    Pointer<Uint8> blobOut,
    int blobCap,
    Pointer<Size> blobLen,
    Pointer<UintPtr> outHandle);

typedef _TripleLoadC = Int32 Function(
    Pointer<Uint8> blob,
    Size blobLen,
    Pointer<Uint8> permMaster,
    Size permMasterLen,
    Pointer<Uint8> wrapMaster,
    Size wrapMasterLen,
    Size mastersCount,
    Pointer<UintPtr> outHandle);
typedef TripleLoadDart = int Function(
    Pointer<Uint8> blob,
    int blobLen,
    Pointer<Uint8> permMaster,
    int permMasterLen,
    Pointer<Uint8> wrapMaster,
    int wrapMasterLen,
    int mastersCount,
    Pointer<UintPtr> outHandle);

typedef _TripleLoadFC = Int32 Function(
    Pointer<Utf8> path,
    Pointer<Uint8> permMaster,
    Size permMasterLen,
    Pointer<Uint8> wrapMaster,
    Size wrapMasterLen,
    Size mastersCount,
    Pointer<UintPtr> outHandle);
typedef TripleLoadFDart = int Function(
    Pointer<Utf8> path,
    Pointer<Uint8> permMaster,
    int permMasterLen,
    Pointer<Uint8> wrapMaster,
    int wrapMasterLen,
    int mastersCount,
    Pointer<UintPtr> outHandle);

typedef _TripleSaveC = Int32 Function(
    UintPtr handle, Pointer<Uint8> blobOut, Size blobCap, Pointer<Size> blobLen);
typedef TripleSaveDart = int Function(
    int handle, Pointer<Uint8> blobOut, int blobCap, Pointer<Size> blobLen);

typedef _TripleSaveFC = Int32 Function(UintPtr handle, Pointer<Utf8> path);
typedef TripleSaveFDart = int Function(int handle, Pointer<Utf8> path);

typedef _TripleInspectC = Int32 Function(Pointer<Uint8> blob, Size blobLen,
    Pointer<Uint8> jsonOut, Size jsonCap, Pointer<Size> jsonLen);
typedef TripleInspectDart = int Function(Pointer<Uint8> blob, int blobLen,
    Pointer<Uint8> jsonOut, int jsonCap, Pointer<Size> jsonLen);

typedef _TripleMaxWorkersC = Int32 Function(UintPtr handle, Int32 n);
typedef TripleMaxWorkersDart = int Function(int handle, int n);

typedef _TripleLookupC = Int32 Function(Pointer<Utf8> name,
    Pointer<Uint8> jsonOut, Size jsonCap, Pointer<Size> jsonLen);
typedef TripleLookupDart = int Function(Pointer<Utf8> name,
    Pointer<Uint8> jsonOut, int jsonCap, Pointer<Size> jsonLen);

typedef _TripleProfilesC = Int32 Function(
    Pointer<Uint8> jsonOut, Size jsonCap, Pointer<Size> jsonLen);
typedef TripleProfilesDart = int Function(
    Pointer<Uint8> jsonOut, int jsonCap, Pointer<Size> jsonLen);

typedef _TripleRekeyC = Int32 Function(
    UintPtr handle,
    Pointer<Uint8> permMaster,
    Size permMasterLen,
    Pointer<Uint8> wrapMaster,
    Size wrapMasterLen,
    Pointer<Uint8> blobOut,
    Size blobCap,
    Pointer<Size> blobLen);
typedef TripleRekeyDart = int Function(
    int handle,
    Pointer<Uint8> permMaster,
    int permMasterLen,
    Pointer<Uint8> wrapMaster,
    int wrapMasterLen,
    Pointer<Uint8> blobOut,
    int blobCap,
    Pointer<Size> blobLen);

typedef _HandleOnlyC = Int32 Function(UintPtr handle);
typedef HandleOnlyDart = int Function(int handle);

typedef _CipherC = Int32 Function(UintPtr handle, Pointer<Uint8> src,
    Size srcLen, Pointer<Uint8> out, Size outCap, Pointer<Size> outLen);
typedef CipherDart = int Function(int handle, Pointer<Uint8> src, int srcLen,
    Pointer<Uint8> out, int outCap, Pointer<Size> outLen);

typedef _RegisterC = Int32 Function(
    Pointer<Utf8> name, Pointer<Utf8> profileJson);
typedef RegisterDart = int Function(
    Pointer<Utf8> name, Pointer<Utf8> profileJson);

typedef _StreamBeginC = Int32 Function(UintPtr pipe, Pointer<UintPtr> out);
typedef StreamBeginDart = int Function(int pipe, Pointer<UintPtr> out);

typedef _StreamWriteC = Int32 Function(
    UintPtr stream, Pointer<Uint8> src, Size srcLen);
typedef StreamWriteDart = int Function(
    int stream, Pointer<Uint8> src, int srcLen);

typedef _StreamReadC = Int32 Function(UintPtr stream, Pointer<Uint8> out,
    Size outCap, Pointer<Size> outLen, Pointer<Int32> finished);
typedef StreamReadDart = int Function(int stream, Pointer<Uint8> out,
    int outCap, Pointer<Size> outLen, Pointer<Int32> finished);

// ---------------------------------------------------------------------------
// Bridge singleton
// ---------------------------------------------------------------------------

/// Lazily-initialized bindings to every libitb3 symbol the package
/// dispatches. Internal to the package.
class FfiBridge {
  FfiBridge._(DynamicLibrary lib)
      : version = lib.lookupFunction<_VersionC, VersionDart>('ITB_Version'),
        lastError = lib.lookupFunction<_VersionC, VersionDart>('ITB_LastError'),
        setMemoryLimit =
            lib.lookupFunction<_SetMemoryLimitC, SetMemoryLimitDart>(
                'ITB_SetMemoryLimit'),
        setGCPercent = lib.lookupFunction<_SetGCPercentC, SetGCPercentDart>(
            'ITB_SetGCPercent'),
        tripleInit =
            lib.lookupFunction<_TripleInitC, TripleInitDart>('ITB_Triple_Init'),
        tripleLoad =
            lib.lookupFunction<_TripleLoadC, TripleLoadDart>('ITB_Triple_Load'),
        tripleLoadF = lib
            .lookupFunction<_TripleLoadFC, TripleLoadFDart>('ITB_Triple_LoadF'),
        tripleSave =
            lib.lookupFunction<_TripleSaveC, TripleSaveDart>('ITB_Triple_Save'),
        tripleSaveF = lib
            .lookupFunction<_TripleSaveFC, TripleSaveFDart>('ITB_Triple_SaveF'),
        tripleInspect = lib.lookupFunction<_TripleInspectC, TripleInspectDart>(
            'ITB_Triple_Inspect'),
        tripleMaxWorkers =
            lib.lookupFunction<_TripleMaxWorkersC, TripleMaxWorkersDart>(
                'ITB_Triple_MaxWorkers'),
        tripleRekey = lib
            .lookupFunction<_TripleRekeyC, TripleRekeyDart>('ITB_Triple_Rekey'),
        tripleClose = lib
            .lookupFunction<_HandleOnlyC, HandleOnlyDart>('ITB_Triple_Close'),
        tripleFree =
            lib.lookupFunction<_HandleOnlyC, HandleOnlyDart>('ITB_Triple_Free'),
        tripleEncryptMessage = lib
            .lookupFunction<_CipherC, CipherDart>('ITB_Triple_EncryptMessage'),
        tripleDecryptMessage = lib
            .lookupFunction<_CipherC, CipherDart>('ITB_Triple_DecryptMessage'),
        tripleEncryptStream = lib
            .lookupFunction<_CipherC, CipherDart>('ITB_Triple_EncryptStream'),
        tripleDecryptStream = lib
            .lookupFunction<_CipherC, CipherDart>('ITB_Triple_DecryptStream'),
        tripleRegister =
            lib.lookupFunction<_RegisterC, RegisterDart>('ITB_Triple_Register'),
        tripleLookup = lib
            .lookupFunction<_TripleLookupC, TripleLookupDart>('ITB_Triple_Lookup'),
        tripleProfiles = lib.lookupFunction<_TripleProfilesC, TripleProfilesDart>(
            'ITB_Triple_Profiles'),
        encryptStreamBegin = lib.lookupFunction<_StreamBeginC, StreamBeginDart>(
            'ITB_Triple_EncryptStreamBegin'),
        decryptStreamBegin = lib.lookupFunction<_StreamBeginC, StreamBeginDart>(
            'ITB_Triple_DecryptStreamBegin'),
        streamWrite = lib.lookupFunction<_StreamWriteC, StreamWriteDart>(
            'ITB_Triple_StreamWrite'),
        streamEnd = lib.lookupFunction<_HandleOnlyC, HandleOnlyDart>(
            'ITB_Triple_StreamEnd'),
        streamRead = lib.lookupFunction<_StreamReadC, StreamReadDart>(
            'ITB_Triple_StreamRead'),
        streamFree = lib.lookupFunction<_HandleOnlyC, HandleOnlyDart>(
            'ITB_Triple_StreamFree');

  static final FfiBridge instance = FfiBridge._(_openLibrary());

  final VersionDart version;
  final VersionDart lastError;
  final SetMemoryLimitDart setMemoryLimit;
  final SetGCPercentDart setGCPercent;
  final TripleInitDart tripleInit;
  final TripleLoadDart tripleLoad;
  final TripleLoadFDart tripleLoadF;
  final TripleSaveDart tripleSave;
  final TripleSaveFDart tripleSaveF;
  final TripleInspectDart tripleInspect;
  final TripleMaxWorkersDart tripleMaxWorkers;
  final TripleRekeyDart tripleRekey;
  final HandleOnlyDart tripleClose;
  final HandleOnlyDart tripleFree;
  final CipherDart tripleEncryptMessage;
  final CipherDart tripleDecryptMessage;
  final CipherDart tripleEncryptStream;
  final CipherDart tripleDecryptStream;
  final RegisterDart tripleRegister;
  final TripleLookupDart tripleLookup;
  final TripleProfilesDart tripleProfiles;
  final StreamBeginDart encryptStreamBegin;
  final StreamBeginDart decryptStreamBegin;
  final StreamWriteDart streamWrite;
  final HandleOnlyDart streamEnd;
  final StreamReadDart streamRead;
  final HandleOnlyDart streamFree;
}

// ---------------------------------------------------------------------------
// Native-buffer helpers shared by pipeline / stream / version code
// ---------------------------------------------------------------------------

/// Copies [data] into a fresh malloc'd native buffer. Returns
/// [nullptr] for an empty input (libitb3 accepts a null pointer with a
/// zero length). The caller frees a non-null result.
Pointer<Uint8> copyIn(Uint8List data) {
  if (data.isEmpty) return nullptr;
  final p = malloc<Uint8>(data.length);
  p.asTypedList(data.length).setAll(0, data);
  return p;
}

/// Frees a [copyIn] result, tolerating the empty-input [nullptr].
void freeIn(Pointer<Uint8> p) {
  if (p != nullptr) malloc.free(p);
}

/// Grow-only pooled native scratch owned by one dispatch object
/// (a [Pipeline] or a stream session): two data buffers plus the
/// small out-params every cipher / drain call needs. Buffers are
/// reused across calls, so steady-state dispatch performs no native
/// allocation and rewrites already-faulted pages instead of touching
/// fresh mmap'd ones. Not shareable across isolates; the owner
/// serializes access (one isolate, one owner).
class NativeScratch {
  Pointer<Uint8> _a = nullptr;
  int _aCap = 0;
  Pointer<Uint8> _b = nullptr;
  int _bCap = 0;
  Pointer<Size> _len = nullptr;
  Pointer<Int32> _fin = nullptr;

  /// Input-side buffer with at least [cap] bytes (grow-only; contents
  /// unspecified after growth). [nullptr] for a zero cap.
  Pointer<Uint8> ensureIn(int cap) {
    if (cap > _aCap) {
      if (_a != nullptr) malloc.free(_a);
      _a = malloc<Uint8>(cap);
      _aCap = cap;
    }
    return _a;
  }

  /// Output-side buffer with at least [cap] bytes (grow-only).
  Pointer<Uint8> ensureOut(int cap) {
    if (cap > _bCap) {
      if (_b != nullptr) malloc.free(_b);
      _b = malloc<Uint8>(cap);
      _bCap = cap;
    }
    return _b;
  }

  /// Pooled `size_t` out-param.
  Pointer<Size> get len {
    if (_len == nullptr) _len = malloc<Size>();
    return _len;
  }

  /// Pooled `int32` out-param (stream `finished` flag).
  Pointer<Int32> get fin {
    if (_fin == nullptr) _fin = malloc<Int32>();
    return _fin;
  }

  /// Frees every pooled allocation. Idempotent; the pools re-grow on
  /// the next ensure / getter if the owner keeps dispatching.
  void release() {
    if (_a != nullptr) {
      malloc.free(_a);
      _a = nullptr;
      _aCap = 0;
    }
    if (_b != nullptr) {
      malloc.free(_b);
      _b = nullptr;
      _bCap = 0;
    }
    if (_len != nullptr) {
      malloc.free(_len);
      _len = nullptr;
    }
    if (_fin != nullptr) {
      malloc.free(_fin);
      _fin = nullptr;
    }
  }
}

/// GC backstop for [NativeScratch] pools whose owner was never
/// explicitly freed. Owners detach on deterministic free.
final Finalizer<NativeScratch> scratchFinalizer =
    Finalizer<NativeScratch>((s) => s.release());

/// Reads a NUL-terminated string out of a length-reporting libitb3
/// call (`ITB_Version` / `ITB_LastError` shape): first a capacity
/// query with a null buffer, then the actual read. Returns the empty
/// string when nothing is recorded or the read fails.
String readCString(VersionDart f) {
  final need = malloc<Size>();
  try {
    need.value = 0;
    final rc1 = f(nullptr, 0, need);
    final cap = need.value;
    // 0 = ok, 5 = buffer too small (expected on the capacity query).
    if ((rc1 != 0 && rc1 != 5) || cap <= 1) return '';
    final buf = malloc<Uint8>(cap);
    try {
      need.value = 0;
      if (f(buf, cap, need) != 0) return '';
      final written = need.value;
      final n = written > 0 ? written - 1 : 0; // strip trailing NUL
      return utf8.decode(buf.asTypedList(n), allowMalformed: true);
    } finally {
      malloc.free(buf);
    }
  } finally {
    malloc.free(need);
  }
}
