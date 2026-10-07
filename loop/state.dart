// Shared declarations of the loop stress harness: the cipher-surface
// selectors, the concurrency mode this binding runs, the resolved
// configuration, the cross-isolate cell the workers and the launcher
// share, and the output helpers every unit writes through.
//
// Dart-specific. Isolates share no mutable object graph, so what the
// C reference keeps in one struct splits in two here: everything a
// worker only reads travels as a copied message, and the two cells a
// worker must observe while it is inside a synchronous call live in
// native memory addressed by an integer. A declarations unit holding
// what both sides need is the same answer the C reference reaches
// with its header.

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:libitb3/itb.dart';

/* Cipher surfaces the --shape flag selects. */
const int shapeStream = 0; // session pump: begin / write / read / end
const int shapeMessage = 1; // Single Message: one whole-buffer call
const int shapeStreamOneShot = 2; // stream surface, one whole-buffer call
const int shapeBoth = 3; // all three, rotating by iteration number

const List<String> shapeNames = [
  'stream',
  'message',
  'stream_one_shot',
  'both',
];

String shapeName(int shape) => shapeNames[shape];

int? parseShape(String s) {
  final i = shapeNames.indexOf(s);
  return i < 0 ? null : i;
}

/// `--goroutines` ceiling; the harness targets modest hosts and each
/// worker pins payload-sized buffers for the whole run.
const int maxWorkers = 10;

/// Concurrency mode. This binding runs independent-handles: an isolate
/// shares no memory with another, and the binding's `Pipeline` owns
/// its handle through a `Finalizer` and owns a pool of native buffers
/// whose only serialisation is that one isolate owns it, so two
/// wrappers around one handle would mean two finalizers racing to free
/// it and two isolates writing one buffer pool. The public surface
/// offers no entry that adopts an existing handle either — `create`,
/// `load` and `loadF` are the only paths to one. So every worker opens
/// its own handle from the Init blob and maintains it alone.
const String concurrency = 'independent-handles';

/// Largest slice fed to a stream session per write; the drain after
/// every write uses the same bound.
const int pumpSlice = 1 << 20;

/// The resolved command line, as it crosses to every worker isolate.
class Config {
  /// Run duration in nanoseconds; ignored when [iterations] > 0.
  int durationNs = 0;

  /// Per-worker count incl. warmup; 0 = duration-based.
  int iterations = 0;

  /// The `--goroutines` value as given.
  int workersRequested = 0;

  /// The effective worker count.
  int workers = 0;
  int shape = shapeStream;
  String hash = '';
  String mac = '';

  /// Plaintext bytes per iteration.
  int payload = 0;

  /// Resolved bytes; the effective limit once shaped.
  int memlimit = 0;

  /// `--memlimit auto`: cap only when the runtime has none.
  bool memlimitAuto = false;

  /// 0 = leave the runtime default.
  int gogc = 0;
  bool parallax = true;
  bool wrapper = true;

  /// Empty = shape-based profile pair.
  String profile = '';

  /// 0 = profile default.
  int keyBits = 0;

  /// 0 = profile default.
  int nonceBits = 0;

  /// Container floor sizing mode: 1 (per-region, default) | 2
  /// (per-container).
  int blobMode = 1;

  /// 0 = profile default.
  int chunkSize = 0;

  /// 0 = profile default.
  int barrierFill = 0;

  /// DRBG fill primitive; "" = profile default (auto tier).
  String drbg = '';

  /// 0 = inherit from the environment.
  int gomaxprocs = 0;

  /// Per-worker iterations between rotations; 0 = never.
  int rekeyEvery = 0;

  /// Per-worker iterations between reopens; 0 = never.
  int blobCycleEvery = 0;
  int payloadMode = 0;

  /// 0 = OS CSPRNG plaintexts. Held as the raw 64 bits; the rendering
  /// helpers reinterpret it as unsigned.
  int seed = 0;
  bool jsonOutput = false;

  /// Empty = none.
  String memprofile = '';
}

/* Slots of the native cell the launcher and the workers address. */
const int _slotStop = 0;
const int _slotRelease = 1;
const int _sharedSlots = 2;

/// The two cells several isolates touch: the stop request and the
/// warmup gate.
///
/// Dart-specific. A worker sitting inside a synchronous foreign call
/// cannot service its message port, so a stop request delivered by
/// message would not arrive until the call had returned and the loop
/// was about to ask for it anyway. A plain aligned 32-bit slot in
/// native memory is what a worker can read between iterations without
/// yielding, and native memory is the one address space every isolate
/// of the group already shares. Each isolate builds its own pointer
/// from the address it was handed; only the address travels.
class Shared {
  Shared(this.addr) : _cells = Pointer<Int32>.fromAddress(addr);

  /// The address the launcher hands every worker.
  final int addr;
  final Pointer<Int32> _cells;

  static Shared create() => Shared(calloc<Int32>(_sharedSlots).address);

  void release() {
    calloc.free(_cells);
  }

  bool stopRequested() => _cells[_slotStop] != 0;

  void requestStop() {
    _cells[_slotStop] = 1;
  }

  /// Opens the gate every worker waits at after its warmup iteration.
  void openGate() {
    _cells[_slotRelease] = 1;
  }

  /// Dart-specific. `sleep` is the one blocking wait an isolate can
  /// perform without an event loop turn, which is what is needed here:
  /// the worker is about to spend the whole run inside synchronous
  /// calls and must not depend on its port being serviced.
  void waitForGate() {
    while (_cells[_slotRelease] == 0) {
      sleep(const Duration(milliseconds: 1));
    }
  }
}

/// What a worker isolate is handed when it starts.
class WorkerJob {
  WorkerJob({
    required this.id,
    required this.cfg,
    required this.sharedAddr,
    required this.streamProfile,
    required this.msgProfile,
    required this.streamBlob,
    required this.msgBlob,
    required this.port,
  });

  final int id;
  final Config cfg;
  final int sharedAddr;
  final String streamProfile;
  final String msgProfile;
  final Uint8List? streamBlob;
  final Uint8List? msgBlob;
  final SendPort port;
}

/// One worker's closing report.
class WorkerReport {
  WorkerReport({
    required this.id,
    required this.iters,
    required this.bytesEnc,
    required this.bytesDec,
    required this.nanosEnc,
    required this.nanosDec,
    required this.finishNs,
    required this.failed,
    required this.error,
  });

  final int id;
  final int iters;
  final int bytesEnc;
  final int bytesDec;
  final int nanosEnc;
  final int nanosDec;
  final int finishNs;
  final bool failed;
  final String error;
}

/// A worker reached its warmup barrier.
class WarmupMsg {
  const WarmupMsg(this.worker);

  final int worker;
}

/// A worker completed a maintenance operation. The launcher owns the
/// run-wide counts and prints the line, so two workers rotating at
/// once cannot be handed the same number.
class MaintenanceMsg {
  const MaintenanceMsg(this.rekey, this.worker, this.iter);

  /// True for a master rotation, false for a blob reopen.
  final bool rekey;
  final int worker;
  final int iter;
}

// ─── libc ──────────────────────────────────────────────────────────

typedef SignalC = Pointer<Void> Function(Int32 sig, Pointer<Void> handler);
typedef SignalDart = Pointer<Void> Function(int sig, Pointer<Void> handler);
typedef WriteC = IntPtr Function(Int32 fd, Pointer<Uint8> buf, IntPtr n);
typedef WriteDart = int Function(int fd, Pointer<Uint8> buf, int n);
typedef ExitC = Void Function(Int32 code);
typedef ExitDart = void Function(int code);
typedef ErrnoC = Pointer<Int32> Function();
typedef ClockGettimeC = Int32 Function(Int32 clk, Pointer<Int64> ts);
typedef ClockGettimeDart = int Function(int clk, Pointer<Int64> ts);

const int _sigpipe = 13;

/// CLOCK_MONOTONIC, the clock `size.dart` reads for every timing.
const int clockMonotonic = 1;
const int _eintr = 4;
const int _eagain = 11;
const int _epipe = 32;

/// Dart-specific. Three host-platform facilities the runtime does not
/// expose and the ITB binding has no business carrying: the signal
/// disposition the output contract requires, a write that happens on
/// the calling isolate's own thread rather than through the buffered
/// sink, an immediate process exit that skips every teardown, and the
/// monotonic clock, which `Stopwatch` measures only per instance and
/// therefore cannot compare across isolates. They are reached through
/// the process's own symbol table by the same `dart:ffi` mechanism the
/// binding uses for the library.
class Libc {
  Libc._(DynamicLibrary lib)
      : signal = lib.lookupFunction<SignalC, SignalDart>('signal'),
        write = lib.lookupFunction<WriteC, WriteDart>('write'),
        exitNow = lib.lookupFunction<ExitC, ExitDart>('_exit'),
        errnoLocation = lib.lookupFunction<ErrnoC, ErrnoC>('__errno_location'),
        clockGettime = lib
            .lookupFunction<ClockGettimeC, ClockGettimeDart>('clock_gettime');

  static final Libc instance = Libc._(DynamicLibrary.process());

  final SignalDart signal;
  final WriteDart write;
  final ExitDart exitNow;
  final ErrnoC errnoLocation;
  final ClockGettimeDart clockGettime;
}

/// Leaves the process on the spot with the given code, without
/// unwinding and without flushing anything.
///
/// Dart-specific. `exit` from a spawned isolate runs the runtime's
/// teardown and the mismatch path must touch nothing; the libc entry
/// that ends a process without any of it is reached through the same
/// FFI mechanism the binding itself uses.
Never hardExit(int code) {
  Libc.instance.exitNow(code);
  // Unreachable; _exit does not return.
  throw StateError('_exit returned');
}

/// A consumer that stops reading ends the run. The default disposition
/// for SIGPIPE is restored so the process dies from the signal with
/// status 141 and prints nothing — the reference behaviour, and what
/// anyone piping into head or less expects. The runtime installs
/// SIG_IGN before any user code runs and the failed write surfaces as
/// an error return instead, so restoring the default is an explicit
/// step here rather than something inherited; the runtime exposes no
/// signal-disposition API for this signal, so libc's own entry is
/// called. Returns whether the disposition was installed, so the fix
/// can be stated rather than inferred from a count of clean runs.
bool restoreSigpipe() {
  try {
    Libc.instance.signal(_sigpipe, Pointer<Void>.fromAddress(0));
    return true;
  } on ArgumentError {
    return false;
  }
}

Pointer<Uint8>? _outBuf;
int _outCap = 0;

/// Writes the whole string to a descriptor, in as few write calls as
/// the descriptor allows, and leaves with 141 when the consumer has
/// gone.
///
/// Dart-specific. The runtime's standard sinks buffer and flush on
/// their own schedule, which neither keeps a line and its newline in
/// one write nor lets the failing write happen on the thread that is
/// about to die of it. A descriptor the runtime left in non-blocking
/// mode returns EAGAIN rather than blocking, so the write is retried;
/// and where the default SIGPIPE disposition could not be restored the
/// EPIPE return is all that is left of the signal, so it becomes the
/// status the signal would have produced, having printed nothing.
void writeAll(int fd, String text) {
  final bytes = utf8.encode(text);
  if (bytes.length > _outCap) {
    if (_outBuf != null) malloc.free(_outBuf!);
    _outBuf = malloc<Uint8>(bytes.length);
    _outCap = bytes.length;
  }
  final buf = _outBuf!;
  buf.asTypedList(bytes.length).setAll(0, bytes);
  var off = 0;
  while (off < bytes.length) {
    final r = Libc.instance.write(fd, buf + off, bytes.length - off);
    if (r > 0) {
      off += r;
      continue;
    }
    final err = Libc.instance.errnoLocation().value;
    if (err == _eintr || err == _eagain) continue;
    hardExit(err == _epipe ? 141 : 1);
  }
}

/// Prints one prefixed status line to stdout.
///
/// The line is assembled with its newline and handed to one write
/// call, so a line logged from another isolate cannot land between a
/// text and the newline that terminates it.
void logLine(String text) => writeAll(1, '[loop] $text\n');

/// Prints one prefixed diagnostic to stderr.
void errLine(String text) => writeAll(2, 'loop: $text\n');

/// Prints an already-composed block to stderr.
void errRaw(String text) => writeAll(2, text);

/// Prints an already-composed line to stdout.
void outRaw(String text) => writeAll(1, text);

String onOff(bool b) => b ? 'on' : 'off';

/// Renders an encoder policy env value for the summary: the raw string
/// when set, "default" when the shipped ladder applies.
String policyLabel(String? env) {
  if (env == null) return 'default';
  final trimmed = env.replaceFirst(RegExp(r'^[ \t]+'), '');
  return trimmed.isEmpty ? 'default' : trimmed;
}

/// The sentence a failing call left behind. Nothing is composed here:
/// the library hands over the class of failure and, where there is
/// one, the instance, and that text is printed as it arrived.
String errorSentence(Object e) =>
    e is ItbException ? e.lastError : e.toString();

/// The failure detail a log line carries: the numeric status the
/// binding's own surface exposes and the finished sentence the library
/// left behind.
String statusDetail(Object e) => e is ItbException
    ? 'status ${e.statusCode}: ${e.lastError}'
    : e.toString();

/// One worker's private state: the handles it owns, the blobs it
/// retains, its plaintext, its generator, its counters, and the error
/// it stopped on. Under independent-handles every field below belongs
/// to one isolate alone; only [shared] is seen by another.
class WorkerState {
  WorkerState(this.id, this.cfg, this.shared, this.port);

  final int id;
  final Config cfg;
  final Shared shared;
  final SendPort port;

  Pipeline? streamPipe;
  Pipeline? msgPipe;
  String streamProfile = '';
  String msgProfile = '';

  /// The blob Init handed out, replaced by every rekey; the input of
  /// the next blob reopen.
  Uint8List streamBlob = Uint8List(0);
  Uint8List msgBlob = Uint8List(0);

  Uint8List plaintext = Uint8List(0);
  int payloadMode = 0;
  bool seeded = false;

  /// splitmix64 state when seeded.
  int rng = 0;

  /* Counters the closing report carries back to the launcher. */
  int iters = 0;
  int bytesEnc = 0;
  int bytesDec = 0;
  int nanosEnc = 0;
  int nanosDec = 0;

  bool failed = false;
  String error = '';
}

/// Records the worker's error text (first error wins) and requests a
/// stop of the whole run.
void workerFail(WorkerState w, String text) {
  if (!w.failed) {
    w.error = text;
    w.failed = true;
  }
  w.shared.requestStop();
}
