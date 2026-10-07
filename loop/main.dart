// Long-run stress harness. The loop utility holds one Pipeline handle
// per exercised cipher surface for minutes, hammers it with encrypt →
// decrypt → compare round-trips from N worker isolates, rotates the
// outer masters and reopens the handle from its session blob on a
// schedule, and reports whether the process survived with every byte
// intact. It is the Dart binding's counterpart of the Go harness under
// tools/loop: the same flags, the same round structure, the same
// summary in both renderings.
//
// The default shape is full production: the Streaming AEAD profile
// with parallax on, wrapper on, hmac-blake3 MAC, Areion-SoEM-512 inner
// hash, 1024-bit keys and the profile's 512-bit nonce width, driven
// through a stream session by three workers for five minutes on 16 MiB
// plaintexts. Every worker owns a distinct CSPRNG-generated plaintext
// held for the whole run, so any cross-call state leakage inside the
// Pipeline surfaces as a data mismatch between workers rather than
// cancelling out.
//
// A failure is one of two things. A cipher, rekey or load call that
// returns a non-OK status is a worker error: the run stops, the summary
// lists it, the verdict is FAIL and the exit code 1. A round-trip that
// returns without error but with different bytes is a data mismatch:
// the process terminates on the spot with exit code 3, printing the
// worker, the iteration and the first differing offset, and no summary
// — the state that produced the wrong bytes is the evidence. A crash
// inside the shared library or the host runtime has no exit code of its
// own here; surfacing it is what the utility is for.
//
// Usage:
//
//   ./run_loop.sh --duration 5m --goroutines 3 --shape stream \
//                 --hash areion512 --mac hmac-blake3 \
//                 --payload-size 16MB --memlimit auto \
//                 --parallax on --wrapper on
//
// Ctrl-C triggers a graceful shutdown: in-flight iterations complete,
// then the partial summary prints.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:libitb3/itb.dart';

import 'payload.dart';
import 'size.dart';
import 'state.dart';
import 'summary.dart';
import 'worker.dart';

/* Profiles the shape-based pair is built against when --profile is
 * empty. */
const String _defaultStreamProfile = 'streaming-aead-triple-mac-v1';
const String _defaultMessageProfile = 'singlemsg-triple-mac-v1';

/// The primitive supplied for the parallax palette and the outer
/// cipher when a profile leaves them unnamed. AES-CMAC is PRF-grade,
/// so it is sound outside the Interlocked Barrier, and it is the
/// closest relative of the AES-based inner primitive whose profiles
/// need this fill.
const String _keystreamFillCipher = 'aescmac';

// ─── Flags ─────────────────────────────────────────────────────────

enum _Kind { int32, int64, uint64, string, boolean }

/// One command-line flag: its name, the type label the usage prints,
/// the kind that decides how its value parses, and its help text.
/// Values are validated after the whole line is parsed.
class _Flag {
  const _Flag(this.name, this.typeLabel, this.kind, this.help);

  final String name;
  final String typeLabel;
  final _Kind kind;
  final String help;
}

/// The flag table, in alphabetical order (the order the usage prints).
const List<_Flag> _flags = [
  _Flag('barrier-fill', 'int', _Kind.int32,
      'DRBG barrier fill margin: 1 | 2 | 4 | 8 | 16 | 32; 0 = profile default (1)'),
  _Flag('blob-cycle-every', 'int', _Kind.int64,
      'reopen each pipeline from its session blob every N iterations per worker; 0 = never'),
  _Flag('blob-mode', 'int', _Kind.int32,
      'container floor sizing mode: 1 (per-region, default) | 2 (per-container)'),
  _Flag('chunk-size', 'string', _Kind.string,
      'streaming chunk-size budget (e.g. 4MB); 0 = profile default; inert for pure message shape'),
  _Flag('drbg', 'string', _Kind.string,
      'DRBG fill primitive name (see itb3 drbgs); empty = profile default (auto tier)'),
  _Flag('duration', 'duration', _Kind.string,
      'run duration (Go format: 30s / 5m / 1h); ignored when --iterations > 0'),
  _Flag('gogc', 'int', _Kind.int32,
      'GC trigger percentage; 0 = leave the runtime default'),
  _Flag('gomaxprocs', 'int', _Kind.int32,
      'Go runtime GOMAXPROCS override; 0 = inherit from the environment'),
  _Flag('goroutines', 'int', _Kind.int32,
      'concurrent workers (1..10); on runtimes without parallelism values above 1 are clamped to 1'),
  _Flag('hash', 'string', _Kind.string, 'inner ITB hash primitive name'),
  _Flag('iterations', 'int', _Kind.int64,
      'fixed per-worker iteration count; 0 = duration-based'),
  _Flag('json-output', '', _Kind.boolean,
      'print the final summary as one compact JSON object instead of log lines'),
  _Flag('key-bits', 'int', _Kind.int32,
      'per-seed key width in bits: 512 | 1024 | 2048; 0 = profile default (1024)'),
  _Flag('mac', 'string', _Kind.string, 'MAC primitive name'),
  _Flag('memlimit', 'string', _Kind.string,
      'Go heap soft limit: auto (1GiB when goroutines <= 3, else 256MiB, applied only when the runtime has no limit) or a size (e.g. 512MB)'),
  _Flag('memprofile', 'string', _Kind.string,
      'write a Go runtime heap profile (pprof) to this path at the end of the run; empty = none'),
  _Flag('nonce-bits', 'int', _Kind.int32,
      'on-wire nonce width in bits: 128 | 256 | 512; 0 = profile default (512)'),
  _Flag('parallax', 'string', _Kind.string, 'parallax layer: on | off'),
  _Flag('payload-mode', 'string', _Kind.string,
      'plaintext content: fixed | rotating | pattern-zero | pattern-ff | pattern-ascii'),
  _Flag('payload-size', 'string', _Kind.string,
      'per-iteration plaintext size (e.g. 1MB / 16MB / 64MB)'),
  _Flag('profile', 'string', _Kind.string,
      'exercise this single registered triple profile (overrides --shape with the profile\'s surface); empty = shape-based profile pair'),
  _Flag('rekey-every', 'int', _Kind.int64,
      'rotate the parallax + wrapper masters via Rekey every N iterations per worker; 0 = never'),
  _Flag('seed', 'uint', _Kind.uint64,
      'deterministic plaintext RNG seed for bug reproduction, NOT for security testing (pipeline keys stay CSPRNG-drawn); 0 = crypto/rand plaintexts'),
  _Flag('shape', 'string', _Kind.string,
      'cipher surface to exercise: stream | message | stream_one_shot | both'),
  _Flag('wrapper', 'string', _Kind.string, 'wrapper layer: on | off'),
];

/// The raw flag values before validation, keyed by flag name. String
/// defaults are the literals the usage prints as defaults.
Map<String, Object> _rawDefaults() => {
      'barrier-fill': 0,
      'blob-cycle-every': 0,
      'blob-mode': 1,
      'chunk-size': '0',
      'drbg': '',
      'duration': '5m',
      'gogc': 0,
      'gomaxprocs': 0,
      'goroutines': 3,
      'hash': 'areion512',
      'iterations': 0,
      'json-output': false,
      'key-bits': 0,
      'mac': 'hmac-blake3',
      'memlimit': 'auto',
      'memprofile': '',
      'nonce-bits': 0,
      'parallax': 'on',
      'payload-mode': 'fixed',
      'payload-size': '16MB',
      'profile': '',
      'rekey-every': 0,
      'seed': 0,
      'shape': 'stream',
      'wrapper': 'on',
    };

void _usage(Map<String, Object> defaults) {
  final out = StringBuffer('Usage of loop:\n');
  for (final f in _flags) {
    out.write('  -${f.name}${f.typeLabel.isEmpty ? '' : ' ${f.typeLabel}'}\n');
    out.write('    \t${f.help}');
    // Dart-specific. The default-value suffix is composed by hand; a
    // flag library that appends its own renders it itself.
    final v = defaults[f.name];
    if (f.kind == _Kind.int32 && v is int && v != 0) {
      out.write(' (default $v)');
    } else if (f.kind == _Kind.string && v is String && v.isNotEmpty) {
      out.write(' (default "$v")');
    }
    out.write('\n');
  }
  errRaw(out.toString());
}

/// Parses one value into its flag slot; false on a malformed value.
bool _assign(Map<String, Object> raw, _Flag f, String value) {
  switch (f.kind) {
    case _Kind.int32:
      final v = int.tryParse(value);
      if (v == null || v > 2147483647 || v < -2147483647) return false;
      raw[f.name] = v;
      return true;
    case _Kind.int64:
      final v = int.tryParse(value);
      if (v == null) return false;
      raw[f.name] = v;
      return true;
    case _Kind.uint64:
      if (value.startsWith('-')) return false;
      final v = BigInt.tryParse(value);
      if (v == null || v < BigInt.zero || v.bitLength > 64) return false;
      raw[f.name] = v.toSigned(64).toInt();
      return true;
    case _Kind.string:
      raw[f.name] = value;
      return true;
    case _Kind.boolean:
      if (value == 'true') {
        raw[f.name] = true;
      } else if (value == 'false') {
        raw[f.name] = false;
      } else {
        return false;
      }
      return true;
  }
}

/// Parses argv into the raw flag values. Accepts -name value,
/// --name value, -name=value and --name=value; a boolean flag takes no
/// value unless given as -name=true / -name=false. Returns 0, 1 for
/// -h / --help (usage printed), or -1 after printing the error.
int _parseArgv(List<String> argv, Map<String, Object> raw) {
  final defaults = _rawDefaults();
  for (var i = 0; i < argv.length; i++) {
    final arg = argv[i];
    if (!arg.startsWith('-') || arg.length == 1) {
      errLine('unexpected positional arguments: [$arg]');
      return -1;
    }
    final name = arg.substring(arg.startsWith('--') ? 2 : 1);
    if (name == 'h' || name == 'help') {
      _usage(defaults);
      return 1;
    }
    final eq = name.indexOf('=');
    final key = eq < 0 ? name : name.substring(0, eq);
    _Flag? f;
    for (final candidate in _flags) {
      if (candidate.name == key) {
        f = candidate;
        break;
      }
    }
    if (f == null) {
      errLine('flag provided but not defined: -$key');
      _usage(defaults);
      return -1;
    }
    String value;
    if (eq >= 0) {
      value = name.substring(eq + 1);
    } else if (f.kind == _Kind.boolean) {
      value = 'true';
    } else if (i + 1 < argv.length) {
      value = argv[++i];
    } else {
      errLine('flag needs an argument: -${f.name}');
      return -1;
    }
    if (!_assign(raw, f, value)) {
      errLine('invalid value "$value" for flag -${f.name}');
      return -1;
    }
  }
  return 0;
}

/// Maps "on" / "off" to a bool; null otherwise.
bool? _parseOnOff(String v) => v == 'on' ? true : (v == 'off' ? false : null);

/// Whether the name is one the shipped hash registry carries, read
/// from the binding's own registry enumeration.
bool _hashRegistered(String name) {
  try {
    return Itb.hashNames().contains(name);
  } on ItbException {
    return false;
  }
}

/// Resolves a registered profile to the shape family its record's mode
/// exposes by reading the record through the binding's lookup: a mode
/// beginning with "streaming" exposes the stream surfaces, one
/// beginning with "singlemsg" the message surface, "blob-only" none.
/// Prints the validation message and returns null on rejection.
int? _profileSurface(String name) {
  Profile record;
  try {
    record = Itb.lookup(name);
  } on ItbException {
    errLine('--profile "$name" is not a registered triple profile');
    return null;
  }
  if (record.mode.startsWith('streaming')) return shapeStream;
  if (record.mode.startsWith('singlemsg')) return shapeMessage;
  errLine('--profile "$name" carries no cipher surface (blob-only mode)');
  return null;
}

/// Applies a --profile's surface to the requested shape: a
/// message-surface profile forces message; a stream-surface profile
/// keeps stream or stream_one_shot as requested and turns message or
/// both into stream.
int _narrowShape(int requested, int surface) {
  if (surface == shapeMessage) return shapeMessage;
  return requested == shapeStreamOneShot ? shapeStreamOneShot : shapeStream;
}

/// Builds the resolved config from argv. Returns 0, 1 for help, or -1
/// after printing "loop: <message>" for the first failing rule.
(int, Config) _parseFlags(List<String> argv) {
  final cfg = Config();
  final raw = _rawDefaults();
  final rc = _parseArgv(argv, raw);
  if (rc != 0) return (rc, cfg);

  String str(String k) => raw[k]! as String;
  int num(String k) => raw[k]! as int;

  final durationNs = parseDuration(str('duration'));
  if (durationNs == null || durationNs <= 0) {
    errLine('--duration must be positive, got ${str('duration')}');
    return (-1, cfg);
  }
  cfg.durationNs = durationNs;
  cfg.iterations = num('iterations');
  if (cfg.iterations < 0) {
    errLine('--iterations must be >= 0, got ${cfg.iterations}');
    return (-1, cfg);
  }
  final goroutines = num('goroutines');
  if (goroutines < 1 || goroutines > maxWorkers) {
    errLine('--goroutines must be in 1..$maxWorkers, got $goroutines');
    return (-1, cfg);
  }
  // Concurrency mode. This binding runs independent-handles: a worker
  // is an isolate with its own Pipeline opened from the Init blob, so
  // --goroutines is the isolate count verbatim, never clamped.
  cfg.workersRequested = goroutines;
  cfg.workers = goroutines;
  final shape = parseShape(str('shape'));
  if (shape == null) {
    errLine('--shape must be stream | message | stream_one_shot | both, '
        'got "${str('shape')}"');
    return (-1, cfg);
  }
  cfg.shape = shape;
  if (!_hashRegistered(str('hash'))) {
    errLine('--hash "${str('hash')}" is not a registered hash primitive');
    return (-1, cfg);
  }
  cfg.hash = str('hash');
  // Validated by Init: the C ABI enumerates no MAC names.
  cfg.mac = str('mac');
  final payload = parseSize(str('payload-size'));
  if (payload == null) {
    errLine('--payload-size: invalid size "${str('payload-size')}"');
    return (-1, cfg);
  }
  cfg.payload = payload;
  if (cfg.payload < 1) {
    errLine('--payload-size must be at least 1 byte');
    return (-1, cfg);
  }
  if (str('memlimit') == 'auto') {
    cfg.memlimitAuto = true;
    cfg.memlimit = cfg.workers <= 3 ? 1 << 30 : 256 << 20;
  } else {
    final limit = parseSize(str('memlimit'));
    if (limit == null) {
      errLine('--memlimit: invalid size "${str('memlimit')}"');
      return (-1, cfg);
    }
    cfg.memlimit = limit;
  }
  cfg.gogc = num('gogc');
  if (cfg.gogc < 0) {
    errLine('--gogc must be >= 0, got ${cfg.gogc}');
    return (-1, cfg);
  }
  final parallax = _parseOnOff(str('parallax'));
  if (parallax == null) {
    errLine('--parallax must be on | off, got "${str('parallax')}"');
    return (-1, cfg);
  }
  cfg.parallax = parallax;
  final wrapper = _parseOnOff(str('wrapper'));
  if (wrapper == null) {
    errLine('--wrapper must be on | off, got "${str('wrapper')}"');
    return (-1, cfg);
  }
  cfg.wrapper = wrapper;
  cfg.profile = str('profile');
  if (cfg.profile.isNotEmpty) {
    final surface = _profileSurface(cfg.profile);
    if (surface == null) return (-1, cfg);
    cfg.shape = _narrowShape(cfg.shape, surface);
  }
  cfg.keyBits = num('key-bits');
  if (![0, 512, 1024, 2048].contains(cfg.keyBits)) {
    errLine('--key-bits must be 512 | 1024 | 2048 '
        '(or 0 = profile default), got ${cfg.keyBits}');
    return (-1, cfg);
  }
  cfg.nonceBits = num('nonce-bits');
  if (![0, 128, 256, 512].contains(cfg.nonceBits)) {
    errLine('--nonce-bits must be 128 | 256 | 512 '
        '(or 0 = profile default), got ${cfg.nonceBits}');
    return (-1, cfg);
  }
  cfg.blobMode = num('blob-mode');
  if (![1, 2].contains(cfg.blobMode)) {
    errLine('--blob-mode must be 1 (per-region) | 2 (per-container), '
        'got ${cfg.blobMode}');
    return (-1, cfg);
  }
  cfg.barrierFill = num('barrier-fill');
  if (![0, 1, 2, 4, 8, 16, 32].contains(cfg.barrierFill)) {
    errLine('--barrier-fill must be 1 | 2 | 4 | 8 | 16 | 32 '
        '(or 0 = profile default), got ${cfg.barrierFill}');
    return (-1, cfg);
  }
  // Validated by Init: the C ABI enumerates no DRBG names.
  cfg.drbg = str('drbg');
  final chunk = parseSize(str('chunk-size'));
  if (chunk == null) {
    errLine('--chunk-size: invalid size "${str('chunk-size')}"');
    return (-1, cfg);
  }
  cfg.chunkSize = chunk;
  cfg.gomaxprocs = num('gomaxprocs');
  if (cfg.gomaxprocs < 0) {
    errLine('--gomaxprocs must be > 0 when specified, got ${cfg.gomaxprocs}');
    return (-1, cfg);
  }
  cfg.rekeyEvery = num('rekey-every');
  if (cfg.rekeyEvery < 0) {
    errLine('--rekey-every must be >= 0, got ${cfg.rekeyEvery}');
    return (-1, cfg);
  }
  cfg.blobCycleEvery = num('blob-cycle-every');
  if (cfg.blobCycleEvery < 0) {
    errLine('--blob-cycle-every must be >= 0, got ${cfg.blobCycleEvery}');
    return (-1, cfg);
  }
  final mode = parsePayloadMode(str('payload-mode'));
  if (mode == null) {
    errLine('--payload-mode must be fixed | rotating | pattern-zero | '
        'pattern-ff | pattern-ascii, got "${str('payload-mode')}"');
    return (-1, cfg);
  }
  cfg.payloadMode = mode;
  cfg.seed = num('seed');
  cfg.jsonOutput = raw['json-output']! as bool;
  cfg.memprofile = str('memprofile');
  return (0, cfg);
}

// ─── Pipelines ─────────────────────────────────────────────────────

/// Folds a keystream primitive into opts for any layer the named
/// profile leaves unfilled but the operator asked for.
///
/// A profile built around a primitive that is safe only inside the
/// Interlocked Barrier ships with no parallax palette and no outer
/// cipher: both layers run outside the barrier, where that primitive
/// would stand bare, so the recipe leaves them unnamed rather than
/// naming a primitive that must not key them. Engaging either layer
/// therefore needs a keystream-capable primitive supplied from outside
/// the recipe; without it construction fails on a palette below its
/// minimum or an unnamed outer cipher, and the primitive that most
/// deserves stressing becomes the one that cannot be stressed with
/// those layers engaged.
///
/// Overrides fold into the resolved record the blob carries, so the
/// receiver rebuilds the same shape from the blob alone.
///
/// Returns 1 when a layer was filled, 0 when none needed it, -1 on a
/// lookup failure (message already printed).
int _fillKeystreamLayers(
    String name, Opts opts, bool wantParallax, bool wantWrapper) {
  Profile record;
  try {
    record = Itb.lookup(name);
  } on ItbException {
    errLine('--profile "$name" is not a registered triple profile');
    return -1;
  }
  var filled = 0;
  if (wantParallax && record.palette.isEmpty) {
    opts.withParallaxPalette(const [
      _keystreamFillCipher,
      _keystreamFillCipher,
      _keystreamFillCipher,
    ]);
    if (record.segment == 0) {
      // A recipe that never carried a palette never carried a segment
      // size either, and the schedule rejects zero.
      opts.withParallaxSegmentSize(4093);
    }
    filled = 1;
  }
  if (wantWrapper && record.outer.isEmpty) {
    opts.withOuterCipher(_keystreamFillCipher);
    filled = 1;
  }
  return filled;
}

/// Prints the construction line with the recipe read back from the
/// blob the Pipeline handed out, not echoed from the flags: every
/// construction override is proven to have reached the library by the
/// value the receiver would see. Record values that are empty (a No
/// MAC profile's MAC, a mixed profile's single hash) print as "-".
void _logPipelineInitialised(String profile, Uint8List blob) {
  Profile r;
  try {
    r = Itb.inspect(blob);
  } catch (e) {
    logLine('pipeline initialised: profile=$profile blob=${blob.length} bytes '
        '(inspect: ${errorSentence(e)})');
    return;
  }
  logLine('pipeline initialised: profile=$profile blob=${blob.length} bytes '
      'hash=${r.hash.isEmpty ? '-' : r.hash} key-bits=${r.keyBits} '
      'nonce-bits=${r.nonceBits ?? 0} barrier-fill=${r.barrierFill ?? 0} '
      'chunk-size=${r.chunk} mac=${r.mac.isEmpty ? '-' : r.mac} '
      'parallax=${onOff(r.parallax)} wrapper=${onOff(r.wrapper)}'
      '${r.containerMode == 2 ? ' container-mode=${r.containerMode}' : ''}'
      '${r.drbg.isNotEmpty ? ' drbg=${r.drbg}' : ''}');
}

/// Sets the inner blob's "mode" field of a wrap-layer session blob to
/// targetMode (1 = per-region, 2 = per-container) and returns the
/// re-encoded blob, or the failure detail. The wrap layer's profile
/// record carries its own "mode" (a string), so only the inner blob
/// ("ib") is touched; every other value survives the round trip
/// unchanged (integers stay integers, strings stay byte-identical) and
/// no key is added.
(Uint8List?, String) _editInnerBlobMode(Uint8List blob, int targetMode) {
  Object? wrap;
  try {
    wrap = jsonDecode(utf8.decode(blob));
  } on FormatException catch (e) {
    return (null, 'unmarshal wrap blob: ${e.message}');
  }
  if (wrap is! Map<String, dynamic>) {
    return (null, 'wrap blob is not a JSON object');
  }
  final inner = wrap['ib'];
  if (inner is! Map<String, dynamic>) {
    return (null, 'inner blob not found');
  }
  if (!inner.containsKey('mode')) {
    return (null, 'inner blob mode field not found');
  }
  inner['mode'] = targetMode;
  return (Uint8List.fromList(utf8.encode(jsonEncode(wrap))), '');
}

/// Constructs one Pipeline against profile with every flag-carried
/// override in the opts string (zero values included — the shared
/// library treats zero as "profile default"), then obtains the Init
/// blob once through save: the binding's init entry does not hand the
/// blob back, and the bytes are the ones Init produced. Later blob
/// reopens use the retained blob; save is never called again.
(Pipeline, Uint8List)? _buildPipeline(Config cfg, String profile) {
  final opts = Opts()
      .withInnerHash(cfg.hash)
      .withMacName(cfg.mac)
      .withParallax(cfg.parallax)
      .withWrapper(cfg.wrapper)
      .withKeyBits(cfg.keyBits)
      .withNonceBits(cfg.nonceBits)
      .withBarrierFill(cfg.barrierFill)
      .withDrbg(cfg.drbg)
      .withChunkSize(cfg.chunkSize);
  if (cfg.profile.isNotEmpty) {
    final filled =
        _fillKeystreamLayers(cfg.profile, opts, cfg.parallax, cfg.wrapper);
    if (filled < 0) return null;
    if (filled > 0) {
      errLine('${cfg.profile} leaves the requested keystream layers '
          'unnamed; $_keystreamFillCipher supplied for them');
    }
  }
  Pipeline pipe;
  try {
    pipe = Itb.create(profile, opts);
  } catch (e) {
    errLine('Init($profile): ${statusDetail(e)}');
    return null;
  }
  Uint8List blob;
  try {
    blob = pipe.save();
  } catch (e) {
    errLine('Save($profile): ${statusDetail(e)}');
    pipe.free();
    return null;
  }
  if (cfg.blobMode == 2) {
    // The sizing mode is not an Opts knob: the Init blob is edited and
    // the pipeline reopened from it, so the retained blob (the one
    // blob-cycle reopens from) carries the edited mode.
    final (edited, detail) = _editInnerBlobMode(blob, 2);
    if (edited == null) {
      errLine('rewrite blob mode: $detail');
      pipe.free();
      return null;
    }
    blob = edited;
    pipe.free();
    try {
      pipe = Itb.load(blob);
    } catch (e) {
      errLine('reload Mode 2 blob: ${statusDetail(e)}');
      return null;
    }
  }
  _logPipelineInitialised(profile, blob);
  return (pipe, blob);
}

// ─── Run ───────────────────────────────────────────────────────────

Future<int> _run(List<String> argv) async {
  final (rc, cfg) = _parseFlags(argv);
  if (rc == 1) return 0;
  if (rc != 0) return 2;

  // Runtime shaping. A long run under allocation churn grows the Go
  // heap inside the shared library without bound unless a soft limit
  // paces the collector, so a limit is always in force: an explicit
  // --memlimit is set as given, and auto caps the heap only when the
  // runtime reports no limit at all (a limit already installed from
  // the environment is left standing). The GC percentage and
  // GOMAXPROCS are set only when their flag is non-zero — a zero flag
  // skips the setter rather than calling it with zero, because zero is
  // a real value to the GC-percent setter, and a call would clobber
  // whatever the environment installed. All of it lands before any
  // Pipeline exists so the baselines are taken under the shaped
  // runtime, in the order heap limit, GC percent, GOMAXPROCS.
  if (cfg.memlimitAuto) {
    if (Itb.setMemoryLimit(-1) == 0x7fffffffffffffff) {
      Itb.setMemoryLimit(cfg.memlimit);
    }
  } else {
    Itb.setMemoryLimit(cfg.memlimit);
  }
  cfg.memlimit = Itb.setMemoryLimit(-1);
  if (cfg.gogc > 0) Itb.setGcPercent(cfg.gogc);
  if (cfg.gomaxprocs > 0) Itb.setGomaxprocs(cfg.gomaxprocs);

  logLine('start: duration=${humanDuration(cfg.durationNs)} '
      'iterations=${cfg.iterations} goroutines=${cfg.workersRequested} '
      'workers=${cfg.workers} concurrency=$concurrency '
      'shape=${shapeName(cfg.shape)} hash=${cfg.hash} mac=${cfg.mac} '
      'payload=${humanBytes(cfg.payload)} '
      'memlimit=${humanBytes(cfg.memlimit)} '
      'parallax=${onOff(cfg.parallax)} wrapper=${onOff(cfg.wrapper)}');
  logLine('overrides: profile="${cfg.profile}" key-bits=${cfg.keyBits} '
      'nonce-bits=${cfg.nonceBits} '
      'chunk-size=${humanBytes(cfg.chunkSize)} '
      'barrier-fill=${cfg.barrierFill} gomaxprocs=${cfg.gomaxprocs} '
      'rekey-every=${cfg.rekeyEvery} '
      'blob-cycle-every=${cfg.blobCycleEvery} '
      'payload-mode=${payloadModeName(cfg.payloadMode)} '
      'seed=${u64Dec(cfg.seed)} '
      'json-output=${cfg.jsonOutput ? 'true' : 'false'}'
      '${cfg.blobMode != 1 ? ' blob-mode=${cfg.blobMode}' : ''}'
      '${cfg.drbg.isNotEmpty ? ' drbg=${cfg.drbg}' : ''}');
  logLine('policy: '
      'microbatch-tiers='
      '${policyLabel(Platform.environment['ITB_MICROBATCH_TIERS'])} '
      'hashpool-starters='
      '${policyLabel(Platform.environment['ITB_HASHPOOL_STARTERS'])}');

  // Pipeline construction — one Init per exercised shape, from which
  // every worker opens its own handle. stream and stream_one_shot
  // share the streaming recipe.
  final streamProfile =
      cfg.profile.isNotEmpty ? cfg.profile : _defaultStreamProfile;
  final msgProfile =
      cfg.profile.isNotEmpty ? cfg.profile : _defaultMessageProfile;
  (Pipeline, Uint8List)? streamInit;
  (Pipeline, Uint8List)? msgInit;
  if (cfg.shape == shapeStream ||
      cfg.shape == shapeStreamOneShot ||
      cfg.shape == shapeBoth) {
    streamInit = _buildPipeline(cfg, streamProfile);
    if (streamInit == null) return 1;
  }
  if (cfg.shape == shapeMessage || cfg.shape == shapeBoth) {
    msgInit = _buildPipeline(cfg, msgProfile);
    if (msgInit == null) return 1;
  }

  final shared = Shared.create();
  var poolWarmup = poolSnapshot();
  if (poolWarmup.isEmpty) {
    errLine('pool snapshot alloc failed');
    return 1;
  }

  // Graceful stop. SIGINT / SIGTERM set the run's stop request, which
  // every worker checks before starting an iteration, so a signal
  // interrupts nothing mid-call — the in-flight encrypt / decrypt /
  // compare completes, the worker returns, and the partial summary
  // prints with the verdict the completed iterations earned.
  final sigint = ProcessSignal.sigint.watch().listen((_) => shared.requestStop());
  final sigterm =
      ProcessSignal.sigterm.watch().listen((_) => shared.requestStop());

  final reports = List<WorkerReport?>.filled(cfg.workers, null);
  final failures = List<String>.filled(cfg.workers, '');
  final warmupSeen = List<bool>.filled(cfg.workers, false);
  var warmupPending = cfg.workers;
  var donePending = cfg.workers;
  var rekeys = 0;
  var blobCycles = 0;
  final warmupComplete = Completer<void>();
  final allReported = Completer<void>();

  void arriveWarmup(int id) {
    if (warmupSeen[id]) return;
    warmupSeen[id] = true;
    if (--warmupPending == 0 && !warmupComplete.isCompleted) {
      warmupComplete.complete();
    }
  }

  void arriveDone(int id) {
    if (--donePending == 0 && !allReported.isCompleted) {
      allReported.complete();
    }
  }

  // Warmup barrier. Every worker runs one iteration and reports; the
  // clock starts only once all of them have paid their first-call
  // costs (pool warm-up, lazy kernel dispatch, page faults on the
  // payload buffers), and the RSS and pool baselines taken here
  // describe a process that has already run the whole cipher path once
  // per worker. A worker that dies before it reports still releases
  // the barrier through its exit notification, so the launcher never
  // waits on a rendezvous that can no longer happen.
  final recv = ReceivePort();
  final exitPorts = <ReceivePort>[];
  recv.listen((m) {
    if (m is WarmupMsg) {
      arriveWarmup(m.worker);
    } else if (m is MaintenanceMsg) {
      if (m.rekey) {
        rekeys++;
        logLine('rekey: g${m.worker} iter ${m.iter} '
            'rotated parallax + wrapper masters (rekey #$rekeys)');
      } else {
        blobCycles++;
        logLine('blob-cycle: g${m.worker} iter ${m.iter} '
            'reopened from session blob (cycle #$blobCycles)');
      }
    } else if (m is WorkerReport) {
      reports[m.id] = m;
      arriveDone(m.id);
    }
  });

  final warmupStart = nowNs();
  for (var i = 0; i < cfg.workers; i++) {
    final id = i;
    final errPort = ReceivePort();
    final exitPort = ReceivePort();
    exitPorts.add(errPort);
    exitPorts.add(exitPort);
    errPort.listen((e) {
      final text = e is List && e.isNotEmpty ? '${e.first}' : '$e';
      failures[id] = 'g$id: isolate error: $text';
      shared.requestStop();
    });
    exitPort.listen((_) {
      arriveWarmup(id);
      if (reports[id] == null) {
        reports[id] = WorkerReport(
          id: id,
          iters: 0,
          bytesEnc: 0,
          bytesDec: 0,
          nanosEnc: 0,
          nanosDec: 0,
          finishNs: nowNs(),
          failed: true,
          error: failures[id].isEmpty
              ? 'g$id: worker isolate produced no report'
              : failures[id],
        );
        arriveDone(id);
      }
    });
    await Isolate.spawn(
      workerEntry,
      WorkerJob(
        id: id,
        cfg: cfg,
        sharedAddr: shared.addr,
        streamProfile: streamProfile,
        msgProfile: msgProfile,
        streamBlob: streamInit?.$2,
        msgBlob: msgInit?.$2,
        port: recv.sendPort,
      ),
      onError: errPort.sendPort,
      onExit: exitPort.sendPort,
    );
  }

  await warmupComplete.future;
  var (rssWarmup, rssPeak) = readRss();
  poolWarmup = poolSnapshot();
  final warmupNs = nowNs() - warmupStart;
  logLine('warmup: ${cfg.workers} workers x 1 iter completed in '
      '${humanDuration(roundNs(warmupNs, 100000000))} '
      '(baseline rss=${humanBytes(rssWarmup)})');

  // Open the gate; the deadline below asks the workers to stop in
  // duration mode.
  final startNs = nowNs();
  shared.openGate();
  Timer? deadline;
  if (cfg.iterations == 0) {
    deadline = Timer(Duration(microseconds: cfg.durationNs ~/ 1000),
        () => shared.requestStop());
  }
  await allReported.future;
  deadline?.cancel();
  await sigint.cancel();
  await sigterm.cancel();
  recv.close();
  for (final p in exitPorts) {
    p.close();
  }

  var finishNs = startNs;
  final finalReports = <WorkerReport>[];
  for (var i = 0; i < cfg.workers; i++) {
    final r = reports[i]!;
    if (failures[i].isNotEmpty && !r.failed) {
      finalReports.add(WorkerReport(
        id: r.id,
        iters: r.iters,
        bytesEnc: r.bytesEnc,
        bytesDec: r.bytesDec,
        nanosEnc: r.nanosEnc,
        nanosDec: r.nanosDec,
        finishNs: r.finishNs,
        failed: true,
        error: failures[i],
      ));
    } else {
      finalReports.add(r);
    }
    if (r.finishNs > finishNs) finishNs = r.finishNs;
  }
  final elapsedNs = finishNs - startNs;

  final (rssFinal, peak) = readRss();
  if (peak > rssPeak) rssPeak = peak;
  final poolSteady = poolSnapshot();

  if (cfg.memprofile.isNotEmpty) {
    try {
      Itb.writeHeapProfile(cfg.memprofile);
      logLine('memprofile: heap profile written to ${cfg.memprofile}');
    } catch (e) {
      errLine('memprofile: ${errorSentence(e)}');
    }
  }

  final code = finalSummary(SummaryInput(
    cfg: cfg,
    reports: finalReports,
    rekeys: rekeys,
    blobCycles: blobCycles,
    streamProfile: streamInit == null ? '' : streamProfile,
    msgProfile: msgInit == null ? '' : msgProfile,
    rssWarmup: rssWarmup,
    rssPeak: rssPeak,
    rssFinal: rssFinal,
    poolWarmup: poolWarmup,
    poolSteady: poolSteady,
    gomaxprocs: Itb.setGomaxprocs(0),
    elapsedNs: elapsedNs,
  ));

  streamInit?.$1.free();
  msgInit?.$1.free();
  shared.release();
  return code;
}

Future<void> main(List<String> argv) async {
  restoreSigpipe();
  try {
    exit(await _run(argv));
  } catch (e) {
    errLine('$e');
    exit(1);
  }
}
