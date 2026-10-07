// The final summary in both renderings, and the two measurements it
// folds in that are not per-worker counters: the process resident set
// and the shared library's pool counters.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:libitb3/itb.dart';

import 'payload.dart';
import 'size.dart';
import 'state.dart';

/// The process's current resident set and its high-water mark in
/// bytes, from /proc/self/status (VmRSS and VmHWM, reported in kB).
/// Both are zero on a platform without that file; the figures are
/// informational and never enter the verdict.
(int, int) readRss() {
  var current = 0;
  var peak = 0;
  try {
    for (final line in File('/proc/self/status').readAsLinesSync()) {
      if (line.startsWith('VmRSS:')) {
        current = _statusKb(line);
      } else if (line.startsWith('VmHWM:')) {
        peak = _statusKb(line);
      }
    }
  } on FileSystemException {
    return (0, 0);
  }
  return (current, peak);
}

/// Parses one "Vm...:   1234 kB" line into bytes; zero on any parse
/// failure.
int _statusKb(String line) {
  final colon = line.indexOf(':');
  if (colon < 0) return 0;
  final digits = RegExp(r'\d+').firstMatch(line.substring(colon + 1));
  return digits == null ? 0 : int.parse(digits.group(0)!) * 1024;
}

/// Pool counters. The shared library keeps process-wide monotonic
/// totals at every pool checkout of its cipher core: per hash-array
/// tier the starter width, checkouts, constructor misses, regrow
/// replacements and bytes allocated; for the scratch byte pool and the
/// parallax chunk pool the checkouts, constructor misses, regrows and
/// regrow bytes. Two snapshots bracketing the main loop are
/// differenced into per-run hit / miss figures that tell whether a
/// pool keeps its items warm between calls or evicts them across GC
/// cycles. The slot layout is read from the library: slot 0 carries
/// the tier count T, tier i occupies the five slots at 1 + 5*i, and
/// the two byte pools occupy the eight slots at 1 + 5*T; the buffer is
/// sized from the binding's length query, never from a constant.
Int64List poolSnapshot() {
  try {
    return Itb.poolStats();
  } on ItbException {
    return Int64List(0);
  }
}

/// The differenced pool figures of one run.
class _PoolTier {
  _PoolTier(this.tier, this.starter, this.get, this.fresh, this.regrow,
      this.newBytes);

  final int tier;
  final int starter;
  final int get;
  final int fresh;
  final int regrow;
  final int newBytes;

  double get missPercent => _missPercent(fresh + regrow, get);
}

class _BytePool {
  _BytePool(this.get, this.fresh, this.regrow, this.regrowBytes);

  final int get;
  final int fresh;
  final int regrow;
  final int regrowBytes;

  double get missPercent => _missPercent(regrow, get);
}

class _PoolDelta {
  _PoolDelta(this.tiers, this.buf, this.chunk);

  final List<_PoolTier> tiers;
  final _BytePool buf;
  final _BytePool chunk;
}

double _missPercent(int miss, int get) =>
    get <= 0 ? 0.0 : 100.0 * miss / get;

final _BytePool _emptyPool = _BytePool(0, 0, 0, 0);

_PoolDelta _poolDiff(Int64List warmup, Int64List steady) {
  if (warmup.length < 9 || steady.length < 9) {
    return _PoolDelta(const [], _emptyPool, _emptyPool);
  }
  final tiers = steady[0];
  if (tiers < 0 || 1 + 5 * tiers + 8 > steady.length) {
    return _PoolDelta(const [], _emptyPool, _emptyPool);
  }
  final out = <_PoolTier>[];
  for (var i = 0; i < tiers; i++) {
    final base = 1 + 5 * i;
    // A tier is reported only when its starter width is non-zero.
    if (steady[base] == 0) continue;
    out.add(_PoolTier(
      i,
      steady[base],
      steady[base + 1] - warmup[base + 1],
      steady[base + 2] - warmup[base + 2],
      steady[base + 3] - warmup[base + 3],
      steady[base + 4] - warmup[base + 4],
    ));
  }
  final tail = 1 + 5 * tiers;
  final buf = _BytePool(
    steady[tail] - warmup[tail],
    steady[tail + 1] - warmup[tail + 1],
    steady[tail + 2] - warmup[tail + 2],
    steady[tail + 3] - warmup[tail + 3],
  );
  final chunk = _BytePool(
    steady[tail + 4] - warmup[tail + 4],
    steady[tail + 5] - warmup[tail + 5],
    steady[tail + 6] - warmup[tail + 6],
    steady[tail + 7] - warmup[tail + 7],
  );
  return _PoolDelta(out, buf, chunk);
}

/// The measurements the launcher hands the summary beside the config
/// and the per-worker reports.
class SummaryInput {
  SummaryInput({
    required this.cfg,
    required this.reports,
    required this.rekeys,
    required this.blobCycles,
    required this.streamProfile,
    required this.msgProfile,
    required this.rssWarmup,
    required this.rssPeak,
    required this.rssFinal,
    required this.poolWarmup,
    required this.poolSteady,
    required this.gomaxprocs,
    required this.elapsedNs,
  });

  final Config cfg;
  final List<WorkerReport> reports;
  final int rekeys;
  final int blobCycles;
  final String streamProfile;
  final String msgProfile;
  final int rssWarmup;
  final int rssPeak;
  final int rssFinal;
  final Int64List poolWarmup;
  final Int64List poolSteady;
  final int gomaxprocs;
  final int elapsedNs;
}

/// The effective GC percentage as the runtime reports it: the query
/// form of the setter (a set-and-restore round trip inside the
/// library) so the field is the same whether the value came from the
/// flag, the environment, or the runtime default.
int _effectiveGogc(int flag) => flag > 0 ? flag : Itb.setGcPercent(-1);

/// Output contract. Both renderings are shared with the Go harness and
/// every other binding's loop utility field for field: the same lines
/// in the same order, the same keys in the same order, floats with a
/// fixed number of decimals so the JSON is byte-identical across
/// implementations. The Go harness alone adds its runtime-internal
/// lines after rss: and its runtime-internal keys after
/// parallax_chunk_pool; nothing here reproduces them because nothing
/// they read is reachable through the C ABI.
int finalSummary(SummaryInput s) {
  final cfg = s.cfg;
  var totalIters = 0;
  var totalEnc = 0;
  var totalDec = 0;
  var nanosEnc = 0;
  var nanosDec = 0;
  var errors = 0;
  for (final r in s.reports) {
    totalIters += r.iters;
    totalEnc += r.bytesEnc;
    totalDec += r.bytesDec;
    nanosEnc += r.nanosEnc;
    nanosDec += r.nanosDec;
    if (r.failed) errors++;
  }

  // Throughput. Per-direction throughput divides the sum of every
  // worker's wall time in that direction by the worker count — the
  // equivalent single-stream wall time under N-way concurrency — so
  // each direction reports the aggregate rate it sustained rather than
  // collapsing to combined/2 (every iteration moves equal encrypt and
  // decrypt bytes, so a total-elapsed denominator would give both
  // directions the same figure). The combined rate keeps total elapsed
  // as the one-glance overall figure.
  final avgEnc = nanosEnc > 0 ? nanosEnc ~/ cfg.workers : 0;
  final avgDec = nanosDec > 0 ? nanosDec ~/ cfg.workers : 0;

  final rssDelta = s.rssFinal - s.rssWarmup;
  final rssGrowth =
      s.rssWarmup > 0 ? 100.0 * rssDelta / s.rssWarmup : 0.0;
  final pd = _poolDiff(s.poolWarmup, s.poolSteady);
  final pass = errors == 0;

  if (cfg.jsonOutput) {
    final o = StringBuffer('{');
    o.write('"duration_seconds":${(s.elapsedNs / 1e9).toStringAsFixed(3)}');
    o.write(',"iterations":$totalIters');
    o.write(',"per_worker_iterations":'
        '[${s.reports.map((r) => r.iters).join(',')}]');
    o.write(',"bytes_encrypted":$totalEnc');
    o.write(',"bytes_decrypted":$totalDec');
    o.write(',"encrypt_mb_per_sec":'
        '${mbPerSec(totalEnc, avgEnc).toStringAsFixed(1)}');
    o.write(',"decrypt_mb_per_sec":'
        '${mbPerSec(totalDec, avgDec).toStringAsFixed(1)}');
    o.write(',"combined_mb_per_sec":'
        '${mbPerSec(totalEnc + totalDec, s.elapsedNs).toStringAsFixed(1)}');
    o.write(',"rekeys":${s.rekeys}');
    o.write(',"blob_cycles":${s.blobCycles}');
    o.write(',"worker_errors":[');
    o.write(s.reports
        .where((r) => r.failed)
        .map((r) => jsonEncode(r.error))
        .join(','));
    o.write(']');
    o.write(',"verdict":"${pass ? 'PASS' : 'FAIL'}"');
    o.write(',"shape":"${shapeName(cfg.shape)}"');
    o.write(',"stream_profile":${jsonEncode(s.streamProfile)}');
    o.write(',"message_profile":${jsonEncode(s.msgProfile)}');
    o.write(',"hash":${jsonEncode(cfg.hash)}');
    o.write(',"mac":${jsonEncode(cfg.mac)}');
    o.write(',"payload_bytes":${cfg.payload}');
    o.write(',"payload_mode":"${payloadModeName(cfg.payloadMode)}"');
    o.write(',"seed":${u64Dec(cfg.seed)}');
    o.write(',"key_bits":${cfg.keyBits}');
    o.write(',"nonce_bits":${cfg.nonceBits}');
    o.write(',"blob_mode":${cfg.blobMode}');
    o.write(',"drbg":${jsonEncode(cfg.drbg)}');
    o.write(',"drbg_auto_tier":${jsonEncode(Itb.drbgAutoTier())}');
    o.write(',"chunk_size_bytes":${cfg.chunkSize}');
    o.write(',"barrier_fill":${cfg.barrierFill}');
    o.write(',"parallax":"${onOff(cfg.parallax)}"');
    o.write(',"wrapper":"${onOff(cfg.wrapper)}"');
    o.write(',"goroutines_requested":${cfg.workersRequested}');
    o.write(',"goroutines":${cfg.workers}');
    o.write(',"concurrency":"$concurrency"');
    o.write(',"gogc":"${_effectiveGogc(cfg.gogc)}"');
    o.write(',"memlimit_bytes":${cfg.memlimit}');
    o.write(',"gomaxprocs":${s.gomaxprocs}');
    o.write(',"microbatch_tiers":'
        '${jsonEncode(policyLabel(Platform.environment['ITB_MICROBATCH_TIERS']))}');
    o.write(',"hashpool_starters":'
        '${jsonEncode(policyLabel(Platform.environment['ITB_HASHPOOL_STARTERS']))}');
    o.write(',"rss_warmup_bytes":${s.rssWarmup}');
    o.write(',"rss_peak_bytes":${s.rssPeak}');
    o.write(',"rss_final_bytes":${s.rssFinal}');
    o.write(',"rss_growth_percent":${rssGrowth.toStringAsFixed(2)}');
    o.write(',"hash_pool_tiers":[');
    o.write(pd.tiers
        .map((t) => '{"tier":${t.tier},"starter":${t.starter},'
            '"get":${t.get},"new":${t.fresh},"regrow":${t.regrow},'
            '"new_bytes":${t.newBytes},'
            '"miss_percent":${t.missPercent.toStringAsFixed(2)}}')
        .join(','));
    o.write(']');
    o.write(',"buf_pool":${_poolJson(pd.buf)}');
    o.write(',"parallax_chunk_pool":${_poolJson(pd.chunk)}');
    o.write('}\n');
    outRaw(o.toString());
    return pass ? 0 : 1;
  }

  logLine('=== FINAL ===');
  logLine('  duration: ${humanDuration(roundNs(s.elapsedNs, 1000000))}');
  logLine('  iterations: ${s.reports.map((r) => r.iters).join(' + ')} '
      '= $totalIters total');
  logLine('  throughput: encrypt ${humanRate(totalEnc, avgEnc)}, '
      'decrypt ${humanRate(totalDec, avgDec)}, '
      'combined ${humanRate(totalEnc + totalDec, s.elapsedNs)}');
  logLine('  bytes: ${humanBytes(totalEnc)} encrypted, '
      '${humanBytes(totalDec)} decrypted');
  logLine('  data integrity: $totalIters/$totalIters PASS');
  logLine('  concurrency: $concurrency, workers ${cfg.workers} '
      '(requested ${cfg.workersRequested})');
  logLine('  rss: warmup ${humanBytes(s.rssWarmup)}, '
      'peak ${humanBytes(s.rssPeak)}, final ${humanBytes(s.rssFinal)} '
      '(delta ${humanBytesSigned(rssDelta)}, '
      '${rssGrowth.toStringAsFixed(1)}% growth)');
  for (final t in pd.tiers) {
    logLine('  hash pool tier ${t.tier} (starter ${t.starter}): '
        'get ${t.get}, miss ${t.fresh + t.regrow} '
        '(new ${t.fresh} + regrow ${t.regrow}), '
        'miss ${t.missPercent.toStringAsFixed(2)}%, '
        '${humanBytes(t.newBytes)} allocated');
  }
  logLine('  buf pool: get ${pd.buf.get}, regrow ${pd.buf.regrow} '
      '(of which fresh ${pd.buf.fresh}), '
      'miss ${pd.buf.missPercent.toStringAsFixed(2)}%, '
      '${humanBytes(pd.buf.regrowBytes)} regrown');
  logLine('  parallax chunk pool: get ${pd.chunk.get}, '
      'regrow ${pd.chunk.regrow} (of which fresh ${pd.chunk.fresh}), '
      'miss ${pd.chunk.missPercent.toStringAsFixed(2)}%, '
      '${humanBytes(pd.chunk.regrowBytes)} regrown');
  if (s.rekeys > 0) logLine('  rekeys: ${s.rekeys}');
  if (s.blobCycles > 0) logLine('  blob cycles: ${s.blobCycles}');
  for (final r in s.reports) {
    if (r.failed) logLine('  ERROR: ${r.error}');
  }
  if (pass) {
    logLine('  verdict: PASS');
    return 0;
  }
  logLine('  verdict: FAIL (errors=$errors)');
  return 1;
}

String _poolJson(_BytePool p) => '{"get":${p.get},"new":${p.fresh},'
    '"regrow":${p.regrow},"regrow_bytes":${p.regrowBytes},'
    '"miss_percent":${p.missPercent.toStringAsFixed(2)}}';
