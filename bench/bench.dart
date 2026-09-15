// Micro-benchmarks for the Dart binding: encryptMessageInto (Single
// Message shape, caller-buffer variant), incremental stream pump
// (Streaming Non-AEAD shape, reusable drain scratch), and stream
// one-shot (whole-buffer path, single FFI round trip through the
// Pipeline's stream chain) throughput at 1 MiB / 16 MiB / 64 MiB.
// Wall-clock via Stopwatch; output is a fixed-width table:
//
//   bench             size     mb_per_sec
//   message           1 MiB    <n>
//   ...
//
// Configuration is driven by environment variables so a side-by-side
// comparison with the root Go bench harness is straightforward:
//
//   ITB_NONCE_BITS      512         shipped secure default
//   ITB_KEY_BITS        1024        matches root Go BENCH3.md
//   ITB_WITH_PARALLAX   false       root Go bench runs without parallax
//   ITB_WITH_WRAPPER    false       root Go bench runs without the wrapper
//   ITB_INNER_HASH      (profile)   opaque hash name
//   ITB_MSG_PROFILE     (fallback ITB_PROFILE, then singlemsg-triple-nomac-v1)
//   ITB_STREAM_PROFILE  (fallback ITB_PROFILE, then streaming-noaead-triple-v1)
//   ITB_BENCH_MIN_SEC   5           per-case wall-clock budget (seconds)

import 'dart:io';
import 'dart:typed_data';

import 'package:libitb3/itb.dart';

/// Per-case iteration floor alongside the wall-clock budget.
const int benchMinIters = 3;

const List<int> sizes = [1 << 20, 16 << 20, 64 << 20];

double benchMinSeconds() {
  final raw = Platform.environment['ITB_BENCH_MIN_SEC'] ?? '';
  final v = double.tryParse(raw);
  return (v != null && v > 0) ? v : 5.0;
}

/// Reads the bench-shape env vars and builds an [Opts]. Defaults
/// match root Go BENCH3.md so numbers are directly comparable.
Opts buildOpts() {
  final env = Platform.environment;
  bool flag(String name) => const ['true', '1'].contains(env[name] ?? '');
  final opts = Opts()
      .withNonceBits(int.tryParse(env['ITB_NONCE_BITS'] ?? '') ?? 512)
      .withKeyBits(int.tryParse(env['ITB_KEY_BITS'] ?? '') ?? 1024)
      .withParallax(flag('ITB_WITH_PARALLAX'))
      .withWrapper(flag('ITB_WITH_WRAPPER'));
  final inner = env['ITB_INNER_HASH'] ?? '';
  if (inner.isNotEmpty) {
    opts.withInnerHash(inner);
  }
  final macName = env['ITB_MAC_NAME'] ?? '';
  if (macName.isNotEmpty) {
    opts.withMacName(macName);
  }
  return opts;
}

String profileName(String shapeEnv, String fallback) {
  final env = Platform.environment;
  final s = env[shapeEnv] ?? '';
  if (s.isNotEmpty) return s;
  final p = env['ITB_PROFILE'] ?? '';
  return p.isEmpty ? fallback : p;
}

/// Deterministic non-trivial payload (xorshift64 fill; not in the
/// timing loop).
Uint8List payload(int n, int seed) {
  var x = seed | 1;
  final out = Uint8List(n);
  for (var i = 0; i < n; i++) {
    x ^= x << 13;
    x ^= x >>> 7;
    x ^= x << 17;
    out[i] = x & 0xff;
  }
  return out;
}

String sizeLabel(int size) =>
    size >= 1 << 20 ? '${size >> 20} MiB' : '${size >> 10} KiB';

void benchHeader() {
  print('${'bench'.padRight(17)} ${'size'.padRight(8)} mb_per_sec');
}

/// Runs [fn] until the wall-clock budget is spent (with an iteration
/// floor + one untimed warm-up), then prints one table row.
void benchCase(String name, int size, void Function() fn) {
  fn(); // warm-up
  final budgetUs = (benchMinSeconds() * 1e6).round();
  final sw = Stopwatch()..start();
  var iters = 0;
  while (sw.elapsedMicroseconds < budgetUs || iters < benchMinIters) {
    fn();
    iters++;
  }
  final secs = sw.elapsedMicroseconds / 1e6;
  final mb = size * iters / (1024.0 * 1024.0);
  print('${name.padRight(17)} ${sizeLabel(size).padRight(8)} '
      '${(mb / secs).toStringAsFixed(1)}');
}

void benchMessage() {
  final pipe =
      Itb.create(profileName('ITB_MSG_PROFILE', 'singlemsg-triple-nomac-v1'), buildOpts());
  for (final size in sizes) {
    final plain = payload(size, size);
    // Reusable wire scratch shared by every iteration of the size
    // case, pre-sized to the documented expansion bound
    // (payload * 5/4 + 65536): encryptMessageInto rewrites it in
    // place — no per-iteration Dart-heap allocation.
    final wire = Uint8List(size + (size >> 2) + 65536);
    benchCase('message', size, () => pipe.encryptMessageInto(plain, wire));
    // Pre-encrypt one wire outside the decrypt timing loop.
    final decWire = pipe.encryptMessage(plain);
    final decOut = Uint8List(size + 65536);
    benchCase('message-dec', size,
        () => pipe.decryptMessageInto(decWire, decOut));
  }
  pipe.free();
}

void benchStream() {
  final pipe =
      Itb.create(profileName('ITB_STREAM_PROFILE', 'streaming-noaead-triple-v1'), buildOpts());
  const chunk = 4 << 20;
  // One reusable drain buffer across every iteration: the consumer
  // side of a real pump (socket / file sink) reads into a stable
  // buffer, so the bench does the same via read(out) instead of
  // materializing a fresh chunk per drain call.
  final out = Uint8List(chunk + 65536);
  for (final size in sizes) {
    final plain = payload(size, size + 1);
    void run() {
      final sess = pipe.encryptStream();
      for (var off = 0; off < plain.length; off += chunk) {
        sess.write(Uint8List.sublistView(
            plain, off, (off + chunk).clamp(0, plain.length)));
        // Drain available output so the spool stays bounded.
        for (;;) {
          final r = sess.read(out);
          if (r.n == 0) break;
        }
      }
      sess.end();
      for (;;) {
        final r = sess.read(out);
        if (r.finished) break;
      }
      sess.free();
    }

    benchCase('stream_pump', size, run);
    // Pre-encrypt one wire outside the decrypt timing loop.
    final builder = BytesBuilder();
    final encSess = pipe.encryptStream();
    for (var off = 0; off < plain.length; off += chunk) {
      encSess.write(Uint8List.sublistView(
          plain, off, (off + chunk).clamp(0, plain.length)));
      for (;;) {
        final r = encSess.read(out);
        if (r.n == 0) break;
        builder.add(out.sublist(0, r.n));
      }
    }
    encSess.end();
    for (;;) {
      final r = encSess.read(out);
      if (r.n > 0) builder.add(out.sublist(0, r.n));
      if (r.finished) break;
    }
    encSess.free();
    final decWire = builder.toBytes();
    void runDec() {
      final sess = pipe.decryptStream();
      for (var off = 0; off < decWire.length; off += chunk) {
        sess.write(Uint8List.sublistView(
            decWire, off, (off + chunk).clamp(0, decWire.length)));
        for (;;) {
          final r = sess.read(out);
          if (r.n == 0) break;
        }
      }
      sess.end();
      for (;;) {
        final r = sess.read(out);
        if (r.finished) break;
      }
      sess.free();
    }

    benchCase('stream_pump-dec', size, runDec);
  }
  pipe.free();
}

void benchStreamOneShot() {
  final pipe =
      Itb.create(profileName('ITB_STREAM_PROFILE', 'streaming-noaead-triple-v1'), buildOpts());
  for (final size in sizes) {
    final plain = payload(size, size + 2);
    benchCase('stream_one_shot', size, () {
      pipe.encryptStreamOneShot(plain);
    });
    // Pre-encrypt one wire outside the decrypt timing loop.
    final decWire = pipe.encryptStreamOneShot(plain);
    benchCase('stream_one_shot-dec', size, () {
      pipe.decryptStreamOneShot(decWire);
    });
  }
  pipe.free();
}

void main() {
  // Bench-scale allocation churn leaks Go scratch heap unboundedly
  // without a soft memory cap + aggressive GC; the return values
  // report the previous settings, not an error.
  Itb.setMemoryLimit(4 << 30);
  Itb.setGcPercent(100);

  benchHeader();
  benchMessage();
  benchStream();
  benchStreamOneShot();
}
