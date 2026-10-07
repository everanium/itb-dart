// Plaintext content: the payload modes, the seeded per-worker
// generator, and the buffer fill from the operating-system CSPRNG.

import 'dart:io';
import 'dart:typed_data';

/* Plaintext content policies the --payload-mode flag selects.
 *
 *   - fixed: one CSPRNG-generated buffer per worker, held unchanged
 *     for the whole run (the default).
 *   - rotating: the buffer is regenerated before every iteration, so
 *     no two encrypt calls see the same plaintext.
 *   - pattern-zero / pattern-ff: degenerate constant fills (all 0x00 /
 *     all 0xFF) probing minimum-entropy plaintext handling.
 *   - pattern-ascii: a repeating 'A'..'Z' ramp probing low-entropy
 *     structured text. */
const int payloadFixed = 0;
const int payloadRotating = 1;
const int payloadPatternZero = 2;
const int payloadPatternFf = 3;
const int payloadPatternAscii = 4;

const List<String> payloadModeNames = [
  'fixed',
  'rotating',
  'pattern-zero',
  'pattern-ff',
  'pattern-ascii',
];

String payloadModeName(int mode) => payloadModeNames[mode];

int? parsePayloadMode(String s) {
  final i = payloadModeNames.indexOf(s);
  return i < 0 ? null : i;
}

/// Seeded plaintext. The seed makes plaintext content reproducible so
/// a failing iteration can be replayed with the same bytes; it governs
/// nothing else — pipeline keys, nonces and masters stay CSPRNG-drawn,
/// so a seeded run is a reproduction aid and never a security test.
/// Each worker's stream is domain-separated by its id so seeded
/// workers still hold pairwise-distinct buffers under the fixed and
/// rotating modes. The generator is splitmix64: a few lines in any
/// language, which is why it is the one every binding uses.
int seedWorker(int seed, int workerId) => seed + workerId + 1;

int _splitmix64(Uint8List dst, int state) {
  final view = ByteData.view(dst.buffer, dst.offsetInBytes, dst.length);
  var s = state;
  final whole = dst.length - dst.length % 8;
  for (var i = 0; i < whole; i += 8) {
    s += 0x9E3779B97F4A7C15;
    var z = s;
    z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9;
    z = (z ^ (z >>> 27)) * 0x94D049BB133111EB;
    view.setUint64(i, z ^ (z >>> 31), Endian.little);
  }
  if (whole < dst.length) {
    s += 0x9E3779B97F4A7C15;
    var z = s;
    z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9;
    z = (z ^ (z >>> 27)) * 0x94D049BB133111EB;
    z ^= z >>> 31;
    for (var i = whole; i < dst.length; i++) {
      dst[i] = (z >>> (8 * (i - whole))) & 0xff;
    }
  }
  return s;
}

RandomAccessFile? _urandom;

/// Fills [dst] from the operating-system CSPRNG.
///
/// Dart-specific. The runtime's own secure generator yields one value
/// per call, which is not a way to produce a payload-sized buffer, so
/// the entropy source the platform offers for bulk draws is read
/// directly. The descriptor is opened once per isolate and the read
/// loops, because a large read may come back short.
void fillRandom(Uint8List dst) {
  final f = _urandom ??= File('/dev/urandom').openSync();
  var off = 0;
  while (off < dst.length) {
    final n = f.readIntoSync(dst, off, dst.length);
    if (n <= 0) {
      throw const FileSystemException('short read', '/dev/urandom');
    }
    off += n;
  }
}

/// Writes one plaintext buffer according to the payload mode and
/// returns the generator state to carry into the next fill. The fixed
/// and rotating modes draw from the seeded generator when the run is
/// seeded and from the OS CSPRNG otherwise; the pattern modes are
/// deterministic regardless of the seed.
int fillPayload(Uint8List dst, int mode, bool seeded, int rng) {
  switch (mode) {
    case payloadFixed:
    case payloadRotating:
      if (!seeded) {
        fillRandom(dst);
        return rng;
      }
      return _splitmix64(dst, rng);
    case payloadPatternZero:
      dst.fillRange(0, dst.length, 0x00);
      return rng;
    case payloadPatternFf:
      dst.fillRange(0, dst.length, 0xFF);
      return rng;
    default:
      for (var i = 0; i < dst.length; i++) {
        dst[i] = 0x41 + i % 26;
      }
      return rng;
  }
}
