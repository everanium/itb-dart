// Size and duration parsing, the monotonic clock, and the human
// renderings of sizes, rates and durations. Every rendering here is
// part of the output contract shared with the Go harness and the other
// bindings' loop utilities, so the formats are fixed to the character,
// not to taste.

import 'dart:ffi';

import 'package:ffi/ffi.dart';

import 'state.dart';

Pointer<Int64>? _tsBuf;

/// Monotonic wall clock in nanoseconds, comparable across isolates.
///
/// Dart-specific. `Stopwatch` measures only from its own start instant
/// and does not cross an isolate boundary, so the launcher could not
/// compare a worker's finish instant with its own; the platform clock
/// the host offers is read instead, through the two-word struct it
/// fills.
int nowNs() {
  final ts = _tsBuf ??= malloc<Int64>(2);
  Libc.instance.clockGettime(clockMonotonic, ts);
  return ts[0] * 1000000000 + ts[1];
}

/// Parses a human byte-size string ("16MB", "1MiB", "512K",
/// "1073741824") into a byte count. Every suffix is a binary
/// multiple: K/KB/KiB = 1024, M/MB/MiB = 1024^2, G/GB/GiB = 1024^3, B
/// or none = bytes; matching is case-insensitive and surrounding
/// whitespace is trimmed. Returns null on a malformed or negative
/// value.
int? parseSize(String raw) {
  final s = raw.trim().toUpperCase();
  if (s.isEmpty) return null;
  const table = <String, int>{
    'KIB': 1 << 10,
    'KB': 1 << 10,
    'K': 1 << 10,
    'MIB': 1 << 20,
    'MB': 1 << 20,
    'M': 1 << 20,
    'GIB': 1 << 30,
    'GB': 1 << 30,
    'G': 1 << 30,
    'B': 1,
  };
  var mult = 1;
  var digits = s;
  for (final entry in table.entries) {
    if (s.length >= entry.key.length && s.endsWith(entry.key)) {
      mult = entry.value;
      digits = s.substring(0, s.length - entry.key.length);
      break;
    }
  }
  digits = digits.trimRight();
  if (digits.isEmpty) return null;
  for (final c in digits.codeUnits) {
    if (c < 0x30 || c > 0x39) return null;
  }
  final n = int.tryParse(digits);
  if (n == null || n < 0) return null;
  if (mult > 1 && n > 0x7fffffffffffffff ~/ mult) return null;
  return n * mult;
}

/// One unit of the duration grammar, in the order the parser probes
/// them: a two-letter unit has to be tried before the single letter it
/// ends with, or "ms" would match "m" and leave a stray "s".
const List<(String, double)> _durationUnits = [
  ('ns', 1.0),
  ('us', 1e3),
  ('ms', 1e6),
  ('s', 1e9),
  ('m', 60e9),
  ('h', 3600e9),
];

/// Parses the Go duration grammar — a sequence of decimal numbers each
/// followed by a unit (h, m, s, ms, us, ns), such as "30s", "5m",
/// "1h30m", "3s500ms", "1.5s" — into nanoseconds. Returns null on a
/// malformed string.
int? parseDuration(String s) {
  if (s.isEmpty) return null;
  var total = 0.0;
  var i = 0;
  while (i < s.length) {
    final c = s.codeUnitAt(i);
    if (!((c >= 0x30 && c <= 0x39) || c == 0x2e)) return null;
    var j = i;
    while (j < s.length) {
      final d = s.codeUnitAt(j);
      if ((d >= 0x30 && d <= 0x39) || d == 0x2e) {
        j++;
      } else {
        break;
      }
    }
    final v = double.tryParse(s.substring(i, j));
    if (v == null || v < 0) return null;
    i = j;
    var mult = 0.0;
    for (final (unit, ns) in _durationUnits) {
      if (i + unit.length <= s.length &&
          s.substring(i, i + unit.length) == unit &&
          !_isAlpha(s, i + unit.length)) {
        mult = ns;
        i += unit.length;
        break;
      }
    }
    if (mult == 0.0) return null;
    total += v * mult;
  }
  if (total > 9.2e18) return null;
  return total.toInt();
}

bool _isAlpha(String s, int at) {
  if (at >= s.length) return false;
  final c = s.codeUnitAt(at) | 0x20;
  return c >= 0x61 && c <= 0x7a;
}

/// Renders a byte count with a binary-unit suffix: "1.0GiB",
/// "16.0MiB", "4.0KiB", "512B".
String humanBytes(int n) {
  if (n >= (1 << 30)) return '${(n / (1 << 30)).toStringAsFixed(1)}GiB';
  if (n >= (1 << 20)) return '${(n / (1 << 20)).toStringAsFixed(1)}MiB';
  if (n >= (1 << 10)) return '${(n / (1 << 10)).toStringAsFixed(1)}KiB';
  return '${n}B';
}

/// Renders a possibly-negative byte delta with an explicit sign.
String humanBytesSigned(int n) =>
    n < 0 ? '-${humanBytes(-n)}' : '+${humanBytes(n)}';

/// Binary MiB per second over a nanosecond window; 0 when the window
/// is unmeasured.
double mbPerSec(int bytes, int ns) =>
    ns <= 0 ? 0.0 : bytes / (1 << 20) / (ns / 1e9);

/// Renders a throughput as "123.4MB/s" (binary MiB per second) or
/// "n/a" for an unmeasured window.
String humanRate(int bytes, int ns) =>
    ns <= 0 ? 'n/a' : '${mbPerSec(bytes, ns).toStringAsFixed(1)}MB/s';

/// The fractional part of a nanosecond remainder (0 .. 1e9) as ".ddd"
/// with trailing zeros removed; the empty string for zero.
String _fraction(int fracNs) {
  if (fracNs == 0) return '';
  var digits = fracNs.toString().padLeft(9, '0');
  while (digits.endsWith('0')) {
    digits = digits.substring(0, digits.length - 1);
  }
  return '.$digits';
}

/// Renders a duration the way Go's time.Duration prints: below one
/// second as milliseconds ("900ms", "1.5ms"); otherwise "[Hh][Mm]Ss"
/// where the hour part appears when non-zero, the minute part when the
/// hour part appears or the minutes are non-zero, and the seconds
/// carry their fraction with trailing zeros removed ("5s", "5.003s",
/// "1m0s", "1m5.25s", "1h0m0s"). The caller rounds first.
String humanDuration(int nanos) {
  var ns = nanos < 0 ? -nanos : nanos;
  if (ns == 0) return '0s';
  if (ns < 1000000000) {
    final ms = ns ~/ 1000000;
    final frac = (ns % 1000000) * 1000; // scale to 9 digits
    return '$ms${_fraction(frac)}ms';
  }
  final hours = ns ~/ 3600000000000;
  var rem = ns % 3600000000000;
  final minutes = rem ~/ 60000000000;
  rem %= 60000000000;
  final seconds = rem ~/ 1000000000;
  final frac = rem % 1000000000;
  final out = StringBuffer();
  if (hours > 0) out.write('${hours}h');
  if (hours > 0 || minutes > 0) out.write('${minutes}m');
  out.write('$seconds${_fraction(frac)}s');
  return out.toString();
}

/// Rounds a nanosecond count to a multiple of [unit], half away from
/// zero — the rounding the `duration:` and `warmup:` lines apply
/// before rendering.
int roundNs(int ns, int unit) => (ns + unit ~/ 2) ~/ unit * unit;

/// Renders a 64-bit value held in a signed int as the unsigned decimal
/// the output contract fixes for the seed, which the flag accepts over
/// the whole unsigned range.
String u64Dec(int v) =>
    v >= 0 ? v.toString() : (BigInt.from(v) + (BigInt.one << 64)).toString();
