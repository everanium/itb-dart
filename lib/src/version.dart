// Process-wide Go runtime knobs plus the library version strings.

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'errors.dart';
import 'ffi_bridge.dart';

/// Binding package version, reported by the eitb CLI.
const String bindingVersion = '0.5.1';

/// Returns the libitb3 library version string.
String libVersion() {
  final v = readCString(FfiBridge.instance.version);
  if (v.isEmpty) {
    throw ItbException(Status.internal, 'ITB_Version returned nothing');
  }
  return v;
}

/// Returns the fill cipher the auto DRBG tier selected on this host
/// (`aes-256-ctr` or `chacha20`): the tier a Pipeline uses when its
/// drbg option is empty, resolved per host and recorded in no blob.
String drbgAutoTier() {
  final v = readCString(FfiBridge.instance.drbgAutoTier);
  if (v.isEmpty) {
    throw ItbException(Status.internal, 'ITB_DRBGAutoTier returned nothing');
  }
  return v;
}

/// Sets the Go runtime's soft heap limit in bytes and returns the
/// previous limit. A negative value queries without changing.
int setMemoryLimit(int bytes) => FfiBridge.instance.setMemoryLimit(bytes);

/// Sets the Go GC trigger percentage and returns the previous value.
/// A negative value queries without changing.
int setGcPercent(int pct) => FfiBridge.instance.setGCPercent(pct);

/// Sets the Go runtime's GOMAXPROCS and returns the previous value.
/// A value of zero or below queries without changing.
int setGomaxprocs(int n) => FfiBridge.instance.setGOMAXPROCS(n);

/// Writes a Go runtime heap profile (pprof format, readable with
/// `go tool pprof`) to [path] after one forced garbage collection, so
/// the in-use figures describe the live heap at the call. An empty
/// path lets the library fall back to its own `ITB_MEMPROFILE`
/// environment variable; when that is empty too the call throws with
/// [Status.badInput].
void writeHeapProfile(String path) {
  final pathP = path.toNativeUtf8(allocator: malloc);
  try {
    check(FfiBridge.instance.writeHeapProfile(pathP));
  } finally {
    malloc.free(pathP);
  }
}

/// The number of `int64` slots [poolStats] reports. The slot count
/// grows if the library adds a pool, so a consumer sizes its own
/// storage from this call rather than from a constant of its own.
int poolStatsLen() => FfiBridge.instance.poolStatsLen();

/// The library's pool hit / miss counters, every one a monotonically
/// increasing total since library load — a consumer differences two
/// snapshots.
///
/// With `T` the hash-array pool tier count carried in slot 0, tier
/// `i` occupies the five slots at `1 + 5*i` (starter width,
/// checkouts, constructor misses, regrow replacements, bytes
/// allocated), and the scratch byte pool and the parallax chunk pool
/// occupy the four slots each at `1 + 5*T` (checkouts, constructor
/// misses, regrows, regrow bytes).
Int64List poolStats() {
  final n = FfiBridge.instance.poolStatsLen();
  if (n <= 0) return Int64List(0);
  final buf = malloc<Int64>(n);
  final outLen = malloc<Size>();
  try {
    outLen.value = 0;
    check(FfiBridge.instance.poolStats(buf, n, outLen));
    return Int64List.fromList(buf.asTypedList(outLen.value));
  } finally {
    malloc.free(buf);
    malloc.free(outLen);
  }
}
