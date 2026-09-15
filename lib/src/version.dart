// Process-wide Go runtime knobs plus the library version strings.

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

/// Sets the Go runtime's soft heap limit in bytes and returns the
/// previous limit. A negative value queries without changing.
int setMemoryLimit(int bytes) => FfiBridge.instance.setMemoryLimit(bytes);

/// Sets the Go GC trigger percentage and returns the previous value.
/// A negative value queries without changing.
int setGcPercent(int pct) => FfiBridge.instance.setGCPercent(pct);
