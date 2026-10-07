// Status codes and the exception type shared by every fallible call.
//
// Numeric values mirror the libitb3 C ABI
// (cmd/cshared/internal/capi/errors.go) and are stable across
// releases.

import 'ffi_bridge.dart';

/// Integer status codes returned by every libitb3 entry point.
abstract final class Status {
  static const int ok = 0;
  static const int badHash = 1;
  static const int badKeyBits = 2;
  static const int badHandle = 3;
  static const int badInput = 4;
  static const int bufferTooSmall = 5;
  static const int encryptFailed = 6;
  static const int decryptFailed = 7;
  static const int seedWidthMix = 8;
  static const int badMac = 9;
  static const int macFailure = 10;
  static const int blobMalformedRecipe = 11;
  static const int recipePrimitiveUnknown = 12;
  static const int unknownProfile = 13;
  static const int blobModeMismatch = 19;
  static const int blobMalformed = 20;
  static const int blobVersionTooNew = 21;
  static const int blobTooManyOpts = 22;
  static const int streamTruncated = 23;
  static const int streamAfterFinal = 24;
  static const int tripleClosed = 25;
  static const int profileExists = 26;
  static const int internal = 99;
}

/// Thrown whenever libitb3 returns a non-OK status.
///
/// [statusCode] carries the numeric code; [lastError] carries the
/// `ITB_LastError` diagnostic captured immediately after the failing
/// call. The diagnostic is process-global last-write-wins — under
/// concurrent FFI use the text may belong to a different call; the
/// status code is always attributable.
class ItbException implements Exception {
  ItbException(this.statusCode, [String? detail])
      : lastError = detail ?? readLastError();

  /// Numeric libitb3 status code (see [Status]).
  final int statusCode;

  /// `ITB_LastError` diagnostic text ('' when none is recorded).
  final String lastError;

  @override
  String toString() => 'itb: status=$statusCode: $lastError';
}

/// Maps a raw FFI return code onto void / thrown [ItbException].
void check(int rc) {
  if (rc != Status.ok) {
    throw ItbException(rc);
  }
}

/// Reads the `ITB_LastError` diagnostic (NUL-stripped). Returns the
/// empty string when no diagnostic is recorded.
String readLastError() => readCString(FfiBridge.instance.lastError);
