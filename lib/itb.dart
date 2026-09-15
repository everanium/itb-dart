// Thin Dart proxy over the libitb3 shared library's Triple Pipeline
// surface.
//
// The package wraps the `ITB_Triple_*` C ABI exported by
// `cmd/cshared` (libitb3.so / .dylib / .dll) through `dart:ffi` —
// runtime FFI, no build step, no C compiler at install time. Every
// hash-name / MAC-name / cipher-name / profile-name is an opaque
// string passed through to Go for validation; the binding carries no
// ITB construction logic of its own.
//
//   import 'package:libitb3/itb.dart';
//
//   final sender = Itb.create('singlemsg-triple-mac-v1');
//   final receiver = Itb.load(sender.save());
//   final wire = sender.encryptMessage(plain);
//   final back = receiver.decryptMessage(wire);

import 'dart:typed_data';

import 'src/pipeline.dart' as p;
import 'src/pipeline.dart';
import 'src/version.dart' as rt;

export 'src/errors.dart';
export 'src/pipeline.dart';
export 'src/stream.dart';
export 'src/version.dart';

/// Convenience facade over the package's top-level surface.
abstract final class Itb {
  /// The sorted names of every registered profile (the shipped
  /// catalogue plus prior [register] calls), read from the library
  /// via `ITB_Triple_Profiles`. The blob-only profile exposes no
  /// cipher surface.
  static List<String> profiles() => p.profiles();

  /// Constructs a fresh [Pipeline] against the named profile.
  static Pipeline create(String profile, [Opts? opts]) =>
      Pipeline.create(profile, opts);

  /// Reconstructs a [Pipeline] from a blob produced by
  /// [Pipeline.save] or [Pipeline.rekey].
  static Pipeline load(Uint8List blob,
          {Uint8List? permMaster, Uint8List? wrapMaster}) =>
      Pipeline.load(blob, permMaster: permMaster, wrapMaster: wrapMaster);

  /// [load] for a blob stored in a file; the file is read inside the
  /// library.
  static Pipeline loadF(String path,
          {Uint8List? permMaster, Uint8List? wrapMaster}) =>
      Pipeline.loadF(path, permMaster: permMaster, wrapMaster: wrapMaster);

  /// Decodes the blob's embedded profile record without opening a
  /// Pipeline.
  static Profile inspect(Uint8List blob) => p.inspect(blob);

  /// Registers [profile] under [name] (see [p.register]).
  static void register(String name, Profile profile) =>
      p.register(name, profile);

  /// Looks up a registered profile by name (see [p.lookup]).
  static Profile lookup(String name) => p.lookup(name);

  /// The libitb3 library version string.
  static String version() => rt.libVersion();

  /// Sets the Go runtime's soft heap limit in bytes; returns the
  /// previous limit. A negative value queries without changing.
  static int setMemoryLimit(int bytes) => rt.setMemoryLimit(bytes);

  /// Sets the Go GC trigger percentage; returns the previous value.
  /// A negative value queries without changing.
  static int setGcPercent(int pct) => rt.setGcPercent(pct);
}
