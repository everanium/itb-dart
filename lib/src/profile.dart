// Typed view of the Triple profile record — the JSON object that
// ITB_Triple_Inspect / ITB_Triple_Lookup emit, ITB_Triple_Register
// accepts, and the session blob carries in its wrap-layer.

import 'dart:convert';

/// A Triple Pipeline profile record.
///
/// The record is a plain data holder plus a JSON codec over the keys
/// of the wire object. No semantic validation happens on the Dart
/// side — every field rule (mode names, width / hash agreement, key
/// sizes, palette shape, reserved name prefixes) is enforced by Go at
/// [register] / [Pipeline.load] time and surfaces as an
/// `ItbException`. Primitive / MAC / cipher names are opaque strings.
///
/// Encoding mirrors the Go codec: `mode`, `width`, `keybits`,
/// `wrapper`, `parallax` are always emitted; an empty string, zero
/// integer, or empty list is omitted. [hashes] carries either nothing
/// or exactly eight slot names in the order `[noise, lock, data1,
/// data2, data3, start1, start2, start3]`.
///
/// [nonceBits] and [barrierFill] are inspection-only. They are not
/// part of the profile recipe: `inspect` reads them from the blob's
/// runtime globals snapshot, while `lookup` leaves both null because
/// the registry entry never carries them. libitb3 rejects a `register`
/// payload that carries either key, so clear both before registering
/// an inspected record.
class Profile {
  Profile({
    this.name = '',
    this.mode = '',
    this.width = 0,
    this.hash = '',
    this.hashes = const [],
    this.keyBits = 0,
    this.mac = '',
    this.tagStub = 0,
    this.chunk = 0,
    this.wrapper = false,
    this.outer = '',
    this.parallax = false,
    this.palette = const [],
    this.segment = 0,
    this.nonceBits,
    this.barrierFill,
  });

  /// Registry handle (`name`); empty on an anonymous record.
  String name;

  /// Pipeline mode (`mode`), e.g. `streaming-aead`.
  String mode;

  /// Seed width in bits (`width`).
  int width;

  /// Uniform inner hash (`hash`); empty on a mixed profile.
  String hash;

  /// Eight-slot mixed constellation (`hashes`); empty on a uniform
  /// profile.
  List<String> hashes;

  /// Key material size in bits (`keybits`).
  int keyBits;

  /// On-wire nonce width in bits (`nonce_bits`), read from the blob's
  /// runtime globals. Inspection-only: non-null on a record from
  /// [Itb.inspect], null on one from [Itb.lookup] and on one built by
  /// hand. libitb3 rejects a register payload carrying the key.
  int? nonceBits;

  /// DRBG barrier fill margin (`barrier_fill`), read from the blob's
  /// runtime globals. Same inspection-only lifecycle as [nonceBits].
  int? barrierFill;

  /// MAC name (`mac`); empty on a No MAC profile.
  String mac;

  /// Tag stub size (`tagstub`); 0 when absent.
  int tagStub;

  /// Streaming chunk size (`chunk`); 0 when absent.
  int chunk;

  /// Whether the wrapper layer is on (`wrapper`).
  bool wrapper;

  /// Outer cipher name (`outer`); empty when absent.
  String outer;

  /// Whether the parallax layer is on (`parallax`).
  bool parallax;

  /// Parallax palette (`palette`); empty when absent.
  List<String> palette;

  /// Parallax segment size (`segment`); 0 when absent.
  int segment;

  /// The wire object as a map (omitted keys absent).
  Map<String, Object> toMap() => {
        if (name.isNotEmpty) 'name': name,
        'mode': mode,
        'width': width,
        if (hash.isNotEmpty) 'hash': hash,
        if (hashes.isNotEmpty) 'hashes': List<String>.of(hashes),
        'keybits': keyBits,
        if (nonceBits != null) 'nonce_bits': nonceBits!,
        if (barrierFill != null) 'barrier_fill': barrierFill!,
        if (mac.isNotEmpty) 'mac': mac,
        if (tagStub != 0) 'tagstub': tagStub,
        if (chunk != 0) 'chunk': chunk,
        'wrapper': wrapper,
        if (outer.isNotEmpty) 'outer': outer,
        'parallax': parallax,
        if (palette.isNotEmpty) 'palette': List<String>.of(palette),
        if (segment != 0) 'segment': segment,
      };

  /// Renders the record as the wire JSON object.
  String toJson() => jsonEncode(toMap());

  /// Decodes a wire JSON object into a record. Unknown keys are
  /// ignored here; the Go side is the strict decoder.
  factory Profile.fromJson(String json) =>
      Profile.fromMap(jsonDecode(json) as Map<String, dynamic>);

  /// Builds a record from a decoded wire object.
  factory Profile.fromMap(Map<String, dynamic> m) => Profile(
        name: (m['name'] as String?) ?? '',
        mode: (m['mode'] as String?) ?? '',
        width: (m['width'] as int?) ?? 0,
        hash: (m['hash'] as String?) ?? '',
        hashes: _strings(m['hashes']),
        keyBits: (m['keybits'] as int?) ?? 0,
        nonceBits: m['nonce_bits'] as int?,
        barrierFill: m['barrier_fill'] as int?,
        mac: (m['mac'] as String?) ?? '',
        tagStub: (m['tagstub'] as int?) ?? 0,
        chunk: (m['chunk'] as int?) ?? 0,
        wrapper: (m['wrapper'] as bool?) ?? false,
        outer: (m['outer'] as String?) ?? '',
        parallax: (m['parallax'] as bool?) ?? false,
        palette: _strings(m['palette']),
        segment: (m['segment'] as int?) ?? 0,
      );

  /// A copy of the record (lists included).
  Profile copy() => Profile.fromMap(toMap());

  static List<String> _strings(Object? v) =>
      v is List ? v.map((e) => e.toString()).toList() : const [];

  @override
  String toString() => 'Profile${toJson()}';

  @override
  bool operator ==(Object other) => other is Profile && other.toJson() == toJson();

  @override
  int get hashCode => toJson().hashCode;
}

/// Decodes a JSON array of strings (the `ITB_Triple_Profiles`
/// output).
List<String> stringsFromJson(String json) =>
    (jsonDecode(json) as List).map((e) => e.toString()).toList();
