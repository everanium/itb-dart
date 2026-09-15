// Surface-parity suite for the Dart binding: version / roster /
// profile round trips / stream sessions / error mapping / large
// payloads. The deep suite lives in Go under the shipped tree.

import 'dart:io';
import 'dart:typed_data';

import 'package:libitb3/itb.dart';
import 'package:test/test.dart';

/// Deterministic non-trivial payload (xorshift64 fill).
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

/// Cipher-surface profiles (the blob-only profile has no cipher
/// surface and is exercised in the error-mapping group).
const cipherProfiles = [
  'streaming-aead-triple-mac-v1',
  'streaming-noaead-triple-v1',
  'singlemsg-triple-mac-v1',
  'singlemsg-triple-nomac-v1',
  'streaming-aead-triple-mac-mixed-v1',
  'streaming-noaead-triple-mixed-v1',
  'singlemsg-triple-mac-mixed-v1',
  'singlemsg-triple-nomac-mixed-v1',
];

void main() {
  test('library version is reported', () {
    final v = Itb.version();
    expect(v, isNotEmpty);
    expect(v, contains('.'));
  });

  test('profiles list covers every cipher profile', () {
    for (final profile in cipherProfiles) {
      expect(Itb.profiles(), contains(profile));
    }
    expect(Itb.profiles(), contains('blob-triple-mac-v1'));
  });

  test('Single Message round trip (singlemsg-triple-mac-v1)', () {
    final sender = Itb.create('singlemsg-triple-mac-v1');
    final receiver = Itb.load(sender.save());
    // Empty input has no cover story in any cryptographic
    // construction (see triple/doc.go): every Pipeline cipher entry
    // point rejects nil / zero-length plaintext uniformly with
    // Status.badInput before any wire is produced. The symmetric
    // decrypt-side rejection guards the empty-wire parse.
    expect(
      () => sender.encryptMessage(Uint8List(0)),
      throwsA(isA<ItbException>()
          .having((e) => e.statusCode, 'statusCode', Status.badInput)),
    );
    expect(
      () => receiver.decryptMessage(Uint8List(0)),
      throwsA(isA<ItbException>()
          .having((e) => e.statusCode, 'statusCode', Status.badInput)),
    );
    for (final size in [1, 4 * 1024, 256 * 1024]) {
      final plain = payload(size, size + 1);
      final wire = sender.encryptMessage(plain);
      expect(wire, isNot(equals(plain)));
      expect(receiver.decryptMessage(wire), plain, reason: '@$size');
    }
    sender.free();
    receiver.free();
  });

  test('Single Message round trip across every cipher profile', () {
    for (final profile in cipherProfiles) {
      final sender = Itb.create(profile);
      final receiver = Itb.load(sender.save());
      final plain = payload(4 * 1024, profile.length);
      final wire = sender.encryptMessage(plain);
      expect(receiver.decryptMessage(wire), plain, reason: profile);
      sender.free();
      receiver.free();
    }
  });

  test('incremental stream round trip (streaming-noaead-triple-v1)', () {
    final sender = Itb.create('streaming-noaead-triple-v1');
    final receiver = Itb.load(sender.save());

    final plain = payload(512 * 1024, 7);
    final enc = sender.encryptStream();
    // Pathological batch split: 1 B, 4 KiB-ish odd strides, big tail.
    var off = 0;
    for (final n in [1, 4093, 65536, plain.length - 1 - 4093 - 65536]) {
      enc.write(Uint8List.sublistView(plain, off, off + n));
      off += n;
    }
    expect(off, plain.length);
    final wire = enc.drainAll();
    enc.free();
    expect(wire.length, greaterThan(plain.length));

    final dec = receiver.decryptStream();
    final got = BytesBuilder(copy: true);
    // Feed the wire in odd-sized slices, draining in between.
    final buf = Uint8List(64 * 1024);
    var woff = 0;
    while (woff < wire.length) {
      final n = (wire.length - woff).clamp(0, 10007);
      dec.write(Uint8List.sublistView(wire, woff, woff + n));
      woff += n;
      for (;;) {
        final r = dec.read(buf);
        if (r.n == 0) break;
        got.add(Uint8List.sublistView(buf, 0, r.n));
      }
    }
    got.add(dec.drainAll());
    dec.free();
    expect(got.takeBytes(), plain);

    sender.free();
    receiver.free();
  });

  test('stream pump round trip (streaming-aead-triple-mac-v1)', () {
    final sender = Itb.create('streaming-aead-triple-mac-v1');
    final receiver = Itb.load(sender.save());

    final plain = payload(256 * 1024, 11);
    final wire = BytesBuilder(copy: true);
    final enc = sender.encryptStream();
    enc.pump(
      [
        Uint8List.sublistView(plain, 0, 100 * 1024),
        Uint8List.sublistView(plain, 100 * 1024),
      ],
      wire.add,
    );
    enc.free();

    final back = BytesBuilder(copy: true);
    final dec = receiver.decryptStream();
    dec.pump([wire.takeBytes()], back.add);
    dec.free();
    expect(back.takeBytes(), plain);

    sender.free();
    receiver.free();
  });

  test('rekey refreshes the blob and the new blob opens', () {
    final sender = Itb.create('singlemsg-triple-mac-v1');
    final before = sender.save();
    sender.rekey(payload(32, 3), payload(32, 5));
    expect(sender.save(), isNot(equals(before)));
    final receiver = Itb.load(sender.save());
    final plain = payload(8 * 1024, 13);
    expect(receiver.decryptMessage(sender.encryptMessage(plain)), plain);
    sender.free();
    receiver.free();
  });

  group('error mapping', () {
    test('unknown profile is UnknownProfile with a diagnostic', () {
      expect(
        () => Itb.create('no-such-profile'),
        throwsA(isA<ItbException>()
            .having((e) => e.statusCode, 'statusCode', Status.unknownProfile)
            .having((e) => e.toString(), 'message', isNotEmpty)),
      );
    });

    test('closed Pipeline reports TripleClosed', () {
      final pipe = Itb.create('singlemsg-triple-mac-v1');
      pipe.close();
      pipe.close(); // idempotent
      expect(
        () => pipe.encryptMessage(payload(16, 1)),
        throwsA(isA<ItbException>()
            .having((e) => e.statusCode, 'statusCode', Status.tripleClosed)),
      );
      pipe.free();
    });

    test('tampered Single Message wire fails to decrypt', () {
      final sender = Itb.create('singlemsg-triple-mac-v1');
      final receiver = Itb.load(sender.save());
      final wire = sender.encryptMessage(payload(64 * 1024, 17));

      // Position probe rather than a single bit flip: the over-sized
      // container carries CSPRNG residue in the non-payload area — a
      // flip landing inside the residue is architecturally inert and
      // the decrypt finishes clean. Probing evenly-spaced positions
      // makes the all-residue probability negligible.
      const probes = 32;
      final stride = (wire.length - 32) ~/ probes;
      var failures = 0;
      for (var probe = 0; probe < probes; probe++) {
        final tampered = Uint8List.fromList(wire);
        tampered[16 + probe * stride] ^= 0x01;
        try {
          receiver.decryptMessage(tampered);
        } on ItbException catch (e) {
          expect(e.statusCode, isNot(Status.ok));
          failures++;
        }
      }
      expect(failures, greaterThan(0),
          reason: 'no probe among $probes positions surfaced a failure');
      sender.free();
      receiver.free();
    });

    test('typed withInnerHashes overrides the profile constellation', () {
      // Base profile is a shipped single-primitive width-512 Single
      // Message profile; the per-call withInnerHashes override
      // rebinds all 8 slots to an alternate width-512 constellation
      // for one Pipeline pair without touching the shipped registry.
      final override = Opts().withInnerHashes(const [
        'areion512', 'blake2b512', 'areion512', 'blake2b512',
        'areion512', 'blake2b512', 'areion512', 'blake2b512',
      ]);
      final sender = Itb.create('singlemsg-triple-mac-v1', override);
      final receiver = Itb.load(sender.save());
      final plain = payload(2048, 43);
      expect(receiver.decryptMessage(sender.encryptMessage(plain)), plain);
      sender.free();
      receiver.free();
    });

    test('register profile round trip, duplicate name rejected', () {
      final profile = Profile(
        mode: 'singlemsg-nomac',
        width: 256,
        hashes: const [
          'blake3', 'blake2s', 'areion256', 'blake2b256',
          'chacha20', 'blake3', 'blake2s', 'areion256',
        ],
        keyBits: 1024,
        parallax: false,
        wrapper: false,
      );
      register('dart-binding-test-mixed', profile);

      final sender = Itb.create('dart-binding-test-mixed');
      final receiver = Itb.load(sender.save());
      final plain = payload(4 * 1024, 19);
      expect(receiver.decryptMessage(sender.encryptMessage(plain)), plain);
      sender.free();
      receiver.free();

      expect(
        () => register('dart-binding-test-mixed', profile),
        throwsA(isA<ItbException>()
            .having((e) => e.statusCode, 'statusCode', Status.profileExists)),
      );
    });
  });

  test('large plaintext exercises the pre-allocate + retry path', () {
    // > 1 MiB payload: the 1.25x + 65536 pre-allocation covers the
    // envelope for large payloads in one call; a tiny payload
    // (handled above) exercises the small-input expansion. Both must
    // round-trip byte-exact.
    final sender = Itb.create('singlemsg-triple-nomac-v1');
    final receiver = Itb.load(sender.save());
    final plain = payload(3 * 1024 * 1024 + 12345, 23);
    final wire = sender.encryptMessage(plain);
    expect(wire.length, greaterThan(plain.length));
    expect(receiver.decryptMessage(wire), plain);
    sender.free();
    receiver.free();
  });

  test('caller-buffer message round trip via encryptMessageInto', () {
    final sender = Itb.create('singlemsg-triple-nomac-v1');
    final receiver = Itb.load(sender.save());
    final plain = payload(256 * 1024 + 777, 29);
    final wireBuf = Uint8List(plain.length + (plain.length >> 2) + 65536);
    final backBuf = Uint8List(wireBuf.length);

    // Two rewrites of the same scratch pair must both round-trip
    // byte-exact (the buffers are reusable across calls).
    for (var round = 0; round < 2; round++) {
      final wn = sender.encryptMessageInto(plain, wireBuf);
      expect(wn, greaterThan(plain.length));
      expect(wn, lessThanOrEqualTo(wireBuf.length));
      final wire = Uint8List.sublistView(wireBuf, 0, wn);
      final pn = receiver.decryptMessageInto(wire, backBuf);
      expect(pn, plain.length);
      expect(Uint8List.sublistView(backBuf, 0, pn), plain);
    }

    // Matches the allocating sibling byte-for-byte on the decrypt
    // side: an encryptMessage wire decrypts through the caller-buffer
    // entry.
    final wire = sender.encryptMessage(plain);
    final pn = receiver.decryptMessageInto(wire, backBuf);
    expect(Uint8List.sublistView(backBuf, 0, pn), plain);

    // Cap-guard: a cap past the real buffer length is rejected
    // before any FFI dispatch.
    expect(
      () => sender.encryptMessageInto(plain, wireBuf, wireBuf.length + 1),
      throwsA(isA<ArgumentError>()),
    );
    // Undersized dst fails with bufferTooSmall — no retry on the
    // caller-buffer path.
    expect(
      () => sender.encryptMessageInto(plain, Uint8List(16)),
      throwsA(isA<ItbException>().having(
          (e) => e.statusCode, 'statusCode', Status.bufferTooSmall)),
    );
    sender.free();
    receiver.free();
  });

  test('stream read cap-guard and reusable drain scratch', () {
    final pipe = Itb.create('streaming-noaead-triple-v1');
    final dec = Itb.load(pipe.save());
    final plain = payload(1024 * 1024 + 321, 31);

    final enc = pipe.encryptStream();
    expect(
      () => enc.read(Uint8List(64), 65),
      throwsA(isA<ArgumentError>()),
    );
    enc.write(plain);
    final wire = BytesBuilder(copy: true);
    enc.end();
    // Drain through the pooled read path into one reusable scratch.
    final scratch = Uint8List(256 * 1024);
    for (;;) {
      final r = enc.read(scratch);
      if (r.n > 0) wire.add(Uint8List.sublistView(scratch, 0, r.n));
      if (r.finished) break;
    }
    enc.free();

    final back = dec.decryptStream();
    back.write(wire.takeBytes());
    expect(back.drainAll(), plain);
    back.free();
    pipe.free();
    dec.free();
  });

  group('persistence', () {
    final plain = payload(2048, 71);

    test('save then load round trip', () {
      final sender = Itb.create('singlemsg-triple-mac-v1');
      final blob = sender.save();
      expect(blob, isNotEmpty);
      expect(sender.save(), blob);
      final receiver = Itb.load(blob);
      expect(receiver.save(), blob);
      expect(receiver.decryptMessage(sender.encryptMessage(plain)), plain);
      sender.free();
      receiver.free();
    });

    test('saveF then loadF round trip', () {
      final dir = Directory.systemTemp.createTempSync('itb-dart-');
      try {
        final file = '${dir.path}/session.blob';
        final sender = Itb.create('streaming-aead-triple-mac-v1');
        sender.saveF(file);
        expect(File(file).readAsBytesSync(), sender.save());
        final receiver = Itb.loadF(file);
        expect(receiver.decryptStreamOneShot(sender.encryptStreamOneShot(plain)),
            plain);
        sender.free();
        receiver.free();
      } finally {
        dir.deleteSync(recursive: true);
      }
    });

    test('load with master override after rekey', () {
      final perm = Uint8List(32)..fillRange(0, 32, 0x33);
      final wrap = Uint8List(32)..fillRange(0, 32, 0x44);
      final sender = Itb.create('singlemsg-triple-mac-v1');
      final blob = sender.save();
      final rotated = sender.rekey(perm, wrap);
      expect(rotated, isNot(equals(blob)));
      expect(sender.save(), rotated);
      final receiver = Itb.load(blob, permMaster: perm, wrapMaster: wrap);
      expect(receiver.decryptMessage(sender.encryptMessage(plain)), plain);
      sender.free();
      receiver.free();
    });

    test('inspect reads the embedded record', () {
      final pipe = Itb.create('streaming-aead-triple-mac-v1');
      final prof = Itb.inspect(pipe.save());
      expect(prof.name, 'streaming-aead-triple-mac-v1');
      expect(prof.mode, 'streaming-aead');
      expect(prof.width, 512);
      // The recipe fields match the registry entry; the two
      // inspection-only fields separate the two records.
      final recipe = prof.copy()
        ..nonceBits = null
        ..barrierFill = null;
      expect(recipe, Itb.lookup('streaming-aead-triple-mac-v1'));
      pipe.free();
    });

    test('inspect carries the runtime globals, lookup does not', () {
      // Defaults: the blob records the compile-in nonce width and
      // barrier fill margin, and inspect surfaces both.
      final pipe = Itb.create('streaming-aead-triple-mac-v1');
      final prof = Itb.inspect(pipe.save());
      expect(prof.nonceBits, 512);
      expect(prof.barrierFill, 1);
      pipe.free();

      // Per-Pipeline overrides travel through the blob into inspect.
      final tuned = Itb.create('streaming-aead-triple-mac-v1',
          Opts().withNonceBits(256).withBarrierFill(4));
      final tunedProf = Itb.inspect(tuned.save());
      expect(tunedProf.nonceBits, 256);
      expect(tunedProf.barrierFill, 4);
      expect(tunedProf.toJson(), contains('"nonce_bits":256'));
      expect(tunedProf.toJson(), contains('"barrier_fill":4'));
      // copy() round-trips the two fields rather than dropping them.
      expect(tunedProf.copy().nonceBits, 256);
      tuned.free();

      // The registry entry is the recipe alone — neither field is
      // part of it, so both read as absent rather than as zero.
      final registry = Itb.lookup('streaming-aead-triple-mac-v1');
      expect(registry.nonceBits, isNull);
      expect(registry.barrierFill, isNull);
      expect(registry.toJson(), isNot(contains('nonce_bits')));
      expect(registry.toJson(), isNot(contains('barrier_fill')));
    });

    test('lookup of an unknown name is UnknownProfile', () {
      expect(
        () => Itb.lookup('no-such-profile'),
        throwsA(isA<ItbException>()
            .having((e) => e.statusCode, 'statusCode', Status.unknownProfile)),
      );
    });

    test('register a copy of a shipped profile', () {
      final copy = Itb.lookup('singlemsg-triple-nomac-v1')..name = '';
      Itb.register('dart-binding-test-copy', copy);
      final back = Itb.lookup('dart-binding-test-copy');
      expect(back.name, 'dart-binding-test-copy');
      expect(back.mode, copy.mode);
      expect(Itb.profiles(), contains('dart-binding-test-copy'));
      final sender = Itb.create('dart-binding-test-copy');
      final receiver = Itb.load(sender.save());
      expect(receiver.decryptMessage(sender.encryptMessage(plain)), plain);
      sender.free();
      receiver.free();
    });

    test('profile JSON codec round-trips', () {
      final p = Itb.lookup('streaming-aead-triple-mac-mixed-v1');
      expect(p.hashes, hasLength(8));
      expect(Profile.fromJson(p.toJson()), p);
    });

    test('maxWorkers clamps and a closed Pipeline reports TripleClosed', () {
      final pipe = Itb.create('singlemsg-triple-mac-v1', Opts().withMaxWorkers(-1));
      pipe.maxWorkers(2);
      pipe.maxWorkers(-1);
      pipe.maxWorkers(1000);
      expect(pipe.decryptMessage(pipe.encryptMessage(plain)), plain);
      pipe.close();
      expect(
        () => pipe.maxWorkers(2),
        throwsA(isA<ItbException>()
            .having((e) => e.statusCode, 'statusCode', Status.tripleClosed)),
      );
      pipe.free();
    });
  });
}
