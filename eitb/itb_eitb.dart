// eitb — command-line demonstrator for the ITB Dart binding.
//
// Subcommands:
//
//   eitb version                                   library + binding versions
//   eitb profiles                                  registered profile catalogue
//   eitb encrypt <profile> <in-file> <out-file>    Single Message encrypt
//   eitb decrypt <profile> <blob-hex> <in-file> <out-file>
//
// `encrypt` prints the session blob to stderr as hex; feed that hex
// back to `decrypt` on the receiving side. `profiles` lists the
// registered profile catalogue one name per line; the profiles that
// carry a cipher surface are the ones `encrypt` / `decrypt` accept.

import 'dart:io';
import 'dart:typed_data';

import 'package:libitb3/itb.dart';

const String _usage = 'usage: eitb version\n'
    '       eitb profiles\n'
    '       eitb encrypt <profile> <in-file> <out-file>\n'
    '       eitb decrypt <profile> <blob-hex> <in-file> <out-file>';

Never usage() {
  stderr.writeln(_usage);
  exit(2);
}

void cmdVersion() {
  print('libitb3 ${Itb.version()}');
  print('itb-dart $bindingVersion');
}

void cmdProfiles() {
  for (final p in Itb.profiles()) {
    print(p);
  }
}

String _hex(Uint8List bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

Uint8List _unhex(String s) {
  if (s.length % 2 != 0 || RegExp('[^0-9a-fA-F]').hasMatch(s)) {
    throw const FormatException('blob hex is malformed');
  }
  final out = Uint8List(s.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(s.substring(2 * i, 2 * i + 2), radix: 16);
  }
  return out;
}

// Profiles whose canonical name begins with "streaming-" route
// through the one-shot streaming buffered pair instead of the Single
// Message pair.
bool _isStreamingProfile(String profile) => profile.startsWith('streaming-');

// Recursively create the parent directory of [path] (mkdir -p).
void _ensureParentDir(String path) {
  final parent = File(path).parent;
  if (!parent.existsSync()) {
    parent.createSync(recursive: true);
  }
}

void cmdEncrypt(String profile, String infile, String outfile) {
  final plain = File(infile).readAsBytesSync();
  final pipe = Itb.create(profile);
  final wire = _isStreamingProfile(profile)
      ? pipe.encryptStreamOneShot(plain)
      : pipe.encryptMessage(plain);
  _ensureParentDir(outfile);
  File(outfile).writeAsBytesSync(wire);
  stderr.writeln(_hex(pipe.save()));
  print('encrypted $infile -> $outfile '
      '(${plain.length} -> ${wire.length} bytes)');
  pipe.free();
}

void cmdDecrypt(String profile, String blobHex, String infile, String outfile) {
  final blob = _unhex(blobHex);
  final wire = File(infile).readAsBytesSync();
  final pipe = Itb.load(blob);
  final plain = _isStreamingProfile(profile)
      ? pipe.decryptStreamOneShot(wire)
      : pipe.decryptMessage(wire);
  _ensureParentDir(outfile);
  File(outfile).writeAsBytesSync(plain);
  print('decrypted $infile -> $outfile '
      '(${wire.length} -> ${plain.length} bytes)');
  pipe.free();
}

void main(List<String> args) {
  Itb.setMemoryLimit(4 << 30);
  Itb.setGcPercent(100);
  try {
    switch (args.isEmpty ? '' : args[0]) {
      case 'version':
        cmdVersion();
      case 'profiles':
        cmdProfiles();
      case 'encrypt':
        if (args.length != 4) usage();
        cmdEncrypt(args[1], args[2], args[3]);
      case 'decrypt':
        if (args.length != 5) usage();
        cmdDecrypt(args[1], args[2], args[3], args[4]);
      default:
        usage();
    }
  } on Exception catch (e) {
    stderr.writeln('eitb: $e');
    exit(1);
  }
}
