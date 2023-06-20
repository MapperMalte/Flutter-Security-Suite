import 'dart:typed_data';

import 'package:chat_security/flutter_security_suite/m_511.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:uuid/uuid.dart';
import 'dart:math' as Math;

import '../cha_cha_20.dart';

void main() {

  final Uint32List rfc_7539_232_sample_state = Uint32List.fromList([
    0x61707865,  0x3320646e,  0x79622d32,  0x6b206574,
    0x03020100,  0x07060504  ,0x0b0a0908  ,0x0f0e0d0c,
    0x13121110,  0x17161514,  0x1b1a1918,  0x1f1e1d1c,
    0x00000001,  0x09000000,  0x4a000000,  0x00000000
  ]);

  final Uint32List rfc_7539_232_sample_state_expected_state_after_20_cha_cha_quarter_rounds = Uint32List.fromList([
    0x837778ab,  0xe238d763,  0xa67ae21e,  0x5950bb2f,
    0xc4f2d0c7,  0xfc62bb2f,  0x8fa018fc,  0x3f5ec7b7,
    0x335271c2,  0xf29489f3,  0xeabda8fc,  0x82e46ebd,
    0xd19c12b4,  0xb04e16de,  0x9e83d0cb,  0x4e3c50a2
  ]);

  final key = Uint32List.fromList([
    0x00, 0x11, 0x22, 0x33,
    0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff,
  ]);

  final nonce = Uint32List.fromList([
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
  ]);

  final input = Uint32List.fromList([
    0x00, 0x11, 0x22, 0x33,
    0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff,
  ]);

  double calculateEntropy(Uint8List bytes) {
    final byteCount = bytes.length;
    final frequencyMap = <int, int>{};

    for (var i = 0; i < byteCount; i++) {
      final byte = bytes[i];
      frequencyMap[byte] = (frequencyMap[byte] ?? 0) + 1;
    }

    final frequencies = frequencyMap.values;
    final totalBytes = frequencies.reduce((sum, count) => sum + count);
    final probabilities = frequencies.map((count) => count / totalBytes);
    final entropy = probabilities.fold(0.0, (double sum, double p) => sum - p * Math.log(p)/Math.ln2);

    return entropy;
  }

  test('BigInt to Uint32List and back to BigInt restores the original BigInt', () {
    BigInt randomInt = M511.randomBigInt(512);
    Uint32List uint32list = ChaCha20.convertBigIntToUint32List(randomInt);
    BigInt restoredInt = ChaCha20.convertUint32ListToBigInt(uint32list);
    expect(randomInt, restoredInt);
  });

  test('10 ChaCha20 Quarter Rounds give the 7539_232 sample state', () {
    {
      ChaCha20 chaCha20 = ChaCha20(rfc_7539_232_sample_state);
      chaCha20.tenQuarterRounds();
      expect(chaCha20.cha_cha_state, rfc_7539_232_sample_state_expected_state_after_20_cha_cha_quarter_rounds);
    }
  });

  test('ChaCha20 XOR encrypts a low-entropy-string to a high-entropy-string', (){
    BigInt password = M511.randomBigInt(256);
    String uuid = Uuid().v1();

    String aBunchOfAs = "";
    for(int i = 0; i < 5000; i++)
    {
      aBunchOfAs += "a";
    }
    Uint8List bytes = Uint8List.fromList(aBunchOfAs.codeUnits.toList());

    Uint8List output = ChaCha20.XORAndChaCha(
      bytes,
      password,
      uuid
    );

    double outputEntropy = calculateEntropy(output);
    double inputEntropy = calculateEntropy(bytes);
    double maximallyPossiblyOutputEntropy = 8; // 8 bytes is the output of a perfect equal distribution of output

    print("INPUT ENTROPY: "+inputEntropy.toString());
    print("OUTPUT ENTROPY: "+outputEntropy.toString());

    expect(inputEntropy, 0);
    expect(maximallyPossiblyOutputEntropy-outputEntropy, lessThan(0.05));
  });
}