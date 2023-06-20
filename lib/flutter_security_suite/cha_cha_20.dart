import 'dart:io';
import 'dart:typed_data';
import 'package:chat_security/flutter_security_suite/security_utils.dart';
import 'package:crypto/crypto.dart';


Future<List<Uint8List>> chachaXOR(
  List<String> filePaths,
  List<BigInt> passwords,
  List<String> fileUUIDs
) async {
  List<Uint8List> outputBytesList = [];
  for(int i = 0; i < filePaths.length; i++)
  {
    File file = File(filePaths[i]);
    if (await file.exists()) {
      Uint8List inputBytes = await file.readAsBytes();
      outputBytesList.add(ChaCha20.XORAndChaCha(
          inputBytes,
          passwords[i],
          fileUUIDs[i]
      ));
    } else {
      throw Exception('File not found');
    }
  }
  return outputBytesList;
}

Future<List<Uint8List>> encryptFilesWithChaCha20(
    List<String> filePaths,
    List<BigInt> passwords,
    List<String> fileUUIDs
    ) async {
  return chachaXOR(filePaths,passwords,fileUUIDs);
}

Future<List<Uint8List>> decryptFilesWithChaCha20(
    List<String> filePaths,
    List<BigInt> passwords,
    List<String> fileUUIDs
    ) async {
  return chachaXOR(filePaths,passwords,fileUUIDs);
}

class ChaCha20
{
  /// KEEP IN MIND:
  /// Each Nonce may only be used EXACTLY ONCE .. if you reuse a nonce, you will leak entropy.
  /// It should be random, but it does NOT have to be SECRET.
  /// It's perfectly fine if an attacker knows how a nonce is made, as long as your password is private and
  /// you don't reuse the nonce.
  /// If you associate a unique UUID to each file/message/whatever you want to encrypt/decrypt,
  /// you can ensure this.
  static Uint8List XORAndChaCha(Uint8List inputBytes, BigInt password, String uuidForNonce)
  {
    ChaCha20 chaCha20 = ChaCha20(
        ChaCha20.makeChaChaState(
            SecurityUtils.convertBigIntToUint32List(password),
            0,
            SecurityUtils.convertToNonce(uuidForNonce)
        )
    );

    Uint8List outputBytes = Uint8List(inputBytes.length);
    chaCha20.cha_cha_20();
    Uint8List nextChaChaBytes = chaCha20.cha_cha_state.buffer.asUint8List();
    for(int j = 0; j < outputBytes.length; j++)
    {
      outputBytes[j] = inputBytes[j] ^ nextChaChaBytes[j%64];
      if ( j%64 == 0 )
      {
        chaCha20.cha_cha_20();
        nextChaChaBytes = chaCha20.cha_cha_state.buffer.asUint8List();
      }
    }

    return outputBytes;
  }

  static List<int> magicConstants = [
    0x61707865, 0x3320646e,
    0x79622d32, 0x6b206574
  ];
  Uint32List cha_cha_state;


  static Uint32List makeChaChaState(Uint32List key, int blockCounter, Uint32List nonce)
  {
    assert(key.length == 8);
    assert(nonce.length == 3);
    return Uint32List.fromList([
      magicConstants[0], magicConstants[1], magicConstants[2], magicConstants[3],
      key[0], key[1], key[2], key[3],
      key[4], key[5], key[6], key[7],
      blockCounter, nonce[0], nonce[1], nonce[2]
    ]);
  }

  ChaCha20(this.cha_cha_state);

  int rotateLeft(int n, int count) {
    assert(count >= 0 && count < 32);
    if (count == 0) return n;
    return (n << count) | ((n >= 0) ? n >> (32 - count) : ~(~n >> (32 - count)));
  }

  void tenQuarterRounds()
  {
    for(int i = 0; i < 10; i++)
    {
      quarterRound(0, 4, 8, 12);
      quarterRound(1, 5, 9, 13);
      quarterRound(2, 6, 10, 14);
      quarterRound(3, 7, 11, 15);
      quarterRound(0, 5, 10, 15);
      quarterRound(1, 6, 11, 12);
      quarterRound(2, 7, 8, 13);
      quarterRound(3, 4, 9, 14);
    }
  }
  void cha_cha_20(){
    Uint32List initialStateCopy = Uint32List.fromList(cha_cha_state.toList());
    tenQuarterRounds();

    for(int i = 0; i < cha_cha_state.length; i++)
    {
      cha_cha_state[i] += initialStateCopy[i];
    }
  }

  Uint32List transformFourInputsByChaChaQuarterRound(Uint32List fourInputs)
  {
    fourInputs[0] += fourInputs[1];
    fourInputs[3] ^= fourInputs[0];
    fourInputs[3] = rotateLeft(fourInputs[3],16);

    fourInputs[2] += fourInputs[3];
    fourInputs[1] ^= fourInputs[2];
    fourInputs[1] = rotateLeft(fourInputs[1],12);

    fourInputs[0] += fourInputs[1];
    fourInputs[3] ^= fourInputs[0];
    fourInputs[3] = rotateLeft(fourInputs[3],8);

    fourInputs[2] += fourInputs[3];
    fourInputs[1] ^= fourInputs[2];
    fourInputs[1] = rotateLeft(fourInputs[1],7);

    return fourInputs;
  }

  void quarterRound(int a, int b, int c, int d)
  {
    Uint32List result = transformFourInputsByChaChaQuarterRound(Uint32List.fromList([
      cha_cha_state[a],
      cha_cha_state[b],
      cha_cha_state[c],
      cha_cha_state[d]
    ]));
    cha_cha_state[a] = result[0];
    cha_cha_state[b] = result[1];
    cha_cha_state[c] = result[2];
    cha_cha_state[d] = result[3];
  }
}