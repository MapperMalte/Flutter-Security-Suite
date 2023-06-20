import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

class SecurityUtils
{
  static BigInt randomBigInt(int bitLength) {
    final random = Random.secure();
    final hexDigitCount = (bitLength / 4).ceil(); // Each hex digit represents 4 bits
    final buffer = StringBuffer();

    while (buffer.length < hexDigitCount) {
      buffer.write(random.nextInt(16).toRadixString(16));
    }

    // Add leading zeros if necessary to reach the desired bit length
    final hexString = buffer.toString().padLeft(hexDigitCount, '0');
    return BigInt.parse(hexString, radix: 16);
  }


  static int _concatFourBytesToInt32(int b3, int b2, int b1, int b0) {
    final int8List = new Int8List(4)
      ..[3] = b3
      ..[2] = b2
      ..[1] = b1
      ..[0] = b0;
    return int8List.buffer.asByteData().getInt32(0);
  }

  static Uint32List convertToNonce(String uuid)
  {
    Uint32List nonce = new Uint32List(3);
    List<int> hashed_uuid_bytes = sha256.convert(uuid.codeUnits).bytes;
    for(int i = 0; i < nonce.length; i++)
    {
      nonce[i] = (_concatFourBytesToInt32(
          hashed_uuid_bytes[0+i*4],
          hashed_uuid_bytes[1+i*4],
          hashed_uuid_bytes[2+i*4],
          hashed_uuid_bytes[3+i*4]
      ));
    }
    return nonce;
  }

  static Uint32List convertBigIntToUint32List(BigInt number) {
    final byteData = ByteData(4);

    final byteCount = (number.bitLength + 31) ~/ 32;
    final uint32List = Uint32List(byteCount);

    for (var i = 0; i < byteCount; i++) {
      byteData.setUint32(0, number.toUnsigned(32).toInt());
      uint32List[i] = byteData.getUint32(0);
      number = number >> 32;
    }

    return uint32List;
  }

  static BigInt convertUint32ListToBigInt(Uint32List uint32List) {
    BigInt number = BigInt.zero;

    for (var i = uint32List.length - 1; i >= 0; i--) {
      number = (number << 32) + BigInt.from(uint32List[i]);
    }

    return number;
  }
}