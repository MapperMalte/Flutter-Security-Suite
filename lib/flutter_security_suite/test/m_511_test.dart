import 'package:flutter_test/flutter_test.dart';

import '../m_511.dart';

void main() {
  test('A random BigInt has expected amount of bits', () {
    expect(M511.randomBigInt(4096).bitLength, 4096);
  });

  test('Two random Big Ints are different', () {
    BigInt alice_secret = M511.randomBigInt(4096);
    BigInt bob_secret = M511.randomBigInt(4096);

    expect(alice_secret, isNot(bob_secret));
  });

  test('Alice and Bob have different public keys', () {
    BigInt alice_secret = M511.randomBigInt(4096);
    BigInt bob_secret = M511.randomBigInt(4096);

    EllipticCurvePoint alicePublicKey = M511.multiply(M511.secureBasePoint, alice_secret);
    EllipticCurvePoint bobPublicKey = M511.multiply(M511.secureBasePoint, bob_secret);

    expect(alicePublicKey.x, isNot(bobPublicKey.x));
    expect(alicePublicKey.y, isNot(bobPublicKey.y));
  });

  test('Alice and Bob compute the same secret', () {
    BigInt alice_secret = M511.randomBigInt(4096);
    BigInt bob_secret = M511.randomBigInt(4096);

    print("ALICE RANDOM NUMBER: "+alice_secret.toString());
    print("BOB RANDOM NUMBER: "+bob_secret.toString());

    EllipticCurvePoint alicePublicKey = M511.multiply(M511.secureBasePoint, alice_secret);
    EllipticCurvePoint bobPublicKey = M511.multiply(M511.secureBasePoint, bob_secret);

    print("ALICE PUBLIC KEY: "+alicePublicKey.x.toRadixString(16)+"/"+alicePublicKey.y.toRadixString(16));
    print("BOB PUBLIC KEY: "+bobPublicKey.x.toRadixString(16)+"/"+bobPublicKey.y.toRadixString(16));

    EllipticCurvePoint aliceComputesSharedSecret = M511.multiply(bobPublicKey, alice_secret);
    EllipticCurvePoint bobComputesSharedSecret = M511.multiply(alicePublicKey, bob_secret);
    print("ALICE SHARED SECRET: "+bobComputesSharedSecret.x.toString());
    print("BOB SHARED SECRET: "+bobComputesSharedSecret.x.toString());

    expect(aliceComputesSharedSecret.x, bobComputesSharedSecret.x);
  });
}