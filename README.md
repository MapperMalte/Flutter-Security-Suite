<!--

ChaCha20 is a fast encryption algorithm.
M-511 is a very good elliptic curve for Elliptic Key Diffie Hellman.

Together, they provide a good security framework.

## Usage

Alice and Bob create random Big Integers.

From this and M511 they can create a public/private key-pair.

Alice's public key and Bob's private key will compute the same shared secret as
Bob's public key and Alice's private key.

```dart
    BigInt alice_secret = M511.randomBigInt(4096);
    BigInt bob_secret = M511.randomBigInt(4096);

    EllipticCurvePoint alicePublicKey = M511.multiply(M511.secureBasePoint, alice_secret);
    EllipticCurvePoint bobPublicKey = M511.multiply(M511.secureBasePoint, bob_secret);

    EllipticCurvePoint aliceComputesSharedSecret = M511.multiply(bobPublicKey, alice_secret);
    EllipticCurvePoint bobComputesSharedSecret = M511.multiply(alicePublicKey, bob_secret);
```

This password can then be used for symmetric encryption using ChaCha20.

ChaCha20 requires a 256-bit password and a 96-bit nonce.
The nonce should NEVER be used twice and be random in the sense of high-entropy.
It is okay, however, if an attacker knows how the nonce is made,
as long as the key is private.

If you assign, for example, each file you want to encrypt and decrypt with a UUID,
you can use that UUID to generate pseudo-random nonce.

Technically, ChaCha20 produces a bunch of deterministic "random number" from an input that 
encrypts/decrypts the input by XOR-ing its bytes with the ChaCha20 bytes

```dart
    BigInt password = M511.randomBigInt(256);
    String uuid = Uuid().v1();
    Uint8List bytes = Uint8List.fromList("SOME TEXT YOU WANT TO ENCRYPT".codeUnits.toList());
    Uint8List output = ChaCha20.XORAndChaCha(
      bytes,
      password,
      uuid
    );
```

## TO DO

* Clean up the code
* Speed could be improved
* randomBigInt does not always produce the desired length of bits.