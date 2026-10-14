// Tests for the PEM layer that replaced `basic_utils` in 2.0.0.
//
// The encoders are pinned against PEMs OpenSSL produced for the same key, so
// a regression here shows up as a diff against another implementation rather
// than only as a round-trip that still agrees with itself.
import 'dart:convert';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart' as jwt;
import 'package:dpop_client/dpop_client.dart';
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/curves/prime256v1.dart';
import 'package:test/test.dart';

import 'golden_key.dart';

/// The DER inside a PEM's armour.
Uint8List derOf(String pem) => base64.decode(
  pem
      .split(RegExp(r'\r?\n'))
      .where(
        (String line) => !line.startsWith('-----') && line.trim().isNotEmpty,
      )
      .join(),
);

/// The `privateKey` OCTET STRING of a SEC 1 `ECPrivateKey`.
Uint8List sec1ScalarOf(String pem) {
  final seq = ASN1Parser(derOf(pem)).nextObject() as ASN1Sequence;
  return (seq.elements[1] as ASN1OctetString).octets;
}

void main() {
  group('encoding matches OpenSSL', () {
    final pair = DPoPKeyPair.fromPrivateKeyPem(goldenPrivateKeyPem);

    test('the SEC 1 private PEM round-trips byte for byte', () {
      expect(pair.privateKeyPem, goldenPrivateKeyPem);
    });

    test('the SPKI public PEM matches openssl ec -pubout', () {
      expect(pair.publicKeyPem, goldenPublicKeyPem);
    });

    test('an independent parser reads the private PEM we emit', () {
      // dart_jsonwebtoken's own PEM parser, not ours.
      expect(() => jwt.ECPrivateKey(pair.privateKeyPem), returnsNormally);
      expect(() => jwt.ECPublicKey(pair.publicKeyPem), returnsNormally);
    });
  });

  group('PKCS#8 input', () {
    test('is accepted and yields the same key', () {
      final fromPkcs8 = DPoPKeyPair.fromPrivateKeyPem(goldenPkcs8PrivateKeyPem);

      expect(fromPkcs8.thumbprint, goldenThumbprint);
      expect(fromPkcs8.privateKeyPem, goldenPrivateKeyPem);
    });
  });

  group('PEM bundles', () {
    test('an EC PARAMETERS block ahead of the key is skipped', () {
      // What `openssl ecparam -name prime256v1 -genkey` writes.
      final bundle =
          '-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n'
          '-----END EC PARAMETERS-----\n$goldenPrivateKeyPem\n';

      expect(
        DPoPKeyPair.fromPrivateKeyPem(bundle).thumbprint,
        goldenThumbprint,
      );
    });
  });

  group('RFC 5915 scalar width', () {
    // RFC 5915 §3 fixes the privateKey OCTET STRING at the curve's octet
    // length. A minimal encoding — what a scalar with a leading zero byte
    // produces, roughly one key in 256 — is what strict parsers reject.
    test('a scalar with a leading zero byte is padded to 32 octets', () {
      final params = ECCurve_prime256v1();
      // 248 bits: the top octet is zero, so a minimal encoding is 31 bytes.
      final d = BigInt.parse('00ff${'a' * 60}', radix: 16);
      expect(d.bitLength, 248, reason: 'fixture must have a zero top octet');

      final pair = DPoPKeyPair(
        privateKey: ECPrivateKey(d, params),
        publicKey: ECPublicKey(params.G * d, params),
      );

      expect(sec1ScalarOf(pair.privateKeyPem), hasLength(32));
      expect(sec1ScalarOf(pair.privateKeyPem).first, 0);
    });

    test('a padded scalar still restores to the same key', () {
      final params = ECCurve_prime256v1();
      final d = BigInt.parse('00ff${'a' * 60}', radix: 16);
      final original = DPoPKeyPair(
        privateKey: ECPrivateKey(d, params),
        publicKey: ECPublicKey(params.G * d, params),
      );

      final restored = DPoPKeyPair.fromPrivateKeyPem(original.privateKeyPem);

      expect(restored.privateKey.d, d);
      expect(restored.thumbprint, original.thumbprint);
    });

    test('every generated key encodes a 32-octet scalar', () {
      for (int i = 0; i < 40; i++) {
        expect(
          sec1ScalarOf(DPoPKeyPair.generate().privateKeyPem),
          hasLength(32),
        );
      }
    });
  });

  group('unsupported curves are refused', () {
    test('a P-384 private key is rejected, not reinterpreted', () {
      expect(
        () => DPoPKeyPair.fromPrivateKeyPem(p384PrivateKeyPem),
        throwsA(isA<FormatException>()),
      );
    });

    test('a secp256k1 public key is rejected', () {
      // Same field size as P-256, so only the curve OID tells them apart.
      expect(
        () => DPoPKeyPair.fromPem(
          privateKeyPem: goldenPrivateKeyPem,
          publicKeyPem: secp256k1PublicKeyPem,
        ),
        throwsA(isA<FormatException>()),
      );
    });
  });

  group('malformed input', () {
    test('a non-PEM string is rejected', () {
      expect(
        () => DPoPKeyPair.fromPrivateKeyPem('not a pem'),
        throwsA(isA<FormatException>()),
      );
    });

    test('an empty PEM body is rejected', () {
      expect(
        () => DPoPKeyPair.fromPrivateKeyPem(
          '-----BEGIN EC PRIVATE KEY-----\n-----END EC PRIVATE KEY-----',
        ),
        throwsA(isA<FormatException>()),
      );
    });

    test('a PEM whose body is not base64 is rejected', () {
      expect(
        () => DPoPKeyPair.fromPrivateKeyPem(
          '-----BEGIN EC PRIVATE KEY-----\n!!!!\n-----END EC PRIVATE KEY-----',
        ),
        throwsA(isA<FormatException>()),
      );
    });
  });

  group('mismatched halves', () {
    test('fromPem rejects a public key belonging to another private key', () {
      // Silently accepting this produces proofs whose embedded JWK cannot
      // verify their own signature — a failure the server reports only as a
      // flat rejection.
      expect(
        () => DPoPKeyPair.fromPem(
          privateKeyPem: goldenPrivateKeyPem,
          publicKeyPem: DPoPKeyPair.generate().publicKeyPem,
        ),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('fromPem accepts halves that do belong together', () {
      expect(
        DPoPKeyPair.fromPem(
          privateKeyPem: goldenPrivateKeyPem,
          publicKeyPem: goldenPublicKeyPem,
        ).thumbprint,
        goldenThumbprint,
      );
    });
  });
}
