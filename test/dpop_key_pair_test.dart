import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:dpop_client/dpop_client.dart';
import 'package:test/test.dart';

import 'golden_key.dart';

void main() {
  test('generate produces a usable P-256 pair', () {
    final pair = DPoPKeyPair.generate();
    expect(pair.privateKeyPem, contains('BEGIN EC PRIVATE KEY'));
    expect(pair.publicKeyPem, contains('BEGIN PUBLIC KEY'));
  });

  test('generate produces a different pair each time', () {
    expect(
      DPoPKeyPair.generate().thumbprint,
      isNot(DPoPKeyPair.generate().thumbprint),
    );
  });

  group('round-tripping through PEM', () {
    test('fromPrivateKeyPem derives the same public key', () {
      final original = DPoPKeyPair.generate();
      final restored = DPoPKeyPair.fromPrivateKeyPem(original.privateKeyPem);

      expect(restored.publicKeyPem, original.publicKeyPem);
      expect(restored.jwk, original.jwk);
      expect(restored.thumbprint, original.thumbprint);
    });

    test('fromPem restores both halves', () {
      final original = DPoPKeyPair.generate();
      final restored = DPoPKeyPair.fromPem(
        privateKeyPem: original.privateKeyPem,
        publicKeyPem: original.publicKeyPem,
      );

      expect(restored.thumbprint, original.thumbprint);
      expect(restored.privateKeyPem, original.privateKeyPem);
    });

    test('fromPrivateKeyPem rejects a PEM it cannot read', () {
      expect(
        () => DPoPKeyPair.fromPrivateKeyPem('not a pem'),
        throwsA(anything),
      );
    });
  });

  group('jwk', () {
    test('carries the public EC parameters and nothing private', () {
      final jwk = DPoPKeyPair.generate().jwk;

      expect(jwk['kty'], 'EC');
      expect(jwk['crv'], 'P-256');
      expect(jwk['alg'], 'ES256');
      expect(jwk['use'], 'sig');
      expect(jwk.keys, isNot(contains('d')));
    });

    test('encodes x and y as 32-byte unpadded base64url', () {
      final jwk = DPoPKeyPair.generate().jwk;

      for (final field in <String>['x', 'y']) {
        final value = jwk[field]!;
        expect(value, isNot(contains('=')), reason: '$field is padded');
        expect(value, isNot(contains('+')), reason: '$field is not base64url');
        expect(value, isNot(contains('/')), reason: '$field is not base64url');
        expect(base64Url.decode(base64Url.normalize(value)), hasLength(32));
      }
    });

    test('jwkJson is the JWK as compact JSON', () {
      final pair = DPoPKeyPair.generate();
      expect(jsonDecode(pair.jwkJson), pair.jwk);
      expect(pair.jwkJson, isNot(contains(' ')));
    });
  });

  group('derived values are cached', () {
    test('the same instances come back on every read', () {
      // Every proof reads these; recomputing them per request was most of the
      // cost of signing one.
      final pair = DPoPKeyPair.generate();

      expect(identical(pair.jwk, pair.jwk), isTrue);
      expect(identical(pair.privateKeyPem, pair.privateKeyPem), isTrue);
      expect(identical(pair.thumbprint, pair.thumbprint), isTrue);
    });

    test('the shared jwk cannot be mutated by a caller', () {
      final pair = DPoPKeyPair.generate();

      expect(() => pair.jwk['x'] = 'tampered', throwsUnsupportedError);
      expect(() => pair.jwk.remove('kty'), throwsUnsupportedError);
    });
  });

  group('thumbprint', () {
    test('is the RFC 7638 hash of the four required members', () {
      final pair = DPoPKeyPair.generate();
      final jwk = pair.jwk;

      // Recomputed independently: the required members only, ordered
      // lexicographically, no whitespace.
      final canonical =
          '{"crv":"${jwk['crv']}","kty":"${jwk['kty']}",'
          '"x":"${jwk['x']}","y":"${jwk['y']}"}';
      final expected = base64Url
          .encode(sha256.convert(utf8.encode(canonical)).bytes)
          .replaceAll('=', '');

      expect(pair.thumbprint, expected);
    });

    test('is pinned for a fixed key', () {
      // A regression guard on the canonical form: change the member ordering,
      // the whitespace or the encoding and this value moves.
      final pair = DPoPKeyPair.fromPrivateKeyPem(goldenPrivateKeyPem);

      expect(pair.thumbprint, goldenThumbprint);
      expect(pair.jwk['x'], goldenX);
      expect(pair.jwk['y'], goldenY);
    });

    test('is stable across restores and unpadded', () {
      final pair = DPoPKeyPair.generate();
      expect(pair.thumbprint, pair.thumbprint);
      expect(pair.thumbprint, isNot(contains('=')));
      expect(
        base64Url.decode(base64Url.normalize(pair.thumbprint)),
        hasLength(32),
      );
    });
  });
}
