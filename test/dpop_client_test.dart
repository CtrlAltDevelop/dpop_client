import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart' as jwt;
import 'package:dpop_client/dpop_client.dart';
import 'package:test/test.dart';

import 'golden_key.dart';

/// Decodes a JWT's header without verifying it, the way a server would before
/// picking a key.
Map<String, dynamic> headerOf(String token) => jsonDecode(
  utf8.decode(base64Url.decode(base64Url.normalize(token.split('.').first))),
) as Map<String, dynamic>;

/// Decodes a JWT's payload without verifying it.
Map<String, dynamic> payloadOf(String token) => jsonDecode(
  utf8.decode(base64Url.decode(base64Url.normalize(token.split('.')[1]))),
) as Map<String, dynamic>;

void main() {
  final pair = DPoPKeyPair.fromPrivateKeyPem(goldenPrivateKeyPem);
  final client = DPoPClient(pair);
  final url = Uri.parse('https://api.example.com/v1/orders');

  group('JWT header', () {
    test('is typed dpop+jwt and signed ES256', () {
      final header = headerOf(
        client.createProof(url: url, method: 'GET').token,
      );

      expect(header['typ'], 'dpop+jwt');
      expect(header['alg'], 'ES256');
    });

    test('publishes the public JWK, with no private parameter', () {
      final header = headerOf(
        client.createProof(url: url, method: 'GET').token,
      );
      final embedded = header['jwk'] as Map<String, dynamic>;

      expect(embedded['kty'], 'EC');
      expect(embedded['crv'], 'P-256');
      expect(embedded['x'], goldenX);
      expect(embedded['y'], goldenY);
      expect(embedded.keys, isNot(contains('d')));
    });
  });

  group('signature', () {
    test('verifies against the public key', () {
      final proof = client.createProof(url: url, method: 'GET');

      expect(
        // checkHeaderType is off because a DPoP proof is typed `dpop+jwt`,
        // which dart_jsonwebtoken's verifier rejects as "not a jwt".
        () => jwt.JWT.verify(
          proof.token,
          jwt.ECPublicKey(pair.publicKeyPem),
          checkHeaderType: false,
        ),
        returnsNormally,
      );
    });

    test('does not verify against a different key', () {
      final proof = client.createProof(url: url, method: 'GET');
      final other = DPoPKeyPair.generate();

      expect(
        () => jwt.JWT.verify(
          proof.token,
          jwt.ECPublicKey(other.publicKeyPem),
          checkHeaderType: false,
        ),
        throwsA(isA<jwt.JWTException>()),
      );
    });
  });

  group('htm', () {
    test('is the method, upper-cased', () {
      expect(
        payloadOf(client.createProof(url: url, method: 'post').token)['htm'],
        'POST',
      );
    });
  });

  group('htu', () {
    test('drops the query string', () {
      // RFC 9449 §4.2: htu carries no query part. The btcb gateway appends
      // ?lang= to every request, which makes this the failure mode to guard.
      final proof = client.createProof(
        url: Uri.parse('https://api.example.com/v1/orders?limit=20&lang=en'),
        method: 'GET',
      );

      expect(
        payloadOf(proof.token)['htu'],
        'https://api.example.com/v1/orders',
      );
    });

    test('drops the fragment', () {
      final proof = client.createProof(
        url: Uri.parse('https://api.example.com/v1/orders#section'),
        method: 'GET',
      );

      expect(
        payloadOf(proof.token)['htu'],
        'https://api.example.com/v1/orders',
      );
    });

    test('leaves no trailing separator behind', () {
      for (final raw in <String>[
        'https://api.example.com/v1/orders?limit=20',
        'https://api.example.com/v1/orders#x',
        'https://api.example.com/v1/orders?limit=20#x',
      ]) {
        final htu =
            payloadOf(
                  client.createProof(url: Uri.parse(raw), method: 'GET').token,
                )['htu']
                as String;

        expect(htu, isNot(endsWith('?')), reason: raw);
        expect(htu, isNot(contains('#')), reason: raw);
      }
    });

    test('keeps a non-default port and drops a redundant one', () {
      expect(
        payloadOf(
          client
              .createProof(
                url: Uri.parse('https://api.example.com:8443/v1/x'),
                method: 'GET',
              )
              .token,
        )['htu'],
        'https://api.example.com:8443/v1/x',
      );
      expect(
        payloadOf(
          client
              .createProof(
                url: Uri.parse('https://api.example.com:443/v1/x'),
                method: 'GET',
              )
              .token,
        )['htu'],
        'https://api.example.com/v1/x',
      );
    });

    test('preserves the path exactly, including a trailing slash', () {
      expect(
        payloadOf(
          client
              .createProof(
                url: Uri.parse('https://api.example.com/v1/orders/'),
                method: 'GET',
              )
              .token,
        )['htu'],
        'https://api.example.com/v1/orders/',
      );
    });
  });

  group('ath', () {
    test('is the unpadded base64url SHA-256 of the access token', () {
      const token = 'eyJhbGciOiJFUzI1NiJ9.stub-access-token';
      final proof = client.createProof(
        url: url,
        method: 'GET',
        accessToken: token,
      );

      expect(
        payloadOf(proof.token)['ath'],
        base64Url
            .encode(sha256.convert(utf8.encode(token)).bytes)
            .replaceAll('=', ''),
      );
      expect(payloadOf(proof.token)['ath'], isNot(contains('=')));
    });

    test('is absent when no access token is passed', () {
      expect(
        payloadOf(client.createProof(url: url, method: 'GET').token),
        isNot(contains('ath')),
      );
    });

    test('is absent for an empty access token', () {
      final proof = client.createProof(
        url: url,
        method: 'GET',
        accessToken: '',
      );

      expect(payloadOf(proof.token), isNot(contains('ath')));
    });
  });

  group('nonce', () {
    test('is included when the server has demanded one', () {
      final proof = client.createProof(
        url: url,
        method: 'GET',
        nonce: 'eyJ7S_zG.eyJIOjki.hSfMzSHA',
      );

      expect(payloadOf(proof.token)['nonce'], 'eyJ7S_zG.eyJIOjki.hSfMzSHA');
    });

    test('is absent when none was supplied, or an empty one was', () {
      expect(
        payloadOf(client.createProof(url: url, method: 'GET').token),
        isNot(contains('nonce')),
      );
      expect(
        payloadOf(client.createProof(url: url, method: 'GET', nonce: '').token),
        isNot(contains('nonce')),
      );
    });
  });

  group('iat', () {
    test('is truncated to whole seconds, never rounded up', () {
      // 999ms past the second: rounding would report the next second, which
      // puts iat in the future.
      final stamp = DateTime.fromMillisecondsSinceEpoch(1766500000999);
      final proof = client.createProof(
        url: url,
        method: 'GET',
        issuedAt: stamp,
      );

      expect(payloadOf(proof.token)['iat'], 1766500000);
      expect(proof.issuedAt.millisecondsSinceEpoch, 1766500000000);
    });

    test('defaults to now', () {
      final before = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      final iat =
          payloadOf(client.createProof(url: url, method: 'GET').token)['iat']
              as int;
      final after = DateTime.now().millisecondsSinceEpoch ~/ 1000;

      expect(iat, inInclusiveRange(before, after));
    });
  });

  group('jti', () {
    test('is fresh on every proof', () {
      final ids = <String>{
        for (int i = 0; i < 50; i++)
          client.createProof(url: url, method: 'GET').jwtId,
      };

      expect(ids, hasLength(50));
    });

    test('is reported on the proof and carried in the payload', () {
      final proof = client.createProof(url: url, method: 'GET');
      expect(payloadOf(proof.token)['jti'], proof.jwtId);
    });

    test('can be pinned for a test', () {
      final proof = client.createProof(
        url: url,
        method: 'GET',
        jwtId: 'fixed-id',
      );
      expect(payloadOf(proof.token)['jti'], 'fixed-id');
    });
  });

  group('DPoPProof', () {
    test('headers use the standard name by default', () {
      final proof = client.createProof(url: url, method: 'GET');
      expect(proof.headers(), <String, String>{'DPoP': proof.token});
    });

    test('headers accept a gateway-specific name', () {
      final proof = client.createProof(url: url, method: 'GET');
      expect(proof.headers(name: 'X-DPOP'), <String, String>{
        'X-DPOP': proof.token,
      });
    });

    test('reports the signing key thumbprint', () {
      expect(
        client.createProof(url: url, method: 'GET').thumbprint,
        goldenThumbprint,
      );
      expect(client.thumbprint, goldenThumbprint);
    });

    test('toString is the token, for direct interpolation', () {
      final proof = client.createProof(url: url, method: 'GET');
      expect('$proof', proof.token);
    });
  });

  test('the same request signed twice yields different proofs', () {
    // Distinct jti values, so a server that caches them rejects neither.
    final first = client.createProof(url: url, method: 'GET');
    final second = client.createProof(url: url, method: 'GET');

    expect(first.token, isNot(second.token));
  });
}
