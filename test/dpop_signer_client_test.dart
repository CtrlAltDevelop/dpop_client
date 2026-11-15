import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart' as jwt;
import 'package:dpop_client/dpop_client.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:test/test.dart';

import 'golden_key.dart';

Map<String, dynamic> _segment(String token, int index) =>
    jsonDecode(
          utf8.decode(
            base64Url.decode(base64Url.normalize(token.split('.')[index])),
          ),
        )
        as Map<String, dynamic>;

Map<String, dynamic> headerOf(String token) => _segment(token, 0);
Map<String, dynamic> payloadOf(String token) => _segment(token, 1);

Uint8List _fixed32(BigInt value) {
  final Uint8List out = Uint8List(32);
  for (int i = 31; i >= 0; i--) {
    out[i] = (value & BigInt.from(0xff)).toInt();
    value >>= 8;
  }
  return out;
}

/// A signer that, like a WebCrypto or keystore key, only exposes the public
/// JWK (`kty`, `crv`, `x`, `y` and nothing else) and signs on request. It
/// signs with pointycastle directly rather than through the package, so a
/// verified proof is evidence for the package and not just for itself.
class FakeSigner implements DPoPSigner {
  FakeSigner(this._pair)
    : publicJwk = <String, String>{
        'kty': _pair.jwk['kty']!,
        'crv': _pair.jwk['crv']!,
        'x': _pair.jwk['x']!,
        'y': _pair.jwk['y']!,
      };

  final DPoPKeyPair _pair;

  int calls = 0;

  @override
  final Map<String, String> publicJwk;

  @override
  Future<Uint8List> sign(Uint8List message) async {
    calls++;
    final pc.Signer signer = pc.Signer('SHA-256/DET-ECDSA')
      ..init(true, pc.PrivateKeyParameter<pc.ECPrivateKey>(_pair.privateKey));
    final pc.ECSignature signature =
        signer.generateSignature(message) as pc.ECSignature;
    return Uint8List.fromList(<int>[
      ..._fixed32(signature.r),
      ..._fixed32(signature.s),
    ]);
  }
}

class ThrowingSigner implements DPoPSigner {
  ThrowingSigner(this.publicJwk);

  @override
  final Map<String, String> publicJwk;

  @override
  Future<Uint8List> sign(Uint8List message) async =>
      throw StateError('keystore locked');
}

class FixedSignatureSigner implements DPoPSigner {
  FixedSignatureSigner(this.publicJwk, this.signature);

  @override
  final Map<String, String> publicJwk;
  final Uint8List signature;

  @override
  Future<Uint8List> sign(Uint8List message) async => signature;
}

void main() {
  final pair = DPoPKeyPair.fromPrivateKeyPem(goldenPrivateKeyPem);
  final signer = FakeSigner(pair);
  final client = DPoPSignerClient(signer);
  final url = Uri.parse('https://api.example.com/v1/orders');

  group('signature', () {
    test('verifies against the signer\'s public JWK', () async {
      final proof = await client.createProof(url: url, method: 'GET');

      expect(
        () => jwt.JWT.verify(
          proof.token,
          jwt.ECPublicKey(pair.publicKeyPem),
          checkHeaderType: false,
        ),
        returnsNormally,
      );
      expect(signer.calls, 1);
    });

    test('publishes exactly the JWK the signer reports', () async {
      final proof = await client.createProof(url: url, method: 'GET');

      expect(headerOf(proof.token)['jwk'], signer.publicJwk);
      expect(proof.jwk, signer.publicJwk);
      expect(headerOf(proof.token)['typ'], 'dpop+jwt');
      expect(headerOf(proof.token)['alg'], 'ES256');
    });

    test('a key pair works as a signer', () async {
      final viaPair = DPoPSignerClient(pair);
      final proof = await viaPair.createProof(url: url, method: 'GET');

      expect(
        () => jwt.JWT.verify(
          proof.token,
          jwt.ECPublicKey(pair.publicKeyPem),
          checkHeaderType: false,
        ),
        returnsNormally,
      );
      expect(pair.publicJwk, pair.jwk);
    });
  });

  group('parity with DPoPClient', () {
    final issuedAt = DateTime.fromMillisecondsSinceEpoch(
      1700000000123,
      isUtc: true,
    );

    test('same inputs give the same header, claims and headers()', () async {
      final sync = DPoPClient(pair).createProof(
        url: Uri.parse('https://api.example.com:443/v1/orders?limit=20#x'),
        method: 'post',
        accessToken: 'token-123',
        nonce: 'nonce-abc',
        issuedAt: issuedAt,
        jwtId: 'fixed-jti',
      );
      final async = await DPoPSignerClient(pair).createProof(
        url: Uri.parse('https://api.example.com:443/v1/orders?limit=20#x'),
        method: 'post',
        accessToken: 'token-123',
        nonce: 'nonce-abc',
        issuedAt: issuedAt,
        jwtId: 'fixed-jti',
      );

      expect(headerOf(async.token), headerOf(sync.token));
      expect(payloadOf(async.token), payloadOf(sync.token));
      expect(async.headers(), sync.headers());
      expect(async.thumbprint, sync.thumbprint);
      expect(async.jwtId, sync.jwtId);
      expect(async.issuedAt, sync.issuedAt);
      expect(async.isTokenBound, isTrue);
    });
  });

  group('thumbprint', () {
    test('is the RFC 7638 thumbprint of the public JWK', () {
      expect(client.thumbprint, goldenThumbprint);
      expect(client.thumbprint, pair.thumbprint);
    });

    test('proof carries it', () async {
      final proof = await client.createProof(url: url, method: 'GET');

      expect(proof.thumbprint, goldenThumbprint);
    });
  });

  group('dpopThumbprint', () {
    test('equals DPoPKeyPair.thumbprint for the same key', () {
      expect(dpopThumbprint(pair.jwk), pair.thumbprint);
      expect(dpopThumbprint(FakeSigner(pair).publicJwk), pair.thumbprint);
    });

    test('matches the published RFC 9449 example', () {
      // RFC 9449 §4.1 gives the proof's JWK, and §6.1 the `cnf.jkt` of the
      // token bound to it. RFC 7638's own §3.1 example is an RSA key, which
      // this P-256 package does not accept, so this is the EC vector.
      expect(
        dpopThumbprint(const <String, String>{
          'kty': 'EC',
          'x': 'l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs',
          'y': '9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA',
          'crv': 'P-256',
        }),
        '0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I',
      );
    });

    test('ignores members outside the required four', () {
      expect(
        dpopThumbprint(<String, String>{
          ...pair.jwk,
          'ext': 'false',
          'key_ops': 'verify',
          'kid': 'abc',
        }),
        pair.thumbprint,
      );
    });

    test('refuses a JWK that is not a public P-256 key', () {
      final Map<String, String> base = Map.of(pair.jwk);

      for (final bad in <Map<String, String>>[
        {...base}..remove('x'),
        {...base}..remove('y'),
        {...base, 'kty': 'RSA'},
        {...base, 'crv': 'P-384'},
        {...base, 'd': 'c2VjcmV0'},
      ]) {
        expect(() => dpopThumbprint(bad), throwsArgumentError, reason: '$bad');
      }
    });
  });

  group('ws and wss', () {
    Future<String> htuOf(DPoPSignerClient c, String raw) async =>
        payloadOf(
              (await c.createProof(url: Uri.parse(raw), method: 'GET')).token,
            )['htu']
            as String;

    test('wss:443 drops the port and the query', () async {
      expect(
        await htuOf(client, 'wss://host.example.com:443/ws/sync?x=1'),
        'wss://host.example.com/ws/sync',
      );
    });

    test('ws:80 drops the port', () async {
      expect(
        await htuOf(client, 'ws://host.example.com:80/ws/sync'),
        'ws://host.example.com/ws/sync',
      );
    });

    test('keeps a port that is not the scheme\'s default', () async {
      expect(
        await htuOf(client, 'wss://host.example.com:8443/ws'),
        'wss://host.example.com:8443/ws',
      );
      expect(
        await htuOf(client, 'wss://host.example.com:80/ws'),
        'wss://host.example.com:80/ws',
      );
      expect(
        await htuOf(client, 'ws://host.example.com:443/ws'),
        'ws://host.example.com:443/ws',
      );
    });

    test('DPoPClient normalises them the same way', () {
      final sync = DPoPClient(pair);

      expect(
        payloadOf(
          sync
              .createProof(
                url: Uri.parse('wss://host.example.com:443/ws/sync?x=1'),
                method: 'GET',
              )
              .token,
        )['htu'],
        'wss://host.example.com/ws/sync',
      );
    });

    test('empty path becomes /', () async {
      expect(
        await htuOf(client, 'wss://host.example.com'),
        'wss://host.example.com/',
      );
    });
  });

  group('claims', () {
    test('ath is the unpadded base64url SHA-256 of the exact token', () async {
      const token = 'abc.def.ghi';
      final proof = await client.createProof(
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
      expect(proof.headers()['Authorization'], 'DPoP $token');
    });

    test('no token means no ath and no Authorization header', () async {
      final proof = await client.createProof(url: url, method: 'GET');

      expect(payloadOf(proof.token), isNot(contains('ath')));
      expect(proof.headers().keys, ['DPoP']);
      expect(proof.isTokenBound, isFalse);
    });

    test('nonce is omitted when null or empty', () async {
      for (final nonce in <String?>[null, '']) {
        final proof = await client.createProof(
          url: url,
          method: 'GET',
          nonce: nonce,
        );
        expect(payloadOf(proof.token), isNot(contains('nonce')));
      }
      final withNonce = await client.createProof(
        url: url,
        method: 'GET',
        nonce: 'n-1',
      );
      expect(payloadOf(withNonce.token)['nonce'], 'n-1');
    });

    test('iat is truncated and issuedAt overrides now', () async {
      final proof = await client.createProof(
        url: url,
        method: 'GET',
        issuedAt: DateTime.fromMillisecondsSinceEpoch(
          1700000000999,
          isUtc: true,
        ),
      );

      expect(payloadOf(proof.token)['iat'], 1700000000);
      expect(proof.issuedAt.millisecondsSinceEpoch, 1700000000000);
    });

    test('jti is fresh per proof, and jwtId overrides it', () async {
      final a = await client.createProof(url: url, method: 'GET');
      final b = await client.createProof(url: url, method: 'GET');
      final fixed = await client.createProof(
        url: url,
        method: 'GET',
        jwtId: 'mine',
      );

      expect(a.jwtId, isNot(b.jwtId));
      expect(payloadOf(a.token)['jti'], a.jwtId);
      expect(payloadOf(fixed.token)['jti'], 'mine');
    });

    test('htu drops query, fragment and userinfo', () async {
      final proof = await client.createProof(
        url: Uri.parse('https://u:p@api.example.com/v1/x?a=1#f'),
        method: 'GET',
      );

      expect(payloadOf(proof.token)['htu'], 'https://api.example.com/v1/x');
    });

    test('rejects a URL that is not absolute, without signing', () async {
      final before = signer.calls;

      await expectLater(
        client.createProof(url: Uri.parse('/orders'), method: 'GET'),
        throwsArgumentError,
      );
      expect(signer.calls, before);
    });
  });

  group('signer failures', () {
    test('a signer that throws makes createProof throw', () async {
      final failing = DPoPSignerClient(ThrowingSigner(signer.publicJwk));

      await expectLater(
        failing.createProof(url: url, method: 'GET'),
        throwsA(isA<StateError>()),
      );
    });

    test('a DER or otherwise mis-sized signature is refused', () async {
      for (final length in <int>[0, 63, 65, 70, 72]) {
        final wrong = DPoPSignerClient(
          FixedSignatureSigner(signer.publicJwk, Uint8List(length)),
        );

        await expectLater(
          wrong.createProof(url: url, method: 'GET'),
          throwsA(isA<StateError>()),
          reason: '$length bytes',
        );
      }
    });

    test('a JWK carrying a private member is refused before signing', () async {
      final leaky = FakeSigner(pair);
      final client = DPoPSignerClient(
        FixedSignatureSigner({
          ...leaky.publicJwk,
          'd': 'c2VjcmV0',
        }, Uint8List(64)),
      );

      await expectLater(
        client.createProof(url: url, method: 'GET'),
        throwsArgumentError,
      );
    });
  });

  group('web compatibility', () {
    test('the library uses neither dart:io nor dart:html', () {
      final offenders = Directory('lib')
          .listSync(recursive: true)
          .whereType<File>()
          .where((f) => f.path.endsWith('.dart'))
          .where(
            (f) => RegExp(
              r'''import\s+['"]dart:(io|html)['"]''',
            ).hasMatch(f.readAsStringSync()),
          )
          .map((f) => f.path)
          .toList();

      expect(offenders, isEmpty);
    });
  });
}
