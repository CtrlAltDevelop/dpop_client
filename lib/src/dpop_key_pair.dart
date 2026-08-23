import 'dart:convert';

import 'package:basic_utils/basic_utils.dart';
import 'package:crypto/crypto.dart';

import 'encoding.dart';

/// The elliptic curve DPoP proofs are signed on.
///
/// RFC 9449 does not mandate an algorithm, but ES256 over P-256 is what
/// authorization servers implement in practice, and it is the only pairing
/// this package supports.
const String _curve = 'prime256v1';

/// An ES256 key pair used to sign DPoP proofs.
///
/// Generate one per installation with [DPoPKeyPair.generate], persist
/// [privateKeyPem], and restore it on the next launch with
/// [DPoPKeyPair.fromPrivateKeyPem]. The public half is derived from the
/// private scalar, so only the one PEM needs storing.
///
/// The private key is the client's proof of identity for every token bound to
/// it: keep it in the platform keystore, not in plain preferences, and
/// generate a fresh pair when the user signs out.
class DPoPKeyPair {
  /// Wraps an already-constructed key pair.
  ///
  /// Both halves must belong to the P-256 curve. Prefer [generate],
  /// [fromPrivateKeyPem] or [fromPem] unless the keys came from somewhere
  /// this package cannot read.
  DPoPKeyPair({required this.privateKey, required this.publicKey});

  /// Generates a fresh P-256 key pair.
  factory DPoPKeyPair.generate() {
    final AsymmetricKeyPair<PublicKey, PrivateKey> pair =
        CryptoUtils.generateEcKeyPair(curve: _curve);
    return DPoPKeyPair(
      privateKey: pair.privateKey as ECPrivateKey,
      publicKey: pair.publicKey as ECPublicKey,
    );
  }

  /// Restores a key pair from a stored private key PEM, deriving the public
  /// half from it.
  ///
  /// This is the counterpart to persisting [privateKeyPem]. Throws a
  /// [FormatException] if [pem] is not a readable EC private key, or an
  /// [ArgumentError] if it carries no curve parameters to derive against.
  factory DPoPKeyPair.fromPrivateKeyPem(String pem) {
    final ECPrivateKey privateKey = CryptoUtils.ecPrivateKeyFromPem(pem);
    final ECDomainParameters? parameters = privateKey.parameters;
    final BigInt? d = privateKey.d;
    if (parameters == null || d == null) {
      throw ArgumentError.value(
        pem,
        'pem',
        'EC private key carries no curve parameters, so the public key '
            'cannot be derived. Use DPoPKeyPair.fromPem and supply both.',
      );
    }
    return DPoPKeyPair(
      privateKey: privateKey,
      publicKey: ECPublicKey(parameters.G * d, parameters),
    );
  }

  /// Restores a key pair from a stored private and public key PEM pair.
  ///
  /// Use this only when the public key came from elsewhere; otherwise
  /// [fromPrivateKeyPem] derives it and halves what has to be stored.
  factory DPoPKeyPair.fromPem({
    required String privateKeyPem,
    required String publicKeyPem,
  }) => DPoPKeyPair(
    privateKey: CryptoUtils.ecPrivateKeyFromPem(privateKeyPem),
    publicKey: CryptoUtils.ecPublicKeyFromPem(publicKeyPem),
  );

  /// The signing half. Never leaves the device.
  final ECPrivateKey privateKey;

  /// The verifying half, published inside every proof's JWT header as a JWK.
  final ECPublicKey publicKey;

  /// The private key in SEC 1 PEM form, for persisting to secure storage.
  String get privateKeyPem => CryptoUtils.encodeEcPrivateKeyToPem(privateKey);

  /// The public key in SPKI PEM form.
  String get publicKeyPem => CryptoUtils.encodeEcPublicKeyToPem(publicKey);

  /// The public key as a JWK, the form that travels in a proof's JWT header.
  ///
  /// Contains only public parameters: `kty`, `crv`, `x`, `y`, plus the `use`
  /// and `alg` hints. Safe to log.
  Map<String, String> get jwk {
    final ECPoint? q = publicKey.Q;
    if (q == null) {
      throw StateError('EC public key has no point; it cannot be published.');
    }
    return <String, String>{
      'kty': 'EC',
      'crv': 'P-256',
      'x': base64UrlUnpadded(
        CryptoUtils.i2osp(q.x!.toBigInteger()!, outLen: 32),
      ),
      'y': base64UrlUnpadded(
        CryptoUtils.i2osp(q.y!.toBigInteger()!, outLen: 32),
      ),
      'use': 'sig',
      'alg': 'ES256',
    };
  }

  /// The public key's JWK as a compact JSON string.
  ///
  /// Some gateways want the JWK in a header of its own alongside the proof,
  /// even though the proof already carries it. This is that value.
  String get jwkJson => jsonEncode(jwk);

  /// The key's SHA-256 JWK thumbprint, per
  /// [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638).
  ///
  /// This is the `jkt` an authorization server records against a DPoP-bound
  /// access token. Compare it against the `cnf.jkt` claim of a token you have
  /// been issued to confirm the token is bound to *this* key — after
  /// restoring a key from storage, say, or after a refresh.
  String get thumbprint {
    final Map<String, String> publicJwk = jwk;
    // RFC 7638 §3.3: only the required members, ordered lexicographically by
    // key, serialised without whitespace.
    final String canonical = jsonEncode(<String, String>{
      'crv': publicJwk['crv']!,
      'kty': publicJwk['kty']!,
      'x': publicJwk['x']!,
      'y': publicJwk['y']!,
    });
    return base64UrlUnpadded(sha256.convert(utf8.encode(canonical)).bytes);
  }
}
