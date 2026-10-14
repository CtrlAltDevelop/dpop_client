import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/ecc/api.dart';

import 'ec_keys.dart';
import 'encoding.dart';

/// An ES256 key pair used to sign DPoP proofs.
///
/// Generate one per installation with [DPoPKeyPair.generate], persist
/// [privateKeyPem], and restore it on the next launch with
/// [DPoPKeyPair.fromPrivateKeyPem]. The public half is derived from the
/// private scalar, so only the one PEM needs storing.
///
/// RFC 9449 does not mandate an algorithm, but ES256 over P-256 is what
/// authorization servers implement in practice, and it is the only pairing
/// this package supports.
///
/// The private key is the client's proof of identity for every token bound to
/// it: keep it in the platform keystore, not in plain preferences, and
/// generate a fresh pair when the user signs out.
///
/// Every derived value — the PEMs, the [jwk] and the [thumbprint] — is
/// computed once and cached, so holding one instance for the session is much
/// cheaper than rebuilding it per request.
class DPoPKeyPair {
  /// Wraps an already-constructed key pair.
  ///
  /// Both halves must belong to the P-256 curve. Prefer [generate],
  /// [fromPrivateKeyPem] or [fromPem] unless the keys came from somewhere
  /// this package cannot read.
  ///
  /// Throws an [ArgumentError] if either half is on another curve, which would
  /// otherwise be published under a `crv` of `P-256` and fail at the server as
  /// a bad signature.
  DPoPKeyPair({required this.privateKey, required this.publicKey}) {
    if (!isP256(privateKey.parameters)) {
      throw ArgumentError.value(
        privateKey,
        'privateKey',
        'must be a P-256 key; this package signs DPoP proofs with ES256 only',
      );
    }
    if (!isP256(publicKey.parameters)) {
      throw ArgumentError.value(
        publicKey,
        'publicKey',
        'must be a P-256 key; this package signs DPoP proofs with ES256 only',
      );
    }
  }

  /// Generates a fresh P-256 key pair from the platform's secure entropy.
  factory DPoPKeyPair.generate() {
    final AsymmetricKeyPair<ECPublicKey, ECPrivateKey> pair =
        generateP256KeyPair();
    return DPoPKeyPair(privateKey: pair.privateKey, publicKey: pair.publicKey);
  }

  /// Restores a key pair from a stored private key PEM, deriving the public
  /// half from it.
  ///
  /// Accepts both the SEC 1 `EC PRIVATE KEY` form this package emits and the
  /// PKCS#8 `PRIVATE KEY` form other tooling tends to produce. This is the
  /// counterpart to persisting [privateKeyPem].
  ///
  /// Throws a [FormatException] if [pem] is not a readable P-256 private key.
  factory DPoPKeyPair.fromPrivateKeyPem(String pem) {
    final ECPrivateKey privateKey = decodeEcPrivateKeyFromPem(pem);
    final ECDomainParameters parameters = privateKey.parameters!;
    return DPoPKeyPair(
      privateKey: privateKey,
      publicKey: ECPublicKey(parameters.G * privateKey.d!, parameters),
    );
  }

  /// Restores a key pair from a stored private and public key PEM pair.
  ///
  /// Use this only when the public key came from elsewhere; otherwise
  /// [fromPrivateKeyPem] derives it and halves what has to be stored.
  ///
  /// Throws a [FormatException] if either PEM is unreadable, or an
  /// [ArgumentError] if the two halves do not belong together — a mismatch
  /// otherwise yields proofs whose embedded JWK cannot verify their own
  /// signature, which a server reports only as a flat rejection.
  factory DPoPKeyPair.fromPem({
    required String privateKeyPem,
    required String publicKeyPem,
  }) {
    final ECPrivateKey privateKey = decodeEcPrivateKeyFromPem(privateKeyPem);
    final ECPublicKey publicKey = decodeEcPublicKeyFromPem(publicKeyPem);
    final ECDomainParameters parameters = privateKey.parameters!;
    if ((parameters.G * privateKey.d!) != publicKey.Q) {
      throw ArgumentError(
        'The public key PEM does not match the private key PEM. Proofs '
        'signed with this pair would publish a JWK that cannot verify them.',
      );
    }
    return DPoPKeyPair(privateKey: privateKey, publicKey: publicKey);
  }

  /// The signing half. Never leaves the device.
  final ECPrivateKey privateKey;

  /// The verifying half, published inside every proof's JWT header as a JWK.
  final ECPublicKey publicKey;

  /// The private key in SEC 1 PEM form, for persisting to secure storage.
  late final String privateKeyPem = encodeEcPrivateKeyToPem(privateKey);

  /// The public key in SPKI PEM form.
  late final String publicKeyPem = encodeEcPublicKeyToPem(publicKey);

  /// The public key as a JWK, the form that travels in a proof's JWT header.
  ///
  /// Contains only public parameters: `kty`, `crv`, `x`, `y`, plus the `use`
  /// and `alg` hints. Safe to log. The map is unmodifiable, since it is shared
  /// by every proof this key signs.
  late final Map<String, String> jwk = _buildJwk();

  /// The public key's JWK as a compact JSON string.
  ///
  /// Some gateways want the JWK in a header of its own alongside the proof,
  /// even though the proof already carries it. This is that value.
  late final String jwkJson = jsonEncode(jwk);

  /// The key's SHA-256 JWK thumbprint, per
  /// [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638).
  ///
  /// This is the `jkt` an authorization server records against a DPoP-bound
  /// access token. Compare it against the `cnf.jkt` claim of a token you have
  /// been issued to confirm the token is bound to *this* key — after
  /// restoring a key from storage, say, or after a refresh.
  late final String thumbprint = _buildThumbprint();

  /// Whether [accessToken] is bound to this key, judged by the `cnf.jkt` claim
  /// of a JWT access token.
  ///
  /// Returns `true` when the token's `cnf.jkt` equals [thumbprint], `false`
  /// when it names a different key — typically after the key was regenerated
  /// but an old token was kept — and `null` when the token carries no readable
  /// `cnf.jkt`, as an opaque token does. Ask the authorization server's
  /// introspection endpoint for those.
  ///
  /// The token is **not verified**: this is a cheap local check for a stale
  /// key, not a trust decision.
  bool? isBoundTo(String accessToken) {
    final List<String> parts = accessToken.split('.');
    if (parts.length != 3) {
      return null;
    }
    try {
      final Object? claims = jsonDecode(
        utf8.decode(base64Url.decode(base64Url.normalize(parts[1]))),
      );
      final Object? cnf = claims is Map<String, dynamic> ? claims['cnf'] : null;
      final Object? jkt = cnf is Map<String, dynamic> ? cnf['jkt'] : null;
      return jkt is String ? jkt == thumbprint : null;
    } on FormatException {
      return null;
    }
  }

  Map<String, String> _buildJwk() {
    final ECPoint? q = publicKey.Q;
    if (q == null) {
      throw StateError('EC public key has no point; it cannot be published.');
    }
    return Map<String, String>.unmodifiable(<String, String>{
      'kty': 'EC',
      'crv': 'P-256',
      'x': base64UrlUnpadded(i2osp(q.x!.toBigInteger()!, p256FieldBytes)),
      'y': base64UrlUnpadded(i2osp(q.y!.toBigInteger()!, p256FieldBytes)),
      'use': 'sig',
      'alg': 'ES256',
    });
  }

  String _buildThumbprint() {
    // RFC 7638 §3.3: only the required members, ordered lexicographically by
    // key, serialised without whitespace.
    final String canonical = jsonEncode(<String, String>{
      'crv': jwk['crv']!,
      'kty': jwk['kty']!,
      'x': jwk['x']!,
      'y': jwk['y']!,
    });
    return base64UrlUnpadded(sha256.convert(utf8.encode(canonical)).bytes);
  }
}
