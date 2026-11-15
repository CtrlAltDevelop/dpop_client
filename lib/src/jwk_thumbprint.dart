import 'dart:convert';

import 'package:crypto/crypto.dart';

import 'encoding.dart';

/// The RFC 7638 SHA-256 thumbprint of a P-256 public JWK — the `jkt` an
/// authorization server binds a DPoP access token to.
///
/// Use it to learn a key's `jkt` before any proof exists, for a key held where
/// this package cannot read it (a WebCrypto `CryptoKey`, a platform keystore)
/// and so has no `DPoPKeyPair`. For a key pair, `DPoPKeyPair.thumbprint` is
/// the same value, computed once.
///
/// Only `kty`, `crv`, `x` and `y` take part, as RFC 7638 §3.2 requires; any
/// other member (`use`, `alg`, `kid`, `ext`, `key_ops`) is ignored.
///
/// Throws an [ArgumentError] if [publicJwk] is not an EC P-256 key, lacks a
/// coordinate, or carries the private member `d` — a thumbprint of a JWK that
/// should never have left the keystore is a sign something is wrong upstream.
String dpopThumbprint(Map<String, String> publicJwk) {
  if (publicJwk.containsKey('d')) {
    throw ArgumentError.value(
      publicJwk.keys.toList(),
      'publicJwk',
      'carries the private member "d"; pass the public half only',
    );
  }
  if (publicJwk['kty'] != 'EC' || publicJwk['crv'] != 'P-256') {
    throw ArgumentError.value(
      publicJwk,
      'publicJwk',
      'must be an EC P-256 key (kty EC, crv P-256); this package signs DPoP '
          'proofs with ES256 only',
    );
  }
  final String? x = publicJwk['x'];
  final String? y = publicJwk['y'];
  if (x == null || x.isEmpty || y == null || y.isEmpty) {
    throw ArgumentError.value(
      publicJwk,
      'publicJwk',
      'must carry both public coordinates, "x" and "y"',
    );
  }

  // RFC 7638 §3.3: only the required members, ordered lexicographically by
  // key, serialised without whitespace.
  final String canonical = jsonEncode(<String, String>{
    'crv': 'P-256',
    'kty': 'EC',
    'x': x,
    'y': y,
  });
  return base64UrlUnpadded(sha256.convert(utf8.encode(canonical)).bytes);
}
