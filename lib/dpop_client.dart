/// DPoP proof JWTs for Dart, as specified by
/// [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449).
///
/// DPoP binds an access token to a key pair the client holds, so a stolen
/// bearer token is useless without the private key. Each request carries a
/// short-lived JWT — the *proof* — signed by that key and covering the
/// request's method and URI.
///
/// Generate a key pair once, persist it, and create a proof per request:
///
/// ```dart
/// final keyPair = DPoPKeyPair.generate();
/// await storage.write('dpop_key', keyPair.privateKeyPem);
///
/// final client = DPoPClient(keyPair);
/// final proof = client.createProof(
///   url: Uri.parse('https://api.example.com/orders?limit=20'),
///   method: 'POST',
///   accessToken: accessToken,
/// );
///
/// request.headers.addAll(proof.headers());
/// ```
library;

export 'src/dpop_client_base.dart';
export 'src/dpop_key_pair.dart';
export 'src/dpop_proof.dart';
