import 'dart:typed_data';

import 'dpop_key_pair.dart';
import 'dpop_proof.dart';
import 'es256.dart';
import 'unsigned_proof.dart';

/// Signs DPoP proof JWTs with one [DPoPKeyPair].
///
/// Hold a single instance for the lifetime of a signed-in session — it is
/// stateless beyond the key pair — and call [createProof] once per outgoing
/// request:
///
/// ```dart
/// final client = DPoPClient(DPoPKeyPair.generate());
///
/// final proof = client.createProof(
///   url: Uri.parse('https://api.example.com/orders?limit=20'),
///   method: 'POST',
///   accessToken: accessToken,
/// );
///
/// request.headers.addAll(proof.headers());
/// ```
class DPoPClient {
  /// Creates a proof signer for [keyPair].
  const DPoPClient(this.keyPair);

  /// The key pair every proof is signed with, and whose public half travels
  /// in each proof's JWT header.
  final DPoPKeyPair keyPair;

  /// The signing key's RFC 7638 thumbprint — the `jkt` an authorization
  /// server binds an access token to. Shorthand for `keyPair.thumbprint`.
  String get thumbprint => keyPair.thumbprint;

  /// Signs a proof for one request.
  ///
  /// [url] is the request's target. Its query and fragment are **dropped**
  /// from the `htu` claim, as RFC 9449 §4.2 requires — pass the URL as you
  /// will send it and let this method normalise it, rather than trimming it at
  /// the call site. It must be absolute, with a scheme and a host; a relative
  /// URL, or one missing its scheme such as `api.example.com/orders`, throws an
  /// [ArgumentError] here rather than yielding a proof no server can match.
  ///
  /// [method] is the HTTP method, upper-cased for the `htm` claim.
  ///
  /// Pass [accessToken] on any request that carries one. It adds the `ath`
  /// claim, a hash of the token, which is what ties the proof to that specific
  /// token; a resource server that requires `ath` rejects a proof without it.
  /// The returned proof's [DPoPProof.headers] then also carries the matching
  /// `Authorization: DPoP …` header. Omit it for the token request itself,
  /// where no token exists yet.
  ///
  /// Pass [nonce] when a server has demanded one. Servers signal this with a
  /// `401` carrying a `DPoP-Nonce` header and `error="use_dpop_nonce"`; take
  /// that header's value, retry the request with it here, and keep using the
  /// most recent nonce the server sent until it issues another.
  ///
  /// [issuedAt] and [jwtId] default to now and a random UUID v4. Set them only
  /// in tests — a fixed `jti` invites the replay detection it exists to
  /// trigger, and a stale `iat` will be rejected outright.
  DPoPProof createProof({
    required Uri url,
    required String method,
    String? accessToken,
    String? nonce,
    DateTime? issuedAt,
    String? jwtId,
  }) {
    final UnsignedProof unsigned = UnsignedProof(
      publicJwk: keyPair.jwk,
      url: url,
      method: method,
      accessToken: accessToken,
      nonce: nonce,
      issuedAt: issuedAt,
      jwtId: jwtId,
    );
    final Uint8List signature = signEs256(
      keyPair.privateKey,
      unsigned.signingBytes,
    );
    return unsigned.complete(signature, thumbprint: keyPair.thumbprint);
  }
}
