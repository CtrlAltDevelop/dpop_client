/// A single DPoP proof JWT, ready to attach to one request.
///
/// A proof is bound to the method and URI it was created for and carries a
/// timestamp the server will only accept for a short window, so it cannot be
/// reused for a different request or replayed later. Create one per request
/// with [DPoPClient.createProof]; never cache one.
class DPoPProof {
  /// Wraps an already-signed proof.
  ///
  /// Produced by [DPoPClient.createProof]; there is rarely a reason to
  /// construct one directly.
  const DPoPProof({
    required this.token,
    required this.jwk,
    required this.thumbprint,
    required this.jwtId,
    required this.issuedAt,
  });

  /// The signed `dpop+jwt`, the value of the `DPoP` request header.
  final String token;

  /// The public key published in the proof's JWT header, as a JWK.
  final Map<String, String> jwk;

  /// The signing key's RFC 7638 thumbprint — the `jkt` the authorization
  /// server binds the access token to.
  final String thumbprint;

  /// The proof's `jti` claim, the identifier a server uses to reject a replay.
  final String jwtId;

  /// The proof's `iat` claim, truncated to whole seconds as the JWT is.
  final DateTime issuedAt;

  /// The header to add to the outgoing request.
  ///
  /// Pass [name] only for a gateway that expects a non-standard header; RFC
  /// 9449 specifies `DPoP`.
  ///
  /// ```dart
  /// request.headers.addAll(proof.headers());
  /// ```
  Map<String, String> headers({String name = 'DPoP'}) => <String, String>{
    name: token,
  };

  /// The token, so a proof can be interpolated straight into a header value.
  @override
  String toString() => token;
}
