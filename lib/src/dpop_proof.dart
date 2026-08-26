/// A single DPoP proof JWT, ready to attach to one request.
///
/// A proof is bound to the method and URI it was created for and carries a
/// timestamp the server will only accept for a short window, so it cannot be
/// reused for a different request or replayed later. Create one per request
/// with `DPoPClient.createProof`; never cache one.
class DPoPProof {
  /// Wraps an already-signed proof.
  ///
  /// Produced by `DPoPClient.createProof`; there is rarely a reason to
  /// construct one directly.
  ///
  /// [accessToken] is the token this proof's `ath` claim was computed over,
  /// which [headers] needs in order to emit the matching `Authorization`
  /// header. It is held, not published.
  const DPoPProof({
    required this.token,
    required this.jwk,
    required this.thumbprint,
    required this.jwtId,
    required this.issuedAt,
    String? accessToken,
    // A named parameter cannot be private, so `this._accessToken` is not
    // available here and the lint's suggestion does not compile.
    // ignore: prefer_initializing_formals
  }) : _accessToken = accessToken;

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

  /// The access token this proof is bound to, if any. Never exposed.
  final String? _accessToken;

  /// Whether this proof carries an `ath` claim binding it to an access token.
  bool get isTokenBound => _accessToken != null;

  /// The headers to add to the outgoing request.
  ///
  /// When the proof was created with an access token, this returns **both**
  /// headers the request needs:
  ///
  /// ```dart
  /// {
  ///   'DPoP': 'eyJ0eXAiOiJkcG9w…',
  ///   'Authorization': 'DPoP eyJhbGciOiJFUzI1NiJ9…',
  /// }
  /// ```
  ///
  /// The `Authorization` scheme is `DPoP`, not `Bearer` — RFC 9449 §7.1. This
  /// is the step most integrations miss: a correct proof sent alongside
  /// `Authorization: Bearer …` is rejected, because a token bound to a key
  /// must be presented under the scheme that says so.
  ///
  /// The token comes from the proof itself rather than a parameter, so the
  /// `Authorization` header can never disagree with the `ath` claim.
  ///
  /// Pass [name] only for a gateway that expects a non-standard proof header;
  /// RFC 9449 specifies `DPoP`.
  ///
  /// ```dart
  /// request.headers.addAll(proof.headers());
  /// ```
  Map<String, String> headers({String name = 'DPoP'}) {
    final String? accessToken = _accessToken;
    return <String, String>{
      name: token,
      if (accessToken != null) 'Authorization': 'DPoP $accessToken',
    };
  }

  /// The token, so a proof can be interpolated straight into a header value.
  @override
  String toString() => token;

  /// Two proofs are equal when they are the same signed token.
  @override
  bool operator ==(Object other) =>
      identical(this, other) || (other is DPoPProof && other.token == token);

  @override
  int get hashCode => token.hashCode;
}
