## 1.0.0

Initial release, extracted from an internal application module and corrected
against RFC 9449 on the way out.

- `DPoPKeyPair` — ES256 (P-256) key handling: `generate`, PEM round-tripping
  via `privateKeyPem`, and `fromPrivateKeyPem`, which derives the public half
  from the private scalar so only one PEM has to be stored.
- `DPoPKeyPair.jwk` / `jwkJson` — the public key as a JWK, the form that
  travels in a proof's JWT header.
- `DPoPKeyPair.thumbprint` — the RFC 7638 SHA-256 JWK thumbprint, for checking
  an access token's `cnf.jkt` against the key actually held.
- `DPoPClient.createProof` — a signed `dpop+jwt` per request, carrying `htm`,
  `htu`, `iat` and `jti`, plus `ath` when an access token is supplied and
  `nonce` when a server has demanded one.
- `DPoPProof` — the token with its `headers()` map, defaulting to the
  standard `DPoP` header name and accepting a gateway-specific one.
- **`htu` now excludes the query string and fragment**, as RFC 9449 §4.2
  requires. The internal original signed the full request URI, which a strict
  server rejects — and did so invisibly, since the offending query parameter
  was usually added by an interceptor after the call site.
- **`iat` is truncated to whole seconds rather than rounded**, so it cannot
  land up to half a second in the future and be refused by a server with no
  clock-skew allowance. This required `noIssueAt: true` on the underlying
  signer, which otherwise overwrites `iat` with its own clock — meaning the
  original's computed value never reached the token at all.
- Dartdoc across the public API, a runnable `example/`, and 36 tests covering
  the claim set, the header, signature verification, `htu` normalisation and
  `ath` hashing.
