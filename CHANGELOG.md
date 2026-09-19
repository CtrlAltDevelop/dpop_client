## 2.1.0

### Fixed

- **`createProof` rejects a URL that is not absolute.** `Uri.parse('/orders')`
  or a URL missing its scheme, such as `api.example.com/orders`, used to be
  signed with an `htu` of `///orders` — a claim no server can match, reported
  only as a flat `invalid_dpop_proof`. It now throws an `ArgumentError` that
  names the argument and shows the expected shape.
- **The `DPoPKeyPair` constructor rejects a key on any curve but P-256.** It
  documented the requirement without checking it, so a P-384 pair was published
  under `crv: P-256` and failed at the server as a bad signature. The named
  constructors already refused other curves; this closes the same gap for keys
  passed in directly.
- The library-level example called `proof.headers` as a getter; it is a method,
  so the snippet on the package page did not do what it appeared to.

### Changed

- CI moved to the shared reusable workflow in CtrlAltDevelop/ci-workflows:
  formatting, `analyze --fatal-infos`, the tests, the example, a changelog
  entry per version, and a pana score with no points lost — the same gate
  across every package here.
- **The SDK floor moves to Dart 3.12.0**, from Dart 3.11.0. This is the floor
  every package here is gated on rather than something the code needs.
- Dependency bounds are explicit ranges rather than carets — a floor that
  resolves on the supported SDK, the next major as the ceiling — so a consumer
  already on an older version in the same major is not forced to move.
- The README carries the pub, pub points, CI and licence badges the other
  packages here carry.

## 2.0.0

Bug fixes to `htu`, a much cheaper signing path, and a dependency tree cut down
to what a proof signer actually needs.

### Fixed

- **`htu` no longer carries the userinfo component.** A target URI (RFC 9110
  §7.1) has none, so a URL of the form `https://user:pass@host/path` produced a
  claim the server could never match — and wrote the password into a JWT
  payload the server is free to log.
- **`htu` normalises an empty path to `/`.** RFC 9110 §7.1 has the client send
  `/` when the path is empty, so a proof for `https://api.example.com` was
  compared against the server's `https://api.example.com/` and rejected.
- **The SEC 1 private key PEM pads the scalar to the full 32 octets.** RFC 5915
  §3 fixes the `privateKey` OCTET STRING at the curve's octet length; the
  previous encoder emitted a minimal-length field, so roughly one generated key
  in 256 was written to storage in a form strict parsers reject. Existing PEMs
  still read back correctly.

### Added

- **`DPoPProof.headers()` returns the `Authorization` header too**, under the
  `DPoP` scheme rather than `Bearer`, as RFC 9449 §7.1 requires for a bound
  token. The token is taken from the proof itself, so the header cannot
  disagree with the `ath` claim. `DPoPProof.isTokenBound` reports whether a
  proof carries one.
- `DPoPKeyPair.fromPrivateKeyPem` accepts PKCS#8 `PRIVATE KEY` PEMs alongside
  the SEC 1 `EC PRIVATE KEY` form, which is what most non-Dart tooling emits.
- A key on any curve but P-256 is now refused with a clear message instead of
  being reinterpreted against P-256's parameters and failing later as an
  unexplained bad signature.
- `DPoPKeyPair.fromPem` rejects a private and public half that do not belong
  together, rather than producing proofs whose embedded JWK cannot verify them.
- `DPoPProof` implements `==` and `hashCode` over its token.
- A GitHub Actions workflow covering the SDK floor and `stable`, a run against
  the oldest permitted dependency versions, and a publish dry run.

### Changed

- **Signing a proof is roughly twice as fast.** The private key was re-encoded
  to PEM and re-parsed on every single request, which cost more than the ECDSA
  signature itself; the signer now takes the parsed key directly, and the PEMs,
  the JWK and the thumbprint are each computed once per key pair.
- **`basic_utils` is no longer a dependency**, replaced by `pointycastle` and
  `asn1lib` directly. This drops `archive`, `ffi`, `http`, `http_parser`,
  `json_annotation`, `logging` and `posix` from the tree — a proof signer has
  no use for an HTTP client or an archive reader. `privateKey` and `publicKey`
  remain the same `pointycastle` types.
- `keyPair.jwk` is unmodifiable, now that one map is shared by every proof.
- Unreadable key material throws `FormatException` consistently.
- Dependency lower bounds are widened to the oldest versions the package is
  tested against, so it resolves alongside more of the ecosystem. The SDK floor
  stays at 3.13.0.

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
