# dpop_client

DPoP proof JWTs for Dart, as specified by
[RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) — ES256 key handling, PEM
storage, JWK thumbprints, access-token binding and server-supplied nonces.

Pure Dart, so it works in Flutter apps, server code and CLIs alike.

```dart
final keyPair = DPoPKeyPair.generate();
await secureStorage.write('dpop_key', keyPair.privateKeyPem);

final proof = DPoPClient(keyPair).createProof(
  url: Uri.parse('https://api.example.com/v1/orders?limit=20'),
  method: 'POST',
  accessToken: accessToken,
);

// {'DPoP': 'eyJ0eXAiOiJkcG9w…', 'Authorization': 'DPoP <access token>'}
request.headers.addAll(proof.headers());
```

## Why

A bearer token is a password: whoever holds it is the user. DPoP fixes that by
binding the token to a key pair the client generates and never sends. Every
request carries a short-lived JWT — the *proof* — signed by that key and
covering the request's method and URI, so a token lifted from a log or a proxy
is inert without the private key alongside it.

The mechanics are small but unforgiving. Get the `htu` normalisation, the `ath`
hash or the `iat` truncation slightly wrong and the server rejects every
request with a message that names none of them. This package is those details.

## Install

```yaml
dependencies:
  dpop_client: ^2.0.0
```

Requires Dart 3.11.0 or newer, and so any Flutter release shipping that SDK or
later. There is no `flutter` constraint in `pubspec.yaml`, so the package still
resolves in server and CLI projects with no Flutter SDK installed.

## Keys

`DPoPKeyPair` wraps an ES256 (P-256) pair — the pairing authorization servers
actually implement, and the only one this package supports.

```dart
final keyPair = DPoPKeyPair.generate();
```

Persist `privateKeyPem` and nothing else: the public half is derived from the
private scalar on restore.

```dart
final keyPair = DPoPKeyPair.fromPrivateKeyPem(await storage.read('dpop_key'));
```

Both PEM forms are accepted: the SEC 1 `EC PRIVATE KEY` block this package
emits, and the PKCS#8 `PRIVATE KEY` block most other tooling produces. A key on
any curve but P-256 is refused outright rather than reinterpreted.

The private key is the client's identity for every token bound to it. Keep it
in the platform keystore — `flutter_secure_storage`, the Keychain, the Android
keystore — not in plain preferences, and generate a fresh pair on sign-out so
the old one cannot be used to keep presenting an old token.

### Thumbprints

`thumbprint` is the key's [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638)
SHA-256 JWK thumbprint — the `jkt` an authorization server records against a
DPoP-bound access token. Compare it against the token's `cnf.jkt` claim to
confirm a token you have been issued is bound to the key you hold, which is
worth doing after restoring a key from storage:

```dart
if (decodedToken['cnf']?['jkt'] != keyPair.thumbprint) {
  // This token belongs to a key we no longer have. Re-authenticate.
}
```

## Proofs

One proof per request. They are bound to a method, a URI and a moment, so
caching one is never right.

```dart
final client = DPoPClient(keyPair);

final proof = client.createProof(
  url: Uri.parse('https://api.example.com/v1/orders?limit=20'),
  method: 'POST',
  accessToken: accessToken,
);
```

| Claim | Set from | Notes |
| ----- | -------- | ----- |
| `htm` | `method` | Upper-cased. |
| `htu` | `url`    | **Query, fragment and userinfo are dropped**, per RFC 9449 §4.2. An empty path becomes `/`. |
| `iat` | now      | Truncated to whole seconds, never rounded up. |
| `jti` | UUID v4  | Fresh per proof, so a server's replay cache never collides. |
| `ath` | `accessToken` | Unpadded base64url SHA-256 of the token. Omitted when no token is passed. |
| `nonce` | `nonce` | Omitted unless supplied. |

The public JWK travels in the JWT header, alongside `typ: dpop+jwt` and
`alg: ES256`.

### Pass the URL as you will send it

`htu` carries no query string. Hand `createProof` the full URL and let it
normalise — do not trim at the call site, and do not assume your HTTP client
gives you a clean one. This is the single most common way a DPoP integration
fails, because a query parameter added by an interceptor (a `?lang=` on every
request, say) is invisible at the point the proof is built.

Rebuilding the URI also applies the normalisations the server will have applied
to its own copy:

- a redundantly-stated default port is dropped, so `https://api.example.com:443/x`
  and `https://api.example.com/x` agree;
- **userinfo is dropped** — a target URI has no userinfo component, so leaving it
  in both guarantees a mismatch and writes any password in the URL into a JWT
  payload the server is free to log;
- **an empty path becomes `/`** — RFC 9110 §7.1 has the client send `/` when the
  path is empty, so `https://api.example.com` is reconstructed server-side as
  `https://api.example.com/`.

### Send the token under the DPoP scheme, not Bearer

A DPoP-bound access token is presented with `Authorization: DPoP <token>`, not
`Authorization: Bearer <token>` (RFC 9449 §7.1). A perfectly good proof sent
alongside a `Bearer` header is still rejected, and this is the step integrations
miss most often — the proof looks right, so the header rarely gets a second look.

`headers()` emits both, so there is nothing to remember:

```dart
final proof = client.createProof(
  url: url,
  method: 'POST',
  accessToken: accessToken,
);

request.headers.addAll(proof.headers());
// {'DPoP': 'eyJ0eXAiOiJkcG9w…', 'Authorization': 'DPoP <access token>'}
```

The token comes from the proof itself rather than a second argument, so the
`Authorization` header can never disagree with the `ath` claim. Create a proof
without an access token — the token request itself — and no `Authorization`
header is produced, matching the absent `ath`.

### Nonces

A server that wants a nonce answers `401` with `error="use_dpop_nonce"` and a
`DPoP-Nonce` response header. Retry with that value, and keep using the most
recent one the server sent until it issues another:

```dart
String? _nonce;   // the most recent nonce the server issued

Future<Response> send(Request request) async {
  final response = await _send(request, nonce: _nonce);

  final issued = response.headers['dpop-nonce'];
  if (issued == null) return response;

  final isNew = issued != _nonce;
  _nonce = issued;

  // Retry once, and only against a nonce we had not already tried.
  if (response.statusCode == 401 && isNew) return send(request);
  return response;
}
```

### Non-standard header names

RFC 9449 specifies the `DPoP` header. If your gateway wants something else,
name it:

```dart
request.headers.addAll(proof.headers(name: 'X-DPOP'));
```

Some gateways also want the JWK in a header of its own, even though the proof
already carries it. `keyPair.jwkJson` is that value.

## Three details this package gets right

Each is easy to get wrong by hand, and none produces a diagnosable error when
you do.

**`iat` is truncated, not rounded.** Rounding pushes the timestamp up to half a
second into the future, which a server with no clock-skew allowance rejects.
This also means passing `noIssueAt: true` to the underlying signer, since
`dart_jsonwebtoken` otherwise overwrites `iat` with its own clock on the way
out — so hand-rolled code that computes `iat` carefully often finds the value
never reaches the token.

**`htu` excludes the query, the fragment and the userinfo, and never has an
empty path.** See above.

**The bound token is sent under the `DPoP` scheme.** See above.

## Verifying a proof

This package signs proofs; it does not verify them, because a resource server
needs replay detection, nonce issuance and clock-skew policy that belong with
the server, not a client library. If you are writing a verifier, note that
`dart_jsonwebtoken`'s `JWT.verify` rejects a proof outright unless you pass
`checkHeaderType: false` — a DPoP proof is typed `dpop+jwt`, not `JWT`.

## Scope

- ES256 over P-256 only. RFC 9449 permits other algorithms; servers rarely do.
  A key on another curve is refused, not reinterpreted.
- Signing only. No verification, no nonce cache, no HTTP client.
- No key storage. Persist `privateKeyPem` with whatever your platform offers.

The dependency footprint is deliberately small — `pointycastle` and `asn1lib`
for the curve and the PEMs, `dart_jsonwebtoken` for the JWS, `crypto` and
`uuid`. Nothing here pulls in an HTTP client or a logger.

## Upgrading from 1.x

`headers()` now also returns the `Authorization` header when the proof carries
an access token. If you were setting that header yourself, drop your own line —
and if you were setting it to `Bearer`, that was the bug this closes.

```dart
// 1.x
request.headers['Authorization'] = 'Bearer $accessToken';
request.headers.addAll(proof.headers());

// 2.0
request.headers.addAll(proof.headers());
```

Three behaviours changed, each of them a fix:

- `htu` no longer carries userinfo, and an empty path is now emitted as `/`.
  Proofs for `https://api.example.com` and for URLs with credentials in them
  change value — in both cases to the one the server was already expecting.
- `DPoPKeyPair.fromPrivateKeyPem` and `fromPem` throw [FormatException] on
  unreadable input, where 1.x surfaced whatever the underlying library threw.
  `fromPem` now also rejects two halves that do not belong together.
- `keyPair.jwk` is an unmodifiable map, since it is shared across every proof
  the key signs rather than rebuilt per call.

`basic_utils` is no longer a dependency. `privateKey` and `publicKey` are the
same `pointycastle` classes they always were, so if you touched them directly,
import `package:pointycastle/ecc/api.dart` instead of
`package:basic_utils/basic_utils.dart`.

## License

MIT — see [LICENSE](LICENSE).
