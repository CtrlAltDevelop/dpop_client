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

request.headers.addAll(proof.headers());   // {'DPoP': 'eyJ0eXAiOiJkcG9w…'}
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
  dpop_client: ^1.0.0
```

Requires Dart 3.13.0 or newer — Flutter 3.47.0 or newer, if you are on
Flutter. There is no `flutter` constraint in `pubspec.yaml`, so the package
still resolves in server and CLI projects with no Flutter SDK installed.

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
| `htu` | `url`    | **Query and fragment are dropped**, per RFC 9449 §4.2. |
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

Rebuilding the URI also drops a redundantly-stated default port, matching the
normalisation the server applies to its own copy.

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

## Two details this package gets right

Both are easy to get wrong by hand, and neither produces a diagnosable error
when you do.

**`iat` is truncated, not rounded.** Rounding pushes the timestamp up to half a
second into the future, which a server with no clock-skew allowance rejects.
This also means passing `noIssueAt: true` to the underlying signer, since
`dart_jsonwebtoken` otherwise overwrites `iat` with its own clock on the way
out — so hand-rolled code that computes `iat` carefully often finds the value
never reaches the token.

**`htu` excludes the query and the fragment.** See above.

## Verifying a proof

This package signs proofs; it does not verify them, because a resource server
needs replay detection, nonce issuance and clock-skew policy that belong with
the server, not a client library. If you are writing a verifier, note that
`dart_jsonwebtoken`'s `JWT.verify` rejects a proof outright unless you pass
`checkHeaderType: false` — a DPoP proof is typed `dpop+jwt`, not `JWT`.

## Scope

- ES256 over P-256 only. RFC 9449 permits other algorithms; servers rarely do.
- Signing only. No verification, no nonce cache, no HTTP client.
- No key storage. Persist `privateKeyPem` with whatever your platform offers.

## License

MIT — see [LICENSE](LICENSE).
