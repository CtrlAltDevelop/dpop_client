import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart' as jwt;
import 'package:uuid/uuid.dart';

import 'dpop_key_pair.dart';
import 'dpop_proof.dart';
import 'encoding.dart';

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
    if (!url.hasScheme || url.host.isEmpty) {
      // Left alone, this builds an `htu` like `///orders` and signs it without
      // complaint; the server's only response is a flat `invalid_dpop_proof`.
      throw ArgumentError.value(
        url,
        'url',
        'must be an absolute URL with a scheme and host, such as '
            'https://api.example.com/orders',
      );
    }

    final Map<String, String> publicJwk = keyPair.jwk;
    final String id = jwtId ?? const Uuid().v4();
    // Truncated, not rounded: rounding can push `iat` up to half a second
    // into the future, which a server with no clock skew allowance rejects.
    final DateTime stamp = issuedAt ?? DateTime.now();
    final int seconds = stamp.millisecondsSinceEpoch ~/ 1000;

    final bool hasToken = accessToken != null && accessToken.isNotEmpty;

    final Map<String, dynamic> payload = <String, dynamic>{
      'htm': method.toUpperCase(),
      'htu': _htu(url),
      'iat': seconds,
      'jti': id,
    };

    if (hasToken) {
      payload['ath'] = base64UrlUnpadded(
        sha256.convert(utf8.encode(accessToken)).bytes,
      );
    }

    if (nonce != null && nonce.isNotEmpty) {
      payload['nonce'] = nonce;
    }

    final jwt.JWT proof = jwt.JWT(
      payload,
      header: <String, dynamic>{
        'typ': 'dpop+jwt',
        'alg': 'ES256',
        'jwk': publicJwk,
      },
    );

    final String token = proof.sign(
      // `.raw` takes the parsed key straight across. Handing the signer a PEM
      // instead would re-encode and re-parse the key on every request, which
      // costs more than the signature itself.
      jwt.ECPrivateKey.raw(keyPair.privateKey),
      algorithm: jwt.JWTAlgorithm.ES256,
      // Without this, dart_jsonwebtoken overwrites `iat` with its own
      // `DateTime.now()` on the way out, and the value set above — including
      // any [issuedAt] passed in for a test — never reaches the token.
      noIssueAt: true,
    );

    return DPoPProof(
      token: token,
      jwk: publicJwk,
      thumbprint: keyPair.thumbprint,
      jwtId: id,
      issuedAt: DateTime.fromMillisecondsSinceEpoch(
        seconds * 1000,
        isUtc: stamp.isUtc,
      ),
      accessToken: hasToken ? accessToken : null,
    );
  }

  /// The `htu` claim for [url]: scheme, host, port and path only.
  ///
  /// RFC 9449 §4.2 defines `htu` as the target URI (RFC 9110 §7.1) "without
  /// query and fragment parts". Leaving a query string in is a common mistake
  /// and one a strict server rejects, since its own reconstruction of the URI
  /// will not match.
  ///
  /// Built member by member rather than with `Uri.replace`, which renders a
  /// stripped query as a bare trailing `?`. Rebuilding also drops a
  /// redundantly-stated default port, which is the normalisation the server
  /// will have applied to its own copy of the URI.
  ///
  /// Two further normalisations the server's own copy will already have:
  ///
  /// * **Userinfo is dropped.** A target URI has no userinfo component, so
  ///   leaving it in guarantees a mismatch — and writes any password in the
  ///   URL into a JWT payload that the server is free to log.
  /// * **An empty path becomes `/`.** RFC 9110 §7.1 has the client send `/`
  ///   when the path is empty, so `https://api.example.com` is reconstructed
  ///   server-side as `https://api.example.com/`.
  static String _htu(Uri url) => Uri(
    scheme: url.scheme,
    host: url.host,
    port: url.hasPort ? url.port : null,
    path: url.path.isEmpty ? '/' : url.path,
  ).toString();
}
