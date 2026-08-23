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
  /// the call site.
  ///
  /// [method] is the HTTP method, upper-cased for the `htm` claim.
  ///
  /// Pass [accessToken] on any request that carries one. It adds the `ath`
  /// claim, a hash of the token, which is what ties the proof to that specific
  /// token; a resource server that requires `ath` rejects a proof without it.
  /// Omit it for the token request itself, where no token exists yet.
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
    final Map<String, String> publicJwk = keyPair.jwk;
    final String id = jwtId ?? const Uuid().v4();
    // Truncated, not rounded: rounding can push `iat` up to half a second
    // into the future, which a server with no clock skew allowance rejects.
    final DateTime stamp = issuedAt ?? DateTime.now();
    final int seconds = stamp.millisecondsSinceEpoch ~/ 1000;

    final Map<String, dynamic> payload = <String, dynamic>{
      'htm': method.toUpperCase(),
      'htu': _htu(url),
      'iat': seconds,
      'jti': id,
    };

    if (accessToken != null && accessToken.isNotEmpty) {
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
      jwt.ECPrivateKey(keyPair.privateKeyPem),
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
    );
  }

  /// The `htu` claim for [url]: scheme, authority and path only.
  ///
  /// RFC 9449 §4.2 defines `htu` as the target URI "without query and
  /// fragment parts". Leaving a query string in is a common mistake and one a
  /// strict server rejects, since its own reconstruction of the URI will not
  /// match.
  ///
  /// Built member by member rather than with `Uri.replace`, which renders a
  /// stripped query as a bare trailing `?`. Rebuilding also drops a
  /// redundantly-stated default port, which is the normalisation the server
  /// will have applied to its own copy of the URI.
  static String _htu(Uri url) => Uri(
    scheme: url.scheme,
    userInfo: url.userInfo,
    host: url.host,
    port: url.hasPort ? url.port : null,
    path: url.path,
  ).toString();
}
