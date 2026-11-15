import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:uuid/uuid.dart';

import 'dpop_proof.dart';
import 'encoding.dart';

/// Length of an ES256 signature in the JWS form, `r || s`, 32 bytes each.
const int es256SignatureLength = 64;

/// A DPoP proof up to, but not including, its signature.
///
/// The one place claims are built, shared by the synchronous `DPoPClient` and
/// the asynchronous `DPoPSignerClient` so the two cannot drift. Each signs
/// [signingBytes] its own way and hands the signature to [complete].
///
/// Internal to the package: not exported from `dpop_client.dart`.
class UnsignedProof {
  /// Validates the request and builds the header and claims.
  ///
  /// Throws an [ArgumentError] if [url] is not absolute.
  factory UnsignedProof({
    required Map<String, String> publicJwk,
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
      // Any scheme with a host is accepted, `ws` and `wss` included.
      throw ArgumentError.value(
        url,
        'url',
        'must be an absolute URL with a scheme and host, such as '
            'https://api.example.com/orders',
      );
    }

    final String id = jwtId ?? const Uuid().v4();
    // Truncated, not rounded: rounding can push `iat` up to half a second
    // into the future, which a server with no clock skew allowance rejects.
    final DateTime stamp = issuedAt ?? DateTime.now();
    final int seconds = stamp.millisecondsSinceEpoch ~/ 1000;

    final bool hasToken = accessToken != null && accessToken.isNotEmpty;

    final Map<String, Object> payload = <String, Object>{
      'htm': method.toUpperCase(),
      'htu': _htu(url),
      'iat': seconds,
      'jti': id,
      if (hasToken)
        'ath': base64UrlUnpadded(
          sha256.convert(utf8.encode(accessToken)).bytes,
        ),
      if (nonce != null && nonce.isNotEmpty) 'nonce': nonce,
    };
    final Map<String, Object> header = <String, Object>{
      'typ': 'dpop+jwt',
      'alg': 'ES256',
      'jwk': publicJwk,
    };

    return UnsignedProof._(
      signingInput:
          '${base64UrlUnpadded(utf8.encode(jsonEncode(header)))}.'
          '${base64UrlUnpadded(utf8.encode(jsonEncode(payload)))}',
      publicJwk: publicJwk,
      jwtId: id,
      issuedAt: DateTime.fromMillisecondsSinceEpoch(
        seconds * 1000,
        isUtc: stamp.isUtc,
      ),
      accessToken: hasToken ? accessToken : null,
    );
  }

  UnsignedProof._({
    required this.signingInput,
    required this.publicJwk,
    required this.jwtId,
    required this.issuedAt,
    required this.accessToken,
  });

  /// `base64url(header).base64url(payload)`, the JWS signing input.
  final String signingInput;

  /// The JWK published in the header.
  final Map<String, String> publicJwk;

  /// The `jti` claim.
  final String jwtId;

  /// The `iat` claim, truncated to whole seconds.
  final DateTime issuedAt;

  /// The token the `ath` claim covers, if any.
  final String? accessToken;

  /// [signingInput] as the bytes a signature is computed over.
  Uint8List get signingBytes => Uint8List.fromList(utf8.encode(signingInput));

  /// Attaches [signature] and returns the finished proof.
  ///
  /// Throws a [StateError] if [signature] is not the 64 byte `r || s` form: a
  /// DER signature, the usual mistake with a platform keystore, would
  /// otherwise be sent and fail at the server as a bare `invalid_dpop_proof`.
  DPoPProof complete(Uint8List signature, {required String thumbprint}) {
    if (signature.length != es256SignatureLength) {
      throw StateError(
        'The signer returned ${signature.length} bytes; an ES256 JWS '
        'signature is the raw $es256SignatureLength byte r || s form, not '
        'DER.',
      );
    }
    return DPoPProof(
      token: '$signingInput.${base64UrlUnpadded(signature)}',
      jwk: publicJwk,
      thumbprint: thumbprint,
      jwtId: jwtId,
      issuedAt: issuedAt,
      accessToken: accessToken,
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
    port: url.hasPort && url.port != _defaultPorts[url.scheme]
        ? url.port
        : null,
    path: url.path.isEmpty ? '/' : url.path,
  ).toString();

  /// Dart's `Uri` already drops the default port of `http` and `https` while
  /// parsing, but knows nothing of `ws` and `wss`, so `wss://host:443/x` would
  /// keep its port and miss the server's own copy of the URI.
  static const Map<String, int> _defaultPorts = <String, int>{
    'http': 80,
    'https': 443,
    'ws': 80,
    'wss': 443,
  };
}
