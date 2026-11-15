import 'dart:typed_data';

import 'dpop_proof.dart';
import 'dpop_signer.dart';
import 'jwk_thumbprint.dart';
import 'unsigned_proof.dart';

/// Signs DPoP proof JWTs with a [DPoPSigner], so the private key never has to
/// enter Dart memory.
///
/// The counterpart of `DPoPClient` for a key held in a WebCrypto `CryptoKey`
/// or a platform keystore, where signing is asynchronous. The parameters,
/// claims, URL normalisation and `DPoPProof.headers` output are exactly those
/// of `DPoPClient.createProof`; both build the proof with the same code.
///
/// ```dart
/// final client = DPoPSignerClient(keystoreSigner);
///
/// final proof = await client.createProof(
///   url: Uri.parse('https://api.example.com/orders?limit=20'),
///   method: 'POST',
///   accessToken: accessToken,
/// );
///
/// request.headers.addAll(proof.headers());
/// ```
class DPoPSignerClient {
  /// Creates a proof signer backed by [signer].
  const DPoPSignerClient(this.signer);

  /// The signer every proof is signed with, and whose public JWK travels in
  /// each proof's JWT header.
  final DPoPSigner signer;

  /// The signing key's RFC 7638 thumbprint — the `jkt` an authorization
  /// server binds an access token to. Computed from `signer.publicJwk` on
  /// each call.
  ///
  /// Throws an [ArgumentError] if the signer's JWK is not a public P-256 key.
  String get thumbprint => dpopThumbprint(signer.publicJwk);

  /// Signs a proof for one request.
  ///
  /// Takes the same arguments, with the same meaning, as
  /// `DPoPClient.createProof`: [url] is absolute and loses its query, fragment
  /// and userinfo in the `htu` claim (`ws` and `wss` URLs are accepted, and
  /// their default ports dropped, so a WebSocket handshake can carry a proof);
  /// [accessToken] adds `ath`; [nonce] is omitted when null or empty;
  /// [issuedAt] and [jwtId] are for tests, and for applying a server clock
  /// offset to `iat`.
  ///
  /// Failures arrive as a failed future, never a silently unsigned proof: an
  /// [ArgumentError] for a bad [url] or a JWK that is not a public P-256 key,
  /// a [StateError] if the signer returns anything but the 64 byte `r || s`
  /// signature, and whatever the signer itself throws.
  Future<DPoPProof> createProof({
    required Uri url,
    required String method,
    String? accessToken,
    String? nonce,
    DateTime? issuedAt,
    String? jwtId,
  }) async {
    // One read, frozen: the same map must reach the header, the thumbprint
    // and the proof even if the signer hands out a mutable one.
    final Map<String, String> publicJwk = Map<String, String>.unmodifiable(
      signer.publicJwk,
    );
    final String thumbprint = dpopThumbprint(publicJwk);

    final UnsignedProof unsigned = UnsignedProof(
      publicJwk: publicJwk,
      url: url,
      method: method,
      accessToken: accessToken,
      nonce: nonce,
      issuedAt: issuedAt,
      jwtId: jwtId,
    );
    final Uint8List signature = await signer.sign(unsigned.signingBytes);
    return unsigned.complete(signature, thumbprint: thumbprint);
  }
}
