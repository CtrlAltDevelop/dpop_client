import 'dart:typed_data';

/// Signs DPoP proofs without exposing the private key.
///
/// Implement this for a key the app cannot, or must not, read: a WebCrypto
/// `CryptoKey` created with `extractable: false`, or one in the Android
/// Keystore, the iOS Keychain or the Secure Enclave. Such keys can only sign,
/// and usually asynchronously, which is why this interface is async where
/// `DPoPKeyPair` signs in process.
///
/// Pass one to `DPoPSignerClient`. `DPoPKeyPair` implements it too, so one
/// code path serves both kinds of key.
abstract interface class DPoPSigner {
  /// The public key as a JWK: `kty: EC`, `crv: P-256`, `x` and `y` (base64url,
  /// unpadded).
  ///
  /// Published as-is in the `jwk` header of every proof, so it must hold
  /// public members only. A `d` member is refused when a proof is created.
  Map<String, String> get publicJwk;

  /// The ES256 signature of [message], the JWS signing input as UTF-8 bytes.
  ///
  /// The result must be the raw 64 byte `r || s` form a JWS carries (IEEE
  /// P1363), **not** the DER encoding that many platform APIs return — a DER
  /// signature is refused rather than sent as a proof no server can verify.
  /// WebCrypto's `crypto.subtle.sign` with ECDSA already returns `r || s`.
  Future<Uint8List> sign(Uint8List message);
}
