/// A fixed key pair, so tests that need a deterministic thumbprint or
/// signature input do not have to generate one.
///
/// Generated once with [DPoPKeyPair.generate] and pinned here. It is a test
/// fixture in a public repository — never use it for anything else.
library;

/// The fixture's private key, in the SEC 1 PEM form
/// `DPoPKeyPair.privateKeyPem` emits.
const String goldenPrivateKeyPem = '''
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIME6VNd0gS2TIsdhuala9zX1PJnFEIAdDBFtcM6AuXDpoAoGCCqGSM49
AwEHoUQDQgAEgPOMNcff3ESb3NZEqJYYNq68YNUaY7UZ/Qf7GK70Vbfyo/MMWNDU
4OuiGRAfridJM6YO6PhVvDovKuusMHdjag==
-----END EC PRIVATE KEY-----''';

/// The fixture's RFC 7638 SHA-256 JWK thumbprint.
const String goldenThumbprint = 'D4QEbdCL-yzOFh_YbCfEQy7b5Soo6yg832PRnvjKAHA';

/// The `x` coordinate of the fixture's public key, unpadded base64url.
const String goldenX = 'gPOMNcff3ESb3NZEqJYYNq68YNUaY7UZ_Qf7GK70Vbc';

/// The `y` coordinate of the fixture's public key, unpadded base64url.
const String goldenY = '8qPzDFjQ1ODrohkQH64nSTOmDuj4Vbw6LyrrrDB3Y2o';

/// The fixture's public key in the SPKI PEM form
/// `DPoPKeyPair.publicKeyPem` emits, as produced independently by
/// `openssl ec -pubout`.
const String goldenPublicKeyPem = '''
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgPOMNcff3ESb3NZEqJYYNq68YNUa
Y7UZ/Qf7GK70Vbfyo/MMWNDU4OuiGRAfridJM6YO6PhVvDovKuusMHdjag==
-----END PUBLIC KEY-----''';

/// The same key in PKCS#8 form, as other tooling tends to emit it. Produced
/// with `openssl pkcs8 -topk8 -nocrypt`.
const String goldenPkcs8PrivateKeyPem = '''
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgwTpU13SBLZMix2G5
qVr3NfU8mcUQgB0MEW1wzoC5cOmhRANCAASA84w1x9/cRJvc1kSolhg2rrxg1Rpj
tRn9B/sYrvRVt/Kj8wxY0NTg66IZEB+uJ0kzpg7o+FW8Oi8q66wwd2Nq
-----END PRIVATE KEY-----''';

/// A P-384 private key, for checking that a curve this package does not
/// support is refused rather than reinterpreted against P-256.
const String p384PrivateKeyPem = '''
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDCXSqBQ8rEViUKx/Ui83DLBsgxlgNsPqYW5cjfU/PKujNt8y5eWKf8z
+xpkWhGRBZKgBwYFK4EEACKhZANiAATVBJ0XX0N0w27LUuJb5UUvWGhRyeYmHF7Q
I3zf1DjmEu9fd4CAgvKFofXJ+Hjkfh1iF2xGvGdVJMJN5oOe9E3YHF7H28CZXjNO
azwOtG71ocrhnIRRP3e39X0/xfBzmrQ=
-----END EC PRIVATE KEY-----''';

/// A secp256k1 public key. Same field size as P-256, so only the curve OID
/// distinguishes it.
const String secp256k1PublicKeyPem = '''
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE9m0Wkashzo8AE0+I2NlEUxdls/pZlnc2
ujICmbxc74hJUn3cO42GsLbqlTZA1Yp/TGoO/lYSSPQkDYlJ9djOPw==
-----END PUBLIC KEY-----''';
