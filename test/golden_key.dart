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
