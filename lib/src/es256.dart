import 'dart:typed_data';

import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart' as jwt;
import 'package:pointycastle/ecc/api.dart';

/// Signs [message] with [key], returning the 64 byte `r || s` form a JWS
/// carries.
///
/// Deterministic (RFC 6979), so equal inputs give equal signatures.
///
/// `ECPrivateKey.raw` takes the parsed key straight across. Handing the signer
/// a PEM instead would re-encode and re-parse the key on every request, which
/// costs more than the signature itself.
///
/// Internal to the package: not exported from `dpop_client.dart`.
Uint8List signEs256(ECPrivateKey key, Uint8List message) =>
    jwt.JWTAlgorithm.ES256.sign(jwt.ECPrivateKey.raw(key), message);
