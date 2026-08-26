import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/curves/prime256v1.dart';
import 'package:pointycastle/key_generators/api.dart';
import 'package:pointycastle/key_generators/ec_key_generator.dart';
import 'package:pointycastle/random/fortuna_random.dart';

/// P-256 key generation and PEM encoding, built directly on `pointycastle` and
/// `asn1lib`.
///
/// Internal to the package: not exported from `dpop_client.dart`.
///
/// This is deliberately narrow — one curve, two PEM shapes — because that is
/// all a DPoP proof signer needs, and a general-purpose crypto utility library
/// brings an HTTP client, an archive reader and a logger along with it.

/// The octet length of a P-256 field element or private scalar.
const int p256FieldBytes = 32;

/// `id-ecPublicKey`, RFC 5480 §2.1.1.
const String _ecPublicKeyOid = '1.2.840.10045.2.1';

/// `prime256v1`, a.k.a. `secp256r1` and NIST P-256, RFC 5480 §2.1.1.1.
const String _prime256v1Oid = '1.2.840.10045.3.1.7';

const String _beginEcPrivateKey = '-----BEGIN EC PRIVATE KEY-----';
const String _endEcPrivateKey = '-----END EC PRIVATE KEY-----';
const String _beginPrivateKey = '-----BEGIN PRIVATE KEY-----';
const String _beginPublicKey = '-----BEGIN PUBLIC KEY-----';
const String _endPublicKey = '-----END PUBLIC KEY-----';

/// The context-specific constructed tags in RFC 5915's `ECPrivateKey`.
const int _tagParameters = 0xA0;
const int _tagPublicKey = 0xA1;

/// The P-256 domain parameters.
///
/// Built directly rather than looked up by name through pointycastle's
/// registry, so the curve cannot be missing at runtime.
ECDomainParameters p256() => ECCurve_prime256v1();

/// Generates a P-256 key pair from the platform's secure entropy source.
AsymmetricKeyPair<ECPublicKey, ECPrivateKey> generateP256KeyPair() {
  final ECKeyGenerator generator = ECKeyGenerator()
    ..init(
      ParametersWithRandom(ECKeyGeneratorParameters(p256()), _seededRandom()),
    );
  return generator.generateKeyPair();
}

/// A Fortuna instance seeded from `Random.secure()`, which is the OS CSPRNG.
SecureRandom _seededRandom() {
  final Random entropy = Random.secure();
  final Uint8List seed = Uint8List(32);
  for (int i = 0; i < seed.length; i++) {
    seed[i] = entropy.nextInt(256);
  }
  return FortunaRandom()..seed(KeyParameter(seed));
}

/// Encodes [key] as a SEC 1 `EC PRIVATE KEY` PEM, per
/// [RFC 5915](https://www.rfc-editor.org/rfc/rfc5915).
///
/// ```ASN1
/// ECPrivateKey ::= SEQUENCE {
///   version        INTEGER { ecPrivkeyVer1(1) },
///   privateKey     OCTET STRING,
///   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
///   publicKey  [1] BIT STRING OPTIONAL
/// }
/// ```
String encodeEcPrivateKeyToPem(ECPrivateKey key) {
  final ECDomainParameters? parameters = key.parameters;
  final BigInt? d = key.d;
  if (parameters == null || d == null) {
    throw ArgumentError.value(key, 'key', 'EC private key is incomplete');
  }

  final ASN1Sequence namedCurve = ASN1Sequence(tag: _tagParameters)
    ..add(ASN1ObjectIdentifier.fromComponentString(_prime256v1Oid));
  final ASN1Sequence publicKey = ASN1Sequence(tag: _tagPublicKey)
    ..add(ASN1BitString(_encodePoint(parameters.G * d)));

  final ASN1Sequence outer = ASN1Sequence()
    ..add(ASN1Integer(BigInt.one))
    // RFC 5915 §3 fixes this OCTET STRING at the curve's octet length. A
    // minimal-length encoding — which is what a scalar with a leading zero
    // byte produces, roughly one key in 256 — is not conformant, and strict
    // parsers reject the PEM.
    ..add(ASN1OctetString(i2osp(d, p256FieldBytes)))
    ..add(namedCurve)
    ..add(publicKey);

  return _wrapPem(_beginEcPrivateKey, _endEcPrivateKey, outer.encodedBytes);
}

/// Encodes [key] as an SPKI `PUBLIC KEY` PEM, per
/// [RFC 5480](https://www.rfc-editor.org/rfc/rfc5480).
String encodeEcPublicKeyToPem(ECPublicKey key) {
  final ASN1Sequence algorithm = ASN1Sequence()
    ..add(ASN1ObjectIdentifier.fromComponentString(_ecPublicKeyOid))
    ..add(ASN1ObjectIdentifier.fromComponentString(_prime256v1Oid));

  final ASN1Sequence outer = ASN1Sequence()
    ..add(algorithm)
    ..add(ASN1BitString(_encodePoint(key.Q)));

  return _wrapPem(_beginPublicKey, _endPublicKey, outer.encodedBytes);
}

/// Decodes a P-256 private key from a SEC 1 or PKCS#8 PEM.
///
/// Throws a [FormatException] if [pem] is not a readable EC private key on
/// P-256.
ECPrivateKey decodeEcPrivateKeyFromPem(String pem) {
  final ASN1Sequence top = _parseSequence(_derFromPem(pem));

  // PKCS#8 wraps the SEC 1 structure in an OCTET STRING:
  //   PrivateKeyInfo ::= SEQUENCE { version, AlgorithmIdentifier, OCTET STRING }
  final ASN1Sequence sec1;
  if (pem.contains(_beginPrivateKey)) {
    _requireP256(_algorithmCurveOid(top, 1), 'PKCS#8 AlgorithmIdentifier');
    sec1 = _parseSequence(_octetsAt(top, 2, 'PKCS#8 privateKey'));
  } else {
    sec1 = top;
  }

  // RFC 5915 makes `parameters [0]` optional; check it when it is there.
  if (sec1.elements.length > 2 && sec1.elements[2].tag == _tagParameters) {
    _requireP256(_taggedOid(sec1.elements[2]), 'SEC 1 parameters');
  }

  final BigInt d = _os2ip(_octetsAt(sec1, 1, 'SEC 1 privateKey'));
  final ECDomainParameters parameters = p256();
  if (d == BigInt.zero || d >= parameters.n) {
    throw const FormatException('EC private scalar is out of range for P-256.');
  }
  return ECPrivateKey(d, parameters);
}

/// Decodes a P-256 public key from an SPKI PEM.
///
/// Throws a [FormatException] if [pem] is not a readable EC public key on
/// P-256.
ECPublicKey decodeEcPublicKeyFromPem(String pem) {
  final ASN1Sequence top = _parseSequence(_derFromPem(pem));
  if (top.elements.length < 2) {
    throw const FormatException('SPKI structure is truncated.');
  }
  _requireP256(_algorithmCurveOid(top, 0), 'SPKI AlgorithmIdentifier');

  final ASN1Object bits = top.elements[1];
  if (bits is! ASN1BitString) {
    throw const FormatException('SPKI subjectPublicKey is not a BIT STRING.');
  }

  final ECDomainParameters parameters = p256();
  final ECPoint? q = _decodePoint(parameters, bits.stringValue);
  if (q == null) {
    throw const FormatException('SPKI point is not a valid P-256 point.');
  }
  return ECPublicKey(q, parameters);
}

/// Converts [value] to exactly [outLen] octets, big-endian and left-padded,
/// per RFC 3447's I2OSP.
///
/// Unlike a minimal-length encoding, the width is fixed: JOSE coordinates and
/// SEC 1 scalars are both defined as fixed-width fields.
Uint8List i2osp(BigInt value, int outLen) {
  if (value.isNegative) {
    throw ArgumentError.value(value, 'value', 'must not be negative');
  }
  final Uint8List out = Uint8List(outLen);
  BigInt remaining = value;
  for (int i = outLen - 1; i >= 0; i--) {
    out[i] = (remaining & BigInt.from(0xff)).toInt();
    remaining >>= 8;
  }
  if (remaining != BigInt.zero) {
    throw ArgumentError.value(value, 'value', 'does not fit in $outLen octets');
  }
  return out;
}

/// Rejects any curve but P-256, rather than reinterpreting another curve's
/// scalar or point against P-256's parameters and failing later as a bad
/// signature.
void _requireP256(String? oid, String where) {
  if (oid != _prime256v1Oid) {
    throw FormatException(
      'Unsupported curve in $where: ${oid ?? 'unreadable'}. This package '
      'signs DPoP proofs on P-256 (ES256) only.',
    );
  }
}

/// The named-curve OID from an `AlgorithmIdentifier` SEQUENCE at [index]:
/// `SEQUENCE { OID id-ecPublicKey, OID namedCurve }`.
String? _algorithmCurveOid(ASN1Sequence container, int index) {
  if (container.elements.length <= index) {
    return null;
  }
  final ASN1Object algorithm = container.elements[index];
  if (algorithm is! ASN1Sequence || algorithm.elements.length < 2) {
    return null;
  }
  final ASN1Object curve = algorithm.elements[1];
  return curve is ASN1ObjectIdentifier ? curve.identifier : null;
}

/// The OID inside a context-specific constructed element, whose content
/// `asn1lib` leaves unparsed.
String? _taggedOid(ASN1Object tagged) {
  try {
    final ASN1Object inner = ASN1Parser(tagged.valueBytes()).nextObject();
    return inner is ASN1ObjectIdentifier ? inner.identifier : null;
  } on Object {
    return null;
  }
}

BigInt _os2ip(List<int> bytes) {
  BigInt value = BigInt.zero;
  for (final int byte in bytes) {
    value = (value << 8) | BigInt.from(byte);
  }
  return value;
}

/// The uncompressed SEC 1 encoding of [point]: `0x04 || X || Y`.
Uint8List _encodePoint(ECPoint? point) {
  final Uint8List? encoded = point?.getEncoded(false);
  if (encoded == null) {
    throw ArgumentError.value(point, 'point', 'EC point is missing');
  }
  return encoded;
}

ECPoint? _decodePoint(ECDomainParameters parameters, List<int> encoded) {
  try {
    return parameters.curve.decodePoint(encoded);
  } on Object {
    return null;
  }
}

ASN1Sequence _parseSequence(Uint8List der) {
  final ASN1Object object;
  try {
    object = ASN1Parser(der).nextObject();
  } on Object catch (error) {
    throw FormatException('Not a readable DER structure: $error');
  }
  if (object is! ASN1Sequence) {
    throw const FormatException('DER structure is not a SEQUENCE.');
  }
  return object;
}

Uint8List _octetsAt(ASN1Sequence sequence, int index, String what) {
  if (sequence.elements.length <= index) {
    throw FormatException('$what is missing.');
  }
  final ASN1Object element = sequence.elements[index];
  if (element is! ASN1OctetString) {
    throw FormatException('$what is not an OCTET STRING.');
  }
  return Uint8List.fromList(element.octets);
}

String _wrapPem(String begin, String end, Uint8List der) {
  final String body = base64.encode(der);
  final List<String> lines = <String>[
    for (int i = 0; i < body.length; i += 64)
      body.substring(i, min(i + 64, body.length)),
  ];
  return '$begin\n${lines.join('\n')}\n$end';
}

Uint8List _derFromPem(String pem) {
  final String body = pem
      .split(RegExp(r'\r?\n'))
      .where(
        (String line) => !line.startsWith('-----') && line.trim().isNotEmpty,
      )
      .join();
  if (body.isEmpty) {
    throw const FormatException('PEM carries no base64 body.');
  }
  try {
    return base64.decode(body);
  } on FormatException catch (error) {
    throw FormatException('PEM body is not valid base64: ${error.message}');
  }
}
