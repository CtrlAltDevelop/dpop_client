// Signs proofs for a short request sequence, printing the claims a server
// would check. Nothing here talks to a network.
import 'dart:convert';

import 'package:dpop_client/dpop_client.dart';

/// Decodes a JWT segment for display. A real client never needs this — the
/// server does the reading.
Map<String, dynamic> decode(String segment) =>
    jsonDecode(utf8.decode(base64Url.decode(base64Url.normalize(segment))))
        as Map<String, dynamic>;

void main() {
  // 1. Once per installation: generate a pair and persist the private PEM.
  //    In a real app that string belongs in the platform keystore.
  final keyPair = DPoPKeyPair.generate();
  final stored = keyPair.privateKeyPem;

  // 2. On a later launch: restore it. The public half is derived, so the one
  //    PEM is all that has to be kept.
  final restored = DPoPKeyPair.fromPrivateKeyPem(stored);
  print(
    'thumbprint survives a restore: '
    '${restored.thumbprint == keyPair.thumbprint}',
  );
  print('jkt to expect in the token\'s cnf claim: ${restored.thumbprint}');

  final client = DPoPClient(restored);

  // 3. The token request, before any access token exists — no `ath`.
  final tokenProof = client.createProof(
    url: Uri.parse('https://auth.example.com/oauth2/token'),
    method: 'POST',
  );
  print('\ntoken request  -> ${decode(tokenProof.token.split('.')[1])}');

  // 4. A resource request. Passing the access token adds `ath`, which is what
  //    binds this proof to that token.
  const accessToken = 'stub.access.token';
  final apiProof = client.createProof(
    url: Uri.parse('https://api.example.com/v1/orders?limit=20&lang=en'),
    method: 'POST',
    accessToken: accessToken,
  );
  final claims = decode(apiProof.token.split('.')[1]);
  print('\napi request    -> $claims');
  // Note the htu: the query string is gone, as RFC 9449 requires.
  print('htu has no query: ${!(claims['htu'] as String).contains('?')}');

  // 5. The server answers 401 with `error="use_dpop_nonce"` and a
  //    `DPoP-Nonce` header. Retry the same request carrying that nonce, and
  //    keep using it until the server issues another.
  final retried = client.createProof(
    url: Uri.parse('https://api.example.com/v1/orders?limit=20&lang=en'),
    method: 'POST',
    accessToken: accessToken,
    nonce: 'eyJ7S_zG.eyJIOjki.hSfMzSHA',
  );
  print('\nretry w/ nonce -> ${decode(retried.token.split('.')[1])}');

  print('\nheaders to send:');
  // 6. Attaching it to a request. When the proof was built with an access
  //    token, `headers()` also returns the Authorization header — under the
  //    DPoP scheme, not Bearer, which RFC 9449 §7.1 requires for a bound
  //    token and which is the step most integrations miss.
  retried.headers().forEach((name, value) {
    final shown = value.length > 48 ? '${value.substring(0, 45)}...' : value;
    print('  $name: $shown');
  });

  // A proof with no access token carries no Authorization header, matching
  // the absent `ath` claim.
  print('\ntoken request headers: ${tokenProof.headers().keys.toList()}');
}
