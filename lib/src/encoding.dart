import 'dart:convert';

/// Encodes [bytes] as base64url with the `=` padding stripped — the form every
/// JOSE field uses.
///
/// Internal to the package: not exported from `dpop_client.dart`.
String base64UrlUnpadded(List<int> bytes) =>
    base64Url.encode(bytes).replaceAll('=', '');
