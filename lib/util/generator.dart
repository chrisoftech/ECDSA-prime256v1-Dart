import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';
import 'package:pointycastle/export.dart';

class Generator {
  /// Generate a [PublicKey] and [PrivateKey] pair
  ///
  /// Returns a [AsymmetricKeyPair] based on the [ECKeyGenerator] with custom parameters
  Future<AsymmetricKeyPair<PublicKey, PrivateKey>> computeECDSAKeyPair(
      SecureRandom secureRandom) async {
    return await compute(secp256k1KeyPair, secureRandom);
  }

  SecureRandom getSecureRandom() {
    final secureRandom = FortunaRandom();
    final random = Random.secure();
    List<int> seeds = [];
    for (int i = 0; i < 32; i++) {
      seeds.add(random.nextInt(255));
    }
    secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));
    return secureRandom;
  }

  // Encode Private key to PEM Format
  ///
  /// Given [ECPrivateKey] returns a base64 encoded [String] with standard PEM headers and footers
  String encodeECDSAPrivateKeyToPemPKCS1(ECPrivateKey privateKey) {
    //TODO: re-address the accessed object `G` here since it remains constant on  key generation
    final dataBase64 = base64.encode(privateKey.parameters.G.getEncoded(false));

    return """-----BEGIN PRIVATE KEY-----\r\n$dataBase64\r\n-----END PRIVATE KEY-----""";
  }

  /// Encode Public key to PEM Format
  ///
  /// Given [ECPublicKey] returns a base64 encoded [String] with standard PEM headers and footers
  String encodeECDSAPublicKeyToPemPKCS1(ECPublicKey publicKey) {
    final dataBase64 = base64.encode(publicKey.Q.getEncoded(false));

    return """-----BEGIN PUBLIC KEY-----\r\n$dataBase64\r\n-----END PUBLIC KEY-----""";
  }

  String encodeSignatureToPem(ECSignature signature) {
    final topLevel = ASN1Sequence();
    topLevel.add(ASN1Integer(signature.r));
    topLevel.add(ASN1Integer(signature.s));

    final dataBase64 = base64Encode(topLevel.encodedBytes);
    print('Signature: $dataBase64');
    return dataBase64;
  }

  ECSignature generateSignature(String message, ECPrivateKey privateKey) {
    final _signer = ECDSASigner(SHA256Digest());
    final _privParams = () => ParametersWithRandom(
        PrivateKeyParameter<ECPrivateKey>(privateKey), getSecureRandom());

    _signer.init(true, _privParams());

    final ECSignature _ecSignature =
        _signer.generateSignature(sha256.convert(utf8.encode(message)).bytes);

    return _ecSignature;
  }

  bool verifySignature(
      String message, ECPublicKey publicKey, Signature signature) {
    final _signer = ECDSASigner(SHA256Digest());

    final _pubParams = () => PublicKeyParameter<ECPublicKey>(publicKey);

    _signer.reset();
    _signer.init(false, _pubParams());
    final _isVerified = _signer.verifySignature(
        sha256.convert(utf8.encode(message)).bytes, signature);

    print("Verified Signature: $_isVerified");
    return _isVerified;
  }
}

// Uint8List _seed() {
//   final random = Random.secure();
//   final seed = List<int>.generate(32, (_) => random.nextInt(256));
//   final _uInt8List = Uint8List.fromList(seed);

//   print('Seed: $_uInt8List');
//   return _uInt8List;
// }

AsymmetricKeyPair<PublicKey, PrivateKey> secp256k1KeyPair(SecureRandom random) {
  final keyParams = ECKeyGeneratorParameters(ECCurve_prime256v1());

  // final random = FortunaRandom();
  // random.seed(KeyParameter(_seed()));

  final generator = ECKeyGenerator();
  generator.init(ParametersWithRandom(keyParams, random));

  return generator.generateKeyPair();
}
