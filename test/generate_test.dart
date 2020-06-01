import 'package:cryptography_test/util/generator.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:pointycastle/api.dart';
import 'package:matcher/matcher.dart';
import 'package:pointycastle/export.dart';

void main() {
  SecureRandom _secureRandom;
  Generator _generator;

  setUpAll(() {
    _generator = Generator();
    _secureRandom = _generator.getSecureRandom();
  });

  test('should generate a secp256k1 key pair', () {
    final AsymmetricKeyPair<PublicKey, PrivateKey> generatedKeyPair =
        secp256k1KeyPair(_secureRandom);

    expect(generatedKeyPair.privateKey, TypeMatcher<PrivateKey>());
    expect(generatedKeyPair.publicKey, TypeMatcher<PublicKey>());
  });

  group('Signature', () {
    final _tMessage = 'test message';

    AsymmetricKeyPair<PublicKey, PrivateKey> _generatedKeyPair;

    setUp(() {
      _generatedKeyPair = secp256k1KeyPair(_secureRandom);
    });

    test('should return true if signed text is verifiable with public-key', () {
      final _signature =
          _generator.generateSignature(_tMessage, _generatedKeyPair.privateKey);

      final _isSignedByPrimaryKey = _generator.verifySignature(
          _tMessage, _generatedKeyPair.publicKey, _signature);

      expect(_signature, TypeMatcher<ECSignature>());
      expect(_isSignedByPrimaryKey, equals(true));
    });

    test(
        'should return false if presumably signed text is not verifiable with public-key',
        () {
      final _newTestMessage = '$_tMessage added to change signed message';

      final _signature =
          _generator.generateSignature(_tMessage, _generatedKeyPair.privateKey);

      final _isSignedByPrimaryKey = _generator.verifySignature(
          _newTestMessage, _generatedKeyPair.publicKey, _signature);

      expect(_signature, TypeMatcher<ECSignature>());
      expect(_isSignedByPrimaryKey, equals(false));
    });

    test(
        'should return false if signed text is not verifiable with the wrong public-key',
        () {
      final _signature =
          _generator.generateSignature(_tMessage, _generatedKeyPair.privateKey);

      // generated another key-pair
      final _differentGeneratedKeyPair = secp256k1KeyPair(_secureRandom);

      final _isSignedByPrimaryKey = _generator.verifySignature(
          _tMessage, _differentGeneratedKeyPair.publicKey, _signature);

      expect(_signature, TypeMatcher<ECSignature>());
      expect(_isSignedByPrimaryKey, equals(false));
    });
  });
}
