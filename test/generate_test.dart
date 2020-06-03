import 'dart:typed_data';

import 'package:cryptography_test/util/generator.dart';
import 'package:flutter/foundation.dart';
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

  test(
      'Different instances of getSecureRandom method should not return the same values',
      () {
    final _genSeed1 = _generator.getSecureRandom().nextBytes(32).toList();
    final _genSeed2 = _generator.getSecureRandom().nextBytes(32).toList();

    print('GEN 1 $_genSeed1');
    print('GEN 2 $_genSeed2');

    expect(_genSeed1, isNot(equals(_genSeed2)));
  });

  test("Should return true if generated seed has a conflict", () {
    bool _hasConflict = false;

    final _seeds = <List<int>>[];

    for (int i = 0; i < 100; i++) {
      final _genSeed = _generator.getSecureRandom().nextBytes(32);

      for (final seed in _seeds) {
        if (listEquals(seed, _genSeed.toList())) {
          _hasConflict = true;
          break;
        }
      }

      _seeds.add(_genSeed);
    }

    expect(_hasConflict, false);
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
