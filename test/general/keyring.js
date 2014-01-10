'use strict';

var openpgp = typeof window != 'undefined' && window.openpgp ? window.openpgp : require('../../src/index');

var keyring = new openpgp.Keyring(),
  chai = require('chai'),
  expect = chai.expect;

describe("Keyring", function() {
  var user = 'test@t-online.de',
    passphrase = 'asdf',
    keySize = 512,
    keyId = 'F6F60E9B42CDFF4C',
    pubkey = '-----BEGIN PGP PUBLIC KEY BLOCK-----\n' +
      'Version: OpenPGP.js v.1.20131011\n' +
      'Comment: http://openpgpjs.org\n' +
      '\n' +
      'xk0EUlhMvAEB/2MZtCUOAYvyLFjDp3OBMGn3Ev8FwjzyPbIF0JUw+L7y2XR5\n' +
      'RVGvbK88unV3cU/1tOYdNsXI6pSp/Ztjyv7vbBUAEQEAAc0pV2hpdGVvdXQg\n' +
      'VXNlciA8d2hpdGVvdXQudGVzdEB0LW9ubGluZS5kZT7CXAQQAQgAEAUCUlhM\n' +
      'vQkQ9vYOm0LN/0wAAAW4Af9C+kYW1AvNWmivdtr0M0iYCUjM9DNOQH1fcvXq\n' +
      'IiN602mWrkd8jcEzLsW5IUNzVPLhrFIuKyBDTpLnC07Loce1\n' +
      '=6XMW\n' +
      '-----END PGP PUBLIC KEY BLOCK-----',
    privkey = '-----BEGIN PGP PRIVATE KEY BLOCK-----\n' +
      'Version: OpenPGP.js v.1.20131011\n' +
      'Comment: http://openpgpjs.org\n' +
      '\n' +
      'xcBeBFJYTLwBAf9jGbQlDgGL8ixYw6dzgTBp9xL/BcI88j2yBdCVMPi+8tl0\n' +
      'eUVRr2yvPLp1d3FP9bTmHTbFyOqUqf2bY8r+72wVABEBAAH+AwMIhNB4ivtv\n' +
      'Y2xg6VeMcjjHxZayESHACV+nQx5Tx6ev6xzIF1Qh72fNPDppLhFSFOuTTMsU\n' +
      'kTN4c+BVYt29spH+cA1jcDAxQ2ULrNAXo+hheOqhpedTs8aCbcLFkJAS16hk\n' +
      'YSk4OnJgp/z24rVju1SHRSFbgundPzmNgXeX9e8IkviGhhQ11Wc5YwVkx03t\n' +
      'Z3MdDMF0jyhopbPIoBdyJB0dhvBh98w3JmwpYh9wjUA9MBHD1tvHpRmSZ3BM\n' +
      'UCmATn2ZLWBRWiYqFbgDnL1GM80pV2hpdGVvdXQgVXNlciA8d2hpdGVvdXQu\n' +
      'dGVzdEB0LW9ubGluZS5kZT7CXAQQAQgAEAUCUlhMvQkQ9vYOm0LN/0wAAAW4\n' +
      'Af9C+kYW1AvNWmivdtr0M0iYCUjM9DNOQH1fcvXqIiN602mWrkd8jcEzLsW5\n' +
      'IUNzVPLhrFIuKyBDTpLnC07Loce1\n' +
      '=ULta\n' +
      '-----END PGP PRIVATE KEY BLOCK-----';

  it('Import key pair', function(done) {
    // clear any keys already in the keychain
    keyring.clear();
    keyring.importKey(privkey);
    keyring.importKey(pubkey);
    done();
  });

  it('getPublicKeyForAddress() - unknown address', function(done) {
    var key = keyring.getPublicKeyForAddress('nobody@example.com');
    expect(key).to.be.empty;
    done();
  });
  it('getPublicKeyForAddress() - valid address', function(done) {
    var key = keyring.getPublicKeyForAddress(user);
    expect(key).to.exist;
    done();
  });
  it('getPrivateKeyForAddress() - unknown address', function(done) {
    var key = keyring.getPrivateKeyForAddress('nobody@example.com');
    expect(key).to.be.empty;
    done();
  });
  it('getPrivateKeyForAddress() - valid address', function(done) {
    var key = keyring.getPrivateKeyForAddress(user);
    expect(key).to.exist;
    done();
  });
  it('getKeysForKeyId() - unknown id', function(done) {
    var keys = keyring.getKeysForKeyId('000102030405060708');
    expect(keys).to.be.empty;
    done();
  });
  it('getKeysForKeyId() - valid id', function(done) {
    var keys = keyring.getKeysForKeyId(keyId.toLowerCase());
    expect(keys).to.exist.and.have.length(1);
    done();
  });
});

 
