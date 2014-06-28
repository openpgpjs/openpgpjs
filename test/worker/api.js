'use strict';

var openpgp = typeof window != 'undefined' && window.openpgp ? window.openpgp : require('openpgp');

var chai = require('chai'),
  expect = chai.expect;


var pub_key_rsa =
  ['-----BEGIN PGP PUBLIC KEY BLOCK-----',
  'Version: GnuPG v2.0.19 (GNU/Linux)',
  '',
  'mI0EUmEvTgEEANyWtQQMOybQ9JltDqmaX0WnNPJeLILIM36sw6zL0nfTQ5zXSS3+',
  'fIF6P29lJFxpblWk02PSID5zX/DYU9/zjM2xPO8Oa4xo0cVTOTLj++Ri5mtr//f5',
  'GLsIXxFrBJhD/ghFsL3Op0GXOeLJ9A5bsOn8th7x6JucNKuaRB6bQbSPABEBAAG0',
  'JFRlc3QgTWNUZXN0aW5ndG9uIDx0ZXN0QGV4YW1wbGUuY29tPoi5BBMBAgAjBQJS',
  'YS9OAhsvBwsJCAcDAgEGFQgCCQoLBBYCAwECHgECF4AACgkQSmNhOk1uQJQwDAP6',
  'AgrTyqkRlJVqz2pb46TfbDM2TDF7o9CBnBzIGoxBhlRwpqALz7z2kxBDmwpQa+ki',
  'Bq3jZN/UosY9y8bhwMAlnrDY9jP1gdCo+H0sD48CdXybblNwaYpwqC8VSpDdTndf',
  '9j2wE/weihGp/DAdy/2kyBCaiOY1sjhUfJ1GogF49rC4jQRSYS9OAQQA6R/PtBFa',
  'JaT4jq10yqASk4sqwVMsc6HcifM5lSdxzExFP74naUMMyEsKHP53QxTF0Grqusag',
  'Qg/ZtgT0CN1HUM152y7ACOdp1giKjpMzOTQClqCoclyvWOFB+L/SwGEIJf7LSCEr',
  'woBuJifJc8xAVr0XX0JthoW+uP91eTQ3XpsAEQEAAYkBPQQYAQIACQUCUmEvTgIb',
  'LgCoCRBKY2E6TW5AlJ0gBBkBAgAGBQJSYS9OAAoJEOCE90RsICyXuqIEANmmiRCA',
  'SF7YK7PvFkieJNwzeK0V3F2lGX+uu6Y3Q/Zxdtwc4xR+me/CSBmsURyXTO29OWhP',
  'GLszPH9zSJU9BdDi6v0yNprmFPX/1Ng0Abn/sCkwetvjxC1YIvTLFwtUL/7v6NS2',
  'bZpsUxRTg9+cSrMWWSNjiY9qUKajm1tuzPDZXAUEAMNmAN3xXN/Kjyvj2OK2ck0X',
  'W748sl/tc3qiKPMJ+0AkMF7Pjhmh9nxqE9+QCEl7qinFqqBLjuzgUhBU4QlwX1GD',
  'AtNTq6ihLMD5v1d82ZC7tNatdlDMGWnIdvEMCv2GZcuIqDQ9rXWs49e7tq1NncLY',
  'hz3tYjKhoFTKEIq3y3Pp',
  '=h/aX',
  '-----END PGP PUBLIC KEY BLOCK-----'].join('\n');

var priv_key_rsa =
  ['-----BEGIN PGP PRIVATE KEY BLOCK-----',
  'Version: GnuPG v2.0.19 (GNU/Linux)',
  '',
  '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',
  '=lw5e',
  '-----END PGP PRIVATE KEY BLOCK-----'].join('\n');

var pub_key_de =
  ['-----BEGIN PGP PUBLIC KEY BLOCK-----',
  'Version: GnuPG v2.0.22 (GNU/Linux)',
  '',
  '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',
  'og2umGfGng==',
  '=v3+L',
  '-----END PGP PUBLIC KEY BLOCK-----'].join('\n');

var priv_key_de =
  ['-----BEGIN PGP PRIVATE KEY BLOCK-----',
  'Version: GnuPG v2.0.22 (GNU/Linux)',
  '',
  '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',
  'DHTORVqAOdoOcu5Qh7AQg1GdSmfFAsx2',
  '=kyeP',
  '-----END PGP PRIVATE KEY BLOCK-----'].join('\n');


  var plaintext = 'short message\nnext line\n한국어/조선말';

  var pubKeyRSA, privKeyRSA, pubKeyDE, privKeyDE;

  function initKeys() {
    pubKeyRSA = openpgp.key.readArmored(pub_key_rsa).keys[0];
    expect(pubKeyRSA).to.exist;
    privKeyRSA = openpgp.key.readArmored(priv_key_rsa).keys[0];
    expect(privKeyRSA).to.exist;
    pubKeyDE = openpgp.key.readArmored(pub_key_de).keys[0];
    expect(pubKeyDE).to.exist;
    privKeyDE = openpgp.key.readArmored(priv_key_de).keys[0];
    expect(privKeyDE).to.exist;
  }

describe('High level API', function() {

  this.timeout(0);

  before(function() {
    openpgp.initWorker('../dist/openpgp.worker.js');
    initKeys();
  });

  describe('Encryption', function() {

    it('RSA: encryptMessage async', function (done) {
      openpgp.encryptMessage([pubKeyRSA], plaintext, function(err, data) {
        expect(err).to.not.exist;
        expect(data).to.exist;
        expect(data).to.match(/^-----BEGIN PGP MESSAGE/);
        var msg = openpgp.message.readArmored(data);
        expect(msg).to.be.an.instanceof(openpgp.message.Message);
        done();
      });
    });

    it('RSA: encryptMessage one key async', function (done) {
      openpgp.encryptMessage(pubKeyRSA, plaintext, function(err, data) {
        expect(err).to.not.exist;
        expect(data).to.exist;
        expect(data).to.match(/^-----BEGIN PGP MESSAGE/);
        var msg = openpgp.message.readArmored(data);
        expect(msg).to.be.an.instanceof(openpgp.message.Message);
        done();
      });
    });

    it('RSA: encryptMessage sync', function () {
      var msg = openpgp.encryptMessage([pubKeyRSA], plaintext);
      expect(msg).to.exist;
      expect(msg).to.match(/^-----BEGIN PGP MESSAGE/);
      msg = openpgp.message.readArmored(msg);
      expect(msg).to.be.an.instanceof(openpgp.message.Message);
    });

    it('RSA: encryptMessage one key sync', function () {
      var msg = openpgp.encryptMessage(pubKeyRSA, plaintext);
      expect(msg).to.exist;
      expect(msg).to.match(/^-----BEGIN PGP MESSAGE/);
      msg = openpgp.message.readArmored(msg);
      expect(msg).to.be.an.instanceof(openpgp.message.Message);
    });

    it('ELG: encryptMessage async', function (done) {
      openpgp.encryptMessage([pubKeyDE], plaintext, function(err, data) {
        expect(err).to.not.exist;
        expect(data).to.exist;
        expect(data).to.match(/^-----BEGIN PGP MESSAGE/);
        var msg = openpgp.message.readArmored(data);
        expect(msg).to.be.an.instanceof(openpgp.message.Message);
        done();
      });
    });

    it('ELG: encryptMessage sync', function () {
      var msg = openpgp.encryptMessage([pubKeyDE], plaintext);
      expect(msg).to.exist;
      expect(msg).to.match(/^-----BEGIN PGP MESSAGE/);
      msg = openpgp.message.readArmored(msg);
      expect(msg).to.be.an.instanceof(openpgp.message.Message);
    });

  });

  describe('Decryption', function() {

    var msgRSA, msgDE;

    before(function() {
      privKeyRSA.decrypt('hello world');
      privKeyDE.decrypt('hello world');
      msgRSA = openpgp.message.fromText(plaintext).encrypt([pubKeyRSA]);
      msgDE = openpgp.message.fromText(plaintext).encrypt([pubKeyDE]);
    });

    it('RSA: decryptMessage async', function (done) {
      openpgp.decryptMessage(privKeyRSA, msgRSA, function(err, data) {
        expect(err).to.not.exist;
        expect(data).to.exist;
        expect(data).to.equal(plaintext);
        done();
      });
    });

    it('RSA: decryptMessage sync', function () {
      var text = openpgp.decryptMessage(privKeyRSA, msgRSA);
      expect(text).to.exist;
      expect(text).to.equal(plaintext);
    });

    it('ELG: decryptMessage async', function (done) {
      openpgp.decryptMessage(privKeyDE, msgDE, function(err, data) {
        expect(err).to.not.exist;
        expect(data).to.exist;
        expect(data).to.equal(plaintext);
        done();
      });
    });

    it('ELG: decryptMessage sync', function () {
      var text = openpgp.decryptMessage(privKeyDE, msgDE);
      expect(text).to.exist;
      expect(text).to.equal(plaintext);
    });

  });

  function verifySignature(data, privKey) {
    expect(data.text).to.equal(plaintext);
    expect(data.signatures).to.have.length(1);
    expect(data.signatures[0].valid).to.be.true;
    expect(data.signatures[0].keyid.equals(privKey.getSigningKeyPacket().getKeyId())).to.be.true;
  }

  describe('Decrypt and Verify', function() {

    var msgRSA, msgDE;

    before(function() {
      privKeyRSA.decrypt('hello world');
      privKeyDE.decrypt('hello world');
      msgRSA = openpgp.message.fromText(plaintext).sign([privKeyRSA]).encrypt([pubKeyRSA]);
      msgDE = openpgp.message.fromText(plaintext).sign([privKeyDE]).encrypt([pubKeyDE]);
    });

    it('RSA: decryptAndVerifyMessage async', function (done) {
      openpgp.decryptAndVerifyMessage(privKeyRSA, [pubKeyRSA], msgRSA, function(err, data) {
        expect(err).to.not.exist;
        expect(data).to.exist;
        verifySignature(data, privKeyRSA);
        done();
      });
    });

    it('ELG: decryptAndVerifyMessage async', function (done) {
      openpgp.decryptAndVerifyMessage(privKeyDE, [pubKeyDE], msgDE, function(err, data) {
        expect(err).to.not.exist;
        expect(data).to.exist;
        verifySignature(data, privKeyDE);
        done();
      });
    });

  });

  describe('Sign and Encrypt', function() {

    before(function() {
      privKeyRSA.decrypt('hello world');
    });

    it('RSA: signAndEncryptMessage async', function (done) {
      openpgp.signAndEncryptMessage([pubKeyRSA], privKeyRSA, plaintext, function(err, data) {
        expect(err).to.not.exist;
        expect(data).to.exist;
        expect(data).to.match(/^-----BEGIN PGP MESSAGE/);
        var msg = openpgp.message.readArmored(data);
        expect(msg).to.be.an.instanceof(openpgp.message.Message);
        var decrypted = openpgp.decryptAndVerifyMessage(privKeyRSA, [pubKeyRSA], msg);
        verifySignature(decrypted, privKeyRSA);
        done();
      });
    });

  });

  describe('Signing', function() {

    before(function() {
      privKeyRSA.decrypt('hello world');
      privKeyDE.decrypt('hello world');
    });

    it('RSA: signClearMessage async', function (done) {
      openpgp.signClearMessage([privKeyRSA], plaintext, function(err, data) {
        expect(err).to.not.exist;
        expect(data).to.exist;
        expect(data).to.match(/-----BEGIN PGP SIGNED MESSAGE-----/);
        var msg = openpgp.message.readArmored(data);
        expect(msg).to.be.an.instanceof(openpgp.message.Message);
        done();
      });
    });

    it('DSA: signClearMessage async', function (done) {
      openpgp.signClearMessage([privKeyDE], plaintext, function(err, data) {
        expect(err).to.not.exist;
        expect(data).to.exist;
        expect(data).to.match(/-----BEGIN PGP SIGNED MESSAGE-----/);
        var msg = openpgp.message.readArmored(data);
        expect(msg).to.be.an.instanceof(openpgp.message.Message);
        done();
      });
    });

    it('RSA: verifyClearSignedMessage async', function (done) {
      var signed = openpgp.signClearMessage([privKeyRSA], plaintext);
      signed = openpgp.cleartext.readArmored(signed);
      openpgp.verifyClearSignedMessage([pubKeyRSA], signed, function(err, data) {
        expect(err).to.not.exist;
        expect(data).to.exist;
        verifySignature(data, privKeyRSA);
        done();
      });
    });

  });

  describe('Error handling', function() {

    before(initKeys);

    it('Signing with not decrypted key gives error', function (done) {
      openpgp.signClearMessage([privKeyRSA], plaintext, function(err, data) {
        expect(data).to.not.exist;
        expect(err).to.exist;
        expect(err.message).to.equal('Private key is not decrypted.');
        done();
      });
    });

    it('Depleted random buffer in worker gives error', function (done) {
      var wProxy = new openpgp.AsyncProxy('../dist/openpgp.worker.js');
      wProxy.worker = new Worker('../dist/openpgp.worker.js');
      wProxy.worker.onmessage = wProxy.onMessage.bind(wProxy);
      wProxy.seedRandom(10);
      wProxy.encryptMessage([pubKeyRSA], plaintext, function(err, data) {
        expect(data).to.not.exist;
        expect(err).to.exist;
        expect(err).to.eql(new Error('Random number buffer depleted'));
        done();
      });
    });

  });

  describe('Key generation', function() {

    it('Generate 1024-bit RSA/RSA key async', function (done) {
      openpgp.generateKeyPair({numBits: 1024, userId: 'Test McTestington <test@example.com>', passphrase: 'hello world'}, function(err, data) {
        expect(err).to.not.exist;
        expect(data).to.exist;
        expect(data.publicKeyArmored).to.match(/^-----BEGIN PGP PUBLIC/);
        expect(data.privateKeyArmored).to.match(/^-----BEGIN PGP PRIVATE/);
        expect(data.key).to.be.an.instanceof(openpgp.key.Key);
        done();
      });
    });

    it('Generate 1024-bit RSA/RSA key sync', function () {
      var key = openpgp.generateKeyPair({numBits: 1024, userId: 'Test McTestington <test@example.com>', passphrase: 'hello world'});
      expect(key).to.exist;
      expect(key.publicKeyArmored).to.match(/^-----BEGIN PGP PUBLIC/);
      expect(key.privateKeyArmored).to.match(/^-----BEGIN PGP PRIVATE/);
      expect(key.key).to.be.an.instanceof(openpgp.key.Key);
    });

  });

  describe('Decrypt secret key', function() {

    var msg, proxy;

    beforeEach(function() {
      proxy = new openpgp.AsyncProxy('../dist/openpgp.worker.js');
      initKeys();
      msg = openpgp.message.fromText(plaintext).encrypt([pubKeyRSA]);
    });

    it('Decrypt key', function (done) {
      expect(privKeyRSA.primaryKey.isDecrypted).to.be.false;
      expect(privKeyRSA.subKeys[0].subKey.isDecrypted).to.be.false;
      proxy.decryptKey(privKeyRSA, 'hello world', function(err, data) {
        expect(err).to.not.exist;
        expect(data).to.exist;
        expect(data).to.be.an.instanceof(openpgp.key.Key);
        expect(data.primaryKey.isDecrypted).to.be.true;
        expect(data.subKeys[0].subKey.isDecrypted).to.be.true;
        var text = openpgp.decryptMessage(data, msg);
        expect(text).to.equal(plaintext);
        done();
      });
    });

    it('Decrypt key packet', function (done) {
      expect(privKeyRSA.primaryKey.isDecrypted).to.be.false;
      expect(privKeyRSA.subKeys[0].subKey.isDecrypted).to.be.false;
      var keyid = privKeyRSA.subKeys[0].subKey.getKeyId();
      proxy.decryptKeyPacket(privKeyRSA, [keyid], 'hello world', function(err, data) {
        expect(err).to.not.exist;
        expect(data).to.exist;
        expect(data).to.be.an.instanceof(openpgp.key.Key);
        expect(data.primaryKey.isDecrypted).to.be.false;
        expect(data.subKeys[0].subKey.isDecrypted).to.be.true;
        var text = openpgp.decryptMessage(data, msg);
        expect(text).to.equal(plaintext);
        done();
      });
    });

    it('Error on wrong password decryptKey', function (done) {
      proxy.decryptKey(privKeyRSA, 'what?', function(err, data) {
        expect(err).to.eql(new Error('Wrong password'));
        done();
      });
    });

    it('Error on wrong password decryptKeyPacket', function (done) {
      var keyid = privKeyRSA.subKeys[0].subKey.getKeyId();
      proxy.decryptKeyPacket(privKeyRSA, [keyid], 'what?', function(err, data) {
        expect(err).to.eql(new Error('Wrong password'));
        done();
      });
    });

  });

});

describe('Random Buffer', function() {

  var randomBuffer;

  before(function() {
    randomBuffer = new openpgp.crypto.random.randomBuffer.constructor();
    expect(randomBuffer).to.exist;
  });

  it('Throw error if not initialized', function () {
    expect(randomBuffer.set).to.throw('RandomBuffer is not initialized');
    expect(randomBuffer.get).to.throw('RandomBuffer is not initialized');
  });

  it('Initialization', function () {
    randomBuffer.init(5);
    expect(randomBuffer.buffer).to.exist;
    expect(randomBuffer.buffer).to.have.length(5);
    expect(randomBuffer.size).to.equal(0);
  });

  function equal(buf, arr) {
    for (var i = 0; i < buf.length; i++) {
      if (buf[i] !== arr[i]) return false;
    }
    return true;
  }

  it('Set Method', function () {
    randomBuffer.init(5);
    var buf = new Uint32Array(2);
    expect(randomBuffer.set.bind(randomBuffer, buf)).to.throw('Invalid type: buf not an Uint8Array');
    buf = new Uint8Array(2);
    buf[0] = 1; buf[1] = 2;
    randomBuffer.set(buf);
    expect(equal(randomBuffer.buffer, [1,2,0,0,0])).to.be.true;
    expect(randomBuffer.size).to.equal(2);
    randomBuffer.set(buf);
    expect(equal(randomBuffer.buffer, [1,2,1,2,0])).to.be.true;
    expect(randomBuffer.size).to.equal(4);
    randomBuffer.set(buf);
    expect(equal(randomBuffer.buffer, [1,2,1,2,1])).to.be.true;
    expect(randomBuffer.size).to.equal(5);
    randomBuffer.init(1);
    buf = new Uint8Array(2);
    buf[0] = 1; buf[1] = 2;
    randomBuffer.set(buf);
    expect(buf).to.to.have.property('0', 1);
    expect(randomBuffer.size).to.equal(1);
  });

  it('Get Method', function () {
    randomBuffer.init(5);
    var buf = new Uint8Array(5);
    buf[0] = 1; buf[1] = 2; buf[2] = 5; buf[3] = 7; buf[4] = 8;
    randomBuffer.set(buf);
    buf = new Uint32Array(2);
    expect(randomBuffer.get.bind(randomBuffer, buf)).to.throw('Invalid type: buf not an Uint8Array');
    buf = new Uint8Array(2);
    randomBuffer.get(buf);
    expect(equal(randomBuffer.buffer, [1,2,5,0,0])).to.be.true;
    expect(randomBuffer.size).to.equal(3);
    expect(buf).to.to.have.property('0', 8);
    expect(buf).to.to.have.property('1', 7);
    randomBuffer.get(buf);
    expect(buf).to.to.have.property('0', 5);
    expect(buf).to.to.have.property('1', 2);
    expect(equal(randomBuffer.buffer, [1,0,0,0,0])).to.be.true;
    expect(randomBuffer.size).to.equal(1);
    expect(function() { randomBuffer.get(buf) }).to.throw('Random number buffer depleted');
  });

});
