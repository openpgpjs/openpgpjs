'use strict';

var openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../dist/openpgp');

var sinon = require('sinon'),
  chai = require('chai'),
  expect = chai.expect;

describe('OpenPGP.js public api tests', function() {

  describe('initWorker, getWorker, destroyWorker - unit tests', function() {
    afterEach(function() {
      openpgp.destroyWorker(); // cleanup worker in case of failure
    });

    it('should work', function() {
      var workerStub = {
        postMessage: function() {}
      };
      openpgp.initWorker({
        worker: workerStub
      });
      expect(openpgp.getWorker()).to.exist;
      openpgp.destroyWorker();
      expect(openpgp.getWorker()).to.not.exist;
    });
  });

  describe('generateKey - unit tests', function() {
    var keyGenStub, keyObjStub, getWebCryptoStub;

    beforeEach(function() {
      keyObjStub = {
        armor: function() {
          return 'priv_key';
        },
        toPublic: function() {
          return {
            armor: function() {
              return 'pub_key';
            }
          };
        }
      };
      keyGenStub = sinon.stub(openpgp.key, 'generate');
      keyGenStub.returns(resolves(keyObjStub));
      getWebCryptoStub = sinon.stub(openpgp.util, 'getWebCrypto');
    });

    afterEach(function() {
      keyGenStub.restore();
      openpgp.destroyWorker();
      getWebCryptoStub.restore();
    });

    it('should fail for invalid user name', function() {
      var opt = {
        userIds: [{ name: {}, email: 'text@example.com' }]
      };
      var test = openpgp.generateKey.bind(null, opt);
      expect(test).to.throw(/Invalid user id format/);
    });

    it('should fail for invalid user email address', function() {
      var opt = {
        userIds: [{ name: 'Test User', email: 'textexample.com' }]
      };
      var test = openpgp.generateKey.bind(null, opt);
      expect(test).to.throw(/Invalid user id format/);
    });

    it('should fail for invalid user email address', function() {
      var opt = {
        userIds: [{ name: 'Test User', email: 'text@examplecom' }]
      };
      var test = openpgp.generateKey.bind(null, opt);
      expect(test).to.throw(/Invalid user id format/);
    });

    it('should fail for invalid string user id', function() {
      var opt = {
        userIds: ['Test User text@example.com>']
      };
      var test = openpgp.generateKey.bind(null, opt);
      expect(test).to.throw(/Invalid user id format/);
    });

    it('should fail for invalid single string user id', function() {
      var opt = {
        userIds: 'Test User text@example.com>'
      };
      var test = openpgp.generateKey.bind(null, opt);
      expect(test).to.throw(/Invalid user id format/);
    });

    it('should work for valid single string user id', function(done) {
      var opt = {
        userIds: 'Test User <text@example.com>'
      };
      openpgp.generateKey(opt).then(function() { done(); });
    });

    it('should work for valid string user id', function(done) {
      var opt = {
        userIds: ['Test User <text@example.com>']
      };
      openpgp.generateKey(opt).then(function() { done(); });
    });

    it('should work for valid single user id hash', function(done) {
      var opt = {
        userIds: { name: 'Test User', email: 'text@example.com' }
      };
      openpgp.generateKey(opt).then(function() { done(); });
    });

    it('should work for valid single user id hash', function(done) {
      var opt = {
        userIds: [{ name: 'Test User', email: 'text@example.com' }]
      };
      openpgp.generateKey(opt).then(function() { done(); });
    });

    it('should work for an empty name', function(done) {
      var opt = {
        userIds: { email: 'text@example.com' }
      };
      openpgp.generateKey(opt).then(function() { done(); });
    });

    it('should work for an empty email address', function(done) {
      var opt = {
        userIds: { name: 'Test User' }
      };
      openpgp.generateKey(opt).then(function() { done(); });
    });

    it('should have default params set', function(done) {
      var opt = {
        userIds: { name: 'Test User', email: 'text@example.com' },
        passphrase: 'secret',
        unlocked: true
      };
      openpgp.generateKey(opt).then(function(newKey) {
        expect(keyGenStub.withArgs({
          userIds: ['Test User <text@example.com>'],
          passphrase: 'secret',
          numBits: 2048,
          unlocked: true
        }).calledOnce).to.be.true;
        expect(newKey.key).to.exist;
        expect(newKey.privateKeyArmored).to.exist;
        expect(newKey.publicKeyArmored).to.exist;
        done();
      });
    });

    it('should work for no params', function(done) {
      openpgp.generateKey().then(function(newKey) {
        expect(keyGenStub.withArgs({
          userIds: [],
          passphrase: undefined,
          numBits: 2048,
          unlocked: false
        }).calledOnce).to.be.true;
        expect(newKey.key).to.exist;
        done();
      });
    });

    it('should delegate to async proxy', function() {
      var workerStub = {
        postMessage: function() {}
      };
      openpgp.initWorker({
        worker: workerStub
      });
      var proxyGenStub = sinon.stub(openpgp.getWorker(), 'generateKey');
      getWebCryptoStub.returns();

      openpgp.generateKey();
      expect(proxyGenStub.calledOnce).to.be.true;
      expect(keyGenStub.calledOnce).to.be.false;
    });

    it('should delegate to async proxy after web crypto failure', function(done) {
      var workerStub = {
        postMessage: function() {}
      };
      openpgp.initWorker({
        worker: workerStub
      });
      var proxyGenStub = sinon.stub(openpgp.getWorker(), 'generateKey').returns(resolves('proxy_key'));
      getWebCryptoStub.returns({});
      keyGenStub.returns(rejects(new Error('Native webcrypto keygen failed on purpose :)')));

      openpgp.generateKey().then(function(newKey) {
        expect(keyGenStub.calledOnce).to.be.true;
        expect(proxyGenStub.calledOnce).to.be.true;
        expect(newKey).to.equal('proxy_key');
        done();
      });
    });
  });

  describe('generateKey - integration tests', function() {
    var useNativeVal;

    beforeEach(function() {
      useNativeVal = openpgp.config.useNative;
    });

    afterEach(function() {
      openpgp.config.useNative = useNativeVal;
      openpgp.destroyWorker();
    });

    it('should work in JS (without worker)', function(done) {
      openpgp.config.useNative = false;
      openpgp.destroyWorker();
      var opt = {
        userIds: [{ name: 'Test User', email: 'text@example.com' }],
        numBits: 512
      };

      openpgp.generateKey(opt).then(function(newKey) {
        expect(newKey.key.getUserIds()[0]).to.equal('Test User <text@example.com>');
        expect(newKey.privateKeyArmored).to.exist;
        expect(newKey.publicKeyArmored).to.exist;
        done();
      });
    });

    it('should work in JS (with worker)', function(done) {
      openpgp.config.useNative = false;
      openpgp.initWorker({ path:'../dist/openpgp.worker.js' });
      var opt = {
        userIds: [{ name: 'Test User', email: 'text@example.com' }],
        numBits: 512
      };

      openpgp.generateKey(opt).then(function(newKey) {
        expect(newKey.key.getUserIds()[0]).to.equal('Test User <text@example.com>');
        expect(newKey.privateKeyArmored).to.exist;
        expect(newKey.publicKeyArmored).to.exist;
        done();
      });
    });

    it('should work in JS (use native)', function(done) {
      openpgp.config.useNative = true;
      var opt = {
        userIds: [{ name: 'Test User', email: 'text@example.com' }],
        numBits: 512
      };
      if (openpgp.util.getWebCrypto()) { opt.numBits = 2048; } // webkit webcrypto accepts minimum 2048 bit keys

      openpgp.generateKey(opt).then(function(newKey) {
        expect(newKey.key.getUserIds()[0]).to.equal('Test User <text@example.com>');
        expect(newKey.privateKeyArmored).to.exist;
        expect(newKey.publicKeyArmored).to.exist;
        done();
      });
    });
  });

  describe('encrypt, decrypt - integration tests', function() {
    var pub_key =
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

    var priv_key =
        ['-----BEGIN PGP PRIVATE KEY BLOCK-----',
        'Version: GnuPG v2.0.19 (GNU/Linux)',
        '',
        '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',
        '=lw5e',
        '-----END PGP PRIVATE KEY BLOCK-----'].join('\n');

    var passphrase = 'hello world';
    var plaintext = 'short message\nnext line\n한국어/조선말';
    var password1 = 'I am a password';
    var password2 = 'I am another password';

    var privateKey, publicKey;

    before(function() {
      openpgp.initWorker({ path:'../dist/openpgp.worker.js' });
    });

    beforeEach(function() {
      publicKey = openpgp.key.readArmored(pub_key);
      expect(publicKey.keys).to.have.length(1);
      expect(publicKey.err).to.not.exist;
      privateKey = openpgp.key.readArmored(priv_key);
      expect(privateKey.keys).to.have.length(1);
      expect(privateKey.err).to.not.exist;
    });

    after(function() {
      openpgp.destroyWorker(); // cleanup worker in case of failure
    });

    it('Decrypting key with wrong passphrase returns false', function () {
      expect(privateKey.keys[0].decrypt('wrong passphrase')).to.be.false;
    });

    it('Decrypting key with correct passphrase returns true', function () {
      expect(privateKey.keys[0].decrypt(passphrase)).to.be.true;
    });

    function testHelper(encOpt, decOpt, dontUnlock) {
      if (!dontUnlock) {
        expect(privateKey.keys[0].decrypt(passphrase)).to.be.true;
      }
      return openpgp.encrypt(encOpt).then(function(encrypted) {
        expect(encrypted.data).to.exist;
        var msg = openpgp.message.readArmored(encrypted.data);
        expect(msg).to.exist;

        decOpt.message = msg;
        return openpgp.decrypt(decOpt);
      });
    }

    it('Calling decrypt with not decrypted key leads to exception', function (done) {
      var encOpt = {
        data: plaintext,
        publicKeys: publicKey.keys,
      };
      var decOpt = {
        privateKey: privateKey.keys[0]
      };
      testHelper(encOpt, decOpt, true).catch(function(error) {
        expect(error.message).to.match(/not decrypted/);
        done();
      });
    });

    it('should encrypt then decrypt with pgp key pair', function(done) {
      var encOpt = {
        data: plaintext,
        publicKeys: publicKey.keys,
      };
      var decOpt = {
        privateKey: privateKey.keys[0]
      };
      testHelper(encOpt, decOpt).then(function(decrypted) {
        expect(decrypted.data).to.equal(plaintext);
        expect(decrypted.signatures).to.not.exist;
        done();
      });
    });

    it('should encrypt/sign and decrypt/verify with pgp key pair', function(done) {
      var encOpt = {
        data: plaintext,
        publicKeys: publicKey.keys,
        privateKeys: privateKey.keys
      };
      var decOpt = {
        privateKey: privateKey.keys[0],
        publicKeys: publicKey.keys
      };
      testHelper(encOpt, decOpt).then(function(decrypted) {
        expect(decrypted.data).to.equal(plaintext);
        expect(decrypted.signatures[0].valid).to.be.true;
        done();
      });
    });

    it('should fail to verify with wrong public pgp key', function(done) {
      var wrong_pubkey = '-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n' +
        'Version: OpenPGP.js v0.9.0\r\n' +
        'Comment: Hoodiecrow - https://hoodiecrow.com\r\n' +
        '\r\n' +
        'xk0EUlhMvAEB/2MZtCUOAYvyLFjDp3OBMGn3Ev8FwjzyPbIF0JUw+L7y2XR5\r\n' +
        'RVGvbK88unV3cU/1tOYdNsXI6pSp/Ztjyv7vbBUAEQEAAc0pV2hpdGVvdXQg\r\n' +
        'VXNlciA8d2hpdGVvdXQudGVzdEB0LW9ubGluZS5kZT7CXAQQAQgAEAUCUlhM\r\n' +
        'vQkQ9vYOm0LN/0wAAAW4Af9C+kYW1AvNWmivdtr0M0iYCUjM9DNOQH1fcvXq\r\n' +
        'IiN602mWrkd8jcEzLsW5IUNzVPLhrFIuKyBDTpLnC07Loce1\r\n' +
        '=6XMW\r\n' +
        '-----END PGP PUBLIC KEY BLOCK-----\r\n\r\n';

      var encOpt = {
        data: plaintext,
        publicKeys: publicKey.keys,
        privateKeys: privateKey.keys
      };
      var decOpt = {
        privateKey: privateKey.keys[0],
        publicKeys: openpgp.key.readArmored(wrong_pubkey).keys
      };
      testHelper(encOpt, decOpt).then(function(decrypted) {
        expect(decrypted.data).to.equal(plaintext);
        expect(decrypted.signatures[0].valid).to.be.null;
        done();
      });
    });

    it('should encrypt and decrypt with one password', function(done) {
      var encOpt = {
        data: plaintext,
        passwords: password1
      };
      var decOpt = {
        password: password1
      };
      testHelper(encOpt, decOpt).then(function(decrypted) {
        expect(decrypted.data).to.equal(plaintext);
        done();
      });
    });

    it('should encrypt and decrypt with two password2', function(done) {
      var encOpt = {
        data: plaintext,
        passwords: [password1, password2]
      };
      var decOpt = {
        password: password2
      };
      testHelper(encOpt, decOpt).then(function(decrypted) {
        expect(decrypted.data).to.equal(plaintext);
        done();
      });
    });
  });

});
