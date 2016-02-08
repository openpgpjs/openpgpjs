'use strict';

var openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../dist/openpgp');

var sinon = require('sinon'),
  chai = require('chai'),
  expect = chai.expect;

describe('OpenPGP.js public api tests', function() {

  describe('initWorker, getWorker, destroyWorker', function() {
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

});
