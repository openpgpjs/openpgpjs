const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../..');
const crypto = require('../../src/crypto');
const util = require('../../src/util');
const stub = require('sinon/lib/sinon/stub');
const spy = require('sinon/lib/sinon/spy');

const chai = require('chai');
chai.use(require('chai-as-promised'));

const expect = chai.expect;

module.exports = () => describe('Symmetric AES-GCM (experimental)', function() {
  let getWebCryptoStub;
  let getNodeCryptoStub;
  let nativeEncryptSpy;
  let nativeDecryptSpy;

  const disableNative = () => {
    enableNative();
    getWebCryptoStub = stub(util, "getWebCrypto");
    getNodeCryptoStub = stub(util, "getNodeCrypto");
    getWebCryptoStub.returns(null);
    getNodeCryptoStub.returns(null);
  };
  const enableNative = () => {
    getWebCryptoStub && getWebCryptoStub.restore();
    getNodeCryptoStub && getNodeCryptoStub.restore();
  };

  beforeEach(function () {
    const nodeCrypto = util.getNodeCrypto();
    const webCrypto = util.getWebCrypto();
    nativeEncryptSpy = webCrypto ? spy(webCrypto, 'encrypt') : spy(nodeCrypto, 'createCipheriv');
    nativeDecryptSpy = webCrypto ? spy(webCrypto, 'decrypt') : spy(nodeCrypto, 'createDecipheriv');
    enableNative();
  });

  afterEach(function () {
    nativeEncryptSpy.restore();
    nativeDecryptSpy.restore();
    enableNative();
  });

  function testAESGCM(plaintext, nativeEncrypt, nativeDecrypt) {
    const aesAlgos = Object.keys(openpgp.enums.symmetric).filter(
      algo => algo.substr(0,3) === 'aes'
    );
    aesAlgos.forEach(function(algo) {
      it(algo, async function() {
        const key = await crypto.generateSessionKey(algo);
        const iv = await crypto.random.getRandomBytes(crypto.gcm.ivLength);

        nativeEncrypt || disableNative();
        let modeInstance = await crypto.gcm(algo, key);
        const ciphertext = await modeInstance.encrypt(util.strToUint8Array(plaintext), iv);
        enableNative();

        nativeDecrypt || disableNative();
        modeInstance = await crypto.gcm(algo, key);
        const decrypted = await modeInstance.decrypt(util.strToUint8Array(util.uint8ArrayToStr(ciphertext)), iv);
        enableNative();

        const decryptedStr = util.uint8ArrayToStr(decrypted);
        expect(decryptedStr).to.equal(plaintext);

        if (algo !== 'aes192') { // not implemented by webcrypto
          // sanity check: native crypto was indeed on/off
          expect(nativeEncryptSpy.called).to.equal(nativeEncrypt);
          expect(nativeDecryptSpy.called).to.equal(nativeDecrypt);
        }
      });
    });
  }

  describe('Symmetric AES-GCM (native)', function() {
    testAESGCM("12345678901234567890123456789012345678901234567890", true, true);
  });

  describe('Symmetric AES-GCM (asm.js fallback)', function() {
    testAESGCM("12345678901234567890123456789012345678901234567890", false, false);
  });

  describe('Symmetric AES-GCM (native encrypt, asm.js decrypt)', function() {
    testAESGCM("12345678901234567890123456789012345678901234567890", true, false);
  });
});
