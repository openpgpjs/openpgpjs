const sandbox = require('sinon/lib/sinon/sandbox');
const { use: chaiUse, expect } = require('chai');
chaiUse(require('chai-as-promised'));

const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../..');
const crypto = require('../../src/crypto');
const util = require('../../src/util');


module.exports = () => describe('Symmetric AES-GCM (experimental)', function() {
  let sinonSandbox;
  let getWebCryptoStub;
  let getNodeCryptoStub;

  beforeEach(function () {
    sinonSandbox = sandbox.create();
    enableNative();
  });

  afterEach(function () {
    sinonSandbox.restore();
  });

  const disableNative = () => {
    enableNative();
    // stubbed functions return undefined
    getWebCryptoStub = sinonSandbox.stub(util, 'getWebCrypto');
    getNodeCryptoStub = sinonSandbox.stub(util, 'getNodeCrypto');
  };
  const enableNative = () => {
    getWebCryptoStub && getWebCryptoStub.restore();
    getNodeCryptoStub && getNodeCryptoStub.restore();
  };

  function testAESGCM(plaintext, nativeEncrypt, nativeDecrypt) {
    const aesAlgoNames = Object.keys(openpgp.enums.symmetric).filter(
      algoName => algoName.substr(0,3) === 'aes'
    );
    aesAlgoNames.forEach(function(algoName) {
      it(algoName, async function() {
        const nodeCrypto = util.getNodeCrypto();
        const webCrypto = util.getWebCrypto();
        if (!nodeCrypto && !webCrypto) {
          this.skip(); // eslint-disable-line no-invalid-this
        }
        const algo = openpgp.enums.write(openpgp.enums.symmetric, algoName);
        const key = crypto.generateSessionKey(algo);
        const iv = crypto.random.getRandomBytes(crypto.mode.gcm.ivLength);

        const nativeEncryptSpy = nodeCrypto ? sinonSandbox.spy(nodeCrypto, 'createCipheriv') : sinonSandbox.spy(webCrypto, 'encrypt');
        const nativeDecryptSpy = nodeCrypto ? sinonSandbox.spy(nodeCrypto, 'createDecipheriv') : sinonSandbox.spy(webCrypto, 'decrypt');

        nativeEncrypt || disableNative();
        let modeInstance = await crypto.mode.gcm(algo, key);
        const ciphertext = await modeInstance.encrypt(util.stringToUint8Array(plaintext), iv);
        enableNative();

        nativeDecrypt || disableNative();
        modeInstance = await crypto.mode.gcm(algo, key);
        const decrypted = await modeInstance.decrypt(util.stringToUint8Array(util.uint8ArrayToString(ciphertext)), iv);
        enableNative();

        const decryptedStr = util.uint8ArrayToString(decrypted);
        expect(decryptedStr).to.equal(plaintext);

        if (algo !== openpgp.enums.symmetric.aes192) { // not implemented by webcrypto
          // sanity check: native crypto was indeed on/off
          expect(nativeEncryptSpy.called).to.equal(nativeEncrypt);
          expect(nativeDecryptSpy.called).to.equal(nativeDecrypt);
        }
      });
    });
  }

  describe('Symmetric AES-GCM (native)', function() {
    testAESGCM('12345678901234567890123456789012345678901234567890', true, true);
  });

  describe('Symmetric AES-GCM (asm.js fallback)', function() {
    testAESGCM('12345678901234567890123456789012345678901234567890', false, false);
  });

  describe('Symmetric AES-GCM (native encrypt, asm.js decrypt)', function() {
    testAESGCM('12345678901234567890123456789012345678901234567890', true, false);
  });
});
