import sinon from 'sinon';
import { use as chaiUse, expect } from 'chai';
import chaiAsPromised from 'chai-as-promised'; // eslint-disable-line import-x/newline-after-import
chaiUse(chaiAsPromised);

import openpgp from '../initOpenpgp.js';
import * as crypto from '../../src/crypto/index.js';
import util from '../../src/util.js';

export default () => describe('Symmetric AES-GCM', function() {
  let sinonSandbox;
  let getWebCryptoStub;

  beforeEach(function () {
    sinonSandbox = sinon.createSandbox();
    enableNative();
  });

  afterEach(function () {
    sinonSandbox.restore();
  });

  const disableNative = () => {
    enableNative();
    getWebCryptoStub = sinonSandbox.stub(util, 'getWebCrypto').returns({
      importKey: () => { const e = new Error('getWebCrypto is mocked'); e.name = 'NotSupportedError'; throw e; }
    });
  };
  const enableNative = () => {
    getWebCryptoStub && getWebCryptoStub.restore();
  };

  function testAESGCM(plaintext, nativeEncrypt, nativeDecrypt) {
    const aesAlgoNames = Object.keys(openpgp.enums.symmetric).filter(
      algoName => algoName.substr(0,3) === 'aes'
    );
    aesAlgoNames.forEach(function(algoName) {
      it(algoName, async function() {
        const webCrypto = util.getWebCrypto();
        const algo = openpgp.enums.write(openpgp.enums.symmetric, algoName);
        const key = crypto.generateSessionKey(algo);
        const gcmMode = crypto.cipherMode.getAEADMode(openpgp.enums.aead.gcm);
        const iv = crypto.getRandomBytes(gcmMode.ivLength);

        const nativeEncryptSpy = sinonSandbox.spy(webCrypto, 'encrypt');
        const nativeDecryptSpy = sinonSandbox.spy(webCrypto, 'decrypt');

        nativeEncrypt || disableNative();
        let modeInstance = await gcmMode(algo, key);
        const ciphertext = await modeInstance.encrypt(util.stringToUint8Array(plaintext), iv);
        enableNative();

        nativeDecrypt || disableNative();
        modeInstance = await gcmMode(algo, key);
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
    // empty messages gave issues in eg older Safari versions; ensure support
    testAESGCM('', true, true);
  });

  describe('Symmetric AES-GCM (non-native)', function() {
    testAESGCM('12345678901234567890123456789012345678901234567890', false, false);
  });

  describe('Symmetric AES-GCM (native encrypt, non-native decrypt)', function() {
    testAESGCM('12345678901234567890123456789012345678901234567890', true, false);
  });
});
