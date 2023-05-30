import { AES_ECB } from '@openpgp/asmcrypto.js/aes/ecb.js';

/**
 * Javascript AES implementation.
 * This is used as fallback if the native Crypto APIs are not available.
 */
function aes(length) {
  const C = function(key) {
    const aesECB = new AES_ECB(key);

    this.encrypt = function(block) {
      return aesECB.encrypt(block);
    };

    this.decrypt = function(block) {
      return aesECB.decrypt(block);
    };
  };

  C.blockSize = C.prototype.blockSize = 16;
  C.keySize = C.prototype.keySize = length / 8;

  return C;
}

export default aes;
