/**
 * @requires asmcrypto.js
 */

import { AES_ECB } from 'asmcrypto.js/src/aes/ecb/exports';

// TODO use webCrypto or nodeCrypto when possible.
function aes(length) {
  const c = function(key) {
    this.key = key;

    this.encrypt = function(block) {
      return AES_ECB.encrypt(block, this.key, false);
    };

    this.decrypt = function(block) {
      return AES_ECB.decrypt(block, this.key, false);
    };
  };

  c.blockSize = c.prototype.blockSize = 16;
  c.keySize = c.prototype.keySize = length / 8;

  return c;
}

export default aes;
