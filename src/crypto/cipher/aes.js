/**
 * @requires asmcrypto.js
 */

import { AES_ECB } from 'asmcrypto.js/dist_es5/aes/ecb';

// TODO use webCrypto or nodeCrypto when possible.
function aes(length) {
  const C = function(key) {
    const aes_ecb = new AES_ECB(key);

    this.encrypt = function(block) {
      return aes_ecb.encrypt(block);
    };

    this.decrypt = function(block) {
      return aes_ecb.decrypt(block);
    };
  };

  C.blockSize = C.prototype.blockSize = 16;
  C.keySize = C.prototype.keySize = length / 8;

  return C;
}

export default aes;
