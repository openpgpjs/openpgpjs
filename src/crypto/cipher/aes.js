/**
 * @requires asmcrypto.js
 */

import { _AES_asm_instance, _AES_heap_instance } from 'asmcrypto.js/src/aes/exports';
import { AES_ECB } from 'asmcrypto.js/src/aes/ecb/ecb';

// TODO use webCrypto or nodeCrypto when possible.
function aes(length) {
  const c = function(key) {
    const aes_ecb = new AES_ECB(key, _AES_heap_instance, _AES_asm_instance);

    this.encrypt = function(block) {
      return aes_ecb.encrypt(block).result;
    };

    this.decrypt = function(block) {
      return aes_ecb.decrypt(block).result;
    };
  };

  c.blockSize = c.prototype.blockSize = 16;
  c.keySize = c.prototype.keySize = length / 8;

  return c;
}

export default aes;
