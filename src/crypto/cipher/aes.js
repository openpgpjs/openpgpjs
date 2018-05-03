/**
 * @requires asmcrypto.js
 */

import { _AES_asm_instance, _AES_heap_instance } from 'asmcrypto.js/src/aes/exports';
import { AES_ECB } from 'asmcrypto.js/src/aes/ecb/ecb';

// TODO use webCrypto or nodeCrypto when possible.
function aes(length) {
  const C = function(key) {
    const aes_ecb = new AES_ECB(key, _AES_heap_instance, _AES_asm_instance);

    this.encrypt = function(block) {
      return aes_ecb.encrypt(block).result;
    };

    this.decrypt = function(block) {
      return aes_ecb.decrypt(block).result;
    };
  };

  C.blockSize = C.prototype.blockSize = 16;
  C.keySize = C.prototype.keySize = length / 8;

  return C;
}

export default aes;
