/**
 * @module crypto/cipher/aes
 */

'use strict';

import asmCrypto from 'asmcrypto-lite';

export default function aes(length) {

  var c = function(key) {
    this.key = Uint8Array.from(key);

    this.encrypt = function(block) {
      block = Uint8Array.from(block);
      return Array.from(asmCrypto.AES_ECB.encrypt(block, this.key, false));
    };

    this.decrypt = function(block) {
      block = Uint8Array.from(block);
      return Array.from(asmCrypto.AES_ECB.decrypt(block, this.key, false));
    };
  };

  c.blockSize = c.prototype.blockSize = 16;
  c.keySize = c.prototype.keySize = length / 8;

  return c;
}
