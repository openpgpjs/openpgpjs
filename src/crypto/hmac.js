/**
 * @fileoverview This module implements an abstracted interface over
 * HMAC implementation from asmcrypto.js
 * @module crypto/hmac
 * @private
 */

import { Hmac } from '@openpgp/asmcrypto.js/dist_es8/hmac/hmac';
import { Sha1 } from '@openpgp/asmcrypto.js/dist_es8/hash/sha1/sha1';
import { Sha256 } from '@openpgp/asmcrypto.js/dist_es8/hash/sha256/sha256';
import { Sha512 } from '@openpgp/asmcrypto.js/dist_es8/hash/sha512/sha512';
import enums from '../enums';

/**
 * Creats an HMAC object for data authentication
 * @param {module:enums.hash} algo - The hash algorithm to be used in the hmac
 * @param Uint8Array key - The key for the hmac computation
 */
export function createHmac(algo, key) {
  switch (algo) {
    case enums.hash.sha1:
    case enums.hash.sha256:
    case enums.hash.sha512:
      return createSupportedHmac(algo, key);
    default:
      throw new Error("Unsupported hash algorithm.");
  }
}

function createSupportedHmac(algo, key) {
  const hash = getHash(algo);
  const hmac = new Hmac(hash, key);
  return new HMAC(hmac);
}

function getHash(algo) {
  switch (algo) {
    case enums.hash.sha1:
      return new Sha1();
    case enums.hash.sha256:
      return new Sha256();
    case enums.hash.sha512:
      return new Sha512();
  }
}

function HMAC(hmac) {
  this.hmac = hmac;
  this.update = function(data) {
    this.hmac.process(data);
  };
  this.finalize = function() {
    return this.hmac.finish().result;
  };
}
