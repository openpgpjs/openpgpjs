/**
 * @requires crypto/cipher/aes
 * @requires crypto/cipher/des
 * @requires crypto/cipher/cast5
 * @requires crypto/cipher/twofish
 * @requires crypto/cipher/blowfish
 * @module crypto/cipher
 */

import aes from './aes';
import des from './des.js';
import cast5 from './cast5';
import twofish from './twofish';
import blowfish from './blowfish';

export default {
  /** @see module:crypto/cipher/aes */
  aes128: aes(128),
  aes192: aes(192),
  aes256: aes(256),
  /** @see module:crypto/cipher/des~DES */
  des: des.DES,
  /** @see module:crypto/cipher/des~TripleDES */
  tripledes: des.TripleDES,
  /** @see module:crypto/cipher/cast5 */
  cast5: cast5,
  /** @see module:crypto/cipher/twofish */
  twofish: twofish,
  /** @see module:crypto/cipher/blowfish */
  blowfish: blowfish,
  /** Not implemented */
  idea: function() {
    throw new Error('IDEA symmetric-key algorithm not implemented');
  }
};
