/**
 * @requires crypto/cipher/aes
 * @requires crypto/cipher/blowfish
 * @requires crypto/cipher/cast5
 * @requires crypto/cipher/twofish
 * @module crypto/cipher
 */

'use strict';

import desModule from './des.js';
import aes from'./aes.js';

module.exports = {
  /** @see module:crypto/cipher/aes */
  aes128: aes[128],
  aes192: aes[192],
  aes256: aes[256],
  /** @see module:crypto/cipher/des.originalDes */
  des: desModule.originalDes,
  /** @see module:crypto/cipher/des.des */
  tripledes: desModule.des,
  /** @see module:crypto/cipher/cast5 */
  cast5: require('./cast5.js'),
  /** @see module:crypto/cipher/twofish */
  twofish: require('./twofish.js'),
  /** @see module:crypto/cipher/blowfish */
  blowfish: require('./blowfish.js'),
  /** Not implemented */
  idea: function() {
    throw new Error('IDEA symmetric-key algorithm not implemented');
  }
};