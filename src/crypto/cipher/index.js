/**
 * @fileoverview Symmetric cryptography functions
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
  /**
   * AES-128 encryption and decryption (ID 7)
   * @function
   * @param {String} key 128-bit key
   * @see {@link https://github.com/asmcrypto/asmcrypto.js|asmCrypto}
   * @see {@link https://csrc.nist.gov/publications/fips/fips197/fips-197.pdf|NIST FIPS-197}
   * @returns {Object}
   * @requires asmcrypto.js
   */
  aes128: aes(128),
  /**
   * AES-128 Block Cipher (ID 8)
   * @function
   * @param {String} key 192-bit key
   * @see {@link https://github.com/asmcrypto/asmcrypto.js|asmCrypto}
   * @see {@link https://csrc.nist.gov/publications/fips/fips197/fips-197.pdf|NIST FIPS-197}
   * @returns {Object}
   * @requires asmcrypto.js
   */
  aes192: aes(192),
  /**
   * AES-128 Block Cipher (ID 9)
   * @function
   * @param {String} key 256-bit key
   * @see {@link https://github.com/asmcrypto/asmcrypto.js|asmCrypto}
   * @see {@link https://csrc.nist.gov/publications/fips/fips197/fips-197.pdf|NIST FIPS-197}
   * @returns {Object}
   * @requires asmcrypto.js
   */
  aes256: aes(256),
  // Not in OpenPGP specifications
  des: des.DES,
  /**
   * Triple DES Block Cipher (ID 2)
   * @function
   * @param {String} key 192-bit key
   * @see {@link https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-67r2.pdf|NIST SP 800-67}
   * @returns {Object}
   */
  tripledes: des.TripleDES,
  '3des': des.TripleDES,
  /**
   * CAST-128 Block Cipher (ID 3)
   * @function
   * @param {String} key 128-bit key
   * @see {@link https://tools.ietf.org/html/rfc2144|The CAST-128 Encryption Algorithm}
   * @returns {Object}
   */
  cast5: cast5,
  /**
   * Twofish Block Cipher (ID 10)
   * @function
   * @param {String} key 256-bit key
   * @see {@link https://tools.ietf.org/html/rfc4880#ref-TWOFISH|TWOFISH}
   * @returns {Object}
   */
  twofish: twofish,
  /**
   * Blowfish Block Cipher (ID 4)
   * @function
   * @param {String} key 128-bit key
   * @see {@link https://tools.ietf.org/html/rfc4880#ref-BLOWFISH|BLOWFISH}
   * @returns {Object}
   */
  blowfish: blowfish,
  /**
   * Not implemented
   * @function
   * @throws {Error}
   */
  idea: function() {
    throw new Error('IDEA symmetric-key algorithm not implemented');
  }
};
