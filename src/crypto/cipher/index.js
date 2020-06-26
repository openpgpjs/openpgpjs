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
import { DES, TripleDES } from './des.js';
import Cast5 from './cast5';
import TF from './twofish';
import BF from './blowfish';

/**
 * AES-128 encryption and decryption (ID 7)
 * @function
 * @param {String} key 128-bit key
 * @see {@link https://github.com/asmcrypto/asmcrypto.js|asmCrypto}
 * @see {@link https://csrc.nist.gov/publications/fips/fips197/fips-197.pdf|NIST FIPS-197}
 * @returns {Object}
 * @requires asmcrypto.js
 */
export const aes128 = aes(128);
/**
 * AES-128 Block Cipher (ID 8)
 * @function
 * @param {String} key 192-bit key
 * @see {@link https://github.com/asmcrypto/asmcrypto.js|asmCrypto}
 * @see {@link https://csrc.nist.gov/publications/fips/fips197/fips-197.pdf|NIST FIPS-197}
 * @returns {Object}
 * @requires asmcrypto.js
 */
export const aes192 = aes(192);
/**
 * AES-128 Block Cipher (ID 9)
 * @function
 * @param {String} key 256-bit key
 * @see {@link https://github.com/asmcrypto/asmcrypto.js|asmCrypto}
 * @see {@link https://csrc.nist.gov/publications/fips/fips197/fips-197.pdf|NIST FIPS-197}
 * @returns {Object}
 * @requires asmcrypto.js
 */
export const aes256 = aes(256);
// Not in OpenPGP specifications
export const des = DES;
/**
 * Triple DES Block Cipher (ID 2)
 * @function
 * @param {String} key 192-bit key
 * @see {@link https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-67r2.pdf|NIST SP 800-67}
 * @returns {Object}
 */
export const tripledes = TripleDES;
/**
 * CAST-128 Block Cipher (ID 3)
 * @function
 * @param {String} key 128-bit key
 * @see {@link https://tools.ietf.org/html/rfc2144|The CAST-128 Encryption Algorithm}
 * @returns {Object}
 */
export const cast5 = Cast5;
/**
 * Twofish Block Cipher (ID 10)
 * @function
 * @param {String} key 256-bit key
 * @see {@link https://tools.ietf.org/html/rfc4880#ref-TWOFISH|TWOFISH}
 * @returns {Object}
 */
export const twofish = TF;
/**
 * Blowfish Block Cipher (ID 4)
 * @function
 * @param {String} key 128-bit key
 * @see {@link https://tools.ietf.org/html/rfc4880#ref-BLOWFISH|BLOWFISH}
 * @returns {Object}
 */
export const blowfish = BF;
/**
 * Not implemented
 * @function
 * @throws {Error}
 */
export const idea = function() {
  throw new Error('IDEA symmetric-key algorithm not implemented');
};
