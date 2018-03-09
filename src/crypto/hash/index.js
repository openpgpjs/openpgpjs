/**
 * @fileoverview Provides an interface to hashing functions available in Node.js or external libraries.
 * @see {@link https://github.com/srijs/rusha|Rusha}
 * @see {@link https://github.com/asmcrypto/asmcrypto.js|asmCrypto}
 * @see {@link https://github.com/indutny/hash.js|hash.js}
 * @requires rusha
 * @requires asmcrypto.js
 * @requires hash.js
 * @requires crypto/hash/md5
 * @requires util
 * @module crypto/hash
 */

import Rusha from 'rusha';
import { SHA256 } from 'asmcrypto.js/src/hash/sha256/exports';
import sha224 from 'hash.js/lib/hash/sha/224';
import sha384 from 'hash.js/lib/hash/sha/384';
import sha512 from 'hash.js/lib/hash/sha/512';
import { ripemd160 } from 'hash.js/lib/hash/ripemd';
import md5 from './md5';
import util from '../../util';

const rusha = new Rusha();
const nodeCrypto = util.getNodeCrypto();
const Buffer = util.getNodeBuffer();

function node_hash(type) {
  return function (data) {
    const shasum = nodeCrypto.createHash(type);
    shasum.update(new Buffer(data));
    return new Uint8Array(shasum.digest());
  };
}

function hashjs_hash(hash) {
  return function(data) {
    return util.hex_to_Uint8Array(hash().update(data).digest('hex'));
  };
}

let hash_fns;
if (nodeCrypto) { // Use Node native crypto for all hash functions
  hash_fns = {
    md5: node_hash('md5'),
    sha1: node_hash('sha1'),
    sha224: node_hash('sha224'),
    sha256: node_hash('sha256'),
    sha384: node_hash('sha384'),
    sha512: node_hash('sha512'),
    ripemd: node_hash('ripemd160')
  };
} else { // Use JS fallbacks
  hash_fns = {
    md5: md5,
    sha1: function(data) {
      return util.hex_to_Uint8Array(rusha.digest(data));
    },
    sha224: hashjs_hash(sha224),
    sha256: SHA256.bytes,
    sha384: hashjs_hash(sha384),
    // TODO, benchmark this vs asmCrypto's SHA512
    sha512: hashjs_hash(sha512),
    ripemd: hashjs_hash(ripemd160)
  };
}

export default {

  /** @see module:md5 */
  md5: hash_fns.md5,
  /** @see rusha */
  sha1: hash_fns.sha1,
  /** @see hash.js */
  sha224: hash_fns.sha224,
  /** @see asmCrypto */
  sha256: hash_fns.sha256,
  /** @see hash.js */
  sha384: hash_fns.sha384,
  /** @see hash.js */
  sha512: hash_fns.sha512,
  /** @see hash.js */
  ripemd: hash_fns.ripemd,

  /**
   * Create a hash on the specified data using the specified algorithm
   * @param {module:enums.hash} algo Hash algorithm type (see {@link https://tools.ietf.org/html/rfc4880#section-9.4|RFC 4880 9.4})
   * @param {Uint8Array} data Data to be hashed
   * @returns {Uint8Array} hash value
   */
  digest: function(algo, data) {
    switch (algo) {
      case 1:
        // - MD5 [HAC]
        return this.md5(data);
      case 2:
        // - SHA-1 [FIPS180]
        return this.sha1(data);
      case 3:
        // - RIPE-MD/160 [HAC]
        return this.ripemd(data);
      case 8:
        // - SHA256 [FIPS180]
        return this.sha256(data);
      case 9:
        // - SHA384 [FIPS180]
        return this.sha384(data);
      case 10:
        // - SHA512 [FIPS180]
        return this.sha512(data);
      case 11:
        // - SHA224 [FIPS180]
        return this.sha224(data);
      default:
        throw new Error('Invalid hash function.');
    }
  },

  /**
   * Returns the hash size in bytes of the specified hash algorithm type
   * @param {module:enums.hash} algo Hash algorithm type (See {@link https://tools.ietf.org/html/rfc4880#section-9.4|RFC 4880 9.4})
   * @returns {Integer} Size in bytes of the resulting hash
   */
  getHashByteLength: function(algo) {
    switch (algo) {
      case 1:
        // - MD5 [HAC]
        return 16;
      case 2:
        // - SHA-1 [FIPS180]
      case 3:
        // - RIPE-MD/160 [HAC]
        return 20;
      case 8:
        // - SHA256 [FIPS180]
        return 32;
      case 9:
        // - SHA384 [FIPS180]
        return 48;
      case 10:
        // - SHA512 [FIPS180]
        return 64;
      case 11:
        // - SHA224 [FIPS180]
        return 28;
      default:
        throw new Error('Invalid hash algorithm.');
    }
  }
};
