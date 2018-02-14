/**
 * @requires crypto/hash/sha
 * @requires crypto/hash/md5
 * @requires util
 * @module crypto/hash
 */

import Rusha from 'rusha';
import asmCrypto from 'asmcrypto-lite';
import sha224 from 'hash.js/lib/hash/sha/224';
import sha384 from 'hash.js/lib/hash/sha/384';
import sha512 from 'hash.js/lib/hash/sha/512';
import { ripemd160 } from 'hash.js/lib/hash/ripemd';
import md5 from './md5';
import util from '../../util.js';

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
    return util.str2Uint8Array(util.hex2bin(hash().update(data).digest('hex')));
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
    /** @see module:./md5 */
    md5: md5,
    /** @see module:rusha */
    sha1: function(data) {
      return util.str2Uint8Array(util.hex2bin(rusha.digest(data)));
    },
    /** @see module:hash.js */
    sha224: hashjs_hash(sha224),
    /** @see module:asmcrypto */
    sha256: asmCrypto.SHA256.bytes,
    /** @see module:hash.js */
    sha384: hashjs_hash(sha384),
    // TODO, benchmark this vs asmCrypto's SHA512
    /** @see module:hash.js */
    sha512: hashjs_hash(sha512),
    /** @see module:hash.js */
    ripemd: hashjs_hash(ripemd160)
  };
}

export default {

  md5: hash_fns.md5,
  sha1: hash_fns.sha1,
  sha224: hash_fns.sha224,
  sha256: hash_fns.sha256,
  sha384: hash_fns.sha384,
  sha512: hash_fns.sha512,
  ripemd: hash_fns.ripemd,

  /**
   * Create a hash on the specified data using the specified algorithm
   * @param {module:enums.hash} algo Hash algorithm type (see {@link https://tools.ietf.org/html/rfc4880#section-9.4|RFC 4880 9.4})
   * @param {Uint8Array} data Data to be hashed
   * @return {Uint8Array} hash value
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
   * @return {Integer} Size in bytes of the resulting hash
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
