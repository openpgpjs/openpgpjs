/**
 * @fileoverview Provides an interface to hashing functions available in Node.js or external libraries.
 * @see {@link https://github.com/asmcrypto/asmcrypto.js|asmCrypto}
 * @see {@link https://github.com/indutny/hash.js|hash.js}
 * @requires asmcrypto.js
 * @requires hash.js
 * @requires web-stream-tools
 * @requires crypto/hash/md5
 * @requires config
 * @requires util
 * @module crypto/hash
 */

import { Sha1 } from 'asmcrypto.js/dist_es5/hash/sha1/sha1';
import { Sha256 } from 'asmcrypto.js/dist_es5/hash/sha256/sha256';
import sha224 from 'hash.js/lib/hash/sha/224';
import sha384 from 'hash.js/lib/hash/sha/384';
import sha512 from 'hash.js/lib/hash/sha/512';
import { ripemd160 } from 'hash.js/lib/hash/ripemd';
import stream from 'web-stream-tools';
import md5 from './md5';
import config from '../../config';
import util from '../../util';

const webCrypto = util.getWebCrypto();
const nodeCrypto = util.getNodeCrypto();
const Buffer = util.getNodeBuffer();

function node_hash(type) {
  return async function (data) {
    const shasum = nodeCrypto.createHash(type);
    return stream.transform(data, value => {
      shasum.update(Buffer.from(value));
    }, () => new Uint8Array(shasum.digest()));
  };
}

function hashjs_hash(hash, webCryptoHash) {
  return async function(data) {
    if (!util.isStream(data) && webCrypto && webCryptoHash && data.length >= config.min_bytes_for_web_crypto) {
      return new Uint8Array(await webCrypto.digest(webCryptoHash, data));
    }
    const hashInstance = hash();
    return stream.transform(data, value => {
      hashInstance.update(value);
    }, () => new Uint8Array(hashInstance.digest()));
  };
}

function asmcrypto_hash(hash, webCryptoHash) {
  return async function(data) {
    if (util.isStream(data)) {
      const hashInstance = new hash();
      return stream.transform(data, value => {
        hashInstance.process(value);
      }, () => hashInstance.finish().result);
    } else if (webCrypto && webCryptoHash && data.length >= config.min_bytes_for_web_crypto) {
      return new Uint8Array(await webCrypto.digest(webCryptoHash, data));
    } else {
      return hash.bytes(data);
    }
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
    sha1: asmcrypto_hash(Sha1, navigator.userAgent.indexOf('Edge') === -1 && 'SHA-1'),
    sha224: hashjs_hash(sha224),
    sha256: asmcrypto_hash(Sha256, 'SHA-256'),
    sha384: hashjs_hash(sha384, 'SHA-384'),
    sha512: hashjs_hash(sha512, 'SHA-512'), // asmcrypto sha512 is huge.
    ripemd: hashjs_hash(ripemd160)
  };
}

export default {

  /** @see module:md5 */
  md5: hash_fns.md5,
  /** @see asmCrypto */
  sha1: hash_fns.sha1,
  /** @see hash.js */
  sha224: hash_fns.sha224,
  /** @see asmCrypto */
  sha256: hash_fns.sha256,
  /** @see hash.js */
  sha384: hash_fns.sha384,
  /** @see asmCrypto */
  sha512: hash_fns.sha512,
  /** @see hash.js */
  ripemd: hash_fns.ripemd,

  /**
   * Create a hash on the specified data using the specified algorithm
   * @param {module:enums.hash} algo Hash algorithm type (see {@link https://tools.ietf.org/html/rfc4880#section-9.4|RFC 4880 9.4})
   * @param {Uint8Array} data Data to be hashed
   * @returns {Promise<Uint8Array>} hash value
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
      case 1: // - MD5 [HAC]
        return 16;
      case 2: // - SHA-1 [FIPS180]
      case 3: // - RIPE-MD/160 [HAC]
        return 20;
      case 8: // - SHA256 [FIPS180]
        return 32;
      case 9: // - SHA384 [FIPS180]
        return 48;
      case 10: // - SHA512 [FIPS180]
        return 64;
      case 11: // - SHA224 [FIPS180]
        return 28;
      default:
        throw new Error('Invalid hash algorithm.');
    }
  }
};
