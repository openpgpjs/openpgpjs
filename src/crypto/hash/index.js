/**
 * @fileoverview Provides an interface to hashing functions available in Node.js or external libraries.
 * @see {@link https://github.com/asmcrypto/asmcrypto.js|asmCrypto}
 * @see {@link https://github.com/indutny/hash.js|hash.js}
 * @module crypto/hash
 * @private
 */

import { Sha1 } from '@openpgp/asmcrypto.js/dist_es8/hash/sha1/sha1';
import { Sha256 } from '@openpgp/asmcrypto.js/dist_es8/hash/sha256/sha256';
import sha224 from 'hash.js/lib/hash/sha/224';
import sha384 from 'hash.js/lib/hash/sha/384';
import sha512 from 'hash.js/lib/hash/sha/512';
import { ripemd160 } from 'hash.js/lib/hash/ripemd';
import * as stream from '@openpgp/web-stream-tools';
import md5 from './md5';
import util from '../../util';
import defaultConfig from '../../config';

const webCrypto = util.getWebCrypto();
const nodeCrypto = util.getNodeCrypto();

function nodeHash(type) {
  return async function (data) {
    const shasum = nodeCrypto.createHash(type);
    return stream.transform(data, value => {
      shasum.update(value);
    }, () => new Uint8Array(shasum.digest()));
  };
}

function hashjsHash(hash, webCryptoHash) {
  return async function(data, config = defaultConfig) {
    if (stream.isArrayStream(data)) {
      data = await stream.readToEnd(data);
    }
    if (!util.isStream(data) && webCrypto && webCryptoHash && data.length >= config.minBytesForWebCrypto) {
      return new Uint8Array(await webCrypto.digest(webCryptoHash, data));
    }
    const hashInstance = hash();
    return stream.transform(data, value => {
      hashInstance.update(value);
    }, () => new Uint8Array(hashInstance.digest()));
  };
}

function asmcryptoHash(hash, webCryptoHash) {
  return async function(data, config = defaultConfig) {
    if (stream.isArrayStream(data)) {
      data = await stream.readToEnd(data);
    }
    if (util.isStream(data)) {
      const hashInstance = new hash();
      return stream.transform(data, value => {
        hashInstance.process(value);
      }, () => hashInstance.finish().result);
    } else if (webCrypto && webCryptoHash && data.length >= config.minBytesForWebCrypto) {
      return new Uint8Array(await webCrypto.digest(webCryptoHash, data));
    } else {
      return hash.bytes(data);
    }
  };
}

let hashFunctions;
if (nodeCrypto) { // Use Node native crypto for all hash functions
  hashFunctions = {
    md5: nodeHash('md5'),
    sha1: nodeHash('sha1'),
    sha224: nodeHash('sha224'),
    sha256: nodeHash('sha256'),
    sha384: nodeHash('sha384'),
    sha512: nodeHash('sha512'),
    ripemd: nodeHash('ripemd160')
  };
} else { // Use JS fallbacks
  hashFunctions = {
    md5: md5,
    sha1: asmcryptoHash(Sha1, navigator.userAgent.indexOf('Edge') === -1 && 'SHA-1'),
    sha224: hashjsHash(sha224),
    sha256: asmcryptoHash(Sha256, 'SHA-256'),
    sha384: hashjsHash(sha384, 'SHA-384'),
    sha512: hashjsHash(sha512, 'SHA-512'), // asmcrypto sha512 is huge.
    ripemd: hashjsHash(ripemd160)
  };
}

export default {

  /** @see module:md5 */
  md5: hashFunctions.md5,
  /** @see asmCrypto */
  sha1: hashFunctions.sha1,
  /** @see hash.js */
  sha224: hashFunctions.sha224,
  /** @see asmCrypto */
  sha256: hashFunctions.sha256,
  /** @see hash.js */
  sha384: hashFunctions.sha384,
  /** @see asmCrypto */
  sha512: hashFunctions.sha512,
  /** @see hash.js */
  ripemd: hashFunctions.ripemd,

  /**
   * Create a hash on the specified data using the specified algorithm
   * @param {module:enums.hash} algo - Hash algorithm type (see {@link https://tools.ietf.org/html/rfc4880#section-9.4|RFC 4880 9.4})
   * @param {Uint8Array} data - Data to be hashed
   * @returns {Promise<Uint8Array>} Hash value.
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
   * @param {module:enums.hash} algo - Hash algorithm type (See {@link https://tools.ietf.org/html/rfc4880#section-9.4|RFC 4880 9.4})
   * @returns {Integer} Size in bytes of the resulting hash.
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
