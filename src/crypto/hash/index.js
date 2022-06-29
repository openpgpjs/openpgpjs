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
import enums from '../../enums';

const webCrypto = util.getWebCrypto();
const nodeCrypto = util.getNodeCrypto();
const nodeCryptoHashes = nodeCrypto && nodeCrypto.getHashes();

function nodeHash(type) {
  if (!nodeCrypto || !nodeCryptoHashes.includes(type)) {
    return;
  }
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

const hashFunctions = {
  md5: nodeHash('md5') || md5,
  sha1: nodeHash('sha1') || asmcryptoHash(Sha1, 'SHA-1'),
  sha224: nodeHash('sha224') || hashjsHash(sha224),
  sha256: nodeHash('sha256') || asmcryptoHash(Sha256, 'SHA-256'),
  sha384: nodeHash('sha384') || hashjsHash(sha384, 'SHA-384'),
  sha512: nodeHash('sha512') || hashjsHash(sha512, 'SHA-512'), // asmcrypto sha512 is huge.
  ripemd: nodeHash('ripemd160') || hashjsHash(ripemd160)
};

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
      case enums.hash.md5:
        return this.md5(data);
      case enums.hash.sha1:
        return this.sha1(data);
      case enums.hash.ripemd:
        return this.ripemd(data);
      case enums.hash.sha256:
        return this.sha256(data);
      case enums.hash.sha384:
        return this.sha384(data);
      case enums.hash.sha512:
        return this.sha512(data);
      case enums.hash.sha224:
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
      case enums.hash.md5:
        return 16;
      case enums.hash.sha1:
      case enums.hash.ripemd:
        return 20;
      case enums.hash.sha256:
        return 32;
      case enums.hash.sha384:
        return 48;
      case enums.hash.sha512:
        return 64;
      case enums.hash.sha224:
        return 28;
      default:
        throw new Error('Invalid hash algorithm.');
    }
  }
};
