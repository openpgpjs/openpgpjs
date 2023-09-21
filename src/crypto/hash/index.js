/**
 * @fileoverview Provides an interface to hashing functions available in Node.js or external libraries.
 * @see {@link https://github.com/asmcrypto/asmcrypto.js|asmCrypto}
 * @see {@link https://github.com/indutny/hash.js|hash.js}
 * @module crypto/hash
 */

import { sha1 } from '@openpgp/noble-hashes/sha1';
import { sha224, sha256 } from '@openpgp/noble-hashes/sha256';
import { sha384, sha512 } from '@openpgp/noble-hashes/sha512';
import { sha3_256, sha3_512 } from '@openpgp/noble-hashes/sha3';
import { ripemd160 } from '@openpgp/noble-hashes/ripemd160';
import * as stream from '@openpgp/web-stream-tools';
import md5 from './md5';
import util from '../../util';
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

function nobleHash(hash, webCryptoHash) {
  return async function(data) {
    if (stream.isArrayStream(data)) {
      data = await stream.readToEnd(data);
    }
    if (util.isStream(data)) {
      const hashInstance = hash.create();
      return stream.transform(data, value => {
        hashInstance.update(value);
      }, () => hashInstance.digest());
    } else if (webCrypto && webCryptoHash) {
      return new Uint8Array(await webCrypto.digest(webCryptoHash, data));
    } else {
      return hash(data);
    }
  };
}

const hashFunctions = {
  md5: nodeHash('md5') || md5,
  sha1: nodeHash('sha1') || nobleHash(sha1, 'SHA-1'),
  sha224: nodeHash('sha224') || nobleHash(sha224),
  sha256: nodeHash('sha256') || nobleHash(sha256, 'SHA-256'),
  sha384: nodeHash('sha384') || nobleHash(sha384, 'SHA-384'),
  sha512: nodeHash('sha512') || nobleHash(sha512, 'SHA-512'),
  ripemd: nodeHash('ripemd160') || nobleHash(ripemd160),
  sha3_256: nodeHash('sha3-256') || nobleHash(sha3_256),
  sha3_512: nodeHash('sha3-512') || nobleHash(sha3_512)
};

export default {

  /** @see module:md5 */
  md5: hashFunctions.md5,
  sha1: hashFunctions.sha1,
  sha224: hashFunctions.sha224,
  sha256: hashFunctions.sha256,
  sha384: hashFunctions.sha384,
  sha512: hashFunctions.sha512,
  ripemd: hashFunctions.ripemd,
  sha3_256: hashFunctions.sha3_256,
  sha3_512: hashFunctions.sha3_512,

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
      case enums.hash.sha3_256:
        return this.sha3_256(data);
      case enums.hash.sha3_512:
        return this.sha3_512(data);
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
      case enums.hash.sha3_256:
        return 32;
      case enums.hash.sha3_512:
        return 64;
      default:
        throw new Error('Invalid hash algorithm.');
    }
  }
};
