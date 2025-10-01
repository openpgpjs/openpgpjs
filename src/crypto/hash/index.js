/**
 * @fileoverview Provides an interface to hashing functions available in Node.js or external libraries.
 * @see {@link https://github.com/asmcrypto/asmcrypto.js|asmCrypto}
 * @see {@link https://github.com/indutny/hash.js|hash.js}
 * @module crypto/hash
 * @access private
 */

import { transform as streamTransform, isArrayStream, readToEnd as streamReadToEnd } from '@openpgp/web-stream-tools';
import util from '../../util';
import enums from '../../enums';

const webCrypto = util.getWebCrypto();
const nodeCrypto = util.getNodeCrypto();
const nodeCryptoHashes = nodeCrypto && nodeCrypto.getHashes();

function nodeHash(type) {
  if (!nodeCrypto || !nodeCryptoHashes.includes(type)) {
    return;
  }
  // eslint-disable-next-line @typescript-eslint/require-await
  return async function (data) {
    const shasum = nodeCrypto.createHash(type);
    return streamTransform(data, value => {
      shasum.update(value);
    }, () => new Uint8Array(shasum.digest()));
  };
}

function nobleHash(nobleHashName, webCryptoHashName) {
  const getNobleHash = async () => {
    const { nobleHashes } = await import('./noble_hashes');
    const hash = nobleHashes.get(nobleHashName);
    if (!hash) throw new Error('Unsupported hash');
    return hash;
  };

  return async function(data) {
    if (isArrayStream(data)) {
      data = await streamReadToEnd(data);
    }
    if (util.isStream(data)) {
      const hash = await getNobleHash();

      const hashInstance = hash.create();
      return streamTransform(data, value => {
        hashInstance.update(value);
      }, () => hashInstance.digest());
    } else if (webCrypto && webCryptoHashName) {
      return new Uint8Array(await webCrypto.digest(webCryptoHashName, data));
    } else {
      const hash = await getNobleHash();

      return hash(data);
    }
  };
}

const md5 = nodeHash('md5') || nobleHash('md5');
const sha1 = nodeHash('sha1') || nobleHash('sha1', 'SHA-1');
const sha224 = nodeHash('sha224') || nobleHash('sha224');
const sha256 = nodeHash('sha256') || nobleHash('sha256', 'SHA-256');
const sha384 = nodeHash('sha384') || nobleHash('sha384', 'SHA-384');
const sha512 = nodeHash('sha512') || nobleHash('sha512', 'SHA-512');
const ripemd = nodeHash('ripemd160') || nobleHash('ripemd160');
const sha3_256 = nodeHash('sha3-256') || nobleHash('sha3_256');
const sha3_512 = nodeHash('sha3-512') || nobleHash('sha3_512');

/**
 * Create a hash on the specified data using the specified algorithm
 * @param {module:enums.hash} algo - Hash algorithm type (see {@link https://tools.ietf.org/html/rfc4880#section-9.4|RFC 4880 9.4})
 * @param {Uint8Array} data - Data to be hashed
 * @returns {Promise<Uint8Array>} Hash value.
 */
export function computeDigest(algo, data) {
  switch (algo) {
    case enums.hash.md5:
      return md5(data);
    case enums.hash.sha1:
      return sha1(data);
    case enums.hash.ripemd:
      return ripemd(data);
    case enums.hash.sha256:
      return sha256(data);
    case enums.hash.sha384:
      return sha384(data);
    case enums.hash.sha512:
      return sha512(data);
    case enums.hash.sha224:
      return sha224(data);
    case enums.hash.sha3_256:
      return sha3_256(data);
    case enums.hash.sha3_512:
      return sha3_512(data);
    default:
      throw new Error('Unsupported hash function');
  }
}

/**
 * Returns the hash size in bytes of the specified hash algorithm type
 * @param {module:enums.hash} algo - Hash algorithm type (See {@link https://tools.ietf.org/html/rfc4880#section-9.4|RFC 4880 9.4})
 * @returns {Integer} Size in bytes of the resulting hash.
 */
export function getHashByteLength(algo) {
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
