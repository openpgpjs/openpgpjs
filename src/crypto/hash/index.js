/**
 * @fileoverview Provides an interface to hashing functions available in Node.js or external libraries.
 * @see {@link https://github.com/asmcrypto/asmcrypto.js|asmCrypto}
 * @see {@link https://github.com/indutny/hash.js|hash.js}
 * @module crypto/hash
 * @access private
 */

import { transform as streamTransform, isArrayStream, readToEnd as streamReadToEnd } from '@openpgp/web-stream-tools';
import util from '../../util.js';
import enums from '../../enums.ts';

const webCrypto = util.getWebCrypto();
const nodeCrypto = util.getNodeCrypto();
const nodeCryptoHashes = nodeCrypto && nodeCrypto.getHashes();

const getNobleHash = async nobleHashName => {
  const { nobleHashes } = await import('./noble_hashes.js');
  const hash = nobleHashes.get(nobleHashName);
  if (!hash) throw new Error('Unsupported hash');
  return hash;
};

/**
 * Compute the requested hash preferring WebCrypto if supported,
 * otherwise use NodeCrypto or a JS fallback.
 */
function nativeOrNobleHash(nobleHashName, webCryptoHashName, nodeHashName) {
  const supportsNodeCrypto = nodeCrypto && nodeCryptoHashes.includes(nodeHashName);

  return async function(maybeArrayStreamData) {
    const data = isArrayStream(maybeArrayStreamData) ?
      await streamReadToEnd(maybeArrayStreamData) :
      maybeArrayStreamData;

    if (util.isStream(data)) {
      if (supportsNodeCrypto) {
        const nodeHashInstance = nodeCrypto.createHash(nodeHashName);
        return streamTransform(data, value => {
          nodeHashInstance.update(value);
        }, () => new Uint8Array(nodeHashInstance.digest()));
      }

      const hash = await getNobleHash(nobleHashName);
      const hashInstance = hash.create();
      return streamTransform(data, value => {
        hashInstance.update(value);
      }, () => hashInstance.digest());
    } else if (webCryptoHashName) {
      return new Uint8Array(await webCrypto.digest(webCryptoHashName, data));
    } else if (supportsNodeCrypto) {
      return new Uint8Array(nodeCrypto.createHash(nodeHashName).update(data).digest());
    } else {
      const hash = await getNobleHash(nobleHashName);

      return hash(data);
    }
  };
}

const hashFunctions = {
  [enums.hash.md5]: nativeOrNobleHash('md5', null, 'md5'),
  [enums.hash.sha1]: nativeOrNobleHash('sha1', 'SHA-1', 'sha1'),
  [enums.hash.ripemd]: nativeOrNobleHash('ripemd160', null, 'ripemd160'),
  [enums.hash.sha256]: nativeOrNobleHash('sha256', 'SHA-256', 'sha256'),
  [enums.hash.sha384]: nativeOrNobleHash('sha384', 'SHA-384', 'sha384'),
  [enums.hash.sha512]: nativeOrNobleHash('sha512', 'SHA-512', 'sha512'),
  [enums.hash.sha224]: nativeOrNobleHash('sha224', null, 'sha224'),
  [enums.hash.sha3_256]: nativeOrNobleHash('sha3_256', null, 'sha3-256'),
  [enums.hash.sha3_512]: nativeOrNobleHash('sha3_512', null, 'sha3-512')
};

/**
 * Create a hash on the specified data using the specified algorithm
 * @param {module:enums.hash} algo - Hash algorithm type (see {@link https://tools.ietf.org/html/rfc4880#section-9.4|RFC 4880 9.4})
 * @param {Uint8Array} data - Data to be hashed
 * @returns {Promise<Uint8Array>} Hash value.
 */
export function computeDigest(algo, data) {
  const hashFn = hashFunctions[algo];
  if (!hashFn) {
    throw new Error('Unsupported hash function')
  }

  return hashFn(data);
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
