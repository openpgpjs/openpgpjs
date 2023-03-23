/**
 * @fileoverview This module implements HKDF using either the WebCrypto API or Node.js' crypto API.
 * @module crypto/hkdf
 * @private
 */

import enums from '../enums';
import util from '../util';

const webCrypto = util.getWebCrypto();
const nodeCrypto = util.getNodeCrypto();

export default async function HKDF(hashAlgo, key, salt, info, length) {
  const hash = enums.read(enums.webHash, hashAlgo);
  if (!hash) throw new Error('Hash algo not supported with HKDF');

  const crypto = webCrypto || nodeCrypto.webcrypto.subtle;
  const importedKey = await crypto.importKey('raw', key, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.deriveBits({ name: 'HKDF', hash, salt, info }, importedKey, length * 8);
  return new Uint8Array(bits);
}
