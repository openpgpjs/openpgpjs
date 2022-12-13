/**
 * @fileoverview This module implements HKDF-SHA256 using either the WebCrypto API or Node.js' crypto API.
 * @module crypto/hmac
 * @private
 */

import util from '../util';

const webCrypto = util.getWebCrypto();
const nodeCrypto = util.getNodeCrypto();

export default async function HKDF(key, salt, info, length) {
  const crypto = webCrypto || nodeCrypto.webcrypto.subtle;
  const importedKey = await crypto.importKey('raw', key, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, importedKey, length * 8);
  return new Uint8Array(bits);
}
