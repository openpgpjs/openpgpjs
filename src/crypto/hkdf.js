/**
 * @fileoverview This module implements HKDF using either the WebCrypto API or Node.js' crypto API.
 * @module crypto/hkdf
 * @access private
 */

import enums from '../enums';
import util from '../util';

export default async function computeHKDF(hashAlgo, inputKey, salt, info, outLen) {
  const webCrypto = util.getWebCrypto();
  const hash = enums.read(enums.webHash, hashAlgo);
  if (!hash) throw new Error('Hash algo not supported with HKDF');

  const importedKey = await webCrypto.importKey('raw', inputKey, 'HKDF', false, ['deriveBits']);
  const bits = await webCrypto.deriveBits({ name: 'HKDF', hash, salt, info }, importedKey, outLen * 8);
  return new Uint8Array(bits);
}
