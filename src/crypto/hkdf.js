/**
 * @fileoverview This module implements HKDF using either the WebCrypto API or Node.js' crypto API.
 * @module crypto/hkdf
 * @private
 */

import enums from '../enums';
import util from '../util';

const webCrypto = util.getWebCrypto();
const nodeCrypto = util.getNodeCrypto();
const nodeSubtleCrypto = nodeCrypto && nodeCrypto.webcrypto && nodeCrypto.webcrypto.subtle;

export default async function HKDF(hashAlgo, inputKey, salt, info, outLen) {
  const hash = enums.read(enums.webHash, hashAlgo);
  if (!hash) throw new Error('Hash algo not supported with HKDF');

  if (webCrypto || nodeSubtleCrypto) {
    const crypto = webCrypto || nodeSubtleCrypto;
    const importedKey = await crypto.importKey('raw', inputKey, 'HKDF', false, ['deriveBits']);
    const bits = await crypto.deriveBits({ name: 'HKDF', hash, salt, info }, importedKey, outLen * 8);
    return new Uint8Array(bits);
  }

  if (nodeCrypto) {
    const hashAlgoName = enums.read(enums.hash, hashAlgo);
    // Node-only HKDF implementation based on https://www.rfc-editor.org/rfc/rfc5869

    const computeHMAC = (hmacKey, hmacMessage) => nodeCrypto.createHmac(hashAlgoName, hmacKey).update(hmacMessage).digest();
    // Step 1: Extract
    // PRK = HMAC-Hash(salt, IKM)
    const pseudoRandomKey = computeHMAC(salt, inputKey);

    const hashLen = pseudoRandomKey.length;

    // Step 2: Expand
    // HKDF-Expand(PRK, info, L) -> OKM
    const n = Math.ceil(outLen / hashLen);
    const outputKeyingMaterial = new Uint8Array(n * hashLen);

    // HMAC input buffer updated at each iteration
    const roundInput = new Uint8Array(hashLen + info.length + 1);
    // T_i and last byte are updated at each iteration, but `info` remains constant
    roundInput.set(info, hashLen);

    for (let i = 0; i < n; i++) {
      // T(0) = empty string (zero length)
      // T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
      roundInput[roundInput.length - 1] = i + 1;
      // t = T(i+1)
      const t = computeHMAC(pseudoRandomKey, i > 0 ? roundInput : roundInput.subarray(hashLen));
      roundInput.set(t, 0);

      outputKeyingMaterial.set(t, i * hashLen);
    }

    return outputKeyingMaterial.subarray(0, outLen);
  }

  throw new Error('No HKDF implementation available');
}
