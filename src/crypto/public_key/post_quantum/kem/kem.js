/** @access private */

import * as eccKem from './ecc_kem.js';
import * as mlKem from './ml_kem.js';
import * as aesKW from '../../../aes_kw.js';
import util from '../../../../util.js';
import enums from '../../../../enums.ts';
import { computeDigest } from '../../../hash/index.js';

export async function generate(algo) {
  const { eccPublicKey, eccSecretKey } = await eccKem.generate(algo);
  const { mlkemPublicKey, mlkemSeed, mlkemSecretKey } = await mlKem.generate(algo);

  return { eccPublicKey, eccSecretKey, mlkemPublicKey, mlkemSeed, mlkemSecretKey };
}

export async function encrypt(algo, eccPublicKey, mlkemPublicKey, sessionKeyData) {
  const { eccKeyShare, eccCipherText } = await eccKem.encaps(algo, eccPublicKey);
  const { mlkemKeyShare, mlkemCipherText } = await mlKem.encaps(algo, mlkemPublicKey);
  const kek = await multiKeyCombine(algo, mlkemKeyShare, eccKeyShare, eccCipherText, eccPublicKey);
  const wrappedKey = await aesKW.wrap(enums.symmetric.aes256, kek, sessionKeyData); // C
  return { eccCipherText, mlkemCipherText, wrappedKey };
}

export async function decrypt(algo, eccCipherText, mlkemCipherText, eccSecretKey, eccPublicKey, mlkemSecretKey, mlkemPublicKey, encryptedSessionKeyData) {
  const eccKeyShare = await eccKem.decaps(algo, eccCipherText, eccSecretKey, eccPublicKey);
  const mlkemKeyShare = await mlKem.decaps(algo, mlkemCipherText, mlkemSecretKey);
  const kek = await multiKeyCombine(algo, mlkemKeyShare, eccKeyShare, eccCipherText, eccPublicKey);
  const sessionKey = await aesKW.unwrap(enums.symmetric.aes256, kek, encryptedSessionKeyData);
  return sessionKey;
}

/**
 * KEM key combiner
 * @private
 */
async function multiKeyCombine(algo, mlkemKeyShare, ecdhKeyShare, ecdhCipherText, ecdhPublicKey) {
  const domSep = util.encodeUTF8('OpenPGPCompositeKDFv1');
  const encData = util.concatUint8Array([
    mlkemKeyShare,
    ecdhKeyShare,
    ecdhCipherText,
    ecdhPublicKey,
    new Uint8Array([algo]),
    domSep,
    new Uint8Array([domSep.length])
  ]);

  const kek = await computeDigest(enums.hash.sha3_256, encData);
  return kek;
}

export async function validateParams(algo, eccPublicKey, eccSecretKey, mlkemPublicKey, mlkemSeed) {
  const eccValidationPromise = eccKem.validateParams(algo, eccPublicKey, eccSecretKey);
  const mlkemValidationPromise = mlKem.validateParams(algo, mlkemPublicKey, mlkemSeed);
  const valid = await eccValidationPromise && await mlkemValidationPromise;
  return valid;
}
