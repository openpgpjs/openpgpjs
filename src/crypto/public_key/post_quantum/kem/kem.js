import * as eccKem from './ecc_kem';
import * as mlKem from './ml_kem';
import * as aesKW from '../../../aes_kw';
import util from '../../../../util';
import enums from '../../../../enums';

export async function generate(algo) {
  const { eccPublicKey, eccSecretKey } = await eccKem.generate(algo);
  const { mlkemPublicKey, mlkemSeed, mlkemSecretKey } = await mlKem.generate(algo);

  return { eccPublicKey, eccSecretKey, mlkemPublicKey, mlkemSeed, mlkemSecretKey };
}

export async function encrypt(algo, eccPublicKey, mlkemPublicKey, sessioneKeyData) {
  const { eccKeyShare, eccCipherText } = await eccKem.encaps(algo, eccPublicKey);
  const { mlkemKeyShare, mlkemCipherText } = await mlKem.encaps(algo, mlkemPublicKey);
  const kek = await multiKeyCombine(algo, eccKeyShare, eccCipherText, eccPublicKey, mlkemKeyShare, mlkemCipherText, mlkemPublicKey);
  const wrappedKey = await aesKW.wrap(enums.symmetric.aes256, kek, sessioneKeyData); // C
  return { eccCipherText, mlkemCipherText, wrappedKey };
}

export async function decrypt(algo, eccCipherText, mlkemCipherText, eccSecretKey, eccPublicKey, mlkemSecretKey, mlkemPublicKey, encryptedSessionKeyData) {
  const eccKeyShare = await eccKem.decaps(algo, eccCipherText, eccSecretKey, eccPublicKey);
  const mlkemKeyShare = await mlKem.decaps(algo, mlkemCipherText, mlkemSecretKey);
  const kek = await multiKeyCombine(algo, eccKeyShare, eccCipherText, eccPublicKey, mlkemKeyShare, mlkemCipherText, mlkemPublicKey);
  const sessionKey = await aesKW.unwrap(enums.symmetric.aes256, kek, encryptedSessionKeyData);
  return sessionKey;
}

async function multiKeyCombine(algo, ecdhKeyShare, ecdhCipherText, ecdhPublicKey, mlkemKeyShare, mlkemCipherText, mlkemPublicKey) {
  const { kmac256 } = await import('@noble/hashes/sha3-addons');

  const key = util.concatUint8Array([mlkemKeyShare, ecdhKeyShare]);
  const encData = util.concatUint8Array([
    mlkemCipherText,
    ecdhCipherText,
    mlkemPublicKey,
    ecdhPublicKey,
    new Uint8Array([algo])
  ]);
  const domainSeparation = util.encodeUTF8('OpenPGPCompositeKDFv1');

  const kek = kmac256(key, encData, { personalization: domainSeparation }); // output length: 256 bits
  return kek;
}

export async function validateParams(algo, eccPublicKey, eccSecretKey, mlkemPublicKey, mlkemSeed) {
  const eccValidationPromise = eccKem.validateParams(algo, eccPublicKey, eccSecretKey);
  const mlkemValidationPromise = mlKem.validateParams(algo, mlkemPublicKey, mlkemSeed);
  const valid = await eccValidationPromise && await mlkemValidationPromise;
  return valid;
}
