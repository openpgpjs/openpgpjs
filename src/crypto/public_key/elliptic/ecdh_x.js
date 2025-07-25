/**
 * @fileoverview Key encryption and decryption for RFC 6637 ECDH
 * @module crypto/public_key/elliptic/ecdh
 */

import x25519 from '@openpgp/tweetnacl';
import * as aesKW from '../../aes_kw';
import { getRandomBytes } from '../../random';

import enums from '../../../enums';
import util from '../../../util';
import computeHKDF from '../../hkdf';
import { getCipherParams } from '../../cipher';
import { b64ToUint8Array, uint8ArrayToB64 } from '../../../encoding/base64';

const HKDF_INFO = {
  x25519: util.encodeUTF8('OpenPGP X25519'),
  x448: util.encodeUTF8('OpenPGP X448')
};

/**
 * Generate ECDH key for Montgomery curves
 * @param {module:enums.publicKey} algo - Algorithm identifier
 * @returns {Promise<{ A: Uint8Array, k: Uint8Array }>}
 */
export async function generate(algo) {
  switch (algo) {
    case enums.publicKey.x25519:
      try {
        const webCrypto = util.getWebCrypto();
        const webCryptoKey = await webCrypto.generateKey('X25519', true, ['deriveKey', 'deriveBits'])
          .catch(err => {
            if (err.name === 'OperationError') { // Temporary (hopefully) fix for WebKit on Linux
              const newErr = new Error('Unexpected key generation issue');
              newErr.name = 'NotSupportedError';
              throw newErr;
            }
            throw err;
          });

        const privateKey = await webCrypto.exportKey('jwk', webCryptoKey.privateKey);
        const publicKey = await webCrypto.exportKey('jwk', webCryptoKey.publicKey);

        if (privateKey.x !== publicKey.x) { // Weird issue with Webkit on Linux: https://bugs.webkit.org/show_bug.cgi?id=289693
          const err = new Error('Unexpected mismatching public point');
          err.name = 'NotSupportedError';
          throw err;
        }

        return {
          A: new Uint8Array(b64ToUint8Array(publicKey.x)),
          k: b64ToUint8Array(privateKey.d)
        };
      } catch (err) {
        if (err.name !== 'NotSupportedError') {
          throw err;
        }
        // k stays in little-endian, unlike legacy ECDH over curve25519
        const k = getRandomBytes(32);
        const { publicKey: A } = x25519.box.keyPair.fromSecretKey(k);
        return { A, k };
      }

    case enums.publicKey.x448: {
      const x448 = await util.getNobleCurve(enums.publicKey.x448);
      const k = x448.utils.randomPrivateKey();
      const A = x448.getPublicKey(k);
      return { A, k };
    }
    default:
      throw new Error('Unsupported ECDH algorithm');
  }
}

/**
* Validate ECDH parameters
* @param {module:enums.publicKey} algo - Algorithm identifier
* @param {Uint8Array} A - ECDH public point
* @param {Uint8Array} k - ECDH secret scalar
* @returns {Promise<Boolean>} Whether params are valid.
* @async
*/
export async function validateParams(algo, A, k) {
  switch (algo) {
    case enums.publicKey.x25519:
      // Validation is typically not run for ECDH, since encryption subkeys are only validated
      // for gnu-dummy keys.
      // So, for simplicity, we do an encrypt-decrypt round even if WebCrypto support is not available
      try {
        const { ephemeralPublicKey, sharedSecret } = await generateEphemeralEncryptionMaterial(algo, A);
        const recomputedSharedSecret = await recomputeSharedSecret(algo, ephemeralPublicKey, A, k);

        return util.equalsUint8Array(sharedSecret, recomputedSharedSecret);
      } catch (_) {
        return false;
      }

    case enums.publicKey.x448: {
      const x448 = await util.getNobleCurve(enums.publicKey.x448);
      /**
       * Derive public point A' from private key
       * and expect A == A'
       */
      const publicKey = x448.getPublicKey(k);
      return util.equalsUint8Array(A, publicKey);
    }

    default:
      return false;
  }
}

/**
 * Wrap and encrypt a session key
 *
 * @param {module:enums.publicKey} algo - Algorithm identifier
 * @param {Uint8Array} data - session key data to be encrypted
 * @param {Uint8Array} recipientA - Recipient public key (K_B)
 * @returns {Promise<{
 *  ephemeralPublicKey: Uint8Array,
 * wrappedKey: Uint8Array
 * }>} ephemeral public key (K_A) and encrypted key
 * @async
 */
export async function encrypt(algo, data, recipientA) {
  const { ephemeralPublicKey, sharedSecret } = await generateEphemeralEncryptionMaterial(algo, recipientA);
  const hkdfInput = util.concatUint8Array([
    ephemeralPublicKey,
    recipientA,
    sharedSecret
  ]);
  switch (algo) {
    case enums.publicKey.x25519: {
      const cipherAlgo = enums.symmetric.aes128;
      const { keySize } = getCipherParams(cipherAlgo);
      const encryptionKey = await computeHKDF(enums.hash.sha256, hkdfInput, new Uint8Array(), HKDF_INFO.x25519, keySize);
      const wrappedKey = await aesKW.wrap(cipherAlgo, encryptionKey, data);
      return { ephemeralPublicKey, wrappedKey };
    }
    case enums.publicKey.x448: {
      const cipherAlgo = enums.symmetric.aes256;
      const { keySize } = getCipherParams(enums.symmetric.aes256);
      const encryptionKey = await computeHKDF(enums.hash.sha512, hkdfInput, new Uint8Array(), HKDF_INFO.x448, keySize);
      const wrappedKey = await aesKW.wrap(cipherAlgo, encryptionKey, data);
      return { ephemeralPublicKey, wrappedKey };
    }

    default:
      throw new Error('Unsupported ECDH algorithm');
  }
}

/**
 * Decrypt and unwrap the session key
 *
 * @param {module:enums.publicKey} algo - Algorithm identifier
 * @param {Uint8Array} ephemeralPublicKey - (K_A)
 * @param {Uint8Array} wrappedKey,
 * @param {Uint8Array} A - Recipient public key (K_b), needed for KDF
 * @param {Uint8Array} k - Recipient secret key (b)
 * @returns {Promise<Uint8Array>} decrypted session key data
 * @async
 */
export async function decrypt(algo, ephemeralPublicKey, wrappedKey, A, k) {
  const sharedSecret = await recomputeSharedSecret(algo, ephemeralPublicKey, A, k);
  const hkdfInput = util.concatUint8Array([
    ephemeralPublicKey,
    A,
    sharedSecret
  ]);
  switch (algo) {
    case enums.publicKey.x25519: {
      const cipherAlgo = enums.symmetric.aes128;
      const { keySize } = getCipherParams(cipherAlgo);
      const encryptionKey = await computeHKDF(enums.hash.sha256, hkdfInput, new Uint8Array(), HKDF_INFO.x25519, keySize);
      return aesKW.unwrap(cipherAlgo, encryptionKey, wrappedKey);
    }
    case enums.publicKey.x448: {
      const cipherAlgo = enums.symmetric.aes256;
      const { keySize } = getCipherParams(enums.symmetric.aes256);
      const encryptionKey = await computeHKDF(enums.hash.sha512, hkdfInput, new Uint8Array(), HKDF_INFO.x448, keySize);
      return aesKW.unwrap(cipherAlgo, encryptionKey, wrappedKey);
    }
    default:
      throw new Error('Unsupported ECDH algorithm');
  }
}

export function getPayloadSize(algo) {
  switch (algo) {
    case enums.publicKey.x25519:
      return 32;

    case enums.publicKey.x448:
      return 56;

    default:
      throw new Error('Unsupported ECDH algorithm');
  }
}

/**
 * Generate shared secret and ephemeral public key for encryption
 * @returns {Promise<{ ephemeralPublicKey: Uint8Array, sharedSecret: Uint8Array }>} ephemeral public key (K_A) and shared secret
 * @async
 */
export async function generateEphemeralEncryptionMaterial(algo, recipientA) {
  switch (algo) {
    case enums.publicKey.x25519:
      try {
        const webCrypto = util.getWebCrypto();
        const ephemeralKeyPair = await webCrypto.generateKey('X25519', true, ['deriveKey', 'deriveBits'])
          .catch(err => {
            if (err.name === 'OperationError') { // Temporary (hopefully) fix for WebKit on Linux
              const newErr = new Error('Unexpected key generation issue');
              newErr.name = 'NotSupportedError';
              throw newErr;
            }
            throw err;
          });
        const ephemeralPublicKeyJwt = await webCrypto.exportKey('jwk', ephemeralKeyPair.publicKey);
        const ephemeralPrivateKeyJwt = await webCrypto.exportKey('jwk', ephemeralKeyPair.privateKey);
        if (ephemeralPrivateKeyJwt.x !== ephemeralPublicKeyJwt.x) { // Weird issue with Webkit on Linux: https://bugs.webkit.org/show_bug.cgi?id=289693
          const err = new Error('Unexpected mismatching public point');
          err.name = 'NotSupportedError';
          throw err;
        }
        const jwk = publicKeyToJWK(algo, recipientA);
        const recipientPublicKey = await webCrypto.importKey('jwk', jwk, 'X25519', false, []);
        const sharedSecretBuffer = await webCrypto.deriveBits(
          { name: 'X25519', public: recipientPublicKey },
          ephemeralKeyPair.privateKey,
          getPayloadSize(algo) * 8 // in bits
        );
        return {
          sharedSecret: new Uint8Array(sharedSecretBuffer),
          ephemeralPublicKey: new Uint8Array(b64ToUint8Array(ephemeralPublicKeyJwt.x))
        };
      } catch (err) {
        if (err.name !== 'NotSupportedError') {
          throw err;
        }
        const ephemeralSecretKey = getRandomBytes(getPayloadSize(algo));
        const sharedSecret = x25519.scalarMult(ephemeralSecretKey, recipientA);
        assertNonZeroArray(sharedSecret);
        const { publicKey: ephemeralPublicKey } = x25519.box.keyPair.fromSecretKey(ephemeralSecretKey);
        return { ephemeralPublicKey, sharedSecret };
      }
    case enums.publicKey.x448: {
      const x448 = await util.getNobleCurve(enums.publicKey.x448);
      const ephemeralSecretKey = x448.utils.randomPrivateKey();
      const sharedSecret = x448.getSharedSecret(ephemeralSecretKey, recipientA);
      assertNonZeroArray(sharedSecret);
      const ephemeralPublicKey = x448.getPublicKey(ephemeralSecretKey);
      return { ephemeralPublicKey, sharedSecret };
    }
    default:
      throw new Error('Unsupported ECDH algorithm');
  }
}

export async function recomputeSharedSecret(algo, ephemeralPublicKey, A, k) {
  switch (algo) {
    case enums.publicKey.x25519:
      try {
        const webCrypto = util.getWebCrypto();
        const privateKeyJWK = privateKeyToJWK(algo, A, k);
        const ephemeralPublicKeyJWK = publicKeyToJWK(algo, ephemeralPublicKey);
        const privateKey = await webCrypto.importKey('jwk', privateKeyJWK, 'X25519', false, ['deriveKey', 'deriveBits']);
        const ephemeralPublicKeyReference = await webCrypto.importKey('jwk', ephemeralPublicKeyJWK, 'X25519', false, []);
        const sharedSecretBuffer = await webCrypto.deriveBits(
          { name: 'X25519', public: ephemeralPublicKeyReference },
          privateKey,
          getPayloadSize(algo) * 8 // in bits
        );
        return new Uint8Array(sharedSecretBuffer);
      } catch (err) {
        if (err.name !== 'NotSupportedError') {
          throw err;
        }
        const sharedSecret = x25519.scalarMult(k, ephemeralPublicKey);
        assertNonZeroArray(sharedSecret);
        return sharedSecret;
      }
    case enums.publicKey.x448: {
      const x448 = await util.getNobleCurve(enums.publicKey.x448);
      const sharedSecret = x448.getSharedSecret(k, ephemeralPublicKey);
      assertNonZeroArray(sharedSecret);
      return sharedSecret;
    }
    default:
      throw new Error('Unsupported ECDH algorithm');
  }
}

/**
 * x25519 and x448 produce an all-zero value when given as input a point with small order.
 * This does not lead to a security issue in the context of ECDH, but it is still unexpected,
 * hence we throw.
 * @param {Uint8Array} sharedSecret
 */
function assertNonZeroArray(sharedSecret) {
  let acc = 0;
  for (let i = 0; i < sharedSecret.length; i++) {
    acc |= sharedSecret[i];
  }
  if (acc === 0) {
    throw new Error('Unexpected low order point');
  }
}


function publicKeyToJWK(algo, publicKey) {
  switch (algo) {
    case enums.publicKey.x25519: {
      const jwk = {
        kty: 'OKP',
        crv: 'X25519',
        x: uint8ArrayToB64(publicKey, true),
        ext: true
      };
      return jwk;
    }
    default:
      throw new Error('Unsupported ECDH algorithm');
  }
}

function privateKeyToJWK(algo, publicKey, privateKey) {
  switch (algo) {
    case enums.publicKey.x25519: {
      const jwk = publicKeyToJWK(algo, publicKey);
      jwk.d = uint8ArrayToB64(privateKey, true);
      return jwk;
    }
    default:
      throw new Error('Unsupported ECDH algorithm');
  }
}
