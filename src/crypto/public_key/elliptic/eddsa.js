// OpenPGP.js - An OpenPGP implementation in javascript
// Copyright (C) 2018 Proton Technologies AG
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * @fileoverview Implementation of EdDSA following RFC4880bis-03 for OpenPGP
 * @module crypto/public_key/elliptic/eddsa
 * @access private
 */

import util from '../../../util';
import enums from '../../../enums';
import { getHashByteLength } from '../../hash';
import { getRandomBytes } from '../../random';
import { b64ToUint8Array, uint8ArrayToB64 } from '../../../encoding/base64';


/**
 * Generate (non-legacy) EdDSA key
 * @param {module:enums.publicKey} algo - Algorithm identifier
 * @returns {Promise<{ A: Uint8Array, seed: Uint8Array }>}
 */
export async function generate(algo) {
  switch (algo) {
    case enums.publicKey.ed25519:
      try {
        const webCrypto = util.getWebCrypto();
        const webCryptoKey = await webCrypto.generateKey('Ed25519', true, ['sign', 'verify'])
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

        return {
          A: new Uint8Array(b64ToUint8Array(publicKey.x)),
          seed: b64ToUint8Array(privateKey.d, true)
        };
      } catch (err) {
        if (err.name !== 'NotSupportedError') {
          throw err;
        }
        const { default: ed25519 } = await import('@openpgp/tweetnacl');
        const seed = getRandomBytes(getPayloadSize(algo));
        // not using `ed25519.sign.keyPair` since it returns the expanded secret, so using `fromSeed` instead is more straightforward
        const { publicKey: A } = ed25519.sign.keyPair.fromSeed(seed);
        return { A, seed };
      }

    case enums.publicKey.ed448: {
      const ed448 = await util.getNobleCurve(enums.publicKey.ed448);
      const { secretKey: seed, publicKey: A } = ed448.keygen();
      return { A, seed };
    }
    default:
      throw new Error('Unsupported EdDSA algorithm');
  }
}

/**
 * Sign a message using the provided key
 * @param {module:enums.publicKey} algo - Algorithm identifier
 * @param {module:enums.hash} hashAlgo - Hash algorithm used to sign (must be sha256 or stronger)
 * @param {Uint8Array} message - Message to sign
 * @param {Uint8Array} publicKey - Public key
 * @param {Uint8Array} privateKey - Private key used to sign the message
 * @param {Uint8Array} hashed - The hashed message
 * @returns {Promise<{
 *   RS: Uint8Array
 * }>} Signature of the message
 * @async
 */
export async function sign(algo, hashAlgo, message, publicKey, privateKey, hashed) {
  if (getHashByteLength(hashAlgo) < getHashByteLength(getPreferredHashAlgo(algo))) {
    // Enforce digest sizes:
    // - Ed25519: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.4-4
    // - Ed448: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.5-4
    throw new Error('Hash algorithm too weak for EdDSA.');
  }
  switch (algo) {
    case enums.publicKey.ed25519:
      try {
        const webCrypto = util.getWebCrypto();
        const jwk = privateKeyToJWK(algo, publicKey, privateKey);
        const key = await webCrypto.importKey('jwk', jwk, 'Ed25519', false, ['sign']);

        const signature = new Uint8Array(
          await webCrypto.sign('Ed25519', key, hashed)
        );

        return { RS: signature };
      } catch (err) {
        if (err.name !== 'NotSupportedError') {
          throw err;
        }
        const { default: ed25519 } = await import('@openpgp/tweetnacl');
        const secretKey = util.concatUint8Array([privateKey, publicKey]);
        const signature = ed25519.sign.detached(hashed, secretKey);
        return { RS: signature };
      }

    case enums.publicKey.ed448: {
      const ed448 = await util.getNobleCurve(enums.publicKey.ed448);
      const signature = ed448.sign(hashed, privateKey);
      return { RS: signature };
    }
    default:
      throw new Error('Unsupported EdDSA algorithm');
  }

}

/**
 * Verifies if a signature is valid for a message
 * @param {module:enums.publicKey} algo - Algorithm identifier
 * @param {module:enums.hash} hashAlgo - Hash algorithm used in the signature
 * @param  {{ RS: Uint8Array }} signature Signature to verify the message
 * @param {Uint8Array} m - Message to verify
 * @param {Uint8Array} publicKey - Public key used to verify the message
 * @param {Uint8Array} hashed - The hashed message
 * @returns {Boolean}
 * @async
 */
export async function verify(algo, hashAlgo, { RS }, m, publicKey, hashed) {
  if (getHashByteLength(hashAlgo) < getHashByteLength(getPreferredHashAlgo(algo))) {
    // Enforce digest sizes:
    // - Ed25519: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.4-4
    // - Ed448: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.5-4
    throw new Error('Hash algorithm too weak for EdDSA.');
  }
  switch (algo) {
    case enums.publicKey.ed25519:
      try {
        const webCrypto = util.getWebCrypto();
        const jwk = publicKeyToJWK(algo, publicKey);
        const key = await webCrypto.importKey('jwk', jwk, 'Ed25519', false, ['verify']);
        const verified = await webCrypto.verify('Ed25519', key, RS, hashed);
        return verified;
      } catch (err) {
        if (err.name !== 'NotSupportedError') {
          throw err;
        }
        const { default: ed25519 } = await import('@openpgp/tweetnacl');
        return ed25519.sign.detached.verify(hashed, RS, publicKey);
      }

    case enums.publicKey.ed448: {
      const ed448 = await util.getNobleCurve(enums.publicKey.ed448);
      return ed448.verify(RS, hashed, publicKey);
    }
    default:
      throw new Error('Unsupported EdDSA algorithm');
  }
}
/**
 * Validate (non-legacy) EdDSA parameters
 * @param {module:enums.publicKey} algo - Algorithm identifier
 * @param {Uint8Array} A - EdDSA public point
 * @param {Uint8Array} seed - EdDSA secret seed
 * @param {Uint8Array} oid - (legacy only) EdDSA OID
 * @returns {Promise<Boolean>} Whether params are valid.
 * @async
 */
export async function validateParams(algo, A, seed) {
  switch (algo) {
    case enums.publicKey.ed25519:
      // If webcrypto support is available, we sign-verify random data, as the import-export
      // functions might not implement validity checks.
      // If we need to fallback to JS, we instead only re-derive the public key,
      // as this is much faster than sign-verify.
      try {
        const webCrypto = util.getWebCrypto();
        const jwkPrivate = privateKeyToJWK(algo, A, seed);
        const jwkPublic = publicKeyToJWK(algo, A);

        const privateCryptoKey = await webCrypto.importKey('jwk', jwkPrivate, 'Ed25519', false, ['sign']);
        const publicCryptoKey = await webCrypto.importKey('jwk', jwkPublic, 'Ed25519', false, ['verify']);

        const randomData = getRandomBytes(8);
        const signature = new Uint8Array(
          await webCrypto.sign('Ed25519', privateCryptoKey, randomData)
        );

        const verified = await webCrypto.verify('Ed25519', publicCryptoKey, signature, randomData);
        return verified;
      } catch (err) {
        if (err.name !== 'NotSupportedError') {
          return false;
        }
        const { default: ed25519 } = await import('@openpgp/tweetnacl');
        const { publicKey } = ed25519.sign.keyPair.fromSeed(seed);
        return util.equalsUint8Array(A, publicKey);
      }

    case enums.publicKey.ed448: {
      const ed448 = await util.getNobleCurve(enums.publicKey.ed448);

      const publicKey = ed448.getPublicKey(seed);
      return util.equalsUint8Array(A, publicKey);
    }
    default:
      return false;
  }
}

export function getPayloadSize(algo) {
  switch (algo) {
    case enums.publicKey.ed25519:
      return 32;

    case enums.publicKey.ed448:
      return 57;

    default:
      throw new Error('Unsupported EdDSA algorithm');
  }
}

export function getPreferredHashAlgo(algo) {
  switch (algo) {
    case enums.publicKey.ed25519:
      return enums.hash.sha256;
    case enums.publicKey.ed448:
      return enums.hash.sha512;
    default:
      throw new Error('Unknown EdDSA algo');
  }
}

const publicKeyToJWK = (algo, publicKey) => {
  switch (algo) {
    case enums.publicKey.ed25519: {
      const jwk = {
        kty: 'OKP',
        crv: 'Ed25519',
        x: uint8ArrayToB64(publicKey, true),
        ext: true
      };
      return jwk;
    }
    default:
      throw new Error('Unsupported EdDSA algorithm');
  }
};

const privateKeyToJWK = (algo, publicKey, privateKey) => {
  switch (algo) {
    case enums.publicKey.ed25519: {
      const jwk = publicKeyToJWK(algo, publicKey);
      jwk.d = uint8ArrayToB64(privateKey, true);
      return jwk;
    }
    default:
      throw new Error('Unsupported EdDSA algorithm');
  }
};
