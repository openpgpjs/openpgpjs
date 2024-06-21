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
 */

import naclEd25519 from '@openpgp/tweetnacl'; // better constant-timeness as it uses Uint8Arrays over BigInts
import { verify as nobleEd25519Verify } from '@noble/ed25519';

import util from '../../../util';
import enums from '../../../enums';
import hash from '../../hash';
import { getRandomBytes } from '../../random';


/**
 * Generate (non-legacy) EdDSA key
 * @param {module:enums.publicKey} algo - Algorithm identifier
 * @returns {Promise<{ A: Uint8Array, seed: Uint8Array }>}
 */
export async function generate(algo) {
  switch (algo) {
    case enums.publicKey.ed25519: {
      const seed = getRandomBytes(getPayloadSize(algo));
      const { publicKey: A } = naclEd25519.sign.keyPair.fromSeed(seed);
      return { A, seed };
    }
    case enums.publicKey.ed448: {
      const ed448 = await util.getNobleCurve(enums.publicKey.ed448);
      const seed = ed448.utils.randomPrivateKey();
      const A = ed448.getPublicKey(seed);
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
  if (hash.getHashByteLength(hashAlgo) < hash.getHashByteLength(getPreferredHashAlgo(algo))) {
    throw new Error('Hash algorithm too weak for EdDSA.');
  }
  switch (algo) {
    case enums.publicKey.ed25519: {
      const secretKey = util.concatUint8Array([privateKey, publicKey]);
      const signature = naclEd25519.sign.detached(hashed, secretKey);
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
  if (hash.getHashByteLength(hashAlgo) < hash.getHashByteLength(getPreferredHashAlgo(algo))) {
    throw new Error('Hash algorithm too weak for EdDSA.');
  }
  switch (algo) {
    case enums.publicKey.ed25519:
      return nobleEd25519Verify(RS, hashed, publicKey);
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
    case enums.publicKey.ed25519: {
      /**
       * Derive public point A' from private key
       * and expect A == A'
       */
      const { publicKey } = naclEd25519.sign.keyPair.fromSeed(seed);
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
