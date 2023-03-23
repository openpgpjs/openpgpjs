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
 * @private
 */

import sha512 from 'hash.js/lib/hash/sha/512';
import nacl from '@openpgp/tweetnacl/nacl-fast-light';
import util from '../../../util';
import enums from '../../../enums';
import hash from '../../hash';
import { getRandomBytes } from '../../random';

nacl.hash = bytes => new Uint8Array(sha512().update(bytes).digest());

/**
 * Generate (non-legacy) EdDSA key
 * @param {module:enums.publicKey} algo - Algorithm identifier
 * @returns Promise<{ A, seed }>
 */
export async function generate(algo) {
  switch (algo) {
    case enums.publicKey.ed25519: {
      const seed = getRandomBytes(32);
      const { publicKey: A } = nacl.sign.keyPair.fromSeed(seed);
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
 *   r: Uint8Array,
 *   s: Uint8Array
 * }>} Signature of the message
 * @async
 */
export async function sign(algo, hashAlgo, message, publicKey, privateKey, hashed) {
  if (hash.getHashByteLength(hashAlgo) < hash.getHashByteLength(enums.hash.sha256)) {
    // see https://tools.ietf.org/id/draft-ietf-openpgp-rfc4880bis-10.html#section-15-7.2
    throw new Error('Hash algorithm too weak: sha256 or stronger is required for EdDSA.');
  }
  switch (algo) {
    case enums.publicKey.ed25519: {
      const secretKey = util.concatUint8Array([privateKey, publicKey]);
      const signature = nacl.sign.detached(hashed, secretKey);
      return { RS: signature };
    }
    case enums.publicKey.ed448:
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
  switch (algo) {
    case enums.publicKey.ed25519: {
      return nacl.sign.detached.verify(hashed, RS, publicKey);
    }
    case enums.publicKey.ed448:
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
      const { publicKey } = nacl.sign.keyPair.fromSeed(seed);
      return util.equalsUint8Array(A, publicKey);
    }

    case enums.publicKey.ed448: // unsupported
    default:
      return false;
  }
}
