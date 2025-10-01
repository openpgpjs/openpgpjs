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
 * @fileoverview Implementation of legacy EdDSA following RFC4880bis-03 for OpenPGP.
 * This key type has been deprecated by the crypto-refresh RFC.
 * @module crypto/public_key/elliptic/eddsa_legacy
 * @access private
 */

import util from '../../../util';
import enums from '../../../enums';
import { getHashByteLength } from '../../hash';
import { CurveWithOID, checkPublicPointEnconding } from './oid_curves';
import { sign as eddsaSign, verify as eddsaVerify, validateParams as eddsaValidateParams } from './eddsa';

/**
 * Sign a message using the provided legacy EdDSA key
 * @param {module:type/oid} oid - Elliptic curve object identifier
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
export async function sign(oid, hashAlgo, message, publicKey, privateKey, hashed) {
  const curve = new CurveWithOID(oid);
  checkPublicPointEnconding(curve, publicKey);
  if (getHashByteLength(hashAlgo) < getHashByteLength(enums.hash.sha256)) {
    // Enforce digest sizes, since the constraint was already present in RFC4880bis:
    // see https://tools.ietf.org/id/draft-ietf-openpgp-rfc4880bis-10.html#section-15-7.2
    // and https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.3-3
    throw new Error('Hash algorithm too weak for EdDSA.');
  }
  const { RS: signature } = await eddsaSign(enums.publicKey.ed25519, hashAlgo, message, publicKey.subarray(1), privateKey, hashed);
  // EdDSA signature params are returned in little-endian format
  return {
    r: signature.subarray(0, 32),
    s: signature.subarray(32)
  };
}

/**
 * Verifies if a legacy EdDSA signature is valid for a message
 * @param {module:type/oid} oid - Elliptic curve object identifier
 * @param {module:enums.hash} hashAlgo - Hash algorithm used in the signature
 * @param  {{r: Uint8Array,
             s: Uint8Array}}   signature Signature to verify the message
 * @param {Uint8Array} m - Message to verify
 * @param {Uint8Array} publicKey - Public key used to verify the message
 * @param {Uint8Array} hashed - The hashed message
 * @returns {Boolean}
 * @async
 */
// eslint-disable-next-line @typescript-eslint/require-await
export async function verify(oid, hashAlgo, { r, s }, m, publicKey, hashed) {
  const curve = new CurveWithOID(oid);
  checkPublicPointEnconding(curve, publicKey);
  if (getHashByteLength(hashAlgo) < getHashByteLength(enums.hash.sha256)) {
    // Enforce digest sizes, since the constraint was already present in RFC4880bis:
    // see https://tools.ietf.org/id/draft-ietf-openpgp-rfc4880bis-10.html#section-15-7.2
    // and https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.3-3
    throw new Error('Hash algorithm too weak for EdDSA.');
  }
  const RS = util.concatUint8Array([r, s]);
  return eddsaVerify(enums.publicKey.ed25519, hashAlgo, { RS }, m, publicKey.subarray(1), hashed);
}
/**
 * Validate legacy EdDSA parameters
 * @param {module:type/oid} oid - Elliptic curve object identifier
 * @param {Uint8Array} Q - EdDSA public point
 * @param {Uint8Array} k - EdDSA secret seed
 * @returns {Promise<Boolean>} Whether params are valid.
 * @async
 */
export async function validateParams(oid, Q, k) {
  // Check whether the given curve is supported
  if (oid.getName() !== enums.curve.ed25519Legacy) {
    return false;
  }

  // First byte is relevant for encoding purposes only
  if (Q.length < 1 || Q[0] !== 0x40) {
    return false;
  }
  return eddsaValidateParams(enums.publicKey.ed25519, Q.subarray(1), k);
}
