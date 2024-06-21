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
 */

import naclEd25519 from '@openpgp/tweetnacl'; // better constant-timeness as it uses Uint8Arrays over BigInts
import { verify as nobleEd25519Verify } from '@noble/ed25519';
import util from '../../../util';
import enums from '../../../enums';
import hash from '../../hash';
import { CurveWithOID, checkPublicPointEnconding } from './oid_curves';

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
  if (hash.getHashByteLength(hashAlgo) < hash.getHashByteLength(enums.hash.sha256)) {
    // see https://tools.ietf.org/id/draft-ietf-openpgp-rfc4880bis-10.html#section-15-7.2
    throw new Error('Hash algorithm too weak for EdDSA.');
  }
  const secretKey = util.concatUint8Array([privateKey, publicKey.subarray(1)]);
  const signature = naclEd25519.sign.detached(hashed, secretKey);
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
export async function verify(oid, hashAlgo, { r, s }, m, publicKey, hashed) {
  const curve = new CurveWithOID(oid);
  checkPublicPointEnconding(curve, publicKey);
  if (hash.getHashByteLength(hashAlgo) < hash.getHashByteLength(enums.hash.sha256)) {
    throw new Error('Hash algorithm too weak for EdDSA.');
  }
  const signature = util.concatUint8Array([r, s]);
  return nobleEd25519Verify(signature, hashed, publicKey.subarray(1));
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

  /**
   * Derive public point Q' = dG from private key
   * and expect Q == Q'
   */
  const { publicKey } = naclEd25519.sign.keyPair.fromSeed(k);
  const dG = new Uint8Array([0x40, ...publicKey]); // Add public key prefix
  return util.equalsUint8Array(Q, dG);

}
