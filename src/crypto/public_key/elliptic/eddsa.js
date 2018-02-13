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

// Implementation of EdDSA following RFC4880bis-03 for OpenPGP

/**
 * @requires bn.js
 * @requires crypto/hash
 * @requires crypto/public_key/elliptic/curves
 * @module crypto/public_key/elliptic/eddsa
 */

import BN from 'bn.js';
import hash from '../../hash';
import curves from './curves';

/**
 * Sign a message using the provided key
 * @param  {String}      oid        Elliptic curve for the key
 * @param  {enums.hash}  hash_algo  Hash algorithm used to sign
 * @param  {Uint8Array}  m          Message to sign
 * @param  {BigInteger}  d          Private key used to sign
 * @return {{R: BN, S: BN}}         Signature of the message
 */
async function sign(oid, hash_algo, m, d) {
  const curve = curves.get(oid);
  const key = curve.keyFromSecret(d.toByteArray());
  const signature = await key.sign(m, hash_algo);
  // EdDSA signature params are returned in little-endian format
  return {
    R: new BN(Array.from(signature.Rencoded()).reverse()),
    S: new BN(Array.from(signature.Sencoded()).reverse())
  };
}

/**
 * Verifies if a signature is valid for a message
 * @param  {String}      oid        Elliptic curve for the key
 * @param  {enums.hash}  hash_algo  Hash algorithm used in the signature
 * @param  {{R: BigInteger, S: BigInteger}}  signature  Signature to verify
 * @param  {Uint8Array}  m          Message to verify
 * @param  {BigInteger}  Q          Public key used to verify the message
 * @return {Boolean}
 */
async function verify(oid, hash_algo, signature, m, Q) {
  const curve = curves.get(oid);
  const key = curve.keyFromPublic(Q.toByteArray());
  // EdDSA signature params are expected in little-endian format
  const R = Array.from(signature.R.toByteArray()).reverse();
  const S = Array.from(signature.S.toByteArray()).reverse();
  return key.verify(m, {
    R: [].concat(R, Array(curve.payloadSize - R.length).fill(0)),
    S: [].concat(S, Array(curve.payloadSize - S.length).fill(0))
  }, hash_algo);
}

module.exports = {
  sign: sign,
  verify: verify
};
