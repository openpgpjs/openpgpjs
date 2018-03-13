// OpenPGP.js - An OpenPGP implementation in javascript
// Copyright (C) 2015-2016 Decentral
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
 * @fileoverview Implementation of ECDSA following RFC6637 for Openpgpjs
 * @requires crypto/hash
 * @requires crypto/public_key/elliptic/curve
 * @module crypto/public_key/elliptic/ecdsa
 */

import hash from '../../hash';
import Curve from './curves';

/**
 * Sign a message using the provided key
 * @param  {module:type/oid}   oid       Elliptic curve object identifier
 * @param  {module:enums.hash} hash_algo Hash algorithm used to sign
 * @param  {Uint8Array}        m         Message to sign
 * @param  {Uint8Array}        d         Private key used to sign the message
 * @returns {{r: Uint8Array,
 *            s: Uint8Array}}            Signature of the message
 * @async
 */
async function sign(oid, hash_algo, m, d) {
  const curve = new Curve(oid);
  const key = curve.keyFromPrivate(d);
  const signature = await key.sign(m, hash_algo);
  return { r: signature.r.toArrayLike(Uint8Array),
           s: signature.s.toArrayLike(Uint8Array) };
}

/**
 * Verifies if a signature is valid for a message
 * @param  {module:type/oid}   oid       Elliptic curve object identifier
 * @param  {module:enums.hash} hash_algo Hash algorithm used in the signature
 * @param  {{r: Uint8Array,
             s: Uint8Array}}   signature Signature to verify
 * @param  {Uint8Array}        m         Message to verify
 * @param  {Uint8Array}        Q         Public key used to verify the message
 * @returns {Boolean}
 * @async
 */
async function verify(oid, hash_algo, signature, m, Q) {
  const curve = new Curve(oid);
  const key = curve.keyFromPublic(Q);
  return key.verify(m, signature, hash_algo);
}

export default { sign, verify };
