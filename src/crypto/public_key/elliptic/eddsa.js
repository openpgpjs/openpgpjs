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
 * @requires hash.js
 * @requires tweetnacl
 * @requires crypto/public_key/elliptic/curve
 * @requires util
 * @module crypto/public_key/elliptic/eddsa
 */

import sha512 from 'hash.js/lib/hash/sha/512';
import nacl from 'tweetnacl/nacl-fast-light.js';
import util from '../../../util';

nacl.hash = bytes => new Uint8Array(sha512().update(bytes).digest());

/**
 * Sign a message using the provided key
 * @param  {module:type/oid}   oid          Elliptic curve object identifier
 * @param  {module:enums.hash} hash_algo    Hash algorithm used to sign
 * @param  {Uint8Array}        message      Message to sign
 * @param  {Uint8Array}        publicKey    Public key
 * @param  {Uint8Array}        privateKey   Private key used to sign the message
 * @param  {Uint8Array}        hashed       The hashed message
 * @returns {{R: Uint8Array,
 *            S: Uint8Array}}               Signature of the message
 * @async
 */
async function sign(oid, hash_algo, message, publicKey, privateKey, hashed) {
  const secretKey = util.concatUint8Array([privateKey, publicKey.subarray(1)]);
  const signature = nacl.sign.detached(hashed, secretKey);
  // EdDSA signature params are returned in little-endian format
  return {
    R: signature.subarray(0, 32),
    S: signature.subarray(32)
  };
}

/**
 * Verifies if a signature is valid for a message
 * @param  {module:type/oid}   oid       Elliptic curve object identifier
 * @param  {module:enums.hash} hash_algo Hash algorithm used in the signature
 * @param  {{R: Uint8Array,
             S: Uint8Array}}   signature Signature to verify the message
 * @param  {Uint8Array}        m         Message to verify
 * @param  {Uint8Array}        publicKey Public key used to verify the message
 * @param  {Uint8Array}        hashed    The hashed message
 * @returns {Boolean}
 * @async
 */
async function verify(oid, hash_algo, { R, S }, m, publicKey, hashed) {
  const signature = util.concatUint8Array([R, S]);
  return nacl.sign.detached.verify(hashed, signature, publicKey.subarray(1));
}

export default { sign, verify };
