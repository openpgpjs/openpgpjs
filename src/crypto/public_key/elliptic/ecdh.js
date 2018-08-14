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
 * @fileoverview Key encryption and decryption for RFC 6637 ECDH
 * @requires crypto/public_key/elliptic/curve
 * @requires crypto/aes_kw
 * @requires crypto/cipher
 * @requires crypto/hash
 * @requires type/kdf_params
 * @requires enums
 * @requires util
 * @module crypto/public_key/elliptic/ecdh
 */

import BN from 'bn.js';
import Curve from './curves';
import aes_kw from '../../aes_kw';
import cipher from '../../cipher';
import hash from '../../hash';
import type_kdf_params from '../../../type/kdf_params';
import enums from '../../../enums';
import util from '../../../util';

// Build Param for ECDH algorithm (RFC 6637)
function buildEcdhParam(public_algo, oid, cipher_algo, hash_algo, fingerprint) {
  const kdf_params = new type_kdf_params([hash_algo, cipher_algo]);
  return util.concatUint8Array([
    oid.write(),
    new Uint8Array([public_algo]),
    kdf_params.write(),
    util.str_to_Uint8Array("Anonymous Sender    "),
    fingerprint.subarray(0, 20)
  ]);
}

// Key Derivation Function (RFC 6637)
function kdf(hash_algo, X, length, param) {
  return hash.digest(hash_algo, util.concatUint8Array([
    new Uint8Array([0, 0, 0, 1]),
    new Uint8Array(X),
    param
  ])).subarray(0, length);
}


/**
 * Encrypt and wrap a session key
 *
 * @param  {module:type/oid}        oid          Elliptic curve object identifier
 * @param  {module:enums.symmetric} cipher_algo  Symmetric cipher to use
 * @param  {module:enums.hash}      hash_algo    Hash algorithm to use
 * @param  {module:type/mpi}        m            Value derived from session key (RFC 6637)
 * @param  {Uint8Array}             Q            Recipient public key
 * @param  {String}                 fingerprint  Recipient fingerprint
 * @returns {Promise<{V: BN, C: BN}>}            Returns ephemeral key and encoded session key
 * @async
 */
async function encrypt(oid, cipher_algo, hash_algo, m, Q, fingerprint) {
  const curve = new Curve(oid);
  const param = buildEcdhParam(enums.publicKey.ecdh, oid, cipher_algo, hash_algo, fingerprint);
  cipher_algo = enums.read(enums.symmetric, cipher_algo);
  const v = await curve.genKeyPair();
  Q = curve.keyFromPublic(Q);
  const S = v.derive(Q);
  const Z = kdf(hash_algo, S, cipher[cipher_algo].keySize, param);
  const C = aes_kw.wrap(Z, m.toString());
  return {
    V: new BN(v.getPublic()),
    C: C
  };
}

/**
 * Decrypt and unwrap the value derived from session key
 *
 * @param  {module:type/oid}        oid          Elliptic curve object identifier
 * @param  {module:enums.symmetric} cipher_algo  Symmetric cipher to use
 * @param  {module:enums.hash}      hash_algo    Hash algorithm to use
 * @param  {BN}                     V            Public part of ephemeral key
 * @param  {Uint8Array}             C            Encrypted and wrapped value derived from session key
 * @param  {Uint8Array}             d            Recipient private key
 * @param  {String}                 fingerprint  Recipient fingerprint
 * @returns {Promise<Uint8Array>}                Value derived from session
 * @async
 */
async function decrypt(oid, cipher_algo, hash_algo, V, C, d, fingerprint) {
  const curve = new Curve(oid);
  const param = buildEcdhParam(enums.publicKey.ecdh, oid, cipher_algo, hash_algo, fingerprint);
  cipher_algo = enums.read(enums.symmetric, cipher_algo);
  V = curve.keyFromPublic(V);
  d = curve.keyFromPrivate(d);
  const S = d.derive(V);
  const Z = kdf(hash_algo, S, cipher[cipher_algo].keySize, param);
  return new BN(aes_kw.unwrap(Z, C));
}

export default { encrypt, decrypt };
