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

// Key encryption and decryption for RFC 6637 ECDH

/**
 * @requires crypto/hash
 * @requires crypto/cipher
 * @requires crypto/rfc3394
 * @requires crypto/public_key/elliptic/curves
 * @requires crypto/public_key/jsbn
 * @requires type/oid
 * @requires type/kdf_params
 * @requires enums
 * @requires util
 * @module crypto/public_key/elliptic/ecdh
 */

'use strict';

import BigInteger from '../jsbn.js';
import curves from './curves.js';
import cipher from '../../cipher';
import hash from '../../hash';
import rfc3394 from '../../rfc3394.js';
import enums from '../../../enums.js';
import util from '../../../util.js';
import type_kdf_params from '../../../type/kdf_params.js';
import type_oid from '../../../type/oid.js';

function hex2Uint8Array(hex) {
  var result = new Uint8Array(hex.length/2);
  for (var k=0; k<hex.length/2; k++) {
    result[k] = parseInt(hex.substr(2*k, 2), 16);
  }
  return result;
}

// Build Param for ECDH algorithm (RFC 6637)
function buildEcdhParam(public_algo, oid, cipher_algo, hash_algo, fingerprint) {
  oid = new type_oid(oid);
  const kdf_params = new type_kdf_params(hash_algo, cipher_algo);
  return util.concatUint8Array([
    oid.write(),
    new Uint8Array([public_algo]),
    kdf_params.write(),
    util.str2Uint8Array("Anonymous Sender    "),
    fingerprint
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
 * @param  {String}      oid          Oid of the curve to use
 * @param  {Enums}       cipher_algo  Symmetric cipher to use
 * @param  {Enums}       hash_algo    Hash to use
 * @param  {Uint8Array}  m            Value derived from session key (RFC 6637)
 * @param  {BigInteger}  R            Recipient public key
 * @param  {String}      fingerprint  Recipient fingerprint
 * @return {{V: BigInteger, C: Uint8Array}}  Returns ephemeral key and encoded session key
 */
function encrypt(oid, cipher_algo, hash_algo, m, R, fingerprint) {
  fingerprint = hex2Uint8Array(fingerprint);
  const param = buildEcdhParam(enums.publicKey.ecdh, oid, cipher_algo, hash_algo, fingerprint);
  const curve = curves.get(oid);
  cipher_algo = enums.read(enums.symmetric, cipher_algo);
  const v = curve.genKeyPair();
  R = curve.keyFromPublic(R.toByteArray());
  const S = v.derive(R);
  const Z = kdf(hash_algo, S, cipher[cipher_algo].keySize, param);
  const C = rfc3394.wrap(Z, m);
  return {
    V: new BigInteger(v.getPublic()),
    C: C
  };
}

/**
 * Decrypt and unwrap the value derived from session key
 *
 * @param  {String}      oid          Curve oid
 * @param  {Enums}       cipher_algo  Symmetric cipher to use
 * @param  {Enums}       hash_algo    Hash algorithm to use
 * @param  {BigInteger}  V            Public part of ephemeral key
 * @param  {Uint8Array}  C            Encrypted and wrapped value derived from session key
 * @param  {BigInteger}  r            Recipient private key
 * @param  {String}      fingerprint  Recipient fingerprint
 * @return {Uint8Array}               Value derived from session
 */
function decrypt(oid, cipher_algo, hash_algo, V, C, r, fingerprint) {
  fingerprint = hex2Uint8Array(fingerprint);
  const param = buildEcdhParam(enums.publicKey.ecdh, oid, cipher_algo, hash_algo, fingerprint);
  const curve = curves.get(oid);
  cipher_algo = enums.read(enums.symmetric, cipher_algo);
  V = curve.keyFromPublic(V.toByteArray());
  r = curve.keyFromPrivate(r.toByteArray());
  const S = r.derive(V);
  const Z = kdf(hash_algo, S, cipher[cipher_algo].keySize, param);
  return new BigInteger(rfc3394.unwrap(Z, C));
}

module.exports = {
  encrypt: encrypt,
  decrypt: decrypt
};
