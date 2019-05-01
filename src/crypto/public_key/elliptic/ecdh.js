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
 * @requires bn.js
 * @requires tweetnacl
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
import nacl from 'tweetnacl/nacl-fast-light.js';
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
async function kdf(hash_algo, X, length, param, stripLeading=false, stripTrailing=false) {
  // Note: X is little endian for Curve25519, big-endian for all others.
  // This is not ideal, but the RFC's are unclear
  // https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-02#appendix-B
  let i;
  if (stripLeading) {
    // Work around old go crypto bug
    for (i = 0; i < X.length && X[i] === 0; i++);
    X = X.subarray(i);
  }
  if (stripTrailing) {
    // Work around old OpenPGP.js bug
    for (i = X.length - 1; i >= 0 && X[i] === 0; i--);
    X = X.subarray(0, i + 1);
  }
  const digest = await hash.digest(hash_algo, util.concatUint8Array([
    new Uint8Array([0, 0, 0, 1]),
    X,
    param
  ]));
  return digest.subarray(0, length);
}

/**
 * Generate ECDHE ephemeral key and secret from public key
 *
 * @param  {Curve}                  curve        Elliptic curve object
 * @param  {Uint8Array}             Q                   Recipient public key
 * @returns {Promise<{V: Uint8Array, S: BN}>}   Returns public part of ephemeral key and generated ephemeral secret
 * @async
 */
async function genPublicEphemeralKey(curve, Q) {
  if (curve.name === 'curve25519') {
    const { secretKey: d } = nacl.box.keyPair();
    const { secretKey, sharedKey } = await genPrivateEphemeralKey(curve, Q, d);
    let { publicKey } = nacl.box.keyPair.fromSecretKey(secretKey);
    publicKey = util.concatUint8Array([new Uint8Array([0x40]), publicKey]);
    return { publicKey, sharedKey }; // Note: sharedKey is little-endian here, unlike below
  }
  const v = await curve.genKeyPair();
  Q = curve.keyFromPublic(Q);
  const publicKey = new Uint8Array(v.getPublic());
  const S = v.derive(Q);
  const len = curve.curve.curve.p.byteLength();
  const sharedKey = S.toArrayLike(Uint8Array, 'be', len);
  return { publicKey, sharedKey };
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
 * @returns {Promise<{V: BN, C: BN}>}            Returns public part of ephemeral key and encoded session key
 * @async
 */
async function encrypt(oid, cipher_algo, hash_algo, m, Q, fingerprint) {
  const curve = new Curve(oid);
  const { publicKey, sharedKey } = await genPublicEphemeralKey(curve, Q);
  const param = buildEcdhParam(enums.publicKey.ecdh, oid, cipher_algo, hash_algo, fingerprint);
  cipher_algo = enums.read(enums.symmetric, cipher_algo);
  const Z = await kdf(hash_algo, sharedKey, cipher[cipher_algo].keySize, param);
  const wrappedKey = aes_kw.wrap(Z, m.toString());
  return { publicKey, wrappedKey };
}

/**
 * Generate ECDHE secret from private key and public part of ephemeral key
 *
 * @param  {Curve}                  curve        Elliptic curve object
 * @param  {Uint8Array}             V            Public part of ephemeral key
 * @param  {Uint8Array}             d            Recipient private key
 * @returns {Promise<BN>}                        Generated ephemeral secret
 * @async
 */
async function genPrivateEphemeralKey(curve, V, d) {
  if (curve.name === 'curve25519') {
    const one = new BN(1);
    const mask = one.ushln(255 - 3).sub(one).ushln(3);
    let secretKey = new BN(d);
    secretKey = secretKey.or(one.ushln(255 - 1));
    secretKey = secretKey.and(mask);
    secretKey = secretKey.toArrayLike(Uint8Array, 'le', 32);
    const sharedKey = nacl.scalarMult(secretKey, V.subarray(1));
    return { secretKey, sharedKey }; // Note: sharedKey is little-endian here, unlike below
  }
  V = curve.keyFromPublic(V);
  d = curve.keyFromPrivate(d);
  const secretKey = new Uint8Array(d.getPrivate());
  const S = d.derive(V);
  const len = curve.curve.curve.p.byteLength();
  const sharedKey = S.toArrayLike(Uint8Array, 'be', len);
  return { secretKey, sharedKey };
}

/**
 * Decrypt and unwrap the value derived from session key
 *
 * @param  {module:type/oid}        oid          Elliptic curve object identifier
 * @param  {module:enums.symmetric} cipher_algo  Symmetric cipher to use
 * @param  {module:enums.hash}      hash_algo    Hash algorithm to use
 * @param  {Uint8Array}             V            Public part of ephemeral key
 * @param  {Uint8Array}             C            Encrypted and wrapped value derived from session key
 * @param  {Uint8Array}             d            Recipient private key
 * @param  {String}                 fingerprint  Recipient fingerprint
 * @returns {Promise<BN>}                        Value derived from session
 * @async
 */
async function decrypt(oid, cipher_algo, hash_algo, V, C, d, fingerprint) {
  const curve = new Curve(oid);
  const { sharedKey } = await genPrivateEphemeralKey(curve, V, d);
  const param = buildEcdhParam(enums.publicKey.ecdh, oid, cipher_algo, hash_algo, fingerprint);
  cipher_algo = enums.read(enums.symmetric, cipher_algo);
  let err;
  for (let i = 0; i < 3; i++) {
    try {
      // Work around old go crypto bug and old OpenPGP.js bug, respectively.
      const Z = await kdf(hash_algo, sharedKey, cipher[cipher_algo].keySize, param, i === 1, i === 2);
      return new BN(aes_kw.unwrap(Z, C));
    } catch (e) {
      err = e;
    }
  }
  throw err;
}

export default { encrypt, decrypt, genPublicEphemeralKey, genPrivateEphemeralKey, buildEcdhParam, kdf };
