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
 * @requires crypto/random
 * @requires crypto/hash
 * @requires type/kdf_params
 * @requires enums
 * @requires util
 * @module crypto/public_key/elliptic/ecdh
 */

import BN from 'bn.js';
import nacl from 'tweetnacl/nacl-fast-light.js';
import Curve, { jwkToRawPublic, rawPublicToJwk, privateToJwk, validateStandardParams } from './curves';
import aes_kw from '../../aes_kw';
import cipher from '../../cipher';
import random from '../../random';
import hash from '../../hash';
import enums from '../../../enums';
import util from '../../../util';
import { keyFromPublic, keyFromPrivate, getIndutnyCurve } from './indutnyKey';

const webCrypto = util.getWebCrypto();
const nodeCrypto = util.getNodeCrypto();

/**
 * Validate ECDH parameters
 * @param {module:type/oid}    oid Elliptic curve object identifier
 * @param {Uint8Array}         Q   ECDH public point
 * @param {Uint8Array}         d   ECDH secret scalar
 * @returns {Promise<Boolean>} whether params are valid
 * @async
 */
async function validateParams(oid, Q, d) {
  return validateStandardParams(enums.publicKey.ecdh, oid, Q, d);
}

// Build Param for ECDH algorithm (RFC 6637)
function buildEcdhParam(public_algo, oid, kdfParams, fingerprint) {
  return util.concatUint8Array([
    oid.write(),
    new Uint8Array([public_algo]),
    kdfParams.write(),
    util.str_to_Uint8Array("Anonymous Sender    "),
    fingerprint.subarray(0, 20)
  ]);
}

/**
 * Parses MPI params and returns them as byte arrays of fixed length
 * @param {Array} params key parameters
 * @returns {Object} parameters in the form
 *  { oid, kdfParams, d: Uint8Array, Q: Uint8Array }
 */
function parseParams(params) {
  if (params.length < 3 || params.length > 4) {
    throw new Error('Unexpected number of parameters');
  }

  const oid = params[0];
  const curve = new Curve(oid);
  const parsedParams = { oid };
  // The public point never has leading zeros, as it is prefixed by 0x40 or 0x04
  parsedParams.Q = params[1].toUint8Array();
  parsedParams.kdfParams = params[2];

  if (params.length === 4) {
    parsedParams.d = params[3].toUint8Array('be', curve.payloadSize);
  }

  return parsedParams;
}

// Key Derivation Function (RFC 6637)
async function kdf(hash_algo, X, length, param, stripLeading = false, stripTrailing = false) {
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
 * @param  {Uint8Array}             Q            Recipient public key
 * @returns {Promise<{publicKey: Uint8Array, sharedKey: Uint8Array}>}
 * @async
 */
async function genPublicEphemeralKey(curve, Q) {
  switch (curve.type) {
    case 'curve25519': {
      const d = await random.getRandomBytes(32);
      const { secretKey, sharedKey } = await genPrivateEphemeralKey(curve, Q, null, d);
      let { publicKey } = nacl.box.keyPair.fromSecretKey(secretKey);
      publicKey = util.concatUint8Array([new Uint8Array([0x40]), publicKey]);
      return { publicKey, sharedKey }; // Note: sharedKey is little-endian here, unlike below
    }
    case 'web':
      if (curve.web && util.getWebCrypto()) {
        try {
          return await webPublicEphemeralKey(curve, Q);
        } catch (err) {
          util.print_debug_error(err);
        }
      }
      break;
    case 'node':
      return nodePublicEphemeralKey(curve, Q);
  }
  return ellipticPublicEphemeralKey(curve, Q);
}

/**
 * Encrypt and wrap a session key
 *
 * @param  {module:type/oid}        oid          Elliptic curve object identifier
 * @param  {module:type/kdf_params} kdfParams    KDF params including cipher and algorithm to use
 * @param  {module:type/mpi}        m            Value derived from session key (RFC 6637)
 * @param  {Uint8Array}             Q            Recipient public key
 * @param  {Uint8Array}             fingerprint  Recipient fingerprint
 * @returns {Promise<{publicKey: Uint8Array, wrappedKey: Uint8Array}>}
 * @async
 */
async function encrypt(oid, kdfParams, m, Q, fingerprint) {
  const curve = new Curve(oid);
  const { publicKey, sharedKey } = await genPublicEphemeralKey(curve, Q);
  const param = buildEcdhParam(enums.publicKey.ecdh, oid, kdfParams, fingerprint);
  const cipher_algo = enums.read(enums.symmetric, kdfParams.cipher);
  const Z = await kdf(kdfParams.hash, sharedKey, cipher[cipher_algo].keySize, param);
  const wrappedKey = aes_kw.wrap(Z, m.toString());
  return { publicKey, wrappedKey };
}

/**
 * Generate ECDHE secret from private key and public part of ephemeral key
 *
 * @param  {Curve}                  curve        Elliptic curve object
 * @param  {Uint8Array}             V            Public part of ephemeral key
 * @param  {Uint8Array}             Q            Recipient public key
 * @param  {Uint8Array}             d            Recipient private key
 * @returns {Promise<{secretKey: Uint8Array, sharedKey: Uint8Array}>}
 * @async
 */
async function genPrivateEphemeralKey(curve, V, Q, d) {
  if (d.length !== curve.payloadSize) {
    const privateKey = new Uint8Array(curve.payloadSize);
    privateKey.set(d, curve.payloadSize - d.length);
    d = privateKey;
  }
  switch (curve.type) {
    case 'curve25519': {
      const secretKey = d.slice().reverse();
      const sharedKey = nacl.scalarMult(secretKey, V.subarray(1));
      return { secretKey, sharedKey }; // Note: sharedKey is little-endian here, unlike below
    }
    case 'web':
      if (curve.web && util.getWebCrypto()) {
        try {
          return await webPrivateEphemeralKey(curve, V, Q, d);
        } catch (err) {
          util.print_debug_error(err);
        }
      }
      break;
    case 'node':
      return nodePrivateEphemeralKey(curve, V, d);
  }
  return ellipticPrivateEphemeralKey(curve, V, d);
}

/**
 * Decrypt and unwrap the value derived from session key
 *
 * @param  {module:type/oid}        oid          Elliptic curve object identifier
 * @param  {module:type/kdf_params} kdfParams    KDF params including cipher and algorithm to use
 * @param  {Uint8Array}             V            Public part of ephemeral key
 * @param  {Uint8Array}             C            Encrypted and wrapped value derived from session key
 * @param  {Uint8Array}             Q            Recipient public key
 * @param  {Uint8Array}             d            Recipient private key
 * @param  {Uint8Array}             fingerprint  Recipient fingerprint
 * @returns {Promise<BN>}                        Value derived from session key
 * @async
 */
async function decrypt(oid, kdfParams, V, C, Q, d, fingerprint) {
  const curve = new Curve(oid);
  const { sharedKey } = await genPrivateEphemeralKey(curve, V, Q, d);
  const param = buildEcdhParam(enums.publicKey.ecdh, oid, kdfParams, fingerprint);
  const cipher_algo = enums.read(enums.symmetric, kdfParams.cipher);
  let err;
  for (let i = 0; i < 3; i++) {
    try {
      // Work around old go crypto bug and old OpenPGP.js bug, respectively.
      const Z = await kdf(kdfParams.hash, sharedKey, cipher[cipher_algo].keySize, param, i === 1, i === 2);
      return new BN(aes_kw.unwrap(Z, C));
    } catch (e) {
      err = e;
    }
  }
  throw err;
}

/**
 * Generate ECDHE secret from private key and public part of ephemeral key using webCrypto
 *
 * @param  {Curve}                  curve         Elliptic curve object
 * @param  {Uint8Array}             V             Public part of ephemeral key
 * @param  {Uint8Array}             Q             Recipient public key
 * @param  {Uint8Array}             d             Recipient private key
 * @returns {Promise<{secretKey: Uint8Array, sharedKey: Uint8Array}>}
 * @async
 */
async function webPrivateEphemeralKey(curve, V, Q, d) {
  const recipient = privateToJwk(curve.payloadSize, curve.web.web, Q, d);
  let privateKey = webCrypto.importKey(
    "jwk",
    recipient,
    {
      name: "ECDH",
      namedCurve: curve.web.web
    },
    true,
    ["deriveKey", "deriveBits"]
  );
  const jwk = rawPublicToJwk(curve.payloadSize, curve.web.web, V);
  let sender = webCrypto.importKey(
    "jwk",
    jwk,
    {
      name: "ECDH",
      namedCurve: curve.web.web
    },
    true,
    []
  );
  [privateKey, sender] = await Promise.all([privateKey, sender]);
  let S = webCrypto.deriveBits(
    {
      name: "ECDH",
      namedCurve: curve.web.web,
      public: sender
    },
    privateKey,
    curve.web.sharedSize
  );
  let secret = webCrypto.exportKey(
    "jwk",
    privateKey
  );
  [S, secret] = await Promise.all([S, secret]);
  const sharedKey = new Uint8Array(S);
  const secretKey = util.b64_to_Uint8Array(secret.d, true);
  return { secretKey, sharedKey };
}

/**
 * Generate ECDHE ephemeral key and secret from public key using webCrypto
 *
 * @param  {Curve}                  curve        Elliptic curve object
 * @param  {Uint8Array}             Q            Recipient public key
 * @returns {Promise<{publicKey: Uint8Array, sharedKey: Uint8Array}>}
 * @async
 */
async function webPublicEphemeralKey(curve, Q) {
  const jwk = rawPublicToJwk(curve.payloadSize, curve.web.web, Q);
  let keyPair = webCrypto.generateKey(
    {
      name: "ECDH",
      namedCurve: curve.web.web
    },
    true,
    ["deriveKey", "deriveBits"]
  );
  let recipient = webCrypto.importKey(
    "jwk",
    jwk,
    {
      name: "ECDH",
      namedCurve: curve.web.web
    },
    false,
    []
  );
  [keyPair, recipient] = await Promise.all([keyPair, recipient]);
  let s = webCrypto.deriveBits(
    {
      name: "ECDH",
      namedCurve: curve.web.web,
      public: recipient
    },
    keyPair.privateKey,
    curve.web.sharedSize
  );
  let p = webCrypto.exportKey(
    "jwk",
    keyPair.publicKey
  );
  [s, p] = await Promise.all([s, p]);
  const sharedKey = new Uint8Array(s);
  const publicKey = new Uint8Array(jwkToRawPublic(p));
  return { publicKey, sharedKey };
}

/**
 * Generate ECDHE secret from private key and public part of ephemeral key using indutny/elliptic
 *
 * @param  {Curve}                  curve        Elliptic curve object
 * @param  {Uint8Array}             V            Public part of ephemeral key
 * @param  {Uint8Array}             d            Recipient private key
 * @returns {Promise<{secretKey: Uint8Array, sharedKey: Uint8Array}>}
 * @async
 */
async function ellipticPrivateEphemeralKey(curve, V, d) {
  const indutnyCurve = await getIndutnyCurve(curve.name);
  V = keyFromPublic(indutnyCurve, V);
  d = keyFromPrivate(indutnyCurve, d);
  const secretKey = new Uint8Array(d.getPrivate());
  const S = d.derive(V.getPublic());
  const len = indutnyCurve.curve.p.byteLength();
  const sharedKey = S.toArrayLike(Uint8Array, 'be', len);
  return { secretKey, sharedKey };
}

/**
 * Generate ECDHE ephemeral key and secret from public key using indutny/elliptic
 *
 * @param  {Curve}                  curve        Elliptic curve object
 * @param  {Uint8Array}             Q            Recipient public key
 * @returns {Promise<{publicKey: Uint8Array, sharedKey: Uint8Array}>}
 * @async
 */
async function ellipticPublicEphemeralKey(curve, Q) {
  const indutnyCurve = await getIndutnyCurve(curve.name);
  const v = await curve.genKeyPair();
  Q = keyFromPublic(indutnyCurve, Q);
  const V = keyFromPrivate(indutnyCurve, v.privateKey);
  const publicKey = v.publicKey;
  const S = V.derive(Q.getPublic());
  const len = indutnyCurve.curve.p.byteLength();
  const sharedKey = S.toArrayLike(Uint8Array, 'be', len);
  return { publicKey, sharedKey };
}

/**
 * Generate ECDHE secret from private key and public part of ephemeral key using nodeCrypto
 *
 * @param  {Curve}                  curve          Elliptic curve object
 * @param  {Uint8Array}             V              Public part of ephemeral key
 * @param  {Uint8Array}             d              Recipient private key
 * @returns {Promise<{secretKey: Uint8Array, sharedKey: Uint8Array}>}
 * @async
 */
async function nodePrivateEphemeralKey(curve, V, d) {
  const recipient = nodeCrypto.createECDH(curve.node.node);
  recipient.setPrivateKey(d);
  const sharedKey = new Uint8Array(recipient.computeSecret(V));
  const secretKey = new Uint8Array(recipient.getPrivateKey());
  return { secretKey, sharedKey };
}

/**
 * Generate ECDHE ephemeral key and secret from public key using nodeCrypto
 *
 * @param  {Curve}                  curve        Elliptic curve object
 * @param  {Uint8Array}             Q            Recipient public key
 * @returns {Promise<{publicKey: Uint8Array, sharedKey: Uint8Array}>}
 * @async
 */
async function nodePublicEphemeralKey(curve, Q) {
  const sender = nodeCrypto.createECDH(curve.node.node);
  sender.generateKeys();
  const sharedKey = new Uint8Array(sender.computeSecret(Q));
  const publicKey = new Uint8Array(sender.getPublicKey());
  return { publicKey, sharedKey };
}

export default { encrypt, decrypt, genPublicEphemeralKey, genPrivateEphemeralKey, buildEcdhParam, kdf, webPublicEphemeralKey, webPrivateEphemeralKey, ellipticPublicEphemeralKey, ellipticPrivateEphemeralKey, nodePublicEphemeralKey, nodePrivateEphemeralKey, validateParams, parseParams };
