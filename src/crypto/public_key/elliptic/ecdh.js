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
 * @module crypto/public_key/elliptic/ecdh
 */

import { CurveWithOID, jwkToRawPublic, rawPublicToJWK, privateToJWK, validateStandardParams, checkPublicPointEnconding } from './oid_curves';
import * as aesKW from '../../aes_kw';
import { computeDigest } from '../../hash';
import enums from '../../../enums';
import util from '../../../util';
import { b64ToUint8Array } from '../../../encoding/base64';
import * as pkcs5 from '../../pkcs5';
import { getCipherParams } from '../../cipher';
import { generateEphemeralEncryptionMaterial as ecdhXGenerateEphemeralEncryptionMaterial, recomputeSharedSecret as ecdhXRecomputeSharedSecret } from './ecdh_x';

/**
 * Validate ECDH parameters
 * @param {module:type/oid} oid - Elliptic curve object identifier
 * @param {Uint8Array} Q - ECDH public point
 * @param {Uint8Array} d - ECDH secret scalar
 * @returns {Promise<Boolean>} Whether params are valid.
 * @async
 */
export async function validateParams(oid, Q, d) {
  return validateStandardParams(enums.publicKey.ecdh, oid, Q, d);
}

// Build Param for ECDH algorithm (RFC 6637)
function buildEcdhParam(public_algo, oid, kdfParams, fingerprint) {
  return util.concatUint8Array([
    oid.write(),
    new Uint8Array([public_algo]),
    kdfParams.write(),
    util.stringToUint8Array('Anonymous Sender    '),
    fingerprint
  ]);
}

// Key Derivation Function (RFC 6637)
async function kdf(hashAlgo, X, length, param, stripLeading = false, stripTrailing = false) {
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
  const digest = await computeDigest(hashAlgo, util.concatUint8Array([
    new Uint8Array([0, 0, 0, 1]),
    X,
    param
  ]));
  return digest.subarray(0, length);
}

/**
 * Generate ECDHE ephemeral key and secret from public key
 *
 * @param {CurveWithOID} curve - Elliptic curve object
 * @param {Uint8Array} Q - Recipient public key
 * @returns {Promise<{publicKey: Uint8Array, sharedKey: Uint8Array}>}
 * @async
 */
async function genPublicEphemeralKey(curve, Q) {
  switch (curve.type) {
    case 'curve25519Legacy': {
      const { sharedSecret: sharedKey, ephemeralPublicKey } = await ecdhXGenerateEphemeralEncryptionMaterial(enums.publicKey.x25519, Q.subarray(1));
      const publicKey = util.concatUint8Array([new Uint8Array([curve.wireFormatLeadingByte]), ephemeralPublicKey]);
      return { publicKey, sharedKey }; // Note: sharedKey is little-endian here, unlike below
    }
    case 'web':
      if (curve.web && util.getWebCrypto()) {
        try {
          return await webPublicEphemeralKey(curve, Q);
        } catch (err) {
          util.printDebugError(err);
          return jsPublicEphemeralKey(curve, Q);
        }
      }
      break;
    case 'node':
      return nodePublicEphemeralKey(curve, Q);
    default:
      return jsPublicEphemeralKey(curve, Q);

  }
}

/**
 * Encrypt and wrap a session key
 *
 * @param {module:type/oid} oid - Elliptic curve object identifier
 * @param {module:type/kdf_params} kdfParams - KDF params including cipher and algorithm to use
 * @param {Uint8Array} data - Unpadded session key data
 * @param {Uint8Array} Q - Recipient public key
 * @param {Uint8Array} fingerprint - Recipient fingerprint, already truncated depending on the key version
 * @returns {Promise<{publicKey: Uint8Array, wrappedKey: Uint8Array}>}
 * @async
 */
export async function encrypt(oid, kdfParams, data, Q, fingerprint) {
  const m = pkcs5.encode(data);

  const curve = new CurveWithOID(oid);
  checkPublicPointEnconding(curve, Q);
  const { publicKey, sharedKey } = await genPublicEphemeralKey(curve, Q);
  const param = buildEcdhParam(enums.publicKey.ecdh, oid, kdfParams, fingerprint);
  const { keySize } = getCipherParams(kdfParams.cipher);
  const Z = await kdf(kdfParams.hash, sharedKey, keySize, param);
  const wrappedKey = await aesKW.wrap(kdfParams.cipher, Z, m);
  return { publicKey, wrappedKey };
}

/**
 * Generate ECDHE secret from private key and public part of ephemeral key
 *
 * @param {CurveWithOID} curve - Elliptic curve object
 * @param {Uint8Array} V - Public part of ephemeral key
 * @param {Uint8Array} Q - Recipient public key
 * @param {Uint8Array} d - Recipient private key
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
    case 'curve25519Legacy': {
      const secretKey = d.slice().reverse();
      const sharedKey = await ecdhXRecomputeSharedSecret(enums.publicKey.x25519, V.subarray(1), Q.subarray(1), secretKey);
      return { secretKey, sharedKey }; // Note: sharedKey is little-endian here, unlike below
    }
    case 'web':
      if (curve.web && util.getWebCrypto()) {
        try {
          return await webPrivateEphemeralKey(curve, V, Q, d);
        } catch (err) {
          util.printDebugError(err);
          return jsPrivateEphemeralKey(curve, V, d);
        }
      }
      break;
    case 'node':
      return nodePrivateEphemeralKey(curve, V, d);
    default:
      return jsPrivateEphemeralKey(curve, V, d);
  }
}

/**
 * Decrypt and unwrap the value derived from session key
 *
 * @param {module:type/oid} oid - Elliptic curve object identifier
 * @param {module:type/kdf_params} kdfParams - KDF params including cipher and algorithm to use
 * @param {Uint8Array} V - Public part of ephemeral key
 * @param {Uint8Array} C - Encrypted and wrapped value derived from session key
 * @param {Uint8Array} Q - Recipient public key
 * @param {Uint8Array} d - Recipient private key
 * @param {Uint8Array} fingerprint - Recipient fingerprint, already truncated depending on the key version
 * @returns {Promise<Uint8Array>} Value derived from session key.
 * @async
 */
export async function decrypt(oid, kdfParams, V, C, Q, d, fingerprint) {
  const curve = new CurveWithOID(oid);
  checkPublicPointEnconding(curve, Q);
  checkPublicPointEnconding(curve, V);
  const { sharedKey } = await genPrivateEphemeralKey(curve, V, Q, d);
  const param = buildEcdhParam(enums.publicKey.ecdh, oid, kdfParams, fingerprint);
  const { keySize } = getCipherParams(kdfParams.cipher);
  let err;
  for (let i = 0; i < 3; i++) {
    try {
      // Work around old go crypto bug and old OpenPGP.js bug, respectively.
      const Z = await kdf(kdfParams.hash, sharedKey, keySize, param, i === 1, i === 2);
      return pkcs5.decode(await aesKW.unwrap(kdfParams.cipher, Z, C));
    } catch (e) {
      err = e;
    }
  }
  throw err;
}

async function jsPrivateEphemeralKey(curve, V, d) {
  const nobleCurve = await util.getNobleCurve(enums.publicKey.ecdh, curve.name);
  // The output includes parity byte
  const sharedSecretWithParity = nobleCurve.getSharedSecret(d, V);
  const sharedKey = sharedSecretWithParity.subarray(1);
  return { secretKey: d, sharedKey };
}

async function jsPublicEphemeralKey(curve, Q) {
  const nobleCurve = await util.getNobleCurve(enums.publicKey.ecdh, curve.name);
  const { publicKey: V, privateKey: v } = await curve.genKeyPair();

  // The output includes parity byte
  const sharedSecretWithParity = nobleCurve.getSharedSecret(v, Q);
  const sharedKey = sharedSecretWithParity.subarray(1);
  return { publicKey: V, sharedKey };
}

/**
 * Generate ECDHE secret from private key and public part of ephemeral key using webCrypto
 *
 * @param {CurveWithOID} curve - Elliptic curve object
 * @param {Uint8Array} V - Public part of ephemeral key
 * @param {Uint8Array} Q - Recipient public key
 * @param {Uint8Array} d - Recipient private key
 * @returns {Promise<{secretKey: Uint8Array, sharedKey: Uint8Array}>}
 * @async
 */
async function webPrivateEphemeralKey(curve, V, Q, d) {
  const webCrypto = util.getWebCrypto();
  const recipient = privateToJWK(curve.payloadSize, curve.web, Q, d);
  let privateKey = webCrypto.importKey(
    'jwk',
    recipient,
    {
      name: 'ECDH',
      namedCurve: curve.web
    },
    true,
    ['deriveKey', 'deriveBits']
  );
  const jwk = rawPublicToJWK(curve.payloadSize, curve.web, V);
  let sender = webCrypto.importKey(
    'jwk',
    jwk,
    {
      name: 'ECDH',
      namedCurve: curve.web
    },
    true,
    []
  );
  [privateKey, sender] = await Promise.all([privateKey, sender]);
  let S = webCrypto.deriveBits(
    {
      name: 'ECDH',
      namedCurve: curve.web,
      public: sender
    },
    privateKey,
    curve.sharedSize
  );
  let secret = webCrypto.exportKey(
    'jwk',
    privateKey
  );
  [S, secret] = await Promise.all([S, secret]);
  const sharedKey = new Uint8Array(S);
  const secretKey = b64ToUint8Array(secret.d, true);
  return { secretKey, sharedKey };
}

/**
 * Generate ECDHE ephemeral key and secret from public key using webCrypto
 *
 * @param {CurveWithOID} curve - Elliptic curve object
 * @param {Uint8Array} Q - Recipient public key
 * @returns {Promise<{publicKey: Uint8Array, sharedKey: Uint8Array}>}
 * @async
 */
async function webPublicEphemeralKey(curve, Q) {
  const webCrypto = util.getWebCrypto();
  const jwk = rawPublicToJWK(curve.payloadSize, curve.web, Q);
  let keyPair = webCrypto.generateKey(
    {
      name: 'ECDH',
      namedCurve: curve.web
    },
    true,
    ['deriveKey', 'deriveBits']
  );
  let recipient = webCrypto.importKey(
    'jwk',
    jwk,
    {
      name: 'ECDH',
      namedCurve: curve.web
    },
    false,
    []
  );
  [keyPair, recipient] = await Promise.all([keyPair, recipient]);
  let s = webCrypto.deriveBits(
    {
      name: 'ECDH',
      namedCurve: curve.web,
      public: recipient
    },
    keyPair.privateKey,
    curve.sharedSize
  );
  let p = webCrypto.exportKey(
    'jwk',
    keyPair.publicKey
  );
  [s, p] = await Promise.all([s, p]);
  const sharedKey = new Uint8Array(s);
  const publicKey = new Uint8Array(jwkToRawPublic(p, curve.wireFormatLeadingByte));
  return { publicKey, sharedKey };
}

/**
 * Generate ECDHE secret from private key and public part of ephemeral key using nodeCrypto
 *
 * @param {CurveWithOID} curve - Elliptic curve object
 * @param {Uint8Array} V - Public part of ephemeral key
 * @param {Uint8Array} d - Recipient private key
 * @returns {Promise<{secretKey: Uint8Array, sharedKey: Uint8Array}>}
 * @async
 */
async function nodePrivateEphemeralKey(curve, V, d) {
  const nodeCrypto = util.getNodeCrypto();
  const recipient = nodeCrypto.createECDH(curve.node);
  recipient.setPrivateKey(d);
  const sharedKey = new Uint8Array(recipient.computeSecret(V));
  const secretKey = new Uint8Array(recipient.getPrivateKey());
  return { secretKey, sharedKey };
}

/**
 * Generate ECDHE ephemeral key and secret from public key using nodeCrypto
 *
 * @param {CurveWithOID} curve - Elliptic curve object
 * @param {Uint8Array} Q - Recipient public key
 * @returns {Promise<{publicKey: Uint8Array, sharedKey: Uint8Array}>}
 * @async
 */
async function nodePublicEphemeralKey(curve, Q) {
  const nodeCrypto = util.getNodeCrypto();
  const sender = nodeCrypto.createECDH(curve.node);
  sender.generateKeys();
  const sharedKey = new Uint8Array(sender.computeSecret(Q));
  const publicKey = new Uint8Array(sender.getPublicKey());
  return { publicKey, sharedKey };
}
