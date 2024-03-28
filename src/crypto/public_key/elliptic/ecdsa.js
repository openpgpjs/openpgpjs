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
 * @module crypto/public_key/elliptic/ecdsa
 */

import enums from '../../../enums';
import util from '../../../util';
import { getRandomBytes } from '../../random';
import hash from '../../hash';
import { CurveWithOID, webCurves, privateToJWK, rawPublicToJWK, validateStandardParams, nodeCurves } from './oid_curves';

const webCrypto = util.getWebCrypto();
const nodeCrypto = util.getNodeCrypto();

/**
 * Sign a message using the provided key
 * @param {module:type/oid} oid - Elliptic curve object identifier
 * @param {module:enums.hash} hashAlgo - Hash algorithm used to sign
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
  if (message && !util.isStream(message)) {
    const keyPair = { publicKey, privateKey };
    switch (curve.type) {
      case 'web':
        // If browser doesn't support a curve, we'll catch it
        try {
          // Need to await to make sure browser succeeds
          return await webSign(curve, hashAlgo, message, keyPair);
        } catch (err) {
          // We do not fallback if the error is related to key integrity
          // Unfortunaley Safari does not support nistP521 and throws a DataError when using it
          // So we need to always fallback for that curve
          if (curve.name !== 'nistP521' && (err.name === 'DataError' || err.name === 'OperationError')) {
            throw err;
          }
          util.printDebugError('Browser did not support signing: ' + err.message);
        }
        break;
      case 'node':
        return nodeSign(curve, hashAlgo, message, privateKey);
    }
  }

  const nobleCurve = await util.getNobleCurve(enums.publicKey.ecdsa, curve.name);
  // lowS: non-canonical sig: https://stackoverflow.com/questions/74338846/ecdsa-signature-verification-mismatch
  const signature = nobleCurve.sign(hashed, privateKey, { lowS: false });
  return {
    r: signature.r.toUint8Array('be', curve.payloadSize),
    s: signature.s.toUint8Array('be', curve.payloadSize)
  };
}

/**
 * Verifies if a signature is valid for a message
 * @param {module:type/oid} oid - Elliptic curve object identifier
 * @param {module:enums.hash} hashAlgo - Hash algorithm used in the signature
 * @param  {{r: Uint8Array,
             s: Uint8Array}}   signature Signature to verify
 * @param {Uint8Array} message - Message to verify
 * @param {Uint8Array} publicKey - Public key used to verify the message
 * @param {Uint8Array} hashed - The hashed message
 * @returns {Boolean}
 * @async
 */
export async function verify(oid, hashAlgo, signature, message, publicKey, hashed) {
  const curve = new CurveWithOID(oid);
  // See https://github.com/openpgpjs/openpgpjs/pull/948.
  // NB: the impact was more likely limited to Brainpool curves, since thanks
  // to WebCrypto availability, NIST curve should not have been affected.
  // Similarly, secp256k1 should have been used rarely enough.
  // However, we implement the fix for all curves, since it's only needed in case of
  // verification failure, which is unexpected, hence a minor slowdown is acceptable.
  const tryFallbackVerificationForOldBug = async () => (
    hashed[0] === 0 ?
      jsVerify(curve, signature, hashed.subarray(1), publicKey) :
      false
  );

  if (message && !util.isStream(message)) {
    switch (curve.type) {
      case 'web':
        try {
          // Need to await to make sure browser succeeds
          const verified = await webVerify(curve, hashAlgo, signature, message, publicKey);
          return verified || tryFallbackVerificationForOldBug();
        } catch (err) {
          // We do not fallback if the error is related to key integrity
          // Unfortunately Safari does not support nistP521 and throws a DataError when using it
          // So we need to always fallback for that curve
          if (curve.name !== 'nistP521' && (err.name === 'DataError' || err.name === 'OperationError')) {
            throw err;
          }
          util.printDebugError('Browser did not support verifying: ' + err.message);
        }
        break;
      case 'node': {
        const verified = await nodeVerify(curve, hashAlgo, signature, message, publicKey);
        return verified || tryFallbackVerificationForOldBug();
      }
    }
  }

  const verified = await jsVerify(curve, signature, hashed, publicKey);
  return verified || tryFallbackVerificationForOldBug();
}

/**
 * Validate ECDSA parameters
 * @param {module:type/oid} oid - Elliptic curve object identifier
 * @param {Uint8Array} Q - ECDSA public point
 * @param {Uint8Array} d - ECDSA secret scalar
 * @returns {Promise<Boolean>} Whether params are valid.
 * @async
 */
export async function validateParams(oid, Q, d) {
  const curve = new CurveWithOID(oid);
  // Reject curves x25519 and ed25519
  if (curve.keyType !== enums.publicKey.ecdsa) {
    return false;
  }

  // To speed up the validation, we try to use node- or webcrypto when available
  // and sign + verify a random message
  switch (curve.type) {
    case 'web':
    case 'node': {
      const message = getRandomBytes(8);
      const hashAlgo = enums.hash.sha256;
      const hashed = await hash.digest(hashAlgo, message);
      try {
        const signature = await sign(oid, hashAlgo, message, Q, d, hashed);
        return await verify(oid, hashAlgo, signature, message, Q, hashed);
      } catch (err) {
        return false;
      }
    }
    default:
      return validateStandardParams(enums.publicKey.ecdsa, oid, Q, d);
  }
}


//////////////////////////
//                      //
//   Helper functions   //
//                      //
//////////////////////////

/**
 * Fallback javascript implementation of ECDSA verification.
 * To be used if no native implementation is available for the given curve/operation.
 */
async function jsVerify(curve, signature, hashed, publicKey) {
  const nobleCurve = await util.getNobleCurve(enums.publicKey.ecdsa, curve.name);
  // lowS: non-canonical sig: https://stackoverflow.com/questions/74338846/ecdsa-signature-verification-mismatch
  return nobleCurve.verify(util.concatUint8Array([signature.r, signature.s]), hashed, publicKey, { lowS: false });
}

async function webSign(curve, hashAlgo, message, keyPair) {
  const len = curve.payloadSize;
  const jwk = privateToJWK(curve.payloadSize, webCurves[curve.name], keyPair.publicKey, keyPair.privateKey);
  const key = await webCrypto.importKey(
    'jwk',
    jwk,
    {
      'name': 'ECDSA',
      'namedCurve': webCurves[curve.name],
      'hash': { name: enums.read(enums.webHash, curve.hash) }
    },
    false,
    ['sign']
  );

  const signature = new Uint8Array(await webCrypto.sign(
    {
      'name': 'ECDSA',
      'namedCurve': webCurves[curve.name],
      'hash': { name: enums.read(enums.webHash, hashAlgo) }
    },
    key,
    message
  ));

  return {
    r: signature.slice(0, len),
    s: signature.slice(len, len << 1)
  };
}

async function webVerify(curve, hashAlgo, { r, s }, message, publicKey) {
  const jwk = rawPublicToJWK(curve.payloadSize, webCurves[curve.name], publicKey);
  const key = await webCrypto.importKey(
    'jwk',
    jwk,
    {
      'name': 'ECDSA',
      'namedCurve': webCurves[curve.name],
      'hash': { name: enums.read(enums.webHash, curve.hash) }
    },
    false,
    ['verify']
  );

  const signature = util.concatUint8Array([r, s]).buffer;

  return webCrypto.verify(
    {
      'name': 'ECDSA',
      'namedCurve': webCurves[curve.name],
      'hash': { name: enums.read(enums.webHash, hashAlgo) }
    },
    key,
    signature,
    message
  );
}

async function nodeSign(curve, hashAlgo, message, privateKey) {
  // JWT encoding cannot be used for now, as Brainpool curves are not supported
  const ecKeyUtils = util.nodeRequire('eckey-utils');
  const nodeBuffer = util.getNodeBuffer();
  const { privateKey: derPrivateKey } = ecKeyUtils.generateDer({
    curveName: nodeCurves[curve.name],
    privateKey: nodeBuffer.from(privateKey)
  });

  const sign = nodeCrypto.createSign(enums.read(enums.hash, hashAlgo));
  sign.write(message);
  sign.end();

  const signature = new Uint8Array(sign.sign({ key: derPrivateKey, format: 'der', type: 'sec1', dsaEncoding: 'ieee-p1363' }));
  const len = curve.payloadSize;

  return {
    r: signature.subarray(0, len),
    s: signature.subarray(len, len << 1)
  };
}

async function nodeVerify(curve, hashAlgo, { r, s }, message, publicKey) {
  const ecKeyUtils = util.nodeRequire('eckey-utils');
  const nodeBuffer = util.getNodeBuffer();
  const { publicKey: derPublicKey } = ecKeyUtils.generateDer({
    curveName: nodeCurves[curve.name],
    publicKey: nodeBuffer.from(publicKey)
  });

  const verify = nodeCrypto.createVerify(enums.read(enums.hash, hashAlgo));
  verify.write(message);
  verify.end();

  const signature = util.concatUint8Array([r, s]);

  try {
    return verify.verify({ key: derPublicKey, format: 'der', type: 'spki', dsaEncoding: 'ieee-p1363' }, signature);
  } catch (err) {
    return false;
  }
}
