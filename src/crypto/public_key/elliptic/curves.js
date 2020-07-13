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
 * @fileoverview Wrapper of an instance of an Elliptic Curve
 * @requires bn.js
 * @requires tweetnacl
 * @requires crypto/public_key/elliptic/key
 * @requires crypto/random
 * @requires enums
 * @requires util
 * @requires type/oid
 * @requires config
 * @module crypto/public_key/elliptic/curve
 */

import BN from 'bn.js';
import nacl from 'tweetnacl/nacl-fast-light.js';
import random from '../../random';
import enums from '../../../enums';
import util from '../../../util';
import OID from '../../../type/oid';
import { keyFromPublic, keyFromPrivate, getIndutnyCurve } from './indutnyKey';

const webCrypto = util.getWebCrypto();
const nodeCrypto = util.getNodeCrypto();

const webCurves = {
  'p256': 'P-256',
  'p384': 'P-384',
  'p521': 'P-521'
};
const knownCurves = nodeCrypto ? nodeCrypto.getCurves() : [];
const nodeCurves = nodeCrypto ? {
  secp256k1: knownCurves.includes('secp256k1') ? 'secp256k1' : undefined,
  p256: knownCurves.includes('prime256v1') ? 'prime256v1' : undefined,
  p384: knownCurves.includes('secp384r1') ? 'secp384r1' : undefined,
  p521: knownCurves.includes('secp521r1') ? 'secp521r1' : undefined,
  ed25519: knownCurves.includes('ED25519') ? 'ED25519' : undefined,
  curve25519: knownCurves.includes('X25519') ? 'X25519' : undefined,
  brainpoolP256r1: knownCurves.includes('brainpoolP256r1') ? 'brainpoolP256r1' : undefined,
  brainpoolP384r1: knownCurves.includes('brainpoolP384r1') ? 'brainpoolP384r1' : undefined,
  brainpoolP512r1: knownCurves.includes('brainpoolP512r1') ? 'brainpoolP512r1' : undefined
} : {};

const curves = {
  p256: {
    oid: [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
    keyType: enums.publicKey.ecdsa,
    hash: enums.hash.sha256,
    cipher: enums.symmetric.aes128,
    node: nodeCurves.p256,
    web: webCurves.p256,
    payloadSize: 32,
    sharedSize: 256
  },
  p384: {
    oid: [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22],
    keyType: enums.publicKey.ecdsa,
    hash: enums.hash.sha384,
    cipher: enums.symmetric.aes192,
    node: nodeCurves.p384,
    web: webCurves.p384,
    payloadSize: 48,
    sharedSize: 384
  },
  p521: {
    oid: [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23],
    keyType: enums.publicKey.ecdsa,
    hash: enums.hash.sha512,
    cipher: enums.symmetric.aes256,
    node: nodeCurves.p521,
    web: webCurves.p521,
    payloadSize: 66,
    sharedSize: 528
  },
  secp256k1: {
    oid: [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A],
    keyType: enums.publicKey.ecdsa,
    hash: enums.hash.sha256,
    cipher: enums.symmetric.aes128,
    node: nodeCurves.secp256k1,
    payloadSize: 32
  },
  ed25519: {
    oid: [0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01],
    keyType: enums.publicKey.eddsa,
    hash: enums.hash.sha512,
    node: false, // nodeCurves.ed25519 TODO
    payloadSize: 32
  },
  curve25519: {
    oid: [0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01],
    keyType: enums.publicKey.ecdh,
    hash: enums.hash.sha256,
    cipher: enums.symmetric.aes128,
    node: false, // nodeCurves.curve25519 TODO
    payloadSize: 32
  },
  brainpoolP256r1: {
    oid: [0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07],
    keyType: enums.publicKey.ecdsa,
    hash: enums.hash.sha256,
    cipher: enums.symmetric.aes128,
    node: nodeCurves.brainpoolP256r1,
    payloadSize: 32
  },
  brainpoolP384r1: {
    oid: [0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B],
    keyType: enums.publicKey.ecdsa,
    hash: enums.hash.sha384,
    cipher: enums.symmetric.aes192,
    node: nodeCurves.brainpoolP384r1,
    payloadSize: 48
  },
  brainpoolP512r1: {
    oid: [0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D],
    keyType: enums.publicKey.ecdsa,
    hash: enums.hash.sha512,
    cipher: enums.symmetric.aes256,
    node: nodeCurves.brainpoolP512r1,
    payloadSize: 64
  }
};

/**
 * @constructor
 */
function Curve(oid_or_name, params) {
  try {
    if (util.isArray(oid_or_name) ||
        util.isUint8Array(oid_or_name)) {
      // by oid byte array
      oid_or_name = new OID(oid_or_name);
    }
    if (oid_or_name instanceof OID) {
      // by curve OID
      oid_or_name = oid_or_name.getName();
    }
    // by curve name or oid string
    this.name = enums.write(enums.curve, oid_or_name);
  } catch (err) {
    throw new Error('Not valid curve');
  }
  params = params || curves[this.name];

  this.keyType = params.keyType;

  this.oid = params.oid;
  this.hash = params.hash;
  this.cipher = params.cipher;
  this.node = params.node && curves[this.name];
  this.web = params.web && curves[this.name];
  this.payloadSize = params.payloadSize;
  if (this.web && util.getWebCrypto()) {
    this.type = 'web';
  } else if (this.node && util.getNodeCrypto()) {
    this.type = 'node';
  } else if (this.name === 'curve25519') {
    this.type = 'curve25519';
  } else if (this.name === 'ed25519') {
    this.type = 'ed25519';
  }
}

Curve.prototype.genKeyPair = async function () {
  let keyPair;
  switch (this.type) {
    case 'web':
      try {
        return await webGenKeyPair(this.name);
      } catch (err) {
        util.print_debug_error("Browser did not support generating ec key " + err.message);
        break;
      }
    case 'node':
      return nodeGenKeyPair(this.name);
    case 'curve25519': {
      const privateKey = await random.getRandomBytes(32);
      privateKey[0] = (privateKey[0] & 127) | 64;
      privateKey[31] &= 248;
      const secretKey = privateKey.slice().reverse();
      keyPair = nacl.box.keyPair.fromSecretKey(secretKey);
      const publicKey = util.concatUint8Array([new Uint8Array([0x40]), keyPair.publicKey]);
      return { publicKey, privateKey };
    }
    case 'ed25519': {
      const privateKey = await random.getRandomBytes(32);
      const keyPair = nacl.sign.keyPair.fromSeed(privateKey);
      const publicKey = util.concatUint8Array([new Uint8Array([0x40]), keyPair.publicKey]);
      return { publicKey, privateKey };
    }
  }
  const indutnyCurve = await getIndutnyCurve(this.name);
  keyPair = await indutnyCurve.genKeyPair({
    entropy: util.Uint8Array_to_str(await random.getRandomBytes(32))
  });
  return { publicKey: new Uint8Array(keyPair.getPublic('array', false)), privateKey: keyPair.getPrivate().toArrayLike(Uint8Array) };
};

async function generate(curve) {
  curve = new Curve(curve);
  const keyPair = await curve.genKeyPair();
  return {
    oid: curve.oid,
    Q: new BN(keyPair.publicKey),
    d: new BN(keyPair.privateKey),
    hash: curve.hash,
    cipher: curve.cipher
  };
}

function getPreferredHashAlgo(oid) {
  return curves[enums.write(enums.curve, oid.toHex())].hash;
}

/**
 * Validate ECDH and EcDSA parameters
 * Not suitable for EdDSA (different secret key format)
 * @param {module:enums.publicKey}  algo EC algorithm, to filter supported curves
 * @param {module:type/oid}         oid  EC object identifier
 * @param {Uint8Array}              Q    EC public point
 * @param {Uint8Array}              d    EC secret scalar
 * @returns {Promise<Boolean>}      whether params are valid
 * @async
 */
async function validateStandardParams(algo, oid, Q, d) {
  const supportedCurves = {
    p256: true,
    p384: true,
    p521: true,
    secp256k1: true,
    curve25519: algo === enums.publicKey.ecdh,
    brainpoolP256r1: true,
    brainpoolP384r1: true,
    brainpoolP512r1: true
  };

  // Check whether the given curve is supported
  const curveName = oid.getName();
  if (!supportedCurves[curveName]) {
    return false;
  }

  if (curveName === 'curve25519') {
    d = d.slice().reverse();
    // Re-derive public point Q'
    const { publicKey } = nacl.box.keyPair.fromSecretKey(d);

    Q = new Uint8Array(Q);
    const dG = new Uint8Array([0x40, ...publicKey]); // Add public key prefix
    if (!util.equalsUint8Array(dG, Q)) {
      return false;
    }

    return true;
  }

  const curve = await getIndutnyCurve(curveName);
  try {
    // Parse Q and check that it is on the curve but not at infinity
    Q = keyFromPublic(curve, Q).getPublic();
  } catch (validationErrors) {
    return false;
  }

  /**
   * Re-derive public point Q' = dG from private key
   * Expect Q == Q'
   */
  d = new BN(d);
  const dG = keyFromPrivate(curve, d).getPublic();
  if (!dG.eq(Q)) {
    return false;
  }

  return true;
}

export default Curve;

export {
  curves, webCurves, nodeCurves, generate, getPreferredHashAlgo, jwkToRawPublic, rawPublicToJwk, privateToJwk, validateStandardParams
};

//////////////////////////
//                      //
//   Helper functions   //
//                      //
//////////////////////////


async function webGenKeyPair(name) {
  // Note: keys generated with ECDSA and ECDH are structurally equivalent
  const webCryptoKey = await webCrypto.generateKey({ name: "ECDSA", namedCurve: webCurves[name] }, true, ["sign", "verify"]);

  const privateKey = await webCrypto.exportKey("jwk", webCryptoKey.privateKey);
  const publicKey = await webCrypto.exportKey("jwk", webCryptoKey.publicKey);

  return {
    publicKey: jwkToRawPublic(publicKey),
    privateKey: util.b64_to_Uint8Array(privateKey.d, true)
  };
}

async function nodeGenKeyPair(name) {
  // Note: ECDSA and ECDH key generation is structurally equivalent
  const ecdh = nodeCrypto.createECDH(nodeCurves[name]);
  await ecdh.generateKeys();
  return {
    publicKey: new Uint8Array(ecdh.getPublicKey()),
    privateKey: new Uint8Array(ecdh.getPrivateKey())
  };
}

//////////////////////////
//                      //
//   Helper functions   //
//                      //
//////////////////////////

/**
 * @param  {JsonWebKey}                jwk  key for conversion
 *
 * @returns {Uint8Array}                    raw public key
 */
function jwkToRawPublic(jwk) {
  const bufX = util.b64_to_Uint8Array(jwk.x);
  const bufY = util.b64_to_Uint8Array(jwk.y);
  const publicKey = new Uint8Array(bufX.length + bufY.length + 1);
  publicKey[0] = 0x04;
  publicKey.set(bufX, 1);
  publicKey.set(bufY, bufX.length + 1);
  return publicKey;
}

/**
 * @param  {Integer}                payloadSize  ec payload size
 * @param  {String}                 name         curve name
 * @param  {Uint8Array}             publicKey    public key
 *
 * @returns {JsonWebKey}                         public key in jwk format
 */
function rawPublicToJwk(payloadSize, name, publicKey) {
  const len = payloadSize;
  const bufX = publicKey.slice(1, len + 1);
  const bufY = publicKey.slice(len + 1, len * 2 + 1);
  // https://www.rfc-editor.org/rfc/rfc7518.txt
  const jwk = {
    kty: "EC",
    crv: name,
    x: util.Uint8Array_to_b64(bufX, true),
    y: util.Uint8Array_to_b64(bufY, true),
    ext: true
  };
  return jwk;
}

/**
 * @param  {Integer}                payloadSize  ec payload size
 * @param  {String}                 name         curve name
 * @param  {Uint8Array}             publicKey    public key
 * @param  {Uint8Array}             privateKey   private key
 *
 * @returns {JsonWebKey}                         private key in jwk format
 */
function privateToJwk(payloadSize, name, publicKey, privateKey) {
  const jwk = rawPublicToJwk(payloadSize, name, publicKey);
  jwk.d = util.Uint8Array_to_b64(privateKey, true);
  return jwk;
}
