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
 * @module crypto/public_key/elliptic/curve
 */
import nacl from '@openpgp/tweetnacl';
import { getRandomBytes } from '../../random';
import enums from '../../../enums';
import util from '../../../util';
import { uint8ArrayToB64, b64ToUint8Array } from '../../../encoding/base64';
import OID from '../../../type/oid';
import { UnsupportedError } from '../../../packet/packet';

const webCrypto = util.getWebCrypto();
const nodeCrypto = util.getNodeCrypto();

const webCurves = {
  [enums.curve.nistP256]: 'P-256',
  [enums.curve.nistP384]: 'P-384',
  [enums.curve.nistP521]: 'P-521'
};
const knownCurves = nodeCrypto ? nodeCrypto.getCurves() : [];
const nodeCurves = nodeCrypto ? {
  [enums.curve.secp256k1]: knownCurves.includes('secp256k1') ? 'secp256k1' : undefined,
  [enums.curve.nistP256]: knownCurves.includes('prime256v1') ? 'prime256v1' : undefined,
  [enums.curve.nistP384]: knownCurves.includes('secp384r1') ? 'secp384r1' : undefined,
  [enums.curve.nistP521]: knownCurves.includes('secp521r1') ? 'secp521r1' : undefined,
  [enums.curve.ed25519Legacy]: knownCurves.includes('ED25519') ? 'ED25519' : undefined,
  [enums.curve.curve25519Legacy]: knownCurves.includes('X25519') ? 'X25519' : undefined,
  [enums.curve.brainpoolP256r1]: knownCurves.includes('brainpoolP256r1') ? 'brainpoolP256r1' : undefined,
  [enums.curve.brainpoolP384r1]: knownCurves.includes('brainpoolP384r1') ? 'brainpoolP384r1' : undefined,
  [enums.curve.brainpoolP512r1]: knownCurves.includes('brainpoolP512r1') ? 'brainpoolP512r1' : undefined
} : {};

const curves = {
  [enums.curve.nistP256]: {
    oid: [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
    keyType: enums.publicKey.ecdsa,
    hash: enums.hash.sha256,
    cipher: enums.symmetric.aes128,
    node: nodeCurves[enums.curve.nistP256],
    web: webCurves[enums.curve.nistP256],
    payloadSize: 32,
    sharedSize: 256,
    wireFormatLeadingByte: 0x04
  },
  [enums.curve.nistP384]: {
    oid: [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22],
    keyType: enums.publicKey.ecdsa,
    hash: enums.hash.sha384,
    cipher: enums.symmetric.aes192,
    node: nodeCurves[enums.curve.nistP384],
    web: webCurves[enums.curve.nistP384],
    payloadSize: 48,
    sharedSize: 384,
    wireFormatLeadingByte: 0x04
  },
  [enums.curve.nistP521]: {
    oid: [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23],
    keyType: enums.publicKey.ecdsa,
    hash: enums.hash.sha512,
    cipher: enums.symmetric.aes256,
    node: nodeCurves[enums.curve.nistP521],
    web: webCurves[enums.curve.nistP521],
    payloadSize: 66,
    sharedSize: 528,
    wireFormatLeadingByte: 0x04
  },
  [enums.curve.secp256k1]: {
    oid: [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A],
    keyType: enums.publicKey.ecdsa,
    hash: enums.hash.sha256,
    cipher: enums.symmetric.aes128,
    node: nodeCurves[enums.curve.secp256k1],
    payloadSize: 32,
    wireFormatLeadingByte: 0x04
  },
  [enums.curve.ed25519Legacy]: {
    oid: [0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01],
    keyType: enums.publicKey.eddsaLegacy,
    hash: enums.hash.sha512,
    node: false, // nodeCurves.ed25519 TODO
    payloadSize: 32,
    wireFormatLeadingByte: 0x40
  },
  [enums.curve.curve25519Legacy]: {
    oid: [0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01],
    keyType: enums.publicKey.ecdh,
    hash: enums.hash.sha256,
    cipher: enums.symmetric.aes128,
    node: false, // nodeCurves.curve25519 TODO
    payloadSize: 32,
    wireFormatLeadingByte: 0x40
  },
  [enums.curve.brainpoolP256r1]: {
    oid: [0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07],
    keyType: enums.publicKey.ecdsa,
    hash: enums.hash.sha256,
    cipher: enums.symmetric.aes128,
    node: nodeCurves[enums.curve.brainpoolP256r1],
    payloadSize: 32,
    wireFormatLeadingByte: 0x04
  },
  [enums.curve.brainpoolP384r1]: {
    oid: [0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B],
    keyType: enums.publicKey.ecdsa,
    hash: enums.hash.sha384,
    cipher: enums.symmetric.aes192,
    node: nodeCurves[enums.curve.brainpoolP384r1],
    payloadSize: 48,
    wireFormatLeadingByte: 0x04
  },
  [enums.curve.brainpoolP512r1]: {
    oid: [0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D],
    keyType: enums.publicKey.ecdsa,
    hash: enums.hash.sha512,
    cipher: enums.symmetric.aes256,
    node: nodeCurves[enums.curve.brainpoolP512r1],
    payloadSize: 64,
    wireFormatLeadingByte: 0x04
  }
};

class CurveWithOID {
  constructor(oidOrName) {
    try {
      this.name = oidOrName instanceof OID ?
        oidOrName.getName() :
        enums.write(enums.curve,oidOrName);
    } catch (err) {
      throw new UnsupportedError('Unknown curve');
    }
    const params = curves[this.name];

    this.keyType = params.keyType;

    this.oid = params.oid;
    this.hash = params.hash;
    this.cipher = params.cipher;
    this.node = params.node;
    this.web = params.web;
    this.payloadSize = params.payloadSize;
    this.sharedSize = params.sharedSize;
    this.wireFormatLeadingByte = params.wireFormatLeadingByte;
    if (this.web && util.getWebCrypto()) {
      this.type = 'web';
    } else if (this.node && util.getNodeCrypto()) {
      this.type = 'node';
    } else if (this.name === enums.curve.curve25519Legacy) {
      this.type = 'curve25519Legacy';
    } else if (this.name === enums.curve.ed25519Legacy) {
      this.type = 'ed25519Legacy';
    }
  }

  async genKeyPair() {
    switch (this.type) {
      case 'web':
        try {
          return await webGenKeyPair(this.name, this.wireFormatLeadingByte);
        } catch (err) {
          util.printDebugError('Browser did not support generating ec key ' + err.message);
          return jsGenKeyPair(this.name);
        }
      case 'node':
        return nodeGenKeyPair(this.name);
      case 'curve25519Legacy': {
        const privateKey = getRandomBytes(32);
        privateKey[0] = (privateKey[0] & 127) | 64;
        privateKey[31] &= 248;
        const secretKey = privateKey.slice().reverse();
        const { publicKey: rawPublicKey } = nacl.box.keyPair.fromSecretKey(secretKey);
        const publicKey = util.concatUint8Array([new Uint8Array([this.wireFormatLeadingByte]), rawPublicKey]);
        return { publicKey, privateKey };
      }
      case 'ed25519Legacy': {
        const privateKey = getRandomBytes(32);
        const keyPair = nacl.sign.keyPair.fromSeed(privateKey);
        const publicKey = util.concatUint8Array([new Uint8Array([this.wireFormatLeadingByte]), keyPair.publicKey]);
        return { publicKey, privateKey };
      }
      default:
        return jsGenKeyPair(this.name);
    }
  }
}

async function generate(curveName) {
  const curve = new CurveWithOID(curveName);
  const { oid, hash, cipher } = curve;
  const keyPair = await curve.genKeyPair();
  return {
    oid,
    Q: keyPair.publicKey,
    secret: util.leftPad(keyPair.privateKey, curve.payloadSize),
    hash,
    cipher
  };
}

/**
 * Get preferred hash algo to use with the given curve
 * @param {module:type/oid} oid - curve oid
 * @returns {enums.hash} hash algorithm
 */
function getPreferredHashAlgo(oid) {
  return curves[oid.getName()].hash;
}

/**
 * Validate ECDH and ECDSA parameters
 * Not suitable for EdDSA (different secret key format)
 * @param {module:enums.publicKey} algo - EC algorithm, to filter supported curves
 * @param {module:type/oid} oid - EC object identifier
 * @param {Uint8Array} Q - EC public point
 * @param {Uint8Array} d - EC secret scalar
 * @returns {Promise<Boolean>} Whether params are valid.
 * @async
 */
async function validateStandardParams(algo, oid, Q, d) {
  const supportedCurves = {
    [enums.curve.nistP256]: true,
    [enums.curve.nistP384]: true,
    [enums.curve.nistP521]: true,
    [enums.curve.secp256k1]: true,
    [enums.curve.curve25519Legacy]: algo === enums.publicKey.ecdh,
    [enums.curve.brainpoolP256r1]: true,
    [enums.curve.brainpoolP384r1]: true,
    [enums.curve.brainpoolP512r1]: true
  };

  // Check whether the given curve is supported
  const curveName = oid.getName();
  if (!supportedCurves[curveName]) {
    return false;
  }

  if (curveName === enums.curve.curve25519Legacy) {
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

  const nobleCurve = await util.getNobleCurve(enums.publicKey.ecdsa, curveName); // excluding curve25519Legacy, ecdh and ecdsa use the same curves
  /*
   * Re-derive public point Q' = dG from private key
   * Expect Q == Q'
   */
  const dG = nobleCurve.getPublicKey(d, false);
  if (!util.equalsUint8Array(dG, Q)) {
    return false;
  }

  return true;
}

/**
 * Check whether the public point has a valid encoding.
 * NB: this function does not check e.g. whether the point belongs to the curve.
 */
function checkPublicPointEnconding(curve, V) {
  const { payloadSize, wireFormatLeadingByte, name: curveName } = curve;

  const pointSize = (curveName === enums.curve.curve25519Legacy || curveName === enums.curve.ed25519Legacy) ? payloadSize : payloadSize * 2;

  if (V[0] !== wireFormatLeadingByte || V.length !== pointSize + 1) {
    throw new Error('Invalid point encoding');
  }
}

export {
  CurveWithOID, curves, webCurves, nodeCurves, generate, getPreferredHashAlgo, jwkToRawPublic, rawPublicToJWK, privateToJWK, validateStandardParams, checkPublicPointEnconding
};

//////////////////////////
//                      //
//   Helper functions   //
//                      //
//////////////////////////
async function jsGenKeyPair(name) {
  const nobleCurve = await util.getNobleCurve(enums.publicKey.ecdsa, name); // excluding curve25519Legacy, ecdh and ecdsa use the same curves
  const privateKey = nobleCurve.utils.randomPrivateKey();
  const publicKey = nobleCurve.getPublicKey(privateKey, false);
  return { publicKey, privateKey };
}

async function webGenKeyPair(name, wireFormatLeadingByte) {
  // Note: keys generated with ECDSA and ECDH are structurally equivalent
  const webCryptoKey = await webCrypto.generateKey({ name: 'ECDSA', namedCurve: webCurves[name] }, true, ['sign', 'verify']);

  const privateKey = await webCrypto.exportKey('jwk', webCryptoKey.privateKey);
  const publicKey = await webCrypto.exportKey('jwk', webCryptoKey.publicKey);

  return {
    publicKey: jwkToRawPublic(publicKey, wireFormatLeadingByte),
    privateKey: b64ToUint8Array(privateKey.d, true)
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
 * @param {JsonWebKey} jwk - key for conversion
 *
 * @returns {Uint8Array} Raw public key.
 */
function jwkToRawPublic(jwk, wireFormatLeadingByte) {
  const bufX = b64ToUint8Array(jwk.x);
  const bufY = b64ToUint8Array(jwk.y);
  const publicKey = new Uint8Array(bufX.length + bufY.length + 1);
  publicKey[0] = wireFormatLeadingByte;
  publicKey.set(bufX, 1);
  publicKey.set(bufY, bufX.length + 1);
  return publicKey;
}

/**
 * @param {Integer} payloadSize - ec payload size
 * @param {String} name - curve name
 * @param {Uint8Array} publicKey - public key
 *
 * @returns {JsonWebKey} Public key in jwk format.
 */
function rawPublicToJWK(payloadSize, name, publicKey) {
  const len = payloadSize;
  const bufX = publicKey.slice(1, len + 1);
  const bufY = publicKey.slice(len + 1, len * 2 + 1);
  // https://www.rfc-editor.org/rfc/rfc7518.txt
  const jwk = {
    kty: 'EC',
    crv: name,
    x: uint8ArrayToB64(bufX, true),
    y: uint8ArrayToB64(bufY, true),
    ext: true
  };
  return jwk;
}

/**
 * @param {Integer} payloadSize - ec payload size
 * @param {String} name - curve name
 * @param {Uint8Array} publicKey - public key
 * @param {Uint8Array} privateKey - private key
 *
 * @returns {JsonWebKey} Private key in jwk format.
 */
function privateToJWK(payloadSize, name, publicKey, privateKey) {
  const jwk = rawPublicToJWK(payloadSize, name, publicKey);
  jwk.d = uint8ArrayToB64(privateKey, true);
  return jwk;
}
