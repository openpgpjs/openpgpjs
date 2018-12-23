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
 * @requires elliptic
 * @requires crypto/public_key/elliptic/key
 * @requires crypto/random
 * @requires enums
 * @requires util
 * @requires type/oid
 * @module crypto/public_key/elliptic/curve
 */

import BN from 'bn.js';
import { ec as EC, eddsa as EdDSA } from 'elliptic';
import KeyPair from './key';
import random from '../../random';
import enums from '../../../enums';
import util from '../../../util';
import OID from '../../../type/oid';

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
    payloadSize: 32
  },
  p384: {
    oid: [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22],
    keyType: enums.publicKey.ecdsa,
    hash: enums.hash.sha384,
    cipher: enums.symmetric.aes192,
    node: nodeCurves.p384,
    web: webCurves.p384,
    payloadSize: 48
  },
  p521: {
    oid: [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23],
    keyType: enums.publicKey.ecdsa,
    hash: enums.hash.sha512,
    cipher: enums.symmetric.aes256,
    node: nodeCurves.p521,
    web: webCurves.p521,
    payloadSize: 66
  },
  secp256k1: {
    oid: [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A],
    keyType: enums.publicKey.ecdsa,
    hash: enums.hash.sha256,
    cipher: enums.symmetric.aes128,
    node: nodeCurves.secp256k1
  },
  ed25519: {
    oid: [0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01],
    keyType: enums.publicKey.eddsa,
    hash: enums.hash.sha512,
    node: false // nodeCurves.ed25519 TODO
  },
  curve25519: {
    oid: [0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01],
    keyType: enums.publicKey.ecdsa,
    hash: enums.hash.sha256,
    cipher: enums.symmetric.aes128,
    node: false // nodeCurves.curve25519 TODO
  },
  brainpoolP256r1: {
    oid: [0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07],
    keyType: enums.publicKey.ecdsa,
    hash: enums.hash.sha256,
    cipher: enums.symmetric.aes128,
    node: nodeCurves.brainpoolP256r1
  },
  brainpoolP384r1: {
    oid: [0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B],
    keyType: enums.publicKey.ecdsa,
    hash: enums.hash.sha384,
    cipher: enums.symmetric.aes192,
    node: nodeCurves.brainpoolP384r1
  },
  brainpoolP512r1: {
    oid: [0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D],
    keyType: enums.publicKey.ecdsa,
    hash: enums.hash.sha512,
    cipher: enums.symmetric.aes256,
    node: nodeCurves.brainpoolP512r1
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
  switch (this.keyType) {
    case enums.publicKey.ecdsa:
      this.curve = new EC(this.name);
      break;
    case enums.publicKey.eddsa:
      this.curve = new EdDSA(this.name);
      break;
    default:
      throw new Error('Unknown elliptic key type;');
  }

  this.oid = params.oid;
  this.hash = params.hash;
  this.cipher = params.cipher;
  this.node = params.node && curves[this.name];
  this.web = params.web && curves[this.name];
  this.payloadSize = params.payloadSize;
}

Curve.prototype.keyFromPrivate = function (priv) { // Not for ed25519
  return new KeyPair(this, { priv: priv });
};

Curve.prototype.keyFromSecret = function (secret) { // Only for ed25519
  return new KeyPair(this, { secret: secret });
};

Curve.prototype.keyFromPublic = function (pub) {
  const keyPair = new KeyPair(this, { pub: pub });
  if (
    this.keyType === enums.publicKey.ecdsa &&
    keyPair.keyPair.validate().result !== true
  ) {
    throw new Error('Invalid elliptic public key');
  }
  return keyPair;
};

Curve.prototype.genKeyPair = async function () {
  let keyPair;
  if (this.web && util.getWebCrypto()) {
    // If browser doesn't support a curve, we'll catch it
    try {
      keyPair = await webGenKeyPair(this.name);
    } catch (err) {
      util.print_debug("Browser did not support signing: " + err.message);
    }
  } else if (this.node && util.getNodeCrypto()) {
    keyPair = await nodeGenKeyPair(this.name);
  }

  if (!keyPair || !keyPair.priv) {
    // elliptic fallback
    const r = await this.curve.genKeyPair({
      entropy: util.Uint8Array_to_str(await random.getRandomBytes(32))
    });
    const compact = this.curve.curve.type === 'edwards' || this.curve.curve.type === 'mont';
    if (this.keyType === enums.publicKey.eddsa) {
      keyPair = { secret: r.getSecret() };
    } else {
      keyPair = { pub: r.getPublic('array', compact), priv: r.getPrivate().toArray() };
    }
  }
  return new KeyPair(this, keyPair);
};

async function generate(curve) {
  curve = new Curve(curve);
  const keyPair = await curve.genKeyPair();
  return {
    oid: curve.oid,
    Q: new BN(keyPair.getPublic()),
    d: new BN(keyPair.getPrivate()),
    hash: curve.hash,
    cipher: curve.cipher
  };
}

function getPreferredHashAlgo(oid) {
  return curves[enums.write(enums.curve, oid.toHex())].hash;
}

export default Curve;

export {
  curves, webCurves, nodeCurves, generate, getPreferredHashAlgo
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
    pub: {
      x: util.b64_to_Uint8Array(publicKey.x, true),
      y: util.b64_to_Uint8Array(publicKey.y, true)
    },
    priv: util.b64_to_Uint8Array(privateKey.d, true)
  };
}

async function nodeGenKeyPair(name) {
  // Note: ECDSA and ECDH key generation is structurally equivalent
  const ecdh = nodeCrypto.createECDH(nodeCurves[name]);
  await ecdh.generateKeys();

  return {
    pub: ecdh.getPublicKey().toJSON().data,
    priv: ecdh.getPrivateKey().toJSON().data
  };
}
