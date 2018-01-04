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

// Wrapper of an instance of an Elliptic Curve

/**
 * @requires crypto/public_key/elliptic/key
 * @requires crypto/public_key/jsbn
 * @requires enums
 * @requires util
 * @module crypto/public_key/elliptic/curve
 */

'use strict';

import { ec as EC, eddsa as EdDSA } from 'elliptic';
import { KeyPair } from './key';
import BigInteger from '../jsbn';
import random from '../../random';
import config from '../../../config';
import enums from '../../../enums';
import util from '../../../util';
import base64 from '../../../encoding/base64';

const webCrypto = util.getWebCrypto();
const nodeCrypto = util.getNodeCrypto();

var webCurves = {}, nodeCurves = {};
if (webCrypto && config.use_native) {
  webCurves = {
    'p256': 'P-256',
    'p384': 'P-384',
    'p521': 'P-521'
  };
} else if (nodeCrypto && config.use_native) {
  var knownCurves = nodeCrypto.getCurves();
  nodeCurves = {
    'secp256k1': knownCurves.includes('secp256k1') ? 'secp256k1' : undefined,
    'p256': knownCurves.includes('prime256v1') ? 'prime256v1' : undefined,
    'p384': knownCurves.includes('secp384r1') ? 'secp384r1' : undefined,
    'p521': knownCurves.includes('secp521r1') ? 'secp521r1' : undefined
    // TODO add more here
  };
}

const curves = {
  p256: {
    oid: util.bin2str([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]),
    hash: enums.hash.sha256,
    cipher: enums.symmetric.aes128,
    node: nodeCurves.secp256r1,
    web: webCurves.secp256r1,
    payloadSize: 32
  },
  p384: {
    oid: util.bin2str([0x2B, 0x81, 0x04, 0x00, 0x22]),
    hash: enums.hash.sha384,
    cipher: enums.symmetric.aes192,
    node: nodeCurves.secp384r1,
    web: webCurves.secp384r1,
    payloadSize: 48
  },
  p521: {
    oid: util.bin2str([0x2B, 0x81, 0x04, 0x00, 0x23]),
    hash: enums.hash.sha512,
    cipher: enums.symmetric.aes256,
    node: nodeCurves.secp521r1,
    web: webCurves.secp521r1,
    payloadSize: 66
  },
  secp256k1: {
    oid: util.bin2str([0x2B, 0x81, 0x04, 0x00, 0x0A]),
    hash: enums.hash.sha256,
    cipher: enums.symmetric.aes128,
    node: false // FIXME when we replace jwk-to-pem or it supports this curve
  },
  ed25519: {
    oid: util.bin2str([0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01]),
    hash: enums.hash.sha512,
    keyType: enums.publicKey.eddsa
  },
  curve25519: {
    oid: util.bin2str([0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01]),
    hash: enums.hash.sha256,
    cipher: enums.symmetric.aes128
  },
  brainpoolP256r1: { // TODO 1.3.36.3.3.2.8.1.1.7
    oid: util.bin2str([0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07])
  },
  brainpoolP512r1: { // TODO 1.3.36.3.3.2.8.1.1.13
    oid: util.bin2str([0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D])
  }
};

function Curve(name, params) {
  if (params.keyType === enums.publicKey.eddsa) {
    this.curve = new EdDSA(name);
    this.keyType = enums.publicKey.eddsa;
  } else {
    this.curve = new EC(name);
    this.keyType = enums.publicKey.ecdsa;
  }
  this.oid = curves[name].oid;
  this.hash = params.hash;
  this.cipher = params.cipher;
  this.node = params.node && curves[name].node;
  this.web = params.web && curves[name].web;
  this.payloadSize = curves[name].payloadSize;
}

Curve.prototype.keyFromPrivate = function (priv) { // Not for ed25519
  return new KeyPair(this.curve, { priv: priv });
};

Curve.prototype.keyFromSecret = function (secret) { // Only for ed25519
  return new KeyPair(this.curve, { secret: secret });
};

Curve.prototype.keyFromPublic = function (pub) {
  return new KeyPair(this.curve, { pub: pub });
};

Curve.prototype.genKeyPair = async function () {
  var r, keyPair;
  if (webCrypto && config.use_native && this.web) {
    keyPair = await webGenKeyPair(this.name, "ECDSA"); // FIXME is ECDH different?
  } else if (nodeCrypto && config.use_native && this.node) {
    keyPair = await nodeGenKeyPair(this.name);
  } else {
    if (this.keyType === enums.publicKey.eddsa) {
      keyPair = {
        secret: util.hexidump(random.getRandomBytes(32))
      };
    } else {
      r = this.curve.genKeyPair();
      keyPair = {
        pub: r.getPublic().encode(),
        priv: r.getPrivate().toArray()
      };
    }
  }
  return new KeyPair(this.curve, keyPair);
};


function get(oid_or_name) {
  var name;
  if (enums.curve[oid_or_name]) {
    name = enums.write(enums.curve, oid_or_name);
    return new Curve(name, curves[name]);
  }
  for (name in curves) {
    if (curves[name].oid === oid_or_name) {
      return new Curve(name, curves[name]);
    }
  }
  throw new Error('Not valid curve');
}

async function generate(curve) {
  curve = get(curve);
  var keyPair = await curve.genKeyPair();
  return {
    oid: curve.oid,
    Q: new BigInteger(keyPair.getPublic()),
    d: new BigInteger(keyPair.getPrivate()),
    hash: curve.hash,
    cipher: curve.cipher
  };
}

module.exports = {
  Curve: Curve,
  generate: generate,
  get: get
};


//////////////////////////
//                      //
//   Helper functions   //
//                      //
//////////////////////////


async function webGenKeyPair(name, algorithm) {
  var webCryptoKey = await webCrypto.generateKey(
    {
      name: algorithm === "ECDH" ? "ECDH" : "ECDSA",
      namedCurve: webCurves[name]
    },
    true,
    algorithm === "ECDH" ? ["deriveKey", "deriveBits"] : ["sign", "verify"]
  );

  var privateKey = await webCrypto.exportKey("jwk", webCryptoKey.privateKey);
  var publicKey = await webCrypto.exportKey("jwk", webCryptoKey.publicKey);

  return {
    pub: {
      x: base64.decode(publicKey.x, 'base64url'),
      y: base64.decode(publicKey.y, 'base64url')
    },
    priv: base64.decode(privateKey.d, 'base64url')
  };
}

async function nodeGenKeyPair(name) {
  var ecdh = nodeCrypto.createECDH(name === "secp256r1" ? "prime256v1" : name);
  await ecdh.generateKeys();

  return {
    pub: ecdh.getPublicKey().toJSON().data,
    priv: ecdh.getPrivateKey().toJSON().data
  };
}
