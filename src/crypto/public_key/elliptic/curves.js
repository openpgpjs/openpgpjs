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

import {ec as EC} from 'elliptic';
import {KeyPair} from './key.js';
import BigInteger from '../jsbn.js';
import config from '../../../config';
import enums from '../../../enums.js';
import util from '../../../util.js';

const webCrypto = util.getWebCrypto();
const nodeCrypto = util.getNodeCrypto();

var webCurves = [], nodeCurves = [];
if (webCrypto && config.use_native) {
  // see https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API/Supported_algorithms
  webCurves = ['P-256', 'P-384', 'P-521'];
} else if (nodeCrypto && config.use_native) {
  // FIXME make sure the name translations are correct
  nodeCurves = nodeCrypto.getCurves();
}

const curves = {
  p256: {
    oid: util.bin2str([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]),
    namedCurve: 'P-256',
    opensslCurve: 'prime256v1',
    hashName: 'SHA-256',
    hash: enums.hash.sha256,
    cipher: enums.symmetric.aes128,
    node: nodeCurves.includes('prime256v1'),
    web: webCurves.includes('P-256')
  },
  p384: {
    oid: util.bin2str([0x2B, 0x81, 0x04, 0x00, 0x22]),
    namedCurve: 'P-384',
    opensslCurve: 'secp384r1', // FIXME
    hashName: 'SHA-384',
    hash: enums.hash.sha384,
    cipher: enums.symmetric.aes192,
    node: nodeCurves.includes('secp384r1'), // FIXME
    web: webCurves.includes('P-384')
  },
  p521: {
    oid: util.bin2str([0x2B, 0x81, 0x04, 0x00, 0x23]),
    namedCurve: 'P-521',
    opensslCurve: 'secp521r1', // FIXME
    hashName: 'SHA-512',
    hash: enums.hash.sha512,
    cipher: enums.symmetric.aes256,
    node: nodeCurves.includes('secp521r1'), // FIXME
    web: webCurves.includes('P-521')
  },
  secp256k1: {
    oid: util.bin2str([0x2B, 0x81, 0x04, 0x00, 0x0A]),
    namedCurve: 'SECP-256K1',
    opensslCurve: 'secp256k1',
    hashName: 'SHA-256',
    hash: enums.hash.sha256,
    cipher: enums.symmetric.aes128,
    node: false, // FIXME nodeCurves.includes('secp256k1'),
    // this is because jwk-to-pem does not support this curve.
    web: false
  }
};

function Curve(name, {oid, hash, cipher, namedCurve, opensslCurve, hashName, node, web}) {
  this.curve = new EC(name);
  this.name = name;
  this.oid = oid;
  this.hash = hash;
  this.cipher = cipher;
  this.namedCurve= namedCurve;
  this.opensslCurve = opensslCurve;
  this.hashName = hashName;
  this.node = node;
  this.web = web;
}

Curve.prototype.keyFromPrivate = function (priv) {
  return new KeyPair(this.curve, {priv: priv});
};

Curve.prototype.keyFromPublic = function (pub) {
  return new KeyPair(this.curve, {pub: pub});
};

Curve.prototype.genKeyPair = async function () {
  var keyPair;
  if (webCrypto && config.use_native && this.web) {
    keyPair = await webGenKeyPair(this.namedCurve);
  } else if (nodeCrypto && config.use_native && this.node) {
    keyPair = await nodeGenKeyPair(this.opensslCurve);
  } else {
    var r = this.curve.genKeyPair();
    keyPair = {
      pub: r.getPublic().encode(),
      priv: r.getPrivate().toArray()
    };
  }
  return new KeyPair(this.curve, keyPair);
};


function get(oid_or_name) {
  for (var name in curves) {
    if (curves[name].oid === oid_or_name || name === oid_or_name) {
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


async function webGenKeyPair(namedCurve) {
  try {
    var keyPair = await webCrypto.generateKey(
      {
        name: "ECDSA", // FIXME or "ECDH"
        // "P-256", "P-384", or "P-521"
        namedCurve: namedCurve
      },
      // TODO whether the key is extractable (i.e. can be used in exportKey)
      false,
      // FIXME this can be any combination of "sign" and "verify"
      // or "deriveKey" and "deriveBits" for ECDH
      ["sign", "verify"]
    );

    return {
      pub: keyPair.publicKey.encode(), // FIXME encoding
      priv: keyPair.privateKey.toArray()  // FIXME encoding
    };
  } catch(err) {
    throw new Error(err);
  }
}

async function nodeGenKeyPair(opensslCurve) {
  try {
    var ecdh = nodeCrypto.createECDH(opensslCurve);
    await ecdh.generateKeys();

    return {
      pub: ecdh.getPublicKey().toJSON().data,
      priv: ecdh.getPrivateKey().toJSON().data
    };
  } catch(err) {
    throw new Error(err);
  }
}
