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
    curveName: 'P-256',
    opensslName: 'prime256v1',
    hashName: 'SHA-256',
    hash: enums.hash.sha256,
    cipher: enums.symmetric.aes128,
    nist: true,
    node: nodeCurves.includes('prime256v1'),
    web: webCurves.includes('P-256')
  },
  p384: {
    oid: util.bin2str([0x2B, 0x81, 0x04, 0x00, 0x22]),
    curveName: 'P-384',
    opensslName: 'secp384r1', // FIXME
    hashName: 'SHA-384',
    hash: enums.hash.sha384,
    cipher: enums.symmetric.aes192,
    nist: true,
    node: nodeCurves.includes('secp384r1'), // FIXME
    web: webCurves.includes('P-384')
  },
  p521: {
    oid: util.bin2str([0x2B, 0x81, 0x04, 0x00, 0x23]),
    curveName: 'P-521',
    opensslName: 'secp521r1', // FIXME
    hashName: 'SHA-512',
    hash: enums.hash.sha512,
    cipher: enums.symmetric.aes256,
    nist: true,
    node: nodeCurves.includes('secp521r1'), // FIXME
    web: webCurves.includes('P-521')
  },
  secp256k1: {
    oid: util.bin2str([0x2B, 0x81, 0x04, 0x00, 0x0A]),
    curveName: 'SECP-256K1',
    opensslName: 'secp256k1',
    hashName: 'SHA-256',
    hash: enums.hash.sha256,
    cipher: enums.symmetric.aes128,
    nist: false,
    node: nodeCurves.includes('secp256k1'),
    web: false // Not supported as of 12/2017
  }
};

function Curve(name, {oid, hash, cipher, curveName, opensslName, hashName, nist, node, web}) {
  this.curve = new EC(name);
  // webCurve doesn't really have a standalone curve type
  if (nodeCrypto && config.use_native && curves[name].node) {
    this.nodeCurve = new nodeCrypto.createECDH(curve.opensslName);
  }
  this.name = name;
  this.oid = oid;
  this.hash = hash;
  this.cipher = cipher;
  this.curveName= curveName;
  this.opensslName = opensslName;
  this.hashName = hashName;
  this.nist = nist;
  this.node = node;
  this.web = web;
}

Curve.prototype.keyFromPrivate = function (priv) {
  return new KeyPair(this.curve, {priv: priv, nodeCurve: this.nodeCurve});
};

Curve.prototype.keyFromPublic = function (pub) {
  return new KeyPair(this.curve, {pub: pub, nodeCurve: this.nodeCurve});
};

Curve.prototype.genKeyPair = function () {
  if (webCrypto && config.use_native && this.web) {
    var keyPair = webGenKeyPair(this.curveName);
  } else if (nodeCrypto && config.use_native && this.node) {
    var keyPair = nodeGenKeyPair(this.opensslName);
  } else {
    var r = this.curve.genKeyPair();
    var keyPair = {
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

function generate(curve) {
  return new Promise(function (resolve) {
    curve = get(curve);
    var keyPair = curve.genKeyPair();
    resolve({
      oid: curve.oid,
      Q: new BigInteger(keyPair.getPublic()),
      d: new BigInteger(keyPair.getPrivate()),
      hash: curve.hash,
      cipher: curve.cipher
    });
  });
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


function webGenKeyPair(curveName) {
  return webCrypto.generateKey(
    {
      name: "ECDSA",
//      FIXME 
//      name: "ECDH",
      namedCurve: curveName, // "P-256", "P-384", or "P-521"
    },
//   FIXME
    false, // whether the key is extractable (i.e. can be used in exportKey)
    ["sign", "verify"] // can be any combination of "sign" and "verify"
//    FIXME 
//    ["deriveKey", "deriveBits"] // can be any combination of "deriveKey" and "deriveBits"
  ).then(function(key){
    return {
      pub: key.publicKey.encode(), // FIXME encoding
      priv: key.privateKey.toArray()  // FIXME encoding
    };
  }).catch(function(err){
    throw new Error(err);
  });
}

function nodeGenKeyPair(opensslName) {
  // TODO turn this into a promise
  var ecc = nodeCrypto.createECDH(opensslName);
  var key = ecc.generateKeys();
  return {
    pub: ecc.getPrivateKey().toJSON().data,
    priv: ecc.getPublicKey().toJSON().data
  };
}
