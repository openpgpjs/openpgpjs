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
import enums from '../../../enums.js';
import util from '../../../util.js';

const curves = {
  p256: {
    oid: util.bin2str([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]),
    curveName: 'P-256',
    hashName: 'SHA-256',
    hash: enums.hash.sha256,
    cipher: enums.symmetric.aes128,
    nist: true
  },
  p384: {
    oid: util.bin2str([0x2B, 0x81, 0x04, 0x00, 0x22]),
    curveName: 'P-384',
    hashName: 'SHA-384',
    hash: enums.hash.sha384,
    cipher: enums.symmetric.aes192,
    nist: true
  },
  p521: {
    oid: util.bin2str([0x2B, 0x81, 0x04, 0x00, 0x23]),
    curveName: 'P-521',
    hashName: 'SHA-512',
    hash: enums.hash.sha512,
    cipher: enums.symmetric.aes256,
    nist: true
  },
  secp256k1: {
    oid: util.bin2str([0x2B, 0x81, 0x04, 0x00, 0x0A]),
    curveName: 'SECP-256K1',
    hashName: 'SHA-256',
    hash: enums.hash.sha256,
    cipher: enums.symmetric.aes128,
    nist: false
  }
};

function Curve(name, {oid, hash, cipher, curveName, hashName, nist}) {
  this.curve = new EC(name);
  this.name = name;
  this.oid = oid;
  this.hash = hash;
  this.cipher = cipher;
  this.curveName= curveName;
  this.hashName = hashName;
  this.nist = nist;
}

Curve.prototype.keyFromPrivate = function (priv) {
  return new KeyPair(this.curve, {priv: priv});
};

Curve.prototype.keyFromPublic = function (pub) {
  return new KeyPair(this.curve, {pub: pub});
};

Curve.prototype.genKeyPair = function () {
  var r = this.curve.genKeyPair();
  return new KeyPair(this.curve, {
    pub: r.getPublic().encode(),
    priv: r.getPrivate().toArray()
  });
};


function get(oid_or_name) {
  for (var name in curves) {
    if (curves[name].oid === oid_or_name || name === oid_or_name) {
      return new Curve(name, {
        oid: curves[name].oid,
        hash: curves[name].hash,
        cipher: curves[name].cipher,
        curveName: curves[name].curveName,
        hashName: curves[name].hashName,
        nist: curves[name].nist
      });
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
