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

// Wrapper for a KeyPair of an Elliptic Curve

/**
 * @requires bn.js
 * @requires asn1.js
 * @requires jwk-to-pem
 * @requires crypto/public_key/elliptic/curves
 * @requires crypto/hash
 * @requires util
 * @requires enums
 * @requires config
 * @requires encoding/base64
 * @module crypto/public_key/elliptic/key
 */

'use strict';

import BN from 'bn.js';
import ASN1 from 'asn1.js';
import jwkToPem from 'jwk-to-pem';

import curves from './curves';
import hash from '../../hash';
import util from '../../../util';
import enums from '../../../enums';
import config from '../../../config';
import base64 from '../../../encoding/base64';

const webCrypto = util.getWebCrypto();
const webCurves = curves.webCurves;
const nodeCrypto = util.getNodeCrypto();
const nodeCurves = curves.nodeCurves;

var ECDSASignature = ASN1.define('ECDSASignature', function() {
  this.seq().obj(
    this.key('r').int(),
    this.key('s').int()
  );
});

function KeyPair(curve, options) {
  this.curve = curve;
  this.keyType = curve.curve.type === 'edwards' ? enums.publicKey.eddsa : enums.publicKey.ecdsa;
  this.keyPair = this.curve.keyPair(options);
}

KeyPair.prototype.sign = async function (message, hash_algo) {
  if (typeof message === 'string') {
    message = util.str2Uint8Array(message);
  }
  if (webCrypto && config.use_native && this.curve.web) {
    return webSign(this.curve, hash_algo, message, this.keyPair);
  } else if (nodeCrypto && config.use_native && this.curve.node) {
    return nodeSign(this.curve, hash_algo, message, this.keyPair);
  } else {
    const digest = (typeof hash_algo === 'undefined') ? message : hash.digest(hash_algo, message);
    return this.keyPair.sign(digest);
  }
};

KeyPair.prototype.verify = async function (message, signature, hash_algo) {
  if (typeof message === 'string') {
    message = util.str2Uint8Array(message);
  }
  if (webCrypto && config.use_native && this.curve.web) {
    return webVerify(this.curve, hash_algo, signature, message, this.keyPair.getPublic());
  } else if (nodeCrypto && config.use_native && this.curve.node) {
    return nodeVerify(this.curve, hash_algo, signature, message, this.keyPair.getPublic());
  } else {
    const digest = (typeof hash_algo === 'undefined') ? message : hash.digest(hash_algo, message);
    return this.keyPair.verify(digest, signature);
  }
};

KeyPair.prototype.derive = function (pub) {
  if (this.keyType === enums.publicKey.eddsa) {
    throw new Error('Key can only be used for EdDSA');
  }
  return this.keyPair.derive(pub.keyPair.getPublic());
};

KeyPair.prototype.getPublic = function () {
  var compact = (this.curve.curve.type === 'edwards' || this.curve.curve.type === 'mont');
  return this.keyPair.getPublic('array', compact);
};

KeyPair.prototype.getPrivate = function () {
  if (this.keyType === enums.publicKey.eddsa) {
    return this.keyPair.getSecret();
  } else {
    return this.keyPair.getPrivate().toArray();
  }
};

KeyPair.prototype.isValid = function () {
  if (this.curve.curve.type === 'edwards' || this.curve.curve.type === 'mont') {
    throw new Error('Validation is not Implemented for this curve.');
  }
  return this.keyPair.validate().result;
};

module.exports = {
  KeyPair: KeyPair
};


//////////////////////////
//                      //
//   Helper functions   //
//                      //
//////////////////////////


async function webSign(curve, hash_algo, message, keyPair) {
  var l = curve.payloadSize;
  const key = await webCrypto.importKey(
    "jwk",
    {
      "kty": "EC",
      "crv": webCurves[curve.name],
      "x": base64.encode(new Uint8Array(keyPair.getPublic().getX().toArray('be', l)), true),
      "y": base64.encode(new Uint8Array(keyPair.getPublic().getY().toArray('be', l)), true),
      "d": base64.encode(new Uint8Array(keyPair.getPrivate().toArray('be', l)), true),
      "use": "sig",
      "kid": "ECDSA Private Key"
    },
    {
      "name": "ECDSA",
      "namedCurve": webCurves[curve.name],
      "hash": { name: enums.read(enums.webHash, curve.hash) }
    },
    false,
    ["sign"]
  );

  const signature = new Uint8Array(await webCrypto.sign(
    {
      "name": 'ECDSA',
      "namedCurve": webCurves[curve.name],
      "hash": { name: enums.read(enums.webHash, hash_algo) }
    },
    key,
    message
  ));
  return {
    r: signature.slice(0, l),
    s: signature.slice(l, 2 * l)
  };
}

async function webVerify(curve, hash_algo, {r, s}, message, publicKey) {
  var l = curve.payloadSize;
  r = (r.length === l) ? r : [0].concat(r);
  s = (s.length === l) ? s : [0].concat(s);
  var signature = new Uint8Array(r.concat(s)).buffer;
  const key = await webCrypto.importKey(
    "jwk",
    {
      "kty": "EC",
      "crv": webCurves[curve.name],
      "x": base64.encode(new Uint8Array(publicKey.getX().toArray('be', l)), true),
      "y": base64.encode(new Uint8Array(publicKey.getY().toArray('be', l)), true),
      "use": "sig",
      "kid": "ECDSA Public Key"
    },
    {
      "name": "ECDSA",
      "namedCurve": webCurves[curve.name],
      "hash": { name: enums.read(enums.webHash, curve.hash) }
    },
    false,
    ["verify"]
  );

  return webCrypto.verify(
    {
      "name": 'ECDSA',
      "namedCurve": webCurves[curve.name],
      "hash": { name: enums.read(enums.webHash, hash_algo) }
    },
    key,
    signature,
    message
  );
}


async function nodeSign(curve, hash_algo, message, keyPair) {
  const key = jwkToPem(
    {
      "kty": "EC",
      "crv": webCurves[curve.name],
      "x": base64.encode(new Uint8Array(keyPair.getPublic().getX().toArray())),
      "y": base64.encode(new Uint8Array(keyPair.getPublic().getY().toArray())),
      "d": base64.encode(new Uint8Array(keyPair.getPrivate().toArray())),
      "use": "sig",
      "kid": "ECDSA Private Key"
    },
    { private: true }
  );

  const sign = nodeCrypto.createSign(enums.read(enums.hash, hash_algo));
  sign.write(message);
  sign.end();
  const signature = await ECDSASignature.decode(sign.sign(key), 'der');
  return {
    r: signature.r.toArray(),
    s: signature.s.toArray()
  };
}

async function nodeVerify(curve, hash_algo, {r, s}, message, publicKey) {
  var signature = ECDSASignature.encode({ r: new BN(r), s: new BN(s) }, 'der');
  const key = jwkToPem(
    {
      "kty": "EC",
      "crv": webCurves[curve.name],
      "x": base64.encode(new Uint8Array(publicKey.getX().toArray())),
      "y": base64.encode(new Uint8Array(publicKey.getY().toArray())),
      "use": "sig",
      "kid": "ECDSA Public Key"
    },
    { private: false }
  );

  // FIXME what happens when hash_algo = undefined?
  const verify = nodeCrypto.createVerify(enums.read(enums.hash, hash_algo));
  verify.write(message);
  verify.end();
  const result = await verify.verify(key, signature);
  return result;
}
