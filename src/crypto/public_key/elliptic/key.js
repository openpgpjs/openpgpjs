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
 * @requires crypto/public_key/elliptic/curves
 * @requires crypto/public_key/jsbn
 * @requires crypto/hash
 * @requires util
 * @requires enums
 * @requires encoding/base64
 * @requires jwk-to-pem
 * @requires asn1.js
 * @module crypto/public_key/elliptic/key
 */

import { webCurves, nodeCurves } from './curves';
import BigInteger from '../jsbn';
import hash from '../../hash';
import util from '../../../util';
import enums from '../../../enums';
import base64 from '../../../encoding/base64';

const webCrypto = util.getWebCrypto();
const nodeCrypto = util.getNodeCrypto();

const jwkToPem = nodeCrypto ? require('jwk-to-pem') : undefined;
const ECDSASignature = nodeCrypto ?
      require('asn1.js').define('ECDSASignature', function() {
        this.seq().obj(
          this.key('r').int(),
          this.key('s').int()
        );
      }) : undefined;

export default function KeyPair(curve, options) {
  this.curve = curve;
  this.keyType = curve.curve.type === 'edwards' ? enums.publicKey.eddsa : enums.publicKey.ecdsa;
  this.keyPair = this.curve.keyPair(options);
}

KeyPair.prototype.sign = async function (message, hash_algo) {
  if (webCrypto && this.curve.web) {
    // If browser doesn't support a curve, we'll catch it
    try {
      return webSign(this.curve, hash_algo, message, this.keyPair);
    } catch (err) {
      util.print_debug("Browser did not support signing: " + err.message);
    }
  } else if (nodeCrypto && this.curve.node) {
    return nodeSign(this.curve, hash_algo, message, this.keyPair);
  }
  const digest = (typeof hash_algo === 'undefined') ? message : hash.digest(hash_algo, message);
  return this.keyPair.sign(digest);
};

KeyPair.prototype.verify = async function (message, signature, hash_algo) {
  if (webCrypto && this.curve.web) {
    // If browser doesn't support a curve, we'll catch it
    try {
      return webVerify(this.curve, hash_algo, signature, message, this.keyPair.getPublic());
    } catch (err) {
      util.print_debug("Browser did not support signing: " + err.message);
    }
  } else if (nodeCrypto && this.curve.node) {
    return nodeVerify(this.curve, hash_algo, signature, message, this.keyPair.getPublic());
  }
  const digest = (typeof hash_algo === 'undefined') ? message : hash.digest(hash_algo, message);
  return this.keyPair.verify(digest, signature);
};

KeyPair.prototype.derive = function (pub) {
  if (this.keyType === enums.publicKey.eddsa) {
    throw new Error('Key can only be used for EdDSA');
  }
  return this.keyPair.derive(pub.keyPair.getPublic());
};

KeyPair.prototype.getPublic = function () {
  const compact = (this.curve.curve.type === 'edwards' || this.curve.curve.type === 'mont');
  return this.keyPair.getPublic('array', compact);
};

KeyPair.prototype.getPrivate = function () {
  if (this.keyType === enums.publicKey.eddsa) {
    return this.keyPair.getSecret();
  }
  return this.keyPair.getPrivate().toArray();
};


//////////////////////////
//                      //
//   Helper functions   //
//                      //
//////////////////////////


async function webSign(curve, hash_algo, message, keyPair) {
  const l = curve.payloadSize;
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

async function webVerify(curve, hash_algo, { r, s }, message, publicKey) {
  const l = curve.payloadSize;
  r = Array(l - r.length).fill(0).concat(r);
  s = Array(l - s.length).fill(0).concat(s);
  const signature = new Uint8Array(r.concat(s)).buffer;
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

async function nodeVerify(curve, hash_algo, { r, s }, message, publicKey) {
  const signature = ECDSASignature.encode(
    { r: new BigInteger(util.hexidump(r), 16), s: new BigInteger(util.hexidump(s), 16) }, 'der');
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

  const verify = nodeCrypto.createVerify(enums.read(enums.hash, hash_algo));
  verify.write(message);
  verify.end();
  const result = await verify.verify(key, signature);
  return result;
}
