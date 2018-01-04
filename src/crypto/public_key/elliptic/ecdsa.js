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

// Implementation of ECDSA following RFC6637 for Openpgpjs

/**
 * @requires crypto/public_key/jsbn
 * @requires crypto/public_key/elliptic/curves
 * @module crypto/public_key/elliptic/ecdsa
 */

'use strict';

import BN from 'bn.js';
import ASN1 from 'asn1.js';
import jwkToPem from 'jwk-to-pem';

import curves from './curves.js';
import BigInteger from '../jsbn.js';
import config from '../../../config';
import enums from '../../../enums.js';
import util from '../../../util.js';
import base64 from '../../../encoding/base64.js';

const webCrypto = util.getWebCrypto();
const nodeCrypto = util.getNodeCrypto();

var ECDSASignature = ASN1.define('ECDSASignature', function() {
  this.seq().obj(
    this.key('r').int(),  // FIXME int or BN?
    this.key('s').int()   // FIXME int or BN?
  );
});

/**
 * Sign a message using the provided key
 * @param  {String}      oid        Elliptic curve for the key
 * @param  {enums.hash}  hash_algo  Hash algorithm used to sign
 * @param  {Uint8Array}  m          Message to sign
 * @param  {BigInteger}  d          Private key used to sign
 * @return {{r: BigInteger, s: BigInteger}}  Signature of the message
 */
async function sign(oid, hash_algo, m, d) {
  var signature;
  const curve = curves.get(oid);
  hash_algo = hash_algo ? hash_algo : curve.hash;
  const key = curve.keyFromPrivate(d.toByteArray());
  if (webCrypto && config.use_native && curve.web) {
    signature = await webSign(curve, hash_algo, m, key.keyPair);
  } else if (nodeCrypto && config.use_native && curve.node) {
    signature = await nodeSign(curve, hash_algo, m, key.keyPair);
  } else {
    signature = await key.sign(m, hash_algo);
  }
  return {
    r: new BigInteger(signature.r),
    s: new BigInteger(signature.s)
  };
}

/**
 * Verifies if a signature is valid for a message
 * @param  {String}      oid        Elliptic curve for the key
 * @param  {enums.hash}  hash_algo  Hash algorithm used in the signature
 * @param  {{r: BigInteger, s: BigInteger}}  signature  Signature to verify
 * @param  {Uint8Array}  m          Message to verify
 * @param  {BigInteger}  Q          Public key used to verify the message
 * @return {Boolean}
 */
async function verify(oid, hash_algo, signature, m, Q) {
  var result;
  const curve = curves.get(oid);
  hash_algo = hash_algo ? hash_algo : curve.hash;  // FIXME is this according to the RFC?
  const key = curve.keyFromPublic(Q.toByteArray());
  if (webCrypto && config.use_native && curve.web) {
    result = await webVerify(curve, hash_algo, signature, m, key.keyPair.getPublic());
  } else if (nodeCrypto && config.use_native && curve.node) {
    result = await nodeVerify(curve, hash_algo, signature, m, key.keyPair.getPublic());
  } else {
    result = await key.verify(
      m, {r: signature.r.toByteArray(), s: signature.s.toByteArray()}, hash_algo
    );
  }
  return result;
}

module.exports = {
  sign: sign,
  verify: verify
};


//////////////////////////
//                      //
//   Helper functions   //
//                      //
//////////////////////////


async function webSign(curve, hash_algo, message, keyPair) {
  var l = curve.pointSize;
  if (typeof message === 'string') {
    message = util.str2Uint8Array(message);
  }
  const key = await webCrypto.importKey(
    "jwk",
    {
      "kty": "EC",
      "crv": curve.namedCurve,
      "x": base64.encode(new Uint8Array(keyPair.getPublic().getX().toArray('be', l)), null, 'base64url'),
      "y": base64.encode(new Uint8Array(keyPair.getPublic().getY().toArray('be', l)), null, 'base64url'),
      "d": base64.encode(new Uint8Array(keyPair.getPrivate().toArray('be', l)), null, 'base64url'),
      "use": "sig",
      "kid": "ECDSA Private Key"
    },
    {
      "name": "ECDSA",
      "namedCurve": curve.namedCurve,
      "hash": { name: curve.hashName }
    },
    false,
    ["sign"]
  );

  const signature = new Uint8Array(await webCrypto.sign(
    {
      "name": 'ECDSA',
      "namedCurve": curve.namedCurve,
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

async function webVerify(curve, hash_algo, signature, message, publicKey) {
  var r = signature.r.toByteArray(), s = signature.s.toByteArray(), l = curve.pointSize;
  r = (r.length === l) ? r : [0].concat(r);
  s = (s.length === l) ? s : [0].concat(s);
  signature = new Uint8Array(r.concat(s)).buffer;
  if (typeof message === 'string') {
    message = util.str2Uint8Array(message);
  }
  const key = await webCrypto.importKey(
    "jwk",
    {
      "kty": "EC",
      "crv": curve.namedCurve,
      "x": base64.encode(new Uint8Array(publicKey.getX().toArray('be', l)), null, 'base64url'),
      "y": base64.encode(new Uint8Array(publicKey.getY().toArray('be', l)), null, 'base64url'),
      "use": "sig",
      "kid": "ECDSA Public Key"
    },
    {
      "name": "ECDSA",
      "namedCurve": curve.namedCurve,
      "hash": { name: curve.hashName }
    },
    false,
    ["verify"]
  );

  return webCrypto.verify(
    {
      "name": 'ECDSA',
      "namedCurve": curve.namedCurve,
      "hash": { name: enums.read(enums.webHash, hash_algo) }
    },
    key,
    signature,
    message
  );
}


async function nodeSign(curve, hash_algo, message, keyPair) {
  if (typeof message === 'string') {
    message = util.str2Uint8Array(message);
  }
  const key = jwkToPem(
    {
      "kty": "EC",
      "crv": curve.namedCurve,
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

async function nodeVerify(curve, hash_algo, signature, message, publicKey) {
  signature = ECDSASignature.encode(
    {
      r: new BN(signature.r.toByteArray()),
      s: new BN(signature.s.toByteArray())
    },
    'der');
  if (typeof message === 'string') {
    message = util.str2Uint8Array(message);
  }
  const key = jwkToPem(
    {
      "kty": "EC",
      "crv": curve.namedCurve,
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
