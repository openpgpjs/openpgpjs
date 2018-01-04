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

import asn1 from 'asn1.js';
import jwk2pem from 'jwk-to-pem';

import curves from './curves.js';
import BigInteger from '../jsbn.js';
import config from '../../../config';
import enums from '../../../enums.js';
import util from '../../../util.js';

const webCrypto = util.getWebCrypto();
const nodeCrypto = util.getNodeCrypto();

var ECDSASignature = asn1.define('ecdsa-sig', function() {
  return this.seq().obj(
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
function sign(oid, hash_algo, m, d) {
  var signature;
  const curve = curves.get(oid);
  if (webCrypto && config.use_native && curve.web) {
    signature = webSign(curve, hash_algo, m, d);
  } else if (nodeCrypto && config.use_native && curve.node) {
    signature = nodeSign(curve, hash_algo, m, d);
  } else {
    const key = curve.keyFromPrivate(d.toByteArray());
    signature = key.sign(m, hash_algo);
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
function verify(oid, hash_algo, signature, m, Q) {
  const curve = curves.get(oid);
  if (webCrypto && config.use_native && curve.web) {
    return webVerify(curve, hash_algo, signature, m, Q);
  } else if (nodeCrypto && config.use_native && curve.node) {
    return nodeVerify(curve, hash_algo, signature, m, Q);
  } else {
    const key = curve.keyFromPublic(Q.toByteArray());
    return key.verify(m, {r: signature.r.toByteArray(), s: signature.s.toByteArray()}, hash_algo);
  }
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


async function webSign(curve, hash_algo, m, d) {
  const publicKey = curve.keyFromPrivate(d).getPublic();
  const privateKey = await webCrypto.importKey(
    "jwk",
    {
      "kty": "EC",
      "crv": curve.namedCurve,
      "x": publicKey.getX().toBuffer().base64Slice(),
      "y": publicKey.getY().toBuffer().base64Slice(),
      "d": d.toBuffer().base64Slice(),
      "use": "sig",
      "kid": "ECDSA Private Key"
    },
    {
      "name": "ECDSA",
      "namedCurve": curve.namedCurve,
      "hash": { name: enums.read(enums.hash, hash_algo) }
    },
    false,
    ["sign"]
  );

  try {
    return await webCrypto.sign(
      {
        "name": 'ECDSA',
        "namedCurve": curve.namedCurve,
        "hash": { name: enums.read(enums.hash, hash_algo) }
      },
      privateKey,
      m
    );
  } catch(err) {
    throw new Error(err);
  }
}

async function webVerify(curve, hash_algo, signature, m, Q) {
  const publicKey = await webCrypto.importKey(
    "jwk",
    {
      "kty": "EC",
      "crv": curve.namedCurve,
      "x": Q.getX().toBuffer().base64Slice(),
      "y": Q.getY().toBuffer().base64Slice(),
      "use": "sig",
      "kid": "ECDSA Public Key"
    },
    {
      "name": "ECDSA",
      "namedCurve": curve.namedCurve,
      "hash": { name: enums.read(enums.hash, hash_algo) }
    },
    false,
    ["verify"]
  );

  try {
    return await webCrypto.verify(
      {
        "name": 'ECDSA',
        "namedCurve": curve.namedCurve,
        "hash": { name: enums.read(enums.hash, hash_algo) }
      },
      publicKey,
      signature,
      m
    );
  } catch(err) {
    throw new Error(err);
  }
}


async function nodeSign(curve, hash_algo, m, d) {
  const publicKey = curve.keyFromPrivate(d).getPublic();
  const privateKey = jwk2pem(
    {"kty": "EC",
     "crv": curve.namedCurve,
     "x": publicKey.getX().toBuffer().base64Slice(),
     "y": publicKey.getY().toBuffer().base64Slice(),
     "d": d.toBuffer().base64Slice(),
     "use": "sig",
     "kid": "ECDSA Private Key"},
    {private: true}
  );

  const sign = nodeCrypto.createSign(enums.read(enums.hash, hash_algo));
  sign.write(m);
  sign.end();
  const signature = await sign.sign(privateKey);
  return ECDSASignature.decode(signature, 'der');
}

async function nodeVerify(curve, hash_algo, signature, m, Q) {
  const publicKey = jwk2pem(
    {"kty": "EC",
     "crv": curve.namedCurve,
     "x": Q.getX().toBuffer().base64Slice(),
     "y": Q.getY().toBuffer().base64Slice(),
     "use": "sig",
     "kid": "ECDSA Public Key"},
    {private: false}
  );

  const verify = nodeCrypto.createVerify(enums.read(enums.hash, hash_algo));
  verify.write(m);
  verify.end();
  const result = await verify.verify(publicKey, signature);
  return result;
}
