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
 * @fileoverview Implementation of ECDSA following RFC6637 for Openpgpjs
 * @requires bn.js
 * @requires web-stream-tools
 * @requires enums
 * @requires util
 * @requires crypto/public_key/elliptic/curves
 * @module crypto/public_key/elliptic/ecdsa
 */

import BN from 'bn.js';
import stream from 'web-stream-tools';
import enums from '../../../enums';
import util from '../../../util';
import Curve, { webCurves } from './curves';

const webCrypto = util.getWebCrypto();
const nodeCrypto = util.getNodeCrypto();

/**
 * Sign a message using the provided key
 * @param  {module:type/oid}   oid          Elliptic curve object identifier
 * @param  {module:enums.hash} hash_algo    Hash algorithm used to sign
 * @param  {Uint8Array}        message      Message to sign
 * @param  {Uint8Array}        privateKey   Private key used to sign the message
 * @param  {Uint8Array}        hashed       The hashed message
 * @returns {{r: Uint8Array,
 *            s: Uint8Array}}               Signature of the message
 * @async
 */
async function sign(oid, hash_algo, message, privateKey, hashed) {
  const curve = new Curve(oid);
  const key = curve.keyFromPrivate(privateKey);
  let signature;
  if (message && !message.locked) {
    message = await stream.readToEnd(message);
    if (key.curve.web && util.getWebCrypto()) {
      // If browser doesn't support a curve, we'll catch it
      try {
        // need to await to make sure browser succeeds
        const signature = await webSign(key.curve, hash_algo, message, key.keyPair);
        return signature;
      } catch (err) {
        util.print_debug("Browser did not support signing: " + err.message);
      }
    } else if (key.curve.node && util.getNodeCrypto()) {
      signature = await nodeSign(key.curve, hash_algo, message, key.keyPair);
    }
  }
  if (!signature) {
    signature = key.keyPair.sign(hashed);
  }
  return {
    r: signature.r.toArrayLike(Uint8Array),
    s: signature.s.toArrayLike(Uint8Array)
  };
}

/**
 * Verifies if a signature is valid for a message
 * @param  {module:type/oid}   oid       Elliptic curve object identifier
 * @param  {module:enums.hash} hash_algo Hash algorithm used in the signature
 * @param  {{r: Uint8Array,
             s: Uint8Array}}   signature Signature to verify
 * @param  {Uint8Array}        message   Message to verify
 * @param  {Uint8Array}        publicKey Public key used to verify the message
 * @param  {Uint8Array}        hashed    The hashed message
 * @returns {Boolean}
 * @async
 */
async function verify(oid, hash_algo, signature, message, publicKey, hashed) {
  const curve = new Curve(oid);
  const key = curve.keyFromPublic(publicKey);
  if (message && !message.locked) {
    message = await stream.readToEnd(message);
    if (key.curve.web && util.getWebCrypto()) {
      // If browser doesn't support a curve, we'll catch it
      try {
        // need to await to make sure browser succeeds
        const result = await webVerify(key.curve, hash_algo, signature, message, key.keyPair.getPublic());
        return result;
      } catch (err) {
        util.print_debug("Browser did not support signing: " + err.message);
      }
    } else if (key.curve.node && util.getNodeCrypto()) {
      return nodeVerify(key.curve, hash_algo, signature, message, key.keyPair.getPublic());
    }
  }
  const digest = (typeof hash_algo === 'undefined') ? message : hashed;
  return key.keyPair.verify(digest, signature);
}

export default { sign, verify };


//////////////////////////
//                      //
//   Helper functions   //
//                      //
//////////////////////////


async function webSign(curve, hash_algo, message, keyPair) {
  const len = curve.payloadSize;
  const key = await webCrypto.importKey(
    "jwk",
    {
      "kty": "EC",
      "crv": webCurves[curve.name],
      "x": util.Uint8Array_to_b64(new Uint8Array(keyPair.getPublic().getX().toArray('be', len)), true),
      "y": util.Uint8Array_to_b64(new Uint8Array(keyPair.getPublic().getY().toArray('be', len)), true),
      "d": util.Uint8Array_to_b64(new Uint8Array(keyPair.getPrivate().toArray('be', len)), true),
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
    r: signature.slice(0, len),
    s: signature.slice(len, len << 1)
  };
}

async function webVerify(curve, hash_algo, { r, s }, message, publicKey) {
  const len = curve.payloadSize;
  const key = await webCrypto.importKey(
    "jwk",
    {
      "kty": "EC",
      "crv": webCurves[curve.name],
      "x": util.Uint8Array_to_b64(new Uint8Array(publicKey.getX().toArray('be', len)), true),
      "y": util.Uint8Array_to_b64(new Uint8Array(publicKey.getY().toArray('be', len)), true),
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

  const signature = util.concatUint8Array([
    new Uint8Array(len - r.length), r,
    new Uint8Array(len - s.length), s
  ]).buffer;

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
  const sign = nodeCrypto.createSign(enums.read(enums.hash, hash_algo));
  sign.write(message);
  sign.end();

  const key = ECPrivateKey.encode({
    version: 1,
    parameters: curve.oid,
    privateKey: keyPair.getPrivate().toArray(),
    publicKey: { unused: 0, data: keyPair.getPublic().encode() }
  }, 'pem', {
    label: 'EC PRIVATE KEY'
  });

  return ECDSASignature.decode(sign.sign(key), 'der');
}

async function nodeVerify(curve, hash_algo, { r, s }, message, publicKey) {
  const verify = nodeCrypto.createVerify(enums.read(enums.hash, hash_algo));
  verify.write(message);
  verify.end();

  const key = SubjectPublicKeyInfo.encode({
    algorithm: {
      algorithm: [1, 2, 840, 10045, 2, 1],
      parameters: curve.oid
    },
    subjectPublicKey: { unused: 0, data: publicKey.encode() }
  }, 'pem', {
    label: 'PUBLIC KEY'
  });

  const signature = ECDSASignature.encode({
    r: new BN(r), s: new BN(s)
  }, 'der');

  try {
    return verify.verify(key, signature);
  } catch (err) {
    return false;
  }
}

// Originally written by Owen Smith https://github.com/omsmith
// Adapted on Feb 2018 from https://github.com/Brightspace/node-jwk-to-pem/

/* eslint-disable no-invalid-this */

const asn1 = nodeCrypto ? require('asn1.js') : undefined;

const ECDSASignature = nodeCrypto ?
  asn1.define('ECDSASignature', function() {
    this.seq().obj(
      this.key('r').int(),
      this.key('s').int()
    );
  }) : undefined;

const ECPrivateKey = nodeCrypto ?
  asn1.define('ECPrivateKey', function() {
    this.seq().obj(
      this.key('version').int(),
      this.key('privateKey').octstr(),
      this.key('parameters').explicit(0).optional().any(),
      this.key('publicKey').explicit(1).optional().bitstr()
    );
  }) : undefined;

const AlgorithmIdentifier = nodeCrypto ?
  asn1.define('AlgorithmIdentifier', function() {
    this.seq().obj(
      this.key('algorithm').objid(),
      this.key('parameters').optional().any()
    );
  }) : undefined;

const SubjectPublicKeyInfo = nodeCrypto ?
  asn1.define('SubjectPublicKeyInfo', function() {
    this.seq().obj(
      this.key('algorithm').use(AlgorithmIdentifier),
      this.key('subjectPublicKey').bitstr()
    );
  }) : undefined;
