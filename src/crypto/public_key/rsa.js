// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
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
 * @fileoverview RSA implementation
 * @requires bn.js
 * @requires crypto/public_key/prime
 * @requires crypto/random
 * @requires config
 * @requires util
 * @module crypto/public_key/rsa
 */

import BN from 'bn.js';
import prime from './prime';
import random from '../random';
import config from '../../config';
import util from '../../util';
import pkcs1 from '../pkcs1';
import enums from '../../enums';
import type_mpi from '../../type/mpi';

const webCrypto = util.getWebCrypto();
const nodeCrypto = util.getNodeCrypto();
const asn1 = nodeCrypto ? require('asn1.js') : undefined;

// Helper for IE11 KeyOperation objects
function promisifyIE11Op(keyObj, err) {
  if (typeof keyObj.then !== 'function') { // IE11 KeyOperation
    return new Promise(function(resolve, reject) {
      keyObj.onerror = function () {
        reject(new Error(err));
      };
      keyObj.oncomplete = function (e) {
        resolve(e.target.result);
      };
    });
  }
  return keyObj;
}

/* eslint-disable no-invalid-this */
const RSAPrivateKey = util.detectNode() ? asn1.define('RSAPrivateKey', function () {
  this.seq().obj( // used for native NodeJS crypto
    this.key('version').int(), // 0
    this.key('modulus').int(), // n
    this.key('publicExponent').int(), // e
    this.key('privateExponent').int(), // d
    this.key('prime1').int(), // p
    this.key('prime2').int(), // q
    this.key('exponent1').int(), // dp
    this.key('exponent2').int(), // dq
    this.key('coefficient').int() // u
  );
}) : undefined;

const RSAPublicKey = util.detectNode() ? asn1.define('RSAPubliceKey', function () {
  this.seq().obj( // used for native NodeJS crypto
    this.key('modulus').int(), // n
    this.key('publicExponent').int(), // e
  );
}) : undefined;
/* eslint-enable no-invalid-this */

export default {
  /** Create signature
   * @param {module:enums.hash} hash_algo Hash algorithm
   * @param {Uint8Array} data message
   * @param {Uint8Array} n RSA public modulus
   * @param {Uint8Array} e RSA public exponent
   * @param {Uint8Array} d RSA private exponent
   * @param {Uint8Array} p RSA private prime p
   * @param {Uint8Array} q RSA private prime q
   * @param {Uint8Array} u RSA private coefficient
   * @param {Uint8Array} hashed hashed message
   * @returns {Uint8Array} RSA Signature
   * @async
   */
  sign: async function(hash_algo, data, n, e, d, p, q, u, hashed) {
    if (data && !util.isStream(data)) {
      if (util.getWebCrypto()) {
        try {
          return await this.webSign(enums.read(enums.webHash, hash_algo), data, n, e, d, p, q, u);
        } catch (err) {
          util.print_debug_error(err);
        }
      } else if (util.getNodeCrypto()) {
        return this.nodeSign(hash_algo, data, n, e, d, p, q, u);
      }
    }
    return this.bnSign(hash_algo, n, d, hashed);
  },

  /**
   * Verify signature
   * @param {module:enums.hash} hash_algo Hash algorithm
   * @param {Uint8Array} data message
   * @param {Uint8Array} s signature
   * @param {Uint8Array} n RSA public modulus
   * @param {Uint8Array} e RSA public exponent
   * @param {Uint8Array} hashed  hashed message
   * @returns {Boolean}
   * @async
   */
  verify: async function(hash_algo, data, s, n, e, hashed) {
    if (data && !util.isStream(data)) {
      if (util.getWebCrypto()) {
        try {
          return await this.webVerify(enums.read(enums.webHash, hash_algo), data, s, n, e);
        } catch (err) {
          util.print_debug_error(err);
        }
      } else if (util.getNodeCrypto()) {
        return this.nodeVerify(hash_algo, data, s, n, e);
      }
    }
    return this.bnVerify(hash_algo, s, n, e, hashed);
  },

  /**
   * Encrypt message
   * @param {Uint8Array} data message
   * @param {Uint8Array} n RSA public modulus
   * @param {Uint8Array} e RSA public exponent
   * @returns {Uint8Array} RSA Ciphertext
   * @async
   */
  encrypt: async function(data, n, e) {
    if (util.getNodeCrypto()) {
      return this.nodeEncrypt(data, n, e);
    }
    return this.bnEncrypt(data, n, e);
  },

  /**
   * Decrypt RSA message
   * @param {Uint8Array} m message
   * @param {Uint8Array} n RSA public modulus
   * @param {Uint8Array} e RSA public exponent
   * @param {Uint8Array} d RSA private exponent
   * @param {Uint8Array} p RSA private prime p
   * @param {Uint8Array} q RSA private prime q
   * @param {Uint8Array} u RSA private coefficient
   * @returns {String} RSA Plaintext
   * @async
   */
  decrypt: async function(data, n, e, d, p, q, u) {
    if (util.getNodeCrypto()) {
      return this.nodeDecrypt(data, n, e, d, p, q, u);
    }
    return this.bnDecrypt(data, n, e, d, p, q, u);
  },

  /**
   * Generate a new random private key B bits long with public exponent E.
   *
   * When possible, webCrypto or nodeCrypto is used. Otherwise, primes are generated using
   * 40 rounds of the Miller-Rabin probabilistic random prime generation algorithm.
   * @see module:crypto/public_key/prime
   * @param {Integer} B RSA bit length
   * @param {String}  E RSA public exponent in hex string
   * @returns {{n: BN, e: BN, d: BN,
   *            p: BN, q: BN, u: BN}} RSA public modulus, RSA public exponent, RSA private exponent,
   *                                  RSA private prime p, RSA private prime q, u = q ** -1 mod p
   * @async
   */
  generate: async function(B, E) {
    let key;
    E = new BN(E, 16);

    // Native RSA keygen using Web Crypto
    if (util.getWebCrypto()) {
      let keyPair;
      let keyGenOpt;
      if ((global.crypto && global.crypto.subtle) || global.msCrypto) {
        // current standard spec
        keyGenOpt = {
          name: 'RSASSA-PKCS1-v1_5',
          modulusLength: B, // the specified keysize in bits
          publicExponent: E.toArrayLike(Uint8Array), // take three bytes (max 65537) for exponent
          hash: {
            name: 'SHA-1' // not required for actual RSA keys, but for crypto api 'sign' and 'verify'
          }
        };
        keyPair = webCrypto.generateKey(keyGenOpt, true, ['sign', 'verify']);
        keyPair = await promisifyIE11Op(keyPair, 'Error generating RSA key pair.');
      } else if (global.crypto && global.crypto.webkitSubtle) {
        // outdated spec implemented by old Webkit
        keyGenOpt = {
          name: 'RSA-OAEP',
          modulusLength: B, // the specified keysize in bits
          publicExponent: E.toArrayLike(Uint8Array), // take three bytes (max 65537) for exponent
          hash: {
            name: 'SHA-1' // not required for actual RSA keys, but for crypto api 'sign' and 'verify'
          }
        };
        keyPair = await webCrypto.generateKey(keyGenOpt, true, ['encrypt', 'decrypt']);
      } else {
        throw new Error('Unknown WebCrypto implementation');
      }

      // export the generated keys as JsonWebKey (JWK)
      // https://tools.ietf.org/html/draft-ietf-jose-json-web-key-33
      let jwk = webCrypto.exportKey('jwk', keyPair.privateKey);
      jwk = await promisifyIE11Op(jwk, 'Error exporting RSA key pair.');

      // parse raw ArrayBuffer bytes to jwk/json (WebKit/Safari/IE11 quirk)
      if (jwk instanceof ArrayBuffer) {
        jwk = JSON.parse(String.fromCharCode.apply(null, new Uint8Array(jwk)));
      }
      // map JWK parameters to BN
      key = {};
      key.n = new BN(util.b64_to_Uint8Array(jwk.n));
      key.e = E;
      key.d = new BN(util.b64_to_Uint8Array(jwk.d));
      // switch p and q
      key.p = new BN(util.b64_to_Uint8Array(jwk.q));
      key.q = new BN(util.b64_to_Uint8Array(jwk.p));
      // Since p and q are switched in places, we could keep u
      key.u = new BN(util.b64_to_Uint8Array(jwk.qi));
      return key;
    } else if (util.getNodeCrypto() && nodeCrypto.generateKeyPair && RSAPrivateKey) {
      const opts = {
        modulusLength: Number(B.toString(10)),
        publicExponent: Number(E.toString(10)),
        publicKeyEncoding: { type: 'pkcs1', format: 'der' },
        privateKeyEncoding: { type: 'pkcs1', format: 'der' }
      };
      const prv = await new Promise((resolve, reject) => nodeCrypto.generateKeyPair('rsa', opts, (err, _, der) => {
        if (err) {
          reject(err);
        } else {
          resolve(RSAPrivateKey.decode(der, 'der'));
        }
      }));
      /**  PGP spec differs from DER spec, DER: `(inverse of q) mod p`, PGP: `(inverse of p) mod q`.
       * @link https://tools.ietf.org/html/rfc3447#section-3.2
       * @link https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-08#section-5.6.1
       */
      return {
        n: prv.modulus,
        e: prv.publicExponent,
        d: prv.privateExponent,
        // switch p and q
        p: prv.prime2,
        q: prv.prime1,
        // Since p and q are switched in places, we could keep u
        u: prv.coefficient // PGP type of u
      };
    }

    // RSA keygen fallback using 40 iterations of the Miller-Rabin test
    // See https://stackoverflow.com/a/6330138 for justification
    // Also see section C.3 here: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST
    let q = await prime.randomProbablePrime(B - (B >> 1), E, 40);
    let p = await prime.randomProbablePrime(B >> 1, E, 40);

    if (q.cmp(p) < 0) {
      [p, q] = [q, p];
    }

    const phi = p.subn(1).mul(q.subn(1));
    return {
      n: p.mul(q),
      e: E,
      d: E.invm(phi),
      p: p,
      q: q,
      // dp: d.mod(p.subn(1)),
      // dq: d.mod(q.subn(1)),
      u: p.invm(q)
    };
  },

  /**
   * Validate RSA parameters
   * @param {Uint8Array}         n RSA public modulus
   * @param {Uint8Array}         e RSA public exponent
   * @param {Uint8Array}         d RSA private exponent
   * @param {Uint8Array}         p RSA private prime p
   * @param {Uint8Array}         q RSA private prime q
   * @param {Uint8Array}         u RSA inverse of p w.r.t. q
   * @returns {Promise<Boolean>} whether params are valid
   * @async
   */
  validateParams: async function (n, e, d, p, q, u) {
    n = new BN(n);
    p = new BN(p);
    q = new BN(q);

    // expect pq = n
    if (!p.mul(q).eq(n)) {
      return false;
    }

    const one = new BN(1);
    const two = new BN(2);
    // expect p*u = 1 mod q
    u = new BN(u);
    if (!p.mul(u).umod(q).eq(one)) {
      return false;
    }

    e = new BN(e);
    d = new BN(d);
    /**
     * In RSA pkcs#1 the exponents (d, e) are inverses modulo lcm(p-1, q-1)
     * We check that [de = 1 mod (p-1)] and [de = 1 mod (q-1)]
     * By CRT on coprime factors of (p-1, q-1) it follows that [de = 1 mod lcm(p-1, q-1)]
     *
     * We blind the multiplication with r, and check that rde = r mod lcm(p-1, q-1)
     */
    const r = await random.getRandomBN(two, two.shln(n.bitLength() / 3)); // r in [ 2, 2^{|n|/3} ) < p and q
    const rde = r.mul(d).mul(e);

    const areInverses = rde.umod(p.sub(one)).eq(r) && rde.umod(q.sub(one)).eq(r);
    if (!areInverses) {
      return false;
    }

    return true;
  },

  bnSign: async function (hash_algo, n, d, hashed) {
    n = new BN(n);
    const m = new BN(await pkcs1.emsa.encode(hash_algo, hashed, n.byteLength()), 16);
    d = new BN(d);
    if (n.cmp(m) <= 0) {
      throw new Error('Message size cannot exceed modulus size');
    }
    const nred = new BN.red(n);
    return m.toRed(nred).redPow(d).toArrayLike(Uint8Array, 'be', n.byteLength());
  },

  webSign: async function (hash_name, data, n, e, d, p, q, u) {
    /** OpenPGP keys require that p < q, and Safari Web Crypto requires that p > q.
     * We swap them in privateToJwk, so it usually works out, but nevertheless,
     * not all OpenPGP keys are compatible with this requirement.
     * OpenPGP.js used to generate RSA keys the wrong way around (p > q), and still
     * does if the underlying Web Crypto does so (e.g. old MS Edge 50% of the time).
     */
    const jwk = privateToJwk(n, e, d, p, q, u);
    const algo = {
      name: "RSASSA-PKCS1-v1_5",
      hash: { name: hash_name }
    };
    const key = await webCrypto.importKey("jwk", jwk, algo, false, ["sign"]);
    // add hash field for ms edge support
    return new Uint8Array(await webCrypto.sign({ "name": "RSASSA-PKCS1-v1_5", "hash": hash_name }, key, data));
  },

  nodeSign: async function (hash_algo, data, n, e, d, p, q, u) {
    const pBNum = new BN(p);
    const qBNum = new BN(q);
    const dBNum = new BN(d);
    const dq = dBNum.mod(qBNum.subn(1)); // d mod (q-1)
    const dp = dBNum.mod(pBNum.subn(1)); // d mod (p-1)
    const sign = nodeCrypto.createSign(enums.read(enums.hash, hash_algo));
    sign.write(data);
    sign.end();
    const keyObject = {
      version: 0,
      modulus: new BN(n),
      publicExponent: new BN(e),
      privateExponent: new BN(d),
      // switch p and q
      prime1: new BN(q),
      prime2: new BN(p),
      // switch dp and dq
      exponent1: dq,
      exponent2: dp,
      coefficient: new BN(u)
    };
    if (typeof nodeCrypto.createPrivateKey !== 'undefined') { //from version 11.6.0 Node supports der encoded key objects
      const der = RSAPrivateKey.encode(keyObject, 'der');
      return new Uint8Array(sign.sign({ key: der, format: 'der', type: 'pkcs1' }));
    }
    const pem = RSAPrivateKey.encode(keyObject, 'pem', {
      label: 'RSA PRIVATE KEY'
    });
    return new Uint8Array(sign.sign(pem));
  },

  bnVerify: async function (hash_algo, s, n, e, hashed) {
    n = new BN(n);
    s = new BN(s);
    e = new BN(e);
    if (n.cmp(s) <= 0) {
      throw new Error('Signature size cannot exceed modulus size');
    }
    const nred = new BN.red(n);
    const EM1 = s.toRed(nred).redPow(e).toArrayLike(Uint8Array, 'be', n.byteLength());
    const EM2 = await pkcs1.emsa.encode(hash_algo, hashed, n.byteLength());
    return util.Uint8Array_to_hex(EM1) === EM2;
  },

  webVerify: async function (hash_name, data, s, n, e) {
    const jwk = publicToJwk(n, e);
    const key = await webCrypto.importKey("jwk", jwk, {
      name: "RSASSA-PKCS1-v1_5",
      hash: { name:  hash_name }
    }, false, ["verify"]);
    // add hash field for ms edge support
    return webCrypto.verify({ "name": "RSASSA-PKCS1-v1_5", "hash": hash_name }, key, s, data);
  },

  nodeVerify: async function (hash_algo, data, s, n, e) {
    const verify = nodeCrypto.createVerify(enums.read(enums.hash, hash_algo));
    verify.write(data);
    verify.end();
    const keyObject = {
      modulus: new BN(n),
      publicExponent: new BN(e)
    };
    let key;
    if (typeof nodeCrypto.createPrivateKey !== 'undefined') { //from version 11.6.0 Node supports der encoded key objects
      const der = RSAPublicKey.encode(keyObject, 'der');
      key = { key: der, format: 'der', type: 'pkcs1' };
    } else {
      key = RSAPublicKey.encode(keyObject, 'pem', {
        label: 'RSA PUBLIC KEY'
      });
    }
    try {
      return await verify.verify(key, s);
    } catch (err) {
      return false;
    }
  },

  nodeEncrypt: async function (data, n, e) {
    const keyObject = {
      modulus: new BN(n),
      publicExponent: new BN(e)
    };
    let key;
    if (typeof nodeCrypto.createPrivateKey !== 'undefined') {
      const der = RSAPublicKey.encode(keyObject, 'der');
      key = { key: der, format: 'der', type: 'pkcs1', padding: nodeCrypto.constants.RSA_PKCS1_PADDING };
    } else {
      const pem = RSAPublicKey.encode(keyObject, 'pem', {
        label: 'RSA PUBLIC KEY'
      });
      key = { key: pem, padding: nodeCrypto.constants.RSA_PKCS1_PADDING };
    }
    return new Uint8Array(nodeCrypto.publicEncrypt(key, data));
  },

  bnEncrypt: async function (data, n, e) {
    n = new BN(n);
    data = new type_mpi(await pkcs1.eme.encode(util.Uint8Array_to_str(data), n.byteLength()));
    data = data.toBN();
    e = new BN(e);
    if (n.cmp(data) <= 0) {
      throw new Error('Message size cannot exceed modulus size');
    }
    const nred = new BN.red(n);
    return data.toRed(nred).redPow(e).toArrayLike(Uint8Array, 'be', n.byteLength());
  },

  nodeDecrypt: function (data, n, e, d, p, q, u) {
    const pBNum = new BN(p);
    const qBNum = new BN(q);
    const dBNum = new BN(d);
    const dq = dBNum.mod(qBNum.subn(1)); // d mod (q-1)
    const dp = dBNum.mod(pBNum.subn(1)); // d mod (p-1)
    const keyObject = {
      version: 0,
      modulus: new BN(n),
      publicExponent: new BN(e),
      privateExponent: new BN(d),
      // switch p and q
      prime1: new BN(q),
      prime2: new BN(p),
      // switch dp and dq
      exponent1: dq,
      exponent2: dp,
      coefficient: new BN(u)
    };
    let key;
    if (typeof nodeCrypto.createPrivateKey !== 'undefined') {
      const der = RSAPrivateKey.encode(keyObject, 'der');
      key = { key: der, format: 'der' , type: 'pkcs1', padding: nodeCrypto.constants.RSA_PKCS1_PADDING };
    } else {
      const pem = RSAPrivateKey.encode(keyObject, 'pem', {
        label: 'RSA PRIVATE KEY'
      });
      key = { key: pem, padding: nodeCrypto.constants.RSA_PKCS1_PADDING };
    }
    return util.Uint8Array_to_str(nodeCrypto.privateDecrypt(key, data));
  },

  bnDecrypt: async function(data, n, e, d, p, q, u) {
    data = new BN(data);
    n = new BN(n);
    e = new BN(e);
    d = new BN(d);
    p = new BN(p);
    q = new BN(q);
    u = new BN(u);
    if (n.cmp(data) <= 0) {
      throw new Error('Data too large.');
    }
    const dq = d.mod(q.subn(1)); // d mod (q-1)
    const dp = d.mod(p.subn(1)); // d mod (p-1)
    const pred = new BN.red(p);
    const qred = new BN.red(q);
    const nred = new BN.red(n);

    let blinder;
    let unblinder;
    if (config.rsa_blinding) {
      unblinder = (await random.getRandomBN(new BN(2), n)).toRed(nred);
      blinder = unblinder.redInvm().redPow(e);
      data = data.toRed(nred).redMul(blinder).fromRed();
    }

    const mp = data.toRed(pred).redPow(dp);
    const mq = data.toRed(qred).redPow(dq);
    const t = mq.redSub(mp.fromRed().toRed(qred));
    const h = u.toRed(qred).redMul(t).fromRed();

    let result = h.mul(p).add(mp).toRed(nred);

    if (config.rsa_blinding) {
      result = result.redMul(unblinder);
    }

    return pkcs1.eme.decode((new type_mpi(result)).toString());
  },

  prime: prime
};

/** Convert Openpgp private key params to jwk key according to
 * @link https://tools.ietf.org/html/rfc7517
 * @param {String} hash_algo
 * @param {Uint8Array} n
 * @param {Uint8Array} e
 * @param {Uint8Array} d
 * @param {Uint8Array} p
 * @param {Uint8Array} q
 * @param {Uint8Array} u
 */
function privateToJwk(n, e, d, p, q, u) {
  const pBNum = new BN(p);
  const qBNum = new BN(q);
  const dBNum = new BN(d);

  let dq = dBNum.mod(qBNum.subn(1)); // d mod (q-1)
  let dp = dBNum.mod(pBNum.subn(1)); // d mod (p-1)
  dp = dp.toArrayLike(Uint8Array);
  dq = dq.toArrayLike(Uint8Array);
  return {
    kty: 'RSA',
    n: util.Uint8Array_to_b64(n, true),
    e: util.Uint8Array_to_b64(e, true),
    d: util.Uint8Array_to_b64(d, true),
    // switch p and q
    p: util.Uint8Array_to_b64(q, true),
    q: util.Uint8Array_to_b64(p, true),
    // switch dp and dq
    dp: util.Uint8Array_to_b64(dq, true),
    dq: util.Uint8Array_to_b64(dp, true),
    qi: util.Uint8Array_to_b64(u, true),
    ext: true
  };
}

/** Convert Openpgp key public params to jwk key according to
 * @link https://tools.ietf.org/html/rfc7517
 * @param {String} hash_algo
 * @param {Uint8Array} n
 * @param {Uint8Array} e
 */
function publicToJwk(n, e) {
  return {
    kty: 'RSA',
    n: util.Uint8Array_to_b64(n, true),
    e: util.Uint8Array_to_b64(e, true),
    ext: true
  };
}
