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

export default {
  /** Create signature
   * @param {BN} m message
   * @param {BN} n RSA public modulus
   * @param {BN} e RSA public exponent
   * @param {BN} d RSA private exponent
   * @returns {BN} RSA Signature
   * @async
   */
  sign: async function(m, n, e, d) {
    if (n.cmp(m) <= 0) {
      throw new Error('Message size cannot exceed modulus size');
    }
    const nred = new BN.red(n);
    return m.toRed(nred).redPow(d).toArrayLike(Uint8Array, 'be', n.byteLength());
  },

  /**
   * Verify signature
   * @param {BN} s signature
   * @param {BN} n RSA public modulus
   * @param {BN} e RSA public exponent
   * @returns {BN}
   * @async
   */
  verify: async function(s, n, e) {
    if (n.cmp(s) <= 0) {
      throw new Error('Signature size cannot exceed modulus size');
    }
    const nred = new BN.red(n);
    return s.toRed(nred).redPow(e).toArrayLike(Uint8Array, 'be', n.byteLength());
  },

  /**
   * Encrypt message
   * @param {BN} m message
   * @param {BN} n RSA public modulus
   * @param {BN} e RSA public exponent
   * @returns {BN} RSA Ciphertext
   * @async
   */
  encrypt: async function(m, n, e) {
    if (n.cmp(m) <= 0) {
      throw new Error('Message size cannot exceed modulus size');
    }
    const nred = new BN.red(n);
    return m.toRed(nred).redPow(e).toArrayLike(Uint8Array, 'be', n.byteLength());
  },

  /**
   * Decrypt RSA message
   * @param {BN} m message
   * @param {BN} n RSA public modulus
   * @param {BN} e RSA public exponent
   * @param {BN} d RSA private exponent
   * @param {BN} p RSA private prime p
   * @param {BN} q RSA private prime q
   * @param {BN} u RSA private inverse of prime q
   * @returns {BN} RSA Plaintext
   * @async
   */
  decrypt: async function(m, n, e, d, p, q, u) {
    if (n.cmp(m) <= 0) {
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
      m = m.toRed(nred).redMul(blinder).fromRed();
    }

    const mp = m.toRed(pred).redPow(dp);
    const mq = m.toRed(qred).redPow(dq);
    const t = mq.redSub(mp.fromRed().toRed(qred));
    const h = u.toRed(qred).redMul(t).fromRed();

    let result = h.mul(p).add(mp).toRed(nred);

    if (config.rsa_blinding) {
      result = result.redMul(unblinder);
    }

    return result.toArrayLike(Uint8Array, 'be', n.byteLength());
  },

  /**
   * Generate a new random private key B bits long with public exponent E.
   *
   * When possible, webCrypto is used. Otherwise, primes are generated using
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
    const webCrypto = util.getWebCryptoAll();

    // Native RSA keygen using Web Crypto
    if (webCrypto) {
      let keyPair;
      let keyGenOpt;
      if ((window.crypto && window.crypto.subtle) || window.msCrypto) {
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
      } else if (window.crypto && window.crypto.webkitSubtle) {
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
      key.p = new BN(util.b64_to_Uint8Array(jwk.p));
      key.q = new BN(util.b64_to_Uint8Array(jwk.q));
      key.u = key.p.invm(key.q);
      return key;
    }

    // RSA keygen fallback using 40 iterations of the Miller-Rabin test
    // See https://stackoverflow.com/a/6330138 for justification
    // Also see section C.3 here: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST
    let p = await prime.randomProbablePrime(B - (B >> 1), E, 40);
    let q = await prime.randomProbablePrime(B >> 1, E, 40);

    if (p.cmp(q) < 0) {
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

  prime: prime
};
