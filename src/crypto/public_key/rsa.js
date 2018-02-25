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
//
// RSA implementation

/**
 * @requires bn.js
 * @requires asmcrypto.js
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

const two = new BN(2);

// TODO use this is ../../encoding/base64.js and ./elliptic/{key,curve}.js
function b64toBN(base64url) {
  const base64 = base64url.replace(/\-/g, '+').replace(/_/g, '/');
  const hex = util.hexstrdump(atob(base64));
  return new BN(hex, 16);
}

export default {
  /** Create signature
   * @param m message as BN
   * @param n public MPI part as BN
   * @param e public MPI part as BN
   * @param d private MPI part as BN
   * @return BN
   */
  sign: function(m, n, e, d) {
    if (n.cmp(m) <= 0) {
      throw new Error('Data too large.');
    }
    const nred = new BN.red(n);
    return m.toRed(nred).redPow(d).toArrayLike(Uint8Array, 'be', n.byteLength());
  },

  /**
   * Verify signature
   * @param s signature as BN
   * @param n public MPI part as BN
   * @param e public MPI part as BN
   * @return BN
   */
  verify: function(s, n, e) {
    if (n.cmp(s) <= 0) {
      throw new Error('Data too large.');
    }
    const nred = new BN.red(n);
    return s.toRed(nred).redPow(e).toArrayLike(Uint8Array, 'be', n.byteLength());
  },

  /**
   * Encrypt message
   * @param m message as BN
   * @param n public MPI part as BN
   * @param e public MPI part as BN
   * @return BN
   */
  encrypt: function(m, n, e) {
    if (n.cmp(m) <= 0) {
      throw new Error('Data too large.');
    }
    const nred = new BN.red(n);
    return m.toRed(nred).redPow(e).toArrayLike(Uint8Array, 'be', n.byteLength());
  },

  /**
   * Decrypt RSA message
   * @param m message as BN
   * @param n RSA public modulus n as BN
   * @param e RSA public exponent as BN
   * @param d RSA d as BN
   * @param p RSA p as BN
   * @param q RSA q as BN
   * @param u RSA u as BN
   * @return {BN} The decrypted value of the message
   */
  decrypt: function(m, n, e, d, p, q, u) {
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
      unblinder = random.getRandomBN(two, n).toRed(nred);
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
   * Generate a new random private key B bits long with public exponent E
   * @param {Integer} B RSA bit length
   * @param {String} E RSA public exponent in hex
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
        keyPair = await webCrypto.generateKey(keyGenOpt, true, ['sign', 'verify']);
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
      let jwk = await webCrypto.exportKey('jwk', keyPair.privateKey);

      // parse raw ArrayBuffer bytes to jwk/json (WebKit/Safari/IE11 quirk)
      if (jwk instanceof ArrayBuffer) {
        jwk = JSON.parse(String.fromCharCode.apply(null, new Uint8Array(jwk)));
      }

      // map JWK parameters to BN
      key = {};
      key.n = b64toBN(jwk.n);
      key.e = E;
      key.d = b64toBN(jwk.d);
      key.p = b64toBN(jwk.p);
      key.q = b64toBN(jwk.q);
      key.u = key.p.invm(key.q);
      return key;
    }

    while (true) {
      let p = prime.randomProbablePrime(B - (B >> 1), E);
      let q = prime.randomProbablePrime(B >> 1, E);

      if (p.cmp(q) < 0) {
        const t = p;
        p = q;
        q = t;
      }

      const phi = p.subn(1).mul(q.subn(1));
      return {
        n: p.mul(q),
        e: E,
        d: E.invm(phi),
        q: q,
        p: p,
        // dq: d.mod(q.subn(1)),
        // dp: d.mod(p.subn(1)),
        u: p.invm(q)
      };
    }
  }
};
