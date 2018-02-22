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
 * @requires crypto/random
 * @requires config
 * @requires util
 * @module crypto/public_key/rsa
 */


import BN from 'bn.js';
import { RSA } from 'asmcrypto.js/src/rsa/exports-keygen';
import { RSA_RAW } from 'asmcrypto.js/src/rsa/exports-raw';
import { random as asmcrypto_random } from 'asmcrypto.js/src/random/exports';
import random from '../random';
import config from '../../config';
import util from '../../util';

const two = new BN(2);
const zero = new BN(0);

export default {
  /** Create signature
   * @param m message as BN
   * @param n public MPI part as BN
   * @param e public MPI part as BN
   * @param d private MPI part as BN
   * @return BN
   */
  sign: function(m, n, e, d) {
    m = m.toArrayLike(Uint8Array);
    n = n.toArrayLike(Uint8Array);
    e = e.toArrayLike(Uint8Array);
    d = d.toArrayLike(Uint8Array);
    return RSA_RAW.sign(m, [n, e, d]);
  },

  /**
   * Verify signature
   * @param s signature as BN
   * @param n public MPI part as BN
   * @param e public MPI part as BN
   * @return BN
   */
  verify: function(s, n, e) {
    s = s.toArrayLike(Uint8Array);
    n = n.toArrayLike(Uint8Array);
    e = e.toArrayLike(Uint8Array);
    return RSA_RAW.verify(s, [n, e]);
  },

  /**
   * Encrypt message
   * @param m message as BN
   * @param n public MPI part as BN
   * @param e public MPI part as BN
   * @return BN
   */
  encrypt: function(m, n, e) {
    m = m.toArrayLike(Uint8Array);
    n = n.toArrayLike(Uint8Array);
    e = e.toArrayLike(Uint8Array);
    return RSA_RAW.encrypt(m, [n, e]);
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
    let blinder = zero;
    let unblinder = zero;
    const nred = new BN.red(n);

    config.rsa_blinding = false; // FIXME
    if (config.rsa_blinding) {
      if (unblinder.bitLength() === n.bitLength()) {
        unblinder = unblinder.sqr().mod(n);
      } else {
        unblinder = random.getRandomBN(two, n);
      }
      blinder = unblinder.toRed(nred).redInvm().redPow(e).fromRed();
      m = m.mul(blinder).mod(n);
    }

    const dq = d.mod(q.subn(1)).toArrayLike(Uint8Array); // d mod (q-1)
    const dp = d.mod(p.subn(1)).toArrayLike(Uint8Array); // d mod (p-1)
    const nn = n.toArrayLike(Uint8Array);
    m = m.toArrayLike(Uint8Array);
    e = e.toArrayLike(Uint8Array);
    d = d.toArrayLike(Uint8Array);
    q = q.toArrayLike(Uint8Array);
    p = p.toArrayLike(Uint8Array);
    u = u.toArrayLike(Uint8Array);
    let result = new BN(RSA_RAW.decrypt(m, [nn, e, d, q, p, dq, dp, u]).slice(1)); // FIXME remove slice

    if (config.rsa_blinding) {
      result = result.mul(unblinder).mod(n);
    }

    return result;
  },

  /**
   * Generate a new random private key B bits long with public exponent E
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

    // TODO use this is ../../encoding/base64.js and ./elliptic/{key,curve}.js
    function b64toBN(base64url) {
      const base64 = base64url.replace(/\-/g, '+').replace(/_/g, '/');
      const hex = util.hexstrdump(atob(base64));
      return new BN(hex, 16);
    }

    // asmcrypto fallback
    await asmcrypto_random.seed(await random.getRandomBytes(1024)); // FIXME how much randomness?
    key = await RSA.generateKey(B, E.toArrayLike(Uint8Array));
    return {
      n: new BN(key[0]),
      e: new BN(key[1]),
      d: new BN(key[2]),
      q: new BN(key[3]),
      p: new BN(key[4]),
      // dq: new BN(key[5]),
      // dp: new BN(key[6]),
      u: new BN(key[7])
    };
  }
};
