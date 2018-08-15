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
 * @fileoverview A Digital signature algorithm implementation
 * @requires bn.js
 * @requires crypto/random
 * @requires util
 * @module crypto/public_key/dsa
 */

import BN from 'bn.js';
import random from '../random';
import util from '../../util';

const one = new BN(1);
const zero = new BN(0);

/*
  TODO regarding the hash function, read:
   https://tools.ietf.org/html/rfc4880#section-13.6
   https://tools.ietf.org/html/rfc4880#section-14
*/

export default {
  /**
   * DSA Sign function
   * @param {Integer} hash_algo
   * @param {Uint8Array} hashed
   * @param {BN} g
   * @param {BN} p
   * @param {BN} q
   * @param {BN} x
   * @returns {{ r: BN, s: BN }}
   * @async
   */
  sign: async function(hash_algo, hashed, g, p, q, x) {
    let k;
    let r;
    let s;
    let t;
    const redp = new BN.red(p);
    const redq = new BN.red(q);
    const gred = g.toRed(redp);
    const xred = x.toRed(redq);
    // If the output size of the chosen hash is larger than the number of
    // bits of q, the hash result is truncated to fit by taking the number
    // of leftmost bits equal to the number of bits of q.  This (possibly
    // truncated) hash function result is treated as a number and used
    // directly in the DSA signature algorithm.
    const h = new BN(
      util.getLeftNBits(hashed, q.bitLength()))
      .toRed(redq);
    // FIPS-186-4, section 4.6:
    // The values of r and s shall be checked to determine if r = 0 or s = 0.
    // If either r = 0 or s = 0, a new value of k shall be generated, and the
    // signature shall be recalculated. It is extremely unlikely that r = 0
    // or s = 0 if signatures are generated properly.
    while (true) {
      // See Appendix B here: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
      k = await random.getRandomBN(one, q); // returns in [1, q-1]
      r = gred.redPow(k).fromRed().toRed(redq); // (g**k mod p) mod q
      if (zero.cmp(r) === 0) {
        continue;
      }
      t = h.redAdd(xred.redMul(r)); // H(m) + x*r mod q
      s = k.toRed(redq).redInvm().redMul(t); // k**-1 * (H(m) + x*r) mod q
      if (zero.cmp(s) === 0) {
        continue;
      }
      break;
    }
    return { r: r.toArrayLike(Uint8Array),
             s: s.toArrayLike(Uint8Array) };
  },

  /**
   * DSA Verify function
   * @param {Integer} hash_algo
   * @param {BN} r
   * @param {BN} s
   * @param {Uint8Array} hashed
   * @param {BN} g
   * @param {BN} p
   * @param {BN} q
   * @param {BN} y
   * @returns BN
   * @async
   */
  verify: async function(hash_algo, r, s, hashed, g, p, q, y) {
    if (zero.ucmp(r) >= 0 || r.ucmp(q) >= 0 ||
        zero.ucmp(s) >= 0 || s.ucmp(q) >= 0) {
      util.print_debug("invalid DSA Signature");
      return null;
    }
    const redp = new BN.red(p);
    const redq = new BN.red(q);
    const h = new BN(
      util.getLeftNBits(hashed, q.bitLength()));
    const w = s.toRed(redq).redInvm(); // s**-1 mod q
    if (zero.cmp(w) === 0) {
      util.print_debug("invalid DSA Signature");
      return null;
    }
    const u1 = h.toRed(redq).redMul(w); // H(m) * w mod q
    const u2 = r.toRed(redq).redMul(w); // r * w mod q
    const t1 = g.toRed(redp).redPow(u1.fromRed()); // g**u1 mod p
    const t2 = y.toRed(redp).redPow(u2.fromRed()); // y**u2 mod p
    const v = t1.redMul(t2).fromRed().mod(q); // (g**u1 * y**u2 mod p) mod q
    return v.cmp(r) === 0;
  }
};
