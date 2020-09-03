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
 * @fileoverview ElGamal implementation
 * @requires crypto/random
 * @requires util
 * @module crypto/public_key/elgamal
 */

import util from '../../util';
import random from '../random';

export default {
  /**
   * ElGamal Encryption function
   * @param {BigInteger} m
   * @param {BigInteger} p
   * @param {BigInteger} g
   * @param {BigInteger} y
   * @returns {{ c1: BigInteger, c2: BigInteger }}
   * @async
   */
  encrypt: async function(m, p, g, y) {
    const BigInteger = await util.getBigInteger();
    // See Section 11.5 here: https://crypto.stanford.edu/~dabo/cryptobook/BonehShoup_0_4.pdf
    const k = await random.getRandomBigInteger(new BigInteger(0), p); // returns in [0, p-1]
    return {
      c1: g.modExp(k, p),
      c2: y.modExp(k, p).imul(m).imod(p)
    };
  },

  /**
   * ElGamal Encryption function
   * @param {BigInteger} c1
   * @param {BigInteger} c2
   * @param {BigInteger} p
   * @param {BigInteger} x
   * @returns BigInteger
   * @async
   */
  decrypt: async function(c1, c2, p, x) {
    return c1.modExp(x, p).modInv(p).imul(c2).imod(p);
  },

  /**
   * Validate ElGamal parameters
   * @param {Uint8Array}         p ElGamal prime
   * @param {Uint8Array}         g ElGamal group generator
   * @param {Uint8Array}         y ElGamal public key
   * @param {Uint8Array}         x ElGamal private exponent
   * @returns {Promise<Boolean>} whether params are valid
   * @async
   */
  validateParams: async function (p, g, y, x) {
    const BigInteger = await util.getBigInteger();
    p = new BigInteger(p);
    g = new BigInteger(g);
    y = new BigInteger(y);

    const one = new BigInteger(1);
    // Check that 1 < g < p
    if (g.lte(one) || g.gte(p)) {
      return false;
    }

    // Expect p-1 to be large
    const pSize = new BigInteger(p.bitLength());
    const n1023 = new BigInteger(1023);
    if (pSize.lt(n1023)) {
      return false;
    }

    /**
     * g should have order p-1
     * Check that g ** (p-1) = 1 mod p
     */
    if (!g.modExp(p.dec(), p).isOne()) {
      return false;
    }

    /**
     * Since p-1 is not prime, g might have a smaller order that divides p-1
     * We want to make sure that the order is large enough to hinder a small subgroup attack
     *
     * We just check g**i != 1 for all i up to a threshold
     */
    let res = g;
    const i = new BigInteger(1);
    const threshold = new BigInteger(2).leftShift(new BigInteger(17)); // we want order > threshold
    while (i.lt(threshold)) {
      res = res.mul(g).imod(p);
      if (res.isOne()) {
        return false;
      }
      i.iinc();
    }

    /**
     * Re-derive public key y' = g ** x mod p
     * Expect y == y'
     *
     * Blinded exponentiation computes g**{r(p-1) + x} to compare to y
     */
    x = new BigInteger(x);
    const two = new BigInteger(2);
    const r = await random.getRandomBigInteger(two.leftShift(pSize.dec()), two.leftShift(pSize)); // draw r of same size as p-1
    const rqx = p.dec().imul(r).iadd(x);
    if (!y.equal(g.modExp(rqx, p))) {
      return false;
    }

    return true;
  }
};
