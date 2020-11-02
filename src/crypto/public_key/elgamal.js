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
 * @requires bn.js
 * @requires crypto/random
 * @module crypto/public_key/elgamal
 */

import BN from 'bn.js';
import random from '../random';

export default {
  /**
   * ElGamal Encryption function
   * @param {BN} m
   * @param {BN} p
   * @param {BN} g
   * @param {BN} y
   * @returns {{ c1: BN, c2: BN }}
   * @async
   */
  encrypt: async function(m, p, g, y) {
    const redp = new BN.red(p);
    const mred = m.toRed(redp);
    const gred = g.toRed(redp);
    const yred = y.toRed(redp);
    // OpenPGP uses a "special" version of ElGamal where g is generator of the full group Z/pZ*
    // hence g has order p-1, and to avoid that k = 0 mod p-1, we need to pick k in [1, p-2]
    const k = await random.getRandomBN(new BN(1), p.subn(1));
    return {
      c1: gred.redPow(k).fromRed(),
      c2: yred.redPow(k).redMul(mred).fromRed()
    };
  },

  /**
   * ElGamal Encryption function
   * @param {BN} c1
   * @param {BN} c2
   * @param {BN} p
   * @param {BN} x
   * @returns BN
   * @async
   */
  decrypt: async function(c1, c2, p, x) {
    const redp = new BN.red(p);
    const c1red = c1.toRed(redp);
    const c2red = c2.toRed(redp);
    return c1red.redPow(x).redInvm().redMul(c2red).fromRed();
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
    p = new BN(p);
    g = new BN(g);
    y = new BN(y);

    const one = new BN(1);
    // Check that 1 < g < p
    if (g.lte(one) || g.gte(p)) {
      return false;
    }

    // Expect p-1 to be large
    const pSize = p.subn(1).bitLength();
    if (pSize < 1023) {
      return false;
    }

    const pred = new BN.red(p);
    const gModP = g.toRed(pred);
    /**
     * g should have order p-1
     * Check that g ** (p-1) = 1 mod p
     */
    if (!gModP.redPow(p.subn(1)).eq(one)) {
      return false;
    }

    /**
     * Since p-1 is not prime, g might have a smaller order that divides p-1
     * We want to make sure that the order is large enough to hinder a small subgroup attack
     *
     * We just check g**i != 1 for all i up to a threshold
     */
    let res = g;
    const i = new BN(1);
    const threshold = new BN(2).shln(17); // we want order > threshold
    while (i.lt(threshold)) {
      res = res.mul(g).mod(p);
      if (res.eqn(1)) {
        return false;
      }
      i.iaddn(1);
    }

    /**
     * Re-derive public key y' = g ** x mod p
     * Expect y == y'
     *
     * Blinded exponentiation computes g**{r(p-1) + x} to compare to y
     */
    x = new BN(x);
    const r = await random.getRandomBN(new BN(2).shln(pSize - 1), new BN(2).shln(pSize)); // draw r of same size as p-1
    const rqx = p.subn(1).mul(r).add(x);
    if (!y.eq(gModP.redPow(rqx))) {
      return false;
    }

    return true;
  }
};
