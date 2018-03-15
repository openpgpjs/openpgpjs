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

const zero = new BN(0);

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
    // See Section 11.5 here: https://crypto.stanford.edu/~dabo/cryptobook/BonehShoup_0_4.pdf
    const k = await random.getRandomBN(zero, p); // returns in [0, p-1]
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
  }
};
