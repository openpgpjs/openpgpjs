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
import { getRandomBigInteger } from '../random';
import { emeEncode, emeDecode } from '../pkcs1';

/**
 * ElGamal Encryption function
 * Note that in OpenPGP, the message needs to be padded with PKCS#1 (same as RSA)
 * @param {Uint8Array} data to be padded and encrypted
 * @param {Uint8Array} p
 * @param {Uint8Array} g
 * @param {Uint8Array} y
 * @returns {{ c1: Uint8Array, c2: Uint8Array }}
 * @async
 */
export async function encrypt(data, p, g, y) {
  const BigInteger = await util.getBigInteger();
  p = new BigInteger(p);
  g = new BigInteger(g);
  y = new BigInteger(y);

  const padded = await emeEncode(data, p.byteLength());
  const m = new BigInteger(padded);

  // OpenPGP uses a "special" version of ElGamal where g is generator of the full group Z/pZ*
  // hence g has order p-1, and to avoid that k = 0 mod p-1, we need to pick k in [1, p-2]
  const k = await getRandomBigInteger(new BigInteger(1), p.dec());
  return {
    c1: g.modExp(k, p).toUint8Array(),
    c2: y.modExp(k, p).imul(m).imod(p).toUint8Array()
  };
}

/**
 * ElGamal Encryption function
 * @param {Uint8Array} c1
 * @param {Uint8Array} c2
 * @param {Uint8Array} p
 * @param {Uint8Array} x
 * @returns {Uint8Array} unpadded message
 * @async
 */
export async function decrypt(c1, c2, p, x) {
  const BigInteger = await util.getBigInteger();
  c1 = new BigInteger(c1);
  c2 = new BigInteger(c2);
  p = new BigInteger(p);
  x = new BigInteger(x);

  const padded = c1.modExp(x, p).modInv(p).imul(c2).imod(p);
  return emeDecode(padded.toUint8Array('be', p.byteLength()));
}

/**
 * Validate ElGamal parameters
 * @param {Uint8Array}         p ElGamal prime
 * @param {Uint8Array}         g ElGamal group generator
 * @param {Uint8Array}         y ElGamal public key
 * @param {Uint8Array}         x ElGamal private exponent
 * @returns {Promise<Boolean>} whether params are valid
 * @async
 */
export async function validateParams(p, g, y, x) {
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
  const r = await getRandomBigInteger(two.leftShift(pSize.dec()), two.leftShift(pSize)); // draw r of same size as p-1
  const rqx = p.dec().imul(r).iadd(x);
  if (!y.equal(g.modExp(rqx, p))) {
    return false;
  }

  return true;
}
