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
 * @requires crypto/random
 * @requires util
 * @module crypto/public_key/dsa
 */
import { getRandomBigInteger } from '../random';
import util from '../../util';
import { isProbablePrime } from './prime';

/*
  TODO regarding the hash function, read:
   https://tools.ietf.org/html/rfc4880#section-13.6
   https://tools.ietf.org/html/rfc4880#section-14
*/

/**
 * DSA Sign function
 * @param {Integer} hash_algo
 * @param {Uint8Array} hashed
 * @param {Uint8Array} g
 * @param {Uint8Array} p
 * @param {Uint8Array} q
 * @param {Uint8Array} x
 * @returns {{ r: Uint8Array, s: Uint8Array }}
 * @async
 */
export async function sign(hash_algo, hashed, g, p, q, x) {
  const BigInteger = await util.getBigInteger();
  const one = new BigInteger(1);
  p = new BigInteger(p);
  q = new BigInteger(q);
  g = new BigInteger(g);
  x = new BigInteger(x);

  let k;
  let r;
  let s;
  let t;
  g = g.mod(p);
  x = x.mod(q);
  // If the output size of the chosen hash is larger than the number of
  // bits of q, the hash result is truncated to fit by taking the number
  // of leftmost bits equal to the number of bits of q.  This (possibly
  // truncated) hash function result is treated as a number and used
  // directly in the DSA signature algorithm.
  const h = new BigInteger(hashed.subarray(0, q.byteLength())).mod(q);
  // FIPS-186-4, section 4.6:
  // The values of r and s shall be checked to determine if r = 0 or s = 0.
  // If either r = 0 or s = 0, a new value of k shall be generated, and the
  // signature shall be recalculated. It is extremely unlikely that r = 0
  // or s = 0 if signatures are generated properly.
  while (true) {
    // See Appendix B here: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
    k = await getRandomBigInteger(one, q); // returns in [1, q-1]
    r = g.modExp(k, p).imod(q); // (g**k mod p) mod q
    if (r.isZero()) {
      continue;
    }
    const xr = x.mul(r).imod(q);
    t = h.add(xr).imod(q); // H(m) + x*r mod q
    s = k.modInv(q).imul(t).imod(q); // k**-1 * (H(m) + x*r) mod q
    if (s.isZero()) {
      continue;
    }
    break;
  }
  return {
    r: r.toUint8Array('be', q.byteLength()),
    s: s.toUint8Array('be', q.byteLength())
  };
}

/**
 * DSA Verify function
 * @param {Integer} hash_algo
 * @param {Uint8Array} r
 * @param {Uint8Array} s
 * @param {Uint8Array} hashed
 * @param {Uint8Array} g
 * @param {Uint8Array} p
 * @param {Uint8Array} q
 * @param {Uint8Array} y
 * @returns {boolean}
 * @async
 */
export async function verify(hash_algo, r, s, hashed, g, p, q, y) {
  const BigInteger = await util.getBigInteger();
  const zero = new BigInteger(0);
  r = new BigInteger(r);
  s = new BigInteger(s);

  p = new BigInteger(p);
  q = new BigInteger(q);
  g = new BigInteger(g);
  y = new BigInteger(y);

  if (r.lte(zero) || r.gte(q) ||
      s.lte(zero) || s.gte(q)) {
    util.printDebug("invalid DSA Signature");
    return false;
  }
  const h = new BigInteger(hashed.subarray(0, q.byteLength())).imod(q);
  const w = s.modInv(q); // s**-1 mod q
  if (w.isZero()) {
    util.printDebug("invalid DSA Signature");
    return false;
  }

  g = g.mod(p);
  y = y.mod(p);
  const u1 = h.mul(w).imod(q); // H(m) * w mod q
  const u2 = r.mul(w).imod(q); // r * w mod q
  const t1 = g.modExp(u1, p); // g**u1 mod p
  const t2 = y.modExp(u2, p); // y**u2 mod p
  const v = t1.mul(t2).imod(p).imod(q); // (g**u1 * y**u2 mod p) mod q
  return v.equal(r);
}

/**
 * Validate DSA parameters
 * @param {Uint8Array}         p DSA prime
 * @param {Uint8Array}         q DSA group order
 * @param {Uint8Array}         g DSA sub-group generator
 * @param {Uint8Array}         y DSA public key
 * @param {Uint8Array}         x DSA private key
 * @returns {Promise<Boolean>} whether params are valid
 * @async
 */
export async function validateParams(p, q, g, y, x) {
  const BigInteger = await util.getBigInteger();
  p = new BigInteger(p);
  q = new BigInteger(q);
  g = new BigInteger(g);
  y = new BigInteger(y);
  const one = new BigInteger(1);
  // Check that 1 < g < p
  if (g.lte(one) || g.gte(p)) {
    return false;
  }

  /**
   * Check that subgroup order q divides p-1
   */
  if (!p.dec().mod(q).isZero()) {
    return false;
  }

  /**
   * g has order q
   * Check that g ** q = 1 mod p
   */
  if (!g.modExp(q, p).isOne()) {
    return false;
  }

  /**
   * Check q is large and probably prime (we mainly want to avoid small factors)
   */
  const qSize = new BigInteger(q.bitLength());
  const n150 = new BigInteger(150);
  if (qSize.lt(n150) || !(await isProbablePrime(q, null, 32))) {
    return false;
  }

  /**
   * Re-derive public key y' = g ** x mod p
   * Expect y == y'
   *
   * Blinded exponentiation computes g**{rq + x} to compare to y
   */
  x = new BigInteger(x);
  const two = new BigInteger(2);
  const r = await getRandomBigInteger(two.leftShift(qSize.dec()), two.leftShift(qSize)); // draw r of same size as q
  const rqx = q.mul(r).add(x);
  if (!y.equal(g.modExp(rqx, p))) {
    return false;
  }

  return true;
}
