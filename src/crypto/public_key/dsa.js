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
 * @module crypto/public_key/dsa
 */
import { getRandomBigInteger } from '../random';
import util from '../../util';
import { isProbablePrime } from './prime';
import { bigIntToUint8Array, bitLength, byteLength, mod, modExp, modInv, uint8ArrayToBigInt } from '../biginteger';

/*
  TODO regarding the hash function, read:
   https://tools.ietf.org/html/rfc4880#section-13.6
   https://tools.ietf.org/html/rfc4880#section-14
*/

const _0n = BigInt(0);
const _1n = BigInt(1);

/**
 * DSA Sign function
 * @param {Integer} hashAlgo
 * @param {Uint8Array} hashed
 * @param {Uint8Array} g
 * @param {Uint8Array} p
 * @param {Uint8Array} q
 * @param {Uint8Array} x
 * @returns {Promise<{ r: Uint8Array, s: Uint8Array }>}
 * @async
 */
// eslint-disable-next-line @typescript-eslint/require-await
export async function sign(hashAlgo, hashed, g, p, q, x) {
  const _0n = BigInt(0);
  p = uint8ArrayToBigInt(p);
  q = uint8ArrayToBigInt(q);
  g = uint8ArrayToBigInt(g);
  x = uint8ArrayToBigInt(x);

  let k;
  let r;
  let s;
  let t;
  g = mod(g, p);
  x = mod(x, q);
  // If the output size of the chosen hash is larger than the number of
  // bits of q, the hash result is truncated to fit by taking the number
  // of leftmost bits equal to the number of bits of q.  This (possibly
  // truncated) hash function result is treated as a number and used
  // directly in the DSA signature algorithm.
  const h = mod(uint8ArrayToBigInt(hashed.subarray(0, byteLength(q))), q);
  // FIPS-186-4, section 4.6:
  // The values of r and s shall be checked to determine if r = 0 or s = 0.
  // If either r = 0 or s = 0, a new value of k shall be generated, and the
  // signature shall be recalculated. It is extremely unlikely that r = 0
  // or s = 0 if signatures are generated properly.
  while (true) {
    // See Appendix B here: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
    k = getRandomBigInteger(_1n, q); // returns in [1, q-1]
    r = mod(modExp(g, k, p), q); // (g**k mod p) mod q
    if (r === _0n) {
      continue;
    }
    const xr = mod(x * r, q);
    t = mod(h + xr, q); // H(m) + x*r mod q
    s = mod(modInv(k, q) * t, q); // k**-1 * (H(m) + x*r) mod q
    if (s === _0n) {
      continue;
    }
    break;
  }
  return {
    r: bigIntToUint8Array(r, 'be', byteLength(p)),
    s: bigIntToUint8Array(s, 'be', byteLength(p))
  };
}

/**
 * DSA Verify function
 * @param {Integer} hashAlgo
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
// eslint-disable-next-line @typescript-eslint/require-await
export async function verify(hashAlgo, r, s, hashed, g, p, q, y) {
  r = uint8ArrayToBigInt(r);
  s = uint8ArrayToBigInt(s);

  p = uint8ArrayToBigInt(p);
  q = uint8ArrayToBigInt(q);
  g = uint8ArrayToBigInt(g);
  y = uint8ArrayToBigInt(y);

  if (r <= _0n || r >= q ||
      s <= _0n || s >= q) {
    util.printDebug('invalid DSA Signature');
    return false;
  }
  const h = mod(uint8ArrayToBigInt(hashed.subarray(0, byteLength(q))), q);
  const w = modInv(s, q); // s**-1 mod q
  if (w === _0n) {
    util.printDebug('invalid DSA Signature');
    return false;
  }

  g = mod(g, p);
  y = mod(y, p);
  const u1 = mod(h * w, q); // H(m) * w mod q
  const u2 = mod(r * w, q); // r * w mod q
  const t1 = modExp(g, u1, p); // g**u1 mod p
  const t2 = modExp(y, u2, p); // y**u2 mod p
  const v = mod(mod(t1 * t2, p), q); // (g**u1 * y**u2 mod p) mod q
  return v === r;
}

/**
 * Validate DSA parameters
 * @param {Uint8Array} pBytes - DSA prime
 * @param {Uint8Array} qBytes - DSA group order
 * @param {Uint8Array} gBytes - DSA sub-group generator
 * @param {Uint8Array} yBytes - DSA public key
 * @param {Uint8Array} xBytes - DSA private key
 * @returns {Promise<Boolean>} Whether params are valid.
 * @async
 */
// eslint-disable-next-line @typescript-eslint/require-await
export async function validateParams(pBytes, qBytes, gBytes, yBytes, xBytes) {
  const p = uint8ArrayToBigInt(pBytes);
  const q = uint8ArrayToBigInt(qBytes);
  const g = uint8ArrayToBigInt(gBytes);
  const y = uint8ArrayToBigInt(yBytes);
  // Check that 1 < g < p
  if (g <= _1n || g >= p) {
    return false;
  }

  /**
   * Check that subgroup order q divides p-1
   */
  if (mod(p - _1n, q) !== _0n) {
    return false;
  }

  /**
   * g has order q
   * Check that g ** q = 1 mod p
   */
  if (modExp(g, q, p) !== _1n) {
    return false;
  }

  /**
   * Check q is large and probably prime (we mainly want to avoid small factors)
   */
  const qSize = BigInt(bitLength(q));
  const _150n = BigInt(150);
  if (qSize < _150n || !isProbablePrime(q, null, 32)) {
    return false;
  }

  /**
   * Re-derive public key y' = g ** x mod p
   * Expect y == y'
   *
   * Blinded exponentiation computes g**{rq + x} to compare to y
   */
  const x = uint8ArrayToBigInt(xBytes);
  const _2n = BigInt(2);
  const r = getRandomBigInteger(_2n << (qSize - _1n), _2n << qSize); // draw r of same size as q
  const rqx = q * r + x;
  if (y !== modExp(g, rqx, p)) {
    return false;
  }

  return true;
}
