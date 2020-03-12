// OpenPGP.js - An OpenPGP implementation in javascript
// Copyright (C) 2018 Proton Technologies AG
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
 * @fileoverview Algorithms for probabilistic random prime generation
 * @requires bn.js
 * @requires crypto/random
 * @module crypto/public_key/prime
 */

import BN from 'bn.js';
import random from '../random';

export default {
  randomProbablePrime, isProbablePrime, fermat, millerRabin, divisionTest
};

/**
 * Probabilistic random number generator
 * @param {Integer} bits Bit length of the prime
 * @param {BN}      e    Optional RSA exponent to check against the prime
 * @param {Integer} k    Optional number of iterations of Miller-Rabin test
 * @returns BN
 * @async
 */
async function randomProbablePrime(bits, e, k) {
  const min = new BN(1).shln(bits - 1);
  const thirty = new BN(30);
  /*
   * We can avoid any multiples of 3 and 5 by looking at n mod 30
   * n mod 30 = 0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29
   * the next possible prime is mod 30:
   *            1  7  7  7  7  7  7 11 11 11 11 13 13 17 17 17 17 19 19 23 23 23 23 29 29 29 29 29 29 1
   */
  const adds = [1, 6, 5, 4, 3, 2, 1, 4, 3, 2, 1, 2, 1, 4, 3, 2, 1, 2, 1, 4, 3, 2, 1, 6, 5, 4, 3, 2, 1, 2];

  let n = await random.getRandomBN(min, min.shln(1));
  let i = n.mod(thirty).toNumber();

  do {
    n.iaddn(adds[i]);
    i = (i + adds[i]) % adds.length;
    // If reached the maximum, go back to the minimum.
    if (n.bitLength() > bits) {
      n = n.mod(min.shln(1)).iadd(min);
      i = n.mod(thirty).toNumber();
    }
  } while (!await isProbablePrime(n, e, k));
  return n;
}

/**
 * Probabilistic primality testing
 * @param {BN}      n Number to test
 * @param {BN}      e Optional RSA exponent to check against the prime
 * @param {Integer} k Optional number of iterations of Miller-Rabin test
 * @returns {boolean}
 * @async
 */
async function isProbablePrime(n, e, k) {
  if (e && !n.subn(1).gcd(e).eqn(1)) {
    return false;
  }
  if (!divisionTest(n)) {
    return false;
  }
  if (!fermat(n)) {
    return false;
  }
  if (!await millerRabin(n, k)) {
    return false;
  }
  // TODO implement the Lucas test
  // See Section C.3.3 here: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
  return true;
}

/**
 * Tests whether n is probably prime or not using Fermat's test with b = 2.
 * Fails if b^(n-1) mod n === 1.
 * @param {BN}      n Number to test
 * @param {Integer} b Optional Fermat test base
 * @returns {boolean}
 */
function fermat(n, b) {
  b = b || new BN(2);
  return b.toRed(BN.mont(n)).redPow(n.subn(1)).fromRed().cmpn(1) === 0;
}

function divisionTest(n) {
  return small_primes.every(m => {
    return n.modn(m) !== 0;
  });
}

// https://github.com/gpg/libgcrypt/blob/master/cipher/primegen.c
const small_primes = [
  7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43,
  47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101,
  103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
  157, 163, 167, 173, 179, 181, 191, 193, 197, 199,
  211, 223, 227, 229, 233, 239, 241, 251, 257, 263,
  269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
  331, 337, 347, 349, 353, 359, 367, 373, 379, 383,
  389, 397, 401, 409, 419, 421, 431, 433, 439, 443,
  449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
  509, 521, 523, 541, 547, 557, 563, 569, 571, 577,
  587, 593, 599, 601, 607, 613, 617, 619, 631, 641,
  643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
  709, 719, 727, 733, 739, 743, 751, 757, 761, 769,
  773, 787, 797, 809, 811, 821, 823, 827, 829, 839,
  853, 857, 859, 863, 877, 881, 883, 887, 907, 911,
  919, 929, 937, 941, 947, 953, 967, 971, 977, 983,
  991, 997, 1009, 1013, 1019, 1021, 1031, 1033,
  1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091,
  1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151,
  1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213,
  1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277,
  1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307,
  1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399,
  1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451,
  1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493,
  1499, 1511, 1523, 1531, 1543, 1549, 1553, 1559,
  1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609,
  1613, 1619, 1621, 1627, 1637, 1657, 1663, 1667,
  1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733,
  1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789,
  1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871,
  1873, 1877, 1879, 1889, 1901, 1907, 1913, 1931,
  1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997,
  1999, 2003, 2011, 2017, 2027, 2029, 2039, 2053,
  2063, 2069, 2081, 2083, 2087, 2089, 2099, 2111,
  2113, 2129, 2131, 2137, 2141, 2143, 2153, 2161,
  2179, 2203, 2207, 2213, 2221, 2237, 2239, 2243,
  2251, 2267, 2269, 2273, 2281, 2287, 2293, 2297,
  2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357,
  2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411,
  2417, 2423, 2437, 2441, 2447, 2459, 2467, 2473,
  2477, 2503, 2521, 2531, 2539, 2543, 2549, 2551,
  2557, 2579, 2591, 2593, 2609, 2617, 2621, 2633,
  2647, 2657, 2659, 2663, 2671, 2677, 2683, 2687,
  2689, 2693, 2699, 2707, 2711, 2713, 2719, 2729,
  2731, 2741, 2749, 2753, 2767, 2777, 2789, 2791,
  2797, 2801, 2803, 2819, 2833, 2837, 2843, 2851,
  2857, 2861, 2879, 2887, 2897, 2903, 2909, 2917,
  2927, 2939, 2953, 2957, 2963, 2969, 2971, 2999,
  3001, 3011, 3019, 3023, 3037, 3041, 3049, 3061,
  3067, 3079, 3083, 3089, 3109, 3119, 3121, 3137,
  3163, 3167, 3169, 3181, 3187, 3191, 3203, 3209,
  3217, 3221, 3229, 3251, 3253, 3257, 3259, 3271,
  3299, 3301, 3307, 3313, 3319, 3323, 3329, 3331,
  3343, 3347, 3359, 3361, 3371, 3373, 3389, 3391,
  3407, 3413, 3433, 3449, 3457, 3461, 3463, 3467,
  3469, 3491, 3499, 3511, 3517, 3527, 3529, 3533,
  3539, 3541, 3547, 3557, 3559, 3571, 3581, 3583,
  3593, 3607, 3613, 3617, 3623, 3631, 3637, 3643,
  3659, 3671, 3673, 3677, 3691, 3697, 3701, 3709,
  3719, 3727, 3733, 3739, 3761, 3767, 3769, 3779,
  3793, 3797, 3803, 3821, 3823, 3833, 3847, 3851,
  3853, 3863, 3877, 3881, 3889, 3907, 3911, 3917,
  3919, 3923, 3929, 3931, 3943, 3947, 3967, 3989,
  4001, 4003, 4007, 4013, 4019, 4021, 4027, 4049,
  4051, 4057, 4073, 4079, 4091, 4093, 4099, 4111,
  4127, 4129, 4133, 4139, 4153, 4157, 4159, 4177,
  4201, 4211, 4217, 4219, 4229, 4231, 4241, 4243,
  4253, 4259, 4261, 4271, 4273, 4283, 4289, 4297,
  4327, 4337, 4339, 4349, 4357, 4363, 4373, 4391,
  4397, 4409, 4421, 4423, 4441, 4447, 4451, 4457,
  4463, 4481, 4483, 4493, 4507, 4513, 4517, 4519,
  4523, 4547, 4549, 4561, 4567, 4583, 4591, 4597,
  4603, 4621, 4637, 4639, 4643, 4649, 4651, 4657,
  4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729,
  4733, 4751, 4759, 4783, 4787, 4789, 4793, 4799,
  4801, 4813, 4817, 4831, 4861, 4871, 4877, 4889,
  4903, 4909, 4919, 4931, 4933, 4937, 4943, 4951,
  4957, 4967, 4969, 4973, 4987, 4993, 4999
];


// Miller-Rabin - Miller Rabin algorithm for primality test
// Copyright Fedor Indutny, 2014.
//
// This software is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

// Adapted on Jan 2018 from version 4.0.1 at https://github.com/indutny/miller-rabin

// Sample syntax for Fixed-Base Miller-Rabin:
// millerRabin(n, k, () => new BN(small_primes[Math.random() * small_primes.length | 0]))

/**
 * Tests whether n is probably prime or not using the Miller-Rabin test.
 * See HAC Remark 4.28.
 * @param {BN}       n    Number to test
 * @param {Integer}  k    Optional number of iterations of Miller-Rabin test
 * @param {Function} rand Optional function to generate potential witnesses
 * @returns {boolean}
 * @async
 */
async function millerRabin(n, k, rand) {
  const len = n.bitLength();
  const red = BN.mont(n);
  const rone = new BN(1).toRed(red);

  if (!k) {
    k = Math.max(1, (len / 48) | 0);
  }

  const n1 = n.subn(1);
  const rn1 = n1.toRed(red);

  // Find d and s, (n - 1) = (2 ^ s) * d;
  let s = 0;
  while (!n1.testn(s)) { s++; }
  const d = n.shrn(s);

  for (; k > 0; k--) {
    const a = rand ? rand() : await random.getRandomBN(new BN(2), n1);

    let x = a.toRed(red).redPow(d);
    if (x.eq(rone) || x.eq(rn1)) {
      continue;
    }

    let i;
    for (i = 1; i < s; i++) {
      x = x.redSqr();

      if (x.eq(rone)) {
        return false;
      }
      if (x.eq(rn1)) {
        break;
      }
    }

    if (i === s) {
      return false;
    }
  }

  return true;
}
