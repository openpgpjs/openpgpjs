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
 * @module crypto/public_key/elgamal
 */
import { getRandomBigInteger } from '../random';
import { emeEncode, emeDecode } from '../pkcs1';
import { bigIntToUint8Array, bitLength, byteLength, mod, modExp, modInv, uint8ArrayToBigInt } from '../biginteger';

const _1n = BigInt(1);

/**
 * ElGamal Encryption function
 * Note that in OpenPGP, the message needs to be padded with PKCS#1 (same as RSA)
 * @param {Uint8Array} data - To be padded and encrypted
 * @param {Uint8Array} p
 * @param {Uint8Array} g
 * @param {Uint8Array} y
 * @returns {Promise<{ c1: Uint8Array, c2: Uint8Array }>}
 * @async
 */
// eslint-disable-next-line @typescript-eslint/require-await
export async function encrypt(data, p, g, y) {
  p = uint8ArrayToBigInt(p);
  g = uint8ArrayToBigInt(g);
  y = uint8ArrayToBigInt(y);

  const padded = emeEncode(data, byteLength(p));
  const m = uint8ArrayToBigInt(padded);

  // OpenPGP uses a "special" version of ElGamal where g is generator of the full group Z/pZ*
  // hence g has order p-1, and to avoid that k = 0 mod p-1, we need to pick k in [1, p-2]
  const k = getRandomBigInteger(_1n, p - _1n);
  return {
    c1: bigIntToUint8Array(modExp(g, k, p)),
    c2: bigIntToUint8Array(mod(modExp(y, k, p) * m, p))
  };
}

/**
 * ElGamal Encryption function
 * @param {Uint8Array} c1
 * @param {Uint8Array} c2
 * @param {Uint8Array} p
 * @param {Uint8Array} x
 * @param {Uint8Array} randomPayload - Data to return on unpadding error, instead of throwing
 *                                     (needed for constant-time processing)
 * @returns {Promise<Uint8Array>} Unpadded message.
 * @throws {Error} on decryption error, unless `randomPayload` is given
 * @async
 */
// eslint-disable-next-line @typescript-eslint/require-await
export async function decrypt(c1, c2, p, x, randomPayload) {
  c1 = uint8ArrayToBigInt(c1);
  c2 = uint8ArrayToBigInt(c2);
  p = uint8ArrayToBigInt(p);
  x = uint8ArrayToBigInt(x);

  const padded = mod(modInv(modExp(c1, x, p), p) * c2, p);
  return emeDecode(bigIntToUint8Array(padded, 'be', byteLength(p)), randomPayload);
}

/**
 * Validate ElGamal parameters
 * @param {Uint8Array} pBytes - ElGamal prime
 * @param {Uint8Array} gBytes - ElGamal group generator
 * @param {Uint8Array} yBytes - ElGamal public key
 * @param {Uint8Array} xBytes - ElGamal private exponent
 * @returns {Promise<Boolean>} Whether params are valid.
 * @async
 */
// eslint-disable-next-line @typescript-eslint/require-await
export async function validateParams(pBytes, gBytes, yBytes, xBytes) {
  const p = uint8ArrayToBigInt(pBytes);
  const g = uint8ArrayToBigInt(gBytes);
  const y = uint8ArrayToBigInt(yBytes);

  // Check that 1 < g < p
  if (g <= _1n || g >= p) {
    return false;
  }

  // Expect p-1 to be large
  const pSize = BigInt(bitLength(p));
  const _1023n = BigInt(1023);
  if (pSize < _1023n) {
    return false;
  }

  /**
   * g should have order p-1
   * Check that g ** (p-1) = 1 mod p
   */
  if (modExp(g, p - _1n, p) !== _1n) {
    return false;
  }

  /**
   * Since p-1 is not prime, g might have a smaller order that divides p-1
   * We want to make sure that the order is large enough to hinder a small subgroup attack
   *
   * We just check g**i != 1 for all i up to a threshold
   */
  let res = g;
  let i = BigInt(1);
  const _2n = BigInt(2);
  const threshold = _2n << BigInt(17); // we want order > threshold
  while (i < threshold) {
    res = mod(res * g, p);
    if (res === _1n) {
      return false;
    }
    i++;
  }

  /**
   * Re-derive public key y' = g ** x mod p
   * Expect y == y'
   *
   * Blinded exponentiation computes g**{r(p-1) + x} to compare to y
   */
  const x = uint8ArrayToBigInt(xBytes);
  const r = getRandomBigInteger(_2n << (pSize - _1n), _2n << pSize); // draw r of same size as p-1
  const rqx = (p - _1n) * r + x;
  if (y !== modExp(g, rqx, p)) {
    return false;
  }

  return true;
}
