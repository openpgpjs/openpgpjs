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

// The GPG4Browsers crypto interface

/**
 * @fileoverview Provides tools for retrieving secure randomness from browsers or Node.js
 * @module crypto/random
 */
import { byteLength, mod, uint8ArrayToBigInt } from './biginteger';
import util from '../util';

const nodeCrypto = util.getNodeCrypto();

/**
 * Retrieve secure random byte array of the specified length
 * @param {Integer} length - Length in bytes to generate
 * @returns {Uint8Array} Random byte array.
 */
export function getRandomBytes(length) {
  const webcrypto = typeof crypto !== 'undefined' ? crypto : nodeCrypto?.webcrypto;
  if (webcrypto?.getRandomValues) {
    const buf = new Uint8Array(length);
    return webcrypto.getRandomValues(buf);
  } else {
    throw new Error('No secure random number generator available.');
  }
}

/**
 * Create a secure random BigInt that is greater than or equal to min and less than max.
 * @param {bigint} min - Lower bound, included
 * @param {bigint} max - Upper bound, excluded
 * @returns {bigint} Random BigInt.
 * @async
 */
export function getRandomBigInteger(min, max) {
  if (max < min) {
    throw new Error('Illegal parameter value: max <= min');
  }

  const modulus = max - min;
  const bytes = byteLength(modulus);

  // Using a while loop is necessary to avoid bias introduced by the mod operation.
  // However, we request 64 extra random bits so that the bias is negligible.
  // Section B.1.1 here: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
  const r = uint8ArrayToBigInt(getRandomBytes(bytes + 8));
  return mod(r, modulus) + min;
}
