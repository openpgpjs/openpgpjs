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
 * @requires bn.js
 * @requires util
 * @module crypto/random
 */

import BN from 'bn.js';
import util from '../util';

// Do not use util.getNodeCrypto because we need this regardless of use_native setting
const nodeCrypto = util.detectNode() && require('crypto');

export default {
  /**
   * Retrieve secure random byte array of the specified length
   * @param {Integer} length Length in bytes to generate
   * @returns {Uint8Array} Random byte array
   * @async
   */
  getRandomBytes: async function(length) {
    const buf = new Uint8Array(length);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      crypto.getRandomValues(buf);
    } else if (typeof global !== 'undefined' && typeof global.msCrypto === 'object' && typeof global.msCrypto.getRandomValues === 'function') {
      global.msCrypto.getRandomValues(buf);
    } else if (nodeCrypto) {
      const bytes = nodeCrypto.randomBytes(buf.length);
      buf.set(bytes);
    } else if (this.randomBuffer.buffer) {
      await this.randomBuffer.get(buf);
    } else {
      throw new Error('No secure random number generator available.');
    }
    return buf;
  },

  /**
   * Create a secure random MPI that is greater than or equal to min and less than max.
   * @param {module:type/mpi} min Lower bound, included
   * @param {module:type/mpi} max Upper bound, excluded
   * @returns {module:BN} Random MPI
   * @async
   */
  getRandomBN: async function(min, max) {
    if (max.cmp(min) <= 0) {
      throw new Error('Illegal parameter value: max <= min');
    }

    const modulus = max.sub(min);
    const bytes = modulus.byteLength();

    // Using a while loop is necessary to avoid bias introduced by the mod operation.
    // However, we request 64 extra random bits so that the bias is negligible.
    // Section B.1.1 here: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
    const r = new BN(await this.getRandomBytes(bytes + 8));
    return r.mod(modulus).add(min);
  },

  randomBuffer: new RandomBuffer()
};

/**
 * Buffer for secure random numbers
 */
function RandomBuffer() {
  this.buffer = null;
  this.size = null;
  this.callback = null;
}

/**
 * Initialize buffer
 * @param  {Integer} size size of buffer
 */
RandomBuffer.prototype.init = function(size, callback) {
  this.buffer = new Uint8Array(size);
  this.size = 0;
  this.callback = callback;
};

/**
 * Concat array of secure random numbers to buffer
 * @param {Uint8Array} buf
 */
RandomBuffer.prototype.set = function(buf) {
  if (!this.buffer) {
    throw new Error('RandomBuffer is not initialized');
  }
  if (!(buf instanceof Uint8Array)) {
    throw new Error('Invalid type: buf not an Uint8Array');
  }
  const freeSpace = this.buffer.length - this.size;
  if (buf.length > freeSpace) {
    buf = buf.subarray(0, freeSpace);
  }
  // set buf with offset old size of buffer
  this.buffer.set(buf, this.size);
  this.size += buf.length;
};

/**
 * Take numbers out of buffer and copy to array
 * @param {Uint8Array} buf the destination array
 */
RandomBuffer.prototype.get = async function(buf) {
  if (!this.buffer) {
    throw new Error('RandomBuffer is not initialized');
  }
  if (!(buf instanceof Uint8Array)) {
    throw new Error('Invalid type: buf not an Uint8Array');
  }
  if (this.size < buf.length) {
    if (!this.callback) {
      throw new Error('Random number buffer depleted');
    }
    // Wait for random bytes from main context, then try again
    await this.callback();
    return this.get(buf);
  }
  for (let i = 0; i < buf.length; i++) {
    buf[i] = this.buffer[--this.size];
    // clear buffer value
    this.buffer[this.size] = 0;
  }
};
