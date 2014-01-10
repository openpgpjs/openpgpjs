// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
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
 * @requires type/mpi
 * @module crypto/random
 */

var type_mpi = require('../type/mpi.js');
var nodeCrypto = null;

if (typeof window === 'undefined') {
  nodeCrypto = require('crypto');
}

module.exports = {
  /**
   * Retrieve secure random byte string of the specified length
   * @param {Integer} length Length in bytes to generate
   * @return {String} Random byte string
   */
  getRandomBytes: function(length) {
    var result = '';
    for (var i = 0; i < length; i++) {
      result += String.fromCharCode(this.getSecureRandomOctet());
    }
    return result;
  },

  /**
   * Return a pseudo-random number in the specified range
   * @param {Integer} from Min of the random number
   * @param {Integer} to Max of the random number (max 32bit)
   * @return {Integer} A pseudo random number
   */
  getPseudoRandom: function(from, to) {
    return Math.round(Math.random() * (to - from)) + from;
  },

  /**
   * Return a secure random number in the specified range
   * @param {Integer} from Min of the random number
   * @param {Integer} to Max of the random number (max 32bit)
   * @return {Integer} A secure random number
   */
  getSecureRandom: function(from, to) {
    var buf = new Uint32Array(1);
    this.getRandomValues(buf);
    var bits = ((to - from)).toString(2).length;
    while ((buf[0] & (Math.pow(2, bits) - 1)) > (to - from))
      this.getRandomValues(buf);
    return from + (Math.abs(buf[0] & (Math.pow(2, bits) - 1)));
  },

  getSecureRandomOctet: function() {
    var buf = new Uint32Array(1);
    this.getRandomValues(buf);
    return buf[0] & 0xFF;
  },

  /**
   * Helper routine which calls platform specific crypto random generator
   * @param {Uint32Array} buf
   */
  getRandomValues: function(buf) {
    if (nodeCrypto === null) {
      window.crypto.getRandomValues(buf);
    } else {
      var bytes = nodeCrypto.randomBytes(4);
      buf[0] = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
    }
  },

  /**
   * Create a secure random big integer of bits length
   * @param {Integer} bits Bit length of the MPI to create
   * @return {BigInteger} Resulting big integer
   */
  getRandomBigInteger: function(bits) {
    if (bits < 0) {
      return null;
    }
    var numBytes = Math.floor((bits + 7) / 8);

    var randomBits = this.getRandomBytes(numBytes);
    if (bits % 8 > 0) {

      randomBits = String.fromCharCode(
      (Math.pow(2, bits % 8) - 1) &
        randomBits.charCodeAt(0)) +
        randomBits.substring(1);
    }
    var mpi = new type_mpi();
    mpi.fromBytes(randomBits);
    return mpi.toBigInteger();
  },

  getRandomBigIntegerInRange: function(min, max) {
    if (max.compareTo(min) <= 0) {
      return;
    }

    var range = max.subtract(min);
    var r = this.getRandomBigInteger(range.bitLength());
    while (r > range) {
      r = this.getRandomBigInteger(range.bitLength());
    }
    return min.add(r);
  }

};
