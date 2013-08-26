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

var type_mpi = require('../type/mpi.js');
var uheprng = require('./uheprng.js');

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
		return Math.round(Math.random()*(to-from))+from;
	},

	/**
	 * Return a secure random number in the specified range
	 * @param {Integer} from Min of the random number
	 * @param {Integer} to Max of the random number (max 32bit)
	 * @return {Integer} A secure random number
	 */
	getSecureRandom: function(from, to) {
    var num = uheprng(to - from);
    return num + from;
	},

	getSecureRandomOctet: function() {
    var num = uheprng.string(1);
		return num & 0xFF;
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
    var numBytes = Math.floor((bits+7)/8);

    var randomBits = this.getRandomBytes(numBytes);
    if (bits % 8 > 0) {
      
      randomBits = String.fromCharCode(
              (Math.pow(2,bits % 8)-1) &
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
