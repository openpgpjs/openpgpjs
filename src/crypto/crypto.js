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

var random = require('./random.js'),
	cipher = require('./cipher'),
	cfb = require('./cfb.js'),
	publicKey= require('./public_key'),
	type_mpi = require('../type/mpi.js');

module.exports = {
/**
 * Encrypts data using the specified public key multiprecision integers 
 * and the specified algorithm.
 * @param {Integer} algo Algorithm to be used (See RFC4880 9.1)
 * @param {openpgp_type_mpi[]} publicMPIs Algorithm dependent multiprecision integers
 * @param {openpgp_type_mpi} data Data to be encrypted as MPI
 * @return {openpgp_type_mpi[]} if RSA an openpgp_type_mpi; 
 * if elgamal encryption an array of two openpgp_type_mpi is returned; otherwise null
 */
publicKeyEncrypt: function(algo, publicMPIs, data) {
	var result = (function() {
		switch(algo) {
		case 'rsa_encrypt':
		case 'rsa_encrypt_sign':
			var rsa = new publicKey.rsa();
			var n = publicMPIs[0].toBigInteger();
			var e = publicMPIs[1].toBigInteger();
			var m = data.toBigInteger();
			return [rsa.encrypt(m,e,n)];

		case 'elgamal':
			var elgamal = new publicKey.elgamal();
			var p = publicMPIs[0].toBigInteger();
			var g = publicMPIs[1].toBigInteger();
			var y = publicMPIs[2].toBigInteger();
			var m = data.toBigInteger();
			return elgamal.encrypt(m,g,p,y);

		default:
			return [];
		}
	})();

	return result.map(function(bn) {
		var mpi = new type_mpi();
		mpi.fromBigInteger(bn);
		return mpi;
	});
},

/**
 * Decrypts data using the specified public key multiprecision integers of the private key,
 * the specified secretMPIs of the private key and the specified algorithm.
 * @param {Integer} algo Algorithm to be used (See RFC4880 9.1)
 * @param {openpgp_type_mpi[]} publicMPIs Algorithm dependent multiprecision integers 
 * of the public key part of the private key
 * @param {openpgp_type_mpi[]} secretMPIs Algorithm dependent multiprecision integers 
 * of the private key used
 * @param {openpgp_type_mpi} data Data to be encrypted as MPI
 * @return {openpgp_type_mpi} returns a big integer containing the decrypted data; otherwise null
 */

publicKeyDecrypt: function (algo, keyIntegers, dataIntegers) {
	var bn = (function() {
		switch(algo) {
		case 'rsa_encrypt_sign':
		case 'rsa_encrypt':
			var rsa = new publicKey.rsa();
			// 0 and 1 are the public key.
			var d = keyIntegers[2].toBigInteger();
			var p = keyIntegers[3].toBigInteger();
			var q = keyIntegers[4].toBigInteger();
			var u = keyIntegers[5].toBigInteger();
			var m = dataIntegers[0].toBigInteger();
			return rsa.decrypt(m, d, p, q, u);
		case 'elgamal':
			var elgamal = new publicKey.elgamal();
			var x = keyIntegers[3].toBigInteger();
			var c1 = dataIntegers[0].toBigInteger();
			var c2 = dataIntegers[1].toBigInteger();
			var p = keyIntegers[0].toBigInteger();
			return elgamal.decrypt(c1,c2,p,x);
		default:
			return null;
		}
	})();

	var result = new type_mpi();
	result.fromBigInteger(bn);
	return result;
},

/** Returns the number of integers comprising the private key of an algorithm
 * @param {openpgp.publickey} algo The public key algorithm
 * @return {Integer} The number of integers.
 */
getPrivateMpiCount: function(algo) {
	switch(algo) {
		case 'rsa_encrypt':
		case 'rsa_encrypt_sign':
		case 'rsa_sign':
		//   Algorithm-Specific Fields for RSA secret keys:
		//   - multiprecision integer (MPI) of RSA secret exponent d.
		//   - MPI of RSA secret prime value p.
		//   - MPI of RSA secret prime value q (p < q).
		//   - MPI of u, the multiplicative inverse of p, mod q.
		return 4;
	case 'elgamal':
		// Algorithm-Specific Fields for Elgamal secret keys:
		//   - MPI of Elgamal secret exponent x.
		return 1;
	case 'dsa':
		// Algorithm-Specific Fields for DSA secret keys:
		//   - MPI of DSA secret exponent x.
		return 1;
	default:
		throw new Error('Unknown algorithm');
	}
},
	
getPublicMpiCount: function(algo) {
	// - A series of multiprecision integers comprising the key material:
	//   Algorithm-Specific Fields for RSA public keys:
	//       - a multiprecision integer (MPI) of RSA public modulus n;
	//       - an MPI of RSA public encryption exponent e.
	switch(algo) {
		case 'rsa_encrypt':
		case 'rsa_encrypt_sign':
		case 'rsa_sign':
		return 2;

	//   Algorithm-Specific Fields for Elgamal public keys:
	//     - MPI of Elgamal prime p;
	//     - MPI of Elgamal group generator g;
	//     - MPI of Elgamal public key value y (= g**x mod p where x  is secret).
		case 'elgamal':
		return 3;

	//   Algorithm-Specific Fields for DSA public keys:
	//       - MPI of DSA prime p;
	//       - MPI of DSA group order q (q is a prime divisor of p-1);
	//       - MPI of DSA group generator g;
	//       - MPI of DSA public-key value y (= g**x mod p where x  is secret).
		case 'dsa':
		return 4;

		default:
			throw new Error('Unknown algorithm.');
	}
},


/**
 * generate random byte prefix as string for the specified algorithm
 * @param {Integer} algo Algorithm to use (see RFC4880 9.2)
 * @return {String} Random bytes with length equal to the block
 * size of the cipher
 */
getPrefixRandom: function(algo) {
	return random.getRandomBytes(cipher[algo].blockSize);
},

/**
 * Generating a session key for the specified symmetric algorithm
 * @param {Integer} algo Algorithm to use (see RFC4880 9.2)
 * @return {String} Random bytes as a string to be used as a key
 */
generateSessionKey: function(algo) {
	return random.getRandomBytes(this.getKeyLength(algo)); 
},

/**
 * Create a secure random big integer of bits length
 * @param {Integer} bits Bit length of the MPI to create
 * @return {BigInteger} Resulting big integer
 */
getRandomBigInteger: function(bits) {
	if (bits < 0)
	   return null;
	var numBytes = Math.floor((bits+7)/8);

	var randomBits = random.getRandomBytes(numBytes);
	if (bits % 8 > 0) {
		
		randomBits = String.fromCharCode(
						(Math.pow(2,bits % 8)-1) &
						randomBits.charCodeAt(0)) +
			randomBits.substring(1);
	}
	return new type_mpi().create(randomBits).toBigInteger();
},

getRandomBigIntegerInRange: function(min, max) {
	if (max.compareTo(min) <= 0)
		return;

	var range = max.subtract(min);
	var r = this.getRandomBigInteger(range.bitLength());
	while (r > range) {
		r = this.getRandomBigInteger(range.bitLength());
	}
	return min.add(r);
},

}
