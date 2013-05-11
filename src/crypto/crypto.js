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
		case 1: // RSA (Encrypt or Sign) [HAC]
		case 2: // RSA Encrypt-Only [HAC]
		case 3: // RSA Sign-Only [HAC]
			var rsa = new publicKey.rsa();
			var n = publicMPIs[0].toBigInteger();
			var e = publicMPIs[1].toBigInteger();
			var m = data.toBigInteger();
			return [rsa.encrypt(m,e,n)];
		case 16: // Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
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
		case 1: // RSA (Encrypt or Sign) [HAC]  
		case 2: // RSA Encrypt-Only [HAC]
		case 3: // RSA Sign-Only [HAC]
			var rsa = new publicKey.rsa();
			// 0 and 1 are the public key.
			var d = keyIntegers[2].toBigInteger();
			var p = keyIntegers[3].toBigInteger();
			var q = keyIntegers[4].toBigInteger();
			var u = keyIntegers[5].toBigInteger();
			var m = dataIntegers[0].toBigInteger();
			return rsa.decrypt(m, d, p, q, u);
		case 16: // Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
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
	if (algo > 0 && algo < 4) {
		//   Algorithm-Specific Fields for RSA secret keys:
		//   - multiprecision integer (MPI) of RSA secret exponent d.
		//   - MPI of RSA secret prime value p.
		//   - MPI of RSA secret prime value q (p < q).
		//   - MPI of u, the multiplicative inverse of p, mod q.
		return 4;
	} else if (algo == 16) {
		// Algorithm-Specific Fields for Elgamal secret keys:
		//   - MPI of Elgamal secret exponent x.
		return 1;
	} else if (algo == 17) {
		// Algorithm-Specific Fields for DSA secret keys:
		//   - MPI of DSA secret exponent x.
		return 1;
	}
	else return 0;
},
	
getPublicMpiCount: function(algorithm) {
	// - A series of multiprecision integers comprising the key material:
	//   Algorithm-Specific Fields for RSA public keys:
	//       - a multiprecision integer (MPI) of RSA public modulus n;
	//       - an MPI of RSA public encryption exponent e.
	if (algorithm > 0 && algorithm < 4)
		return 2;

	//   Algorithm-Specific Fields for Elgamal public keys:
	//     - MPI of Elgamal prime p;
	//     - MPI of Elgamal group generator g;
	//     - MPI of Elgamal public key value y (= g**x mod p where x  is secret).
	else if (algorithm == 16)
		return 3;

	//   Algorithm-Specific Fields for DSA public keys:
	//       - MPI of DSA prime p;
	//       - MPI of DSA group order q (q is a prime divisor of p-1);
	//       - MPI of DSA group generator g;
	//       - MPI of DSA public-key value y (= g**x mod p where x  is secret).
	else if (algorithm == 17)
		return 4;
	else
		return 0;
},


/**
 * generate random byte prefix as string for the specified algorithm
 * @param {Integer} algo Algorithm to use (see RFC4880 9.2)
 * @return {String} Random bytes with length equal to the block
 * size of the cipher
 */
getPrefixRandom: function(algo) {
	switch(algo) {
	case 2:
	case 3:
	case 4:
		return random.getRandomBytes(8);
	case 7:
	case 8:
	case 9:
	case 10:
		return random.getRandomBytes(16);
	default:
		return null;
	}
},

/**
 * retrieve the MDC prefixed bytes by decrypting them
 * @param {Integer} algo Algorithm to use (see RFC4880 9.2)
 * @param {String} key Key as string. length is depending on the algorithm used
 * @param {String} data Encrypted data where the prefix is decrypted from
 * @return {String} Plain text data of the prefixed data
 */
MDCSystemBytes: function(algo, key, data) {
	switch(algo) {
	case 0: // Plaintext or unencrypted data
		return data;
	case 2: // TripleDES (DES-EDE, [SCHNEIER] [HAC] - 168 bit key derived from 192)
		return openpgp_cfb_mdc(desede, 8, key, data, openpgp_cfb);
	case 3: // CAST5 (128 bit key, as per [RFC2144])
		return openpgp_cfb_mdc(cast5_encrypt, 8, key, data);
	case 4: // Blowfish (128 bit key, 16 rounds) [BLOWFISH]
		return openpgp_cfb_mdc(BFencrypt, 8, key, data);
	case 7: // AES with 128-bit key [AES]
	case 8: // AES with 192-bit key
	case 9: // AES with 256-bit key
		return openpgp_cfb_mdc(AESencrypt, 16, keyExpansion(key), data);
	case 10: 
		return openpgp_cfb_mdc(TFencrypt, 16, key, data);
	case 1: // IDEA [IDEA]
		throw new Error('IDEA Algorithm not implemented');
	default:
		throw new Error('Invalid algorithm.');
	}
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
 * Get the key length by symmetric algorithm id.
 * @param {Integer} algo Algorithm to use (see RFC4880 9.2)
 * @return {String} Random bytes as a string to be used as a key
 */
getKeyLength: function(algo) {
	switch (algo) {
	case 2: // TripleDES (DES-EDE, [SCHNEIER] [HAC] - 168 bit key derived from 192)
	case 8: // AES with 192-bit key
		return 24;
	case 3: // CAST5 (128 bit key, as per [RFC2144])
	case 4: // Blowfish (128 bit key, 16 rounds) [BLOWFISH]
	case 7: // AES with 128-bit key [AES]
		return 16;
	case 9: // AES with 256-bit key
	case 10:// Twofish with 256-bit key [TWOFISH]
		return 32;
	}
	return null;
},

/**
 * Returns the block length of the specified symmetric encryption algorithm
 * @param {openpgp.symmetric} algo Symmetric algorithm idenhifier
 * @return {Integer} The number of bytes in a single block encrypted by the algorithm
 */
getBlockLength: function(algo) {
	switch (algo) {
	case  1: // - IDEA [IDEA]
	case  2: // - TripleDES (DES-EDE, [SCHNEIER] [HAC] - 168 bit key derived from 192)
	case  3: // - CAST5 (128 bit key, as per [RFC2144])
		return 8;
	case  4: // - Blowfish (128 bit key, 16 rounds) [BLOWFISH]
	case  7: // - AES with 128-bit key [AES]
	case  8: // - AES with 192-bit key
	case  9: // - AES with 256-bit key
		return 16;
	case 10: // - Twofish with 256-bit key [TWOFISH]
		return 32;	    		
	default:
		return 0;
	}
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
	return new openpgp_type_mpi().create(randomBits).toBigInteger();
},

getRandomBigIntegerInRange: function(min, max) {
	if (max.compareTo(min) <= 0)
		return;
	var range = max.subtract(min);
	var r = openpgp_crypto_getRandomBigInteger(range.bitLength());
	while (r > range) {
		r = openpgp_crypto_getRandomBigInteger(range.bitLength());
	}
	return min.add(r);
},


//This is a test method to ensure that encryption/decryption with a given 1024bit RSAKey object functions as intended
testRSA: function(key){
	debugger;
    var rsa = new RSA();
	var mpi = new openpgp_type_mpi();
	mpi.create(openpgp_encoding_eme_pkcs1_encode('ABABABAB', 128));
	var msg = rsa.encrypt(mpi.toBigInteger(),key.ee,key.n);
	var result = rsa.decrypt(msg, key.d, key.p, key.q, key.u);
},

/**
 * @typedef {Object} openpgp_keypair
 * @property {openpgp_packet_keymaterial} privateKey 
 * @property {openpgp_packet_keymaterial} publicKey
 */

/**
 * Calls the necessary crypto functions to generate a keypair. 
 * Called directly by openpgp.js
 * @param {Integer} keyType Follows OpenPGP algorithm convention.
 * @param {Integer} numBits Number of bits to make the key to be generated
 * @return {openpgp_keypair}
 */
generateKeyPair: function(keyType, numBits, passphrase, s2kHash, symmetricEncryptionAlgorithm){
	var privKeyPacket;
	var publicKeyPacket;
	var d = new Date();
	d = d.getTime()/1000;
	var timePacket = String.fromCharCode(Math.floor(d/0x1000000%0x100)) + String.fromCharCode(Math.floor(d/0x10000%0x100)) + String.fromCharCode(Math.floor(d/0x100%0x100)) + String.fromCharCode(Math.floor(d%0x100));
	switch(keyType){
	case 1:
	    var rsa = new RSA();
	    var key = rsa.generate(numBits,"10001");
	    privKeyPacket = new openpgp_packet_keymaterial().write_private_key(keyType, key, passphrase, s2kHash, symmetricEncryptionAlgorithm, timePacket);
	    publicKeyPacket =  new openpgp_packet_keymaterial().write_public_key(keyType, key, timePacket);
	    break;
	default:
		util.print_error("Unknown keytype "+keyType)
	}
	return {privateKey: privKeyPacket, publicKey: publicKeyPacket};
}

}
