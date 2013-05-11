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

// The GPG4Browsers symmetric crypto interface

var cfb = require('./cfb.js'),
	cipher = require('./cipher');

module.exports = {

/**
 * Symmetrically encrypts data using prefixedrandom, a key with length 
 * depending on the algorithm in openpgp_cfb mode with or without resync
 * (MDC style)
 * @param {String} prefixrandom Secure random bytes as string in 
 * length equal to the block size of the algorithm used (use 
 * openpgp_crypto_getPrefixRandom(algo) to retrieve that string
 * @param {Integer} algo Algorithm to use (see RFC4880 9.2)
 * @param {String} key Key as string. length is depending on the algorithm used
 * @param {String} data Data to encrypt
 * @param {Boolean} openpgp_cfb
 * @return {String} Encrypted data
 */
encrypt: function (prefixrandom, algo, key, data, openpgp_cfb) {
	switch(algo) {
		case 'plaintext': // Plaintext or unencrypted data
			return data; // blockcipherencryptfn, plaintext, block_size, key
		case 'des': // TripleDES (DES-EDE, [SCHNEIER] [HAC] - 168 bit key derived from 192)
			return cfb.encrypt(prefixrandom, cipher.des, data,8,key, openpgp_cfb).substring(0, data.length + 10);
		case 'cast5': // CAST5 (128 bit key, as per [RFC2144])
			return cfb.encrypt(prefixrandom, cipher.cast5, data,8,key, openpgp_cfb).substring(0, data.length + 10);
		case 'blowfish': // Blowfish (128 bit key, 16 rounds) [BLOWFISH]
			return cfb.encrypt(prefixrandom, cipher.blowfish, data,8,key, openpgp_cfb).substring(0, data.length + 10);
		case 'aes128': // AES with 128-bit key [AES]
		case 'aes192': // AES with 192-bit key
		case 'aes256': // AES with 256-bit key
			return cfb.encrypt(prefixrandom, cipher.aes.encrypt, data, 16, cipher.aes.keyExpansion(key), openpgp_cfb).substring(0, data.length + 18);
		case 'twofish': // Twofish with 256-bit key [TWOFISH]
			return cfb.encrypt(prefixrandom, cipher.twofish, data,16, key, openpgp_cfb).substring(0, data.length + 18);
		default:
			throw new Error('Invalid algorithm.');
	}
},

/**
 * Symmetrically decrypts data using a key with length depending on the
 * algorithm in openpgp_cfb mode with or without resync (MDC style)
 * @param {Integer} algo Algorithm to use (see RFC4880 9.2)
 * @param {String} key Key as string. length is depending on the algorithm used
 * @param {String} data Data to be decrypted
 * @param {Boolean} openpgp_cfb If true use the resync (for encrypteddata); 
 * otherwise use without the resync (for MDC encrypted data)
 * @return {String} Plaintext data
 */
decrypt: function (algo, key, data, openpgp_cfb) {
	var n = 0;
	if (!openpgp_cfb)
		n = 2;
	switch(algo) {
	case 'plaintext': // Plaintext or unencrypted data
		return data;
	case 'des': // TripleDES (DES-EDE, [SCHNEIER] [HAC] - 168 bit key derived from 192)
		return cfb.decrypt(cipher.des, 8, key, data, openpgp_cfb).substring(n, (data.length+n)-10);
	case 'cast5': // CAST5 (128 bit key, as per [RFC2144])
		return cfb.decrypt(cipher.cast5, 8, key, data, openpgp_cfb).substring(n, (data.length+n)-10);
	case 'blowfish': // Blowfish (128 bit key, 16 rounds) [BLOWFISH]
		return cfb.decrypt(cipher.blowfish, 8, key, data, openpgp_cfb).substring(n, (data.length+n)-10);
	case 'aes128': // AES with 128-bit key [AES]
	case 'aes192': // AES with 192-bit key
	case 'aes256': // AES with 256-bit key
		return cfb.decrypt(cipher.aes.encrypt, 16, cipher.aes.keyExpansion(key), data, openpgp_cfb).substring(n, (data.length+n)-18);
	case 'twofish': // Twofish with 256-bit key [TWOFISH]
		var result = cfb.decrypt(cipher.twofish, 16, key, data, openpgp_cfb).substring(n, (data.length+n)-18);
		return result;
	default:
		throw new Error('Invalid algorithm');
	}
}

}
