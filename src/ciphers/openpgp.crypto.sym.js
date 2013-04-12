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
function openpgp_crypto_symmetricEncrypt(prefixrandom, algo, key, data, openpgp_cfb) {
	switch(algo) {
		case 0: // Plaintext or unencrypted data
			return data; // blockcipherencryptfn, plaintext, block_size, key
		case 2: // TripleDES (DES-EDE, [SCHNEIER] [HAC] - 168 bit key derived from 192)
			return openpgp_cfb_encrypt(prefixrandom, desede, data,8,key, openpgp_cfb).substring(0, data.length + 10);
		case 3: // CAST5 (128 bit key, as per [RFC2144])
			return openpgp_cfb_encrypt(prefixrandom, cast5_encrypt, data,8,key, openpgp_cfb).substring(0, data.length + 10);
		case 4: // Blowfish (128 bit key, 16 rounds) [BLOWFISH]
			return openpgp_cfb_encrypt(prefixrandom, BFencrypt, data,8,key, openpgp_cfb).substring(0, data.length + 10);
		case 7: // AES with 128-bit key [AES]
		case 8: // AES with 192-bit key
		case 9: // AES with 256-bit key
			return openpgp_cfb_encrypt(prefixrandom, AESencrypt, data, 16, keyExpansion(key), openpgp_cfb).substring(0, data.length + 18);
		case 10: // Twofish with 256-bit key [TWOFISH]
			return openpgp_cfb_encrypt(prefixrandom, TFencrypt, data,16, key, openpgp_cfb).substring(0, data.length + 18);
		case 1: // IDEA [IDEA]
			util.print_error("IDEA Algorithm not implemented");
			return null;
		default:
			return null;
	}
}

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
function openpgp_crypto_symmetricDecrypt(algo, key, data, openpgp_cfb) {
	util.print_debug_hexstr_dump("openpgp_crypto_symmetricDecrypt:\nalgo:"+algo+"\nencrypteddata:",data);
	var n = 0;
	if (!openpgp_cfb)
		n = 2;
	switch(algo) {
	case 0: // Plaintext or unencrypted data
		return data;
	case 2: // TripleDES (DES-EDE, [SCHNEIER] [HAC] - 168 bit key derived from 192)
		return openpgp_cfb_decrypt(desede, 8, key, data, openpgp_cfb).substring(n, (data.length+n)-10);
	case 3: // CAST5 (128 bit key, as per [RFC2144])
		return openpgp_cfb_decrypt(cast5_encrypt, 8, key, data, openpgp_cfb).substring(n, (data.length+n)-10);
	case 4: // Blowfish (128 bit key, 16 rounds) [BLOWFISH]
		return openpgp_cfb_decrypt(BFencrypt, 8, key, data, openpgp_cfb).substring(n, (data.length+n)-10);
	case 7: // AES with 128-bit key [AES]
	case 8: // AES with 192-bit key
	case 9: // AES with 256-bit key
		return openpgp_cfb_decrypt(AESencrypt, 16, keyExpansion(key), data, openpgp_cfb).substring(n, (data.length+n)-18);
	case 10: // Twofish with 256-bit key [TWOFISH]
		var result = openpgp_cfb_decrypt(TFencrypt, 16, key, data, openpgp_cfb).substring(n, (data.length+n)-18);
		return result;
	case 1: // IDEA [IDEA]
		util.print_error(""+ (algo == 1 ? "IDEA Algorithm not implemented" : "Twofish Algorithm not implemented"));
		return null;
	default:
	}
	return null;
}
