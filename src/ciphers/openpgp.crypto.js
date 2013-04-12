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
 * Encrypts data using the specified public key multiprecision integers 
 * and the specified algorithm.
 * @param {Integer} algo Algorithm to be used (See RFC4880 9.1)
 * @param {openpgp_type_mpi[]} publicMPIs Algorithm dependent multiprecision integers
 * @param {openpgp_type_mpi} data Data to be encrypted as MPI
 * @return {(openpgp_type_mpi|openpgp_type_mpi[])} if RSA an openpgp_type_mpi; 
 * if elgamal encryption an array of two openpgp_type_mpi is returned; otherwise null
 */
function openpgp_crypto_asymetricEncrypt(algo, publicMPIs, data) {
	switch(algo) {
	case 1: // RSA (Encrypt or Sign) [HAC]
	case 2: // RSA Encrypt-Only [HAC]
	case 3: // RSA Sign-Only [HAC]
		var rsa = new RSA();
		var n = publicMPIs[0].toBigInteger();
		var e = publicMPIs[1].toBigInteger();
		var m = data.toBigInteger();
		return rsa.encrypt(m,e,n).toMPI();
	case 16: // Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
		var elgamal = new Elgamal();
		var p = publicMPIs[0].toBigInteger();
		var g = publicMPIs[1].toBigInteger();
		var y = publicMPIs[2].toBigInteger();
		var m = data.toBigInteger();
		return elgamal.encrypt(m,g,p,y);
	default:
		return null;
	}
}

/**
 * Decrypts data using the specified public key multiprecision integers of the private key,
 * the specified secretMPIs of the private key and the specified algorithm.
 * @param {Integer} algo Algorithm to be used (See RFC4880 9.1)
 * @param {openpgp_type_mpi[]} publicMPIs Algorithm dependent multiprecision integers 
 * of the public key part of the private key
 * @param {openpgp_type_mpi[]} secretMPIs Algorithm dependent multiprecision integers 
 * of the private key used
 * @param {openpgp_type_mpi} data Data to be encrypted as MPI
 * @return {BigInteger} returns a big integer containing the decrypted data; otherwise null
 */

function openpgp_crypto_asymetricDecrypt(algo, publicMPIs, secretMPIs, dataMPIs) {
	switch(algo) {
	case 1: // RSA (Encrypt or Sign) [HAC]  
	case 2: // RSA Encrypt-Only [HAC]
	case 3: // RSA Sign-Only [HAC]
		var rsa = new RSA();
		var d = secretMPIs[0].toBigInteger();
		var p = secretMPIs[1].toBigInteger();
		var q = secretMPIs[2].toBigInteger();
		var u = secretMPIs[3].toBigInteger();
		var m = dataMPIs[0].toBigInteger();
		return rsa.decrypt(m, d, p, q, u);
	case 16: // Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
		var elgamal = new Elgamal();
		var x = secretMPIs[0].toBigInteger();
		var c1 = dataMPIs[0].toBigInteger();
		var c2 = dataMPIs[1].toBigInteger();
		var p = publicMPIs[0].toBigInteger();
		return elgamal.decrypt(c1,c2,p,x);
	default:
		return null;
	}
	
}

/**
 * generate random byte prefix as string for the specified algorithm
 * @param {Integer} algo Algorithm to use (see RFC4880 9.2)
 * @return {String} Random bytes with length equal to the block
 * size of the cipher
 */
function openpgp_crypto_getPrefixRandom(algo) {
	switch(algo) {
	case 2:
	case 3:
	case 4:
		return openpgp_crypto_getRandomBytes(8);
	case 7:
	case 8:
	case 9:
	case 10:
		return openpgp_crypto_getRandomBytes(16);
	default:
		return null;
	}
}

/**
 * retrieve the MDC prefixed bytes by decrypting them
 * @param {Integer} algo Algorithm to use (see RFC4880 9.2)
 * @param {String} key Key as string. length is depending on the algorithm used
 * @param {String} data Encrypted data where the prefix is decrypted from
 * @return {String} Plain text data of the prefixed data
 */
function openpgp_crypto_MDCSystemBytes(algo, key, data) {
	util.print_debug_hexstr_dump("openpgp_crypto_symmetricDecrypt:\nencrypteddata:",data);
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
		util.print_error(""+ (algo == 1 ? "IDEA Algorithm not implemented" : "Twofish Algorithm not implemented"));
		return null;
	default:
	}
	return null;
}
/**
 * Generating a session key for the specified symmetric algorithm
 * @param {Integer} algo Algorithm to use (see RFC4880 9.2)
 * @return {String} Random bytes as a string to be used as a key
 */
function openpgp_crypto_generateSessionKey(algo) {
	switch (algo) {
	case 2: // TripleDES (DES-EDE, [SCHNEIER] [HAC] - 168 bit key derived from 192)
	case 8: // AES with 192-bit key
		return openpgp_crypto_getRandomBytes(24); 
	case 3: // CAST5 (128 bit key, as per [RFC2144])
	case 4: // Blowfish (128 bit key, 16 rounds) [BLOWFISH]
	case 7: // AES with 128-bit key [AES]
		util.print_debug("length = 16:\n"+util.hexstrdump(openpgp_crypto_getRandomBytes(16)));
		return openpgp_crypto_getRandomBytes(16);
	case 9: // AES with 256-bit key
	case 10:// Twofish with 256-bit key [TWOFISH]
		return openpgp_crypto_getRandomBytes(32);
	}
	return null;
}

/**
 * 
 * @param {Integer} algo public Key algorithm
 * @param {Integer} hash_algo Hash algorithm
 * @param {openpgp_type_mpi[]} msg_MPIs Signature multiprecision integers
 * @param {openpgp_type_mpi[]} publickey_MPIs Public key multiprecision integers 
 * @param {String} data Data on where the signature was computed on.
 * @return {Boolean} true if signature (sig_data was equal to data over hash)
 */
function openpgp_crypto_verifySignature(algo, hash_algo, msg_MPIs, publickey_MPIs, data) {
	var calc_hash = openpgp_crypto_hashData(hash_algo, data);
	switch(algo) {
	case 1: // RSA (Encrypt or Sign) [HAC]  
	case 2: // RSA Encrypt-Only [HAC]
	case 3: // RSA Sign-Only [HAC]
		var rsa = new RSA();
		var n = publickey_MPIs[0].toBigInteger();
		var e = publickey_MPIs[1].toBigInteger();
		var x = msg_MPIs[0].toBigInteger();
		var dopublic = rsa.verify(x,e,n);
		var hash  = openpgp_encoding_emsa_pkcs1_decode(hash_algo,dopublic.toMPI().substring(2));
		if (hash == -1) {
			util.print_error("PKCS1 padding in message or key incorrect. Aborting...");
			return false;
		}
		return hash == calc_hash;
		
	case 16: // Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
		util.print_error("signing with Elgamal is not defined in the OpenPGP standard.");
		return null;
	case 17: // DSA (Digital Signature Algorithm) [FIPS186] [HAC]
		var dsa = new DSA();
		var s1 = msg_MPIs[0].toBigInteger();
		var s2 = msg_MPIs[1].toBigInteger();
		var p = publickey_MPIs[0].toBigInteger();
		var q = publickey_MPIs[1].toBigInteger();
		var g = publickey_MPIs[2].toBigInteger();
		var y = publickey_MPIs[3].toBigInteger();
		var m = data;
		var dopublic = dsa.verify(hash_algo,s1,s2,m,p,q,g,y);
		return dopublic.compareTo(s1) == 0;
	default:
		return null;
	}
	
}
   
/**
 * Create a signature on data using the specified algorithm
 * @param {Integer} hash_algo hash Algorithm to use (See RFC4880 9.4)
 * @param {Integer} algo Asymmetric cipher algorithm to use (See RFC4880 9.1)
 * @param {openpgp_type_mpi[]} publicMPIs Public key multiprecision integers 
 * of the private key 
 * @param {openpgp_type_mpi[]} secretMPIs Private key multiprecision 
 * integers which is used to sign the data
 * @param {String} data Data to be signed
 * @return {(String|openpgp_type_mpi)}
 */
function openpgp_crypto_signData(hash_algo, algo, publicMPIs, secretMPIs, data) {
	
	switch(algo) {
	case 1: // RSA (Encrypt or Sign) [HAC]  
	case 2: // RSA Encrypt-Only [HAC]
	case 3: // RSA Sign-Only [HAC]
		var rsa = new RSA();
		var d = secretMPIs[0].toBigInteger();
		var n = publicMPIs[0].toBigInteger();
		var m = openpgp_encoding_emsa_pkcs1_encode(hash_algo, data,publicMPIs[0].mpiByteLength);
		util.print_debug("signing using RSA");
		return rsa.sign(m, d, n).toMPI();
	case 17: // DSA (Digital Signature Algorithm) [FIPS186] [HAC]
		var dsa = new DSA();
		util.print_debug("DSA Sign: q size in Bytes:"+publicMPIs[1].getByteLength());
		var p = publicMPIs[0].toBigInteger();
		var q = publicMPIs[1].toBigInteger();
		var g = publicMPIs[2].toBigInteger();
		var y = publicMPIs[3].toBigInteger();
		var x = secretMPIs[0].toBigInteger();
		var m = data;
		var result = dsa.sign(hash_algo,m, g, p, q, x);
		util.print_debug("signing using DSA\n result:"+util.hexstrdump(result[0])+"|"+util.hexstrdump(result[1]));
		return result[0]+result[1];
	case 16: // Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
			util.print_debug("signing with Elgamal is not defined in the OpenPGP standard.");
			return null;
	default:
		return null;
	}	
}

/**
 * Create a hash on the specified data using the specified algorithm
 * @param {Integer} algo Hash algorithm type (see RFC4880 9.4)
 * @param {String} data Data to be hashed
 * @return {String} hash value
 */
function openpgp_crypto_hashData(algo, data) {
	var hash = null;
	switch(algo) {
	case 1: // - MD5 [HAC]
		hash = MD5(data);
		break;
	case 2: // - SHA-1 [FIPS180]
		hash = str_sha1(data);
		break;
	case 3: // - RIPE-MD/160 [HAC]
		hash = RMDstring(data);
		break;
	case 8: // - SHA256 [FIPS180]
		hash = str_sha256(data);
		break;
	case 9: // - SHA384 [FIPS180]
		hash = str_sha384(data);
		break;
	case 10:// - SHA512 [FIPS180]
		hash = str_sha512(data);
		break;
	case 11:// - SHA224 [FIPS180]
		hash = str_sha224(data);
	default:
		break;
	}
	return hash;
}

/**
 * Returns the hash size in bytes of the specified hash algorithm type
 * @param {Integer} algo Hash algorithm type (See RFC4880 9.4)
 * @return {Integer} Size in bytes of the resulting hash
 */
function openpgp_crypto_getHashByteLength(algo) {
	var hash = null;
	switch(algo) {
	case 1: // - MD5 [HAC]
		return 16;
	case 2: // - SHA-1 [FIPS180]
	case 3: // - RIPE-MD/160 [HAC]
		return 20;
	case 8: // - SHA256 [FIPS180]
		return 32;
	case 9: // - SHA384 [FIPS180]
		return 48
	case 10:// - SHA512 [FIPS180]
		return 64;
	case 11:// - SHA224 [FIPS180]
		return 28;
	}
	return null;
}

/**
 * Retrieve secure random byte string of the specified length
 * @param {Integer} length Length in bytes to generate
 * @return {String} Random byte string
 */
function openpgp_crypto_getRandomBytes(length) {
	var result = '';
	for (var i = 0; i < length; i++) {
		result += String.fromCharCode(openpgp_crypto_getSecureRandomOctet());
	}
	return result;
}

/**
 * Return a pseudo-random number in the specified range
 * @param {Integer} from Min of the random number
 * @param {Integer} to Max of the random number (max 32bit)
 * @return {Integer} A pseudo random number
 */
function openpgp_crypto_getPseudoRandom(from, to) {
	return Math.round(Math.random()*(to-from))+from;
}

/**
 * Return a secure random number in the specified range
 * @param {Integer} from Min of the random number
 * @param {Integer} to Max of the random number (max 32bit)
 * @return {Integer} A secure random number
 */
function openpgp_crypto_getSecureRandom(from, to) {
	var buf = new Uint32Array(1);
	window.crypto.getRandomValues(buf);
	var bits = ((to-from)).toString(2).length;
	while ((buf[0] & (Math.pow(2, bits) -1)) > (to-from))
		window.crypto.getRandomValues(buf);
	return from+(Math.abs(buf[0] & (Math.pow(2, bits) -1)));
}

function openpgp_crypto_getSecureRandomOctet() {
	var buf = new Uint32Array(1);
	window.crypto.getRandomValues(buf);
	return buf[0] & 0xFF;
}

/**
 * Create a secure random big integer of bits length
 * @param {Integer} bits Bit length of the MPI to create
 * @return {BigInteger} Resulting big integer
 */
function openpgp_crypto_getRandomBigInteger(bits) {
	if (bits < 0)
	   return null;
	var numBytes = Math.floor((bits+7)/8);

	var randomBits = openpgp_crypto_getRandomBytes(numBytes);
	if (bits % 8 > 0) {
		
		randomBits = String.fromCharCode(
						(Math.pow(2,bits % 8)-1) &
						randomBits.charCodeAt(0)) +
			randomBits.substring(1);
	}
	return new openpgp_type_mpi().create(randomBits).toBigInteger();
}

function openpgp_crypto_getRandomBigIntegerInRange(min, max) {
	if (max.compareTo(min) <= 0)
		return;
	var range = max.subtract(min);
	var r = openpgp_crypto_getRandomBigInteger(range.bitLength());
	while (r > range) {
		r = openpgp_crypto_getRandomBigInteger(range.bitLength());
	}
	return min.add(r);
}


//This is a test method to ensure that encryption/decryption with a given 1024bit RSAKey object functions as intended
function openpgp_crypto_testRSA(key){
	debugger;
    var rsa = new RSA();
	var mpi = new openpgp_type_mpi();
	mpi.create(openpgp_encoding_eme_pkcs1_encode('ABABABAB', 128));
	var msg = rsa.encrypt(mpi.toBigInteger(),key.ee,key.n);
	var result = rsa.decrypt(msg, key.d, key.p, key.q, key.u);
}

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
function openpgp_crypto_generateKeyPair(keyType, numBits, passphrase, s2kHash, symmetricEncryptionAlgorithm){
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
