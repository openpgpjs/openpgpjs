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

var publicKey = require('./public_key.js'),
	enums = require('../enums.js'),
	util = require('../util'),
	crypto = require('../crypto'),
	type_mpi = require('../type/mpi.js'),
	type_s2k = require('../type/s2k.js');

/**
 * @class
 * @classdesc Implementation of the Key Material Packet (Tag 5,6,7,14)
 *   
 * RFC4480 5.5:
 * A key material packet contains all the information about a public or
 * private key.  There are four variants of this packet type, and two
 * major versions.  Consequently, this section is complex.
 */
function packet_secret_key() {
	publicKey.call(this);

	this.encrypted = null;


	function get_hash_len(hash) {
		if(hash == 'sha1')
			return 20;
		else
			return 2;
	}

	function get_hash_fn(hash) {
		if(hash == 'sha1')
			return crypto.hash.sha1;
		else
			return function(c) {
					return util.writeNumber(util.calc_checksum(c), 2);
				}
	}

	// Helper function
	function parse_cleartext_mpi(hash_algorithm, cleartext, algorithm) {
		var hashlen = get_hash_len(hash_algorithm),
			hashfn = get_hash_fn(hash_algorithm);

		var hashtext = cleartext.substr(cleartext.length - hashlen);
		cleartext = cleartext.substr(0, cleartext.length - hashlen);

		var hash = hashfn(cleartext);

		if(hash != hashtext)
			throw new Error("Hash mismatch.");

		var mpis = crypto.getPrivateMpiCount(algorithm);

		var j = 0;
		var mpi = [];

		for(var i = 0; i < mpis && j < cleartext.length; i++) {
			mpi[i] = new type_mpi();
			j += mpi[i].read(cleartext.substr(j));
		}

		return mpi;
	}

	function write_cleartext_mpi(hash_algorithm, algorithm, mpi) {
		var bytes= '';
		var discard = crypto.getPublicMpiCount(algorithm);

		for(var i = discard; i < mpi.length; i++) {
			bytes += mpi[i].write();
		}


		bytes += get_hash_fn(hash_algorithm)(bytes);
		
		return bytes;
	}
		

	// 5.5.3.  Secret-Key Packet Formats
	
	/**
	 * Internal parser for private keys as specified in RFC 4880 section 5.5.3
	 * @param {String} bytes Input string to read the packet from
	 * @param {Integer} position Start position for the parser
	 * @param {Integer} len Length of the packet or remaining length of bytes
	 * @return {Object} This object with attributes set by the parser
	 */
	this.read = function(bytes) {
	    // - A Public-Key or Public-Subkey packet, as described above.
		var len = this.readPublicKey(bytes);

	    bytes = bytes.substr(len);

		
	    // - One octet indicating string-to-key usage conventions.  Zero
	    //   indicates that the secret-key data is not encrypted.  255 or 254
	    //   indicates that a string-to-key specifier is being given.  Any
	    //   other value is a symmetric-key encryption algorithm identifier.
	    var isEncrypted = bytes[0].charCodeAt();

		if(isEncrypted) {
			this.encrypted = bytes;
		} else {
	
			// - Plain or encrypted multiprecision integers comprising the secret
			//   key data.  These algorithm-specific fields are as described
			//   below.

			this.mpi = this.mpi.concat(parse_cleartext_mpi('mod', bytes.substr(1),
				this.algorithm));
		}    

	}
	
	/*
     * Creates an OpenPGP key packet for the given key. much 
	 * TODO in regards to s2k, subkeys.
     * @param {Integer} keyType Follows the OpenPGP algorithm standard, 
	 * IE 1 corresponds to RSA.
     * @param {RSA.keyObject} key
     * @param passphrase
     * @param s2kHash
     * @param symmetricEncryptionAlgorithm
     * @param timePacket
     * @return {Object} {body: [string]OpenPGP packet body contents, 
		header: [string] OpenPGP packet header, string: [string] header+body}
     */
    this.write = function() {
		var bytes = this.writePublicKey();

		if(!this.encrypted) {
			bytes += String.fromCharCode(0);
			
			bytes += write_cleartext_mpi('mod', this.algorithm, this.mpi);
		} else {
			bytes += this.encrypted;
		}

		return bytes;
	}
			



	/** Encrypt the payload. By default, we use aes256 and iterated, salted string
	 * to key specifier
	 * @param {String} passphrase
	 */
    this.encrypt = function(passphrase) {

		var s2k = new type_s2k(),
			symmetric = 'aes256',
			cleartext = write_cleartext_mpi('sha1', this.algorithm, this.mpi),
			key = produceEncryptionKey(s2k, passphrase, symmetric),
			blockLen = crypto.getBlockLength(symmetric),
			iv = crypto.random.getRandomBytes(blockLen);


		this.encrypted = '';
		this.encrypted += String.fromCharCode(254);
		this.encrypted += String.fromCharCode(enums.write(enums.symmetric, symmetric));
		this.encrypted += s2k.write();
		this.encrypted += iv;


		var fn;

		switch(symmetric) {
		case 'cast5':
			fn = crypto.cipher.cast5;
			break;
		case 'aes128':
		case 'aes192':
		case 'aes256':
    		var fn = function(block,key) {
    		    	return crypto.cipher.aes.encrypt(util.str2bin(block),key);
    			}

			key = new crypto.cipher.aes.keyExpansion(key);
			break;

		default:
			throw new Error("Unsupported symmetric encryption algorithm.");
		}

		console.log(cleartext);

		this.encrypted += crypto.cfb.normalEncrypt(fn, iv.length, key, cleartext, iv);
    }

	function produceEncryptionKey(s2k, passphrase, algorithm) {
		return s2k.produce_key(passphrase,
			crypto.getKeyLength(algorithm));
	}

	/**
	 * Decrypts the private key MPIs which are needed to use the key.
	 * openpgp_packet_keymaterial.hasUnencryptedSecretKeyData should be 
	 * false otherwise
	 * a call to this function is not needed
	 * 
	 * @param {String} str_passphrase The passphrase for this private key 
	 * as string
	 * @return {Boolean} True if the passphrase was correct; false if not
	 */
	this.decrypt = function(passphrase) {
		if (!this.encrypted)
			return;

		var i = 0,
			symmetric,
			key;

		var s2k_usage = this.encrypted[i++].charCodeAt();

	    // - [Optional] If string-to-key usage octet was 255 or 254, a one-
	    //   octet symmetric encryption algorithm.
	    if (s2k_usage == 255 || s2k_usage == 254) {
	    	symmetric = this.encrypted[i++].charCodeAt();
			symmetric = enums.read(enums.symmetric, symmetric);
	     
			// - [Optional] If string-to-key usage octet was 255 or 254, a
			//   string-to-key specifier.  The length of the string-to-key
			//   specifier is implied by its type, as described above.
	    	var s2k = new type_s2k();
	    	i += s2k.read(this.encrypted.substr(i));

			key = produceEncryptionKey(s2k, passphrase, symmetric);
	    } else {
			symmetric = s2k_usage;
			symmetric = enums.read(enums.symmetric, symmetric);
			key = crypto.hash.md5(passphrase);
		}

	    
	    // - [Optional] If secret data is encrypted (string-to-key usage octet
	    //   not zero), an Initial Vector (IV) of the same length as the
	    //   cipher's block size.
		var iv = this.encrypted.substr(i, 
			crypto.getBlockLength(symmetric));

		i += iv.length;

		var cleartext,
			ciphertext = this.encrypted.substr(i);

    	switch (symmetric) {
	    case  'idea': // - IDEA [IDEA]
			throw new Error("IDEA is not implemented.");
	    	return false;
    	case  'des': // - TripleDES (DES-EDE, [SCHNEIER] [HAC] - 168 bit key derived from 192)
    		cleartext = crypto.cfb.normal_decrypt(function(block, key) {
    			return crypto.cipher.des(key, block,1,null,0);
    		}, iv.length, key, ciphertext, iv);
    		break;
    	case  'cast5': // - CAST5 (128 bit key, as per [RFC2144])
    		cleartext = crypto.cfb.normalDecrypt(
				function(block, key) {
					var cast5 = new crypto.cipher.cast5.castClass();
					cast5.setKey(key);
					return cast5.encrypt(util.str2bin(block)); 
				}
			, iv.length, 
			util.str2bin(key.substring(0,16)), ciphertext, iv);
    		break;
	    case  'blowfish': // - Blowfish (128 bit key, 16 rounds) [BLOWFISH]
	    	cleartext = normal_cfb_decrypt(function(block, key) {
    			var blowfish = new Blowfish(key);
        		return blowfish.encrypt(block); 
    		}, iv.length, key, ciphertext, iv);
    		break;
	    case  'aes128': // - AES with 128-bit key [AES]
    	case  'aes192': // - AES with 192-bit key
    	case  'aes256': // - AES with 256-bit key
    		cleartext = crypto.cfb.normalDecrypt(function(block,key){
    		    	return crypto.cipher.aes.encrypt(util.str2bin(block),key);
    			},
    			iv.length, new crypto.cipher.aes.keyExpansion(key), 
					ciphertext, iv);
	    	break;
    	case 'twofish': // - Twofish with 256-bit key [TWOFISH]
			throw new Error("Twofish is not implemented.");
	    	return false;
    	default:
			throw new Error("Unknown symmetric algorithm.");
    		return false;
    	}
 
		var hash = s2k_usage == 254 ?
			'sha1' :
			'mod';

   	
		this.mpi = this.mpi.concat(parse_cleartext_mpi(hash, cleartext,
			this.algorithm));
	}
	
}

packet_secret_key.prototype = new publicKey;

module.exports = packet_secret_key;
