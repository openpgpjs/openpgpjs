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

/**
 * @class
 * @classdesc Implementation of the Key Material Packet (Tag 5,6,7,14)
 *   
 * RFC4480 5.5:
 * A key material packet contains all the information about a public or
 * private key.  There are four variants of this packet type, and two
 * major versions.  Consequently, this section is complex.
 */
function openpgp_packet_secret_key() {
	openpgp_packet_public_key.call(this);

	this.tag = 5;
	this.encrypted = null;


	function get_hash_len(hash) {
		if(hash == openpgp.hash.sha1)
			return 20;
		else
			return 2;
	}

	function get_hash_fn(hash) {
		if(hash == openpgp.hash.sha1)
			return str_sha1;
		else
			return function(c) {
					return openpgp_packet_number_write(util.calc_checksum(c), 2);
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

		var mpis = openpgp_crypto_getPrivateMpiCount(algorithm);

		var j = 0;
		var mpi = [];
		for(var i = 0; i < mpis && j < cleartext.length; i++) {
			mpi[i] = new openpgp_type_mpi();
			j += mpi[i].read(cleartext.substr(j));
		}

		return mpi;
	}

	function write_cleartext_mpi(hash_algorithm, mpi) {
		var bytes= '';
		var discard = openpgp_crypto_getPublicMpiCount(this.algorithm);

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
			
			bytes += write_cleartext_mpi('mod', this.mpi);
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

		var s2k = new openpgp_type_s2k(),
			symmetric = openpgp.symmetric.aes256,
			cleartext = write_cleartext_mpi(openpgp.hash.sha1, this.mpi),
			key = produceEncryptionKey(s2k, passphrase, symmetric),
			blockLen = openpgp_crypto_getBlockLength(symmetric),
			iv = openpgp_crypto_getRandomBytes(blockLen);


		this.encrypted = '';
		this.encrypted += String.fromCharCode(254);
		this.encrypted += String.fromCharCode(symmetric);
		this.encrypted += s2k.write();
		this.encrypted += iv;

		console.log(cleartext);

		switch(symmetric) {
		case 3:
			this.encrypted += normal_cfb_encrypt(function(block, key) {
				var cast5 = new openpgp_symenc_cast5();
				cast5.setKey(key);
				return cast5.encrypt(util.str2bin(block)); 
			}, iv.length, key, cleartext, iv);
			break;
		case 7:
		case 8:
		case 9:
    		var fn = function(block,key) {
    		    	return AESencrypt(util.str2bin(block),key);
    			}
			this.encrypted += normal_cfb_encrypt(fn,
					iv.length, new keyExpansion(key), cleartext, iv);
			break;
		default:
			throw new Error("Unsupported symmetric encryption algorithm.");
		}
    }

	function produceEncryptionKey(s2k, passphrase, algorithm) {
		return s2k.produce_key(passphrase,
			openpgp_crypto_getKeyLength(algorithm));
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
	     
			// - [Optional] If string-to-key usage octet was 255 or 254, a
			//   string-to-key specifier.  The length of the string-to-key
			//   specifier is implied by its type, as described above.
	    	var s2k = new openpgp_type_s2k();
	    	i += s2k.read(this.encrypted.substr(i));

			key = produceEncryptionKey(s2k, passphrase, symmetric);
	    } else {
			symmetric = s2k_usage;
			key = MD5(passphrase);
		}
	    
	    // - [Optional] If secret data is encrypted (string-to-key usage octet
	    //   not zero), an Initial Vector (IV) of the same length as the
	    //   cipher's block size.
		var iv = this.encrypted.substr(i, 
			openpgp_crypto_getBlockLength(symmetric));

		i += iv.length;

		var cleartext,
			ciphertext = this.encrypted.substr(i);


    	switch (symmetric) {
	    case  1: // - IDEA [IDEA]
			throw new Error("IDEA is not implemented.");
	    	return false;
    	case  2: // - TripleDES (DES-EDE, [SCHNEIER] [HAC] - 168 bit key derived from 192)
    		cleartext = normal_cfb_decrypt(function(block, key) {
    			return des(key, block,1,null,0);
    		}, iv.length, key, ciphertext, iv);
    		break;
    	case  3: // - CAST5 (128 bit key, as per [RFC2144])
    		cleartext = normal_cfb_decrypt(function(block, key) {
        		var cast5 = new openpgp_symenc_cast5();
        		cast5.setKey(key);
        		return cast5.encrypt(util.str2bin(block)); 
    		}, iv.length, util.str2bin(key.substring(0,16)), ciphertext, iv);
    		break;
	    case  4: // - Blowfish (128 bit key, 16 rounds) [BLOWFISH]
	    	cleartext = normal_cfb_decrypt(function(block, key) {
    			var blowfish = new Blowfish(key);
        		return blowfish.encrypt(block); 
    		}, iv.length, key, ciphertext, iv);
    		break;
	    case  7: // - AES with 128-bit key [AES]
    	case  8: // - AES with 192-bit key
    	case  9: // - AES with 256-bit key
    		cleartext = normal_cfb_decrypt(function(block,key){
    		    	return AESencrypt(util.str2bin(block),key);
    			},
    			iv.length, new keyExpansion(key), 
					ciphertext, iv);
	    	break;
    	case 10: // - Twofish with 256-bit key [TWOFISH]
			throw new Error("Twofish is not implemented.");
	    	return false;
    	case  5: // - Reserved
    	case  6: // - Reserved
    	default:
			throw new Error("Unknown symmetric algorithm.");
    		return false;
    	}
 
		var hash;
		if(s2k_usage == 254)
			hash = openpgp.hash.sha1;
		else
			hash = 'mod';

   	
		this.mpi = this.mpi.concat(parse_cleartext_mpi(hash, cleartext,
			this.algorithm));
	}
	
	/**
	 * Calculates the key id of they key 
	 * @return {String} A 8 byte key id
	 */
	this.getKeyId = function() {
		if (this.version == 4) {
			var f = this.getFingerprint();
			return f.substring(12,20);
		} else if (this.version == 3 && this.publicKeyAlgorithm > 0 && this.publicKeyAlgorithm < 4) {
			var key_id = this.MPIs[0].substring((this.MPIs[0].mpiByteLength-8));
			util.print_debug("openpgp.msg.publickey read_nodes:\n"+"V3 key ID: "+key_id);
			return key_id;
		}
	}
	
	/**
	 * Calculates the fingerprint of the key
	 * @return {String} A string containing the fingerprint
	 */
	this.getFingerprint = function() {
		if (this.version == 4) {
			tohash = String.fromCharCode(0x99)+ String.fromCharCode(((this.packetdata.length) >> 8) & 0xFF) 
				+ String.fromCharCode((this.packetdata.length) & 0xFF)+this.packetdata;
			util.print_debug("openpgp.msg.publickey creating subkey fingerprint by hashing:"+util.hexstrdump(tohash)+"\npublickeyalgorithm: "+this.publicKeyAlgorithm);
			return str_sha1(tohash, tohash.length);
		} else if (this.version == 3 && this.publicKeyAlgorithm > 0 && this.publicKeyAlgorithm < 4) {
			return MD5(this.MPIs[0].MPI);
		}
	}
}

openpgp_packet_secret_key.prototype = new openpgp_packet_public_key();


function openpgp_packet_secret_subkey() {
	openpgp_packet_secret_key.call(this);
	this.tag = 7;
}

