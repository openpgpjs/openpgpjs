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
	this.tag = 5;
	this.public_key = new openpgp_packet_public_key();
	this.mpi = [];
	this.symmetric_algorithm = openpgp.symmetric.plaintext;
	this.hash_algorithm = openpgp.hash.sha1;
	this.s2k = null;
	this.encrypted = null;
	this.iv = null;


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
			throw "Hash mismatch!";

		var mpis = openpgp_crypto_getPrivateMpiCount(algorithm);

		var j = 0;
		var mpi = [];
		for(var i = 0; i < mpis && j < cleartext.length; i++) {
			mpi[i] = new openpgp_type_mpi();
			j += mpi[i].read(cleartext.substr(j));
		}

		return mpi;
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
		var len = this.public_key.read(bytes);

	    bytes = bytes.substr(len);

		
	    // - One octet indicating string-to-key usage conventions.  Zero
	    //   indicates that the secret-key data is not encrypted.  255 or 254
	    //   indicates that a string-to-key specifier is being given.  Any
	    //   other value is a symmetric-key encryption algorithm identifier.
	    var s2k_usage = bytes[0].charCodeAt();
	    
		var i = 1;

	    // - [Optional] If string-to-key usage octet was 255 or 254, a one-
	    //   octet symmetric encryption algorithm.
	    if (s2k_usage == 255 || s2k_usage == 254) {
	    	this.symmetric_algorithm = bytes[i++].charCodeAt();
	     
			// - [Optional] If string-to-key usage octet was 255 or 254, a
			//   string-to-key specifier.  The length of the string-to-key
			//   specifier is implied by its type, as described above.
	    	this.s2k = new openpgp_type_s2k();
	    	i += this.s2k.read(bytes.substr(i));
	    }
	    
	    // - [Optional] If secret data is encrypted (string-to-key usage octet
	    //   not zero), an Initial Vector (IV) of the same length as the
	    //   cipher's block size.

	    if (s2k_usage != 0 && s2k_usage != 255 &&
	    		s2k_usage != 254) {
	    	this.symmetric_algorithm = s2k_usage;
	    }

	    if (s2k_usage != 0 && this.s2k.type != 1001) {
	    	this.iv = bytes.substr(i, 
				openpgp_crypto_getBlockLength(this.symmetric_algorithm));

	    	i += this.iv.length;
	    }

		if(s2k_usage == 254)
			this.hash_algorithm = openpgp.hash.sha1;
		else
			this.hash_algorithm = 'checksum';

	    // - Plain or encrypted multiprecision integers comprising the secret
	    //   key data.  These algorithm-specific fields are as described
	    //   below.

      // s2k type 1001 corresponds to GPG specific extension without primary key secrets
      // http://www.gnupg.org/faq/GnuPG-FAQ.html#how-can-i-use-gnupg-in-an-automated-environment
	    if (s2k_usage != 0 && this.s2k.type == 1001) {
	    	this.mpi = null;
	    	this.encrypted = null;

	    } else if (s2k_usage != 0) {
	    	this.encrypted = bytes.substr(i);

	    } else {
			this.mpi = parse_cleartext_mpi(this.hash_algorithm, bytes.substr(i),
				this.public_key.algorithm);
	    }
	}
	
	/*
     * Creates an OpenPGP key packet for the given key. much 
	 * TODO in regards to s2k, subkeys.
     * @param {Integer} keyType Follows the OpenPGP algorithm standard, 
	 * IE 1 corresponds to RSA.
     * @param {RSA.keyObject} key
     * @param password
     * @param s2kHash
     * @param symmetricEncryptionAlgorithm
     * @param timePacket
     * @return {Object} {body: [string]OpenPGP packet body contents, 
		header: [string] OpenPGP packet header, string: [string] header+body}
     */
    this.write = function() {
		var bytes = this.public_key.write();

		if(this.encrypted == null) {
			bytes += String.fromCharCode(0);
			
			var mpi = '';
			for(var i in this.mpi) {
				mpi += this.mpi[i].write();
			}

			bytes += mpi;

			// TODO check the cheksum!
			bytes += openpgp_packet_number_write(util.calc_checksum(mpi), 2);
		} else if(this.s2k == null) {
			bytes += String.fromCharCode(this.symmetric_algorithm);
			bytes += this.encrypted;
		} else {
			bytes += String.fromCharCode(254);
			bytes += String.fromCharCode(this.symmetric_algorithm);
			bytes += this.s2k.write();
			bytes += this.encrypted;
		}

		return bytes;
	}
			



    this.encrypt = function(password) {


		switch(keyType){
		case 1:
		    body += String.fromCharCode(keyType);//public key algo
		    body += key.n.toMPI();
		    body += key.ee.toMPI();
		    var algorithmStart = body.length;
		    //below shows ske/s2k
		    if(password){
		        body += String.fromCharCode(254); //octet of 254 indicates s2k with SHA1
		        //if s2k == 255,254 then 1 octet symmetric encryption algo
		        body += String.fromCharCode(this.symmetric_algorithm);
		        //if s2k == 255,254 then s2k specifier
		        body += String.fromCharCode(3); //s2k salt+iter
		        body += String.fromCharCode(s2kHash);
		        //8 octet salt value
		        //1 octet count
		        var cleartext = key.d.toMPI() + key.p.toMPI() + key.q.toMPI() + key.u.toMPI();
		        var sha1Hash = str_sha1(cleartext);
   		        util.print_debug_hexstr_dump('write_private_key sha1: ',sha1Hash);
		        var salt = openpgp_crypto_getRandomBytes(8);
		        util.print_debug_hexstr_dump('write_private_key Salt: ',salt);
		        body += salt;
		        var c = 96; //c of 96 translates to count of 65536
		        body += String.fromCharCode(c);
		        util.print_debug('write_private_key c: '+ c);
		        var s2k = new openpgp_type_s2k();
		        var hashKey = s2k.write(3, s2kHash, password, salt, c);
		        //if s2k, IV of same length as cipher's block
		        switch(this.symmetric_algorithm){
		        case 3:
		            this.iv.length = 8;
		            this.iv = openpgp_crypto_getRandomBytes(this.iv.length);
            		ciphertextMPIs = normal_cfb_encrypt(function(block, key) {
                		var cast5 = new openpgp_symenc_cast5();
                		cast5.setKey(key);
                		return cast5.encrypt(util.str2bin(block)); 
            		}, this.iv.length, util.str2bin(hashKey.substring(0,16)), cleartext + sha1Hash, this.iv);
            		body += this.iv + ciphertextMPIs;
		            break;
		        case 7:
		        case 8:
		        case 9:
		            this.iv.length = 16;
		            this.iv = openpgp_crypto_getRandomBytes(this.iv.length);
		            ciphertextMPIs = normal_cfb_encrypt(AESencrypt,
            				this.iv.length, hashKey, cleartext + sha1Hash, this.iv);
            		body += this.iv + ciphertextMPIs;
	            	break;
		        }
		    }
		    else{
		        body += String.fromCharCode(0);//1 octet -- s2k, 0 for no s2k
		        body += key.d.toMPI() + key.p.toMPI() + key.q.toMPI() + key.u.toMPI();
		        var checksum = util.calc_checksum(key.d.toMPI() + key.p.toMPI() + key.q.toMPI() + key.u.toMPI());
        		body += String.fromCharCode(checksum/0x100) + String.fromCharCode(checksum%0x100);//DEPRECATED:s2k == 0, 255: 2 octet checksum, sum all octets%65536
        		util.print_debug_hexstr_dump('write_private_key basic checksum: '+ checksum);
		    }
		    break;
		default :
			body = "";
			util.print_error("openpgp.packet.keymaterial.js\n"+'error writing private key, unknown type :'+keyType);
        }
		var header = openpgp_packet.write_packet_header(tag,body.length);
		return {string: header+body , header: header, body: body};
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
		if (this.encrypted == null)
			return;

		// creating a key out of the passphrase
		var key = this.s2k.produce_key(passphrase,
			openpgp_crypto_getKeyLength(this.symmetric_algorithm));

		var cleartext = '';


    	switch (this.symmetric_algorithm) {
	    case  1: // - IDEA [IDEA]
	    	util.print_error("openpgp.packet.keymaterial.js\n"
				+"symmetric encryption algorithim: IDEA is not implemented");
	    	return false;
    	case  2: // - TripleDES (DES-EDE, [SCHNEIER] [HAC] - 168 bit key derived from 192)
    		cleartext = normal_cfb_decrypt(function(block, key) {
    			return des(key, block,1,null,0);
    		}, this.iv.length, key, this.encrypted, this.iv);
    		break;
    	case  3: // - CAST5 (128 bit key, as per [RFC2144])
    		cleartext = normal_cfb_decrypt(function(block, key) {
        		var cast5 = new openpgp_symenc_cast5();
        		cast5.setKey(key);
        		return cast5.encrypt(util.str2bin(block)); 
    		}, this.iv.length, util.str2bin(key.substring(0,16)), this.encrypted, this.iv);
    		break;
	    case  4: // - Blowfish (128 bit key, 16 rounds) [BLOWFISH]
	    	cleartext = normal_cfb_decrypt(function(block, key) {
    			var blowfish = new Blowfish(key);
        		return blowfish.encrypt(block); 
    		}, this.iv.length, key, this.encrypted, this.iv);
    		break;
	    case  7: // - AES with 128-bit key [AES]
    	case  8: // - AES with 192-bit key
    	case  9: // - AES with 256-bit key
    		cleartext = normal_cfb_decrypt(function(block,key){
    		    	return AESencrypt(util.str2bin(block),key);
    			},
    			this.iv.length, keyExpansion(key), 
					this.encrypted, this.iv);
	    	break;
    	case 10: // - Twofish with 256-bit key [TWOFISH]
    		util.print_error("openpgp.packet.keymaterial.js\n"+"Key material is encrypted with twofish: not implemented");   		
	    	return false;
    	case  5: // - Reserved
    	case  6: // - Reserved
    	default:
    		util.print_error("openpgp.packet.keymaterial.js\n"+"unknown encryption algorithm for secret key :"+this.symmetric_algorithm);
    		return false;
    	}
    	
    	if (cleartext == null) {
    		util.print_error("openpgp.packet.keymaterial.js\n"+"cleartext was null");
    		return false;
    	}
    	


		this.mpi = parse_cleartext_mpi(this.hash_algorithm, cleartext,
			this.public_key.algorithm);
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


function openpgp_packet_secret_subkey() {
	openpgp_packet_secret_key.call(this);
	this.tag = 7;
}


