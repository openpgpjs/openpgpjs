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
			var mpis = openpgp_crypto_getPrivateMpiCount(this.public_key.algorithm);
			this.mpi = [];

			for(var j = 0; j < mpis; j++) {
	    		this.mpi[j] = new openpgp_type_mpi();
	    		i += this.mpi[j].read(bytes.substr(i));
			}
	    	
	    	// checksum because s2k usage convention is 0
	        this.checksum = [];
		    this.checksum[0] = bytes[i++].charCodeAt();
		    this.checksum[1] = bytes[i++].charCodeAt();
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
			
			for(var i in this.mpi) {
				bytes += this.mpi[i].write();
			}

			// TODO check the cheksum!
			bytes += '00'
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
    	

    	if (this.hash_algorithm == openpgp.hash.sha1) {
    		var hash = str_sha1(cleartext.substring(0,cleartext.length - 20));

			if(hash != cleartext.substring(cleartext.length - 20))
				throw "Hash mismatch!";
			cleartext = cleartext.substr(0, cleartext.length - 20);
    	} else {
			var hash = util.calc_checksum(cleartext.substring(0, cleartext.length - 2));
			
			if(hash != cleartext.substring(cleartext.length -2))
				throw "Hash mismatch!";
			cleartext = cleartext.substr(0, cleartext.length - 2);
		}

		var mpis = openpgp_crypto_getPrivateMpiCount(this.public_key.algorithm);

		var j = 0;
		for(var i = 0; i < mpis && j < cleartext.length; i++) {
			this.mpi[i] = new openpgp_type_mpi();
			j += this.mpi[i].read(cleartext.substr(j));
		}
	}
	
	/**
	 * Generates Debug output
	 * @return String which gives some information about the keymaterial
	 */
	function toString() {
		var result = "";
		switch (this.tagType) {
		case 6:
			 result += '5.5.1.1. Public-Key Packet (Tag 6)\n'+
			   '    length:             '+this.packetLength+'\n'+
			   '    version:            '+this.version+'\n'+
			   '    creation time:      '+this.creationTime+'\n'+
			   '    expiration time:    '+this.expiration+'\n'+
			   '    publicKeyAlgorithm: '+this.publicKeyAlgorithm+'\n';
			break;
		case 14:
			result += '5.5.1.2. Public-Subkey Packet (Tag 14)\n'+
			   '    length:             '+this.packetLength+'\n'+
			   '    version:            '+this.version+'\n'+
			   '    creation time:      '+this.creationTime+'\n'+
			   '    expiration time:    '+this.expiration+'\n'+
			   '    publicKeyAlgorithm: '+this.publicKeyAlgorithm+'\n';
			break;
		case 5:
			result +='5.5.1.3. Secret-Key Packet (Tag 5)\n'+
			   '    length:             '+this.packetLength+'\n'+
			   '    version:            '+this.publicKey.version+'\n'+
			   '    creation time:      '+this.publicKey.creationTime+'\n'+
			   '    expiration time:    '+this.publicKey.expiration+'\n'+
			   '    publicKeyAlgorithm: '+this.publicKey.publicKeyAlgorithm+'\n';
			break;
		case 7:
			result += '5.5.1.4. Secret-Subkey Packet (Tag 7)\n'+
			   '    length:             '+this.packetLength+'\n'+
			   '    version[1]:         '+(this.version == 4)+'\n'+
			   '    creationtime[4]:    '+this.creationTime+'\n'+
			   '    expiration[2]:      '+this.expiration+'\n'+
			   '    publicKeyAlgorithm: '+this.publicKeyAlgorithm+'\n';
			break;
		default:
			result += 'unknown key material packet\n';
		}
		if (this.MPIs != null) {
			result += "Public Key MPIs:\n";
			for (var i = 0; i < this.MPIs.length; i++) {
      	  	result += this.MPIs[i].toString();
        	}
		}
		if (this.publicKey != null && this.publicKey.MPIs != null) {
			result += "Public Key MPIs:\n";
			for (var i = 0; i < this.publicKey.MPIs.length; i++) {
	      	  	result += this.publicKey.MPIs[i].toString();
        	}
		}
		if (this.mpi != null) {
			result += "Secret Key MPIs:\n";
			for (var i = 0; i < this.mpi.length; i++) {
		      	  result += this.mpi[i].toString();
		        }
		}
		
		if (this.subKeySignature != null)
			result += "subKey Signature:\n"+this.subKeySignature.toString();
		
		if (this.subKeyRevocationSignature != null )
			result += "subKey Revocation Signature:\n"+this.subKeyRevocationSignature.toString();
        return result;
	}
	
	/**
	 * Continue parsing packets belonging to the key material such as signatures
	 * @param {Object} parent_node The parent object
	 * @param {String} bytes Input string to read the packet(s) from
	 * @param {Integer} position Start position for the parser
	 * @param {Integer} len Length of the packet(s) or remaining length of bytes
	 * @return {Integer} Length of nodes read
	 */
	function read_nodes(parent_node, bytes, position, len) {
		this.parentNode = parent_node;
		if (this.tagType == 14) { // public sub-key packet
			var pos = position;
			var result = null;
			while (bytes.length != pos) {
				var l = bytes.length - pos;
				result = openpgp_packet.read_packet(bytes, pos, l);
				if (result == null) {
					util.print_error("openpgp.packet.keymaterial.js\n"+'[user_keymat_pub]parsing ends here @:' + pos + " l:" + l);
					break;
				} else {
					
					switch (result.tagType) {
					case 2: // Signature Packet certification signature
						if (result.signatureType == 24)  { // subkey binding signature
							this.subKeySignature = result;
							pos += result.packetLength + result.headerLength;
							break;
						} else if (result.signatureType == 40) { // subkey revocation signature
							this.subKeyRevocationSignature[this.subKeyRevocationSignature.length] = result;
							pos += result.packetLength + result.headerLength;
							break;
						} else {
							util.print_error("openpgp.packet.keymaterial.js\nunknown signature:"+result.toString());
						}
						
					default:
						this.data = bytes;
						this.position = position - this.parentNode.packetLength;
						this.len = pos - position;
						return this.len;
						break;
					}
				}
			}
			this.data = bytes;
			this.position = position - this.parentNode.packetLength;
			this.len = pos - position;
			return this.len;
		} else if (this.tagType == 7) { // private sub-key packet
			var pos = position;
			while (bytes.length != pos) {
				var result = openpgp_packet.read_packet(bytes, pos, len - (pos - position));
				if (result == null) {
					util.print_error("openpgp.packet.keymaterial.js\n"+'[user_keymat_priv] parsing ends here @:' + pos);
					break;
				} else {
					switch (result.tagType) {
					case 2: // Signature Packet certification signature
						if (result.signatureType == 24) // subkey embedded signature
							this.subKeySignature = result; 
						else if (result.signatureType == 40) // subkey revocation signature
							this.subKeyRevocationSignature[this.subKeyRevocationSignature.length] = result;
						pos += result.packetLength + result.headerLength;
						break;
					default:
						this.data = bytes;
						this.position = position - this.parentNode.packetLength;
						this.len = pos - position;
						return this.len;
					}
				}
			}
			this.data = bytes;
			this.position = position - this.parentNode.packetLength;
			this.len = pos - position;
			return this.len;
		} else {
			util.print_error("openpgp.packet.keymaterial.js\n"+"unknown parent node for a key material packet "+parent_node.tagType);
		}
	}

	/**
	 * Checks the validity for usage of this (sub)key
	 * @return {Integer} 0 = bad key, 1 = expired, 2 = revoked, 3 = valid
	 */
	function verifyKey() {
		if (this.tagType == 14) {
			if (this.subKeySignature == null) {
				return 0;
			}
			if (this.subKeySignature.version == 4 &&
				this.subKeySignature.keyNeverExpires != null &&
				!this.subKeySignature.keyNeverExpires &&
				new Date((this.subKeySignature.keyExpirationTime*1000)+ this.creationTime.getTime()) < new Date()) {
				    return 1;
				}
			var hashdata = String.fromCharCode(0x99)+this.parentNode.header.substring(1)+this.parentNode.data+
			String.fromCharCode(0x99)+this.header.substring(1)+this.packetdata;
			if (!this.subKeySignature.verify(hashdata,this.parentNode)) {
				return 0;
			}
			for (var i = 0; i < this.subKeyRevocationSignature.length; i++) {
			    if (this.getKeyId() == this.subKeyRevocationSignature[i].keyId){
			        return 2;
			    }
			}
		}
		return 3;
	}

	/**
	 * Calculates the key id of they key 
	 * @return {String} A 8 byte key id
	 */
	function getKeyId() {
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
	function getFingerprint() {
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


