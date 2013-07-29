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
function openpgp_packet_keymaterial() {
	// members:
	this.publicKeyAlgorithm = null;
	this.tagType = null;
	this.creationTime = null;
	this.version = null;
	this.expiration  = null;// V3
	this.MPIs = null;
	this.secMPIs = null;
	this.publicKey = null;
	this.symmetricEncryptionAlgorithm = null;
	this.s2kUsageConventions = null;
	this.IVLength  = null;
    this.encryptedMPIData = null;
    this.hasUnencryptedSecretKeyData = null;
    this.checksum = null;
    this.parentNode = null;
	this.subKeySignature = null;
	this.subKeyRevocationSignature = null;

	// 5.5.1. Key Packet Variants
	
	// 5.5.1.3. Secret-Key Packet (Tag 5)
	/**
	 * This function reads the payload of a secret key packet (Tag 5)
	 * and initializes the openpgp_packet_keymaterial
	 * @param {String} input Input string to read the packet from
	 * @param {Integer} position Start position for the parser
	 * @param {Intefer} len Length of the packet or remaining length of input
	 * @return {openpgp_packet_keymaterial}
	 */
	function read_tag5(input, position, len) {
		this.tagType = 5;
		this.read_priv_key(input, position, len);
		return this;
	}

	// 5.5.1.1. Public-Key Packet (Tag 6)
	/**
	 * This function reads the payload of a public key packet (Tag 6)
	 * and initializes the openpgp_packet_keymaterial
	 * @param {String} input Input string to read the packet from
	 * @param {Integer} position Start position for the parser
	 * @param {Integer} len Length of the packet or remaining length of input
	 * @return {openpgp_packet_keymaterial}
	 */
	function read_tag6(input, position, len) {
		// A Public-Key packet starts a series of packets that forms an OpenPGP
		// key (sometimes called an OpenPGP certificate).
		this.tagType = 6;
		this.packetLength = len;
		this.read_pub_key(input, position,len);
		
		return this;
	}

	// 5.5.1.4. Secret-Subkey Packet (Tag 7)
	/**
	 * This function reads the payload of a secret key sub packet (Tag 7)
	 * and initializes the openpgp_packet_keymaterial
	 * @param {String} input Input string to read the packet from
	 * @param {Integer} position Start position for the parser
	 * @param {Integer} len Length of the packet or remaining length of input
	 * @return {openpgp_packet_keymaterial}
	 */
	function read_tag7(input, position, len) {
		this.tagType = 7;
		this.packetLength = len;
		return this.read_priv_key(input, position, len);
	}

	// 5.5.1.2. Public-Subkey Packet (Tag 14)
	/**
	 * This function reads the payload of a public key sub packet (Tag 14)
	 * and initializes the openpgp_packet_keymaterial
	 * @param {String} input Input string to read the packet from
	 * @param {Integer} position Start position for the parser
	 * @param {Integer} len Length of the packet or remaining length of input
	 * @return {openpgp_packet_keymaterial}
	 */
	function read_tag14(input, position, len) {
		this.subKeySignature = null;
		this.subKeyRevocationSignature = new Array();
		this.tagType = 14;
		this.packetLength = len;
		this.read_pub_key(input, position,len);
		return this;
	}
	
	/**
	 * Internal Parser for public keys as specified in RFC 4880 section 
	 * 5.5.2 Public-Key Packet Formats
	 * called by read_tag&lt;num&gt;
	 * @param {String} input Input string to read the packet from
	 * @param {Integer} position Start position for the parser
	 * @param {Integer} len Length of the packet or remaining length of input
	 * @return {Object} This object with attributes set by the parser
	 */  
	function read_pub_key(input, position, len) {
		var mypos = position;
		// A one-octet version number (3 or 4).
		this.version = input[mypos++].charCodeAt();
		if (this.version == 3) {
			// A four-octet number denoting the time that the key was created.
			this.creationTime = new Date(((input[mypos++].charCodeAt() << 24) |
				(input[mypos++].charCodeAt() << 16) |
				(input[mypos++].charCodeAt() <<  8) |
				(input[mypos++].charCodeAt()))*1000);
			
		    // - A two-octet number denoting the time in days that this key is
		    //   valid.  If this number is zero, then it does not expire.
			this.expiration = (input[mypos++].charCodeAt() << 8) & input[mypos++].charCodeAt();
	
		    // - A one-octet number denoting the public-key algorithm of this key.
			this.publicKeyAlgorithm = input[mypos++].charCodeAt();
			var mpicount = 0;
		    // - A series of multiprecision integers comprising the key material:
			//   Algorithm-Specific Fields for RSA public keys:
		    //       - a multiprecision integer (MPI) of RSA public modulus n;
		    //       - an MPI of RSA public encryption exponent e.
			if (this.publicKeyAlgorithm > 0 && this.publicKeyAlgorithm < 4)
				mpicount = 2;
			//   Algorithm-Specific Fields for Elgamal public keys:
			//     - MPI of Elgamal prime p;
			//     - MPI of Elgamal group generator g;
			//     - MPI of Elgamal public key value y (= g**x mod p where x  is secret).

			else if (this.publicKeyAlgorithm == 16)
				mpicount = 3;
			//   Algorithm-Specific Fields for DSA public keys:
			//       - MPI of DSA prime p;
			//       - MPI of DSA group order q (q is a prime divisor of p-1);
			//       - MPI of DSA group generator g;
			//       - MPI of DSA public-key value y (= g**x mod p where x  is secret).
			else if (this.publicKeyAlgorithm == 17)
				mpicount = 4;

			this.MPIs = new Array();
			for (var i = 0; i < mpicount; i++) {
				this.MPIs[i] = new openpgp_type_mpi();
				if (this.MPIs[i].read(input, mypos, (mypos-position)) != null && 
						!this.packetLength < (mypos-position)) {
					mypos += this.MPIs[i].packetLength;
				} else {
					util.print_error("openpgp.packet.keymaterial.js\n"+'error reading MPI @:'+mypos);
				}
			}
			this.packetLength = mypos-position;
		} else if (this.version == 4) {
			// - A four-octet number denoting the time that the key was created.
			this.creationTime = new Date(((input[mypos++].charCodeAt() << 24) |
			(input[mypos++].charCodeAt() << 16) |
			(input[mypos++].charCodeAt() <<  8) |
			(input[mypos++].charCodeAt()))*1000);
			
			// - A one-octet number denoting the public-key algorithm of this key.
			this.publicKeyAlgorithm = input[mypos++].charCodeAt();
			var mpicount = 0;
		    // - A series of multiprecision integers comprising the key material:
			//   Algorithm-Specific Fields for RSA public keys:
		    //       - a multiprecision integer (MPI) of RSA public modulus n;
		    //       - an MPI of RSA public encryption exponent e.
			if (this.publicKeyAlgorithm > 0 && this.publicKeyAlgorithm < 4)
					mpicount = 2;
			//   Algorithm-Specific Fields for Elgamal public keys:
			//     - MPI of Elgamal prime p;
			//     - MPI of Elgamal group generator g;
			//     - MPI of Elgamal public key value y (= g**x mod p where x  is secret).
			else if (this.publicKeyAlgorithm == 16)
				mpicount = 3;

			//   Algorithm-Specific Fields for DSA public keys:
			//       - MPI of DSA prime p;
			//       - MPI of DSA group order q (q is a prime divisor of p-1);
			//       - MPI of DSA group generator g;
			//       - MPI of DSA public-key value y (= g**x mod p where x  is secret).
			else if (this.publicKeyAlgorithm == 17)
				mpicount = 4;

			this.MPIs = new Array();
			var i = 0;
			for (var i = 0; i < mpicount; i++) {
				this.MPIs[i] = new openpgp_type_mpi();
				if (this.MPIs[i].read(input, mypos, (mypos-position)) != null &&
						!this.packetLength < (mypos-position)) {
					mypos += this.MPIs[i].packetLength;
				} else {
					util.print_error("openpgp.packet.keymaterial.js\n"+'error reading MPI @:'+mypos);
				}
			}
			this.packetLength = mypos-position;
		} else {
			return null;
		}
		this.data = input.substring(position, mypos);
		this.packetdata = input.substring(position, mypos);
		return this;
	}
	
	// 5.5.3.  Secret-Key Packet Formats
	
	/**
	 * Internal parser for private keys as specified in RFC 4880 section 5.5.3
	 * @param {String} input Input string to read the packet from
	 * @param {Integer} position Start position for the parser
	 * @param {Integer} len Length of the packet or remaining length of input
	 * @return {Object} This object with attributes set by the parser
	 */
	function read_priv_key(input,position, len) {
	    // - A Public-Key or Public-Subkey packet, as described above.
	    this.publicKey = new openpgp_packet_keymaterial();
		if (this.publicKey.read_pub_key(input,position, len) == null) {
			util.print_error("openpgp.packet.keymaterial.js\n"+"Failed reading public key portion of a private key: "+input[position].charCodeAt()+" "+position+" "+len+"\n Aborting here...");
			return null;
		}
		this.publicKey.header = openpgp_packet.write_old_packet_header(6,this.publicKey.packetLength);
		// this.publicKey.header = String.fromCharCode(0x99) + String.fromCharCode(this.publicKey.packetLength >> 8 & 0xFF)+String.fromCharCode(this.publicKey.packetLength & 0xFF);
		var mypos = position + this.publicKey.data.length;
		this.packetLength = len;
		
	    // - One octet indicating string-to-key usage conventions.  Zero
	    //   indicates that the secret-key data is not encrypted.  255 or 254
	    //   indicates that a string-to-key specifier is being given.  Any
	    //   other value is a symmetric-key encryption algorithm identifier.
	    this.s2kUsageConventions = input[mypos++].charCodeAt();
	    
	    if (this.s2kUsageConventions == 0)
	    	this.hasUnencryptedSecretKeyData = true;
	   
	    // - [Optional] If string-to-key usage octet was 255 or 254, a one-
	    //   octet symmetric encryption algorithm.
	    if (this.s2kUsageConventions == 255 || this.s2kUsageConventions == 254) {
	    	this.symmetricEncryptionAlgorithm = input[mypos++].charCodeAt();
	    }
	     
	    // - [Optional] If string-to-key usage octet was 255 or 254, a
	    //   string-to-key specifier.  The length of the string-to-key
	    //   specifier is implied by its type, as described above.
	    if (this.s2kUsageConventions == 255 || this.s2kUsageConventions == 254) {
	    	this.s2k = new openpgp_type_s2k();
	    	this.s2k.read(input, mypos);
	    	mypos +=this.s2k.s2kLength;
	    }
	    
	    // - [Optional] If secret data is encrypted (string-to-key usage octet
	    //   not zero), an Initial Vector (IV) of the same length as the
	    //   cipher's block size.
	    this.symkeylength = 0;
	    if (this.s2kUsageConventions != 0 && this.s2kUsageConventions != 255 &&
	    		this.s2kUsageConventions != 254) {
	    	this.symmetricEncryptionAlgorithm = this.s2kUsageConventions;
	    }
	    if (this.s2kUsageConventions != 0 && this.s2k.type != 1001) {
	    	this.hasIV = true;
	    	switch (this.symmetricEncryptionAlgorithm) {
		    case  1: // - IDEA [IDEA]
		    	util.print_error("openpgp.packet.keymaterial.js\n"+"symmetric encrytryption algorithim: IDEA is not implemented");
		    	return null;
	    	case  2: // - TripleDES (DES-EDE, [SCHNEIER] [HAC] - 168 bit key derived from 192)
	    	case  3: // - CAST5 (128 bit key, as per [RFC2144])
	    		this.IVLength = 8;
		    	break;
		    case  4: // - Blowfish (128 bit key, 16 rounds) [BLOWFISH]
		    case  7: // - AES with 128-bit key [AES]
	    	case  8: // - AES with 192-bit key
	    	case  9: // - AES with 256-bit key
	    		this.IVLength = 16;
		    	break;
	    	case 10: // - Twofish with 256-bit key [TWOFISH]
	    		this.IVLength = 32;	    		
		    	break;
	    	case  5: // - Reserved
	    	case  6: // - Reserved
	    	default:
	    		util.print_error("openpgp.packet.keymaterial.js\n"+"unknown encryption algorithm for secret key :"+this.symmetricEncryptionAlgorithm);
	    		return null;
	    	}
	    	mypos++; 
	    	this.IV = input.substring(mypos, mypos+this.IVLength);
	    	mypos += this.IVLength;
	    }
	    // - Plain or encrypted multiprecision integers comprising the secret
	    //   key data.  These algorithm-specific fields are as described
	    //   below.

      // s2k type 1001 corresponds to GPG specific extension without primary key secrets
      // http://www.gnupg.org/faq/GnuPG-FAQ.html#how-can-i-use-gnupg-in-an-automated-environment
	    if (this.s2kUsageConventions != 0 && this.s2k.type == 1001) {
	    	this.secMPIs = null;
	    	this.encryptedMPIData = null;
	    } else if (!this.hasUnencryptedSecretKeyData) {
	    	this.encryptedMPIData = input.substring(mypos, len);
	    	mypos += this.encryptedMPIData.length;
	    } else {
	    	if (this.publicKey.publicKeyAlgorithm > 0 && this.publicKey.publicKeyAlgorithm < 4) {
	    		//   Algorithm-Specific Fields for RSA secret keys:
	    		//   - multiprecision integer (MPI) of RSA secret exponent d.
	    		//   - MPI of RSA secret prime value p.
	    		//   - MPI of RSA secret prime value q (p < q).
	    		//   - MPI of u, the multiplicative inverse of p, mod q.
	    		this.secMPIs = new Array();
	    		this.secMPIs[0] = new openpgp_type_mpi();
	    		this.secMPIs[0].read(input, mypos, len-2- (mypos - position));
	    		mypos += this.secMPIs[0].packetLength;
	    		this.secMPIs[1] = new openpgp_type_mpi();
	    		this.secMPIs[1].read(input, mypos, len-2- (mypos - position));
	    		mypos += this.secMPIs[1].packetLength;
	    		this.secMPIs[2] = new openpgp_type_mpi();
	    		this.secMPIs[2].read(input, mypos, len-2- (mypos - position));
	    		mypos += this.secMPIs[2].packetLength;
	    		this.secMPIs[3] = new openpgp_type_mpi();
	    		this.secMPIs[3].read(input, mypos, len-2- (mypos - position));
	    		mypos += this.secMPIs[3].packetLength;
	    	} else if (this.publicKey.publicKeyAlgorithm == 16) {
	    		// Algorithm-Specific Fields for Elgamal secret keys:
	    		//   - MPI of Elgamal secret exponent x.
	    		this.secMPIs = new Array();
	    		this.secMPIs[0] = new openpgp_type_mpi();
	    		this.secMPIs[0].read(input, mypos, len-2- (mypos - position));
	    		mypos += this.secMPIs[0].packetLength;
	    	} else if (this.publicKey.publicKeyAlgorithm == 17) {
	    		// Algorithm-Specific Fields for DSA secret keys:
	    		//   - MPI of DSA secret exponent x.
	    		this.secMPIs = new Array();
	    		this.secMPIs[0] = new openpgp_type_mpi();
	    		this.secMPIs[0].read(input, mypos, len-2- (mypos - position));
	    		mypos += this.secMPIs[0].packetLength;
	    	}
	    	// checksum because s2k usage convention is 0
	        this.checksum = new Array(); 
		    this.checksum[0] = input[mypos++].charCodeAt();
		    this.checksum[1] = input[mypos++].charCodeAt();
	    }
	    return this;
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
	function decryptSecretMPIs(str_passphrase) {
		if (this.hasUnencryptedSecretKeyData)
			return this.secMPIs;
		// creating a key out of the passphrase
		var key = this.s2k.produce_key(str_passphrase);
		var cleartextMPIs = "";
    	switch (this.symmetricEncryptionAlgorithm) {
	    case  1: // - IDEA [IDEA]
	    	util.print_error("openpgp.packet.keymaterial.js\n"+"symmetric encryption algorithim: IDEA is not implemented");
	    	return false;
    	case  2: // - TripleDES (DES-EDE, [SCHNEIER] [HAC] - 168 bit key derived from 192)
    		cleartextMPIs = normal_cfb_decrypt(function(block, key) {
    			return des(key, block,1,null,0);
    		}, this.IVLength, key, this.encryptedMPIData, this.IV);
    		break;
    	case  3: // - CAST5 (128 bit key, as per [RFC2144])
    		cleartextMPIs = normal_cfb_decrypt(function(block, key) {
        		var cast5 = new openpgp_symenc_cast5();
        		cast5.setKey(key);
        		return cast5.encrypt(util.str2bin(block)); 
    		}, this.IVLength, util.str2bin(key.substring(0,16)), this.encryptedMPIData, this.IV);
    		break;
	    case  4: // - Blowfish (128 bit key, 16 rounds) [BLOWFISH]
	    	cleartextMPIs = normal_cfb_decrypt(function(block, key) {
    			var blowfish = new Blowfish(key);
        		return blowfish.encrypt(block); 
    		}, this.IVLength, key, this.encryptedMPIData, this.IV);
    		break;
	    case  7: // - AES with 128-bit key [AES]
    	case  8: // - AES with 192-bit key
    	case  9: // - AES with 256-bit key
    	    var numBytes = 16;
            //This is a weird way to achieve this. If's within a switch is probably not ideal.
    	    if(this.symmetricEncryptionAlgorithm == 8){
    	        numBytes = 24;
    	        key = this.s2k.produce_key(str_passphrase,numBytes);
    	    }
    	    if(this.symmetricEncryptionAlgorithm == 9){
    	        numBytes = 32;
    	        key = this.s2k.produce_key(str_passphrase,numBytes);
    	    }
    		cleartextMPIs = normal_cfb_decrypt(function(block,key){
    		    return AESencrypt(util.str2bin(block),key);
    		},
    				this.IVLength, keyExpansion(key.substring(0,numBytes)), this.encryptedMPIData, this.IV);
	    	break;
    	case 10: // - Twofish with 256-bit key [TWOFISH]
    		util.print_error("openpgp.packet.keymaterial.js\n"+"Key material is encrypted with twofish: not implemented");   		
	    	return false;
    	case  5: // - Reserved
    	case  6: // - Reserved
    	default:
    		util.print_error("openpgp.packet.keymaterial.js\n"+"unknown encryption algorithm for secret key :"+this.symmetricEncryptionAlgorithm);
    		return false;
    	}
    	
    	if (cleartextMPIs == null) {
    		util.print_error("openpgp.packet.keymaterial.js\n"+"cleartextMPIs was null");
    		return false;
    	}
    	
    	var cleartextMPIslength = cleartextMPIs.length;

    	if (this.s2kUsageConventions == 254 &&
    			str_sha1(cleartextMPIs.substring(0,cleartextMPIs.length - 20)) == 
    				cleartextMPIs.substring(cleartextMPIs.length - 20)) {
    		cleartextMPIslength -= 20;
    	} else if (this.s2kUsageConventions != 254 && util.calc_checksum(cleartextMPIs.substring(0,cleartextMPIs.length - 2)) == 
    			(cleartextMPIs.charCodeAt(cleartextMPIs.length -2) << 8 | cleartextMPIs.charCodeAt(cleartextMPIs.length -1))) {
    		cleartextMPIslength -= 2;
    	} else {
    		return false;
    	}

    	if (this.publicKey.publicKeyAlgorithm > 0 && this.publicKey.publicKeyAlgorithm < 4) {
    		//   Algorithm-Specific Fields for RSA secret keys:
    		//   - multiprecision integer (MPI) of RSA secret exponent d.
    		//   - MPI of RSA secret prime value p.
    		//   - MPI of RSA secret prime value q (p < q).
    		//   - MPI of u, the multiplicative inverse of p, mod q.
    		var mypos = 0;
    		this.secMPIs = new Array();
    		this.secMPIs[0] = new openpgp_type_mpi();
    		this.secMPIs[0].read(cleartextMPIs, 0, cleartextMPIslength);
    		mypos += this.secMPIs[0].packetLength;
    		this.secMPIs[1] = new openpgp_type_mpi();
    		this.secMPIs[1].read(cleartextMPIs, mypos, cleartextMPIslength-mypos);
    		mypos += this.secMPIs[1].packetLength;
    		this.secMPIs[2] = new openpgp_type_mpi();
    		this.secMPIs[2].read(cleartextMPIs, mypos, cleartextMPIslength-mypos);
    		mypos += this.secMPIs[2].packetLength;
    		this.secMPIs[3] = new openpgp_type_mpi();
    		this.secMPIs[3].read(cleartextMPIs, mypos, cleartextMPIslength-mypos);
    		mypos += this.secMPIs[3].packetLength;
    	} else if (this.publicKey.publicKeyAlgorithm == 16) {
    		// Algorithm-Specific Fields for Elgamal secret keys:
    		//   - MPI of Elgamal secret exponent x.
    		this.secMPIs = new Array();
    		this.secMPIs[0] = new openpgp_type_mpi();
    		this.secMPIs[0].read(cleartextMPIs, 0, cleartextMPIs);
    	} else if (this.publicKey.publicKeyAlgorithm == 17) {
    		// Algorithm-Specific Fields for DSA secret keys:
    		//   - MPI of DSA secret exponent x.
    		this.secMPIs = new Array();
    		this.secMPIs[0] = new openpgp_type_mpi();
    		this.secMPIs[0].read(cleartextMPIs, 0, cleartextMPIslength);
    	}
    	return true;
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
		if (this.secMPIs != null) {
			result += "Secret Key MPIs:\n";
			for (var i = 0; i < this.secMPIs.length; i++) {
		      	  result += this.secMPIs[i].toString();
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
	 * @param {String} input Input string to read the packet(s) from
	 * @param {Integer} position Start position for the parser
	 * @param {Integer} len Length of the packet(s) or remaining length of input
	 * @return {Integer} Length of nodes read
	 */
	function read_nodes(parent_node, input, position, len) {
		this.parentNode = parent_node;
		if (this.tagType == 14) { // public sub-key packet
			var pos = position;
			var result = null;
			while (input.length != pos) {
				var l = input.length - pos;
				result = openpgp_packet.read_packet(input, pos, l);
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
						this.data = input;
						this.position = position - this.parentNode.packetLength;
						this.len = pos - position;
						return this.len;
						break;
					}
				}
			}
			this.data = input;
			this.position = position - this.parentNode.packetLength;
			this.len = pos - position;
			return this.len;
		} else if (this.tagType == 7) { // private sub-key packet
			var pos = position;
			while (input.length != pos) {
				var result = openpgp_packet.read_packet(input, pos, len - (pos - position));
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
						this.data = input;
						this.position = position - this.parentNode.packetLength;
						this.len = pos - position;
						return this.len;
					}
				}
			}
			this.data = input;
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
			var key_id = this.MPIs[0].MPI.substring((this.MPIs[0].mpiByteLength-8));
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
    function write_private_key(keyType, key, password, s2kHash, symmetricEncryptionAlgorithm, timePacket){
        this.symmetricEncryptionAlgorithm = symmetricEncryptionAlgorithm;
		var tag = 5;
		var body = String.fromCharCode(4);
		body += timePacket;
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
		        body += String.fromCharCode(this.symmetricEncryptionAlgorithm);
		        //if s2k == 255,254 then s2k specifier
		        body += String.fromCharCode(3); //s2k salt+iter
		        body += String.fromCharCode(s2kHash);
		        //8 octet salt value
		        //1 octet count
		        var cleartextMPIs = key.d.toMPI() + key.p.toMPI() + key.q.toMPI() + key.u.toMPI();
		        var sha1Hash = str_sha1(cleartextMPIs);
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
		        switch(this.symmetricEncryptionAlgorithm){
		        case 3:
		            this.IVLength = 8;
		            this.IV = openpgp_crypto_getRandomBytes(this.IVLength);
            		ciphertextMPIs = normal_cfb_encrypt(function(block, key) {
                		var cast5 = new openpgp_symenc_cast5();
                		cast5.setKey(key);
                		return cast5.encrypt(util.str2bin(block)); 
            		}, this.IVLength, util.str2bin(hashKey.substring(0,16)), cleartextMPIs + sha1Hash, this.IV);
            		body += this.IV + ciphertextMPIs;
		            break;
		        case 7:
		        case 8:
		        case 9:
		            this.IVLength = 16;
		            this.IV = openpgp_crypto_getRandomBytes(this.IVLength);
		            ciphertextMPIs = normal_cfb_encrypt(AESencrypt,
            				this.IVLength, hashKey, cleartextMPIs + sha1Hash, this.IV);
            		body += this.IV + ciphertextMPIs;
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
	
	/*
     * Same as write_private_key, but has less information because of 
	 * public key.
     * @param {Integer} keyType Follows the OpenPGP algorithm standard, 
	 * IE 1 corresponds to RSA.
     * @param {RSA.keyObject} key
     * @param timePacket
     * @return {Object} {body: [string]OpenPGP packet body contents, 
	 * header: [string] OpenPGP packet header, string: [string] header+body}
     */
    function write_public_key(keyType, key, timePacket){
        var tag = 6;
        var body = String.fromCharCode(4);
        body += timePacket;
		switch(keyType){
		case 1:
		    body += String.fromCharCode(1);//public key algo
		    body += key.n.toMPI();
		    body += key.ee.toMPI();
		    break;
	    default:
	    	util.print_error("openpgp.packet.keymaterial.js\n"+'error writing private key, unknown type :'+keyType);
	    }
        var header = openpgp_packet.write_packet_header(tag,body.length);
        return {string: header+body , header: header, body: body};
        }

	
	this.read_tag5 = read_tag5;
	this.read_tag6 = read_tag6;
	this.read_tag7 = read_tag7;
	this.read_tag14 = read_tag14;
	this.toString = toString;
	this.read_pub_key = read_pub_key;
	this.read_priv_key = read_priv_key;
	this.decryptSecretMPIs = decryptSecretMPIs;
	this.read_nodes = read_nodes;
	this.verifyKey = verifyKey;
	this.getKeyId = getKeyId;
	this.getFingerprint = getFingerprint;
	this.write_private_key = write_private_key;
	this.write_public_key = write_public_key;
}
