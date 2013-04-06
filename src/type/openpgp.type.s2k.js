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
 * @classdesc Implementation of the String-to-key specifier (RFC4880 3.7)
 * String-to-key (S2K) specifiers are used to convert passphrase strings
   into symmetric-key encryption/decryption keys.  They are used in two
   places, currently: to encrypt the secret part of private keys in the
   private keyring, and to convert passphrases to encryption keys for
   symmetrically encrypted messages.
 */
function openpgp_type_s2k() {
	/**
	 * Parsing function for a string-to-key specifier (RFC 4880 3.7).
	 * @param {String} input Payload of string-to-key specifier
	 * @param {Integer} position Position to start reading from the input string
	 * @return {openpgp_type_s2k} Object representation
	 */
	function read(input, position) {
		var mypos = position;
		this.type = input[mypos++].charCodeAt();
		switch (this.type) {
		case 0: // Simple S2K
			// Octet 1: hash algorithm
			this.hashAlgorithm = input[mypos++].charCodeAt();
			this.s2kLength = 1;
			break;

		case 1: // Salted S2K
			// Octet 1: hash algorithm
			this.hashAlgorithm = input[mypos++].charCodeAt();

			// Octets 2-9: 8-octet salt value
			this.saltValue = input.substring(mypos, mypos+8);
			mypos += 8;
			this.s2kLength = 9;
			break;

		case 3: // Iterated and Salted S2K
			// Octet 1: hash algorithm
			this.hashAlgorithm = input[mypos++].charCodeAt();

			// Octets 2-9: 8-octet salt value
			this.saltValue = input.substring(mypos, mypos+8);
			mypos += 8;

			// Octet 10: count, a one-octet, coded value
			this.EXPBIAS = 6;
			var c = input[mypos++].charCodeAt();
			this.count = (16 + (c & 15)) << ((c >> 4) + this.EXPBIAS);
			this.s2kLength = 10;
			break;

		case 101:
			if(input.substring(mypos+1, mypos+4) == "GNU") {
				this.hashAlgorithm = input[mypos++].charCodeAt();
				mypos += 3; // GNU
				var gnuExtType = 1000 + input[mypos++].charCodeAt();
				if(gnuExtType == 1001) {
					this.type = gnuExtType;
					this.s2kLength = 5;
					// GnuPG extension mode 1001 -- don't write secret key at all
				} else {
					util.print_error("unknown s2k gnu protection mode! "+this.type);
				}
			} else {
				util.print_error("unknown s2k type! "+this.type);
			}
			break;

		case 2: // Reserved value
		default:
			util.print_error("unknown s2k type! "+this.type);
			break;
		}
		return this;
	}
	
	
	/**
	 * writes an s2k hash based on the inputs.
	 * @return {String} Produced key of hashAlgorithm hash length
	 */
	function write(type, hash, passphrase, salt, c){
	    this.type = type;
	    if(this.type == 3){this.saltValue = salt;
	        this.hashAlgorithm = hash;
	        this.count = (16 + (c & 15)) << ((c >> 4) + 6);
	        this.s2kLength = 10;
	    }
	    return this.produce_key(passphrase);
	}

	/**
	 * Produces a key using the specified passphrase and the defined 
	 * hashAlgorithm 
	 * @param {String} passphrase Passphrase containing user input
	 * @return {String} Produced key with a length corresponding to 
	 * hashAlgorithm hash length
	 */
	function produce_key(passphrase, numBytes) {
		passphrase = util.encode_utf8(passphrase);
		if (this.type == 0) {
			return openpgp_crypto_hashData(this.hashAlgorithm,passphrase);
		} else if (this.type == 1) {
			return openpgp_crypto_hashData(this.hashAlgorithm,this.saltValue+passphrase);
		} else if (this.type == 3) {
			var isp = [];
			isp[0] = this.saltValue+passphrase;
			while (isp.length*(this.saltValue+passphrase).length < this.count)
				isp.push(this.saltValue+passphrase);
			isp = isp.join('');			
			if (isp.length > this.count)
				isp = isp.substr(0, this.count);
			if(numBytes && (numBytes == 24 || numBytes == 32)){ //This if accounts for RFC 4880 3.7.1.1 -- If hash size is greater than block size, use leftmost bits.  If blocksize larger than hash size, we need to rehash isp and prepend with 0.
			    var key = openpgp_crypto_hashData(this.hashAlgorithm,isp);
			    return key + openpgp_crypto_hashData(this.hashAlgorithm,String.fromCharCode(0)+isp);
			}
			return openpgp_crypto_hashData(this.hashAlgorithm,isp);
		} else return null;
	}
	
	this.read = read;
	this.write = write;
	this.produce_key = produce_key;
}
