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
	/** @type {openpgp.hash} */
	this.algorithm = null;
	/** @type {openpgp_type_s2k.type} */
	this.type = openpgp_type_s2k.type.iterated;
	this.c = 1000;


	// Exponen bias, defined in RFC4880
	var expbias = 6;

	this.get_count = function() {
		return (16 + (this.c & 15)) << ((this.c >> 4) + expbias);
	}

	/**
	 * Parsing function for a string-to-key specifier (RFC 4880 3.7).
	 * @param {String} input Payload of string-to-key specifier
	 * @return {Integer} Actual length of the object
	 */
	this.read = function(bytes) {
		var i = 0;
		this.type = bytes[i++].charCodeAt();
		this.algorithm = bytes[i++].charCodeAt();

		var t = openpgp_type_s2k.type;

		switch (this.type) {
		case t.simple:
			break;

		case t.salted:
			this.salt = bytes.substr(i, 8);
			i += 8;
			break;

		case t.iterated:
			this.salt = bytes.substr(i, 8);
			i += 8;

			// Octet 10: count, a one-octet, coded value
			this.c = bytes[i++].charCodeAt();
			break;

		case t.gnu:
			if(bytes.substr(i, 3) == "GNU") {
				i += 3; // GNU
				var gnuExtType = 1000 + bytes[i++].charCodeAt();
				if(gnuExtType == 1001) {
					this.type = gnuExtType;
					// GnuPG extension mode 1001 -- don't write secret key at all
				} else {
					util.print_error("unknown s2k gnu protection mode! "+this.type);
				}
			} else {
				util.print_error("unknown s2k type! "+this.type);
			}
			break;

		default:
			util.print_error("unknown s2k type! "+this.type);
			break;
		}

		return i;
	}
	
	
	/**
	 * writes an s2k hash based on the inputs.
	 * @return {String} Produced key of hashAlgorithm hash length
	 */
	this.write = function() {
		var bytes = String.fromCharCode(this.type);
		bytes += String.fromCharCode(this.algorithm);

		var t = openpgp_type_s2k.type;
		switch(this.type) {
			case t.simple:
				break;
			case t.salted:
				bytes += this.salt;
				break;
			case t.iterated:
				bytes += this.salt;
				bytes += this.c;
				break;
		};

		return bytes;
	}

	/**
	 * Produces a key using the specified passphrase and the defined 
	 * hashAlgorithm 
	 * @param {String} passphrase Passphrase containing user input
	 * @return {String} Produced key with a length corresponding to 
	 * hashAlgorithm hash length
	 */
	this.produce_key = function(passphrase, numBytes) {
		passphrase = util.encode_utf8(passphrase);

		function round(prefix, s2k) {

			var t = openpgp_type_s2k.type;
			switch(s2k.type) {
				case t.simple:
					return openpgp_crypto_hashData(s2k.algorithm, prefix + passphrase);

				case t.salted:
					return openpgp_crypto_hashData(s2k.algorithm, 
						prefix + s2k.salt + passphrase);

				case t.iterated:
					var isp = [],
						count = s2k.get_count();
						data = s2k.salt + passphrase;

					while (isp.length * data.length < count)
						isp.push(data);

					isp = isp.join('');			

					if (isp.length > count)
						isp = isp.substr(0, count);

					return openpgp_crypto_hashData(s2k.algorithm, prefix + isp);
			};
		}
		
		var result = '',
			prefix = '';

		while(result.length <= numBytes) {
			result += round(prefix, this);
			prefix += String.fromCharCode(0);
		}

		return result.substr(0, numBytes);
	}
}



/** A string to key specifier type
 * @enum {Integer}
 */
openpgp_type_s2k.type = {
	simple: 0,
	salted: 1,
	iterated: 3,
	gnu: 101
}
