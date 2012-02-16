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
 * Implementation of the String-to-key specifier (RFC4880 3.7)
 * String-to-key (S2K) specifiers are used to convert passphrase strings
   into symmetric-key encryption/decryption keys.  They are used in two
   places, currently: to encrypt the secret part of private keys in the
   private keyring, and to convert passphrases to encryption keys for
   symmetrically encrypted messages.
 */
function openpgp_type_s2k() {
	/**
	 * parsing function for a string-to-key specifier (RFC 4880 3.7).
	 * @param input [string] payload of string-to-key specifier
	 * @param position [integer] position to start reading from the input string
	 * @return [openpgp_type_s2k] object representation
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

		case 2: // Reserved value
		default:
			util.print_error("unknown s2k type! "+this.type);
			break;
		}
		return this;
	}

	/**
	 * produces a key using the specified passphrase and the defined hashAlgorithm 
	 * @param passphrase [String] passphrase containing user input
	 * @return [String] produced key with a length corresponding to hashAlgorithm hash length
	 */
	function produce_key(passphrase) {
		if (this.type == 0) {
			return openpgp_crypto_hashData(this.hashAlgorithm,passphrase);
		} else if (this.type == 1) {
			return openpgp_crypto_hashData(this.hashAlgorithm,this.saltValue+passphrase);
		} else if (this.type == 3) {
			var isp = this.saltValue+passphrase;
			while (isp.length < this.count)
				isp += this.saltValue+passphrase; 			
			if (isp.length > this.count)
				isp = isp.substr(0, this.count);
			return openpgp_crypto_hashData(this.hashAlgorithm,isp);
		} else return null;
	}
	
	this.read = read;
	this.produce_key = produce_key;
}
