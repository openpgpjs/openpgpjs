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
 * @classdesc Implementation of the Sym. Encrypted Integrity Protected Data 
 * Packet (Tag 18)
 * 
 * RFC4880 5.13: The Symmetrically Encrypted Integrity Protected Data packet is
 * a variant of the Symmetrically Encrypted Data packet. It is a new feature
 * created for OpenPGP that addresses the problem of detecting a modification to
 * encrypted data. It is used in combination with a Modification Detection Code
 * packet.
 */

function openpgp_packet_sym_encrypted_integrity_protected() {
	this.tag = 18;
	this.version = 1;
	this.encrypted = null; // string
	this.hash = null; // string
	this.data = new openpgp_packetlist();
	this.algorithm = openpgp.symmetric.plaintext;

	/**
	 * Parsing function for the packet.
	 * 
	 * @param {String} input Payload of a tag 18 packet
	 * @param {Integer} position
	 *             position to start reading from the input string
	 * @param {Integer} len Length of the packet or the remaining length of
	 *            input at position
	 * @return {openpgp_packet_encryptedintegrityprotecteddata} object
	 *         representation
	 */
	this.read = function(bytes) {
		// - A one-octet version number. The only currently defined value is
		// 1.
		this.version = bytes[0].charCodeAt();
		if (this.version != 1) {
			util.print_error('openpgp.packet.encryptedintegrityprotecteddata.js' +
				'\nunknown encrypted integrity protected data packet version: '
							+ this.version
							+ "hex:"
							+ util.hexstrdump(bytes));
			return null;
		}

		// - Encrypted data, the output of the selected symmetric-key cipher
		//   operating in Cipher Feedback mode with shift amount equal to the
		//   block size of the cipher (CFB-n where n is the block size).
		this.encrypted = bytes.substr(1);
	}

	/**
	 * Creates a string representation of a Sym. Encrypted Integrity Protected
	 * Data Packet (tag 18) (see RFC4880 5.13)
	 * 
	 * @param {Integer} symmetric_algorithm
	 *            The selected symmetric encryption algorithm to be used
	 * @param {String} key The key of cipher blocksize length to be used
	 * @param {String} data
	 *            Plaintext data to be encrypted within the packet
	 * @return {String} A string representation of the packet
	 */
	this.write = function(symmetric_algorithm, key, data) {
		return String.fromCharCode(this.version) + this.encrypted;
	}

	this.encrypt = function(symmetric_algorithm, key) {
		var bytes = this.data.write()
		
		var prefixrandom = openpgp_crypto_getPrefixRandom(symmetric_algorithm);
		var prefix = prefixrandom
				+ prefixrandom.charAt(prefixrandom.length - 2)
				+ prefixrandom.charAt(prefixrandom.length - 1)

		var tohash = bytes;
		tohash += String.fromCharCode(0xD3);
		tohash += String.fromCharCode(0x14);

		util.print_debug_hexstr_dump("data to be hashed:"
				, prefix + tohash);

		tohash += str_sha1(prefix + tohash);

		util.print_debug_hexstr_dump("hash:"
				, tohash.substring(tohash.length - 20,
						tohash.length));

		this.encrypted = openpgp_crypto_symmetricEncrypt(prefixrandom,
				symmetric_algorithm, key, tohash, false).substring(0,
				prefix.length + tohash.length);
	}

	/**
	 * Decrypts the encrypted data contained in this object read_packet must
	 * have been called before
	 * 
	 * @param {Integer} symmetric_algorithm_type
	 *            The selected symmetric encryption algorithm to be used
	 * @param {String} key The key of cipher blocksize length to be used
	 * @return {String} The decrypted data of this packet
	 */
	this.decrypt = function(symmetric_algorithm_type, key) {
		var decrypted = openpgp_crypto_symmetricDecrypt(
				symmetric_algorithm_type, key, this.encrypted, false);


		// there must be a modification detection code packet as the
		// last packet and everything gets hashed except the hash itself
		this.hash = str_sha1(
			openpgp_crypto_MDCSystemBytes(symmetric_algorithm_type, key, this.encrypted)
			+ decrypted.substring(0, decrypted.length - 20));

		util.print_debug_hexstr_dump("calc hash = ", this.hash);

		this.data.read(decrypted);

		// We pop the mandatory modification detection code packet.
		var mdc = this.data.packets.pop();

		if(this.hash != mdc.hash) {
			this.data = null;
			util.print_error("Decryption stopped: discovered a " +
				"modification of encrypted data.");
			return;
		}
	}

	this.toString = function() {
	    var data = '';
	    if(openpgp.config.debug)
	        data = '    data: Bytes ['
				+ util.hexstrdump(this.encrypted) + ']';
	    
		return '5.13.  Sym. Encrypted Integrity Protected Data Packet (Tag 18)\n'
				+ '\n'
				+ '    version: '
				+ this.version
				+ '\n'
				+ data;
	}

};

function openpgp_packet_modification_detection_code() {
	this.hash = null;
	this.read = function(bytes) {
		this.hash = bytes;
	}
}
