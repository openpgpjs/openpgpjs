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
 * @classdesc Implementation of the Symmetrically Encrypted Data Packet (Tag 9)
 * 
 * RFC4880 5.7: The Symmetrically Encrypted Data packet contains data encrypted
 * with a symmetric-key algorithm. When it has been decrypted, it contains other
 * packets (usually a literal data packet or compressed data packet, but in
 * theory other Symmetrically Encrypted Data packets or sequences of packets
 * that form whole OpenPGP messages).
 */

function openpgp_packet_encrypteddata() {
	this.tagType = 9;
	this.packetLength = null;
	this.encryptedData = null;
	this.decryptedData = null;

	/**
	 * Parsing function for the packet.
	 * 
	 * @param {String} input Payload of a tag 9 packet
	 * @param {Integer} position Position to start reading from the input string
	 * @param {Integer} len Length of the packet or the remaining length of
	 *            input at position
	 * @return {openpgp_packet_encrypteddata} Object representation
	 */
	function read_packet(input, position, len) {
		var mypos = position;
		this.packetLength = len;
		// - Encrypted data, the output of the selected symmetric-key cipher
		// operating in OpenPGP's variant of Cipher Feedback (CFB) mode.
		this.encryptedData = input.substring(position, position + len);
		return this;
	}

	/**
	 * Symmetrically decrypt the packet data
	 * 
	 * @param {Integer} symmetric_algorithm_type
	 *             Symmetric key algorithm to use // See RFC4880 9.2
	 * @param {String} key
	 *             Key as string with the corresponding length to the
	 *            algorithm
	 * @return The decrypted data;
	 */
	function decrypt_sym(symmetric_algorithm_type, key) {
		this.decryptedData = openpgp_crypto_symmetricDecrypt(
				symmetric_algorithm_type, key, this.encryptedData, true);
		util.print_debug("openpgp.packet.encryptedintegrityprotecteddata.js\n"+
				"data: "+util.hexstrdump(this.decryptedData));
		return this.decryptedData;
	}

	/**
	 * Creates a string representation of the packet
	 * 
	 * @param {Integer} algo Symmetric key algorithm to use // See RFC4880 9.2
	 * @param {String} key Key as string with the corresponding length to the
	 *            algorithm
	 * @param {String} data Data to be
	 * @return {String} String-representation of the packet
	 */
	function write_packet(algo, key, data) {
		var result = "";
		result += openpgp_crypto_symmetricEncrypt(
				openpgp_crypto_getPrefixRandom(algo), algo, key, data, true);
		result = openpgp_packet.write_packet_header(9, result.length) + result;
		return result;
	}

	function toString() {
		return '5.7.  Symmetrically Encrypted Data Packet (Tag 9)\n'
				+ '    length:  ' + this.packetLength + '\n'
				+ '    Used symmetric algorithm: ' + this.algorithmType + '\n'
				+ '    encrypted data: Bytes ['
				+ util.hexstrdump(this.encryptedData) + ']\n';
	}
	this.decrypt_sym = decrypt_sym;
	this.toString = toString;
	this.read_packet = read_packet;
	this.write_packet = write_packet;
};
