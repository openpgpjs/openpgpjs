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
 * @classdesc Implementation of the Modification Detection Code Packet (Tag 19)
 * 
 * RFC4880 5.14: The Modification Detection Code packet contains a SHA-1 hash of
 * plaintext data, which is used to detect message modification. It is only used
 * with a Symmetrically Encrypted Integrity Protected Data packet. The
 * Modification Detection Code packet MUST be the last packet in the plaintext
 * data that is encrypted in the Symmetrically Encrypted Integrity Protected
 * Data packet, and MUST appear in no other place.
 */

function openpgp_packet_modificationdetectioncode() {
	this.tagType = 19;
	this.hash = null;
	/**
	 * parsing function for a modification detection code packet (tag 19).
	 * 
	 * @param {String} input payload of a tag 19 packet
	 * @param {Integer} position
	 *            position to start reading from the input string
	 * @param {Integer} len
	 *            length of the packet or the remaining length of
	 *            input at position
	 * @return {openpgp_packet_encrypteddata} object representation
	 */
	function read_packet(input, position, len) {
		this.packetLength = len;

		if (len != 20) {
			util
					.print_error("openpgp.packet.modificationdetectioncode.js\n"
							+ 'invalid length for a modification detection code packet!'
							+ len);
			return null;
		}
		// - A 20-octet SHA-1 hash of the preceding plaintext data of the
		// Symmetrically Encrypted Integrity Protected Data packet,
		// including prefix data, the tag octet, and length octet of the
		// Modification Detection Code packet.
		this.hash = input.substring(position, position + 20);
		return this;
	}

	/*
	 * this packet is created within the encryptedintegrityprotected packet
	 * function write_packet(data) { }
	 */

	/**
	 * generates debug output (pretty print)
	 * 
	 * @return {String} String which gives some information about the 
	 * modification detection code
	 */
	function toString() {
		return '5.14 Modification detection code packet\n' + '    bytes ('
				+ this.hash.length + '): [' + util.hexstrdump(this.hash) + ']';
	}
	this.read_packet = read_packet;
	this.toString = toString;
};
