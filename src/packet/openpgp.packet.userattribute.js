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
 * @classdesc Implementation of the User Attribute Packet (Tag 17)
 *  The User Attribute packet is a variation of the User ID packet.  It
 *  is capable of storing more types of data than the User ID packet,
 *  which is limited to text.  Like the User ID packet, a User Attribute
 *  packet may be certified by the key owner ("self-signed") or any other
 *  key owner who cares to certify it.  Except as noted, a User Attribute
 *  packet may be used anywhere that a User ID packet may be used.
 *
 *  While User Attribute packets are not a required part of the OpenPGP
 *  standard, implementations SHOULD provide at least enough
 *  compatibility to properly handle a certification signature on the
 *  User Attribute packet.  A simple way to do this is by treating the
 *  User Attribute packet as a User ID packet with opaque contents, but
 *  an implementation may use any method desired.
 */
function openpgp_packet_userattribute() {
	this.tagType = 17;
	this.certificationSignatures = [];
	this.certificationRevocationSignatures = [];
	this.revocationSignatures = [];
	this.userattributes = [];

	/**
	 * parsing function for a user attribute packet (tag 17).
	 * @param {String} input payload of a tag 17 packet
	 * @param {Integer} position position to start reading from the input string
	 * @param {Integer} len length of the packet or the remaining length of input at position
	 * @return {openpgp_packet_encrypteddata} object representation
	 */
	this.read = function(bytes) {
		var count = 0;
		var mypos = 0;
		var packet_len = 0;

		while (mypos != bytes.length) {
			var current_len = 0;
			// 4.2.2.1. One-Octet Lengths
			if (bytes[mypos].charCodeAt() < 192) {
				packet_length = bytes[mypos++].charCodeAt();
				current_len = 1;
			// 4.2.2.2. Two-Octet Lengths
			} else if (bytes[mypos].charCodeAt() >= 192 && bytes[mypos].charCodeAt() < 224) {
				packet_length = ((bytes[mypos++].charCodeAt() - 192) << 8)
					+ (bytes[mypos++].charCodeAt()) + 192;
				current_len = 2;
			// 4.2.2.4. Partial Body Lengths
			} else if (bytes[mypos].charCodeAt() > 223 && bytes[mypos].charCodeAt() < 255) {
				packet_length = 1 << (bytes[mypos++].charCodeAt() & 0x1F);
				current_len = 1;
			// 4.2.2.3. Five-Octet Lengths
			} else {
				current_len = 5;
				mypos++;
				packet_length = (bytes[mypos++].charCodeAt() << 24) | 
					(bytes[mypos++].charCodeAt() << 16)
					| (bytes[mypos++].charCodeAt() << 8) | bytes[mypos++].charCodeAt();
			}
			
			var subpackettype = bytes[mypos++].charCodeAt();
			packet_length--;
			current_len++;
			this.userattributes[count] = [];
			this.userattributes[count] = bytes.substring(mypos, mypos + packet_len);
			mypos += packet_length;
			total_len += current_len+packet_len;
		}

		return this;
	}
	
	/**
	 * generates debug output (pretty print)
	 * @return {String} String which gives some information about the user attribute packet
	 */
	function toString() {
		var result = '5.12.  User Attribute Packet (Tag 17)\n'+
		             '    AttributePackets: (count = '+this.userattributes.length+')\n';
		for (var i = 0; i < this.userattributes.length; i++) {
			result += '    ('+this.userattributes[i].length+') bytes: ['+util.hexidump(this.userattributes[i])+']\n'; 
		}
		return result;
	}
	
	/**
	 * Continue parsing packets belonging to the user attribute packet such as signatures
	 * @param {Object} parent_node the parent object
	 * @param {String} input input string to read the packet(s) from
	 * @param {Integer} position start position for the parser
	 * @param {Integer} len length of the packet(s) or remaining length of input
	 * @return {Integer} length of nodes read
	 */
	function read_nodes(parent_node, input, position, len) {
		
		this.parentNode = parent_node;
		var exit = false;
		var pos = position;
		var l = len;
		while (input.length != pos) {
			var result = openpgp_packet.read_packet(input, pos, l);
			if (result == null) {
				util.print_error("openpgp.packet.userattribute.js\n"+'[user_attr] parsing ends here @:' + pos + " l:" + l);
				break;
			} else {
				switch (result.tagType) {
				case 2: // Signature Packet
					if (result.signatureType > 15
							&& result.signatureType < 20) // certification
						// //
						// signature
						this.certificationSignatures[this.certificationSignatures.length] = result;
					else if (result.signatureType == 32) // certification revocation signature
						this.certificationRevocationSignatures[this.certificationRevocationSignatures.length] = result;
					pos += result.packetLength + result.headerLength;
					l = len - (pos - position);
					break;
				default:
					this.data = input;
					this.position = position - parent_node.packetLength;
					this.len = pos - position;
					return this.len;
					break;
				}
			}
		}
		this.data = input;
		this.position = position - parent_node.packetLength;
		this.len = pos - position;
		return this.len;

	}
	
	this.read_packet = read_packet;
	this.read_nodes = read_nodes;
	this.toString = toString;
	
};
