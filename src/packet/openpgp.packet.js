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
 * @classdesc Parent openpgp packet class. Operations focus on determining 
 * packet types and packet header.
 */
function _openpgp_packet() {
	/**
	 * Encodes a given integer of length to the openpgp length specifier to a
	 * string
	 * 
	 * @param {Integer} length The length to encode
	 * @return {String} String with openpgp length representation
	 */
	function encode_length(length) {
		result = "";
		if (length < 192) {
			result += String.fromCharCode(length);
		} else if (length > 191 && length < 8384) {
			/*
			 * let a = (total data packet length) - 192 let bc = two octet
			 * representation of a let d = b + 192
			 */
			result += String.fromCharCode(((length - 192) >> 8) + 192);
			result += String.fromCharCode((length - 192) & 0xFF);
		} else {
			result += String.fromCharCode(255);
			result += String.fromCharCode((length >> 24) & 0xFF);
			result += String.fromCharCode((length >> 16) & 0xFF);
			result += String.fromCharCode((length >> 8) & 0xFF);
			result += String.fromCharCode(length & 0xFF);
		}
		return result;
	}
	this.encode_length = encode_length;

	/**
	 * Writes a packet header version 4 with the given tag_type and length to a
	 * string
	 * 
	 * @param {Integer} tag_type Tag type
	 * @param {Integer} length Length of the payload
	 * @return {String} String of the header
	 */
	function write_packet_header(tag_type, length) {
		/* we're only generating v4 packet headers here */
		var result = "";
		result += String.fromCharCode(0xC0 | tag_type);
		result += encode_length(length);
		return result;
	}

	/**
	 * Writes a packet header Version 3 with the given tag_type and length to a
	 * string
	 * 
	 * @param {Integer} tag_type Tag type
	 * @param {Integer} length Length of the payload
	 * @return {String} String of the header
	 */
	function write_old_packet_header(tag_type, length) {
		var result = "";
		if (length < 256) {
			result += String.fromCharCode(0x80 | (tag_type << 2));
			result += String.fromCharCode(length);
		} else if (length < 65536) {
			result += String.fromCharCode(0x80 | (tag_type << 2) | 1);
			result += String.fromCharCode(length >> 8);
			result += String.fromCharCode(length & 0xFF);
		} else {
			result += String.fromCharCode(0x80 | (tag_type << 2) | 2);
			result += String.fromCharCode((length >> 24) & 0xFF);
			result += String.fromCharCode((length >> 16) & 0xFF);
			result += String.fromCharCode((length >> 8) & 0xFF);
			result += String.fromCharCode(length & 0xFF);
		}
		return result;
	}
	this.write_old_packet_header = write_old_packet_header;
	this.write_packet_header = write_packet_header;
	/**
	 * Generic static Packet Parser function
	 * 
	 * @param {String} input Input stream as string
	 * @param {integer} position Position to start parsing
	 * @param {integer} len Length of the input from position on
	 * @return {Object} Returns a parsed openpgp_packet
	 */
	function read_packet(input, position, len) {
		// some sanity checks
		if (input == null || input.length <= position
				|| input.substring(position).length < 2
				|| (input[position].charCodeAt() & 0x80) == 0) {
			util
					.print_error("Error during parsing. This message / key is probably not containing a valid OpenPGP format.");
			return null;
		}
		var mypos = position;
		var tag = -1;
		var format = -1;

		format = 0; // 0 = old format; 1 = new format
		if ((input[mypos].charCodeAt() & 0x40) != 0) {
			format = 1;
		}

		var packet_length_type;
		if (format) {
			// new format header
			tag = input[mypos].charCodeAt() & 0x3F; // bit 5-0
		} else {
			// old format header
			tag = (input[mypos].charCodeAt() & 0x3F) >> 2; // bit 5-2
			packet_length_type = input[mypos].charCodeAt() & 0x03; // bit 1-0
		}

		// header octet parsing done
		mypos++;

		// parsed length from length field
		var bodydata = null;

		// used for partial body lengths
		var real_packet_length = -1;
		if (!format) {
			// 4.2.1. Old Format Packet Lengths
			switch (packet_length_type) {
			case 0: // The packet has a one-octet length. The header is 2 octets
				// long.
				packet_length = input[mypos++].charCodeAt();
				break;
			case 1: // The packet has a two-octet length. The header is 3 octets
				// long.
				packet_length = (input[mypos++].charCodeAt() << 8)
						| input[mypos++].charCodeAt();
				break;
			case 2: // The packet has a four-octet length. The header is 5
				// octets long.
				packet_length = (input[mypos++].charCodeAt() << 24)
						| (input[mypos++].charCodeAt() << 16)
						| (input[mypos++].charCodeAt() << 8)
						| input[mypos++].charCodeAt();
				break;
			default:
				// 3 - The packet is of indeterminate length. The header is 1
				// octet long, and the implementation must determine how long
				// the packet is. If the packet is in a file, this means that
				// the packet extends until the end of the file. In general, 
				// an implementation SHOULD NOT use indeterminate-length 
				// packets except where the end of the data will be clear 
				// from the context, and even then it is better to use a 
				// definite length, or a new format header. The new format 
				// headers described below have a mechanism for precisely
				// encoding data of indeterminate length.
				packet_length = len;
				break;
			}

		} else // 4.2.2. New Format Packet Lengths
		{

			// 4.2.2.1. One-Octet Lengths
			if (input[mypos].charCodeAt() < 192) {
				packet_length = input[mypos++].charCodeAt();
				util.print_debug("1 byte length:" + packet_length);
				// 4.2.2.2. Two-Octet Lengths
			} else if (input[mypos].charCodeAt() >= 192
					&& input[mypos].charCodeAt() < 224) {
				packet_length = ((input[mypos++].charCodeAt() - 192) << 8)
						+ (input[mypos++].charCodeAt()) + 192;
				util.print_debug("2 byte length:" + packet_length);
				// 4.2.2.4. Partial Body Lengths
			} else if (input[mypos].charCodeAt() > 223
					&& input[mypos].charCodeAt() < 255) {
				packet_length = 1 << (input[mypos++].charCodeAt() & 0x1F);
				util.print_debug("4 byte length:" + packet_length);
				// EEEK, we're reading the full data here...
				var mypos2 = mypos + packet_length;
				bodydata = input.substring(mypos, mypos + packet_length);
				while (true) {
					if (input[mypos2].charCodeAt() < 192) {
						var tmplen = input[mypos2++].charCodeAt();
						packet_length += tmplen;
						bodydata += input.substring(mypos2, mypos2 + tmplen);
						mypos2 += tmplen;
						break;
					} else if (input[mypos2].charCodeAt() >= 192
							&& input[mypos2].charCodeAt() < 224) {
						var tmplen = ((input[mypos2++].charCodeAt() - 192) << 8)
								+ (input[mypos2++].charCodeAt()) + 192;
						packet_length += tmplen;
						bodydata += input.substring(mypos2, mypos2 + tmplen);
						mypos2 += tmplen;
						break;
					} else if (input[mypos2].charCodeAt() > 223
							&& input[mypos2].charCodeAt() < 255) {
						var tmplen = 1 << (input[mypos2++].charCodeAt() & 0x1F);
						packet_length += tmplen;
						bodydata += input.substring(mypos2, mypos2 + tmplen);
						mypos2 += tmplen;
					} else {
						mypos2++;
						var tmplen = (input[mypos2++].charCodeAt() << 24)
								| (input[mypos2++].charCodeAt() << 16)
								| (input[mypos2++].charCodeAt() << 8)
								| input[mypos2++].charCodeAt();
						bodydata += input.substring(mypos2, mypos2 + tmplen);
						packet_length += tmplen;
						mypos2 += tmplen;
						break;
					}
				}
				real_packet_length = mypos2 - mypos;
				// 4.2.2.3. Five-Octet Lengths
			} else {
				mypos++;
				packet_length = (input[mypos++].charCodeAt() << 24)
						| (input[mypos++].charCodeAt() << 16)
						| (input[mypos++].charCodeAt() << 8)
						| input[mypos++].charCodeAt();
			}
		}

		// if there was'nt a partial body length: use the specified
		// packet_length
		if (real_packet_length == -1) {
			real_packet_length = packet_length;
		}

		if (bodydata == null) {
			bodydata = input.substring(mypos, mypos + real_packet_length);
		}

		// alert('tag type: '+this.tag+' length: '+packet_length);
		var version = 1; // (old format; 2= new format)
		// if (input[mypos++].charCodeAt() > 15)
		// version = 2;

		switch (tag) {
		case 0: // Reserved - a packet tag MUST NOT have this value
			break;
		case 1: // Public-Key Encrypted Session Key Packet
			var result = new openpgp_packet_encryptedsessionkey();
			if (result.read_pub_key_packet(bodydata, 0, packet_length) != null) {
				result.headerLength = mypos - position;
				result.packetLength = real_packet_length;
				return result;
			}
			break;
		case 2: // Signature Packet
			var result = new openpgp_packet_signature();
			if (result.read_packet(bodydata, 0, packet_length) != null) {
				result.headerLength = mypos - position;
				result.packetLength = real_packet_length;
				return result;
			}
			break;
		case 3: // Symmetric-Key Encrypted Session Key Packet
			var result = new openpgp_packet_encryptedsessionkey();
			if (result.read_symmetric_key_packet(bodydata, 0, packet_length) != null) {
				result.headerLength = mypos - position;
				result.packetLength = real_packet_length;
				return result;
			}
			break;
		case 4: // One-Pass Signature Packet
			var result = new openpgp_packet_onepasssignature();
			if (result.read_packet(bodydata, 0, packet_length)) {
				result.headerLength = mypos - position;
				result.packetLength = real_packet_length;
				return result;
			}
			break;
		case 5: // Secret-Key Packet
			var result = new openpgp_packet_keymaterial();
			result.header = input.substring(position, mypos);
			if (result.read_tag5(bodydata, 0, packet_length) != null) {
				result.headerLength = mypos - position;
				result.packetLength = real_packet_length;
				return result;
			}
			break;
		case 6: // Public-Key Packet
			var result = new openpgp_packet_keymaterial();
			result.header = input.substring(position, mypos);
			if (result.read_tag6(bodydata, 0, packet_length) != null) {
				result.headerLength = mypos - position;
				result.packetLength = real_packet_length;
				return result;
			}
			break;
		case 7: // Secret-Subkey Packet
			var result = new openpgp_packet_keymaterial();
			if (result.read_tag7(bodydata, 0, packet_length) != null) {
				result.headerLength = mypos - position;
				result.packetLength = real_packet_length;
				return result;
			}
			break;
		case 8: // Compressed Data Packet
			var result = new openpgp_packet_compressed();
			if (result.read_packet(bodydata, 0, packet_length) != null) {
				result.headerLength = mypos - position;
				result.packetLength = real_packet_length;
				return result;
			}
			break;
		case 9: // Symmetrically Encrypted Data Packet
			var result = new openpgp_packet_encrypteddata();
			if (result.read_packet(bodydata, 0, packet_length) != null) {
				result.headerLength = mypos - position;
				result.packetLength = real_packet_length;
				return result;
			}
			break;
		case 10: // Marker Packet = PGP (0x50, 0x47, 0x50)
			var result = new openpgp_packet_marker();
			if (result.read_packet(bodydata, 0, packet_length) != null) {
				result.headerLength = mypos - position;
				result.packetLength = real_packet_length;
				return result;
			}
			break;
		case 11: // Literal Data Packet
			var result = new openpgp_packet_literaldata();
			if (result.read_packet(bodydata, 0, packet_length) != null) {
				result.headerLength = mypos - position;
				result.header = input.substring(position, mypos);
				result.packetLength = real_packet_length;
				return result;
			}
			break;
		case 12: // Trust Packet
			// TODO: to be implemented
			break;
		case 13: // User ID Packet
			var result = new openpgp_packet_userid();
			if (result.read_packet(bodydata, 0, packet_length) != null) {
				result.headerLength = mypos - position;
				result.packetLength = real_packet_length;
				return result;
			}
			break;
		case 14: // Public-Subkey Packet
			var result = new openpgp_packet_keymaterial();
			result.header = input.substring(position, mypos);
			if (result.read_tag14(bodydata, 0, packet_length) != null) {
				result.headerLength = mypos - position;
				result.packetLength = real_packet_length;
				return result;
			}
			break;
		case 17: // User Attribute Packet
			var result = new openpgp_packet_userattribute();
			if (result.read_packet(bodydata, 0, packet_length) != null) {
				result.headerLength = mypos - position;
				result.packetLength = real_packet_length;
				return result;
			}
			break;
		case 18: // Sym. Encrypted and Integrity Protected Data Packet
			var result = new openpgp_packet_encryptedintegrityprotecteddata();
			if (result.read_packet(bodydata, 0, packet_length) != null) {
				result.headerLength = mypos - position;
				result.packetLength = real_packet_length;
				return result;
			}
			break;
		case 19: // Modification Detection Code Packet
			var result = new openpgp_packet_modificationdetectioncode();
			if (result.read_packet(bodydata, 0, packet_length) != null) {
				result.headerLength = mypos - position;
				result.packetLength = real_packet_length;
				return result;
			}
			break;
		default:
			util.print_error("openpgp.packet.js\n"
					+ "[ERROR] openpgp_packet: failed to parse packet @:"
					+ mypos + "\nchar:'"
					+ util.hexstrdump(input.substring(mypos)) + "'\ninput:"
					+ util.hexstrdump(input));
			return null;
			break;
		}
	}

	this.read_packet = read_packet;
}

var openpgp_packet = new _openpgp_packet();
