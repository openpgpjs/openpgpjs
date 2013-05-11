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
 * @classdesc Implementation of the Literal Data Packet (Tag 11)
 * 
 * RFC4880 5.9: A Literal Data packet contains the body of a message; data that
 * is not to be further interpreted.
 */
function literal() {
	this.format = 'utf8';
	this.data = '';
	this.date = new Date();

	
	/**
	 * Set the packet data to a javascript native string or a squence of 
	 * bytes. Conversion to a proper utf8 encoding takes place when the 
	 * packet is written.
	 * @param {String} str Any native javascript string
	 * @param {openpgp_packet_literaldata.format} format 
	 */
	this.set = function(str, format) {
		this.format = format;
		this.data = str;
	}

	/**
	 * Set the packet data to value represented by the provided string
	 * of bytes together with the appropriate conversion format.
	 * @param {String} bytes The string of bytes
	 * @param {openpgp_packet_literaldata.format} format
	 */
	this.setBytes = function(bytes, format) {
		this.format = format;

		if(format == 'utf8')
			bytes = util.decode_utf8(bytes);

		this.data = bytes;
	}

	/**
	 * Get the byte sequence representing the literal packet data
	 * @returns {String} A sequence of bytes
	 */
	this.getBytes = function() {
		if(this.format == 'utf8')
			return util.encode_utf8(this.data);
		else
			return this.data;
	}
	
	

	/**
	 * Parsing function for a literal data packet (tag 11).
	 * 
	 * @param {String} input Payload of a tag 11 packet
	 * @param {Integer} position
	 *            Position to start reading from the input string
	 * @param {Integer} len
	 *            Length of the packet or the remaining length of
	 *            input at position
	 * @return {openpgp_packet_encrypteddata} object representation
	 */
	this.read = function(bytes) {
		// - A one-octet field that describes how the data is formatted.

		var format = enums.read(bytes[0]);

		var filename_len = bytes.charCodeAt(1);
		this.filename = util.decode_utf8(bytes.substr(2, filename_len));

		this.date = openpgp_packet_time_read(bytes.substr(2
				+ filename_len, 4));

		var data = bytes.substring(6 + filename_len);
	
		this.set_data_bytes(data, format);
	}

	/**
	 * Creates a string representation of the packet
	 * 
	 * @param {String} data The data to be inserted as body
	 * @return {String} string-representation of the packet
	 */
	this.write = function() {
		var filename = util.encode_utf8("msg.txt");

		var data = this.get_data_bytes();

		var result = '';
		result += enums.write(this.format);
		result += String.fromCharCode(filename.length);
		result += filename;
		result += openpgp_packet_time_write(this.date);
		result += data;
		return result;
	}
}

