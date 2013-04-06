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
function openpgp_packet_literaldata() {
	this.tagType = 11;

	
	/**
	 * Set the packet data to a javascript native string or a squence of 
	 * bytes. Conversion to a proper utf8 encoding takes place when the 
	 * packet is written.
	 * @param {String} str Any native javascript string
	 * @param {openpgp_packet_literaldata.formats} format 
	 */
	this.set_data = function(str, format) {
		this.format = format;
		this.data = str;
	}

	/**
	 * Set the packet data to value represented by the provided string
	 * of bytes together with the appropriate conversion format.
	 * @param {String} bytes The string of bytes
	 * @param {openpgp_packet_literaldata.formats} format
	 */
	this.set_data_bytes = function(bytes, format) {
		this.format = format;

		if(format == openpgp_packet_literaldata.formats.utf8)
			bytes = util.decode_utf8(bytes);

		this.data = bytes;
	}

	/**
	 * Get the byte sequence representing the literal packet data
	 * @returns {String} A sequence of bytes
	 */
	this.get_data_bytes = function() {
		if(this.format == openpgp_packet_literaldata.formats.utf8)
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
	this.read_packet = function(input, position, len) {
		this.packetLength = len;
		// - A one-octet field that describes how the data is formatted.

		var format = input[position];

		this.filename = util.decode_utf8(input.substr(position + 2, input
				.charCodeAt(position + 1)));

		this.date = new Date(parseInt(input.substr(position + 2
				+ input.charCodeAt(position + 1), 4)) * 1000);

		var bytes = input.substring(position + 6
				+ input.charCodeAt(position + 1));
	
		this.set_data_bytes(bytes, format);
		return this;
	}

	/**
	 * Creates a string representation of the packet
	 * 
	 * @param {String} data The data to be inserted as body
	 * @return {String} string-representation of the packet
	 */
	this.write_packet = function(data) {
		this.set_data(data, openpgp_packet_literaldata.formats.utf8);
		this.filename = util.encode_utf8("msg.txt");
		this.date = new Date();

		data = this.get_data_bytes();

		var result = openpgp_packet.write_packet_header(11, data.length + 6
				+ this.filename.length);
		result += this.format;
		result += String.fromCharCode(this.filename.length);
		result += this.filename;
		result += String
				.fromCharCode((Math.round(this.date.getTime() / 1000) >> 24) & 0xFF);
		result += String
				.fromCharCode((Math.round(this.date.getTime() / 1000) >> 16) & 0xFF);
		result += String
				.fromCharCode((Math.round(this.date.getTime() / 1000) >> 8) & 0xFF);
		result += String
				.fromCharCode(Math.round(this.date.getTime() / 1000) & 0xFF);
		result += data;
		return result;
	}

	/**
	 * Generates debug output (pretty print)
	 * 
	 * @return {String} String which gives some information about the keymaterial
	 */
	this.toString = function() {
		return '5.9.  Literal Data Packet (Tag 11)\n' + '    length: '
				+ this.packetLength + '\n' + '    format: ' + this.format
				+ '\n' + '    filename:' + this.filename + '\n'
				+ '    date:   ' + this.date + '\n' + '    data:  |'
				+ this.data + '|\n' + '    rdata: |' + this.real_data + '|\n';
	}
}

/**
 * Data types in the literal packet
 * @readonly
 * @enum {String}
 */
openpgp_packet_literaldata.formats = {
	/** Binary data */
	binary: 'b',
	/** Text data */
	text: 't',
	/** Utf8 data */
	utf8: 'u'
};
