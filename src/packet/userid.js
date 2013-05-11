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

var util = require('../util');

/**
 * @class
 * @classdesc Implementation of the User ID Packet (Tag 13)
 * A User ID packet consists of UTF-8 text that is intended to represent
 * the name and email address of the key holder.  By convention, it
 * includes an RFC 2822 [RFC2822] mail name-addr, but there are no
 * restrictions on its content.  The packet length in the header
 * specifies the length of the User ID. 
 */
module.exports = function packet_userid() {
	/** @type {String} A string containing the user id. Usually in the form
	 * John Doe <john@example.com> 
	 */
	this.userid = '';
	
	
	/**
	 * Parsing function for a user id packet (tag 13).
	 * @param {String} input payload of a tag 13 packet
	 * @param {Integer} position position to start reading from the input string
	 * @param {Integer} len length of the packet or the remaining length of input 
	 * at position
	 * @return {openpgp_packet_encrypteddata} object representation
	 */
	this.read = function(bytes) {
		this.userid = util.decode_utf8(bytes);
	}

	/**
	 * Creates a string representation of the user id packet
	 * @param {String} user_id the user id as string ("John Doe <john.doe@mail.us")
	 * @return {String} string representation
	 */
	this.write = function() {
		return util.encode_utf8(this.userid);
	}
}
