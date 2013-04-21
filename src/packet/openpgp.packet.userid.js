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
 * @classdesc Implementation of the User ID Packet (Tag 13)
 * A User ID packet consists of UTF-8 text that is intended to represent
 * the name and email address of the key holder.  By convention, it
 * includes an RFC 2822 [RFC2822] mail name-addr, but there are no
 * restrictions on its content.  The packet length in the header
 * specifies the length of the User ID. 
 */

function openpgp_packet_userid() {
	this.text = ''
	this.tagType = 13;
	this.certificationSignatures = new Array();
	this.certificationRevocationSignatures = new Array();
	this.revocationSignatures = new Array();
	this.parentNode = null;
	
	/**
	 * Set the packet text field to a native javascript string
	 * Conversion to a proper utf8 encoding takes place when the 
	 * packet is written.
	 * @param {String} str Any native javascript string
	 */
	this.set_text = function(str) {
		this.text = str;
	}

	/**
	 * Set the packet text to value represented by the provided string
	 * of bytes.
	 * @param {String} bytes A string of bytes
	 */
	this.set_text_bytes = function(bytes) {
		this.text = util.decode_utf8(bytes);
	}

	/**
	 * Get the byte sequence representing the text of this packet.
	 * @returns {String} A sequence of bytes
	 */
	this.get_text_bytes = function() {
		return util.encode_utf8(this.text);
	}
	

	/**
	 * Parsing function for a user id packet (tag 13).
	 * @param {String} input payload of a tag 13 packet
	 * @param {Integer} position position to start reading from the input string
	 * @param {Integer} len length of the packet or the remaining length of input at position
	 * @return {openpgp_packet_encrypteddata} object representation
	 */
	this.read_packet = function(input, position, len) {
		this.packetLength = len;

		var bytes = '';
		for ( var i = 0; i < len; i++) {
			bytes += input[position + i];
		}

		this.set_text_bytes(bytes);
		return this;
	}

	/**
	 * Creates a string representation of the user id packet
	 * @param {String} user_id the user id as string ("John Doe <john.doe@mail.us")
	 * @return {String} string representation
	 */
	this.write_packet = function(user_id) {
		this.set_text(user_id);
		var bytes = this.get_text_bytes();

		var result = openpgp_packet.write_packet_header(13, bytes.length);
		result += bytes;
		return result;
	}

	/**
	 * Continue parsing packets belonging to the userid packet such as signatures
	 * @param {Object} parent_node the parent object
	 * @param {String} input input string to read the packet(s) from
	 * @param {Integer} position start position for the parser
	 * @param {Integer} len length of the packet(s) or remaining length of input
	 * @return {Integer} length of nodes read
	 */
	this.read_nodes = function(parent_node, input, position, len) {
		if (parent_node.tagType == 6) { // public key
			this.parentNode = parent_node;
			var pos = position;
			var l = len;
			while (input.length != pos) {
				var result = openpgp_packet.read_packet(input, pos, l - (pos - position));
				if (result == null) {
					util.print_error('[user_id] parsing ends here @:' + pos + " l:" + l);
					break;
				} else {
					
					pos += result.packetLength + result.headerLength;
					l = input.length - pos;
					switch (result.tagType) {
					case 2: // Signature Packet
						if (result.signatureType > 15
								&& result.signatureType < 20) { // certification
							// //
							// signature
							this.certificationSignatures[this.certificationSignatures.length] = result;
							break;
						} else if (result.signatureType == 48) {// certification revocation signature
							this.certificationRevocationSignatures[this.certificationRevocationSignatures.length] = result;
							break;
						} else if (result.signatureType == 24) { // omg. standalone signature 
							this.certificationSignatures[this.certificationSignatures.length] = result;
							break;
						} else {
							util.print_debug("unknown sig t: "+result.signatureType+"@"+(pos - (result.packetLength + result.headerLength)));
						}
					default:
						this.data = input;
						this.position = position - parent_node.packetLength;
						this.len = pos - position -(result.headerLength + result.packetLength);
						return this.len;
					}
				}
			}
			this.data = input;
			this.position = position - parent_node.packetLength;
			this.len = pos - position -(result.headerLength + result.packetLength);
			return this.len;
		} else if (parent_node.tagType == 5) { // secret Key
			this.parentNode = parent_node;
			var exit = false;
			var pos = position;
			while (input.length != pos) {
				var result = openpgp_packet.read_packet(input, pos, l - (pos - position));
				if (result == null) {
					util.print_error('parsing ends here @:' + pos + " l:" + l);
					break;
				} else {
					pos += result.packetLength + result.headerLength;
					l = input.length - pos;
					switch (result.tagType) {
					case 2: // Signature Packet certification signature
						if (result.signatureType > 15
								&& result.signatureType < 20)
							this.certificationSignatures[this.certificationSignatures.length] = result;
						// certification revocation signature
						else if (result.signatureType == 48)
							this.certificationRevocationSignatures[this.certificationRevocationSignatures.length] = result;
					default:
						this.data = input;
						this.position = position - parent_node.packetLength;
						this.len = pos - position -(result.headerLength + result.packetLength);
						return this.len;
					}
				}
			}
		} else {
			util.print_error("unknown parent node for a userId packet "+parent_node.tagType);
		}
	}
	
	/**
	 * generates debug output (pretty print)
	 * @return {String} String which gives some information about the user id packet
	 */
	this.toString = function() {
		var result = '     5.11.  User ID Packet (Tag 13)\n' + '    text ('
				+ this.text.length + '): "' + this.text.replace("<", "&lt;")
				+ '"\n';
		result +="certification signatures:\n";
		for (var i = 0; i < this.certificationSignatures.length; i++) {
			result += "        "+this.certificationSignatures[i].toString();
		}
		result +="certification revocation signatures:\n";
		for (var i = 0; i < this.certificationRevocationSignatures.length; i++) {
			result += "        "+this.certificationRevocationSignatures[i].toString();
		}
		return result;
	}

	/**
	 * lookup function to find certification revocation signatures
	 * @param {String} keyId string containing the key id of the issuer of this signature
	 * @return a CertificationRevocationSignature if found; otherwise null
	 */
	this.hasCertificationRevocationSignature = function(keyId) {
		for (var i = 0; i < this.certificationRevocationSignatures.length; i++) {
			if ((this.certificationRevocationSignatures[i].version == 3 &&
				 this.certificationRevocationSignatures[i].keyId == keyId) ||
				(this.certificationRevocationSignatures[i].version == 4 &&
				 this.certificationRevocationSignatures[i].issuerKeyId == keyId))
				return this.certificationRevocationSignatures[i];
		}
		return null;
	}

	/**
	 * Verifies all certification signatures. This method does not consider possible revocation signatures.
	 * @param {Object} publicKeyPacket the top level key material
	 * @return {Integer[]} An array of integers corresponding to the array of certification signatures. The meaning of each integer is the following:
	 * 0 = bad signature
	 * 1 = signature expired
	 * 2 = issuer key not available
	 * 3 = revoked
	 * 4 = signature valid
	 * 5 = signature by key owner expired
	 * 6 = signature by key owner revoked
	 */
	this.verifyCertificationSignatures = function(publicKeyPacket) {
		var bytes = this.get_text_bytes();
		result = new Array();
		for (var i = 0 ; i < this.certificationSignatures.length; i++) {
			// A certification signature (type 0x10 through 0x13) hashes the User
			// ID being bound to the key into the hash context after the above
			// data.  A V3 certification hashes the contents of the User ID or
			// attribute packet packet, without any header.  A V4 certification
			// hashes the constant 0xB4 for User ID certifications or the constant
			// 0xD1 for User Attribute certifications, followed by a four-octet
			// number giving the length of the User ID or User Attribute data, and
			// then the User ID or User Attribute data.

			if (this.certificationSignatures[i].version == 4) {
				if (this.certificationSignatures[i].signatureExpirationTime != null &&
						this.certificationSignatures[i].signatureExpirationTime != null &&
						this.certificationSignatures[i].signatureExpirationTime != 0 &&
						!this.certificationSignatures[i].signatureNeverExpires &&
						new Date(this.certificationSignatures[i].creationTime.getTime() +(this.certificationSignatures[i].signatureExpirationTime*1000)) < new Date()) {
					if (this.certificationSignatures[i].issuerKeyId == publicKeyPacket.getKeyId())
						result[i] = 5;
					else
						result[i] = 1;
					continue;
				}
				if (this.certificationSignatures[i].issuerKeyId == null) {
					result[i] = 0;
					continue;
				}
				var issuerPublicKey = openpgp.keyring.getPublicKeysForKeyId(this.certificationSignatures[i].issuerKeyId);
				if (issuerPublicKey == null || issuerPublicKey.length == 0) {
					result[i] = 2;
					continue;
				}
				// TODO: try to verify all returned issuer public keys (key ids are not unique!)
				var issuerPublicKey = issuerPublicKey[0];
				var signingKey = issuerPublicKey.obj.getSigningKey();
				if (signingKey == null) {
					result[i] = 0;
					continue;
				}
				var revocation = this.hasCertificationRevocationSignature(this.certificationSignatures[i].issuerKeyId);
				if (revocation != null && revocation.creationTime > 
					this.certificationSignatures[i].creationTime) {

					var signaturedata = String.fromCharCode(0x99)+ publicKeyPacket.header.substring(1)+
					publicKeyPacket.data+String.fromCharCode(0xB4)+
					String.fromCharCode((bytes.length >> 24) & 0xFF)+
					String.fromCharCode((bytes.length >> 16) & 0xFF)+
					String.fromCharCode((bytes.length >>  8) & 0xFF)+
					String.fromCharCode((bytes.length) & 0xFF)+
					bytes;
					if (revocation.verify(signaturedata, signingKey)) {
						if (this.certificationSignatures[i].issuerKeyId == publicKeyPacket.getKeyId())
							result[i] = 6;
						else
							result[i] = 3;
						continue;
					}
				}

				var signaturedata = String.fromCharCode(0x99)+ publicKeyPacket.header.substring(1)+
						publicKeyPacket.data+String.fromCharCode(0xB4)+
						String.fromCharCode((bytes.length >> 24) & 0xFF)+
						String.fromCharCode((bytes.length >> 16) & 0xFF)+
						String.fromCharCode((bytes.length >>  8) & 0xFF)+
						String.fromCharCode((bytes.length) & 0xFF)+
						bytes;
				if (this.certificationSignatures[i].verify(signaturedata, signingKey)) {
					result[i] = 4;
				} else
				result[i] = 0;
			} else if (this.certificationSignatures[i].version == 3) {
				if (this.certificationSignatures[i].keyId == null) {
					result[i] = 0;
					continue;
				}
				var issuerPublicKey = openpgp.keyring.getPublicKeysForKeyId(this.certificationSignatures[i].keyId);
				if (issuerPublicKey == null || issuerPublicKey.length == 0) {
					result[i] = 2;
					continue;
				}
				issuerPublicKey = issuerPublicKey[0];
				var signingKey = publicKey.obj.getSigningKey();
				if (signingKey == null) {
					result[i] = 0;
					continue;
				}
				var revocation = this.hasCertificationRevocationSignature(this.certificationSignatures[i].keyId);
				if (revocation != null && revocation.creationTime > 
					this.certificationSignatures[i].creationTime) {
					var signaturedata = String.fromCharCode(0x99)+ this.publicKeyPacket.header.substring(1)+
					this.publicKeyPacket.data+bytes;
					if (revocation.verify(signaturedata, signingKey)) {
						if (revocation.keyId == publicKeyPacket.getKeyId())
							result[i] = 6;
						else
							result[i] = 3;
						continue;
					}
				}
				var signaturedata = String.fromCharCode(0x99)+ publicKeyPacket.header.substring(1)+
					publicKeyPacket.data + bytes;
				if (this.certificationSignatures[i].verify(signaturedata, signingKey)) {
					result[i] = 4;
				} else 
				result[i] = 0;
			} else {
				result[i] = 0;
			}
		}
		return result;
	}

	/**
	 * verifies the signatures of the user id
	 * @return 0 if the userid is valid; 1 = userid expired; 2 = userid revoked
	 */
	this.verify = function(publicKeyPacket) {
		var result = this.verifyCertificationSignatures(publicKeyPacket);
		if (result.indexOf(6) != -1)
			return 2;
		if (result.indexOf(5) != -1)
			return 1;
		return 0;
	}

	// TODO: implementation missing
	this.addCertification = function(publicKeyPacket, privateKeyPacket) {
		
	}

	// TODO: implementation missing
	this.revokeCertification = function(publicKeyPacket, privateKeyPacket) {
		
	}
}
