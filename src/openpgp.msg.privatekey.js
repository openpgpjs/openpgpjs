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
 * @classdesc Class that represents a decoded private key for internal openpgp.js use
 */

function openpgp_msg_privatekey() {
	this.subKeys = new Array();
	this.privateKeyPacket = null;
	this.userIds = new Array();
	this.userAttributes = new Array();
	this.revocationSignatures = new Array();
	this.subKeys = new Array();

	/**
	 * 
	 * @return last position
	 */
	function read_nodes(parent_node, input, position, len) {
		this.privateKeyPacket = parent_node;
		
		var pos = position;
		while (input.length > pos) {
			var result = openpgp_packet.read_packet(input, pos, input.length - pos);
			if (result == null) {
				util.print_error("openpgp.msg.messge decrypt:\n"+'[pub/priv_key]parsing ends here @:' + pos + " l:" + len);
				break;
			} else {
				switch (result.tagType) {
				case 2: // public key revocation signature
					if (result.signatureType == 32)
						this.revocationSignatures[this.revocationSignatures.length] = result;
					else if (result.signatureType > 15 && result.signatureType < 20) {
						if (this.certificationsignatures == null)
							this.certificationSignatures = new Array();
						this.certificationSignatures[this.certificationSignatures.length] = result;
					} else
						util.print_error("openpgp.msg.messge decrypt:\n"+"unknown signature type directly on key "+result.signatureType+" @"+pos);
					pos += result.packetLength + result.headerLength;
					break;
				case 7: // PrivateSubkey Packet
					this.subKeys[this.subKeys.length] = result;
					pos += result.packetLength + result.headerLength;
					pos += result.read_nodes(this.privateKeyPacket,input, pos, input.length - pos);
					break;
				case 17: // User Attribute Packet
					this.userAttributes[this.userAttributes.length] = result;
					pos += result.packetLength + result.headerLength;
					pos += result.read_nodes(this.privateKeyPacket,input, pos, input.length - pos);
					break;
				case 13: // User ID Packet
					this.userIds[this.userIds.length] = result;
					pos += result.packetLength + result.headerLength;
					pos += result.read_nodes(this.privateKeyPacket, input, pos, input.length - pos);
					break;
				default:
					this.position = position - this.privateKeyPacket.packetLength - this.privateKeyPacket.headerLength;
					this.len = pos - position;
					return this.len;
				}
			}
		}
		this.position = position - this.privateKeyPacket.packetLength - this.privateKeyPacket.headerLength;
		this.len = pos - position;
		
		return this.len;
	}
	
	function getKeyId() {
		return this.privateKeyPacket.publicKey.getKeyId();
	}
	
	
	function getSubKeyIds() {
		if (this.privateKeyPacket.publicKey.version == 4) // V3 keys MUST NOT have subkeys.
		var result = new Array();
		for (var i = 0; i < this.subKeys.length; i++) {
			result[i] = str_sha1(this.subKeys[i].publicKey.header+this.subKeys[i].publicKey.data).substring(12,20);
		}
		return result;
	}
	
	
	function getSigningKey() {
		if ((this.privateKeyPacket.publicKey.publicKeyAlgorithm == 17 ||
			 this.privateKeyPacket.publicKey.publicKeyAlgorithm != 2)
			&& this.privateKeyPacket.publicKey.verifyKey() == 3)
			return this.privateKeyPacket;
		else if (this.privateKeyPacket.publicKey.version == 4) // V3 keys MUST NOT have subkeys.
			for (var j = 0; j < this.privateKeyPacket.subKeys.length; j++) {
				if ((this.privateKeyPacket.subKeys[j].publicKey.publicKeyAlgorithm == 17 ||
					 this.privateKeyPacket.subKeys[j].publicKey.publicKeyAlgorithm != 2) &&
					 this.privateKeyPacket.subKeys[j].publicKey.verifyKey() == 3)
					return this.privateKeyPacket.subKeys[j];
			}
		return null;
	}
	
	function getPreferredSignatureHashAlgorithm() {
		var pkey = this.getSigningKey();
		if (pkey == null) {
			util.print_error("private key is for encryption only! Cannot create a signature.")
			return null;
		}
		if (pkey.publicKey.publicKeyAlgorithm == 17) {
			var dsa = new DSA();
			return dsa.select_hash_algorithm(pkey.publicKey.MPIs[1].toBigInteger()); // q
		}
		//TODO implement: https://tools.ietf.org/html/rfc4880#section-5.2.3.8
		//separate private key preference from digest preferences
		return openpgp.config.config.prefer_hash_algorithm;
			
	}

	function decryptSecretMPIs(str_passphrase) {
		return this.privateKeyPacket.decryptSecretMPIs(str_passphrase);
	}
	
	function getFingerprint() {
		return this.privateKeyPacket.publicKey.getFingerprint();
	}

	// TODO need to implement this
	function revoke() {
		
	}

	/**
	 * extracts the public key part
	 * @return {String} OpenPGP armored text containing the public key
	 *                  returns null if no sufficient data to extract public key
	 */
	function extractPublicKey() {
		// add public key
		var key = this.privateKeyPacket.publicKey.header + this.privateKeyPacket.publicKey.data;
		for (var i = 0; i < this.userIds.length; i++) {
			// verify userids
			if (this.userIds[i].certificationSignatures.length === 0) {
				util.print_error("extractPublicKey - missing certification signatures");
				return null;
			}
			var userIdPacket = new openpgp_packet_userid();
			// add userids
			key += userIdPacket.write_packet(this.userIds[i].text);
			for (var j = 0; j < this.userIds[i].certificationSignatures.length; j++) {
				var certSig = this.userIds[i].certificationSignatures[j];
				// add signatures
				key += openpgp_packet.write_packet_header(2, certSig.data.length) + certSig.data;
			}
		}
		for (var k = 0; k < this.subKeys.length; k++) {
			var pubSubKey = this.subKeys[k].publicKey;
			// add public subkey package
			key += openpgp_packet.write_old_packet_header(14, pubSubKey.data.length) + pubSubKey.data;
			var subKeySig = this.subKeys[k].subKeySignature;
			if (subKeySig !== null) {
				// add subkey signature
				key += openpgp_packet.write_packet_header(2, subKeySig.data.length) + subKeySig.data;
			} else {
				util.print_error("extractPublicKey - missing subkey signature");
				return null;
			}
		}
		var publicArmored = openpgp_encoding_armor(4, key);
		return publicArmored;
	}

	this.extractPublicKey = extractPublicKey;
	this.getSigningKey = getSigningKey;
	this.getFingerprint = getFingerprint;
	this.getPreferredSignatureHashAlgorithm = getPreferredSignatureHashAlgorithm;
	this.read_nodes = read_nodes;
	this.decryptSecretMPIs = decryptSecretMPIs;
	this.getSubKeyIds = getSubKeyIds;
	this.getKeyId = getKeyId;
	
}
