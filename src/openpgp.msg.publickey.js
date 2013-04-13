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
 * @classdesc Decoded public key object for internal openpgp.js use
 */
function openpgp_msg_publickey() {
	this.data;
	this.position;
	this.len;
	this.tostring = "OPENPGP PUBLIC KEY\n";
	this.bindingSignature = null;
	this.publicKeyPacket = null;
	this.userIds = new Array();
	this.userAttributes = new Array();
	this.revocationSignatures = new Array();
	this.subKeys = new Array();
	this.arbitraryPacket = new Array();
	this.directSignatures = new Array();
	/**
	 * 
	 * @return last position
	 */
	function read_nodes(parent_node, input, position, len) {
		this.publicKeyPacket = parent_node;
		var exit = false;
		var pos = position;
		var l = len;
		while (input.length != pos) {
			var result = openpgp_packet.read_packet(input, pos, input.length - pos);
			if (result == null) {
				util.print_error("openpgp.msg.publickey read_nodes:\n"+'[pub_key]parsing ends here @:' + pos + " l:" + l);
				break;
			} else {
				switch (result.tagType) {
				case 2: // public key revocation signature
					if (result.signatureType == 32)
						this.revocationSignatures[this.revocationSignatures.length] = result;
					else if (result.signatureType == 16 || result.signatureType == 17 || result.signatureType == 18  || result.signatureType == 19)
						this.certificationSignature = result;
					else if (result.signatureType == 25) {
						this.bindingSignature = result;
					} else if (result.signatureType == 31) {
						this.directSignatures[this.directSignatures.length] = result;
					} else
						util.print_error("openpgp.msg.publickey read_nodes:\n"+"unknown signature type directly on key "+result.signatureType);
					pos += result.packetLength + result.headerLength;
					break;
				case 14: // Public-Subkey Packet
					this.subKeys[this.subKeys.length] = result;
					pos += result.packetLength + result.headerLength;
					pos += result.read_nodes(this.publicKeyPacket,input, pos, input.length - pos);
					break;
				case 17: // User Attribute Packet
					this.userAttributes[this.userAttributes.length] = result;
					pos += result.packetLength + result.headerLength;
					pos += result.read_nodes(this.publicKeyPacket,input, pos, input.length - pos);
					break;
				case 13: // User ID Packet
					this.userIds[this.userIds.length] = result;
					pos += result.packetLength + result.headerLength;
					pos += result.read_nodes(this.publicKeyPacket, input, pos, input.length - pos);
					break;
				default:
					this.data = input;
					this.position = position - this.publicKeyPacket.packetLength - this.publicKeyPacket.headerLength;
					this.len = pos - position;
					return this.len;
				}
			}
		}
		this.data = input;
		this.position = position - (this.publicKeyPacket.packetLength - this.publicKeyPacket.headerLength);
		this.len = pos - position;
		return this.len;
	}

	function write() {

	}

	function getKeyId() {
		return this.publicKeyPacket.getKeyId();
	}
	
	function getFingerprint() {
		return this.publicKeyPacket.getFingerprint();
	}


	
	function validate() {
		// check revocation keys
		for (var i = 0; i < this.revocationSignatures.length; i++) {
			var tohash = this.publicKeyPacket.header+this.publicKeyPacket.data;
			if (this.revocationSignatures[i].verify(tohash, this.publicKeyPacket))
				return false;
		}
		
		if (this.subKeys.length != 0) {
			// search for a valid subkey
			var found = false;
			for (var i = 0; i < this.subKeys.length; i++)
				if (this.subKeys[i].verifyKey() == 3) {
					found = true;
					break;
				}
			if (!found)
				return false;
		}
		// search for one valid userid
		found = false;
		for (var i = 0; i < this.userIds.length; i++)
			if (this.userIds[i].verify(this.publicKeyPacket) == 0) {
				found = true;
				break;
			}
		if (!found)
			return false;
		return true;
	}
	
	/**
	 * verifies all signatures
	 * @return a 2 dimensional array. the first dimension corresponds to the userids available
	 */
	function verifyCertificationSignatures() {
		var result = new Array();
		for (var i = 0; i < this.userIds.length; i++) {
			result[i] = this.userIds[i].verifyCertificationSignatures(this.publicKeyPacket);
		}
		return result;
	}
	this.verifyCertificationSignatures = verifyCertificationSignatures;
	
	/**
	 * verifies:
	 *  - revocation certificates directly on key
	 *  - self signatures
	 *  - subkey binding and revocation certificates
	 *  
	 *  This is useful for validating the key
	 *  @returns {Boolean} true if the basic signatures are all valid
	 */
	function verifyBasicSignatures() {
		for (var i = 0; i < this.revocationSignatures.length; i++) {
			var tohash = this.publicKeyPacket.header+this.publicKeyPacket.data;
			if (this.revocationSignatures[i].verify(tohash, this.publicKeyPacket))
				return false;
		}
		
		if (this.subKeys.length != 0) {
			// search for a valid subkey
			var found = false;
			for (var i = 0; i < this.subKeys.length; i++) {
				if (this.subKeys[i] == null)
					continue;
				var result = this.subKeys[i].verifyKey();
				if (result == 3) {
					found = true;
					break;
				} 
			}
			if (!found)
				return false;
		}
		var keyId = this.getKeyId();
		for (var i = 0; i < this.userIds.length; i++) {
			for (var j = 0; j < this.userIds[i].certificationRevocationSignatures.length; j++) {
				if (this.userIds[i].certificationSignatures[j].getIssuer == keyId &&
					this.userIds[i].certificationSignatures[j].verifyBasic(this.publicKeyPacket) != 4)
					return false;
			}
		}
		return true;
	}
	
	function toString() {
		var result = " OPENPGP Public Key\n    length: "+this.len+"\n";
		result += "    Revocation Signatures:\n"
		for (var i=0; i < this.revocationSignatures.length; i++) {
			result += "    "+this.revocationSignatures[i].toString(); 
		}
		result += "    User Ids:\n";
		for (var i=0; i < this.userIds.length; i++) {
			result += "    "+this.userIds[i].toString(); 
		}
		result += "    User Attributes:\n";
		for (var i=0; i < this.userAttributes.length; i++) {
			result += "    "+this.userAttributes[i].toString(); 
		}
		result += "    Public Key SubKeys:\n";
		for (var i=0; i < this.subKeys.length; i++) {
			result += "    "+this.subKeys[i].toString(); 
		}
		return result;
	}
	
	/**
	 * finds an encryption key for this public key
	 * @returns null if no encryption key has been found
	 */
	function getEncryptionKey() {
		// V4: by convention subkeys are prefered for encryption service
		// V3: keys MUST NOT have subkeys
		for (var j = 0; j < this.subKeys.length; j++)
				if (this.subKeys[j].publicKeyAlgorithm != 17 &&
						this.subKeys[j].publicKeyAlgorithm != 3 &&
						this.subKeys[j].verifyKey()) {
					return this.subKeys[j];
				}
		// if no valid subkey for encryption, use primary key
		if (this.publicKeyPacket.publicKeyAlgorithm != 17 && this.publicKeyPacket.publicKeyAlgorithm != 3
			&& this.publicKeyPacket.verifyKey()) {
			return this.publicKeyPacket;	
		}
		return null;
	}
	
	function getSigningKey() {
		if ((this.publicKeyPacket.publicKeyAlgorithm == 17 ||
			 this.publicKeyPacket.publicKeyAlgorithm != 2))
			return this.publicKeyPacket;
		else if (this.publicKeyPacket.version == 4) // V3 keys MUST NOT have subkeys.
			for (var j = 0; j < this.subKeys.length; j++) {
				if ((this.subKeys[j].publicKeyAlgorithm == 17 ||
					 this.subKeys[j].publicKeyAlgorithm != 2) &&
					 this.subKeys[j].verifyKey())
					return this.subKeys[j];
			}
		return null;
	}

        /* Returns the i-th subKey as a openpgp_msg_publickey object */
	function getSubKeyAsKey(i) {
		var ret = new openpgp_msg_publickey();
		ret.userIds = this.userIds;
		ret.userAttributes = this.userAttributes;
		ret.publicKeyPacket = this.subKeys[i];
		return ret;
	}

	this.getEncryptionKey = getEncryptionKey;
	this.getSigningKey = getSigningKey;
	this.read_nodes = read_nodes;
	this.write = write;
	this.toString = toString;
	this.validate = validate;
	this.getFingerprint = getFingerprint;
	this.getKeyId = getKeyId;
	this.verifyBasicSignatures = verifyBasicSignatures;
	this.getSubKeyAsKey = getSubKeyAsKey;
}
