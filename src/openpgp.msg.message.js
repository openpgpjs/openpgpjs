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
 * @protected
 * @class
 * @classdesc Top-level message object. Contains information from one or more packets
 */

function openpgp_msg_message() {
	
	// -1 = no valid passphrase submitted
	// -2 = no private key found
	// -3 = decryption error
	// text = valid decryption
	this.text = "";
	this.messagePacket = null;
	this.type = null;
	
	/**
	 * Decrypts a message and generates user interface message out of the found.
	 * MDC will be verified as well as message signatures
	 * @param {openpgp_msg_privatekey} private_key the private the message is encrypted with (corresponding to the session key)
	 * @param {openpgp_packet_encryptedsessionkey} sessionkey the session key to be used to decrypt the message
	 * @return {String} plaintext of the message or null on error
	 */
	function decrypt(private_key, sessionkey) {
		var textParts = this.decryptAndVerifySignature(private_key, sessionkey);
		if (textParts == null) {
			return null;
		}
		var texts = [];
		for (var i=0; i<textParts.length; i++) {
			if (textParts[i].signatureValid == false) {
				return null;
			}
			texts.push(textParts[i].text);
		}
		return texts.join("\n");
	}

	/**
	 * Decrypts a message and generates user interface message out of the found.
	 * MDC will be verified as well as message signatures
	 * @param {openpgp_msg_privatekey} private_key the private the message is encrypted with (corresponding to the session key)
	 * @param {openpgp_packet_encryptedsessionkey} sessionkey the session key to be used to decrypt the message
	 * @param {openpgp_msg_publickey} pubkey Array of public keys to check signature against. If not provided, checks local keystore.
	 * @return {Array} an array of objects like {text,signatureValid} per signature packet, or null on error.
	 */
	function decryptAndVerifySignature(private_key, sessionkey, pubkey) {
		var messages = this.decryptMessages(private_key, sessionkey);
		var texts = [];
		for(var m in messages){
			if (messages[m].signature) {
				texts.push({text:messages[m].text, signatureValid:messages[m].verifySignature(pubkey)})
			}
		}
		return texts;
	}

	/**
	 * Decrypts a message and generates user interface message out of the found.
	 * Signatures will be ignored.
	 * @param {openpgp_msg_privatekey} private_key the private the message is encrypted with (corresponding to the session key)
	 * @param {openpgp_packet_encryptedsessionkey} sessionkey the session key to be used to decrypt the message
	 * @return {String} plaintext of the message or null on error
	 */
	function decryptWithoutVerification(private_key, sessionkey) {
		var messages = this.decryptMessages(private_key, sessionkey);
		var texts = [];
		for(var m in messages){
			if(messages[m].data){
				texts.push(messages[m].data);
			}
		}
		return texts;
	}

	/**
	 * Decrypts and returns children messages
	 * @param {openpgp_msg_privatekey} private_key the private the message is encrypted with (corresponding to the session key)
	 * @param {openpgp_packet_encryptedsessionkey} sessionkey the session key to be used to decrypt the message
	 * @return {Array} array of openpgp_msg_message's
	 */
	function decryptMessages(private_key, sessionkey) {
		if (private_key == null || sessionkey == null || sessionkey == "") {
			return null;
		}
		var decrypted = sessionkey.decrypt(this, private_key.keymaterial);
		if (decrypted == null) {
			return null;
		}
		util.print_debug_hexstr_dump("openpgp.msg.messge decrypt:\n",decrypted);
		return openpgp.read_messages_dearmored({text: decrypted, openpgp: decrypted});
	}
	
	/**
	 * Verifies a message signature. This function can be called after read_message if the message was signed only.
	 * @param {openpgp_msg_publickey} pubkey Array of public keys to check signature against. If not provided, checks local keystore.
	 * @return {boolean} true if the signature was correct; otherwise false
	 */
	function verifySignature(pubkey) {
		var result = false;
		if (this.signature.tagType == 2) {
			if(!pubkey || pubkey.length == 0){
				var pubkey;
				if (this.signature.version == 4) {
					pubkey = openpgp.keyring.getPublicKeysForKeyId(this.signature.issuerKeyId);
				} else if (this.signature.version == 3) {
					pubkey = openpgp.keyring.getPublicKeysForKeyId(this.signature.keyId);
				} else {
					util.print_error("unknown signature type on message!");
					return false;
				}
			}
			if (pubkey.length == 0)
				util.print_warning("Unable to verify signature of issuer: "+util.hexstrdump(this.signature.issuerKeyId)+". Public key not found in keyring.");
			else {
				for (var i = 0 ; i < pubkey.length; i++) {
					var tohash = this.text.replace(/\r\n/g,"\n").replace(/\n/g,"\r\n");
					if (this.signature.verify(tohash, pubkey[i])) {
						util.print_info("Found Good Signature from "+pubkey[i].obj.userIds[0].text+" (0x"+util.hexstrdump(pubkey[i].obj.getKeyId()).substring(8)+")");
						result = true;
					} else {
						util.print_error("Signature verification failed: Bad Signature from "+pubkey[i].obj.userIds[0].text+" (0x"+util.hexstrdump(pubkey[0].obj.getKeyId()).substring(8)+")");
					}
				}
			}
		}
		return result;
	}
	
	function toString() {
		var result = "Session Keys:\n";
		if (this.sessionKeys !=null)
		for (var i = 0; i < this.sessionKeys.length; i++) {
			result += this.sessionKeys[i].toString();
		}
		result += "\n\n EncryptedData:\n";
		if(this.encryptedData != null)
		result += this.encryptedData.toString();
		
		result += "\n\n Signature:\n";
		if(this.signature != null)
		result += this.signature.toString();
		
		result += "\n\n Text:\n"
		if(this.signature != null)
			result += this.text;
		return result;
	}
	this.decrypt = decrypt;
	this.decryptAndVerifySignature = decryptAndVerifySignature;
	this.decryptWithoutVerification = decryptWithoutVerification;
	this.decryptMessages = decryptMessages;
	this.verifySignature = verifySignature;
	this.toString = toString;
}
