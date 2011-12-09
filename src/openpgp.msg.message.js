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

function openpgp_msg_message() {
	
	// -1 = no valid passphrase submitted
	// -2 = no private key found
	// -3 = decryption error
	// text = valid decryption
	this.text = "";
	
	/**
	 * Decrypts a message and generates user interface message out of the found.
	 * MDC will be verified as well as message signatures
	 * @param private_key [openpgp_msg_privatekey] the private the message is encrypted with (corresponding to the session key)
	 * @param sessionkey [openpgp_packet_encryptedsessionkey] the session key to be used to decrypt the message
	 * @return [String] plaintext of the message or null on error
	 */
	function decrypt(private_key, sessionkey) {
		if (private_key == null || sessionkey == null || sessionkey == "")
			return null;
		var decrypted = sessionkey.decrypt(this, private_key.keymaterial);
		if (decrypted == null)
			return null;
		var packet;
		var position = 0;
		var len = decrypted.length;
		util.print_debug("openpgp.msg.messge decrypt:\n"+util.hexstrdump(decrypted));

		while (position != decrypted.length && (packet = openpgp_packet.read_packet(decrypted, position, len)) != null) {
			if (packet.tagType == 8) {
				this.text = packet.decompress();
				decrypted = packet.decompress();
			}
			util.print_debug(packet.toString());
			position += packet.headerLength+packet.packetLength;
			if (position > 38)
				util.print_debug("openpgp.msg.messge decrypt:\n"+util.hexstrdump(decrypted.substring(position)));
			len = decrypted.length - position;
			if (packet.tagType == 11) {
				this.text = packet.data;
				util.print_info("message successfully decrypted");
			}
			if (packet.tagType == 19)
				// ignore.. we checked that already in a more strict way.
				continue;
			if (packet.tagType == 2 && packet.signatureType < 3) {
				var pubkey = openpgp.keyring.getPublicKeysForKeyId(packet.issuerKeyId);
				if (pubkey.length == 0) {
					util.print_warning("Unable to verify signature of issuer: "+util.hexstrdump(packet.issuerKeyId)+". Public key not found in keyring.");
				} else {
					if(packet.verify(this.text.replace(/\r\n/g,"\n").replace(/\n/g,"\r\n"),pubkey[0]) && pubkey[0].obj.validate())
						util.print_info("Found Good Signature from "+pubkey[0].obj.userIds[0].text+" (0x"+util.hexstrdump(pubkey[0].obj.getKeyId()).substring(8)+")");
					else
						util.print_error("Signature verification failed: Bad Signature from "+pubkey[0].obj.userIds[0].text+" (0x"+util.hexstrdump(pubkey[0].obj.getKeyId()).substring(8)+")");
						
				}
			}
		}
		if (this.text == "") {
			this.text = decrypted;
		}
		return this.text;
	}
	
	/**
	 * Verifies a message signature. This function can be called after read_message if the message was signed only.
	 * @return [boolean] true if the signature was correct; otherwise false
	 */
	function verifySignature() {
		var result = false;
		if (this.type == 2) {
			var pubkey;
			if (this.signature.version == 4) {
				pubkey = openpgp.keyring.getPublicKeysForKeyId(this.signature.issuerKeyId);
			} else if (this.signature.version == 3) {
				pubkey = openpgp.keyring.getPublicKeysForKeyId(this.signature.keyId);
			} else {
				util.print_error("unknown signature type on message!");
				return false;
			}
			if (pubkey.length == 0)
				util.print_warning("Unable to verify signature of issuer: "+util.hexstrdump(this.signature.issuerKeyId)+". Public key not found in keyring.");
			else {
				for (var i = 0 ; i < pubkey.length; i++) {
					var tohash = this.text.replace(/\r\n/g,"\n").replace(/\n/g,"\r\n");
					if (this.signature.verify(tohash.substring(0, tohash.length -2), pubkey[i])) {
						util.print_info("Found Good Signature from "+pubkey[i].obj.userIds[i].text+" (0x"+util.hexstrdump(pubkey[i].obj.getKeyId()).substring(8)+")");
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
	this.verifySignature = verifySignature;
	this.toString = toString;
}