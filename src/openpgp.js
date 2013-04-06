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
 * @fileoverview The openpgp base class should provide all of the functionality 
 * to consume the openpgp.js library. All additional classes are documented 
 * for extending and developing on top of the base library.
 */

/**
 * GPG4Browsers Core interface. A single instance is hold
 * from the beginning. To use this library call "openpgp.init()"
 * @alias openpgp
 * @class
 * @classdesc Main Openpgp.js class. Use this to initiate and make all calls to this library.
 */
function _openpgp () {
	this.tostring = "";
	
	/**
	 * initializes the library:
	 * - reading the keyring from local storage
	 * - reading the config from local storage
	 */
	function init() {
		this.config = new openpgp_config();
		this.config.read();
		this.keyring = new openpgp_keyring();
		this.keyring.init();
	}
	
	/**
	 * reads several publicKey objects from a ascii armored
	 * representation an returns openpgp_msg_publickey packets
	 * @param {String} armoredText OpenPGP armored text containing
	 * the public key(s)
	 * @return {openpgp_msg_publickey[]} on error the function
	 * returns null
	 */
	function read_publicKey(armoredText) {
		var mypos = 0;
		var publicKeys = new Array();
		var publicKeyCount = 0;
		var input = openpgp_encoding_deArmor(armoredText.replace(/\r/g,'')).openpgp;
		var l = input.length;
		while (mypos != input.length) {
			var first_packet = openpgp_packet.read_packet(input, mypos, l);
			// public key parser
			if (input[mypos].charCodeAt() == 0x99 || first_packet.tagType == 6) {
				publicKeys[publicKeyCount] = new openpgp_msg_publickey();				
				publicKeys[publicKeyCount].header = input.substring(mypos,mypos+3);
				if (input[mypos].charCodeAt() == 0x99) {
					// parse the length and read a tag6 packet
					mypos++;
					var l = (input[mypos++].charCodeAt() << 8)
							| input[mypos++].charCodeAt();
					publicKeys[publicKeyCount].publicKeyPacket = new openpgp_packet_keymaterial();
					publicKeys[publicKeyCount].publicKeyPacket.header = publicKeys[publicKeyCount].header;
					publicKeys[publicKeyCount].publicKeyPacket.read_tag6(input, mypos, l);
					mypos += publicKeys[publicKeyCount].publicKeyPacket.packetLength;
					mypos += publicKeys[publicKeyCount].read_nodes(publicKeys[publicKeyCount].publicKeyPacket, input, mypos, (input.length - mypos));
				} else {
					publicKeys[publicKeyCount] = new openpgp_msg_publickey();
					publicKeys[publicKeyCount].publicKeyPacket = first_packet;
					mypos += first_packet.headerLength+first_packet.packetLength;
					mypos += publicKeys[publicKeyCount].read_nodes(first_packet, input, mypos, input.length -mypos);
				}
			} else {
				util.print_error("no public key found!");
				return null;
			}
			publicKeys[publicKeyCount].data = input.substring(0,mypos);
			publicKeyCount++;
		}
		return publicKeys;
	}
	
	/**
	 * reads several privateKey objects from a ascii armored
	 * representation an returns openpgp_msg_privatekey objects
	 * @param {String} armoredText OpenPGP armored text containing
	 * the private key(s)
	 * @return {openpgp_msg_privatekey[]} on error the function
	 * returns null
	 */
	function read_privateKey(armoredText) {
		var privateKeys = new Array();
		var privateKeyCount = 0;
		var mypos = 0;
		var input = openpgp_encoding_deArmor(armoredText.replace(/\r/g,'')).openpgp;
		var l = input.length;
		while (mypos != input.length) {
			var first_packet = openpgp_packet.read_packet(input, mypos, l);
			if (first_packet.tagType == 5) {
				privateKeys[privateKeys.length] = new openpgp_msg_privatekey();
				mypos += first_packet.headerLength+first_packet.packetLength;
				mypos += privateKeys[privateKeyCount].read_nodes(first_packet, input, mypos, l);
			// other blocks	            
			} else {
				util.print_error('no block packet found!');
				return null;
			}
			privateKeys[privateKeyCount].data = input.substring(0,mypos);
			privateKeyCount++;
		}
		return privateKeys;		
	}

	/**
	 * reads message packets out of an OpenPGP armored text and
	 * returns an array of message objects
	 * @param {String} armoredText text to be parsed
	 * @return {openpgp_msg_message[]} on error the function
	 * returns null
	 */
	function read_message(armoredText) {
		var dearmored;
		try{
    		dearmored = openpgp_encoding_deArmor(armoredText.replace(/\r/g,''));
		}
		catch(e){
    		util.print_error('no message found!');
    		return null;
		}
		return read_messages_dearmored(dearmored);
		}
		
	/**
	 * reads message packets out of an OpenPGP armored text and
	 * returns an array of message objects. Can be called externally or internally.
	 * External call will parse a de-armored messaged and return messages found.
	 * Internal will be called to read packets wrapped in other packets (i.e. compressed)
	 * @param {String} input dearmored text of OpenPGP packets, to be parsed
	 * @return {openpgp_msg_message[]} on error the function
	 * returns null
	 */
	function read_messages_dearmored(input){
		var messageString = input.openpgp;
		var signatureText = input.text; //text to verify signatures against. Modified by Tag11.
		var messages = new Array();
		var messageCount = 0;
		var mypos = 0;
		var l = messageString.length;
		while (mypos < messageString.length) {
			var first_packet = openpgp_packet.read_packet(messageString, mypos, l);
			if (!first_packet) {
				break;
			}
			// public key parser (definition from the standard:)
			// OpenPGP Message      :- Encrypted Message | Signed Message |
			//                         Compressed Message | Literal Message.
			// Compressed Message   :- Compressed Data Packet.
			// 
			// Literal Message      :- Literal Data Packet.
			// 
			// ESK                  :- Public-Key Encrypted Session Key Packet |
			//                         Symmetric-Key Encrypted Session Key Packet.
			// 
			// ESK Sequence         :- ESK | ESK Sequence, ESK.
			// 
			// Encrypted Data       :- Symmetrically Encrypted Data Packet |
			//                         Symmetrically Encrypted Integrity Protected Data Packet
			// 
			// Encrypted Message    :- Encrypted Data | ESK Sequence, Encrypted Data.
			// 
			// One-Pass Signed Message :- One-Pass Signature Packet,
			//                         OpenPGP Message, Corresponding Signature Packet.

			// Signed Message       :- Signature Packet, OpenPGP Message |
			//                         One-Pass Signed Message.
			if (first_packet.tagType ==  1 ||
			    (first_packet.tagType == 2 && first_packet.signatureType < 16) ||
			     first_packet.tagType ==  3 ||
			     first_packet.tagType ==  4 ||
				 first_packet.tagType ==  8 ||
				 first_packet.tagType ==  9 ||
				 first_packet.tagType == 10 ||
				 first_packet.tagType == 11 ||
				 first_packet.tagType == 18 ||
				 first_packet.tagType == 19) {
				messages[messages.length] = new openpgp_msg_message();
				messages[messageCount].messagePacket = first_packet;
				messages[messageCount].type = input.type;
				// Encrypted Message
				if (first_packet.tagType == 9 ||
				    first_packet.tagType == 1 ||
				    first_packet.tagType == 3 ||
				    first_packet.tagType == 18) {
					if (first_packet.tagType == 9) {
						util.print_error("unexpected openpgp packet");
						break;
					} else if (first_packet.tagType == 1) {
						util.print_debug("session key found:\n "+first_packet.toString());
						var issessionkey = true;
						messages[messageCount].sessionKeys = new Array();
						var sessionKeyCount = 0;
						while (issessionkey) {
							messages[messageCount].sessionKeys[sessionKeyCount] = first_packet;
							mypos += first_packet.packetLength + first_packet.headerLength;
							l -= (first_packet.packetLength + first_packet.headerLength);
							first_packet = openpgp_packet.read_packet(messageString, mypos, l);
							
							if (first_packet.tagType != 1 && first_packet.tagType != 3)
								issessionkey = false;
							sessionKeyCount++;
						}
						if (first_packet.tagType == 18 || first_packet.tagType == 9) {
							util.print_debug("encrypted data found:\n "+first_packet.toString());
							messages[messageCount].encryptedData = first_packet;
							mypos += first_packet.packetLength+first_packet.headerLength;
							l -= (first_packet.packetLength+first_packet.headerLength);
							messageCount++;
							
						} else {
							util.print_debug("something is wrong: "+first_packet.tagType);
						}
						
					} else if (first_packet.tagType == 18) {
						util.print_debug("symmetric encrypted data");
						break;
					}
				} else 
					if (first_packet.tagType == 2 && first_packet.signatureType < 3) {
					// Signed Message
						mypos += first_packet.packetLength + first_packet.headerLength;
						l -= (first_packet.packetLength + first_packet.headerLength);
						messages[messageCount].text = signatureText;
						messages[messageCount].signature = first_packet;
				        messageCount++;
				} else 
					// Signed Message
					if (first_packet.tagType == 4) {
						//TODO: Implement check
						mypos += first_packet.packetLength + first_packet.headerLength;
						l -= (first_packet.packetLength + first_packet.headerLength);
				} else 
					if (first_packet.tagType == 8) {
					// Compressed Message
						mypos += first_packet.packetLength + first_packet.headerLength;
						l -= (first_packet.packetLength + first_packet.headerLength);
				        var decompressedText = first_packet.decompress();
				        messages = messages.concat(openpgp.read_messages_dearmored({text: decompressedText, openpgp: decompressedText}));
				} else
					// Marker Packet (Obsolete Literal Packet) (Tag 10)
					// "Such a packet MUST be ignored when received." see http://tools.ietf.org/html/rfc4880#section-5.8
					if (first_packet.tagType == 10) {
						// reset messages
						messages.length = 0;
						// continue with next packet
						mypos += first_packet.packetLength + first_packet.headerLength;
						l -= (first_packet.packetLength + first_packet.headerLength);
				} else 
					if (first_packet.tagType == 11) {
					// Literal Message -- work is already done in read_packet
					mypos += first_packet.packetLength + first_packet.headerLength;
					l -= (first_packet.packetLength + first_packet.headerLength);
					signatureText = first_packet.data;
					messages[messageCount].data = first_packet.data;
					messageCount++;
				} else 
					if (first_packet.tagType == 19) {
					// Modification Detect Code
						mypos += first_packet.packetLength + first_packet.headerLength;
						l -= (first_packet.packetLength + first_packet.headerLength);
				}
			} else {
				util.print_error('no message found!');
				return null;
			}
		}
		
		return messages;
	}
	
	/**
	 * creates a binary string representation of an encrypted and signed message.
	 * The message will be encrypted with the public keys specified and signed
	 * with the specified private key.
	 * @param {Object} privatekey {obj: [openpgp_msg_privatekey]} Private key 
	 * to be used to sign the message
	 * @param {Object[]} publickeys An arraf of {obj: [openpgp_msg_publickey]}
	 * - public keys to be used to encrypt the message 
	 * @param {String} messagetext message text to encrypt and sign
	 * @return {String} a binary string representation of the message which 
	 * can be OpenPGP armored
	 */
	function write_signed_and_encrypted_message(privatekey, publickeys, messagetext) {
		var result = "";
		var literal = new openpgp_packet_literaldata().write_packet(messagetext.replace(/\r\n/g,"\n").replace(/\n/g,"\r\n"));
		util.print_debug_hexstr_dump("literal_packet: |"+literal+"|\n",literal);
		for (var i = 0; i < publickeys.length; i++) {
			var onepasssignature = new openpgp_packet_onepasssignature();
			var onepasssigstr = "";
			if (i == 0)
				onepasssigstr = onepasssignature.write_packet(1, openpgp.config.config.prefer_hash_algorithm,  privatekey, false);
			else
				onepasssigstr = onepasssignature.write_packet(1, openpgp.config.config.prefer_hash_algorithm,  privatekey, false);
			util.print_debug_hexstr_dump("onepasssigstr: |"+onepasssigstr+"|\n",onepasssigstr);
			var datasignature = new openpgp_packet_signature().write_message_signature(1, messagetext.replace(/\r\n/g,"\n").replace(/\n/g,"\r\n"), privatekey);
			util.print_debug_hexstr_dump("datasignature: |"+datasignature.openpgp+"|\n",datasignature.openpgp);
			if (i == 0) {
				result = onepasssigstr+literal+datasignature.openpgp;
			} else {
				result = onepasssigstr+result+datasignature.openpgp;
			}
		}
		
		util.print_debug_hexstr_dump("signed packet: |"+result+"|\n",result);
		// signatures done.. now encryption
		var sessionkey = openpgp_crypto_generateSessionKey(openpgp.config.config.encryption_cipher); 
		var result2 = "";
		
		// creating session keys for each recipient
		for (var i = 0; i < publickeys.length; i++) {
			var pkey = publickeys[i].getEncryptionKey();
			if (pkey == null) {
				util.print_error("no encryption key found! Key is for signing only.");
				return null;
			}
			result2 += new openpgp_packet_encryptedsessionkey().
					write_pub_key_packet(
						pkey.getKeyId(),
						pkey.MPIs,
						pkey.publicKeyAlgorithm,
						openpgp.config.config.encryption_cipher,
						sessionkey);
		}
		if (openpgp.config.config.integrity_protect) {
			result2 += new openpgp_packet_encryptedintegrityprotecteddata().write_packet(openpgp.config.config.encryption_cipher, sessionkey, result);
		} else {
			result2 += new openpgp_packet_encrypteddata().write_packet(openpgp.config.config.encryption_cipher, sessionkey, result);
		}
		return openpgp_encoding_armor(3,result2,null,null);
	}
	/**
	 * creates a binary string representation of an encrypted message.
	 * The message will be encrypted with the public keys specified 
	 * @param {Object[]} publickeys An array of {obj: [openpgp_msg_publickey]}
	 * -public keys to be used to encrypt the message 
	 * @param {String} messagetext message text to encrypt
	 * @return {String} a binary string representation of the message
	 * which can be OpenPGP armored
	 */
	function write_encrypted_message(publickeys, messagetext) {
		var result = "";
		var literal = new openpgp_packet_literaldata().write_packet(messagetext.replace(/\r\n/g,"\n").replace(/\n/g,"\r\n"));
		util.print_debug_hexstr_dump("literal_packet: |"+literal+"|\n",literal);
		result = literal;
		
		// signatures done.. now encryption
		var sessionkey = openpgp_crypto_generateSessionKey(openpgp.config.config.encryption_cipher); 
		var result2 = "";
		
		// creating session keys for each recipient
		for (var i = 0; i < publickeys.length; i++) {
			var pkey = publickeys[i].getEncryptionKey();
			if (pkey == null) {
				util.print_error("no encryption key found! Key is for signing only.");
				return null;
			}
			result2 += new openpgp_packet_encryptedsessionkey().
					write_pub_key_packet(
						pkey.getKeyId(),
						pkey.MPIs,
						pkey.publicKeyAlgorithm,
						openpgp.config.config.encryption_cipher,
						sessionkey);
		}
		if (openpgp.config.config.integrity_protect) {
			result2 += new openpgp_packet_encryptedintegrityprotecteddata().write_packet(openpgp.config.config.encryption_cipher, sessionkey, result);
		} else {
			result2 += new openpgp_packet_encrypteddata().write_packet(openpgp.config.config.encryption_cipher, sessionkey, result);
		}
		return openpgp_encoding_armor(3,result2,null,null);
	}
	
	/**
	 * creates a binary string representation a signed message.
	 * The message will be signed with the specified private key.
	 * @param {Object} privatekey {obj: [openpgp_msg_privatekey]}
	 * - the private key to be used to sign the message 
	 * @param {String} messagetext message text to sign
	 * @return {Object} {Object: text [String]}, openpgp: {String} a binary
	 *  string representation of the message which can be OpenPGP
	 *   armored(openpgp) and a text representation of the message (text). 
	 * This can be directly used to OpenPGP armor the message
	 */
	function write_signed_message(privatekey, messagetext) {
		var sig = new openpgp_packet_signature().write_message_signature(1, messagetext.replace(/\r\n/g,"\n").replace(/\n/,"\r\n"), privatekey);
		var result = {text: messagetext.replace(/\r\n/g,"\n").replace(/\n/,"\r\n"), openpgp: sig.openpgp, hash: sig.hash};
		return openpgp_encoding_armor(2,result, null, null)
	}
	
	/**
	 * generates a new key pair for openpgp. Beta stage. Currently only 
	 * supports RSA keys, and no subkeys.
	 * @param {Integer} keyType to indicate what type of key to make. 
	 * RSA is 1. Follows algorithms outlined in OpenPGP.
	 * @param {Integer} numBits number of bits for the key creation. (should 
	 * be 1024+, generally)
	 * @param {String} userId assumes already in form of "User Name 
	 * <username@email.com>"
	 * @param {String} passphrase The passphrase used to encrypt the resulting private key
	 * @return {Object} {privateKey: [openpgp_msg_privatekey], 
	 * privateKeyArmored: [string], publicKeyArmored: [string]}
	 */
	function generate_key_pair(keyType, numBits, userId, passphrase){
		var userIdPacket = new openpgp_packet_userid();
		var userIdString = userIdPacket.write_packet(userId);
		
		var keyPair = openpgp_crypto_generateKeyPair(keyType,numBits, passphrase, openpgp.config.config.prefer_hash_algorithm, 3);
		var privKeyString = keyPair.privateKey;
		var privKeyPacket = new openpgp_packet_keymaterial().read_priv_key(privKeyString.string,3,privKeyString.string.length);
		if(!privKeyPacket.decryptSecretMPIs(passphrase))
		    util.print_error('Issue creating key. Unable to read resulting private key');
		var privKey = new openpgp_msg_privatekey();
		privKey.privateKeyPacket = privKeyPacket;
		privKey.getPreferredSignatureHashAlgorithm = function(){return openpgp.config.config.prefer_hash_algorithm};//need to override this to solve catch 22 to generate signature. 8 is value for SHA256
		
		var publicKeyString = privKey.privateKeyPacket.publicKey.data;
		var hashData = String.fromCharCode(0x99)+ String.fromCharCode(((publicKeyString.length) >> 8) & 0xFF) 
			+ String.fromCharCode((publicKeyString.length) & 0xFF) +publicKeyString+String.fromCharCode(0xB4) +
			String.fromCharCode((userId.length) >> 24) +String.fromCharCode(((userId.length) >> 16) & 0xFF) 
			+ String.fromCharCode(((userId.length) >> 8) & 0xFF) + String.fromCharCode((userId.length) & 0xFF) + userId
		var signature = new openpgp_packet_signature();
		signature = signature.write_message_signature(16,hashData, privKey);
		var publicArmored = openpgp_encoding_armor(4, keyPair.publicKey.string + userIdString + signature.openpgp );

		var privArmored = openpgp_encoding_armor(5,privKeyString.string+userIdString+signature.openpgp);
		
		return {privateKey : privKey, privateKeyArmored: privArmored, publicKeyArmored: publicArmored}
	}
	
	this.generate_key_pair = generate_key_pair;
	this.write_signed_message = write_signed_message; 
	this.write_signed_and_encrypted_message = write_signed_and_encrypted_message;
	this.write_encrypted_message = write_encrypted_message;
	this.read_message = read_message;
	this.read_messages_dearmored = read_messages_dearmored;
	this.read_publicKey = read_publicKey;
	this.read_privateKey = read_privateKey;
	this.init = init;
}

var openpgp = new _openpgp();


