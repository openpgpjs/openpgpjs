require=(function(e,t,n){function i(n,s){if(!t[n]){if(!e[n]){var o=typeof require=="function"&&require;if(!s&&o)return o(n,!0);if(r)return r(n,!0);throw new Error("Cannot find module '"+n+"'")}var u=t[n]={exports:{}};e[n][0].call(u.exports,function(t){var r=e[n][1][t];return i(r?r:t)},u,u.exports)}return t[n].exports}var r=typeof require=="function"&&require;for(var s=0;s<n.length;s++)i(n[s]);return i})({1:[function(require,module,exports){
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

module.exports = new _openpgp();


},{}],2:[function(require,module,exports){
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
 * @classdesc Implementation of the String-to-key specifier (RFC4880 3.7)
 * String-to-key (S2K) specifiers are used to convert passphrase strings
   into symmetric-key encryption/decryption keys.  They are used in two
   places, currently: to encrypt the secret part of private keys in the
   private keyring, and to convert passphrases to encryption keys for
   symmetrically encrypted messages.
 */
function openpgp_type_s2k() {
	/** @type {openpgp.hash} */
	this.algorithm = openpgp.hash.sha256;
	/** @type {openpgp_type_s2k.type} */
	this.type = openpgp_type_s2k.type.iterated;
	this.c = 96;
	/** @type {openpgp_bytearray} 
	 * Eight bytes of salt. */
	this.salt = openpgp_crypto_getRandomBytes(8);


	// Exponen bias, defined in RFC4880
	var expbias = 6;

	this.get_count = function() {
		return (16 + (this.c & 15)) << ((this.c >> 4) + expbias);
	}

	/**
	 * Parsing function for a string-to-key specifier (RFC 4880 3.7).
	 * @param {String} input Payload of string-to-key specifier
	 * @return {Integer} Actual length of the object
	 */
	this.read = function(bytes) {
		var i = 0;
		this.type = bytes[i++].charCodeAt();
		this.algorithm = bytes[i++].charCodeAt();

		var t = openpgp_type_s2k.type;

		switch (this.type) {
		case t.simple:
			break;

		case t.salted:
			this.salt = bytes.substr(i, 8);
			i += 8;
			break;

		case t.iterated:
			this.salt = bytes.substr(i, 8);
			i += 8;

			// Octet 10: count, a one-octet, coded value
			this.c = bytes[i++].charCodeAt();
			break;

		case t.gnu:
			if(bytes.substr(i, 3) == "GNU") {
				i += 3; // GNU
				var gnuExtType = 1000 + bytes[i++].charCodeAt();
				if(gnuExtType == 1001) {
					this.type = gnuExtType;
					// GnuPG extension mode 1001 -- don't write secret key at all
				} else {
					util.print_error("unknown s2k gnu protection mode! "+this.type);
				}
			} else {
				util.print_error("unknown s2k type! "+this.type);
			}
			break;

		default:
			util.print_error("unknown s2k type! "+this.type);
			break;
		}

		return i;
	}
	
	
	/**
	 * writes an s2k hash based on the inputs.
	 * @return {String} Produced key of hashAlgorithm hash length
	 */
	this.write = function() {
		var bytes = String.fromCharCode(this.type);
		bytes += String.fromCharCode(this.algorithm);

		var t = openpgp_type_s2k.type;
		switch(this.type) {
			case t.simple:
				break;
			case t.salted:
				bytes += this.salt;
				break;
			case t.iterated:
				bytes += this.salt;
				bytes += String.fromCharCode(this.c);
				break;
		};

		return bytes;
	}

	/**
	 * Produces a key using the specified passphrase and the defined 
	 * hashAlgorithm 
	 * @param {String} passphrase Passphrase containing user input
	 * @return {String} Produced key with a length corresponding to 
	 * hashAlgorithm hash length
	 */
	this.produce_key = function(passphrase, numBytes) {
		passphrase = util.encode_utf8(passphrase);

		function round(prefix, s2k) {

			var t = openpgp_type_s2k.type;
			switch(s2k.type) {
				case t.simple:
					return openpgp_crypto_hashData(s2k.algorithm, prefix + passphrase);

				case t.salted:
					return openpgp_crypto_hashData(s2k.algorithm, 
						prefix + s2k.salt + passphrase);

				case t.iterated:
					var isp = [],
						count = s2k.get_count();
						data = s2k.salt + passphrase;

					while (isp.length * data.length < count)
						isp.push(data);

					isp = isp.join('');			

					if (isp.length > count)
						isp = isp.substr(0, count);

					return openpgp_crypto_hashData(s2k.algorithm, prefix + isp);
			};
		}
		
		var result = '',
			prefix = '';

		while(result.length <= numBytes) {
			result += round(prefix, this);
			prefix += String.fromCharCode(0);
		}

		return result.substr(0, numBytes);
	}
}



/** A string to key specifier type
 * @enum {Integer}
 */
openpgp_type_s2k.type = {
	simple: 0,
	salted: 1,
	iterated: 3,
	gnu: 101
}

},{}],3:[function(require,module,exports){
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
 * @classdesc Implementation of type key id (RFC4880 3.3)
 *  A Key ID is an eight-octet scalar that identifies a key.
   Implementations SHOULD NOT assume that Key IDs are unique.  The
   section "Enhanced Key Formats" below describes how Key IDs are
   formed.
 */
function openpgp_type_keyid() {
	var bytes = '';

	for(var i = 0; i < 8; i++)
		bytes += String.fromCharCode(0);
	/**
	 * Parsing method for a key id
	 * @param {String} input Input to read the key id from 
	 * @param {integer} position Position where to start reading the key 
	 * id from input
	 * @return {openpgp_type_keyid} This object
	 */
	function read_packet(input, position) {
		this.bytes = input.substring(position, position+8);
		return this;
	}
	
	/**
	 * Generates debug output (pretty print)
	 * @return {String} Key Id as hexadecimal string
	 */
	function toString() {
		return util.hexstrdump(this.bytes);
	}
	
	this.read_packet = read_packet;
	this.toString = toString;
};

},{}],"openpgp":[function(require,module,exports){
module.exports=require('d5yVPw');
},{}],"d5yVPw":[function(require,module,exports){



var crypto = require('./crypto');

module.exports = require('./openpgp.js');
module.exports.util = require('./util');
module.exports.packet = require('./packet');
module.exports.mpi = require('./type/mpi.js');
module.exports.s2k = require('./type/s2k.js');
module.exports.keyid = require('./type/keyid.js');
module.exports.armor = require('./encoding/armor.js');

for(var i in crypto)
	module.exports[i] = crypto[i];


},{"./openpgp.js":1,"./type/mpi.js":4,"./type/s2k.js":2,"./type/keyid.js":3,"./encoding/armor.js":5,"./crypto":6,"./util":7,"./packet":8}],7:[function(require,module,exports){
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

var Util = function() {



	this.readNumber = function (bytes) {
		var n = 0;

		for(var i = 0; i < bytes.length; i++) {
			n <<= 8;
			n += bytes[i].charCodeAt()
		}

		return n;
	}

	this.writeNumber = function(n, bytes) {
		var b = '';
		for(var i = 0; i < bytes; i++) {
			b += String.fromCharCode((n >> (8 * (bytes- i - 1))) & 0xFF);
		}

		return b;
	}



	this.readDate = function(bytes) {
		var n = this.readNumber(bytes);
		var d = new Date();
		d.setTime(n * 1000);
		return d;
	}

	this.writeDate = function(time) {
		var numeric = Math.round(time.getTime() / 1000);

		return this.writeNumber(numeric, 4);
	}

    this.emailRegEx = /[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/;
	
	this.debug = false;

	this.hexdump = function(str) {
	    var r=[];
	    var e=str.length;
	    var c=0;
	    var h;
	    var i = 0;
	    while(c<e){
	        h=str.charCodeAt(c++).toString(16);
	        while(h.length<2) h="0"+h;
	        r.push(" "+h);
	        i++;
	        if (i % 32 == 0)
	        	r.push("\n           ");
	    }
	    return r.join('');
	};
	
	/**
	 * Create hexstring from a binary
	 * @param {String} str String to convert
	 * @return {String} String containing the hexadecimal values
	 */
	this.hexstrdump = function(str) {
		if (str == null)
			return "";
	    var r=[];
	    var e=str.length;
	    var c=0;
	    var h;
	    while(c<e){
	        h=str[c++].charCodeAt().toString(16);
	        while(h.length<2) h="0"+h;
	        r.push(""+h);
	    }
	    return r.join('');
	};
	
	/**
	 * Create binary string from a hex encoded string
	 * @param {String} str Hex string to convert
	 * @return {String} String containing the binary values
	 */
	this.hex2bin = function(hex) {
	    var str = '';
	    for (var i = 0; i < hex.length; i += 2)
	        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
	    return str;
	};
	
	/**
	 * Creating a hex string from an binary array of integers (0..255)
	 * @param {String} str Array of bytes to convert
	 * @return {String} Hexadecimal representation of the array
	 */
	this.hexidump = function(str) {
	    var r=[];
	    var e=str.length;
	    var c=0;
	    var h;
	    while(c<e){
	        h=str[c++].toString(16);
	        while(h.length<2) h="0"+h;
	        r.push(""+h);
	    }
	    return r.join('');
	};


	/**
	 * Convert a native javascript string to a string of utf8 bytes
	 * @param {String} str The string to convert
	 * @return {String} A valid squence of utf8 bytes
	 */
	this.encode_utf8 = function(str) {
		return unescape(encodeURIComponent(str));
	};

	/**
	 * Convert a string of utf8 bytes to a native javascript string
	 * @param {String} utf8 A valid squence of utf8 bytes
	 * @return {String} A native javascript string
	 */
	this.decode_utf8 = function(utf8) {
		return decodeURIComponent(escape(utf8));
	};

	var str2bin = function(str, result) {
		for (var i = 0; i < str.length; i++) {
			result[i] = str.charCodeAt(i);
		}

		return result;
	};
	
	var bin2str = function(bin) {
		var result = [];

		for (var i = 0; i < bin.length; i++) {
			result.push(String.fromCharCode(bin[i]));
		}

		return result.join('');
	};

	/**
	 * Convert a string to an array of integers(0.255)
	 * @param {String} str String to convert
	 * @return {Integer[]} An array of (binary) integers
	 */
	this.str2bin = function(str) { 
		return str2bin(str, new Array(str.length));
	};
	
	
	/**
	 * Convert an array of integers(0.255) to a string 
	 * @param {Integer[]} bin An array of (binary) integers to convert
	 * @return {String} The string representation of the array
	 */
	this.bin2str = bin2str;
	
	/**
	 * Convert a string to a Uint8Array
	 * @param {String} str String to convert
	 * @return {Uint8Array} The array of (binary) integers
	 */
	this.str2Uint8Array = function(str) { 
		return str2bin(str, new Uint8Array(new ArrayBuffer(str.length))); 
	};
	
	/**
	 * Convert a Uint8Array to a string. This currently functions 
	 * the same as bin2str. 
	 * @param {Uint8Array} bin An array of (binary) integers to convert
	 * @return {String} String representation of the array
	 */
	this.Uint8Array2str = bin2str;
	
	/**
	 * Calculates a 16bit sum of a string by adding each character 
	 * codes modulus 65535
	 * @param {String} text String to create a sum of
	 * @return {Integer} An integer containing the sum of all character 
	 * codes % 65535
	 */
	this.calc_checksum = function(text) {
		var checksum = {  s: 0, add: function (sadd) { this.s = (this.s + sadd) % 65536; }};
		for (var i = 0; i < text.length; i++) {
			checksum.add(text.charCodeAt(i));
		}
		return checksum.s;
	};
	
	/**
	 * Helper function to print a debug message. Debug 
	 * messages are only printed if
	 * openpgp.config.debug is set to true. The calling
	 * Javascript context MUST define
	 * a "showMessages(text)" function. Line feeds ('\n')
	 * are automatically converted to HTML line feeds '<br/>'
	 * @param {String} str String of the debug message
	 * @return {String} An HTML tt entity containing a paragraph with a 
	 * style attribute where the debug message is HTMLencoded in. 
	 */
	this.print_debug = function(str) {
		if (this.debug) {
			console.log(str);
		}
	};
	
	/**
	 * Helper function to print a debug message. Debug 
	 * messages are only printed if
	 * openpgp.config.debug is set to true. The calling
	 * Javascript context MUST define
	 * a "showMessages(text)" function. Line feeds ('\n')
	 * are automatically converted to HTML line feeds '<br/>'
	 * Different than print_debug because will call hexstrdump iff necessary.
	 * @param {String} str String of the debug message
	 * @return {String} An HTML tt entity containing a paragraph with a 
	 * style attribute where the debug message is HTMLencoded in. 
	 */
	this.print_debug_hexstr_dump = function(str,strToHex) {
		if (this.debug) {
			str = str + this.hexstrdump(strToHex);
			console.log(str);
		}
	};
	
	/**
	 * Helper function to print an error message. 
	 * The calling Javascript context MUST define
	 * a "showMessages(text)" function. Line feeds ('\n')
	 * are automatically converted to HTML line feeds '<br/>'
	 * @param {String} str String of the error message
	 * @return {String} A HTML paragraph entity with a style attribute 
	 * containing the HTML encoded error message
	 */
	this.print_error = function(str) {
		if(this.debug)
			throw str;
		console.log(str);
	};
	
	/**
	 * Helper function to print an info message. 
	 * The calling Javascript context MUST define
	 * a "showMessages(text)" function. Line feeds ('\n')
	 * are automatically converted to HTML line feeds '<br/>'.
	 * @param {String} str String of the info message
	 * @return {String} A HTML paragraph entity with a style attribute 
	 * containing the HTML encoded info message
	 */
	this.print_info = function(str) {
		if(this.debug)
			console.log(str);
	};
	
	this.print_warning = function(str) {
		console.log(str);
	};
	
	this.getLeftNBits = function (string, bitcount) {
		var rest = bitcount % 8;
		if (rest == 0)
			return string.substring(0, bitcount / 8);
		var bytes = (bitcount - rest) / 8 +1;
		var result = string.substring(0, bytes);
		return this.shiftRight(result, 8-rest); // +String.fromCharCode(string.charCodeAt(bytes -1) << (8-rest) & 0xFF);
	};

	/**
	 * Shifting a string to n bits right
	 * @param {String} value The string to shift
	 * @param {Integer} bitcount Amount of bits to shift (MUST be smaller 
	 * than 9)
	 * @return {String} Resulting string. 
	 */
	this.shiftRight = function(value, bitcount) {
		var temp = util.str2bin(value);
        if (bitcount % 8 != 0) {
        	for (var i = temp.length-1; i >= 0; i--) {
        		temp[i] >>= bitcount % 8;
        		if (i > 0)
        			temp[i] |= (temp[i - 1] << (8 - (bitcount % 8))) & 0xFF;
        	}
        } else {
        	return value;
        }
        return util.bin2str(temp);
	};
	
	/**
	 * Return the algorithm type as string
	 * @return {String} String representing the message type
	 */
	this.get_hashAlgorithmString = function(algo) {
		switch(algo) {
		case 1:
			return "MD5";
		case 2:
			return "SHA1";
		case 3:
			return "RIPEMD160";
		case 8:
			return "SHA256";
		case 9:
			return "SHA384";
		case 10:
			return "SHA512";
		case 11:
			return "SHA224";
		}
		return "unknown";
	};
};

/**
 * an instance that should be used. 
 */
module.exports = new Util();

},{}],5:[function(require,module,exports){
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

var base64 = require('./base64.js');



/**
 * Finds out which Ascii Armoring type is used. This is an internal function
 * @param {String} text [String] ascii armored text
 * @returns {Integer} 0 = MESSAGE PART n of m
 *         1 = MESSAGE PART n
 *         2 = SIGNED MESSAGE
 *         3 = PGP MESSAGE
 *         4 = PUBLIC KEY BLOCK
 *         5 = PRIVATE KEY BLOCK
 *         null = unknown
 */
function get_type(text) {
	var splittedtext = text.split('-----');
	// BEGIN PGP MESSAGE, PART X/Y
	// Used for multi-part messages, where the armor is split amongst Y
	// parts, and this is the Xth part out of Y.
	if (splittedtext[1].match(/BEGIN PGP MESSAGE, PART \d+\/\d+/)) {
		return 0;
	} else
		// BEGIN PGP MESSAGE, PART X
		// Used for multi-part messages, where this is the Xth part of an
		// unspecified number of parts. Requires the MESSAGE-ID Armor
		// Header to be used.
	if (splittedtext[1].match(/BEGIN PGP MESSAGE, PART \d+/)) {
		return 1;

	} else
		// BEGIN PGP SIGNATURE
		// Used for detached signatures, OpenPGP/MIME signatures, and
		// cleartext signatures. Note that PGP 2.x uses BEGIN PGP MESSAGE
		// for detached signatures.
	if (splittedtext[1].match(/BEGIN PGP SIGNED MESSAGE/)) {
		return 2;

	} else
  	    // BEGIN PGP MESSAGE
	    // Used for signed, encrypted, or compressed files.
	if (splittedtext[1].match(/BEGIN PGP MESSAGE/)) {
		return 3;

	} else
		// BEGIN PGP PUBLIC KEY BLOCK
		// Used for armoring public keys.
	if (splittedtext[1].match(/BEGIN PGP PUBLIC KEY BLOCK/)) {
		return 4;

	} else
		// BEGIN PGP PRIVATE KEY BLOCK
		// Used for armoring private keys.
	if (splittedtext[1].match(/BEGIN PGP PRIVATE KEY BLOCK/)) {
		return 5;
	}
}

/**
 * Add additional information to the armor version of an OpenPGP binary
 * packet block.
 * @author  Alex
 * @version 2011-12-16
 * @returns {String} The header information
 */
function armor_addheader() {
    var result = "";
	if (openpgp.config.config.show_version) {
        result += "Version: "+openpgp.config.versionstring+'\r\n';
    }
	if (openpgp.config.config.show_comment) {
        result += "Comment: "+openpgp.config.commentstring+'\r\n';
    }
    result += '\r\n';
    return result;
}



/**
 * Calculates a checksum over the given data and returns it base64 encoded
 * @param {String} data Data to create a CRC-24 checksum for
 * @return {String} Base64 encoded checksum
 */
function getCheckSum(data) {
	var c = createcrc24(data);
	var str = "" + String.fromCharCode(c >> 16)+
				   String.fromCharCode((c >> 8) & 0xFF)+
				   String.fromCharCode(c & 0xFF);
	return base64_encode(str);
}

/**
 * Calculates the checksum over the given data and compares it with the 
 * given base64 encoded checksum
 * @param {String} data Data to create a CRC-24 checksum for
 * @param {String} checksum Base64 encoded checksum
 * @return {Boolean} True if the given checksum is correct; otherwise false
 */
function verifyCheckSum(data, checksum) {
	var c = getCheckSum(data);
	var d = checksum;
	return c[0] == d[0] && c[1] == d[1] && c[2] == d[2];
}
/**
 * Internal function to calculate a CRC-24 checksum over a given string (data)
 * @param {String} data Data to create a CRC-24 checksum for
 * @return {Integer} The CRC-24 checksum as number
 */
var crc_table = [
0x00000000, 0x00864cfb, 0x018ad50d, 0x010c99f6, 0x0393e6e1, 0x0315aa1a, 0x021933ec, 0x029f7f17, 0x07a18139, 0x0727cdc2, 0x062b5434, 0x06ad18cf, 0x043267d8, 0x04b42b23, 0x05b8b2d5, 0x053efe2e, 0x0fc54e89, 0x0f430272, 0x0e4f9b84, 0x0ec9d77f, 0x0c56a868, 0x0cd0e493, 0x0ddc7d65, 0x0d5a319e, 0x0864cfb0, 0x08e2834b, 0x09ee1abd, 0x09685646, 0x0bf72951, 0x0b7165aa, 0x0a7dfc5c, 0x0afbb0a7, 0x1f0cd1e9, 0x1f8a9d12, 0x1e8604e4, 0x1e00481f, 0x1c9f3708, 0x1c197bf3, 0x1d15e205, 0x1d93aefe, 0x18ad50d0, 0x182b1c2b, 0x192785dd, 0x19a1c926, 0x1b3eb631, 0x1bb8faca, 0x1ab4633c, 0x1a322fc7, 0x10c99f60, 0x104fd39b, 0x11434a6d, 0x11c50696, 0x135a7981, 0x13dc357a, 0x12d0ac8c, 0x1256e077, 0x17681e59, 0x17ee52a2, 0x16e2cb54, 0x166487af, 0x14fbf8b8, 0x147db443, 0x15712db5, 0x15f7614e, 0x3e19a3d2, 0x3e9fef29, 0x3f9376df, 0x3f153a24, 0x3d8a4533, 0x3d0c09c8, 0x3c00903e, 0x3c86dcc5, 0x39b822eb, 0x393e6e10, 0x3832f7e6, 0x38b4bb1d, 0x3a2bc40a, 0x3aad88f1, 0x3ba11107, 0x3b275dfc, 0x31dced5b, 0x315aa1a0,
0x30563856, 0x30d074ad, 0x324f0bba, 0x32c94741, 0x33c5deb7, 0x3343924c, 0x367d6c62, 0x36fb2099, 0x37f7b96f, 0x3771f594, 0x35ee8a83, 0x3568c678, 0x34645f8e, 0x34e21375, 0x2115723b, 0x21933ec0, 0x209fa736, 0x2019ebcd, 0x228694da, 0x2200d821, 0x230c41d7, 0x238a0d2c, 0x26b4f302, 0x2632bff9, 0x273e260f, 0x27b86af4, 0x252715e3, 0x25a15918, 0x24adc0ee, 0x242b8c15, 0x2ed03cb2, 0x2e567049, 0x2f5ae9bf, 0x2fdca544, 0x2d43da53, 0x2dc596a8, 0x2cc90f5e, 0x2c4f43a5, 0x2971bd8b, 0x29f7f170, 0x28fb6886, 0x287d247d, 0x2ae25b6a, 0x2a641791, 0x2b688e67, 0x2beec29c, 0x7c3347a4, 0x7cb50b5f, 0x7db992a9, 0x7d3fde52, 0x7fa0a145, 0x7f26edbe, 0x7e2a7448, 0x7eac38b3, 0x7b92c69d, 0x7b148a66, 0x7a181390, 0x7a9e5f6b, 0x7801207c, 0x78876c87, 0x798bf571, 0x790db98a, 0x73f6092d, 0x737045d6, 0x727cdc20, 0x72fa90db, 0x7065efcc, 0x70e3a337, 0x71ef3ac1, 0x7169763a, 0x74578814, 0x74d1c4ef, 0x75dd5d19, 0x755b11e2, 0x77c46ef5, 0x7742220e, 0x764ebbf8, 0x76c8f703, 0x633f964d, 0x63b9dab6, 0x62b54340, 0x62330fbb,
0x60ac70ac, 0x602a3c57, 0x6126a5a1, 0x61a0e95a, 0x649e1774, 0x64185b8f, 0x6514c279, 0x65928e82, 0x670df195, 0x678bbd6e, 0x66872498, 0x66016863, 0x6cfad8c4, 0x6c7c943f, 0x6d700dc9, 0x6df64132, 0x6f693e25, 0x6fef72de, 0x6ee3eb28, 0x6e65a7d3, 0x6b5b59fd, 0x6bdd1506, 0x6ad18cf0, 0x6a57c00b, 0x68c8bf1c, 0x684ef3e7, 0x69426a11, 0x69c426ea, 0x422ae476, 0x42aca88d, 0x43a0317b, 0x43267d80, 0x41b90297, 0x413f4e6c, 0x4033d79a, 0x40b59b61, 0x458b654f, 0x450d29b4, 0x4401b042, 0x4487fcb9, 0x461883ae, 0x469ecf55, 0x479256a3, 0x47141a58, 0x4defaaff, 0x4d69e604, 0x4c657ff2, 0x4ce33309, 0x4e7c4c1e, 0x4efa00e5, 0x4ff69913, 0x4f70d5e8, 0x4a4e2bc6, 0x4ac8673d, 0x4bc4fecb, 0x4b42b230, 0x49ddcd27, 0x495b81dc, 0x4857182a, 0x48d154d1, 0x5d26359f, 0x5da07964, 0x5cace092, 0x5c2aac69, 0x5eb5d37e, 0x5e339f85, 0x5f3f0673, 0x5fb94a88, 0x5a87b4a6, 0x5a01f85d, 0x5b0d61ab, 0x5b8b2d50, 0x59145247, 0x59921ebc, 0x589e874a, 0x5818cbb1, 0x52e37b16, 0x526537ed, 0x5369ae1b, 0x53efe2e0, 0x51709df7, 0x51f6d10c,
0x50fa48fa, 0x507c0401, 0x5542fa2f, 0x55c4b6d4, 0x54c82f22, 0x544e63d9, 0x56d11cce, 0x56575035, 0x575bc9c3, 0x57dd8538];

function createcrc24(input) {
  var crc = 0xB704CE;
  var index = 0;

  while((input.length - index) > 16)  {
   crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index)) & 0xff];
   crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index+1)) & 0xff];
   crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index+2)) & 0xff];
   crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index+3)) & 0xff];
   crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index+4)) & 0xff];
   crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index+5)) & 0xff];
   crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index+6)) & 0xff];
   crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index+7)) & 0xff];
   crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index+8)) & 0xff];
   crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index+9)) & 0xff];
   crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index+10)) & 0xff];
   crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index+11)) & 0xff];
   crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index+12)) & 0xff];
   crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index+13)) & 0xff];
   crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index+14)) & 0xff];
   crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index+15)) & 0xff];
   index += 16;
  }

  for(var j = index; j < input.length; j++) {
   crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index++)) & 0xff]
  }
  return crc & 0xffffff;
}

/**
 * DeArmor an OpenPGP armored message; verify the checksum and return 
 * the encoded bytes
 * @param {String} text OpenPGP armored message
 * @returns {(Boolean|Object)} Either false in case of an error 
 * or an object with attribute "text" containing the message text
 * and an attribute "openpgp" containing the bytes.
 */
function dearmor(text) {
	text = text.replace(/\r/g, '')

	var type = get_type(text);

	if (type != 2) {
		var splittedtext = text.split('-----');

		var data = { 
			openpgp: base64_decode(
				splittedtext[2]
					.split('\n\n')[1]
					.split("\n=")[0]
					.replace(/\n- /g,"\n")),
			type: type
		};

		if (verifyCheckSum(data.openpgp, 
			splittedtext[2]
				.split('\n\n')[1]
				.split("\n=")[1]
				.split('\n')[0]))

			return data;
		else {
			util.print_error("Ascii armor integrity check on message failed: '"
				+ splittedtext[2]
					.split('\n\n')[1]
					.split("\n=")[1]
					.split('\n')[0] 
				+ "' should be '"
				+ getCheckSum(data)) + "'";
			return false;
		}
	} else {
		var splittedtext = text.split('-----');

		var result = {
			text: splittedtext[2]
				.replace(/\n- /g,"\n")
				.split("\n\n")[1],
			openpgp: base64_decode(splittedtext[4]
				.split("\n\n")[1]
				.split("\n=")[0]),
			type: type
		};

		if (verifyCheckSum(result.openpgp, splittedtext[4]
			.split("\n\n")[1]
			.split("\n=")[1]))

				return result;
		else {
			util.print_error("Ascii armor integrity check on message failed");
			return false;
		}
	}
}


/**
 * Armor an OpenPGP binary packet block
 * @param {Integer} messagetype type of the message
 * @param data
 * @param {Integer} partindex
 * @param {Integer} parttotal
 * @returns {String} Armored text
 */
function armor(messagetype, data, partindex, parttotal) {
	var result = "";
	switch(messagetype) {
	case 0:
		result += "-----BEGIN PGP MESSAGE, PART "+partindex+"/"+parttotal+"-----\r\n";
		result += armor_addheader();
		result += base64.encode(data);
		result += "\r\n="+getCheckSum(data)+"\r\n";
		result += "-----END PGP MESSAGE, PART "+partindex+"/"+parttotal+"-----\r\n";
		break;
	case 1:
		result += "-----BEGIN PGP MESSAGE, PART "+partindex+"-----\r\n";
		result += armor_addheader();
		result += base64.encode(data);
		result += "\r\n="+getCheckSum(data)+"\r\n";
		result += "-----END PGP MESSAGE, PART "+partindex+"-----\r\n";
		break;
	case 2:
		result += "\r\n-----BEGIN PGP SIGNED MESSAGE-----\r\nHash: "+data.hash+"\r\n\r\n";
		result += data.text.replace(/\n-/g,"\n- -");
		result += "\r\n-----BEGIN PGP SIGNATURE-----\r\n";
		result += armor_addheader();
		result += base64.encode(data.openpgp);
		result += "\r\n="+getCheckSum(data.openpgp)+"\r\n";
		result += "-----END PGP SIGNATURE-----\r\n";
		break;
	case 3:
		result += "-----BEGIN PGP MESSAGE-----\r\n";
		result += armor_addheader();
		result += base64.encode(data);
		result += "\r\n="+getCheckSum(data)+"\r\n";
		result += "-----END PGP MESSAGE-----\r\n";
		break;
	case 4:
		result += "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n";
		result += armor_addheader();
		result += base64.encode(data);
		result += "\r\n="+getCheckSum(data)+"\r\n";
		result += "-----END PGP PUBLIC KEY BLOCK-----\r\n\r\n";
		break;
	case 5:
		result += "-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n";
		result += armor_addheader();
		result += base64.encode(data);
		result += "\r\n="+getCheckSum(data)+"\r\n";
		result += "-----END PGP PRIVATE KEY BLOCK-----\r\n";
		break;
	}

	return result;
}

module.exports = {
	encode: armor,
	decode: dearmor
}

},{"./base64.js":9}],9:[function(require,module,exports){
/* OpenPGP radix-64/base64 string encoding/decoding
 * Copyright 2005 Herbert Hanewinkel, www.haneWIN.de
 * version 1.0, check www.haneWIN.de for the latest version
 *
 * This software is provided as-is, without express or implied warranty.  
 * Permission to use, copy, modify, distribute or sell this software, with or
 * without fee, for any purpose and by any individual or organization, is hereby
 * granted, provided that the above copyright notice and this paragraph appear 
 * in all copies. Distribution as a part of an application or binary must
 * include the above copyright notice in the documentation and/or other materials
 * provided with the application or distribution.
 */

var b64s = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function s2r(t) {
	var a, c, n;
	var r = '', l = 0, s = 0;
	var tl = t.length;

	for (n = 0; n < tl; n++) {
		c = t.charCodeAt(n);
		if (s == 0) {
			r += b64s.charAt((c >> 2) & 63);
			a = (c & 3) << 4;
		} else if (s == 1) {
			r += b64s.charAt((a | (c >> 4) & 15));
			a = (c & 15) << 2;
		} else if (s == 2) {
			r += b64s.charAt(a | ((c >> 6) & 3));
			l += 1;
			if ((l % 60) == 0)
				r += "\n";
			r += b64s.charAt(c & 63);
		}
		l += 1;
		if ((l % 60) == 0)
			r += "\n";

		s += 1;
		if (s == 3)
			s = 0;
	}
	if (s > 0) {
		r += b64s.charAt(a);
		l += 1;
		if ((l % 60) == 0)
			r += "\n";
		r += '=';
		l += 1;
	}
	if (s == 1) {
		if ((l % 60) == 0)
			r += "\n";
		r += '=';
	}

	return r;
}

function r2s(t) {
	var c, n;
	var r = '', s = 0, a = 0;
	var tl = t.length;

	for (n = 0; n < tl; n++) {
		c = b64s.indexOf(t.charAt(n));
		if (c >= 0) {
			if (s)
				r += String.fromCharCode(a | (c >> (6 - s)) & 255);
			s = (s + 2) & 7;
			a = (c << s) & 255;
		}
	}
	return r;
}

module.exports = {
	encode: s2r,
	decode: r2s
}

},{}],8:[function(require,module,exports){

var enums = require('../enums.js');

module.exports = {
	list: require('./packetlist.js'),
}

var packets = require('./all_packets.js');

for(var i in packets)
	module.exports[i] = packets[i];

},{"../enums.js":10,"./packetlist.js":11,"./all_packets.js":12}],4:[function(require,module,exports){
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

// Hint: We hold our MPIs as an array of octets in big endian format preceeding a two
// octet scalar: MPI: [a,b,c,d,e,f]
// - MPI size: (a << 8) | b 
// - MPI = c | d << 8 | e << ((MPI.length -2)*8) | f ((MPI.length -2)*8)

var BigInteger = require('../crypto/public_key/jsbn.js'),
	util = require('../util');

/**
 * @class
 * @classdescImplementation of type MPI (RFC4880 3.2)
 * Multiprecision integers (also called MPIs) are unsigned integers used
 * to hold large integers such as the ones used in cryptographic
 * calculations.
 * An MPI consists of two pieces: a two-octet scalar that is the length
 * of the MPI in bits followed by a string of octets that contain the
 * actual integer.
 */
module.exports = function mpi() {
	/** An implementation dependent integer */
	this.data = null;

	/**
	 * Parsing function for a mpi (RFC 4880 3.2).
	 * @param {String} input Payload of mpi data
	 * @param {Integer} position Position to start reading from the input 
	 * string
	 * @param {Integer} len Length of the packet or the remaining length of 
	 * input at position
	 * @return {openpgp_type_mpi} Object representation
	 */
	this.read = function(bytes) {
		var bits = (bytes[0].charCodeAt() << 8) | bytes[1].charCodeAt();
		
		// Additional rules:
		//
		//    The size of an MPI is ((MPI.length + 7) / 8) + 2 octets.
		//
		//    The length field of an MPI describes the length starting from its
		//	  most significant non-zero bit.  Thus, the MPI [00 02 01] is not
		//    formed correctly.  It should be [00 01 01].

		// TODO: Verification of this size method! This size calculation as
		// 		 specified above is not applicable in JavaScript
		var bytelen = Math.ceil(bits / 8);
		
		var raw = bytes.substr(2, bytelen);
		this.fromBytes(raw);

		return 2 + bytelen;
	}

	this.fromBytes = function(bytes) {
		this.data = new BigInteger(util.hexstrdump(bytes), 16); 
	}

	this.toBytes = function() {
		return this.write().substr(2);
	}

	this.byteLength = function() {
		return this.toBytes().length;
	}

	/**
	 * Converts the mpi object to a string as specified in RFC4880 3.2
	 * @return {String} mpi Byte representation
	 */
	this.write = function() {
		return this.data.toMPI();
	}

	this.toBigInteger = function() {
		return this.data.clone();
	}

	this.fromBigInteger = function(bn) {
		this.data = bn.clone();
	}
}


},{"../crypto/public_key/jsbn.js":13,"../util":7}],10:[function(require,module,exports){
module.exports = {
	/** RFC4880, section 9.1 
	 * @enum {String}
	 */
	publicKey: {
		rsa_encrypt_sign: 1,
		rsa_encrypt: 2,
		rsa_sign: 3,
		elgamal: 16,
		dsa: 17
	},

	/** RFC4880, section 9.2 
	 * @enum {String}
	 */
	symmetric: {
		plaintext: 0,
		/** Not implemented! */
		idea: 1,
		tripledes: 2,
		cast5: 3,
		blowfish: 4,
		aes128: 7,
		aes192: 8,
		aes256: 9,
		twofish: 10
	},

	/** RFC4880, section 9.3
	 * @enum {String}
	 */
	compression: {
		uncompressed: 0,
		/** RFC1951 */
		zip: 1,
		/** RFC1950 */
		zlib: 2,
		bzip2: 3
	},

	/** RFC4880, section 9.4
	 * @enum {String}
	 */
	hash: {
		md5: 1,
		sha1: 2,
		ripemd: 3,
		sha256: 8,
		sha384: 9,
		sha512: 10,
		sha224: 11
	},


	/**
	 * @enum {String}
	 * A list of packet types and numeric tags associated with them.
	 */
	packet: {
		public_key_encrypted_session_key: 1,
		signature: 2,
		sym_encrypted_session_key: 3,
		one_pass_signature: 4,
		secret_key: 5,
		public_key: 6,
		secret_subkey: 7,
		compressed: 8,
		symmetrically_encrypted: 9,
		marker: 10,
		literal: 11,
		trust: 12,
		userid: 13,
		public_subkey: 14,
		user_attribute: 17,
		sym_encrypted_integrity_protected: 18,
		modification_detection_code: 19
	},


	/**
	 * Data types in the literal packet
	 * @readonly
	 * @enum {String}
	 */
	literal: {
		/** Binary data */
		binary: 'b'.charCodeAt(),
		/** Text data */
		text: 't'.charCodeAt(),
		/** Utf8 data */
		utf8: 'u'.charCodeAt()
	},


	/** One pass signature packet type
	 * @enum {String} */
	signature: {
		/** 0x00: Signature of a binary document. */
		binary: 0,
		/** 0x01: Signature of a canonical text document.
		 * Canonicalyzing the document by converting line endings. */
		text: 1,
		/** 0x02: Standalone signature.
		* This signature is a signature of only its own subpacket contents.
		* It is calculated identically to a signature over a zero-lengh
		* binary document.  Note that it doesn't make sense to have a V3
		* standalone signature. */
		standalone: 2,
		/** 0x10: Generic certification of a User ID and Public-Key packet.
		* The issuer of this certification does not make any particular
		* assertion as to how well the certifier has checked that the owner
		* of the key is in fact the person described by the User ID. */
		cert_generic: 16,
		/** 0x11: Persona certification of a User ID and Public-Key packet.
		* The issuer of this certification has not done any verification of
		* the claim that the owner of this key is the User ID specified. */
		cert_persona: 17,
		/** 0x12: Casual certification of a User ID and Public-Key packet.
		* The issuer of this certification has done some casual
		* verification of the claim of identity. */
		cert_casual: 18,
		/** 0x13: Positive certification of a User ID and Public-Key packet.
		* The issuer of this certification has done substantial
		* verification of the claim of identity.
		* 
		* Most OpenPGP implementations make their "key signatures" as 0x10
		* certifications.  Some implementations can issue 0x11-0x13
		* certifications, but few differentiate between the types. */
		cert_positive: 19,
		/** 0x30: Certification revocation signature
		* This signature revokes an earlier User ID certification signature
		* (signature class 0x10 through 0x13) or direct-key signature
		* (0x1F).  It should be issued by the same key that issued the
		* revoked signature or an authorized revocation key.  The signature
		* is computed over the same data as the certificate that it
		* revokes, and should have a later creation date than that
		* certificate. */
		cert_revocation: 48,
		/** 0x18: Subkey Binding Signature
		* This signature is a statement by the top-level signing key that
		* indicates that it owns the subkey.  This signature is calculated
		* directly on the primary key and subkey, and not on any User ID or
		* other packets.  A signature that binds a signing subkey MUST have
		* an Embedded Signature subpacket in this binding signature that
		* contains a 0x19 signature made by the signing subkey on the
		* primary key and subkey. */
		subkey_binding: 24,
		/** 0x19: Primary Key Binding Signature
		* This signature is a statement by a signing subkey, indicating
		* that it is owned by the primary key and subkey.  This signature
		* is calculated the same way as a 0x18 signature: directly on the
		* primary key and subkey, and not on any User ID or other packets.
		
		* When a signature is made over a key, the hash data starts with the
		* octet 0x99, followed by a two-octet length of the key, and then body
		* of the key packet.  (Note that this is an old-style packet header for
		* a key packet with two-octet length.)  A subkey binding signature
		* (type 0x18) or primary key binding signature (type 0x19) then hashes
		* the subkey using the same format as the main key (also using 0x99 as
		* the first octet). */
		key_binding: 25,
		/** 0x1F: Signature directly on a key
		* This signature is calculated directly on a key.  It binds the
		* information in the Signature subpackets to the key, and is
		* appropriate to be used for subpackets that provide information
		* about the key, such as the Revocation Key subpacket.  It is also
		* appropriate for statements that non-self certifiers want to make
		* about the key itself, rather than the binding between a key and a
		* name. */
		key: 31,
		/** 0x20: Key revocation signature
		* The signature is calculated directly on the key being revoked.  A
		* revoked key is not to be used.  Only revocation signatures by the
		* key being revoked, or by an authorized revocation key, should be
		* considered valid revocation signatures.a */
		key_revocation: 32,
		/** 0x28: Subkey revocation signature
		* The signature is calculated directly on the subkey being revoked.
		* A revoked subkey is not to be used.  Only revocation signatures
		* by the top-level signature key that is bound to this subkey, or
		* by an authorized revocation key, should be considered valid
		* revocation signatures.
		* Key revocation signatures (types 0x20 and 0x28)
		* hash only the key being revoked. */
		subkey_revocation: 40,
		/** 0x40: Timestamp signature.
		* This signature is only meaningful for the timestamp contained in
		* it. */
		timestamp: 64,
		/**    0x50: Third-Party Confirmation signature.
		* This signature is a signature over some other OpenPGP Signature
		* packet(s).  It is analogous to a notary seal on the signed data.
		* A third-party signature SHOULD include Signature Target
		* subpacket(s) to give easy identification.  Note that we really do
		* mean SHOULD.  There are plausible uses for this (such as a blind
		* party that only sees the signature, not the key or source
		* document) that cannot include a target subpacket. */
		third_party: 80
	},

	// Asserts validity and converts from string/integer to integer.
	write: function(type, e) {
		if(typeof e == 'number') {
			e = this.read(type, e);
		}
		
		if(type[e] != undefined) {
			return type[e];
		} else throw new Error('Invalid enum value.');
	},
	// Converts from an integer to string.
	read: function(type, e) {
		for(var i in type)
			if(type[i] == e) return i;

		throw new Error('Invalid enum value.');
	}
}





},{}],6:[function(require,module,exports){

module.exports = {
	cipher: require('./cipher'),
	hash: require('./hash'),
	cfb: require('./cfb.js'),
	publicKey: require('./public_key'),
	signature: require('./signature.js'),
}

var crypto = require('./crypto.js');

for(var i in crypto)
	module.exports[i] = crypto[i];




},{"./cfb.js":14,"./signature.js":15,"./crypto.js":16,"./cipher":17,"./hash":18,"./public_key":19}],11:[function(require,module,exports){


var packetParser = require('./packet.js'),
	packets = require('./all_packets.js'),
	enums = require('../enums.js');

/**
 * @class
 * @classdesc This class represents a list of openpgp packets.
 * Take care when iterating over it - the packets themselves
 * are stored as numerical indices.
 */
module.exports = function packetlist() {
	/** The number of packets contained within the list.
	 * @readonly
	 * @type {Integer} */
	this.length = 0;



	/**
	 * Reads a stream of binary data and interprents it as a list of packets.
	 * @param {openpgp_bytearray} An array of bytes.
	 */
	this.read = function(bytes) {
		var i = 0;

		while(i < bytes.length) {
			var parsed = packetParser.read(bytes, i, bytes.length - i);
			i = parsed.offset;

			var tag = enums.read(enums.packet, parsed.tag);
			var packet = new packets[tag]();

			this.push(packet);

			packet.read(parsed.packet);
		}
	}

	/**
	 * Creates a binary representation of openpgp objects contained within the
	 * class instance.
	 * @returns {openpgp_bytearray} An array of bytes containing valid openpgp packets.
	 */
	this.write = function() {
		var bytes = '';

		for(var i = 0; i < this.length; i++) {
			var packetbytes = this[i].write();
			bytes += packetParser.writeHeader(this[i].tag, packetbytes.length);
			bytes += packetbytes;
		}
		
		return bytes;
	}

	/**
	 * Adds a packet to the list. This is the only supported method of doing so;
	 * writing to packetlist[i] directly will result in an error.
	 */
	this.push = function(packet) {
		packet.packets = new packetlist();

		this[this.length] = packet;
		this.length++;
	}

}

},{"./packet.js":20,"./all_packets.js":12,"../enums.js":10}],12:[function(require,module,exports){

var enums = require('../enums.js');

// This is pretty ugly, but browserify needs to have the requires explicitly written.
module.exports = {
	compressed: require('./compressed.js'),
	sym_encrypted_integrity_protected: require('./sym_encrypted_integrity_protected.js'),
	public_key_encrypted_session_key: require('./public_key_encrypted_session_key.js'),
	sym_encrypted_session_key: require('./sym_encrypted_session_key.js'),
	literal: require('./literal.js'),
	public_key: require('./public_key.js'),
	symmetrically_encrypted: require('./symmetrically_encrypted.js'),
	marker: require('./marker.js'),
	public_subkey: require('./public_subkey.js'),
	user_attribute: require('./user_attribute.js'),
	one_pass_signature: require('./one_pass_signature.js'),
	secret_key: require('./secret_key.js'),
	userid: require('./userid.js'),
	secret_subkey: require('./secret_subkey.js'),
	signature: require('./signature.js'),
	trust: require('./trust.js')
}

for(var i in enums.packet) {
	var packetClass = module.exports[i];

	if(packetClass != undefined)
		packetClass.prototype.tag = enums.packet[i];
}

},{"../enums.js":10,"./compressed.js":21,"./sym_encrypted_integrity_protected.js":22,"./public_key_encrypted_session_key.js":23,"./sym_encrypted_session_key.js":24,"./literal.js":25,"./public_key.js":26,"./symmetrically_encrypted.js":27,"./marker.js":28,"./public_subkey.js":29,"./user_attribute.js":30,"./one_pass_signature.js":31,"./secret_key.js":32,"./userid.js":33,"./secret_subkey.js":34,"./signature.js":35,"./trust.js":36}],13:[function(require,module,exports){
/*
 * Copyright (c) 2003-2005  Tom Wu (tjw@cs.Stanford.EDU) 
 * All Rights Reserved.
 *
 * Modified by Recurity Labs GmbH 
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY 
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  
 *
 * IN NO EVENT SHALL TOM WU BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
 * INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT ADVISED OF
 * THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * In addition, the following condition applies:
 *
 * All redistributions must retain an intact copy of this copyright notice
 * and disclaimer.
 */


var util = require('../../util');

// Basic JavaScript BN library - subset useful for RSA encryption.

// Bits per digit
var dbits;

// JavaScript engine analysis
var canary = 0xdeadbeefcafe;
var j_lm = ((canary&0xffffff)==0xefcafe);

// (public) Constructor
function BigInteger(a,b,c) {
  if(a != null)
    if("number" == typeof a) this.fromNumber(a,b,c);
    else if(b == null && "string" != typeof a) this.fromString(a,256);
    else this.fromString(a,b);
}

// return new, unset BigInteger
function nbi() { return new BigInteger(null); }

// am: Compute w_j += (x*this_i), propagate carries,
// c is initial carry, returns final carry.
// c < 3*dvalue, x < 2*dvalue, this_i < dvalue
// We need to select the fastest one that works in this environment.

// am1: use a single mult and divide to get the high bits,
// max digit bits should be 26 because
// max internal value = 2*dvalue^2-2*dvalue (< 2^53)
function am1(i,x,w,j,c,n) {
  while(--n >= 0) {
    var v = x*this[i++]+w[j]+c;
    c = Math.floor(v/0x4000000);
    w[j++] = v&0x3ffffff;
  }
  return c;
}
// am2 avoids a big mult-and-extract completely.
// Max digit bits should be <= 30 because we do bitwise ops
// on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)
function am2(i,x,w,j,c,n) {
  var xl = x&0x7fff, xh = x>>15;
  while(--n >= 0) {
    var l = this[i]&0x7fff;
    var h = this[i++]>>15;
    var m = xh*l+h*xl;
    l = xl*l+((m&0x7fff)<<15)+w[j]+(c&0x3fffffff);
    c = (l>>>30)+(m>>>15)+xh*h+(c>>>30);
    w[j++] = l&0x3fffffff;
  }
  return c;
}
// Alternately, set max digit bits to 28 since some
// browsers slow down when dealing with 32-bit numbers.
function am3(i,x,w,j,c,n) {
  var xl = x&0x3fff, xh = x>>14;
  while(--n >= 0) {
    var l = this[i]&0x3fff;
    var h = this[i++]>>14;
    var m = xh*l+h*xl;
    l = xl*l+((m&0x3fff)<<14)+w[j]+c;
    c = (l>>28)+(m>>14)+xh*h;
    w[j++] = l&0xfffffff;
  }
  return c;
}
if(j_lm && (navigator.appName == "Microsoft Internet Explorer")) {
  BigInteger.prototype.am = am2;
  dbits = 30;
}
else if(j_lm && (navigator.appName != "Netscape")) {
  BigInteger.prototype.am = am1;
  dbits = 26;
}
else { // Mozilla/Netscape seems to prefer am3
  BigInteger.prototype.am = am3;
  dbits = 28;
}

BigInteger.prototype.DB = dbits;
BigInteger.prototype.DM = ((1<<dbits)-1);
BigInteger.prototype.DV = (1<<dbits);

var BI_FP = 52;
BigInteger.prototype.FV = Math.pow(2,BI_FP);
BigInteger.prototype.F1 = BI_FP-dbits;
BigInteger.prototype.F2 = 2*dbits-BI_FP;

// Digit conversions
var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
var BI_RC = new Array();
var rr,vv;
rr = "0".charCodeAt(0);
for(vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
rr = "a".charCodeAt(0);
for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
rr = "A".charCodeAt(0);
for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;

function int2char(n) { return BI_RM.charAt(n); }
function intAt(s,i) {
  var c = BI_RC[s.charCodeAt(i)];
  return (c==null)?-1:c;
}

// (protected) copy this to r
function bnpCopyTo(r) {
  for(var i = this.t-1; i >= 0; --i) r[i] = this[i];
  r.t = this.t;
  r.s = this.s;
}

// (protected) set from integer value x, -DV <= x < DV
function bnpFromInt(x) {
  this.t = 1;
  this.s = (x<0)?-1:0;
  if(x > 0) this[0] = x;
  else if(x < -1) this[0] = x+DV;
  else this.t = 0;
}

// return bigint initialized to value
function nbv(i) { var r = nbi(); r.fromInt(i); return r; }

// (protected) set from string and radix
function bnpFromString(s,b) {
  var k;
  if(b == 16) k = 4;
  else if(b == 8) k = 3;
  else if(b == 256) k = 8; // byte array
  else if(b == 2) k = 1;
  else if(b == 32) k = 5;
  else if(b == 4) k = 2;
  else { this.fromRadix(s,b); return; }
  this.t = 0;
  this.s = 0;
  var i = s.length, mi = false, sh = 0;
  while(--i >= 0) {
    var x = (k==8)?s[i]&0xff:intAt(s,i);
    if(x < 0) {
      if(s.charAt(i) == "-") mi = true;
      continue;
    }
    mi = false;
    if(sh == 0)
      this[this.t++] = x;
    else if(sh+k > this.DB) {
      this[this.t-1] |= (x&((1<<(this.DB-sh))-1))<<sh;
      this[this.t++] = (x>>(this.DB-sh));
    }
    else
      this[this.t-1] |= x<<sh;
    sh += k;
    if(sh >= this.DB) sh -= this.DB;
  }
  if(k == 8 && (s[0]&0x80) != 0) {
    this.s = -1;
    if(sh > 0) this[this.t-1] |= ((1<<(this.DB-sh))-1)<<sh;
  }
  this.clamp();
  if(mi) BigInteger.ZERO.subTo(this,this);
}

// (protected) clamp off excess high words
function bnpClamp() {
  var c = this.s&this.DM;
  while(this.t > 0 && this[this.t-1] == c) --this.t;
}

// (public) return string representation in given radix
function bnToString(b) {
  if(this.s < 0) return "-"+this.negate().toString(b);
  var k;
  if(b == 16) k = 4;
  else if(b == 8) k = 3;
  else if(b == 2) k = 1;
  else if(b == 32) k = 5;
  else if(b == 4) k = 2;
  else return this.toRadix(b);
  var km = (1<<k)-1, d, m = false, r = "", i = this.t;
  var p = this.DB-(i*this.DB)%k;
  if(i-- > 0) {
    if(p < this.DB && (d = this[i]>>p) > 0) { m = true; r = int2char(d); }
    while(i >= 0) {
      if(p < k) {
        d = (this[i]&((1<<p)-1))<<(k-p);
        d |= this[--i]>>(p+=this.DB-k);
      }
      else {
        d = (this[i]>>(p-=k))&km;
        if(p <= 0) { p += this.DB; --i; }
      }
      if(d > 0) m = true;
      if(m) r += int2char(d);
    }
  }
  return m?r:"0";
}

// (public) -this
function bnNegate() { var r = nbi(); BigInteger.ZERO.subTo(this,r); return r; }

// (public) |this|
function bnAbs() { return (this.s<0)?this.negate():this; }

// (public) return + if this > a, - if this < a, 0 if equal
function bnCompareTo(a) {
  var r = this.s-a.s;
  if(r != 0) return r;
  var i = this.t;
  r = i-a.t;
  if(r != 0) return r;
  while(--i >= 0) if((r=this[i]-a[i]) != 0) return r;
  return 0;
}

// returns bit length of the integer x
function nbits(x) {
  var r = 1, t;
  if((t=x>>>16) != 0) { x = t; r += 16; }
  if((t=x>>8) != 0) { x = t; r += 8; }
  if((t=x>>4) != 0) { x = t; r += 4; }
  if((t=x>>2) != 0) { x = t; r += 2; }
  if((t=x>>1) != 0) { x = t; r += 1; }
  return r;
}

// (public) return the number of bits in "this"
function bnBitLength() {
  if(this.t <= 0) return 0;
  return this.DB*(this.t-1)+nbits(this[this.t-1]^(this.s&this.DM));
}

// (protected) r = this << n*DB
function bnpDLShiftTo(n,r) {
  var i;
  for(i = this.t-1; i >= 0; --i) r[i+n] = this[i];
  for(i = n-1; i >= 0; --i) r[i] = 0;
  r.t = this.t+n;
  r.s = this.s;
}

// (protected) r = this >> n*DB
function bnpDRShiftTo(n,r) {
  for(var i = n; i < this.t; ++i) r[i-n] = this[i];
  r.t = Math.max(this.t-n,0);
  r.s = this.s;
}

// (protected) r = this << n
function bnpLShiftTo(n,r) {
  var bs = n%this.DB;
  var cbs = this.DB-bs;
  var bm = (1<<cbs)-1;
  var ds = Math.floor(n/this.DB), c = (this.s<<bs)&this.DM, i;
  for(i = this.t-1; i >= 0; --i) {
    r[i+ds+1] = (this[i]>>cbs)|c;
    c = (this[i]&bm)<<bs;
  }
  for(i = ds-1; i >= 0; --i) r[i] = 0;
  r[ds] = c;
  r.t = this.t+ds+1;
  r.s = this.s;
  r.clamp();
}

// (protected) r = this >> n
function bnpRShiftTo(n,r) {
  r.s = this.s;
  var ds = Math.floor(n/this.DB);
  if(ds >= this.t) { r.t = 0; return; }
  var bs = n%this.DB;
  var cbs = this.DB-bs;
  var bm = (1<<bs)-1;
  r[0] = this[ds]>>bs;
  for(var i = ds+1; i < this.t; ++i) {
    r[i-ds-1] |= (this[i]&bm)<<cbs;
    r[i-ds] = this[i]>>bs;
  }
  if(bs > 0) r[this.t-ds-1] |= (this.s&bm)<<cbs;
  r.t = this.t-ds;
  r.clamp();
}

// (protected) r = this - a
function bnpSubTo(a,r) {
  var i = 0, c = 0, m = Math.min(a.t,this.t);
  while(i < m) {
    c += this[i]-a[i];
    r[i++] = c&this.DM;
    c >>= this.DB;
  }
  if(a.t < this.t) {
    c -= a.s;
    while(i < this.t) {
      c += this[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += this.s;
  }
  else {
    c += this.s;
    while(i < a.t) {
      c -= a[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c -= a.s;
  }
  r.s = (c<0)?-1:0;
  if(c < -1) r[i++] = this.DV+c;
  else if(c > 0) r[i++] = c;
  r.t = i;
  r.clamp();
}

// (protected) r = this * a, r != this,a (HAC 14.12)
// "this" should be the larger one if appropriate.
function bnpMultiplyTo(a,r) {
  var x = this.abs(), y = a.abs();
  var i = x.t;
  r.t = i+y.t;
  while(--i >= 0) r[i] = 0;
  for(i = 0; i < y.t; ++i) r[i+x.t] = x.am(0,y[i],r,i,0,x.t);
  r.s = 0;
  r.clamp();
  if(this.s != a.s) BigInteger.ZERO.subTo(r,r);
}

// (protected) r = this^2, r != this (HAC 14.16)
function bnpSquareTo(r) {
  var x = this.abs();
  var i = r.t = 2*x.t;
  while(--i >= 0) r[i] = 0;
  for(i = 0; i < x.t-1; ++i) {
    var c = x.am(i,x[i],r,2*i,0,1);
    if((r[i+x.t]+=x.am(i+1,2*x[i],r,2*i+1,c,x.t-i-1)) >= x.DV) {
      r[i+x.t] -= x.DV;
      r[i+x.t+1] = 1;
    }
  }
  if(r.t > 0) r[r.t-1] += x.am(i,x[i],r,2*i,0,1);
  r.s = 0;
  r.clamp();
}

// (protected) divide this by m, quotient and remainder to q, r (HAC 14.20)
// r != q, this != m.  q or r may be null.
function bnpDivRemTo(m,q,r) {
  var pm = m.abs();
  if(pm.t <= 0) return;
  var pt = this.abs();
  if(pt.t < pm.t) {
    if(q != null) q.fromInt(0);
    if(r != null) this.copyTo(r);
    return;
  }
  if(r == null) r = nbi();
  var y = nbi(), ts = this.s, ms = m.s;
  var nsh = this.DB-nbits(pm[pm.t-1]);	// normalize modulus
  if(nsh > 0) { pm.lShiftTo(nsh,y); pt.lShiftTo(nsh,r); }
  else { pm.copyTo(y); pt.copyTo(r); }
  var ys = y.t;
  var y0 = y[ys-1];
  if(y0 == 0) return;
  var yt = y0*(1<<this.F1)+((ys>1)?y[ys-2]>>this.F2:0);
  var d1 = this.FV/yt, d2 = (1<<this.F1)/yt, e = 1<<this.F2;
  var i = r.t, j = i-ys, t = (q==null)?nbi():q;
  y.dlShiftTo(j,t);
  if(r.compareTo(t) >= 0) {
    r[r.t++] = 1;
    r.subTo(t,r);
  }
  BigInteger.ONE.dlShiftTo(ys,t);
  t.subTo(y,y);	// "negative" y so we can replace sub with am later
  while(y.t < ys) y[y.t++] = 0;
  while(--j >= 0) {
    // Estimate quotient digit
    var qd = (r[--i]==y0)?this.DM:Math.floor(r[i]*d1+(r[i-1]+e)*d2);
    if((r[i]+=y.am(0,qd,r,j,0,ys)) < qd) {	// Try it out
      y.dlShiftTo(j,t);
      r.subTo(t,r);
      while(r[i] < --qd) r.subTo(t,r);
    }
  }
  if(q != null) {
    r.drShiftTo(ys,q);
    if(ts != ms) BigInteger.ZERO.subTo(q,q);
  }
  r.t = ys;
  r.clamp();
  if(nsh > 0) r.rShiftTo(nsh,r);	// Denormalize remainder
  if(ts < 0) BigInteger.ZERO.subTo(r,r);
}

// (public) this mod a
function bnMod(a) {
  var r = nbi();
  this.abs().divRemTo(a,null,r);
  if(this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r,r);
  return r;
}

// Modular reduction using "classic" algorithm
function Classic(m) { this.m = m; }
function cConvert(x) {
  if(x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
  else return x;
}
function cRevert(x) { return x; }
function cReduce(x) { x.divRemTo(this.m,null,x); }
function cMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }
function cSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

Classic.prototype.convert = cConvert;
Classic.prototype.revert = cRevert;
Classic.prototype.reduce = cReduce;
Classic.prototype.mulTo = cMulTo;
Classic.prototype.sqrTo = cSqrTo;

// (protected) return "-1/this % 2^DB"; useful for Mont. reduction
// justification:
//         xy == 1 (mod m)
//         xy =  1+km
//   xy(2-xy) = (1+km)(1-km)
// x[y(2-xy)] = 1-k^2m^2
// x[y(2-xy)] == 1 (mod m^2)
// if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
// should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
// JS multiply "overflows" differently from C/C++, so care is needed here.
function bnpInvDigit() {
  if(this.t < 1) return 0;
  var x = this[0];
  if((x&1) == 0) return 0;
  var y = x&3;		// y == 1/x mod 2^2
  y = (y*(2-(x&0xf)*y))&0xf;	// y == 1/x mod 2^4
  y = (y*(2-(x&0xff)*y))&0xff;	// y == 1/x mod 2^8
  y = (y*(2-(((x&0xffff)*y)&0xffff)))&0xffff;	// y == 1/x mod 2^16
  // last step - calculate inverse mod DV directly;
  // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
  y = (y*(2-x*y%this.DV))%this.DV;		// y == 1/x mod 2^dbits
  // we really want the negative inverse, and -DV < y < DV
  return (y>0)?this.DV-y:-y;
}

// Montgomery reduction
function Montgomery(m) {
  this.m = m;
  this.mp = m.invDigit();
  this.mpl = this.mp&0x7fff;
  this.mph = this.mp>>15;
  this.um = (1<<(m.DB-15))-1;
  this.mt2 = 2*m.t;
}

// xR mod m
function montConvert(x) {
  var r = nbi();
  x.abs().dlShiftTo(this.m.t,r);
  r.divRemTo(this.m,null,r);
  if(x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r,r);
  return r;
}

// x/R mod m
function montRevert(x) {
  var r = nbi();
  x.copyTo(r);
  this.reduce(r);
  return r;
}

// x = x/R mod m (HAC 14.32)
function montReduce(x) {
  while(x.t <= this.mt2)	// pad x so am has enough room later
    x[x.t++] = 0;
  for(var i = 0; i < this.m.t; ++i) {
    // faster way of calculating u0 = x[i]*mp mod DV
    var j = x[i]&0x7fff;
    var u0 = (j*this.mpl+(((j*this.mph+(x[i]>>15)*this.mpl)&this.um)<<15))&x.DM;
    // use am to combine the multiply-shift-add into one call
    j = i+this.m.t;
    x[j] += this.m.am(0,u0,x,i,0,this.m.t);
    // propagate carry
    while(x[j] >= x.DV) { x[j] -= x.DV; x[++j]++; }
  }
  x.clamp();
  x.drShiftTo(this.m.t,x);
  if(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
}

// r = "x^2/R mod m"; x != r
function montSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

// r = "xy/R mod m"; x,y != r
function montMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

Montgomery.prototype.convert = montConvert;
Montgomery.prototype.revert = montRevert;
Montgomery.prototype.reduce = montReduce;
Montgomery.prototype.mulTo = montMulTo;
Montgomery.prototype.sqrTo = montSqrTo;

// (protected) true iff this is even
function bnpIsEven() { return ((this.t>0)?(this[0]&1):this.s) == 0; }

// (protected) this^e, e < 2^32, doing sqr and mul with "r" (HAC 14.79)
function bnpExp(e,z) {
  if(e > 0xffffffff || e < 1) return BigInteger.ONE;
  var r = nbi(), r2 = nbi(), g = z.convert(this), i = nbits(e)-1;
  g.copyTo(r);
  while(--i >= 0) {
    z.sqrTo(r,r2);
    if((e&(1<<i)) > 0) z.mulTo(r2,g,r);
    else { var t = r; r = r2; r2 = t; }
  }
  return z.revert(r);
}

// (public) this^e % m, 0 <= e < 2^32
function bnModPowInt(e,m) {
  var z;
  if(e < 256 || m.isEven()) z = new Classic(m); else z = new Montgomery(m);
  return this.exp(e,z);
}

// protected
BigInteger.prototype.copyTo = bnpCopyTo;
BigInteger.prototype.fromInt = bnpFromInt;
BigInteger.prototype.fromString = bnpFromString;
BigInteger.prototype.clamp = bnpClamp;
BigInteger.prototype.dlShiftTo = bnpDLShiftTo;
BigInteger.prototype.drShiftTo = bnpDRShiftTo;
BigInteger.prototype.lShiftTo = bnpLShiftTo;
BigInteger.prototype.rShiftTo = bnpRShiftTo;
BigInteger.prototype.subTo = bnpSubTo;
BigInteger.prototype.multiplyTo = bnpMultiplyTo;
BigInteger.prototype.squareTo = bnpSquareTo;
BigInteger.prototype.divRemTo = bnpDivRemTo;
BigInteger.prototype.invDigit = bnpInvDigit;
BigInteger.prototype.isEven = bnpIsEven;
BigInteger.prototype.exp = bnpExp;

// public
BigInteger.prototype.toString = bnToString;
BigInteger.prototype.negate = bnNegate;
BigInteger.prototype.abs = bnAbs;
BigInteger.prototype.compareTo = bnCompareTo;
BigInteger.prototype.bitLength = bnBitLength;
BigInteger.prototype.mod = bnMod;
BigInteger.prototype.modPowInt = bnModPowInt;

// "constants"
BigInteger.ZERO = nbv(0);
BigInteger.ONE = nbv(1);

module.exports = BigInteger;



















/*
 * Copyright (c) 2003-2005  Tom Wu (tjw@cs.Stanford.EDU) 
 * All Rights Reserved.
 *
 * Modified by Recurity Labs GmbH
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY 
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  
 *
 * IN NO EVENT SHALL TOM WU BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
 * INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT ADVISED OF
 * THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * In addition, the following condition applies:
 *
 * All redistributions must retain an intact copy of this copyright notice
 * and disclaimer.
 */


// Extended JavaScript BN functions, required for RSA private ops.

// Version 1.1: new BigInteger("0", 10) returns "proper" zero
// Version 1.2: square() API, isProbablePrime fix

// (public)
function bnClone() { var r = nbi(); this.copyTo(r); return r; }

// (public) return value as integer
function bnIntValue() {
  if(this.s < 0) {
    if(this.t == 1) return this[0]-this.DV;
    else if(this.t == 0) return -1;
  }
  else if(this.t == 1) return this[0];
  else if(this.t == 0) return 0;
  // assumes 16 < DB < 32
  return ((this[1]&((1<<(32-this.DB))-1))<<this.DB)|this[0];
}

// (public) return value as byte
function bnByteValue() { return (this.t==0)?this.s:(this[0]<<24)>>24; }

// (public) return value as short (assumes DB>=16)
function bnShortValue() { return (this.t==0)?this.s:(this[0]<<16)>>16; }

// (protected) return x s.t. r^x < DV
function bnpChunkSize(r) { return Math.floor(Math.LN2*this.DB/Math.log(r)); }

// (public) 0 if this == 0, 1 if this > 0
function bnSigNum() {
  if(this.s < 0) return -1;
  else if(this.t <= 0 || (this.t == 1 && this[0] <= 0)) return 0;
  else return 1;
}

// (protected) convert to radix string
function bnpToRadix(b) {
  if(b == null) b = 10;
  if(this.signum() == 0 || b < 2 || b > 36) return "0";
  var cs = this.chunkSize(b);
  var a = Math.pow(b,cs);
  var d = nbv(a), y = nbi(), z = nbi(), r = "";
  this.divRemTo(d,y,z);
  while(y.signum() > 0) {
    r = (a+z.intValue()).toString(b).substr(1) + r;
    y.divRemTo(d,y,z);
  }
  return z.intValue().toString(b) + r;
}

// (protected) convert from radix string
function bnpFromRadix(s,b) {
  this.fromInt(0);
  if(b == null) b = 10;
  var cs = this.chunkSize(b);
  var d = Math.pow(b,cs), mi = false, j = 0, w = 0;
  for(var i = 0; i < s.length; ++i) {
    var x = intAt(s,i);
    if(x < 0) {
      if(s.charAt(i) == "-" && this.signum() == 0) mi = true;
      continue;
    }
    w = b*w+x;
    if(++j >= cs) {
      this.dMultiply(d);
      this.dAddOffset(w,0);
      j = 0;
      w = 0;
    }
  }
  if(j > 0) {
    this.dMultiply(Math.pow(b,j));
    this.dAddOffset(w,0);
  }
  if(mi) BigInteger.ZERO.subTo(this,this);
}

// (protected) alternate constructor
function bnpFromNumber(a,b,c) {
  if("number" == typeof b) {
    // new BigInteger(int,int,RNG)
    if(a < 2) this.fromInt(1);
    else {
      this.fromNumber(a,c);
      if(!this.testBit(a-1))	// force MSB set
        this.bitwiseTo(BigInteger.ONE.shiftLeft(a-1),op_or,this);
      if(this.isEven()) this.dAddOffset(1,0); // force odd
      while(!this.isProbablePrime(b)) {
        this.dAddOffset(2,0);
        if(this.bitLength() > a) this.subTo(BigInteger.ONE.shiftLeft(a-1),this);
      }
    }
  }
  else {
    // new BigInteger(int,RNG)
    var x = new Array(), t = a&7;
    x.length = (a>>3)+1;
    b.nextBytes(x);
    if(t > 0) x[0] &= ((1<<t)-1); else x[0] = 0;
    this.fromString(x,256);
  }
}

// (public) convert to bigendian byte array
function bnToByteArray() {
  var i = this.t, r = new Array();
  r[0] = this.s;
  var p = this.DB-(i*this.DB)%8, d, k = 0;
  if(i-- > 0) {
    if(p < this.DB && (d = this[i]>>p) != (this.s&this.DM)>>p)
      r[k++] = d|(this.s<<(this.DB-p));
    while(i >= 0) {
      if(p < 8) {
        d = (this[i]&((1<<p)-1))<<(8-p);
        d |= this[--i]>>(p+=this.DB-8);
      }
      else {
        d = (this[i]>>(p-=8))&0xff;
        if(p <= 0) { p += this.DB; --i; }
      }
      //if((d&0x80) != 0) d |= -256;
      //if(k == 0 && (this.s&0x80) != (d&0x80)) ++k;
      if(k > 0 || d != this.s) r[k++] = d;
    }
  }
  return r;
}

function bnEquals(a) { return(this.compareTo(a)==0); }
function bnMin(a) { return(this.compareTo(a)<0)?this:a; }
function bnMax(a) { return(this.compareTo(a)>0)?this:a; }

// (protected) r = this op a (bitwise)
function bnpBitwiseTo(a,op,r) {
  var i, f, m = Math.min(a.t,this.t);
  for(i = 0; i < m; ++i) r[i] = op(this[i],a[i]);
  if(a.t < this.t) {
    f = a.s&this.DM;
    for(i = m; i < this.t; ++i) r[i] = op(this[i],f);
    r.t = this.t;
  }
  else {
    f = this.s&this.DM;
    for(i = m; i < a.t; ++i) r[i] = op(f,a[i]);
    r.t = a.t;
  }
  r.s = op(this.s,a.s);
  r.clamp();
}

// (public) this & a
function op_and(x,y) { return x&y; }
function bnAnd(a) { var r = nbi(); this.bitwiseTo(a,op_and,r); return r; }

// (public) this | a
function op_or(x,y) { return x|y; }
function bnOr(a) { var r = nbi(); this.bitwiseTo(a,op_or,r); return r; }

// (public) this ^ a
function op_xor(x,y) { return x^y; }
function bnXor(a) { var r = nbi(); this.bitwiseTo(a,op_xor,r); return r; }

// (public) this & ~a
function op_andnot(x,y) { return x&~y; }
function bnAndNot(a) { var r = nbi(); this.bitwiseTo(a,op_andnot,r); return r; }

// (public) ~this
function bnNot() {
  var r = nbi();
  for(var i = 0; i < this.t; ++i) r[i] = this.DM&~this[i];
  r.t = this.t;
  r.s = ~this.s;
  return r;
}

// (public) this << n
function bnShiftLeft(n) {
  var r = nbi();
  if(n < 0) this.rShiftTo(-n,r); else this.lShiftTo(n,r);
  return r;
}

// (public) this >> n
function bnShiftRight(n) {
  var r = nbi();
  if(n < 0) this.lShiftTo(-n,r); else this.rShiftTo(n,r);
  return r;
}

// return index of lowest 1-bit in x, x < 2^31
function lbit(x) {
  if(x == 0) return -1;
  var r = 0;
  if((x&0xffff) == 0) { x >>= 16; r += 16; }
  if((x&0xff) == 0) { x >>= 8; r += 8; }
  if((x&0xf) == 0) { x >>= 4; r += 4; }
  if((x&3) == 0) { x >>= 2; r += 2; }
  if((x&1) == 0) ++r;
  return r;
}

// (public) returns index of lowest 1-bit (or -1 if none)
function bnGetLowestSetBit() {
  for(var i = 0; i < this.t; ++i)
    if(this[i] != 0) return i*this.DB+lbit(this[i]);
  if(this.s < 0) return this.t*this.DB;
  return -1;
}

// return number of 1 bits in x
function cbit(x) {
  var r = 0;
  while(x != 0) { x &= x-1; ++r; }
  return r;
}

// (public) return number of set bits
function bnBitCount() {
  var r = 0, x = this.s&this.DM;
  for(var i = 0; i < this.t; ++i) r += cbit(this[i]^x);
  return r;
}

// (public) true iff nth bit is set
function bnTestBit(n) {
  var j = Math.floor(n/this.DB);
  if(j >= this.t) return(this.s!=0);
  return((this[j]&(1<<(n%this.DB)))!=0);
}

// (protected) this op (1<<n)
function bnpChangeBit(n,op) {
  var r = BigInteger.ONE.shiftLeft(n);
  this.bitwiseTo(r,op,r);
  return r;
}

// (public) this | (1<<n)
function bnSetBit(n) { return this.changeBit(n,op_or); }

// (public) this & ~(1<<n)
function bnClearBit(n) { return this.changeBit(n,op_andnot); }

// (public) this ^ (1<<n)
function bnFlipBit(n) { return this.changeBit(n,op_xor); }

// (protected) r = this + a
function bnpAddTo(a,r) {
  var i = 0, c = 0, m = Math.min(a.t,this.t);
  while(i < m) {
    c += this[i]+a[i];
    r[i++] = c&this.DM;
    c >>= this.DB;
  }
  if(a.t < this.t) {
    c += a.s;
    while(i < this.t) {
      c += this[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += this.s;
  }
  else {
    c += this.s;
    while(i < a.t) {
      c += a[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += a.s;
  }
  r.s = (c<0)?-1:0;
  if(c > 0) r[i++] = c;
  else if(c < -1) r[i++] = this.DV+c;
  r.t = i;
  r.clamp();
}

// (public) this + a
function bnAdd(a) { var r = nbi(); this.addTo(a,r); return r; }

// (public) this - a
function bnSubtract(a) { var r = nbi(); this.subTo(a,r); return r; }

// (public) this * a
function bnMultiply(a) { var r = nbi(); this.multiplyTo(a,r); return r; }

// (public) this^2
function bnSquare() { var r = nbi(); this.squareTo(r); return r; }

// (public) this / a
function bnDivide(a) { var r = nbi(); this.divRemTo(a,r,null); return r; }

// (public) this % a
function bnRemainder(a) { var r = nbi(); this.divRemTo(a,null,r); return r; }

// (public) [this/a,this%a]
function bnDivideAndRemainder(a) {
  var q = nbi(), r = nbi();
  this.divRemTo(a,q,r);
  return new Array(q,r);
}

// (protected) this *= n, this >= 0, 1 < n < DV
function bnpDMultiply(n) {
  this[this.t] = this.am(0,n-1,this,0,0,this.t);
  ++this.t;
  this.clamp();
}

// (protected) this += n << w words, this >= 0
function bnpDAddOffset(n,w) {
  if(n == 0) return;
  while(this.t <= w) this[this.t++] = 0;
  this[w] += n;
  while(this[w] >= this.DV) {
    this[w] -= this.DV;
    if(++w >= this.t) this[this.t++] = 0;
    ++this[w];
  }
}

// A "null" reducer
function NullExp() {}
function nNop(x) { return x; }
function nMulTo(x,y,r) { x.multiplyTo(y,r); }
function nSqrTo(x,r) { x.squareTo(r); }

NullExp.prototype.convert = nNop;
NullExp.prototype.revert = nNop;
NullExp.prototype.mulTo = nMulTo;
NullExp.prototype.sqrTo = nSqrTo;

// (public) this^e
function bnPow(e) { return this.exp(e,new NullExp()); }

// (protected) r = lower n words of "this * a", a.t <= n
// "this" should be the larger one if appropriate.
function bnpMultiplyLowerTo(a,n,r) {
  var i = Math.min(this.t+a.t,n);
  r.s = 0; // assumes a,this >= 0
  r.t = i;
  while(i > 0) r[--i] = 0;
  var j;
  for(j = r.t-this.t; i < j; ++i) r[i+this.t] = this.am(0,a[i],r,i,0,this.t);
  for(j = Math.min(a.t,n); i < j; ++i) this.am(0,a[i],r,i,0,n-i);
  r.clamp();
}

// (protected) r = "this * a" without lower n words, n > 0
// "this" should be the larger one if appropriate.
function bnpMultiplyUpperTo(a,n,r) {
  --n;
  var i = r.t = this.t+a.t-n;
  r.s = 0; // assumes a,this >= 0
  while(--i >= 0) r[i] = 0;
  for(i = Math.max(n-this.t,0); i < a.t; ++i)
    r[this.t+i-n] = this.am(n-i,a[i],r,0,0,this.t+i-n);
  r.clamp();
  r.drShiftTo(1,r);
}

// Barrett modular reduction
function Barrett(m) {
  // setup Barrett
  this.r2 = nbi();
  this.q3 = nbi();
  BigInteger.ONE.dlShiftTo(2*m.t,this.r2);
  this.mu = this.r2.divide(m);
  this.m = m;
}

function barrettConvert(x) {
  if(x.s < 0 || x.t > 2*this.m.t) return x.mod(this.m);
  else if(x.compareTo(this.m) < 0) return x;
  else { var r = nbi(); x.copyTo(r); this.reduce(r); return r; }
}

function barrettRevert(x) { return x; }

// x = x mod m (HAC 14.42)
function barrettReduce(x) {
  x.drShiftTo(this.m.t-1,this.r2);
  if(x.t > this.m.t+1) { x.t = this.m.t+1; x.clamp(); }
  this.mu.multiplyUpperTo(this.r2,this.m.t+1,this.q3);
  this.m.multiplyLowerTo(this.q3,this.m.t+1,this.r2);
  while(x.compareTo(this.r2) < 0) x.dAddOffset(1,this.m.t+1);
  x.subTo(this.r2,x);
  while(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
}

// r = x^2 mod m; x != r
function barrettSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

// r = x*y mod m; x,y != r
function barrettMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

Barrett.prototype.convert = barrettConvert;
Barrett.prototype.revert = barrettRevert;
Barrett.prototype.reduce = barrettReduce;
Barrett.prototype.mulTo = barrettMulTo;
Barrett.prototype.sqrTo = barrettSqrTo;

// (public) this^e % m (HAC 14.85)
function bnModPow(e,m) {
  var i = e.bitLength(), k, r = nbv(1), z;
  if(i <= 0) return r;
  else if(i < 18) k = 1;
  else if(i < 48) k = 3;
  else if(i < 144) k = 4;
  else if(i < 768) k = 5;
  else k = 6;
  if(i < 8)
    z = new Classic(m);
  else if(m.isEven())
    z = new Barrett(m);
  else
    z = new Montgomery(m);

  // precomputation
  var g = new Array(), n = 3, k1 = k-1, km = (1<<k)-1;
  g[1] = z.convert(this);
  if(k > 1) {
    var g2 = nbi();
    z.sqrTo(g[1],g2);
    while(n <= km) {
      g[n] = nbi();
      z.mulTo(g2,g[n-2],g[n]);
      n += 2;
    }
  }

  var j = e.t-1, w, is1 = true, r2 = nbi(), t;
  i = nbits(e[j])-1;
  while(j >= 0) {
    if(i >= k1) w = (e[j]>>(i-k1))&km;
    else {
      w = (e[j]&((1<<(i+1))-1))<<(k1-i);
      if(j > 0) w |= e[j-1]>>(this.DB+i-k1);
    }

    n = k;
    while((w&1) == 0) { w >>= 1; --n; }
    if((i -= n) < 0) { i += this.DB; --j; }
    if(is1) {	// ret == 1, don't bother squaring or multiplying it
      g[w].copyTo(r);
      is1 = false;
    }
    else {
      while(n > 1) { z.sqrTo(r,r2); z.sqrTo(r2,r); n -= 2; }
      if(n > 0) z.sqrTo(r,r2); else { t = r; r = r2; r2 = t; }
      z.mulTo(r2,g[w],r);
    }

    while(j >= 0 && (e[j]&(1<<i)) == 0) {
      z.sqrTo(r,r2); t = r; r = r2; r2 = t;
      if(--i < 0) { i = this.DB-1; --j; }
    }
  }
  return z.revert(r);
}

// (public) gcd(this,a) (HAC 14.54)
function bnGCD(a) {
  var x = (this.s<0)?this.negate():this.clone();
  var y = (a.s<0)?a.negate():a.clone();
  if(x.compareTo(y) < 0) { var t = x; x = y; y = t; }
  var i = x.getLowestSetBit(), g = y.getLowestSetBit();
  if(g < 0) return x;
  if(i < g) g = i;
  if(g > 0) {
    x.rShiftTo(g,x);
    y.rShiftTo(g,y);
  }
  while(x.signum() > 0) {
    if((i = x.getLowestSetBit()) > 0) x.rShiftTo(i,x);
    if((i = y.getLowestSetBit()) > 0) y.rShiftTo(i,y);
    if(x.compareTo(y) >= 0) {
      x.subTo(y,x);
      x.rShiftTo(1,x);
    }
    else {
      y.subTo(x,y);
      y.rShiftTo(1,y);
    }
  }
  if(g > 0) y.lShiftTo(g,y);
  return y;
}

// (protected) this % n, n < 2^26
function bnpModInt(n) {
  if(n <= 0) return 0;
  var d = this.DV%n, r = (this.s<0)?n-1:0;
  if(this.t > 0)
    if(d == 0) r = this[0]%n;
    else for(var i = this.t-1; i >= 0; --i) r = (d*r+this[i])%n;
  return r;
}

// (public) 1/this % m (HAC 14.61)
function bnModInverse(m) {
  var ac = m.isEven();
  if((this.isEven() && ac) || m.signum() == 0) return BigInteger.ZERO;
  var u = m.clone(), v = this.clone();
  var a = nbv(1), b = nbv(0), c = nbv(0), d = nbv(1);
  while(u.signum() != 0) {
    while(u.isEven()) {
      u.rShiftTo(1,u);
      if(ac) {
        if(!a.isEven() || !b.isEven()) { a.addTo(this,a); b.subTo(m,b); }
        a.rShiftTo(1,a);
      }
      else if(!b.isEven()) b.subTo(m,b);
      b.rShiftTo(1,b);
    }
    while(v.isEven()) {
      v.rShiftTo(1,v);
      if(ac) {
        if(!c.isEven() || !d.isEven()) { c.addTo(this,c); d.subTo(m,d); }
        c.rShiftTo(1,c);
      }
      else if(!d.isEven()) d.subTo(m,d);
      d.rShiftTo(1,d);
    }
    if(u.compareTo(v) >= 0) {
      u.subTo(v,u);
      if(ac) a.subTo(c,a);
      b.subTo(d,b);
    }
    else {
      v.subTo(u,v);
      if(ac) c.subTo(a,c);
      d.subTo(b,d);
    }
  }
  if(v.compareTo(BigInteger.ONE) != 0) return BigInteger.ZERO;
  if(d.compareTo(m) >= 0) return d.subtract(m);
  if(d.signum() < 0) d.addTo(m,d); else return d;
  if(d.signum() < 0) return d.add(m); else return d;
}

var lowprimes = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997];
var lplim = (1<<26)/lowprimes[lowprimes.length-1];

// (public) test primality with certainty >= 1-.5^t
function bnIsProbablePrime(t) {
  var i, x = this.abs();
  if(x.t == 1 && x[0] <= lowprimes[lowprimes.length-1]) {
    for(i = 0; i < lowprimes.length; ++i)
      if(x[0] == lowprimes[i]) return true;
    return false;
  }
  if(x.isEven()) return false;
  i = 1;
  while(i < lowprimes.length) {
    var m = lowprimes[i], j = i+1;
    while(j < lowprimes.length && m < lplim) m *= lowprimes[j++];
    m = x.modInt(m);
    while(i < j) if(m%lowprimes[i++] == 0) return false;
  }
  return x.millerRabin(t);
}

/* added by Recurity Labs */

function nbits(x) {
	var n = 1, t;
	if ((t = x >>> 16) != 0) {
		x = t;
		n += 16;
	}
	if ((t = x >> 8) != 0) {
		x = t;
		n += 8;
	}
	if ((t = x >> 4) != 0) {
		x = t;
		n += 4;
	}
	if ((t = x >> 2) != 0) {
		x = t;
		n += 2;
	}
	if ((t = x >> 1) != 0) {
		x = t;
		n += 1;
	}
	return n;
}

function bnToMPI () {
	var ba = this.toByteArray();
	var size = (ba.length-1)*8+nbits(ba[0]);
	var result = "";
	result += String.fromCharCode((size & 0xFF00) >> 8);
	result += String.fromCharCode(size & 0xFF);
	result += util.bin2str(ba);
	return result;
}
/* END of addition */

// (protected) true if probably prime (HAC 4.24, Miller-Rabin)
function bnpMillerRabin(t) {
  var n1 = this.subtract(BigInteger.ONE);
  var k = n1.getLowestSetBit();
  if(k <= 0) return false;
  var r = n1.shiftRight(k);
  t = (t+1)>>1;
  if(t > lowprimes.length) t = lowprimes.length;
  var a = nbi();
  for(var i = 0; i < t; ++i) {
    //Pick bases at random, instead of starting at 2
    a.fromInt(lowprimes[Math.floor(Math.random()*lowprimes.length)]);
    var y = a.modPow(r,this);
    if(y.compareTo(BigInteger.ONE) != 0 && y.compareTo(n1) != 0) {
      var j = 1;
      while(j++ < k && y.compareTo(n1) != 0) {
        y = y.modPowInt(2,this);
        if(y.compareTo(BigInteger.ONE) == 0) return false;
      }
      if(y.compareTo(n1) != 0) return false;
    }
  }
  return true;
}

var BigInteger = require('./jsbn.js');

// protected
BigInteger.prototype.chunkSize = bnpChunkSize;
BigInteger.prototype.toRadix = bnpToRadix;
BigInteger.prototype.fromRadix = bnpFromRadix;
BigInteger.prototype.fromNumber = bnpFromNumber;
BigInteger.prototype.bitwiseTo = bnpBitwiseTo;
BigInteger.prototype.changeBit = bnpChangeBit;
BigInteger.prototype.addTo = bnpAddTo;
BigInteger.prototype.dMultiply = bnpDMultiply;
BigInteger.prototype.dAddOffset = bnpDAddOffset;
BigInteger.prototype.multiplyLowerTo = bnpMultiplyLowerTo;
BigInteger.prototype.multiplyUpperTo = bnpMultiplyUpperTo;
BigInteger.prototype.modInt = bnpModInt;
BigInteger.prototype.millerRabin = bnpMillerRabin;

// public
BigInteger.prototype.clone = bnClone;
BigInteger.prototype.intValue = bnIntValue;
BigInteger.prototype.byteValue = bnByteValue;
BigInteger.prototype.shortValue = bnShortValue;
BigInteger.prototype.signum = bnSigNum;
BigInteger.prototype.toByteArray = bnToByteArray;
BigInteger.prototype.equals = bnEquals;
BigInteger.prototype.min = bnMin;
BigInteger.prototype.max = bnMax;
BigInteger.prototype.and = bnAnd;
BigInteger.prototype.or = bnOr;
BigInteger.prototype.xor = bnXor;
BigInteger.prototype.andNot = bnAndNot;
BigInteger.prototype.not = bnNot;
BigInteger.prototype.shiftLeft = bnShiftLeft;
BigInteger.prototype.shiftRight = bnShiftRight;
BigInteger.prototype.getLowestSetBit = bnGetLowestSetBit;
BigInteger.prototype.bitCount = bnBitCount;
BigInteger.prototype.testBit = bnTestBit;
BigInteger.prototype.setBit = bnSetBit;
BigInteger.prototype.clearBit = bnClearBit;
BigInteger.prototype.flipBit = bnFlipBit;
BigInteger.prototype.add = bnAdd;
BigInteger.prototype.subtract = bnSubtract;
BigInteger.prototype.multiply = bnMultiply;
BigInteger.prototype.divide = bnDivide;
BigInteger.prototype.remainder = bnRemainder;
BigInteger.prototype.divideAndRemainder = bnDivideAndRemainder;
BigInteger.prototype.modPow = bnModPow;
BigInteger.prototype.modInverse = bnModInverse;
BigInteger.prototype.pow = bnPow;
BigInteger.prototype.gcd = bnGCD;
BigInteger.prototype.isProbablePrime = bnIsProbablePrime;
BigInteger.prototype.toMPI = bnToMPI;

// JSBN-specific extension
BigInteger.prototype.square = bnSquare;



},{"./jsbn.js":13,"../../util":7}],37:[function(require,module,exports){
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

// The GPG4Browsers crypto interface

module.exports = {
	/**
	 * Retrieve secure random byte string of the specified length
	 * @param {Integer} length Length in bytes to generate
	 * @return {String} Random byte string
	 */
	getRandomBytes: function(length) {
		var result = '';
		for (var i = 0; i < length; i++) {
			result += String.fromCharCode(openpgp_crypto_getSecureRandomOctet());
		}
		return result;
	},

	/**
	 * Return a pseudo-random number in the specified range
	 * @param {Integer} from Min of the random number
	 * @param {Integer} to Max of the random number (max 32bit)
	 * @return {Integer} A pseudo random number
	 */
	getPseudoRandom: function(from, to) {
		return Math.round(Math.random()*(to-from))+from;
	},

	/**
	 * Return a secure random number in the specified range
	 * @param {Integer} from Min of the random number
	 * @param {Integer} to Max of the random number (max 32bit)
	 * @return {Integer} A secure random number
	 */
	getSecureRandom: function(from, to) {
		var buf = new Uint32Array(1);
		window.crypto.getRandomValues(buf);
		var bits = ((to-from)).toString(2).length;
		while ((buf[0] & (Math.pow(2, bits) -1)) > (to-from))
			window.crypto.getRandomValues(buf);
		return from+(Math.abs(buf[0] & (Math.pow(2, bits) -1)));
	},

	getSecureRandomOctet: function() {
		var buf = new Uint32Array(1);
		window.crypto.getRandomValues(buf);
		return buf[0] & 0xFF;
	}
}

},{}],22:[function(require,module,exports){
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
 * @classdesc Implementation of the Sym. Encrypted Integrity Protected Data 
 * Packet (Tag 18)
 * 
 * RFC4880 5.13: The Symmetrically Encrypted Integrity Protected Data packet is
 * a variant of the Symmetrically Encrypted Data packet. It is a new feature
 * created for OpenPGP that addresses the problem of detecting a modification to
 * encrypted data. It is used in combination with a Modification Detection Code
 * packet.
 */

module.exports = function packet_sym_encrypted_integrity_protected() {
	/** The encrypted payload. */
	this.encrypted = null; // string
	/** @type {Boolean}
	 * If after decrypting the packet this is set to true,
	 * a modification has been detected and thus the contents
	 * should be discarded.
	 */
	this.modification = false;
	this.packets;


	this.read = function(bytes) {
		// - A one-octet version number. The only currently defined value is
		// 1.
		var version = bytes[0].charCodeAt();

		if (version != 1) {
			throw new Error('Version ' + version + ' of encrypted integrity protected' +
				' packet is unsupported');
		}

		// - Encrypted data, the output of the selected symmetric-key cipher
		//   operating in Cipher Feedback mode with shift amount equal to the
		//   block size of the cipher (CFB-n where n is the block size).
		this.encrypted = bytes.substr(1);
	}

	this.write = function() {
		
		return String.fromCharCode(1) // Version
			+ this.encrypted;
	}

	this.encrypt = function(symmetric_algorithm, key) {
		var bytes = this.packets.write()
		
		var prefixrandom = openpgp_crypto_getPrefixRandom(symmetric_algorithm);
		var prefix = prefixrandom
				+ prefixrandom.charAt(prefixrandom.length - 2)
				+ prefixrandom.charAt(prefixrandom.length - 1)

		var tohash = bytes;


		// Modification detection code packet.
		tohash += String.fromCharCode(0xD3);
		tohash += String.fromCharCode(0x14);

		util.print_debug_hexstr_dump("data to be hashed:"
				, prefix + tohash);

		tohash += str_sha1(prefix + tohash);

		util.print_debug_hexstr_dump("hash:"
				, tohash.substring(tohash.length - 20,
						tohash.length));

		this.encrypted = openpgp_crypto_symmetricEncrypt(prefixrandom,
				symmetric_algorithm, key, tohash, false).substring(0,
				prefix.length + tohash.length);
	}

	/**
	 * Decrypts the encrypted data contained in this object read_packet must
	 * have been called before
	 * 
	 * @param {Integer} symmetric_algorithm_type
	 *            The selected symmetric encryption algorithm to be used
	 * @param {String} key The key of cipher blocksize length to be used
	 * @return {String} The decrypted data of this packet
	 */
	this.decrypt = function(symmetric_algorithm_type, key) {
		var decrypted = openpgp_crypto_symmetricDecrypt(
				symmetric_algorithm_type, key, this.encrypted, false);


		// there must be a modification detection code packet as the
		// last packet and everything gets hashed except the hash itself
		this.hash = str_sha1(
			openpgp_crypto_MDCSystemBytes(symmetric_algorithm_type, key, this.encrypted)
			+ decrypted.substring(0, decrypted.length - 20));

		util.print_debug_hexstr_dump("calc hash = ", this.hash);

		var mdc = decrypted.substr(decrypted.length - 20, 20);

		if(this.hash != mdc) {
			throw new Error('Modification detected.');
		}
		else
			this.packets.read(decrypted.substr(0, decrypted.length - 22));
	}
};

},{}],23:[function(require,module,exports){
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
 * @classdesc Public-Key Encrypted Session Key Packets (Tag 1)
 * 
 * RFC4880 5.1: A Public-Key Encrypted Session Key packet holds the session key
 * used to encrypt a message. Zero or more Public-Key Encrypted Session Key
 * packets and/or Symmetric-Key Encrypted Session Key packets may precede a
 * Symmetrically Encrypted Data Packet, which holds an encrypted message. The
 * message is encrypted with the session key, and the session key is itself
 * encrypted and stored in the Encrypted Session Key packet(s). The
 * Symmetrically Encrypted Data Packet is preceded by one Public-Key Encrypted
 * Session Key packet for each OpenPGP key to which the message is encrypted.
 * The recipient of the message finds a session key that is encrypted to their
 * public key, decrypts the session key, and then uses the session key to
 * decrypt the message.
 */
module.exports = function packet_public_key_encrypted_session_key() {
	this.version = 3;

	this.publicKeyId = new openpgp_type_keyid();
	this.publicKeyAlgorithm = 'rsa_encrypt';

	this.sessionKey = null;
	this.sessionKeyAlgorithm = 'aes256';

	/** @type {openpgp_type_mpi[]} */
	this.encrypted = [];

	/**
	 * Parsing function for a publickey encrypted session key packet (tag 1).
	 * 
	 * @param {String} input Payload of a tag 1 packet
	 * @param {Integer} position Position to start reading from the input string
	 * @param {Integer} len Length of the packet or the remaining length of
	 *            input at position
	 * @return {openpgp_packet_encrypteddata} Object representation
	 */
	this.read = function(bytes) {
		if (bytes.length < 10) {
			util.print_error("openpgp.packet.encryptedsessionkey.js\n" 
				+ 'invalid length');
			return null;
		}

		this.version = bytes[0].charCodeAt();
		this.public_key_id.read_packet(bytes, 1);
		this.public_key_algorithm = bytes[9].charCodeAt();

		var i = 10;

		switch (this.public_key_algorithm) {

		case openpgp.publickey.rsa_encrypt:
		case openpgp.publickey.rsa_encrypt_sign:
			this.encrypted = [];
			this.encrypted[0] = new openpgp_type_mpi();
			this.encrypted[0].read(bytes.substr(i));
			break;

		case openpgp.publickey.elgamal:
			this.encrypted = [];
			this.encrypted[0] = new openpgp_type_mpi();
			i += this.encrypted[0].read(bytes.substr(i));
			this.encrypted[1] = new openpgp_type_mpi();
			this.encrypted[1].read(bytes.substr(i));
			break;

		default:
			util.print_error("openpgp.packet.encryptedsessionkey.js\n"
					+ "unknown public key packet algorithm type "
					+ this.public_key_algorithm);
			break;
		}
	}

	/**
	 * Create a string representation of a tag 1 packet
	 * 
	 * @param {String} publicKeyId
	 *             The public key id corresponding to publicMPIs key as string
	 * @param {openpgp_type_mpi[]} publicMPIs
	 *            Multiprecision integer objects describing the public key
	 * @param {Integer} pubalgo
	 *            The corresponding public key algorithm // See RFC4880 9.1
	 * @param {Integer} symmalgo
	 *            The symmetric cipher algorithm used to encrypt the data 
	 *            within an encrypteddatapacket or encryptedintegrity-
	 *            protecteddatapacket 
	 *            following this packet //See RFC4880 9.2
	 * @param {String} sessionkey
	 *            A string of randombytes representing the session key
	 * @return {String} The string representation
	 */
	this.write = function() {

		var result = String.fromCharCode(this.version);
		result += this.public_key_id.bytes;
		result += String.fromCharCode(this.public_key_algorithm);

		for ( var i = 0; i < this.encrypted.length; i++) {
			result += this.encrypted[i].write()
		}

		return result;
	}

	this.encrypt = function(key) {
		
		var data = String.fromCharCode(this.symmetric_algorithm);
		data += this.symmetric_key;
		var checksum = util.calc_checksum(this.symmetric_key);
		data += String.fromCharCode((checksum >> 8) & 0xFF);
		data += String.fromCharCode((checksum) & 0xFF);

		var mpi = new openpgp_type_mpi();
		mpi.fromBytes(openpgp_encoding_eme_pkcs1_encode(
			data,
			key.mpi[0].byteLength()));

		this.encrypted = openpgp_crypto_asymetricEncrypt(
			this.public_key_algorithm, 
			key.mpi,
			mpi);
	}

	/**
	 * Decrypts the session key (only for public key encrypted session key
	 * packets (tag 1)
	 * 
	 * @param {openpgp_msg_message} msg
	 *            The message object (with member encryptedData
	 * @param {openpgp_msg_privatekey} key
	 *            Private key with secMPIs unlocked
	 * @return {String} The unencrypted session key
	 */
	this.decrypt = function(key) {
		var result = openpgp_crypto_asymetricDecrypt(
				this.public_key_algorithm,
				key.mpi,
				this.encrypted).toBytes();

		var checksum = ((result.charCodeAt(result.length - 2) << 8) 
			+ result.charCodeAt(result.length - 1));

		var decoded = openpgp_encoding_eme_pkcs1_decode(
			result,
			key.mpi[0].byteLength());

		var key = decoded.substring(1, decoded.length - 2);

		if(checksum != util.calc_checksum(key)) {
			util.print_error("Checksum mismatch");
		}
		else {
			this.symmetric_key = key;
			this.symmetric_algorithm = decoded.charCodeAt(0);
		}
	}
};


},{}],24:[function(require,module,exports){
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
 * @classdesc Public-Key Encrypted Session Key Packets (Tag 1)
 * 
 * RFC4880 5.1: A Public-Key Encrypted Session Key packet holds the session key
 * used to encrypt a message. Zero or more Public-Key Encrypted Session Key
 * packets and/or Symmetric-Key Encrypted Session Key packets may precede a
 * Symmetrically Encrypted Data Packet, which holds an encrypted message. The
 * message is encrypted with the session key, and the session key is itself
 * encrypted and stored in the Encrypted Session Key packet(s). The
 * Symmetrically Encrypted Data Packet is preceded by one Public-Key Encrypted
 * Session Key packet for each OpenPGP key to which the message is encrypted.
 * The recipient of the message finds a session key that is encrypted to their
 * public key, decrypts the session key, and then uses the session key to
 * decrypt the message.
 */
module.exports = function packet_sym_encrypted_session_key() {
	this.tag = 3;
	this.private_algorithm = null;
	this.algorithm = openpgp.symmetric.aes256;
	this.encrypted = null;
	this.s2k = new openpgp_type_s2k();

	/**
	 * Parsing function for a symmetric encrypted session key packet (tag 3).
	 * 
	 * @param {String} input Payload of a tag 1 packet
	 * @param {Integer} position Position to start reading from the input string
	 * @param {Integer} len
	 *            Length of the packet or the remaining length of
	 *            input at position
	 * @return {openpgp_packet_encrypteddata} Object representation
	 */
	this.read = function(bytes) {
		// A one-octet version number. The only currently defined version is 4.
		this.version = bytes[0].charCodeAt();

		// A one-octet number describing the symmetric algorithm used.
		var algo = bytes[1].charCodeAt();

		// A string-to-key (S2K) specifier, length as defined above.
		var s2klength = this.s2k.read(bytes.substr(2));

		// Optionally, the encrypted session key itself, which is decrypted
		// with the string-to-key object.
		var done = s2klength + 2;

		if(done < bytes.length) {
			this.encrypted = bytes.substr(done);
			this.private_algorithm = algo
		}
		else
			this.algorithm = algo;
	}

	this.write = function() {
		var algo = this.encrypted == null ? this.algorithm :
			this.private_algorithm;

		var bytes = String.fromCharCode(this.version) +
			String.fromCharCode(algo) +
			this.s2k.write();

		if(this.encrypted != null)
			bytes += this.encrypted;
		return bytes;
	}

	/**
	 * Decrypts the session key (only for public key encrypted session key
	 * packets (tag 1)
	 * 
	 * @param {openpgp_msg_message} msg
	 *            The message object (with member encryptedData
	 * @param {openpgp_msg_privatekey} key
	 *            Private key with secMPIs unlocked
	 * @return {String} The unencrypted session key
	 */
	this.decrypt = function(passphrase) {
		var algo = this.private_algorithm != null ?
			this.private_algorithm :
			this.algorithm

		var length = openpgp_crypto_getKeyLength(algo);
		var key = this.s2k.produce_key(passphrase, length);

		if(this.encrypted == null) {
			this.key = key;

		} else {
			var decrypted = openpgp_crypto_symmetricDecrypt(
				this.private_algorithm, key, this.encrypted, true);

			this.algorithm = decrypted[0].keyCodeAt();
			this.key = decrypted.substr(1);
		}
	}

	this.encrypt = function(passphrase) {
		var length = openpgp_crypto_getKeyLength(this.private_algorithm);
		var key = this.s2k.produce_key(passphrase, length);


		
		var private_key = String.fromCharCode(this.algorithm) +
			openpgp_crypto_getRandomBytes(
				openpgp_crypto_getKeyLength(this.algorithm));

		this.encrypted = openpgp_crypto_symmetricEncrypt(
				openpgp_crypto_getPrefixRandom(this.private_algorithm), 
				this.private_algorithm, key, private_key, true);
	}
};


},{}],27:[function(require,module,exports){
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
 * @classdesc Implementation of the Symmetrically Encrypted Data Packet (Tag 9)
 * 
 * RFC4880 5.7: The Symmetrically Encrypted Data packet contains data encrypted
 * with a symmetric-key algorithm. When it has been decrypted, it contains other
 * packets (usually a literal data packet or compressed data packet, but in
 * theory other Symmetrically Encrypted Data packets or sequences of packets
 * that form whole OpenPGP messages).
 */

module.exports = function packet_symmetrically_encrypted() {
	this.encrypted = null;
	/** Decrypted packets contained within. 
	 * @type {openpgp_packetlist} */
	this.packets;

	

	this.read = function(bytes) {
		this.encrypted = bytes;
	}

	this.write = function() {
		return this.encrypted;
	}

	/**
	 * Symmetrically decrypt the packet data
	 * 
	 * @param {Integer} symmetric_algorithm_type
	 *             Symmetric key algorithm to use // See RFC4880 9.2
	 * @param {String} key
	 *             Key as string with the corresponding length to the
	 *            algorithm
	 * @return The decrypted data;
	 */
	this.decrypt = function(symmetric_algorithm_type, key) {
		var decrypted = openpgp_crypto_symmetricDecrypt(
				symmetric_algorithm_type, key, this.encrypted, true);

		this.packets.read(decrypted);
	}

	this.encrypt = function(algo, key) {
		var data = this.packets.write();

		this.encrypted = openpgp_crypto_symmetricEncrypt(
				openpgp_crypto_getPrefixRandom(algo), algo, key, data, true);
	}
};

},{}],26:[function(require,module,exports){
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
 * @classdesc Implementation of the Key Material Packet (Tag 5,6,7,14)
 *   
 * RFC4480 5.5:
 * A key material packet contains all the information about a public or
 * private key.  There are four variants of this packet type, and two
 * major versions.  Consequently, this section is complex.
 */
module.exports = function packet_public_key() {
	/** Key creation date.
	 * @type {Date} */
	this.created = new Date();
	/** A list of multiprecision integers
	 * @type {openpgp_type_mpi} */
	this.mpi = [];
	/** Public key algorithm
	 * @type {openpgp.publickey} */
	this.algorithm = 'rsa_sign';


	/**
	 * Internal Parser for public keys as specified in RFC 4880 section 
	 * 5.5.2 Public-Key Packet Formats
	 * called by read_tag&lt;num&gt;
	 * @param {String} input Input string to read the packet from
	 * @param {Integer} position Start position for the parser
	 * @param {Integer} len Length of the packet or remaining length of input
	 * @return {Object} This object with attributes set by the parser
	 */  
	this.readPublicKey = this.read = function(bytes) {
		// A one-octet version number (3 or 4).
		var version = bytes[0].charCodeAt();

		if (version == 4) {
			// - A four-octet number denoting the time that the key was created.
			this.created = openpgp_packet_time_read(bytes.substr(1, 4));
			
			// - A one-octet number denoting the public-key algorithm of this key.
			this.algorithm = bytes[5].charCodeAt();

			var mpicount = openpgp_crypto_getPublicMpiCount(this.algorithm);
			this.mpi = [];

			var bmpi = bytes.substr(6);
			var p = 0;

			for (var i = 0; 
				i < mpicount && p < bmpi.length; 
				i++) {

				this.mpi[i] = new openpgp_type_mpi();

				p += this.mpi[i].read(bmpi.substr(p))

				if(p > bmpi.length)
					util.print_error("openpgp.packet.keymaterial.js\n"
						+'error reading MPI @:'+p);
			}

			return p + 6;
		} else {
			throw new Error('Version ' + version + ' of the key packet is unsupported.');
		}
	}

	/*
     * Same as write_private_key, but has less information because of 
	 * public key.
     * @param {Integer} keyType Follows the OpenPGP algorithm standard, 
	 * IE 1 corresponds to RSA.
     * @param {RSA.keyObject} key
     * @param timePacket
     * @return {Object} {body: [string]OpenPGP packet body contents, 
	 * header: [string] OpenPGP packet header, string: [string] header+body}
     */
    this.writePublicKey = this.write = function() {
		// Version
		var result = String.fromCharCode(4);
        result += openpgp_packet_time_write(this.created);
		result += String.fromCharCode(this.algorithm);

		var mpicount = openpgp_crypto_getPublicMpiCount(this.algorithm);

		for(var i = 0; i < mpicount; i++) {
			result += this.mpi[i].write();
		}

		return result;
	}

	// Write an old version packet - it's used by some of the internal routines.
	this.writeOld = function() {
		var bytes = this.writePublicKey();

		return String.fromCharCode(0x99) +
			openpgp_packet_number_write(bytes.length, 2) +
			bytes;
	}

	/**
	 * Calculates the key id of the key 
	 * @return {String} A 8 byte key id
	 */
	this.getKeyId = function() {
		return this.getFingerprint().substr(12, 8);
	}
	
	/**
	 * Calculates the fingerprint of the key
	 * @return {String} A string containing the fingerprint
	 */
	this.getFingerprint = function() {
		var toHash = this.writeOld();
		return str_sha1(toHash, toHash.length);
	}

}

},{}],28:[function(require,module,exports){
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
 * @classdesc Implementation of the strange "Marker packet" (Tag 10)
 * 
 * RFC4880 5.8: An experimental version of PGP used this packet as the Literal
 * packet, but no released version of PGP generated Literal packets with this
 * tag. With PGP 5.x, this packet has been reassigned and is reserved for use as
 * the Marker packet.
 * 
 * Such a packet MUST be ignored when received.
 */
function packet_marker() {
	/**
	 * Parsing function for a literal data packet (tag 10).
	 * 
	 * @param {String} input Payload of a tag 10 packet
	 * @param {Integer} position
	 *            Position to start reading from the input string
	 * @param {Integer} len
	 *            Length of the packet or the remaining length of
	 *            input at position
	 * @return {openpgp_packet_encrypteddata} Object representation
	 */
	this.read = function(bytes) {
		if (bytes[0].charCodeAt() == 0x50 && // P
				bytes[1].charCodeAt() == 0x47 && // G
				bytes[2].charCodeAt() == 0x50) // P
			return true;
		// marker packet does not contain "PGP"
		return false;
	}
}

module.exports = packet_marker;

},{}],30:[function(require,module,exports){
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
 * @classdesc Implementation of the User Attribute Packet (Tag 17)
 *  The User Attribute packet is a variation of the User ID packet.  It
 *  is capable of storing more types of data than the User ID packet,
 *  which is limited to text.  Like the User ID packet, a User Attribute
 *  packet may be certified by the key owner ("self-signed") or any other
 *  key owner who cares to certify it.  Except as noted, a User Attribute
 *  packet may be used anywhere that a User ID packet may be used.
 *
 *  While User Attribute packets are not a required part of the OpenPGP
 *  standard, implementations SHOULD provide at least enough
 *  compatibility to properly handle a certification signature on the
 *  User Attribute packet.  A simple way to do this is by treating the
 *  User Attribute packet as a User ID packet with opaque contents, but
 *  an implementation may use any method desired.
 */
module.exports = function packet_user_attribute() {
	this.tag = 17;
	this.attributes = [];

	/**
	 * parsing function for a user attribute packet (tag 17).
	 * @param {String} input payload of a tag 17 packet
	 * @param {Integer} position position to start reading from the input string
	 * @param {Integer} len length of the packet or the remaining length of input at position
	 * @return {openpgp_packet_encrypteddata} object representation
	 */
	this.read = function(bytes) {
		var i = 0;
		while(i < bytes.length) {
			var len = openpgp_packet.read_simple_length(bytes);

			i += len.offset;
			this.attributes.push(bytes.substr(i, len.len));
			i += len.len;
		}
	}
};

},{}],36:[function(require,module,exports){

module.exports = function packet_trust() {

};

},{}],17:[function(require,module,exports){

module.exports = {
	aes: require('./aes.js'),
	des: require('./des.js'),
	cast5: require('./cast5.js'),
	twofish: require('./twofish.js'),
	blowfish: require('./blowfish.js')
}


},{"./aes.js":38,"./des.js":39,"./cast5.js":40,"./twofish.js":41,"./blowfish.js":42}],18:[function(require,module,exports){

var sha = require('./sha.js');

module.exports = {
	md5: require('./md5.js'),
	sha1: sha.sha1,
	sha256: sha.sha256,
	sha224: sha.sha224,
	sha384: sha.sha384,
	sha512: sha.sha512,
	ripemd: require('./ripe-md.js'),

	/**
	 * Create a hash on the specified data using the specified algorithm
	 * @param {Integer} algo Hash algorithm type (see RFC4880 9.4)
	 * @param {String} data Data to be hashed
	 * @return {String} hash value
	 */
	digest: function(algo, data) {
		switch(algo) {
		case 1: // - MD5 [HAC]
			return this.md5(data);
		case 2: // - SHA-1 [FIPS180]
			return this.sha1(data);
		case 3: // - RIPE-MD/160 [HAC]
			return this.ripemd(data);
		case 8: // - SHA256 [FIPS180]
			return this.sha256(data);
		case 9: // - SHA384 [FIPS180]
			return this.sha384(data);
		case 10:// - SHA512 [FIPS180]
			return this.sha512(data);
		case 11:// - SHA224 [FIPS180]
			return this.sha224(data);
		default:
			throw new Error('Invalid hash function.');
		}
	},

	/**
	 * Returns the hash size in bytes of the specified hash algorithm type
	 * @param {Integer} algo Hash algorithm type (See RFC4880 9.4)
	 * @return {Integer} Size in bytes of the resulting hash
	 */
	getHashByteLength: function(algo) {
		switch(algo) {
		case 1: // - MD5 [HAC]
			return 16;
		case 2: // - SHA-1 [FIPS180]
		case 3: // - RIPE-MD/160 [HAC]
			return 20;
		case 8: // - SHA256 [FIPS180]
			return 32;
		case 9: // - SHA384 [FIPS180]
			return 48
		case 10:// - SHA512 [FIPS180]
			return 64;
		case 11:// - SHA224 [FIPS180]
			return 28;
		default:
			throw new Error('Invalid hash algorithm.');
		}
	}

}


},{"./sha.js":43,"./md5.js":44,"./ripe-md.js":45}],14:[function(require,module,exports){
(function(){// Modified by Recurity Labs GmbH 

// modified version of http://www.hanewin.net/encrypt/PGdecode.js:

/* OpenPGP encryption using RSA/AES
 * Copyright 2005-2006 Herbert Hanewinkel, www.haneWIN.de
 * version 2.0, check www.haneWIN.de for the latest version

 * This software is provided as-is, without express or implied warranty.  
 * Permission to use, copy, modify, distribute or sell this software, with or
 * without fee, for any purpose and by any individual or organization, is hereby
 * granted, provided that the above copyright notice and this paragraph appear 
 * in all copies. Distribution as a part of an application or binary must
 * include the above copyright notice in the documentation and/or other
 * materials provided with the application or distribution.
 */

var util = require('../util');

module.exports = {

	/**
	 * An array of bytes, that is integers with values from 0 to 255
	 * @typedef {(Array|Uint8Array)} openpgp_byte_array
	 */

	/**
	 * Block cipher function
	 * @callback openpgp_cipher_block_fn
	 * @param {openpgp_byte_array} block A block to perform operations on
	 * @param {openpgp_byte_array} key to use in encryption/decryption
	 * @return {openpgp_byte_array} Encrypted/decrypted block
	 */


	// --------------------------------------
	/**
	 * This function encrypts a given with the specified prefixrandom 
	 * using the specified blockcipher to encrypt a message
	 * @param {String} prefixrandom random bytes of block_size length provided 
	 *  as a string to be used in prefixing the data
	 * @param {openpgp_cipher_block_fn} blockcipherfn the algorithm encrypt function to encrypt
	 *  data in one block_size encryption. 
	 * @param {Integer} block_size the block size in bytes of the algorithm used
	 * @param {String} plaintext data to be encrypted provided as a string
	 * @param {openpgp_byte_array} key key to be used to encrypt the data. This will be passed to the 
	 *  blockcipherfn
	 * @param {Boolean} resync a boolean value specifying if a resync of the 
	 *  IV should be used or not. The encrypteddatapacket uses the 
	 *  "old" style with a resync. Encryption within an 
	 *  encryptedintegrityprotecteddata packet is not resyncing the IV.
	 * @return {String} a string with the encrypted data
	 */
	encrypt: function (prefixrandom, blockcipherencryptfn, plaintext, block_size, key, resync) {
		var FR = new Array(block_size);
		var FRE = new Array(block_size);

		prefixrandom = prefixrandom + prefixrandom.charAt(block_size-2) +prefixrandom.charAt(block_size-1);
		util.print_debug("prefixrandom:"+util.hexstrdump(prefixrandom));
		var ciphertext = "";
		// 1.  The feedback register (FR) is set to the IV, which is all zeros.
		for (var i = 0; i < block_size; i++) FR[i] = 0;
		
		// 2.  FR is encrypted to produce FRE (FR Encrypted).  This is the
		//     encryption of an all-zero value.
		FRE = blockcipherencryptfn(FR, key);
		// 3.  FRE is xored with the first BS octets of random data prefixed to
		//     the plaintext to produce C[1] through C[BS], the first BS octets
		//     of ciphertext.
		for (var i = 0; i < block_size; i++) ciphertext += String.fromCharCode(FRE[i] ^ prefixrandom.charCodeAt(i));
		
		// 4.  FR is loaded with C[1] through C[BS].
		for (var i = 0; i < block_size; i++) FR[i] = ciphertext.charCodeAt(i);
		
		// 5.  FR is encrypted to produce FRE, the encryption of the first BS
		// 	   octets of ciphertext.
		FRE = blockcipherencryptfn(FR, key);

		// 6.  The left two octets of FRE get xored with the next two octets of
		//     data that were prefixed to the plaintext.  This produces C[BS+1]
		//     and C[BS+2], the next two octets of ciphertext.
		ciphertext += String.fromCharCode(FRE[0] ^ prefixrandom.charCodeAt(block_size));
		ciphertext += String.fromCharCode(FRE[1] ^ prefixrandom.charCodeAt(block_size+1));

		if (resync) {
			// 7.  (The resync step) FR is loaded with C3-C10.
			for (var i = 0; i < block_size; i++) FR[i] = ciphertext.charCodeAt(i+2);
		} else {
			for (var i = 0; i < block_size; i++) FR[i] = ciphertext.charCodeAt(i);
		}
		// 8.  FR is encrypted to produce FRE.
		FRE = blockcipherencryptfn(FR, key);
		
		if (resync) {
			// 9.  FRE is xored with the first 8 octets of the given plaintext, now
			//	   that we have finished encrypting the 10 octets of prefixed data.
			// 	   This produces C11-C18, the next 8 octets of ciphertext.
			for (var i = 0; i < block_size; i++)
				ciphertext += String.fromCharCode(FRE[i] ^ plaintext.charCodeAt(i));
			for(n=block_size+2; n < plaintext.length; n+=block_size) {
				// 10. FR is loaded with C11-C18
				for (var i = 0; i < block_size; i++) FR[i] = ciphertext.charCodeAt(n+i);
			
				// 11. FR is encrypted to produce FRE.
				FRE = blockcipherencryptfn(FR, key);
			
				// 12. FRE is xored with the next 8 octets of plaintext, to produce the
				// next 8 octets of ciphertext.  These are loaded into FR and the
				// process is repeated until the plaintext is used up.
				for (var i = 0; i < block_size; i++) ciphertext += String.fromCharCode(FRE[i] ^ plaintext.charCodeAt((n-2)+i));
			}
		}
		else {
			plaintext = "  "+plaintext;
			// 9.  FRE is xored with the first 8 octets of the given plaintext, now
			//	   that we have finished encrypting the 10 octets of prefixed data.
			// 	   This produces C11-C18, the next 8 octets of ciphertext.
			for (var i = 2; i < block_size; i++) ciphertext += String.fromCharCode(FRE[i] ^ plaintext.charCodeAt(i));
			var tempCiphertext = ciphertext.substring(0,2*block_size).split('');
			var tempCiphertextString = ciphertext.substring(block_size);
			for(n=block_size; n<plaintext.length; n+=block_size) {
				// 10. FR is loaded with C11-C18
				for (var i = 0; i < block_size; i++) FR[i] = tempCiphertextString.charCodeAt(i);
				tempCiphertextString='';
				
				// 11. FR is encrypted to produce FRE.
				FRE = blockcipherencryptfn(FR, key);
				
				// 12. FRE is xored with the next 8 octets of plaintext, to produce the
				//     next 8 octets of ciphertext.  These are loaded into FR and the
				//     process is repeated until the plaintext is used up.
				for (var i = 0; i < block_size; i++){ tempCiphertext.push(String.fromCharCode(FRE[i] ^ plaintext.charCodeAt(n+i)));
				tempCiphertextString += String.fromCharCode(FRE[i] ^ plaintext.charCodeAt(n+i));
				}
			}
			ciphertext = tempCiphertext.join('');
			
		}
		return ciphertext;
	},

	/**
	 * Decrypts the prefixed data for the Modification Detection Code (MDC) computation
	 * @param {openpgp_block_cipher_fn} blockcipherencryptfn Cipher function to use
	 * @param {Integer} block_size Blocksize of the algorithm
	 * @param {openpgp_byte_array} key The key for encryption
	 * @param {String} ciphertext The encrypted data
	 * @return {String} plaintext Data of D(ciphertext) with blocksize length +2
	 */
	mdc: function (blockcipherencryptfn, block_size, key, ciphertext) {
		var iblock = new Array(block_size);
		var ablock = new Array(block_size);
		var i;

		// initialisation vector
		for(i=0; i < block_size; i++) iblock[i] = 0;

		iblock = blockcipherencryptfn(iblock, key);
		for(i = 0; i < block_size; i++)
		{
			ablock[i] = ciphertext.charCodeAt(i);
			iblock[i] ^= ablock[i];
		}

		ablock = blockcipherencryptfn(ablock, key);

		return util.bin2str(iblock)+
			String.fromCharCode(ablock[0]^ciphertext.charCodeAt(block_size))+
			String.fromCharCode(ablock[1]^ciphertext.charCodeAt(block_size+1));
	},
	/**
	 * This function decrypts a given plaintext using the specified
	 * blockcipher to decrypt a message
	 * @param {openpgp_cipher_block_fn} blockcipherfn The algorithm _encrypt_ function to encrypt
	 *  data in one block_size encryption.
	 * @param {Integer} block_size the block size in bytes of the algorithm used
	 * @param {String} plaintext ciphertext to be decrypted provided as a string
	 * @param {openpgp_byte_array} key key to be used to decrypt the ciphertext. This will be passed to the 
	 *  blockcipherfn
	 * @param {Boolean} resync a boolean value specifying if a resync of the 
	 *  IV should be used or not. The encrypteddatapacket uses the 
	 *  "old" style with a resync. Decryption within an 
	 *  encryptedintegrityprotecteddata packet is not resyncing the IV.
	 * @return {String} a string with the plaintext data
	 */

	decrypt: function (blockcipherencryptfn, block_size, key, ciphertext, resync)
	{
		util.print_debug("resync:"+resync);
		var iblock = new Array(block_size);
		var ablock = new Array(block_size);
		var i, n = '';
		var text = [];

		// initialisation vector
		for(i=0; i < block_size; i++) iblock[i] = 0;

		iblock = blockcipherencryptfn(iblock, key);
		for(i = 0; i < block_size; i++)
		{
			ablock[i] = ciphertext.charCodeAt(i);
			iblock[i] ^= ablock[i];
		}

		ablock = blockcipherencryptfn(ablock, key);

		util.print_debug("openpgp_cfb_decrypt:\niblock:"+util.hexidump(iblock)+"\nablock:"+util.hexidump(ablock)+"\n");
		util.print_debug((ablock[0]^ciphertext.charCodeAt(block_size)).toString(16)+(ablock[1]^ciphertext.charCodeAt(block_size+1)).toString(16));
		
		// test check octets
		if(iblock[block_size-2]!=(ablock[0]^ciphertext.charCodeAt(block_size))
		|| iblock[block_size-1]!=(ablock[1]^ciphertext.charCodeAt(block_size+1)))
		{
			util.print_eror("error duding decryption. Symmectric encrypted data not valid.");
			return text.join('');
		}
		
		/*  RFC4880: Tag 18 and Resync:
		 *  [...] Unlike the Symmetrically Encrypted Data Packet, no
		 *  special CFB resynchronization is done after encrypting this prefix
		 *  data.  See "OpenPGP CFB Mode" below for more details.

		 */
		
		if (resync) {
			for(i=0; i<block_size; i++) iblock[i] = ciphertext.charCodeAt(i+2);
			for(n=block_size+2; n<ciphertext.length; n+=block_size)
			{
				ablock = blockcipherencryptfn(iblock, key);

				for(i = 0; i<block_size && i+n < ciphertext.length; i++)
				{
					iblock[i] = ciphertext.charCodeAt(n+i);
					text.push(String.fromCharCode(ablock[i]^iblock[i])); 
				}
			}
		} else {
			for(i=0; i<block_size; i++) iblock[i] = ciphertext.charCodeAt(i);
			for(n=block_size; n<ciphertext.length; n+=block_size)
			{
				ablock = blockcipherencryptfn(iblock, key);
				for(i = 0; i<block_size && i+n < ciphertext.length; i++)
				{
					iblock[i] = ciphertext.charCodeAt(n+i);
					text.push(String.fromCharCode(ablock[i]^iblock[i])); 
				}
			}
		}
		
		return text.join('');
	},


	normalEncrypt: function(blockcipherencryptfn, block_size, key, plaintext, iv) {
		var blocki ="";
		var blockc = "";
		var pos = 0;
		var cyphertext = [];
		var tempBlock = [];
		blockc = iv.substring(0,block_size);
		while (plaintext.length > block_size*pos) {
			var encblock = blockcipherencryptfn(blockc, key);
			blocki = plaintext.substring((pos*block_size),(pos*block_size)+block_size);
			for (var i=0; i < blocki.length; i++)
				tempBlock.push(String.fromCharCode(blocki.charCodeAt(i) ^ encblock[i]));
			blockc = tempBlock.join('');
			tempBlock = [];
			cyphertext.push(blockc);
			pos++;
		}
		return cyphertext.join('');
	},

	normalDecrypt: function(blockcipherencryptfn, block_size, key, ciphertext, iv) { 
		var blockp ="";
		var pos = 0;
		var plaintext = [];
		var offset = 0;
		if (iv == null)
			for (var i = 0; i < block_size; i++) blockp += String.fromCharCode(0);
		else
			blockp = iv.substring(0,block_size);
		while (ciphertext.length > (block_size*pos)) {
			var decblock = blockcipherencryptfn(blockp, key);
			blockp = ciphertext.substring((pos*(block_size))+offset,(pos*(block_size))+(block_size)+offset);
			for (var i=0; i < blockp.length; i++) {
				plaintext.push(String.fromCharCode(blockp.charCodeAt(i) ^ decblock[i]));
			}
			pos++;
		}
		
		return plaintext.join('');
	}
}

})()
},{"../util":7}],19:[function(require,module,exports){

module.exports = {
	rsa: require('./rsa.js'),
	elgamal: require('./elgamal.js'),
	dsa: require('./dsa.js')
}


},{"./rsa.js":46,"./elgamal.js":47,"./dsa.js":48}],15:[function(require,module,exports){

var publicKey = require('./public_key'),
	pkcs1 = require('./pkcs1.js'),
	hashModule = require('./hash');

module.exports = {
	/**
	 * 
	 * @param {Integer} algo public Key algorithm
	 * @param {Integer} hash_algo Hash algorithm
	 * @param {openpgp_type_mpi[]} msg_MPIs Signature multiprecision integers
	 * @param {openpgp_type_mpi[]} publickey_MPIs Public key multiprecision integers 
	 * @param {String} data Data on where the signature was computed on.
	 * @return {Boolean} true if signature (sig_data was equal to data over hash)
	 */
	verify: function(algo, hash_algo, msg_MPIs, publickey_MPIs, data) {
		var calc_hash = hashModule.digest(hash_algo, data);

		switch(algo) {
		case 1: // RSA (Encrypt or Sign) [HAC]  
		case 2: // RSA Encrypt-Only [HAC]
		case 3: // RSA Sign-Only [HAC]
			var rsa = new publicKey.rsa();
			var n = publickey_MPIs[0].toBigInteger();
			var e = publickey_MPIs[1].toBigInteger();
			var x = msg_MPIs[0].toBigInteger();
			var dopublic = rsa.verify(x,e,n);
			var hash  = pkcs1.emsa.decode(hash_algo,dopublic.toMPI().substring(2));
			if (hash == -1) {
				throw new Error('PKCS1 padding in message or key incorrect. Aborting...');
			}
			return hash == calc_hash;
			
		case 16: // Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
			throw new Error("signing with Elgamal is not defined in the OpenPGP standard.");
		case 17: // DSA (Digital Signature Algorithm) [FIPS186] [HAC]
			var dsa = new publicKey.dsa();
			var s1 = msg_MPIs[0].toBigInteger();
			var s2 = msg_MPIs[1].toBigInteger();
			var p = publickey_MPIs[0].toBigInteger();
			var q = publickey_MPIs[1].toBigInteger();
			var g = publickey_MPIs[2].toBigInteger();
			var y = publickey_MPIs[3].toBigInteger();
			var m = data;
			var dopublic = dsa.verify(hash_algo,s1,s2,m,p,q,g,y);
			return dopublic.compareTo(s1) == 0;
		default:
			throw new Error('Invalid signature algorithm.');
		}
		
	},
	   
	/**
	 * Create a signature on data using the specified algorithm
	 * @param {Integer} hash_algo hash Algorithm to use (See RFC4880 9.4)
	 * @param {Integer} algo Asymmetric cipher algorithm to use (See RFC4880 9.1)
	 * @param {openpgp_type_mpi[]} publicMPIs Public key multiprecision integers 
	 * of the private key 
	 * @param {openpgp_type_mpi[]} secretMPIs Private key multiprecision 
	 * integers which is used to sign the data
	 * @param {String} data Data to be signed
	 * @return {openpgp_type_mpi[]}
	 */
	sign: function(hash_algo, algo, keyIntegers, data) {
		
		switch(algo) {
		case 1: // RSA (Encrypt or Sign) [HAC]  
		case 2: // RSA Encrypt-Only [HAC]
		case 3: // RSA Sign-Only [HAC]
			var rsa = new publicKey.rsa();
			var d = keyIntegers[2].toBigInteger();
			var n = keyIntegers[0].toBigInteger();
			var m = pkcs1.emsa.encode(hash_algo, 
				data, keyIntegers[0].byteLength());

			return rsa.sign(m, d, n).toMPI();

		case 17: // DSA (Digital Signature Algorithm) [FIPS186] [HAC]
			var dsa = new publicKey.dsa();

			var p = keyIntegers[0].toBigInteger();
			var q = keyIntegers[1].toBigInteger();
			var g = keyIntegers[2].toBigInteger();
			var y = keyIntegers[3].toBigInteger();
			var x = keyIntegers[4].toBigInteger();
			var m = data;
			var result = dsa.sign(hash_algo,m, g, p, q, x);

			return result[0].toString() + result[1].toString();
		case 16: // Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
			throw new Error('Signing with Elgamal is not defined in the OpenPGP standard.');
		default:
			throw new Error('Invalid signature algorithm.');
		}	
	}
}

},{"./pkcs1.js":49,"./public_key":19,"./hash":18}],16:[function(require,module,exports){
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

// The GPG4Browsers crypto interface

var random = require('./random.js'),
	publicKey= require('./public_key'),
	type_mpi = require('../type/mpi.js');

module.exports = {
/**
 * Encrypts data using the specified public key multiprecision integers 
 * and the specified algorithm.
 * @param {Integer} algo Algorithm to be used (See RFC4880 9.1)
 * @param {openpgp_type_mpi[]} publicMPIs Algorithm dependent multiprecision integers
 * @param {openpgp_type_mpi} data Data to be encrypted as MPI
 * @return {openpgp_type_mpi[]} if RSA an openpgp_type_mpi; 
 * if elgamal encryption an array of two openpgp_type_mpi is returned; otherwise null
 */
publicKeyEncrypt: function(algo, publicMPIs, data) {
	var result = (function() {
		switch(algo) {
		case 1: // RSA (Encrypt or Sign) [HAC]
		case 2: // RSA Encrypt-Only [HAC]
		case 3: // RSA Sign-Only [HAC]
			var rsa = new publicKey.rsa();
			var n = publicMPIs[0].toBigInteger();
			var e = publicMPIs[1].toBigInteger();
			var m = data.toBigInteger();
			return [rsa.encrypt(m,e,n)];
		case 16: // Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
			var elgamal = new publicKey.elgamal();
			var p = publicMPIs[0].toBigInteger();
			var g = publicMPIs[1].toBigInteger();
			var y = publicMPIs[2].toBigInteger();
			var m = data.toBigInteger();
			return elgamal.encrypt(m,g,p,y);
		default:
			return [];
		}
	})();

	return result.map(function(bn) {
		var mpi = new type_mpi();
		mpi.fromBigInteger(bn);
		return mpi;
	});
},

/**
 * Decrypts data using the specified public key multiprecision integers of the private key,
 * the specified secretMPIs of the private key and the specified algorithm.
 * @param {Integer} algo Algorithm to be used (See RFC4880 9.1)
 * @param {openpgp_type_mpi[]} publicMPIs Algorithm dependent multiprecision integers 
 * of the public key part of the private key
 * @param {openpgp_type_mpi[]} secretMPIs Algorithm dependent multiprecision integers 
 * of the private key used
 * @param {openpgp_type_mpi} data Data to be encrypted as MPI
 * @return {openpgp_type_mpi} returns a big integer containing the decrypted data; otherwise null
 */

publicKeyDecrypt: function (algo, keyIntegers, dataIntegers) {
	var bn = (function() {
		switch(algo) {
		case 1: // RSA (Encrypt or Sign) [HAC]  
		case 2: // RSA Encrypt-Only [HAC]
		case 3: // RSA Sign-Only [HAC]
			var rsa = new publicKey.rsa();
			// 0 and 1 are the public key.
			var d = keyIntegers[2].toBigInteger();
			var p = keyIntegers[3].toBigInteger();
			var q = keyIntegers[4].toBigInteger();
			var u = keyIntegers[5].toBigInteger();
			var m = dataIntegers[0].toBigInteger();
			return rsa.decrypt(m, d, p, q, u);
		case 16: // Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
			var elgamal = new publicKey.elgamal();
			var x = keyIntegers[3].toBigInteger();
			var c1 = dataIntegers[0].toBigInteger();
			var c2 = dataIntegers[1].toBigInteger();
			var p = keyIntegers[0].toBigInteger();
			return elgamal.decrypt(c1,c2,p,x);
		default:
			return null;
		}
	})();

	var result = new type_mpi();
	result.fromBigInteger(bn);
	return result;
},

/** Returns the number of integers comprising the private key of an algorithm
 * @param {openpgp.publickey} algo The public key algorithm
 * @return {Integer} The number of integers.
 */
getPrivateMpiCount: function(algo) {
	if (algo > 0 && algo < 4) {
		//   Algorithm-Specific Fields for RSA secret keys:
		//   - multiprecision integer (MPI) of RSA secret exponent d.
		//   - MPI of RSA secret prime value p.
		//   - MPI of RSA secret prime value q (p < q).
		//   - MPI of u, the multiplicative inverse of p, mod q.
		return 4;
	} else if (algo == 16) {
		// Algorithm-Specific Fields for Elgamal secret keys:
		//   - MPI of Elgamal secret exponent x.
		return 1;
	} else if (algo == 17) {
		// Algorithm-Specific Fields for DSA secret keys:
		//   - MPI of DSA secret exponent x.
		return 1;
	}
	else return 0;
},
	
getPublicMpiCount: function(algorithm) {
	// - A series of multiprecision integers comprising the key material:
	//   Algorithm-Specific Fields for RSA public keys:
	//       - a multiprecision integer (MPI) of RSA public modulus n;
	//       - an MPI of RSA public encryption exponent e.
	if (algorithm > 0 && algorithm < 4)
		return 2;

	//   Algorithm-Specific Fields for Elgamal public keys:
	//     - MPI of Elgamal prime p;
	//     - MPI of Elgamal group generator g;
	//     - MPI of Elgamal public key value y (= g**x mod p where x  is secret).
	else if (algorithm == 16)
		return 3;

	//   Algorithm-Specific Fields for DSA public keys:
	//       - MPI of DSA prime p;
	//       - MPI of DSA group order q (q is a prime divisor of p-1);
	//       - MPI of DSA group generator g;
	//       - MPI of DSA public-key value y (= g**x mod p where x  is secret).
	else if (algorithm == 17)
		return 4;
	else
		return 0;
},


/**
 * generate random byte prefix as string for the specified algorithm
 * @param {Integer} algo Algorithm to use (see RFC4880 9.2)
 * @return {String} Random bytes with length equal to the block
 * size of the cipher
 */
getPrefixRandom: function(algo) {
	switch(algo) {
	case 2:
	case 3:
	case 4:
		return random.getRandomBytes(8);
	case 7:
	case 8:
	case 9:
	case 10:
		return random.getRandomBytes(16);
	default:
		return null;
	}
},

/**
 * retrieve the MDC prefixed bytes by decrypting them
 * @param {Integer} algo Algorithm to use (see RFC4880 9.2)
 * @param {String} key Key as string. length is depending on the algorithm used
 * @param {String} data Encrypted data where the prefix is decrypted from
 * @return {String} Plain text data of the prefixed data
 */
MDCSystemBytes: function(algo, key, data) {
	switch(algo) {
	case 0: // Plaintext or unencrypted data
		return data;
	case 2: // TripleDES (DES-EDE, [SCHNEIER] [HAC] - 168 bit key derived from 192)
		return openpgp_cfb_mdc(desede, 8, key, data, openpgp_cfb);
	case 3: // CAST5 (128 bit key, as per [RFC2144])
		return openpgp_cfb_mdc(cast5_encrypt, 8, key, data);
	case 4: // Blowfish (128 bit key, 16 rounds) [BLOWFISH]
		return openpgp_cfb_mdc(BFencrypt, 8, key, data);
	case 7: // AES with 128-bit key [AES]
	case 8: // AES with 192-bit key
	case 9: // AES with 256-bit key
		return openpgp_cfb_mdc(AESencrypt, 16, keyExpansion(key), data);
	case 10: 
		return openpgp_cfb_mdc(TFencrypt, 16, key, data);
	case 1: // IDEA [IDEA]
		throw new Error('IDEA Algorithm not implemented');
	default:
		throw new Error('Invalid algorithm.');
	}
},
/**
 * Generating a session key for the specified symmetric algorithm
 * @param {Integer} algo Algorithm to use (see RFC4880 9.2)
 * @return {String} Random bytes as a string to be used as a key
 */
generateSessionKey: function(algo) {
	return random.getRandomBytes(this.getKeyLength(algo)); 
},

/**
 * Get the key length by symmetric algorithm id.
 * @param {Integer} algo Algorithm to use (see RFC4880 9.2)
 * @return {String} Random bytes as a string to be used as a key
 */
getKeyLength: function(algo) {
	switch (algo) {
	case 2: // TripleDES (DES-EDE, [SCHNEIER] [HAC] - 168 bit key derived from 192)
	case 8: // AES with 192-bit key
		return 24;
	case 3: // CAST5 (128 bit key, as per [RFC2144])
	case 4: // Blowfish (128 bit key, 16 rounds) [BLOWFISH]
	case 7: // AES with 128-bit key [AES]
		return 16;
	case 9: // AES with 256-bit key
	case 10:// Twofish with 256-bit key [TWOFISH]
		return 32;
	}
	return null;
},

/**
 * Returns the block length of the specified symmetric encryption algorithm
 * @param {openpgp.symmetric} algo Symmetric algorithm idenhifier
 * @return {Integer} The number of bytes in a single block encrypted by the algorithm
 */
getBlockLength: function(algo) {
	switch (algo) {
	case  1: // - IDEA [IDEA]
	case  2: // - TripleDES (DES-EDE, [SCHNEIER] [HAC] - 168 bit key derived from 192)
	case  3: // - CAST5 (128 bit key, as per [RFC2144])
		return 8;
	case  4: // - Blowfish (128 bit key, 16 rounds) [BLOWFISH]
	case  7: // - AES with 128-bit key [AES]
	case  8: // - AES with 192-bit key
	case  9: // - AES with 256-bit key
		return 16;
	case 10: // - Twofish with 256-bit key [TWOFISH]
		return 32;	    		
	default:
		return 0;
	}
},

/**
 * Create a secure random big integer of bits length
 * @param {Integer} bits Bit length of the MPI to create
 * @return {BigInteger} Resulting big integer
 */
getRandomBigInteger: function(bits) {
	if (bits < 0)
	   return null;
	var numBytes = Math.floor((bits+7)/8);

	var randomBits = random.getRandomBytes(numBytes);
	if (bits % 8 > 0) {
		
		randomBits = String.fromCharCode(
						(Math.pow(2,bits % 8)-1) &
						randomBits.charCodeAt(0)) +
			randomBits.substring(1);
	}
	return new openpgp_type_mpi().create(randomBits).toBigInteger();
},

getRandomBigIntegerInRange: function(min, max) {
	if (max.compareTo(min) <= 0)
		return;
	var range = max.subtract(min);
	var r = openpgp_crypto_getRandomBigInteger(range.bitLength());
	while (r > range) {
		r = openpgp_crypto_getRandomBigInteger(range.bitLength());
	}
	return min.add(r);
},


//This is a test method to ensure that encryption/decryption with a given 1024bit RSAKey object functions as intended
testRSA: function(key){
	debugger;
    var rsa = new RSA();
	var mpi = new openpgp_type_mpi();
	mpi.create(openpgp_encoding_eme_pkcs1_encode('ABABABAB', 128));
	var msg = rsa.encrypt(mpi.toBigInteger(),key.ee,key.n);
	var result = rsa.decrypt(msg, key.d, key.p, key.q, key.u);
},

/**
 * @typedef {Object} openpgp_keypair
 * @property {openpgp_packet_keymaterial} privateKey 
 * @property {openpgp_packet_keymaterial} publicKey
 */

/**
 * Calls the necessary crypto functions to generate a keypair. 
 * Called directly by openpgp.js
 * @param {Integer} keyType Follows OpenPGP algorithm convention.
 * @param {Integer} numBits Number of bits to make the key to be generated
 * @return {openpgp_keypair}
 */
generateKeyPair: function(keyType, numBits, passphrase, s2kHash, symmetricEncryptionAlgorithm){
	var privKeyPacket;
	var publicKeyPacket;
	var d = new Date();
	d = d.getTime()/1000;
	var timePacket = String.fromCharCode(Math.floor(d/0x1000000%0x100)) + String.fromCharCode(Math.floor(d/0x10000%0x100)) + String.fromCharCode(Math.floor(d/0x100%0x100)) + String.fromCharCode(Math.floor(d%0x100));
	switch(keyType){
	case 1:
	    var rsa = new RSA();
	    var key = rsa.generate(numBits,"10001");
	    privKeyPacket = new openpgp_packet_keymaterial().write_private_key(keyType, key, passphrase, s2kHash, symmetricEncryptionAlgorithm, timePacket);
	    publicKeyPacket =  new openpgp_packet_keymaterial().write_public_key(keyType, key, timePacket);
	    break;
	default:
		util.print_error("Unknown keytype "+keyType)
	}
	return {privateKey: privKeyPacket, publicKey: publicKeyPacket};
}

}

},{"./random.js":37,"../type/mpi.js":4,"./public_key":19}],21:[function(require,module,exports){
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

var enums = require('../enums.js');

/**
 * @class
 * @classdesc Implementation of the Compressed Data Packet (Tag 8)
 * 
 * RFC4880 5.6:
 * The Compressed Data packet contains compressed data.  Typically, this
 * packet is found as the contents of an encrypted packet, or following
 * a Signature or One-Pass Signature packet, and contains a literal data
 * packet.
 */   
module.exports = function packet_compressed() {
	/** @type {packetlist} */
	this.packets;
	/** @type {compression} */
	this.algorithm = 'uncompressed';

	this.compressed = null;

	
	/**
	 * Parsing function for the packet.
	 * @param {String} input Payload of a tag 8 packet
	 * @param {Integer} position Position to start reading from the input string
	 * @parAM {iNTEGER} LEN lENGTH OF the packet or the remaining length of 
	 * input at position
	 * @return {openpgp_packet_compressed} Object representation
	 */
	this.read = function(bytes) {
		// One octet that gives the algorithm used to compress the packet.
		this.algorithm = enums.read(enums.compression, bytes.charCodeAt(0));

		// Compressed data, which makes up the remainder of the packet.
		this.compressed = bytes.substr(1);

		this.decompress();
	}

	
	
	this.write = function() {
		if(this.compressed == null)
			this.compress();

		return String.fromCharCode(enums.write(enums.compression, this.algorithm)) 
			+ this.compressed;
	}


	/**
	 * Decompression method for decompressing the compressed data
	 * read by read_packet
	 * @return {String} The decompressed data
	 */
	this.decompress = function() {
		var decompressed;

		switch (this.algorithm) {
		case 'uncompressed':
			decompressed = this.compressed;
			break;

		case 'zip':
			var compData = this.compressed;

			var radix = s2r(compData).replace(/\n/g,"");
			// no header in this case, directly call deflate
			var jxg_obj = new JXG.Util.Unzip(JXG.Util.Base64.decodeAsArray(radix));

			decompressed = unescape(jxg_obj.deflate()[0][0]);
			break;

		case 'zlib':
			//RFC 1950. Bits 0-3 Compression Method
			var compressionMethod = this.compressed.charCodeAt(0) % 0x10;

			//Bits 4-7 RFC 1950 are LZ77 Window. Generally this value is 7 == 32k window size.
			// 2nd Byte in RFC 1950 is for "FLAGs" Allows for a Dictionary 
			// (how is this defined). Basic checksum, and compression level.

			if (compressionMethod == 8) { //CM 8 is for DEFLATE, RFC 1951
				// remove 4 bytes ADLER32 checksum from the end
				var compData = this.compressed.substring(0, this.compressed.length - 4);
				var radix = s2r(compData).replace(/\n/g,"");
				//TODO check ADLER32 checksum
				decompressed = JXG.decompress(radix);
				break;

			} else {
				util.print_error("Compression algorithm ZLIB only supports " +
					"DEFLATE compression method.");
			}
			break;

		case 'bzip2':
			// TODO: need to implement this
			throw new Error('Compression algorithm BZip2 [BZ2] is not implemented.');
			break;

		default:
			throw new Error("Compression algorithm unknown :" + this.alogrithm);
			break;
		}

		this.packets.read(decompressed);
	}

	/**
	 * Compress the packet data (member decompressedData)
	 * @param {Integer} type Algorithm to be used // See RFC 4880 9.3
	 * @param {String} data Data to be compressed
	 * @return {String} The compressed data stored in attribute compressedData
	 */
	this.compress = function() {
		switch (this.algorithm) {

		case 'uncompressed': // - Uncompressed
			this.compressed = this.packets.write();
			break;

		case 'zip': // - ZIP [RFC1951]
			util.print_error("Compression algorithm ZIP [RFC1951] is not implemented.");
			break;

		case 'zlib': // - ZLIB [RFC1950]
			// TODO: need to implement this
			util.print_error("Compression algorithm ZLIB [RFC1950] is not implemented.");
			break;

		case 'bzip2': //  - BZip2 [BZ2]
			// TODO: need to implement this
			util.print_error("Compression algorithm BZip2 [BZ2] is not implemented.");
			break;

		default:
			util.print_error("Compression algorithm unknown :"+this.type);
			break;
		}
	}
};

},{"../enums.js":10}],29:[function(require,module,exports){
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

var public_key = require('./public_key.js');

module.exports = function public_subkey() {
	public_key.call(this);
}

},{"./public_key.js":26}],31:[function(require,module,exports){
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
 * @classdesc Implementation of the One-Pass Signature Packets (Tag 4)
 * 
 * RFC4880 5.4:
 * The One-Pass Signature packet precedes the signed data and contains
 * enough information to allow the receiver to begin calculating any
 * hashes needed to verify the signature.  It allows the Signature
 * packet to be placed at the end of the message, so that the signer
 * can compute the entire signed message in one pass.
 */

var enums = require('../enums.js');

module.exports = function packet_one_pass_signature() {
	this.version = null; // A one-octet version number.  The current version is 3.
	this.type = null; 	 // A one-octet signature type.  Signature types are described in RFC4880 Section 5.2.1.
	this.hashAlgorithm = null; 	   // A one-octet number describing the hash algorithm used. (See RFC4880 9.4)
	this.publicKeyAlgorithm = null;	     // A one-octet number describing the public-key algorithm used. (See RFC4880 9.1)
	this.signingKeyId = null; // An eight-octet number holding the Key ID of the signing key.
	this.flags = null; 	//  A one-octet number holding a flag showing whether the signature is nested.  A zero value indicates that the next packet is another One-Pass Signature packet that describes another signature to be applied to the same message data.

	/**
	 * parsing function for a one-pass signature packet (tag 4).
	 * @param {String} bytes payload of a tag 4 packet
	 * @param {Integer} position position to start reading from the bytes string
	 * @param {Integer} len length of the packet or the remaining length of bytes at position
	 * @return {openpgp_packet_encrypteddata} object representation
	 */
	this.read = function(bytes) {
		var mypos = 0;
		// A one-octet version number.  The current version is 3.
		this.version = bytes.charCodeAt(mypos++);

	     // A one-octet signature type.  Signature types are described in
	     //   Section 5.2.1.
		this.type = enums.read(enums.signature, bytes.charCodeAt(mypos++));

	     // A one-octet number describing the hash algorithm used.
		this.hashAlgorithm = enums.read(enums.hash, bytes.charCodeAt(mypos++));

	     // A one-octet number describing the public-key algorithm used.
		this.publicKeyAlgorithm = enums.read(enums.publicKey, bytes.charCodeAt(mypos++));

	     // An eight-octet number holding the Key ID of the signing key.
		this.signingKeyId = new openpgp_type_keyid();
		this.signingKeyId.read_packet(bytes,mypos);
		mypos += 8;
		
	     // A one-octet number holding a flag showing whether the signature
	     //   is nested.  A zero value indicates that the next packet is
	     //   another One-Pass Signature packet that describes another
	     //   signature to be applied to the same message data.
		this.flags = bytes.charCodeAt(mypos++);
		return this;
	}

	/**
	 * creates a string representation of a one-pass signature packet
	 * @param {Integer} type Signature types as described in RFC4880 Section 5.2.1.
	 * @param {Integer} hashalgorithm the hash algorithm used within the signature
	 * @param {openpgp_msg_privatekey} privatekey the private key used to generate the signature
	 * @param {Integer} length length of data to be signed
	 * @param {boolean} nested boolean showing whether the signature is nested. 
	 *  "true" indicates that the next packet is another One-Pass Signature packet
	 *   that describes another signature to be applied to the same message data. 
	 * @return {String} a string representation of a one-pass signature packet
	 */
	this.write = function(type, hashalgorithm, privatekey, length, nested) {
		var result =""; 
		
		result += String.fromCharCode(3);
		result += String.fromCharCode(enums.write(enums.signature, type));
		result += String.fromCharCode(enums.write(enums.hash, this.hashAlgorithm));
		result += String.fromCharCode(enums.write(enums.publicKey, privatekey.algorithm));
		result += privatekey.getKeyId();
		if (nested)
			result += String.fromCharCode(0);
		else
			result += String.fromCharCode(1);
		
		return result;
	}
};

},{"../enums.js":10}],34:[function(require,module,exports){
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

var secret_key = require('./secret_key.js');

module.exports = function secret_subkey() {
	secret_key.call(this);
}

},{"./secret_key.js":32}],43:[function(require,module,exports){
/* A JavaScript implementation of the SHA family of hashes, as defined in FIPS 
 * PUB 180-2 as well as the corresponding HMAC implementation as defined in
 * FIPS PUB 198a
 *
 * Version 1.3 Copyright Brian Turek 2008-2010
 * Distributed under the BSD License
 * See http://jssha.sourceforge.net/ for more information
 *
 * Several functions taken from Paul Johnson
 */

/* Modified by Recurity Labs GmbH
 * 
 * This code has been slightly modified direct string output:
 * - bin2bstr has been added
 * - following wrappers of this library have been added:
 *   - str_sha1
 *   - str_sha256
 *   - str_sha224
 *   - str_sha384
 *   - str_sha512
 */

var jsSHA = (function () {
	
	/*
	 * Configurable variables. Defaults typically work
	 */
	/* Number of Bits Per character (8 for ASCII, 16 for Unicode) */
	var charSize = 8, 
	/* base-64 pad character. "=" for strict RFC compliance */
	b64pad = "", 
	/* hex output format. 0 - lowercase; 1 - uppercase */
	hexCase = 0, 

	/*
	 * Int_64 is a object for 2 32-bit numbers emulating a 64-bit number
	 *
	 * @constructor
	 * @param {Number} msint_32 The most significant 32-bits of a 64-bit number
	 * @param {Number} lsint_32 The least significant 32-bits of a 64-bit number
	 */
	Int_64 = function (msint_32, lsint_32)
	{
		this.highOrder = msint_32;
		this.lowOrder = lsint_32;
	},

	/*
	 * Convert a string to an array of big-endian words
	 * If charSize is ASCII, characters >255 have their hi-byte silently
	 * ignored.
	 *
	 * @param {String} str String to be converted to binary representation
	 * @return Integer array representation of the parameter
	 */
	str2binb = function (str)
	{
		var bin = [], mask = (1 << charSize) - 1,
			length = str.length * charSize, i;

		for (i = 0; i < length; i += charSize)
		{
			bin[i >> 5] |= (str.charCodeAt(i / charSize) & mask) <<
				(32 - charSize - (i % 32));
		}

		return bin;
	},

	/*
	 * Convert a hex string to an array of big-endian words
	 *
	 * @param {String} str String to be converted to binary representation
	 * @return Integer array representation of the parameter
	 */
	hex2binb = function (str)
	{
		var bin = [], length = str.length, i, num;

		for (i = 0; i < length; i += 2)
		{
			num = parseInt(str.substr(i, 2), 16);
			if (!isNaN(num))
			{
				bin[i >> 3] |= num << (24 - (4 * (i % 8)));
			}
			else
			{
				return "INVALID HEX STRING";
			}
		}

		return bin;
	},

	/*
	 * Convert an array of big-endian words to a hex string.
	 *
	 * @private
	 * @param {Array} binarray Array of integers to be converted to hexidecimal
	 *	 representation
	 * @return Hexidecimal representation of the parameter in String form
	 */
	binb2hex = function (binarray)
	{
		var hex_tab = (hexCase) ? "0123456789ABCDEF" : "0123456789abcdef",
			str = "", length = binarray.length * 4, i, srcByte;

		for (i = 0; i < length; i += 1)
		{
			srcByte = binarray[i >> 2] >> ((3 - (i % 4)) * 8);
			str += hex_tab.charAt((srcByte >> 4) & 0xF) +
				hex_tab.charAt(srcByte & 0xF);
		}

		return str;
	},

	/*
	 * Convert an array of big-endian words to a base-64 string
	 *
	 * @private
	 * @param {Array} binarray Array of integers to be converted to base-64
	 *	 representation
	 * @return Base-64 encoded representation of the parameter in String form
	 */
	binb2b64 = function (binarray)
	{
		var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" +
			"0123456789+/", str = "", length = binarray.length * 4, i, j,
			triplet;

		for (i = 0; i < length; i += 3)
		{
			triplet = (((binarray[i >> 2] >> 8 * (3 - i % 4)) & 0xFF) << 16) |
				(((binarray[i + 1 >> 2] >> 8 * (3 - (i + 1) % 4)) & 0xFF) << 8) |
				((binarray[i + 2 >> 2] >> 8 * (3 - (i + 2) % 4)) & 0xFF);
			for (j = 0; j < 4; j += 1)
			{
				if (i * 8 + j * 6 <= binarray.length * 32)
				{
					str += tab.charAt((triplet >> 6 * (3 - j)) & 0x3F);
				}
				else
				{
					str += b64pad;
				}
			}
		}
		return str;
	},

	/*
	 * Convert an array of big-endian words to a string
	 */
	binb2str = function (bin)
	{
	  var str = "";
	  var mask = (1 << 8) - 1;
	  for(var i = 0; i < bin.length * 32; i += 8)
	    str += String.fromCharCode((bin[i>>5] >>> (24 - i%32)) & mask);
	  return str;
	},
	/*
	 * The 32-bit implementation of circular rotate left
	 *
	 * @private
	 * @param {Number} x The 32-bit integer argument
	 * @param {Number} n The number of bits to shift
	 * @return The x shifted circularly by n bits
	 */
	rotl_32 = function (x, n)
	{
		return (x << n) | (x >>> (32 - n));
	},

	/*
	 * The 32-bit implementation of circular rotate right
	 *
	 * @private
	 * @param {Number} x The 32-bit integer argument
	 * @param {Number} n The number of bits to shift
	 * @return The x shifted circularly by n bits
	 */
	rotr_32 = function (x, n)
	{
		return (x >>> n) | (x << (32 - n));
	},

	/*
	 * The 64-bit implementation of circular rotate right
	 *
	 * @private
	 * @param {Int_64} x The 64-bit integer argument
	 * @param {Number} n The number of bits to shift
	 * @return The x shifted circularly by n bits
	 */
	rotr_64 = function (x, n)
	{
		if (n <= 32)
		{
			return new Int_64(
					(x.highOrder >>> n) | (x.lowOrder << (32 - n)),
					(x.lowOrder >>> n) | (x.highOrder << (32 - n))
				);
		}
		else
		{
			return new Int_64(
					(x.lowOrder >>> n) | (x.highOrder << (32 - n)),
					(x.highOrder >>> n) | (x.lowOrder << (32 - n))
				);
		}
	},

	/*
	 * The 32-bit implementation of shift right
	 *
	 * @private
	 * @param {Number} x The 32-bit integer argument
	 * @param {Number} n The number of bits to shift
	 * @return The x shifted by n bits
	 */
	shr_32 = function (x, n)
	{
		return x >>> n;
	},

	/*
	 * The 64-bit implementation of shift right
	 *
	 * @private
	 * @param {Int_64} x The 64-bit integer argument
	 * @param {Number} n The number of bits to shift
	 * @return The x shifted by n bits
	 */
	shr_64 = function (x, n)
	{
		if (n <= 32)
		{
			return new Int_64(
					x.highOrder >>> n,
					x.lowOrder >>> n | (x.highOrder << (32 - n))
				);
		}
		else
		{
			return new Int_64(
					0,
					x.highOrder << (32 - n)
				);
		}
	},

	/*
	 * The 32-bit implementation of the NIST specified Parity function
	 *
	 * @private
	 * @param {Number} x The first 32-bit integer argument
	 * @param {Number} y The second 32-bit integer argument
	 * @param {Number} z The third 32-bit integer argument
	 * @return The NIST specified output of the function
	 */
	parity_32 = function (x, y, z)
	{
		return x ^ y ^ z;
	},

	/*
	 * The 32-bit implementation of the NIST specified Ch function
	 *
	 * @private
	 * @param {Number} x The first 32-bit integer argument
	 * @param {Number} y The second 32-bit integer argument
	 * @param {Number} z The third 32-bit integer argument
	 * @return The NIST specified output of the function
	 */
	ch_32 = function (x, y, z)
	{
		return (x & y) ^ (~x & z);
	},

	/*
	 * The 64-bit implementation of the NIST specified Ch function
	 *
	 * @private
	 * @param {Int_64} x The first 64-bit integer argument
	 * @param {Int_64} y The second 64-bit integer argument
	 * @param {Int_64} z The third 64-bit integer argument
	 * @return The NIST specified output of the function
	 */
	ch_64 = function (x, y, z)
	{
		return new Int_64(
				(x.highOrder & y.highOrder) ^ (~x.highOrder & z.highOrder),
				(x.lowOrder & y.lowOrder) ^ (~x.lowOrder & z.lowOrder)
			);
	},

	/*
	 * The 32-bit implementation of the NIST specified Maj function
	 *
	 * @private
	 * @param {Number} x The first 32-bit integer argument
	 * @param {Number} y The second 32-bit integer argument
	 * @param {Number} z The third 32-bit integer argument
	 * @return The NIST specified output of the function
	 */
	maj_32 = function (x, y, z)
	{
		return (x & y) ^ (x & z) ^ (y & z);
	},

	/*
	 * The 64-bit implementation of the NIST specified Maj function
	 *
	 * @private
	 * @param {Int_64} x The first 64-bit integer argument
	 * @param {Int_64} y The second 64-bit integer argument
	 * @param {Int_64} z The third 64-bit integer argument
	 * @return The NIST specified output of the function
	 */
	maj_64 = function (x, y, z)
	{
		return new Int_64(
				(x.highOrder & y.highOrder) ^
				(x.highOrder & z.highOrder) ^
				(y.highOrder & z.highOrder),
				(x.lowOrder & y.lowOrder) ^
				(x.lowOrder & z.lowOrder) ^
				(y.lowOrder & z.lowOrder)
			);
	},

	/*
	 * The 32-bit implementation of the NIST specified Sigma0 function
	 *
	 * @private
	 * @param {Number} x The 32-bit integer argument
	 * @return The NIST specified output of the function
	 */
	sigma0_32 = function (x)
	{
		return rotr_32(x, 2) ^ rotr_32(x, 13) ^ rotr_32(x, 22);
	},

	/*
	 * The 64-bit implementation of the NIST specified Sigma0 function
	 *
	 * @private
	 * @param {Int_64} x The 64-bit integer argument
	 * @return The NIST specified output of the function
	 */
	sigma0_64 = function (x)
	{
		var rotr28 = rotr_64(x, 28), rotr34 = rotr_64(x, 34),
			rotr39 = rotr_64(x, 39);

		return new Int_64(
				rotr28.highOrder ^ rotr34.highOrder ^ rotr39.highOrder,
				rotr28.lowOrder ^ rotr34.lowOrder ^ rotr39.lowOrder);
	},

	/*
	 * The 32-bit implementation of the NIST specified Sigma1 function
	 *
	 * @private
	 * @param {Number} x The 32-bit integer argument
	 * @return The NIST specified output of the function
	 */
	sigma1_32 = function (x)
	{
		return rotr_32(x, 6) ^ rotr_32(x, 11) ^ rotr_32(x, 25);
	},

	/*
	 * The 64-bit implementation of the NIST specified Sigma1 function
	 *
	 * @private
	 * @param {Int_64} x The 64-bit integer argument
	 * @return The NIST specified output of the function
	 */
	sigma1_64 = function (x)
	{
		var rotr14 = rotr_64(x, 14), rotr18 = rotr_64(x, 18),
			rotr41 = rotr_64(x, 41);

		return new Int_64(
				rotr14.highOrder ^ rotr18.highOrder ^ rotr41.highOrder,
				rotr14.lowOrder ^ rotr18.lowOrder ^ rotr41.lowOrder);
	},

	/*
	 * The 32-bit implementation of the NIST specified Gamma0 function
	 *
	 * @private
	 * @param {Number} x The 32-bit integer argument
	 * @return The NIST specified output of the function
	 */
	gamma0_32 = function (x)
	{
		return rotr_32(x, 7) ^ rotr_32(x, 18) ^ shr_32(x, 3);
	},

	/*
	 * The 64-bit implementation of the NIST specified Gamma0 function
	 *
	 * @private
	 * @param {Int_64} x The 64-bit integer argument
	 * @return The NIST specified output of the function
	 */
	gamma0_64 = function (x)
	{
		var rotr1 = rotr_64(x, 1), rotr8 = rotr_64(x, 8), shr7 = shr_64(x, 7);

		return new Int_64(
				rotr1.highOrder ^ rotr8.highOrder ^ shr7.highOrder,
				rotr1.lowOrder ^ rotr8.lowOrder ^ shr7.lowOrder
			);
	},

	/*
	 * The 32-bit implementation of the NIST specified Gamma1 function
	 *
	 * @private
	 * @param {Number} x The 32-bit integer argument
	 * @return The NIST specified output of the function
	 */
	gamma1_32 = function (x)
	{
		return rotr_32(x, 17) ^ rotr_32(x, 19) ^ shr_32(x, 10);
	},

	/*
	 * The 64-bit implementation of the NIST specified Gamma1 function
	 *
	 * @private
	 * @param {Int_64} x The 64-bit integer argument
	 * @return The NIST specified output of the function
	 */
	gamma1_64 = function (x)
	{
		var rotr19 = rotr_64(x, 19), rotr61 = rotr_64(x, 61),
			shr6 = shr_64(x, 6);

		return new Int_64(
				rotr19.highOrder ^ rotr61.highOrder ^ shr6.highOrder,
				rotr19.lowOrder ^ rotr61.lowOrder ^ shr6.lowOrder
			);
	},

	/*
	 * Add two 32-bit integers, wrapping at 2^32. This uses 16-bit operations
	 * internally to work around bugs in some JS interpreters.
	 *
	 * @private
	 * @param {Number} x The first 32-bit integer argument to be added
	 * @param {Number} y The second 32-bit integer argument to be added
	 * @return The sum of x + y
	 */
	safeAdd_32_2 = function (x, y)
	{
		var lsw = (x & 0xFFFF) + (y & 0xFFFF),
			msw = (x >>> 16) + (y >>> 16) + (lsw >>> 16);

		return ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);
	},

	/*
	 * Add four 32-bit integers, wrapping at 2^32. This uses 16-bit operations
	 * internally to work around bugs in some JS interpreters.
	 *
	 * @private
	 * @param {Number} a The first 32-bit integer argument to be added
	 * @param {Number} b The second 32-bit integer argument to be added
	 * @param {Number} c The third 32-bit integer argument to be added
	 * @param {Number} d The fourth 32-bit integer argument to be added
	 * @return The sum of a + b + c + d
	 */
	safeAdd_32_4 = function (a, b, c, d)
	{
		var lsw = (a & 0xFFFF) + (b & 0xFFFF) + (c & 0xFFFF) + (d & 0xFFFF),
			msw = (a >>> 16) + (b >>> 16) + (c >>> 16) + (d >>> 16) +
				(lsw >>> 16);

		return ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);
	},

	/*
	 * Add five 32-bit integers, wrapping at 2^32. This uses 16-bit operations
	 * internally to work around bugs in some JS interpreters.
	 *
	 * @private
	 * @param {Number} a The first 32-bit integer argument to be added
	 * @param {Number} b The second 32-bit integer argument to be added
	 * @param {Number} c The third 32-bit integer argument to be added
	 * @param {Number} d The fourth 32-bit integer argument to be added
	 * @param {Number} e The fifth 32-bit integer argument to be added
	 * @return The sum of a + b + c + d + e
	 */
	safeAdd_32_5 = function (a, b, c, d, e)
	{
		var lsw = (a & 0xFFFF) + (b & 0xFFFF) + (c & 0xFFFF) + (d & 0xFFFF) +
				(e & 0xFFFF),
			msw = (a >>> 16) + (b >>> 16) + (c >>> 16) + (d >>> 16) +
				(e >>> 16) + (lsw >>> 16);

		return ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);
	},

	/*
	 * Add two 64-bit integers, wrapping at 2^64. This uses 16-bit operations
	 * internally to work around bugs in some JS interpreters.
	 *
	 * @private
	 * @param {Int_64} x The first 64-bit integer argument to be added
	 * @param {Int_64} y The second 64-bit integer argument to be added
	 * @return The sum of x + y
	 */
	safeAdd_64_2 = function (x, y)
	{
		var lsw, msw, lowOrder, highOrder;

		lsw = (x.lowOrder & 0xFFFF) + (y.lowOrder & 0xFFFF);
		msw = (x.lowOrder >>> 16) + (y.lowOrder >>> 16) + (lsw >>> 16);
		lowOrder = ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);

		lsw = (x.highOrder & 0xFFFF) + (y.highOrder & 0xFFFF) + (msw >>> 16);
		msw = (x.highOrder >>> 16) + (y.highOrder >>> 16) + (lsw >>> 16);
		highOrder = ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);

		return new Int_64(highOrder, lowOrder);
	},

	/*
	 * Add four 64-bit integers, wrapping at 2^64. This uses 16-bit operations
	 * internally to work around bugs in some JS interpreters.
	 *
	 * @private
	 * @param {Int_64} a The first 64-bit integer argument to be added
	 * @param {Int_64} b The second 64-bit integer argument to be added
	 * @param {Int_64} c The third 64-bit integer argument to be added
	 * @param {Int_64} d The fouth 64-bit integer argument to be added
	 * @return The sum of a + b + c + d
	 */
	safeAdd_64_4 = function (a, b, c, d)
	{
		var lsw, msw, lowOrder, highOrder;

		lsw = (a.lowOrder & 0xFFFF) + (b.lowOrder & 0xFFFF) +
			(c.lowOrder & 0xFFFF) + (d.lowOrder & 0xFFFF);
		msw = (a.lowOrder >>> 16) + (b.lowOrder >>> 16) +
			(c.lowOrder >>> 16) + (d.lowOrder >>> 16) + (lsw >>> 16);
		lowOrder = ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);

		lsw = (a.highOrder & 0xFFFF) + (b.highOrder & 0xFFFF) +
			(c.highOrder & 0xFFFF) + (d.highOrder & 0xFFFF) + (msw >>> 16);
		msw = (a.highOrder >>> 16) + (b.highOrder >>> 16) +
			(c.highOrder >>> 16) + (d.highOrder >>> 16) + (lsw >>> 16);
		highOrder = ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);

		return new Int_64(highOrder, lowOrder);
	},

	/*
	 * Add five 64-bit integers, wrapping at 2^64. This uses 16-bit operations
	 * internally to work around bugs in some JS interpreters.
	 *
	 * @private
	 * @param {Int_64} a The first 64-bit integer argument to be added
	 * @param {Int_64} b The second 64-bit integer argument to be added
	 * @param {Int_64} c The third 64-bit integer argument to be added
	 * @param {Int_64} d The fouth 64-bit integer argument to be added
	 * @param {Int_64} e The fouth 64-bit integer argument to be added
	 * @return The sum of a + b + c + d + e
	 */
	safeAdd_64_5 = function (a, b, c, d, e)
	{
		var lsw, msw, lowOrder, highOrder;

		lsw = (a.lowOrder & 0xFFFF) + (b.lowOrder & 0xFFFF) +
			(c.lowOrder & 0xFFFF) + (d.lowOrder & 0xFFFF) +
			(e.lowOrder & 0xFFFF);
		msw = (a.lowOrder >>> 16) + (b.lowOrder >>> 16) +
			(c.lowOrder >>> 16) + (d.lowOrder >>> 16) + (e.lowOrder >>> 16) +
			(lsw >>> 16);
		lowOrder = ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);

		lsw = (a.highOrder & 0xFFFF) + (b.highOrder & 0xFFFF) +
			(c.highOrder & 0xFFFF) + (d.highOrder & 0xFFFF) +
			(e.highOrder & 0xFFFF) + (msw >>> 16);
		msw = (a.highOrder >>> 16) + (b.highOrder >>> 16) +
			(c.highOrder >>> 16) + (d.highOrder >>> 16) +
			(e.highOrder >>> 16) + (lsw >>> 16);
		highOrder = ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);

		return new Int_64(highOrder, lowOrder);
	},

	/*
	 * Calculates the SHA-1 hash of the string set at instantiation
	 *
	 * @private
	 * @param {Array} message The binary array representation of the string to
	 *	 hash
	 * @param {Number} messageLen The number of bits in the message
	 * @return The array of integers representing the SHA-1 hash of message
	 */
	coreSHA1 = function (message, messageLen)
	{
		var W = [], a, b, c, d, e, T, ch = ch_32, parity = parity_32,
			maj = maj_32, rotl = rotl_32, safeAdd_2 = safeAdd_32_2, i, t,
			safeAdd_5 = safeAdd_32_5, appendedMessageLength,
			H = [
				0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
			],
			K = [
				0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
				0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
				0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
				0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
				0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
				0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
				0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
				0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
				0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
				0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
				0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
				0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
				0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
				0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
				0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
				0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6,
				0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6,
				0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6,
				0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6,
				0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6
			];

		/* Append '1' at the end of the binary string */
		message[messageLen >> 5] |= 0x80 << (24 - (messageLen % 32));
		/* Append length of binary string in the position such that the new
		length is a multiple of 512.  Logic does not work for even multiples
		of 512 but there can never be even multiples of 512 */
		message[(((messageLen + 65) >> 9) << 4) + 15] = messageLen;

		appendedMessageLength = message.length;

		for (i = 0; i < appendedMessageLength; i += 16)
		{
			a = H[0];
			b = H[1];
			c = H[2];
			d = H[3];
			e = H[4];

			for (t = 0; t < 80; t += 1)
			{
				if (t < 16)
				{
					W[t] = message[t + i];
				}
				else
				{
					W[t] = rotl(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
				}

				if (t < 20)
				{
					T = safeAdd_5(rotl(a, 5), ch(b, c, d), e, K[t], W[t]);
				}
				else if (t < 40)
				{
					T = safeAdd_5(rotl(a, 5), parity(b, c, d), e, K[t], W[t]);
				}
				else if (t < 60)
				{
					T = safeAdd_5(rotl(a, 5), maj(b, c, d), e, K[t], W[t]);
				} else {
					T = safeAdd_5(rotl(a, 5), parity(b, c, d), e, K[t], W[t]);
				}

				e = d;
				d = c;
				c = rotl(b, 30);
				b = a;
				a = T;
			}

			H[0] = safeAdd_2(a, H[0]);
			H[1] = safeAdd_2(b, H[1]);
			H[2] = safeAdd_2(c, H[2]);
			H[3] = safeAdd_2(d, H[3]);
			H[4] = safeAdd_2(e, H[4]);
		}

		return H;
	},

	/*
	 * Calculates the desired SHA-2 hash of the string set at instantiation
	 *
	 * @private
	 * @param {Array} The binary array representation of the string to hash
	 * @param {Number} The number of bits in message
	 * @param {String} variant The desired SHA-2 variant
	 * @return The array of integers representing the SHA-2 hash of message
	 */
	coreSHA2 = function (message, messageLen, variant)
	{
		var a, b, c, d, e, f, g, h, T1, T2, H, numRounds, lengthPosition, i, t,
			binaryStringInc, binaryStringMult, safeAdd_2, safeAdd_4, safeAdd_5,
			gamma0, gamma1, sigma0, sigma1, ch, maj, Int, K, W = [],
			appendedMessageLength;

		/* Set up the various function handles and variable for the specific 
		 * variant */
		if (variant === "SHA-224" || variant === "SHA-256")
		{
			/* 32-bit variant */
			numRounds = 64;
			lengthPosition = (((messageLen + 65) >> 9) << 4) + 15;
			binaryStringInc = 16;
			binaryStringMult = 1;
			Int = Number;
			safeAdd_2 = safeAdd_32_2;
			safeAdd_4 = safeAdd_32_4;
			safeAdd_5 = safeAdd_32_5;
			gamma0 = gamma0_32;
			gamma1 = gamma1_32;
			sigma0 = sigma0_32;
			sigma1 = sigma1_32;
			maj = maj_32;
			ch = ch_32;
			K = [
					0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
					0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
					0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
					0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
					0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
					0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
					0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
					0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
					0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
					0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
					0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
					0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
					0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
					0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
					0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
					0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
				];

			if (variant === "SHA-224")
			{
				H = [
						0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
						0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
					];
			}
			else
			{
				H = [
						0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
						0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
					];
			}
		}
		else if (variant === "SHA-384" || variant === "SHA-512")
		{
			/* 64-bit variant */
			numRounds = 80;
			lengthPosition = (((messageLen + 128) >> 10) << 5) + 31;
			binaryStringInc = 32;
			binaryStringMult = 2;
			Int = Int_64;
			safeAdd_2 = safeAdd_64_2;
			safeAdd_4 = safeAdd_64_4;
			safeAdd_5 = safeAdd_64_5;
			gamma0 = gamma0_64;
			gamma1 = gamma1_64;
			sigma0 = sigma0_64;
			sigma1 = sigma1_64;
			maj = maj_64;
			ch = ch_64;

			K = [
				new Int(0x428a2f98, 0xd728ae22), new Int(0x71374491, 0x23ef65cd),
				new Int(0xb5c0fbcf, 0xec4d3b2f), new Int(0xe9b5dba5, 0x8189dbbc),
				new Int(0x3956c25b, 0xf348b538), new Int(0x59f111f1, 0xb605d019),
				new Int(0x923f82a4, 0xaf194f9b), new Int(0xab1c5ed5, 0xda6d8118),
				new Int(0xd807aa98, 0xa3030242), new Int(0x12835b01, 0x45706fbe),
				new Int(0x243185be, 0x4ee4b28c), new Int(0x550c7dc3, 0xd5ffb4e2),
				new Int(0x72be5d74, 0xf27b896f), new Int(0x80deb1fe, 0x3b1696b1),
				new Int(0x9bdc06a7, 0x25c71235), new Int(0xc19bf174, 0xcf692694),
				new Int(0xe49b69c1, 0x9ef14ad2), new Int(0xefbe4786, 0x384f25e3),
				new Int(0x0fc19dc6, 0x8b8cd5b5), new Int(0x240ca1cc, 0x77ac9c65),
				new Int(0x2de92c6f, 0x592b0275), new Int(0x4a7484aa, 0x6ea6e483),
				new Int(0x5cb0a9dc, 0xbd41fbd4), new Int(0x76f988da, 0x831153b5),
				new Int(0x983e5152, 0xee66dfab), new Int(0xa831c66d, 0x2db43210),
				new Int(0xb00327c8, 0x98fb213f), new Int(0xbf597fc7, 0xbeef0ee4),
				new Int(0xc6e00bf3, 0x3da88fc2), new Int(0xd5a79147, 0x930aa725),
				new Int(0x06ca6351, 0xe003826f), new Int(0x14292967, 0x0a0e6e70),
				new Int(0x27b70a85, 0x46d22ffc), new Int(0x2e1b2138, 0x5c26c926),
				new Int(0x4d2c6dfc, 0x5ac42aed), new Int(0x53380d13, 0x9d95b3df),
				new Int(0x650a7354, 0x8baf63de), new Int(0x766a0abb, 0x3c77b2a8),
				new Int(0x81c2c92e, 0x47edaee6), new Int(0x92722c85, 0x1482353b),
				new Int(0xa2bfe8a1, 0x4cf10364), new Int(0xa81a664b, 0xbc423001),
				new Int(0xc24b8b70, 0xd0f89791), new Int(0xc76c51a3, 0x0654be30),
				new Int(0xd192e819, 0xd6ef5218), new Int(0xd6990624, 0x5565a910),
				new Int(0xf40e3585, 0x5771202a), new Int(0x106aa070, 0x32bbd1b8),
				new Int(0x19a4c116, 0xb8d2d0c8), new Int(0x1e376c08, 0x5141ab53),
				new Int(0x2748774c, 0xdf8eeb99), new Int(0x34b0bcb5, 0xe19b48a8),
				new Int(0x391c0cb3, 0xc5c95a63), new Int(0x4ed8aa4a, 0xe3418acb),
				new Int(0x5b9cca4f, 0x7763e373), new Int(0x682e6ff3, 0xd6b2b8a3),
				new Int(0x748f82ee, 0x5defb2fc), new Int(0x78a5636f, 0x43172f60),
				new Int(0x84c87814, 0xa1f0ab72), new Int(0x8cc70208, 0x1a6439ec),
				new Int(0x90befffa, 0x23631e28), new Int(0xa4506ceb, 0xde82bde9),
				new Int(0xbef9a3f7, 0xb2c67915), new Int(0xc67178f2, 0xe372532b),
				new Int(0xca273ece, 0xea26619c), new Int(0xd186b8c7, 0x21c0c207),
				new Int(0xeada7dd6, 0xcde0eb1e), new Int(0xf57d4f7f, 0xee6ed178),
				new Int(0x06f067aa, 0x72176fba), new Int(0x0a637dc5, 0xa2c898a6),
				new Int(0x113f9804, 0xbef90dae), new Int(0x1b710b35, 0x131c471b),
				new Int(0x28db77f5, 0x23047d84), new Int(0x32caab7b, 0x40c72493),
				new Int(0x3c9ebe0a, 0x15c9bebc), new Int(0x431d67c4, 0x9c100d4c),
				new Int(0x4cc5d4be, 0xcb3e42b6), new Int(0x597f299c, 0xfc657e2a),
				new Int(0x5fcb6fab, 0x3ad6faec), new Int(0x6c44198c, 0x4a475817)
			];

			if (variant === "SHA-384")
			{
				H = [
					new Int(0xcbbb9d5d, 0xc1059ed8), new Int(0x0629a292a, 0x367cd507),
					new Int(0x9159015a, 0x3070dd17), new Int(0x0152fecd8, 0xf70e5939),
					new Int(0x67332667, 0xffc00b31), new Int(0x98eb44a87, 0x68581511),
					new Int(0xdb0c2e0d, 0x64f98fa7), new Int(0x047b5481d, 0xbefa4fa4)
				];
			}
			else
			{
				H = [
					new Int(0x6a09e667, 0xf3bcc908), new Int(0xbb67ae85, 0x84caa73b),
					new Int(0x3c6ef372, 0xfe94f82b), new Int(0xa54ff53a, 0x5f1d36f1),
					new Int(0x510e527f, 0xade682d1), new Int(0x9b05688c, 0x2b3e6c1f),
					new Int(0x1f83d9ab, 0xfb41bd6b), new Int(0x5be0cd19, 0x137e2179)
				];
			}
		}

		/* Append '1' at the end of the binary string */
		message[messageLen >> 5] |= 0x80 << (24 - messageLen % 32);
		/* Append length of binary string in the position such that the new
		 * length is correct */
		message[lengthPosition] = messageLen;

		appendedMessageLength = message.length;

		for (i = 0; i < appendedMessageLength; i += binaryStringInc)
		{
			a = H[0];
			b = H[1];
			c = H[2];
			d = H[3];
			e = H[4];
			f = H[5];
			g = H[6];
			h = H[7];

			for (t = 0; t < numRounds; t += 1)
			{
				if (t < 16)
				{
					/* Bit of a hack - for 32-bit, the second term is ignored */
					W[t] = new Int(message[t * binaryStringMult + i],
							message[t * binaryStringMult + i + 1]);
				}
				else
				{
					W[t] = safeAdd_4(
							gamma1(W[t - 2]), W[t - 7],
							gamma0(W[t - 15]), W[t - 16]
						);
				}

				T1 = safeAdd_5(h, sigma1(e), ch(e, f, g), K[t], W[t]);
				T2 = safeAdd_2(sigma0(a), maj(a, b, c));
				h = g;
				g = f;
				f = e;
				e = safeAdd_2(d, T1);
				d = c;
				c = b;
				b = a;
				a = safeAdd_2(T1, T2);
			}

			H[0] = safeAdd_2(a, H[0]);
			H[1] = safeAdd_2(b, H[1]);
			H[2] = safeAdd_2(c, H[2]);
			H[3] = safeAdd_2(d, H[3]);
			H[4] = safeAdd_2(e, H[4]);
			H[5] = safeAdd_2(f, H[5]);
			H[6] = safeAdd_2(g, H[6]);
			H[7] = safeAdd_2(h, H[7]);
		}

		switch (variant)
		{
		case "SHA-224":
			return	[
				H[0], H[1], H[2], H[3],
				H[4], H[5], H[6]
			];
		case "SHA-256":
			return H;
		case "SHA-384":
			return [
				H[0].highOrder, H[0].lowOrder,
				H[1].highOrder, H[1].lowOrder,
				H[2].highOrder, H[2].lowOrder,
				H[3].highOrder, H[3].lowOrder,
				H[4].highOrder, H[4].lowOrder,
				H[5].highOrder, H[5].lowOrder
			];
		case "SHA-512":
			return [
				H[0].highOrder, H[0].lowOrder,
				H[1].highOrder, H[1].lowOrder,
				H[2].highOrder, H[2].lowOrder,
				H[3].highOrder, H[3].lowOrder,
				H[4].highOrder, H[4].lowOrder,
				H[5].highOrder, H[5].lowOrder,
				H[6].highOrder, H[6].lowOrder,
				H[7].highOrder, H[7].lowOrder
			];
		default:
			/* This should never be reached */
			return []; 
		}
	},

	/*
	 * jsSHA is the workhorse of the library.  Instantiate it with the string to
	 * be hashed as the parameter
	 *
	 * @constructor
	 * @param {String} srcString The string to be hashed
	 * @param {String} inputFormat The format of srcString, ASCII or HEX
	 */
	jsSHA = function (srcString, inputFormat)
	{

		this.sha1 = null;
		this.sha224 = null;
		this.sha256 = null;
		this.sha384 = null;
		this.sha512 = null;

		this.strBinLen = null;
		this.strToHash = null;

		/* Convert the input string into the correct type */
		if ("HEX" === inputFormat)
		{
			if (0 !== (srcString.length % 2))
			{
				return "TEXT MUST BE IN BYTE INCREMENTS";
			}
			this.strBinLen = srcString.length * 4;
			this.strToHash = hex2binb(srcString);
		}
		else if (("ASCII" === inputFormat) ||
			 ('undefined' === typeof(inputFormat)))
		{
			this.strBinLen = srcString.length * charSize;
			this.strToHash = str2binb(srcString);
		}
		else
		{
			return "UNKNOWN TEXT INPUT TYPE";
		}
	};

	jsSHA.prototype = {
		/*
		 * Returns the desired SHA hash of the string specified at instantiation
		 * using the specified parameters
		 *
		 * @param {String} variant The desired SHA variant (SHA-1, SHA-224,
		 *	 SHA-256, SHA-384, or SHA-512)
		 * @param {String} format The desired output formatting (B64 or HEX)
		 * @return The string representation of the hash in the format specified
		 */
		getHash : function (variant, format)
		{
			var formatFunc = null, message = this.strToHash.slice();

			switch (format)
			{
			case "HEX":
				formatFunc = binb2hex;
				break;
			case "B64":
				formatFunc = binb2b64;
				break;
			case "ASCII":
				formatFunc = binb2str;
				break;
			default:
				return "FORMAT NOT RECOGNIZED";
			}

			switch (variant)
			{
			case "SHA-1":
				if (null === this.sha1)
				{
					this.sha1 = coreSHA1(message, this.strBinLen);
				}
				return formatFunc(this.sha1);
			case "SHA-224":
				if (null === this.sha224)
				{
					this.sha224 = coreSHA2(message, this.strBinLen, variant);
				}
				return formatFunc(this.sha224);
			case "SHA-256":
				if (null === this.sha256)
				{
					this.sha256 = coreSHA2(message, this.strBinLen, variant);
				}
				return formatFunc(this.sha256);
			case "SHA-384":
				if (null === this.sha384)
				{
					this.sha384 = coreSHA2(message, this.strBinLen, variant);
				}
				return formatFunc(this.sha384);
			case "SHA-512":
				if (null === this.sha512)
				{
					this.sha512 = coreSHA2(message, this.strBinLen, variant);
				}
				return formatFunc(this.sha512);
			default:
				return "HASH NOT RECOGNIZED";
			}
		},

		/*
		 * Returns the desired HMAC of the string specified at instantiation
		 * using the key and variant param.
		 *
		 * @param {String} key The key used to calculate the HMAC
		 * @param {String} inputFormat The format of key, ASCII or HEX
		 * @param {String} variant The desired SHA variant (SHA-1, SHA-224,
		 *	 SHA-256, SHA-384, or SHA-512)
		 * @param {String} outputFormat The desired output formatting
		 *	 (B64 or HEX)
		 * @return The string representation of the hash in the format specified
		 */
		getHMAC : function (key, inputFormat, variant, outputFormat)
		{
			var formatFunc, keyToUse, blockByteSize, blockBitSize, i,
				retVal, lastArrayIndex, keyBinLen, hashBitSize,
				keyWithIPad = [], keyWithOPad = [];

			/* Validate the output format selection */
			switch (outputFormat)
			{
			case "HEX":
				formatFunc = binb2hex;
				break;
			case "B64":
				formatFunc = binb2b64;
				break;
			case "ASCII":
				formatFunc = binb2str;
				break;
			default:
				return "FORMAT NOT RECOGNIZED";
			}

			/* Validate the hash variant selection and set needed variables */
			switch (variant)
			{
			case "SHA-1":
				blockByteSize = 64;
				hashBitSize = 160;
				break;
			case "SHA-224":
				blockByteSize = 64;
				hashBitSize = 224;
				break;
			case "SHA-256":
				blockByteSize = 64;
				hashBitSize = 256;
				break;
			case "SHA-384":
				blockByteSize = 128;
				hashBitSize = 384;
				break;
			case "SHA-512":
				blockByteSize = 128;
				hashBitSize = 512;
				break;
			default:
				return "HASH NOT RECOGNIZED";
			}

			/* Validate input format selection */
			if ("HEX" === inputFormat)
			{
				/* Nibbles must come in pairs */
				if (0 !== (key.length % 2))
				{
					return "KEY MUST BE IN BYTE INCREMENTS";
				}
				keyToUse = hex2binb(key);
				keyBinLen = key.length * 4;
			}
			else if ("ASCII" === inputFormat)
			{
				keyToUse = str2binb(key);
				keyBinLen = key.length * charSize;
			}
			else
			{
				return "UNKNOWN KEY INPUT TYPE";
			}

			/* These are used multiple times, calculate and store them */
			blockBitSize = blockByteSize * 8;
			lastArrayIndex = (blockByteSize / 4) - 1;

			/* Figure out what to do with the key based on its size relative to
			 * the hash's block size */
			if (blockByteSize < (keyBinLen / 8))
			{
				if ("SHA-1" === variant)
				{
					keyToUse = coreSHA1(keyToUse, keyBinLen);
				}
				else
				{
					keyToUse = coreSHA2(keyToUse, keyBinLen, variant);
				}
				/* For all variants, the block size is bigger than the output
				 * size so there will never be a useful byte at the end of the
				 * string */
				keyToUse[lastArrayIndex] &= 0xFFFFFF00;
			}
			else if (blockByteSize > (keyBinLen / 8))
			{
				/* If the blockByteSize is greater than the key length, there
				 * will always be at LEAST one "useless" byte at the end of the
				 * string */
				keyToUse[lastArrayIndex] &= 0xFFFFFF00;
			}

			/* Create ipad and opad */
			for (i = 0; i <= lastArrayIndex; i += 1)
			{
				keyWithIPad[i] = keyToUse[i] ^ 0x36363636;
				keyWithOPad[i] = keyToUse[i] ^ 0x5C5C5C5C;
			}

			/* Calculate the HMAC */
			if ("SHA-1" === variant)
			{
				retVal = coreSHA1(
							keyWithIPad.concat(this.strToHash),
							blockBitSize + this.strBinLen);
				retVal = coreSHA1(
							keyWithOPad.concat(retVal),
							blockBitSize + hashBitSize);
			}
			else
			{
				retVal = coreSHA2(
							keyWithIPad.concat(this.strToHash),
							blockBitSize + this.strBinLen, variant);
				retVal = coreSHA2(
							keyWithOPad.concat(retVal),
							blockBitSize + hashBitSize, variant);
			}

			return (formatFunc(retVal));
		}
	};

	return jsSHA;
}());

module.exports = {
	sha1: function(str) {
		var shaObj = new jsSHA(str, "ASCII");
		return shaObj.getHash("SHA-1", "ASCII");
	},
	sha224: function(str) {
		var shaObj = new jsSHA(str, "ASCII");
		return shaObj.getHash("SHA-224", "ASCII");
	},
	sha256: function(str) {
		var shaObj = new jsSHA(str, "ASCII");
		return shaObj.getHash("SHA-256", "ASCII");
	},
	sha384: function(str) {
		var shaObj = new jsSHA(str, "ASCII");
		return shaObj.getHash("SHA-384", "ASCII");

	},
	sha512: function(str) {
		var shaObj = new jsSHA(str, "ASCII");
		return shaObj.getHash("SHA-512", "ASCII");
	}
}

},{}],45:[function(require,module,exports){
/*
 * CryptoMX Tools
 * Copyright (C) 2004 - 2006 Derek Buitenhuis
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/* Modified by Recurity Labs GmbH
 */

var RMDsize   = 160;
var X = new Array();

function ROL(x, n)
{
  return new Number ((x << n) | ( x >>> (32 - n)));
}

function F(x, y, z)
{
  return new Number(x ^ y ^ z);
}

function G(x, y, z)
{
  return new Number((x & y) | (~x & z));
}

function H(x, y, z)
{
  return new Number((x | ~y) ^ z);
}

function I(x, y, z)
{
  return new Number((x & z) | (y & ~z));
}

function J(x, y, z)
{
  return new Number(x ^ (y | ~z));
}

function mixOneRound(a, b, c, d, e, x, s, roundNumber)
{
  switch (roundNumber)
  {
    case 0 : a += F(b, c, d) + x + 0x00000000; break;
    case 1 : a += G(b, c, d) + x + 0x5a827999; break;
    case 2 : a += H(b, c, d) + x + 0x6ed9eba1; break;
    case 3 : a += I(b, c, d) + x + 0x8f1bbcdc; break;
    case 4 : a += J(b, c, d) + x + 0xa953fd4e; break;
    case 5 : a += J(b, c, d) + x + 0x50a28be6; break;
    case 6 : a += I(b, c, d) + x + 0x5c4dd124; break;
    case 7 : a += H(b, c, d) + x + 0x6d703ef3; break;
    case 8 : a += G(b, c, d) + x + 0x7a6d76e9; break;
    case 9 : a += F(b, c, d) + x + 0x00000000; break;
    
    default : document.write("Bogus round number"); break;
  }  
  
  a = ROL(a, s) + e;
  c = ROL(c, 10);

  a &= 0xffffffff;
  b &= 0xffffffff;
  c &= 0xffffffff;
  d &= 0xffffffff;
  e &= 0xffffffff;

  var retBlock = new Array();
  retBlock[0] = a;
  retBlock[1] = b;
  retBlock[2] = c;
  retBlock[3] = d;
  retBlock[4] = e;
  retBlock[5] = x;
  retBlock[6] = s;

  return retBlock;
}

function MDinit (MDbuf)
{
  MDbuf[0] = 0x67452301;
  MDbuf[1] = 0xefcdab89;
  MDbuf[2] = 0x98badcfe;
  MDbuf[3] = 0x10325476;
  MDbuf[4] = 0xc3d2e1f0;
}

var ROLs = [
  [11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8],
  [ 7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12],
  [11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5],
  [11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12],
  [ 9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6],
  [ 8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6],
  [ 9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11],
  [ 9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5],
  [15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8],
  [ 8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11]
];

var indexes = [
  [ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15],
  [ 7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8],
  [ 3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12],
  [ 1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2],
  [ 4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13],
  [ 5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12],
  [ 6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2],
  [15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13],
  [ 8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14],
  [12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11]
];

function compress (MDbuf, X)
{
  blockA = new Array();
  blockB = new Array();

  var retBlock;

  for (var i=0; i < 5; i++)
  {
    blockA[i] = new Number(MDbuf[i]);
    blockB[i] = new Number(MDbuf[i]);
  }

  var step = 0;
  for (var j = 0; j < 5; j++)
  {
    for (var i = 0; i < 16; i++)
    {
      retBlock = mixOneRound(
        blockA[(step+0) % 5],
        blockA[(step+1) % 5],   
        blockA[(step+2) % 5],   
        blockA[(step+3) % 5],   
        blockA[(step+4) % 5],  
        X[indexes[j][i]], 
        ROLs[j][i],
        j
      );

      blockA[(step+0) % 5] = retBlock[0];
      blockA[(step+1) % 5] = retBlock[1];
      blockA[(step+2) % 5] = retBlock[2];
      blockA[(step+3) % 5] = retBlock[3];
      blockA[(step+4) % 5] = retBlock[4];

      step += 4;
    }
  }

  step = 0;
  for (var j = 5; j < 10; j++)
  {
    for (var i = 0; i < 16; i++)
    {  
      retBlock = mixOneRound(
        blockB[(step+0) % 5], 
        blockB[(step+1) % 5], 
        blockB[(step+2) % 5], 
        blockB[(step+3) % 5], 
        blockB[(step+4) % 5],  
        X[indexes[j][i]], 
        ROLs[j][i],
        j
      );

      blockB[(step+0) % 5] = retBlock[0];
      blockB[(step+1) % 5] = retBlock[1];
      blockB[(step+2) % 5] = retBlock[2];
      blockB[(step+3) % 5] = retBlock[3];
      blockB[(step+4) % 5] = retBlock[4];

      step += 4;
    }
  }

  blockB[3] += blockA[2] + MDbuf[1];
  MDbuf[1]  = MDbuf[2] + blockA[3] + blockB[4];
  MDbuf[2]  = MDbuf[3] + blockA[4] + blockB[0];
  MDbuf[3]  = MDbuf[4] + blockA[0] + blockB[1];
  MDbuf[4]  = MDbuf[0] + blockA[1] + blockB[2];
  MDbuf[0]  = blockB[3];
}

function zeroX(X)
{
  for (var i = 0; i < 16; i++) { X[i] = 0; }
}

function MDfinish (MDbuf, strptr, lswlen, mswlen)
{
  var X = new Array(16);
  zeroX(X);

  var j = 0;
  for (var i=0; i < (lswlen & 63); i++)
  {
    X[i >>> 2] ^= (strptr.charCodeAt(j++) & 255) << (8 * (i & 3));
  }

  X[(lswlen >>> 2) & 15] ^= 1 << (8 * (lswlen & 3) + 7);

  if ((lswlen & 63) > 55)
  {
    compress(MDbuf, X);
    var X = new Array(16);
    zeroX(X);
  }

  X[14] = lswlen << 3;
  X[15] = (lswlen >>> 29) | (mswlen << 3);

  compress(MDbuf, X);
}

function BYTES_TO_DWORD(fourChars)
{
  var tmp  = (fourChars.charCodeAt(3) & 255) << 24;
  tmp   |= (fourChars.charCodeAt(2) & 255) << 16;
  tmp   |= (fourChars.charCodeAt(1) & 255) << 8;
  tmp   |= (fourChars.charCodeAt(0) & 255);  

  return tmp;
}

function RMD(message)
{
  var MDbuf   = new Array(RMDsize / 32);
  var hashcode   = new Array(RMDsize / 8);
  var length;  
  var nbytes;

  MDinit(MDbuf);
  length = message.length;

  var X = new Array(16);
  zeroX(X);

  var j=0;
  for (var nbytes=length; nbytes > 63; nbytes -= 64)
  {
    for (var i=0; i < 16; i++)
    {
      X[i] = BYTES_TO_DWORD(message.substr(j, 4));
      j += 4;
    }
    compress(MDbuf, X);
  }

  MDfinish(MDbuf, message.substr(j), length, 0);

  for (var i=0; i < RMDsize / 8; i += 4)
  {
    hashcode[i]   =  MDbuf[i >>> 2]   & 255;
    hashcode[i+1] = (MDbuf[i >>> 2] >>> 8)   & 255;
    hashcode[i+2] = (MDbuf[i >>> 2] >>> 16) & 255;
    hashcode[i+3] = (MDbuf[i >>> 2] >>> 24) & 255;
  }

  return hashcode;
}


function RMDstring(message)
{
  var hashcode = RMD(message);
  var retString = "";

  for (var i=0; i < RMDsize/8; i++)
  {
    retString += String.fromCharCode(hashcode[i]);
  }  

  return retString;  
}

module.exports = RMDstring;

},{}],48:[function(require,module,exports){
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
//
// A Digital signature algorithm implementation

function DSA() {
	// s1 = ((g**s) mod p) mod q
	// s1 = ((s**-1)*(sha-1(m)+(s1*x) mod q)
	function sign(hashalgo, m, g, p, q, x) {
		// If the output size of the chosen hash is larger than the number of
		// bits of q, the hash result is truncated to fit by taking the number
		// of leftmost bits equal to the number of bits of q.  This (possibly
		// truncated) hash function result is treated as a number and used
		// directly in the DSA signature algorithm.
		var hashed_data = util.getLeftNBits(openpgp_crypto_hashData(hashalgo,m),q.bitLength());
		var hash = new BigInteger(util.hexstrdump(hashed_data), 16);
		var k = openpgp_crypto_getRandomBigIntegerInRange(BigInteger.ONE.add(BigInteger.ONE), q.subtract(BigInteger.ONE));
		var s1 = (g.modPow(k,p)).mod(q); 
		var s2 = (k.modInverse(q).multiply(hash.add(x.multiply(s1)))).mod(q);
		var result = new Array();
		result[0] = s1.toMPI();
		result[1] = s2.toMPI();
		return result;
	}
	function select_hash_algorithm(q) {
		var usersetting = openpgp.config.config.prefer_hash_algorithm;
		/*
		 * 1024-bit key, 160-bit q, SHA-1, SHA-224, SHA-256, SHA-384, or SHA-512 hash
		 * 2048-bit key, 224-bit q, SHA-224, SHA-256, SHA-384, or SHA-512 hash
		 * 2048-bit key, 256-bit q, SHA-256, SHA-384, or SHA-512 hash
		 * 3072-bit key, 256-bit q, SHA-256, SHA-384, or SHA-512 hash
		 */
		switch (Math.round(q.bitLength() / 8)) {
		case 20: // 1024 bit
			if (usersetting != 2 &&
				usersetting > 11 &&
				usersetting != 10 &&
				usersetting < 8)
				return 2; // prefer sha1
			return usersetting;
		case 28: // 2048 bit
			if (usersetting > 11 &&
					usersetting < 8)
					return 11;
			return usersetting;
		case 32: // 4096 bit // prefer sha224
			if (usersetting > 10 &&
					usersetting < 8)
					return 8; // prefer sha256
			return usersetting;
		default:
			util.print_debug("DSA select hash algorithm: returning null for an unknown length of q");
			return null;
			
		}
	}
	this.select_hash_algorithm = select_hash_algorithm;
	
	function verify(hashalgo, s1,s2,m,p,q,g,y) {
		var hashed_data = util.getLeftNBits(openpgp_crypto_hashData(hashalgo,m),q.bitLength());
		var hash = new BigInteger(util.hexstrdump(hashed_data), 16); 
		if (BigInteger.ZERO.compareTo(s1) > 0 ||
				s1.compareTo(q) > 0 ||
				BigInteger.ZERO.compareTo(s2) > 0 ||
				s2.compareTo(q) > 0) {
			util.print_error("invalid DSA Signature");
			return null;
		}
		var w = s2.modInverse(q);
		var u1 = hash.multiply(w).mod(q);
		var u2 = s1.multiply(w).mod(q);
		return g.modPow(u1,p).multiply(y.modPow(u2,p)).mod(p).mod(q);
	}
	
	/*
	 * unused code. This can be used as a start to write a key generator
	 * function.
	
	function generateKey(bitcount) {
	    var qi = new BigInteger(bitcount, primeCenterie);
	    var pi = generateP(q, 512);
	    var gi = generateG(p, q, bitcount);
	    var xi;
	    do {
	        xi = new BigInteger(q.bitCount(), rand);
	    } while (x.compareTo(BigInteger.ZERO) != 1 && x.compareTo(q) != -1);
	    var yi = g.modPow(x, p);
	    return {x: xi, q: qi, p: pi, g: gi, y: yi};
	}

	function generateP(q, bitlength, randomfn) {
	    if (bitlength % 64 != 0) {
	    	return false;
	    }
	    var pTemp;
	    var pTemp2;
	    do {
	        pTemp = randomfn(bitcount, true);
	        pTemp2 = pTemp.subtract(BigInteger.ONE);
	        pTemp = pTemp.subtract(pTemp2.remainder(q));
	    } while (!pTemp.isProbablePrime(primeCenterie) || pTemp.bitLength() != l);
	    return pTemp;
	}
	
	function generateG(p, q, bitlength, randomfn) {
	    var aux = p.subtract(BigInteger.ONE);
	    var pow = aux.divide(q);
	    var gTemp;
	    do {
	        gTemp = randomfn(bitlength);
	    } while (gTemp.compareTo(aux) != -1 && gTemp.compareTo(BigInteger.ONE) != 1);
	    return gTemp.modPow(pow, p);
	}

	function generateK(q, bitlength, randomfn) {
	    var tempK;
	    do {
	        tempK = randomfn(bitlength, false);
	    } while (tempK.compareTo(q) != -1 && tempK.compareTo(BigInteger.ZERO) != 1);
	    return tempK;
	}

	function generateR(q,p) {
	    k = generateK(q);
	    var r = g.modPow(k, p).mod(q);
	    return r;
	}

	function generateS(hashfn,k,r,m,q,x) {
        var hash = hashfn(m);
        s = (k.modInverse(q).multiply(hash.add(x.multiply(r)))).mod(q);
	    return s;
	} */
	this.sign = sign;
	this.verify = verify;
	// this.generate = generateKey;
}

module.exports = DSA;

},{}],44:[function(require,module,exports){
(function(){/**
 * A fast MD5 JavaScript implementation
 * Copyright (c) 2012 Joseph Myers
 * http://www.myersdaily.org/joseph/javascript/md5-text.html
 *
 * Permission to use, copy, modify, and distribute this software
 * and its documentation for any purposes and without
 * fee is hereby granted provided that this copyright notice
 * appears in all copies.
 *
 * Of course, this soft is provided "as is" without express or implied
 * warranty of any kind.
 */

var util = require('../../util/util.js');

function MD5(entree) {
	var hex = md5(entree);
	var bin = util.hex2bin(hex);
	return bin;
}

function md5cycle(x, k) {
var a = x[0], b = x[1], c = x[2], d = x[3];

a = ff(a, b, c, d, k[0], 7, -680876936);
d = ff(d, a, b, c, k[1], 12, -389564586);
c = ff(c, d, a, b, k[2], 17,  606105819);
b = ff(b, c, d, a, k[3], 22, -1044525330);
a = ff(a, b, c, d, k[4], 7, -176418897);
d = ff(d, a, b, c, k[5], 12,  1200080426);
c = ff(c, d, a, b, k[6], 17, -1473231341);
b = ff(b, c, d, a, k[7], 22, -45705983);
a = ff(a, b, c, d, k[8], 7,  1770035416);
d = ff(d, a, b, c, k[9], 12, -1958414417);
c = ff(c, d, a, b, k[10], 17, -42063);
b = ff(b, c, d, a, k[11], 22, -1990404162);
a = ff(a, b, c, d, k[12], 7,  1804603682);
d = ff(d, a, b, c, k[13], 12, -40341101);
c = ff(c, d, a, b, k[14], 17, -1502002290);
b = ff(b, c, d, a, k[15], 22,  1236535329);

a = gg(a, b, c, d, k[1], 5, -165796510);
d = gg(d, a, b, c, k[6], 9, -1069501632);
c = gg(c, d, a, b, k[11], 14,  643717713);
b = gg(b, c, d, a, k[0], 20, -373897302);
a = gg(a, b, c, d, k[5], 5, -701558691);
d = gg(d, a, b, c, k[10], 9,  38016083);
c = gg(c, d, a, b, k[15], 14, -660478335);
b = gg(b, c, d, a, k[4], 20, -405537848);
a = gg(a, b, c, d, k[9], 5,  568446438);
d = gg(d, a, b, c, k[14], 9, -1019803690);
c = gg(c, d, a, b, k[3], 14, -187363961);
b = gg(b, c, d, a, k[8], 20,  1163531501);
a = gg(a, b, c, d, k[13], 5, -1444681467);
d = gg(d, a, b, c, k[2], 9, -51403784);
c = gg(c, d, a, b, k[7], 14,  1735328473);
b = gg(b, c, d, a, k[12], 20, -1926607734);

a = hh(a, b, c, d, k[5], 4, -378558);
d = hh(d, a, b, c, k[8], 11, -2022574463);
c = hh(c, d, a, b, k[11], 16,  1839030562);
b = hh(b, c, d, a, k[14], 23, -35309556);
a = hh(a, b, c, d, k[1], 4, -1530992060);
d = hh(d, a, b, c, k[4], 11,  1272893353);
c = hh(c, d, a, b, k[7], 16, -155497632);
b = hh(b, c, d, a, k[10], 23, -1094730640);
a = hh(a, b, c, d, k[13], 4,  681279174);
d = hh(d, a, b, c, k[0], 11, -358537222);
c = hh(c, d, a, b, k[3], 16, -722521979);
b = hh(b, c, d, a, k[6], 23,  76029189);
a = hh(a, b, c, d, k[9], 4, -640364487);
d = hh(d, a, b, c, k[12], 11, -421815835);
c = hh(c, d, a, b, k[15], 16,  530742520);
b = hh(b, c, d, a, k[2], 23, -995338651);

a = ii(a, b, c, d, k[0], 6, -198630844);
d = ii(d, a, b, c, k[7], 10,  1126891415);
c = ii(c, d, a, b, k[14], 15, -1416354905);
b = ii(b, c, d, a, k[5], 21, -57434055);
a = ii(a, b, c, d, k[12], 6,  1700485571);
d = ii(d, a, b, c, k[3], 10, -1894986606);
c = ii(c, d, a, b, k[10], 15, -1051523);
b = ii(b, c, d, a, k[1], 21, -2054922799);
a = ii(a, b, c, d, k[8], 6,  1873313359);
d = ii(d, a, b, c, k[15], 10, -30611744);
c = ii(c, d, a, b, k[6], 15, -1560198380);
b = ii(b, c, d, a, k[13], 21,  1309151649);
a = ii(a, b, c, d, k[4], 6, -145523070);
d = ii(d, a, b, c, k[11], 10, -1120210379);
c = ii(c, d, a, b, k[2], 15,  718787259);
b = ii(b, c, d, a, k[9], 21, -343485551);

x[0] = add32(a, x[0]);
x[1] = add32(b, x[1]);
x[2] = add32(c, x[2]);
x[3] = add32(d, x[3]);

}

function cmn(q, a, b, x, s, t) {
a = add32(add32(a, q), add32(x, t));
return add32((a << s) | (a >>> (32 - s)), b);
}

function ff(a, b, c, d, x, s, t) {
return cmn((b & c) | ((~b) & d), a, b, x, s, t);
}

function gg(a, b, c, d, x, s, t) {
return cmn((b & d) | (c & (~d)), a, b, x, s, t);
}

function hh(a, b, c, d, x, s, t) {
return cmn(b ^ c ^ d, a, b, x, s, t);
}

function ii(a, b, c, d, x, s, t) {
return cmn(c ^ (b | (~d)), a, b, x, s, t);
}

function md51(s) {
txt = '';
var n = s.length,
state = [1732584193, -271733879, -1732584194, 271733878], i;
for (i=64; i<=s.length; i+=64) {
md5cycle(state, md5blk(s.substring(i-64, i)));
}
s = s.substring(i-64);
var tail = [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0];
for (i=0; i<s.length; i++)
tail[i>>2] |= s.charCodeAt(i) << ((i%4) << 3);
tail[i>>2] |= 0x80 << ((i%4) << 3);
if (i > 55) {
md5cycle(state, tail);
for (i=0; i<16; i++) tail[i] = 0;
}
tail[14] = n*8;
md5cycle(state, tail);
return state;
}

/* there needs to be support for Unicode here,
 * unless we pretend that we can redefine the MD-5
 * algorithm for multi-byte characters (perhaps
 * by adding every four 16-bit characters and
 * shortening the sum to 32 bits). Otherwise
 * I suggest performing MD-5 as if every character
 * was two bytes--e.g., 0040 0025 = @%--but then
 * how will an ordinary MD-5 sum be matched?
 * There is no way to standardize text to something
 * like UTF-8 before transformation; speed cost is
 * utterly prohibitive. The JavaScript standard
 * itself needs to look at this: it should start
 * providing access to strings as preformed UTF-8
 * 8-bit unsigned value arrays.
 */
function md5blk(s) { /* I figured global was faster.   */
var md5blks = [], i; /* Andy King said do it this way. */
for (i=0; i<64; i+=4) {
md5blks[i>>2] = s.charCodeAt(i)
+ (s.charCodeAt(i+1) << 8)
+ (s.charCodeAt(i+2) << 16)
+ (s.charCodeAt(i+3) << 24);
}
return md5blks;
}

var hex_chr = '0123456789abcdef'.split('');

function rhex(n)
{
var s='', j=0;
for(; j<4; j++)
s += hex_chr[(n >> (j * 8 + 4)) & 0x0F]
+ hex_chr[(n >> (j * 8)) & 0x0F];
return s;
}

function hex(x) {
for (var i=0; i<x.length; i++)
x[i] = rhex(x[i]);
return x.join('');
}

function md5(s) {
return hex(md51(s));
}

/* this function is much faster,
so if possible we use it. Some IEs
are the only ones I know of that
need the idiotic second function,
generated by an if clause.  */

function add32(a, b) {
return (a + b) & 0xFFFFFFFF;
}

if (md5('hello') != '5d41402abc4b2a76b9719d911017c592') {
function add32(x, y) {
var lsw = (x & 0xFFFF) + (y & 0xFFFF),
msw = (x >> 16) + (y >> 16) + (lsw >> 16);
return (msw << 16) | (lsw & 0xFFFF);
}
}

module.exports = MD5

})()
},{"../../util/util.js":7}],46:[function(require,module,exports){
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
//
// RSA implementation

var BigInteger = require('./jsbn.js'),
	random = require('../random.js');

function SecureRandom(){
    function nextBytes(byteArray){
        for(var n = 0; n < byteArray.length;n++){
            byteArray[n] = random.getSecureRandomOctet();
        }
    }
    this.nextBytes = nextBytes;
}

function RSA() {
	/**
	 * This function uses jsbn Big Num library to decrypt RSA
	 * @param m
	 *            message
	 * @param d
	 *            RSA d as BigInteger
	 * @param p
	 *            RSA p as BigInteger
	 * @param q
	 *            RSA q as BigInteger
	 * @param u
	 *            RSA u as BigInteger
	 * @return {BigInteger} The decrypted value of the message
	 */
	function decrypt(m, d, p, q, u) {
		var xp = m.mod(p).modPow(d.mod(p.subtract(BigInteger.ONE)), p);
		var xq = m.mod(q).modPow(d.mod(q.subtract(BigInteger.ONE)), q);
		util.print_debug("rsa.js decrypt\nxpn:"+util.hexstrdump(xp.toMPI())+"\nxqn:"+util.hexstrdump(xq.toMPI()));

		var t = xq.subtract(xp);
		if (t[0] == 0) {
			t = xp.subtract(xq);
			t = t.multiply(u).mod(q);
			t = q.subtract(t);
		} else {
			t = t.multiply(u).mod(q);
		}
		return t.multiply(p).add(xp);
	}
	
	/**
	 * encrypt message
	 * @param m message as BigInteger
	 * @param e public MPI part as BigInteger
	 * @param n public MPI part as BigInteger
	 * @return BigInteger
	 */
	function encrypt(m,e,n) {
		return m.modPowInt(e, n);
	}
	
	/* Sign and Verify */
	function sign(m,d,n) {
		return m.modPow(d, n);
	}
		
	function verify(x,e,n) {
		return x.modPowInt(e, n);
	}
	
	// "empty" RSA key constructor
    function keyObject() {
        this.n = null;
        this.e = 0;
        this.ee = null;
        this.d = null;
        this.p = null;
        this.q = null;
        this.dmp1 = null;
        this.dmq1 = null;
        this.u = null;
    }
	
	// Generate a new random private key B bits long, using public expt E
    function generate(B,E) {
        var key = new keyObject();
        var rng = new SecureRandom();
        var qs = B>>1;
        key.e = parseInt(E,16);
        key.ee = new BigInteger(E,16);
        for(;;) {
            for(;;) {
                key.p = new BigInteger(B-qs,1,rng);
                if(key.p.subtract(BigInteger.ONE).gcd(key.ee).compareTo(BigInteger.ONE) == 0 && key.p.isProbablePrime(10)) break;
            }
            for(;;) {
                key.q = new BigInteger(qs,1,rng);
                if(key.q.subtract(BigInteger.ONE).gcd(key.ee).compareTo(BigInteger.ONE) == 0 && key.q.isProbablePrime(10)) break;
            }
            if(key.p.compareTo(key.q) <= 0) {
                var t = key.p;
                key.p = key.q;
                key.q = t;
            }
            var p1 = key.p.subtract(BigInteger.ONE);
            var q1 = key.q.subtract(BigInteger.ONE);
            var phi = p1.multiply(q1);
            if(phi.gcd(key.ee).compareTo(BigInteger.ONE) == 0) {
                key.n = key.p.multiply(key.q);
                key.d = key.ee.modInverse(phi);
                key.dmp1 = key.d.mod(p1);
                key.dmq1 = key.d.mod(q1);
                key.u = key.p.modInverse(key.q);
                break;
            }
        }
        return key;
    }
		
	this.encrypt = encrypt;
	this.decrypt = decrypt;
	this.verify = verify;
	this.sign = sign;
	this.generate = generate;
	this.keyObject = keyObject;
}

module.exports = RSA;

},{"./jsbn.js":13,"../random.js":37}],49:[function(require,module,exports){
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
 * ASN1 object identifiers for hashes (See RFC4880 5.2.2)
 */
hash_headers = new Array();
hash_headers[1]  = [0x30,0x20,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x04,0x10];
hash_headers[3]  = [0x30,0x21,0x30,0x09,0x06,0x05,0x2B,0x24,0x03,0x02,0x01,0x05,0x00,0x04,0x14];
hash_headers[2]  = [0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a,0x05,0x00,0x04,0x14];
hash_headers[8]  = [0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20];
hash_headers[9]  = [0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,0x30];
hash_headers[10] = [0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40];
hash_headers[11] = [0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x04,0x05,0x00,0x04,0x1C];


var crypto = require('./crypto.js'),
	random = require('./random.js'),
	util = require('../util'),
	BigInteger = require('./public_key/jsbn.js'),
	hash = require('./hash');
	
module.exports = {
	eme: {
	/**
	 * create a EME-PKCS1-v1_5 padding (See RFC4880 13.1.1)
	 * @param {String} message message to be padded
	 * @param {Integer} length Length to the resulting message
	 * @return {String} EME-PKCS1 padded message
	 */
	encode: function(message, length) {
		if (message.length > length-11)
			return -1;
		var result = "";
		result += String.fromCharCode(0);
		result += String.fromCharCode(2);
		for (var i = 0; i < length - message.length - 3; i++) {
			result += String.fromCharCode(random.getPseudoRandom(1,255));
		}
		result += String.fromCharCode(0);
		result += message;
		return result;
	},

	/**
	 * decodes a EME-PKCS1-v1_5 padding (See RFC4880 13.1.2)
	 * @param {String} message EME-PKCS1 padded message
	 * @return {String} decoded message 
	 */
	 decode: function(message, len) {
		if (message.length < len)
			message = String.fromCharCode(0)+message;
		if (message.length < 12 || message.charCodeAt(0) != 0 || message.charCodeAt(1) != 2)
			return -1;
		var i = 2;
		while (message.charCodeAt(i) != 0 && message.length > i)
			i++;
		return message.substring(i+1, message.length);
	},
	},

	emsa: {

	/**
	 * create a EMSA-PKCS1-v1_5 padding (See RFC4880 13.1.3)
	 * @param {Integer} algo Hash algorithm type used
	 * @param {String} data Data to be hashed
	 * @param {Integer} keylength Key size of the public mpi in bytes
	 * @returns {String} Hashcode with pkcs1padding as string
	 */
	encode: function(algo, data, keylength) {
		var data2 = "";
		data2 += String.fromCharCode(0x00);
		data2 += String.fromCharCode(0x01);
		for (var i = 0; i < (keylength - hash_headers[algo].length - 3 - 
			hash.getHashByteLength(algo)); i++)

			data2 += String.fromCharCode(0xff);

		data2 += String.fromCharCode(0x00);
		
		for (var i = 0; i < hash_headers[algo].length; i++)
			data2 += String.fromCharCode(hash_headers[algo][i]);
		
		data2 += hash.digest(algo, data);
		return new BigInteger(util.hexstrdump(data2),16);
	},

	/**
	 * extract the hash out of an EMSA-PKCS1-v1.5 padding (See RFC4880 13.1.3) 
	 * @param {String} data Hash in pkcs1 encoding
	 * @returns {String} The hash as string
	 */
	decode: function(algo, data) { 
		var i = 0;
		if (data.charCodeAt(0) == 0) i++;
		else if (data.charCodeAt(0) != 1) return -1;
		else i++;

		while (data.charCodeAt(i) == 0xFF) i++;
		if (data.charCodeAt(i++) != 0) return -1;
		var j = 0;
		for (j = 0; j < hash_headers[algo].length && j+i < data.length; j++) {
			if (data.charCodeAt(j+i) != hash_headers[algo][j]) return -1;
		}
		i+= j;	
		if (data.substring(i).length < hash.getHashByteLength(algo)) return -1;
		return data.substring(i);
	}
	}
}

},{"./crypto.js":16,"./random.js":37,"./public_key/jsbn.js":13,"../util":7,"./hash":18}],20:[function(require,module,exports){
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

var enums = require('../enums.js'),
	util = require('../util');


module.exports = {
	readSimpleLength: function(bytes) {
		var len = 0,
			offset,
			type = bytes[0].charCodeAt();


		if (type < 192) {
			len = bytes[0].charCodeAt();
			offset = 1;
		} else if (type < 255) {
			len = ((bytes[0].charCodeAt() - 192) << 8) + (bytes[1].charCodeAt()) + 192;
			offset = 2;
		} else if (type == 255) {
			len = util.readNumber(bytes.substr(1, 4));
			offset = 5;
		}

		return { len: len, offset: offset };
	},

	/**
	 * Encodes a given integer of length to the openpgp length specifier to a
	 * string
	 * 
	 * @param {Integer} length The length to encode
	 * @return {String} String with openpgp length representation
	 */
	writeSimpleLength: function(length) {
		var result = "";
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
			result += util.writeNumber(length, 4);
		}
		return result;
	},

	/**
	 * Writes a packet header version 4 with the given tag_type and length to a
	 * string
	 * 
	 * @param {Integer} tag_type Tag type
	 * @param {Integer} length Length of the payload
	 * @return {String} String of the header
	 */
	writeHeader: function(tag_type, length) {
		/* we're only generating v4 packet headers here */
		var result = "";
		result += String.fromCharCode(0xC0 | tag_type);
		result += this.writeSimpleLength(length);
		return result;
	},

	/**
	 * Writes a packet header Version 3 with the given tag_type and length to a
	 * string
	 * 
	 * @param {Integer} tag_type Tag type
	 * @param {Integer} length Length of the payload
	 * @return {String} String of the header
	 */
	writeOldHeader: function(tag_type, length) {
		var result = "";
		if (length < 256) {
			result += String.fromCharCode(0x80 | (tag_type << 2));
			result += String.fromCharCode(length);
		} else if (length < 65536) {
			result += String.fromCharCode(0x80 | (tag_type << 2) | 1);
			result += util.writeNumber(length, 2);
		} else {
			result += String.fromCharCode(0x80 | (tag_type << 2) | 2);
			result += util.writeNumber(length, 4);
		}
		return result;
	},

	/**
	 * Generic static Packet Parser function
	 * 
	 * @param {String} input Input stream as string
	 * @param {integer} position Position to start parsing
	 * @param {integer} len Length of the input from position on
	 * @return {Object} Returns a parsed openpgp_packet
	 */
	read: function(input, position, len) {
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
		var packet_length;

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
				real_packet_length = mypos2;
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

		return { 
			tag: tag,
			packet: bodydata,
			offset: mypos + real_packet_length
		};
	}
}


},{"../enums.js":10,"../util":7}],25:[function(require,module,exports){
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

var util = require('../util'),
	enums = require('../enums.js');

/**
 * @class
 * @classdesc Implementation of the Literal Data Packet (Tag 11)
 * 
 * RFC4880 5.9: A Literal Data packet contains the body of a message; data that
 * is not to be further interpreted.
 */
module.exports = function packet_literal() {
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

		var format = enums.read(enums.literal, bytes[0].charCodeAt());

		var filename_len = bytes.charCodeAt(1);
		this.filename = util.decode_utf8(bytes.substr(2, filename_len));

		this.date = util.readDate(bytes.substr(2
				+ filename_len, 4));

		var data = bytes.substring(6 + filename_len);
	
		this.setBytes(data, format);
	}

	/**
	 * Creates a string representation of the packet
	 * 
	 * @param {String} data The data to be inserted as body
	 * @return {String} string-representation of the packet
	 */
	this.write = function() {
		var filename = util.encode_utf8("msg.txt");

		var data = this.getBytes();

		var result = '';
		result += String.fromCharCode(enums.write(enums.literal, this.format));
		result += String.fromCharCode(filename.length);
		result += filename;
		result += util.writeDate(this.date);
		result += data;
		return result;
	}
}

},{"../enums.js":10,"../util":7}],32:[function(require,module,exports){
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

var publicKey = require('./public_key.js'),
	util = require('../util'),
	crypto = require('../crypto');

/**
 * @class
 * @classdesc Implementation of the Key Material Packet (Tag 5,6,7,14)
 *   
 * RFC4480 5.5:
 * A key material packet contains all the information about a public or
 * private key.  There are four variants of this packet type, and two
 * major versions.  Consequently, this section is complex.
 */
function packet_secret_key() {
	publicKey.call(this);

	this.encrypted = null;


	function get_hash_len(hash) {
		if(hash == openpgp.hash.sha1)
			return 20;
		else
			return 2;
	}

	function get_hash_fn(hash) {
		if(hash == openpgp.hash.sha1)
			return str_sha1;
		else
			return function(c) {
					return util.writeNumber(util.calc_checksum(c), 2);
				}
	}

	// Helper function
	function parse_cleartext_mpi(hash_algorithm, cleartext, algorithm) {
		var hashlen = get_hash_len(hash_algorithm),
			hashfn = get_hash_fn(hash_algorithm);

		var hashtext = cleartext.substr(cleartext.length - hashlen);
		cleartext = cleartext.substr(0, cleartext.length - hashlen);

		var hash = hashfn(cleartext);

		if(hash != hashtext)
			throw new Error("Hash mismatch.");

		var mpis = crypto.getPrivateMpiCount(algorithm);

		var j = 0;
		var mpi = [];
		for(var i = 0; i < mpis && j < cleartext.length; i++) {
			mpi[i] = new openpgp_type_mpi();
			j += mpi[i].read(cleartext.substr(j));
		}

		return mpi;
	}

	function write_cleartext_mpi(hash_algorithm, mpi) {
		var bytes= '';
		var discard = crypto.getPublicMpiCount(this.algorithm);

		for(var i = discard; i < mpi.length; i++) {
			bytes += mpi[i].write();
		}


		bytes += get_hash_fn(hash_algorithm)(bytes);
		
		return bytes;
	}
		

	// 5.5.3.  Secret-Key Packet Formats
	
	/**
	 * Internal parser for private keys as specified in RFC 4880 section 5.5.3
	 * @param {String} bytes Input string to read the packet from
	 * @param {Integer} position Start position for the parser
	 * @param {Integer} len Length of the packet or remaining length of bytes
	 * @return {Object} This object with attributes set by the parser
	 */
	this.read = function(bytes) {
	    // - A Public-Key or Public-Subkey packet, as described above.
		var len = this.readPublicKey(bytes);

	    bytes = bytes.substr(len);

		
	    // - One octet indicating string-to-key usage conventions.  Zero
	    //   indicates that the secret-key data is not encrypted.  255 or 254
	    //   indicates that a string-to-key specifier is being given.  Any
	    //   other value is a symmetric-key encryption algorithm identifier.
	    var isEncrypted = bytes[0].charCodeAt();

		if(isEncrypted) {
			this.encrypted = bytes;
		} else {
	
			// - Plain or encrypted multiprecision integers comprising the secret
			//   key data.  These algorithm-specific fields are as described
			//   below.

			this.mpi = this.mpi.concat(parse_cleartext_mpi('mod', bytes.substr(1),
				this.algorithm));
		}    

	}
	
	/*
     * Creates an OpenPGP key packet for the given key. much 
	 * TODO in regards to s2k, subkeys.
     * @param {Integer} keyType Follows the OpenPGP algorithm standard, 
	 * IE 1 corresponds to RSA.
     * @param {RSA.keyObject} key
     * @param passphrase
     * @param s2kHash
     * @param symmetricEncryptionAlgorithm
     * @param timePacket
     * @return {Object} {body: [string]OpenPGP packet body contents, 
		header: [string] OpenPGP packet header, string: [string] header+body}
     */
    this.write = function() {
		var bytes = this.writePublicKey();

		if(!this.encrypted) {
			bytes += String.fromCharCode(0);
			
			bytes += write_cleartext_mpi('mod', this.mpi);
		} else {
			bytes += this.encrypted;
		}

		return bytes;
	}
			



	/** Encrypt the payload. By default, we use aes256 and iterated, salted string
	 * to key specifier
	 * @param {String} passphrase
	 */
    this.encrypt = function(passphrase) {

		var s2k = new openpgp_type_s2k(),
			symmetric = openpgp.symmetric.aes256,
			cleartext = write_cleartext_mpi(openpgp.hash.sha1, this.mpi),
			key = produceEncryptionKey(s2k, passphrase, symmetric),
			blockLen = openpgp_crypto_getBlockLength(symmetric),
			iv = openpgp_crypto_getRandomBytes(blockLen);


		this.encrypted = '';
		this.encrypted += String.fromCharCode(254);
		this.encrypted += String.fromCharCode(symmetric);
		this.encrypted += s2k.write();
		this.encrypted += iv;

		console.log(cleartext);

		switch(symmetric) {
		case 3:
			this.encrypted += normal_cfb_encrypt(function(block, key) {
				var cast5 = new openpgp_symenc_cast5();
				cast5.setKey(key);
				return cast5.encrypt(util.str2bin(block)); 
			}, iv.length, key, cleartext, iv);
			break;
		case 7:
		case 8:
		case 9:
    		var fn = function(block,key) {
    		    	return AESencrypt(util.str2bin(block),key);
    			}
			this.encrypted += normal_cfb_encrypt(fn,
					iv.length, new keyExpansion(key), cleartext, iv);
			break;
		default:
			throw new Error("Unsupported symmetric encryption algorithm.");
		}
    }

	function produceEncryptionKey(s2k, passphrase, algorithm) {
		return s2k.produce_key(passphrase,
			openpgp_crypto_getKeyLength(algorithm));
	}

	/**
	 * Decrypts the private key MPIs which are needed to use the key.
	 * openpgp_packet_keymaterial.hasUnencryptedSecretKeyData should be 
	 * false otherwise
	 * a call to this function is not needed
	 * 
	 * @param {String} str_passphrase The passphrase for this private key 
	 * as string
	 * @return {Boolean} True if the passphrase was correct; false if not
	 */
	this.decrypt = function(passphrase) {
		if (!this.encrypted)
			return;

		var i = 0,
			symmetric,
			key;

		var s2k_usage = this.encrypted[i++].charCodeAt();

	    // - [Optional] If string-to-key usage octet was 255 or 254, a one-
	    //   octet symmetric encryption algorithm.
	    if (s2k_usage == 255 || s2k_usage == 254) {
	    	symmetric = this.encrypted[i++].charCodeAt();
	     
			// - [Optional] If string-to-key usage octet was 255 or 254, a
			//   string-to-key specifier.  The length of the string-to-key
			//   specifier is implied by its type, as described above.
	    	var s2k = new openpgp_type_s2k();
	    	i += s2k.read(this.encrypted.substr(i));

			key = produceEncryptionKey(s2k, passphrase, symmetric);
	    } else {
			symmetric = s2k_usage;
			key = MD5(passphrase);
		}
	    
	    // - [Optional] If secret data is encrypted (string-to-key usage octet
	    //   not zero), an Initial Vector (IV) of the same length as the
	    //   cipher's block size.
		var iv = this.encrypted.substr(i, 
			openpgp_crypto_getBlockLength(symmetric));

		i += iv.length;

		var cleartext,
			ciphertext = this.encrypted.substr(i);


    	switch (symmetric) {
	    case  1: // - IDEA [IDEA]
			throw new Error("IDEA is not implemented.");
	    	return false;
    	case  2: // - TripleDES (DES-EDE, [SCHNEIER] [HAC] - 168 bit key derived from 192)
    		cleartext = normal_cfb_decrypt(function(block, key) {
    			return des(key, block,1,null,0);
    		}, iv.length, key, ciphertext, iv);
    		break;
    	case  3: // - CAST5 (128 bit key, as per [RFC2144])
    		cleartext = normal_cfb_decrypt(function(block, key) {
        		var cast5 = new openpgp_symenc_cast5();
        		cast5.setKey(key);
        		return cast5.encrypt(util.str2bin(block)); 
    		}, iv.length, util.str2bin(key.substring(0,16)), ciphertext, iv);
    		break;
	    case  4: // - Blowfish (128 bit key, 16 rounds) [BLOWFISH]
	    	cleartext = normal_cfb_decrypt(function(block, key) {
    			var blowfish = new Blowfish(key);
        		return blowfish.encrypt(block); 
    		}, iv.length, key, ciphertext, iv);
    		break;
	    case  7: // - AES with 128-bit key [AES]
    	case  8: // - AES with 192-bit key
    	case  9: // - AES with 256-bit key
    		cleartext = normal_cfb_decrypt(function(block,key){
    		    	return AESencrypt(util.str2bin(block),key);
    			},
    			iv.length, new keyExpansion(key), 
					ciphertext, iv);
	    	break;
    	case 10: // - Twofish with 256-bit key [TWOFISH]
			throw new Error("Twofish is not implemented.");
	    	return false;
    	case  5: // - Reserved
    	case  6: // - Reserved
    	default:
			throw new Error("Unknown symmetric algorithm.");
    		return false;
    	}
 
		var hash;
		if(s2k_usage == 254)
			hash = openpgp.hash.sha1;
		else
			hash = 'mod';

   	
		this.mpi = this.mpi.concat(parse_cleartext_mpi(hash, cleartext,
			this.algorithm));
	}
	
}

packet_secret_key.prototype = new publicKey;

module.exports = packet_secret_key;

},{"./public_key.js":26,"../util":7,"../crypto":6}],33:[function(require,module,exports){
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

},{"../util":7}],35:[function(require,module,exports){
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

var util = require('../util'),
	packet = require('./packet.js'),
	enums = require('../enums.js'),
	crypto = require('../crypto'),
	type_mpi = require('../type/mpi.js');

/**
 * @class
 * @classdesc Implementation of the Signature Packet (Tag 2)
 * 
 * RFC4480 5.2:
 * A Signature packet describes a binding between some public key and
 * some data.  The most common signatures are a signature of a file or a
 * block of text, and a signature that is a certification of a User ID.
 */
module.exports = function packet_signature() {

	this.signatureType = null;
	this.hashAlgorithm = null;
	this.publicKeyAlgorithm = null; 

	this.signatureData = null;
	this.signedHashValue = null;
	this.mpi = null;

	this.created = null;
	this.signatureExpirationTime = null;
	this.signatureNeverExpires = null;
	this.exportable = null;
	this.trustLevel = null;
	this.trustAmount = null;
	this.regularExpression = null;
	this.revocable = null;
	this.keyExpirationTime = null;
	this.keyNeverExpires = null;
	this.preferredSymmetricAlgorithms = null;
	this.revocationKeyClass = null;
	this.revocationKeyAlgorithm = null;
	this.revocationKeyFingerprint = null;
	this.issuerKeyId = null;
	this.notation = {};
	this.preferredHashAlgorithms = null;
	this.preferredCompressionAlgorithms = null;
	this.keyServerPreferences = null;
	this.preferredKeyServer = null;
	this.isPrimaryUserID = null;
	this.policyURI = null;
	this.keyFlags = null;
	this.signersUserId = null;
	this.reasonForRevocationFlag = null;
	this.reasonForRevocationString = null;
	this.signatureTargetPublicKeyAlgorithm = null;
	this.signatureTargetHashAlgorithm = null;
	this.signatureTargetHash = null;
	this.embeddedSignature = null;

	this.verified = false;
	

	/**
	 * parsing function for a signature packet (tag 2).
	 * @param {String} bytes payload of a tag 2 packet
	 * @param {Integer} position position to start reading from the bytes string
	 * @param {Integer} len length of the packet or the remaining length of bytes at position
	 * @return {openpgp_packet_encrypteddata} object representation
	 */
	this.read = function(bytes) {
		var i = 0;

		var version = bytes[i++].charCodeAt();
		// switch on version (3 and 4)
		switch (version) {
		case 3:
			// One-octet length of following hashed material. MUST be 5.
			if (bytes[i++].charCodeAt() != 5)
				util.print_debug("openpgp.packet.signature.js\n"+
					'invalid One-octet length of following hashed material.' +
					'MUST be 5. @:'+(i-1));

			var sigpos = i;
			// One-octet signature type.
			this.signatureType = bytes[i++].charCodeAt();

			// Four-octet creation time.
			this.created = util.readDate(bytes.substr(i, 4));
			i += 4;
			
			// storing data appended to data which gets verified
			this.signatureData = bytes.substring(position, i);
			
			// Eight-octet Key ID of signer.
			this.issuerKeyId = bytes.substring(i, i +8);
			i += 8;

			// One-octet public-key algorithm.
			this.publicKeyAlgorithm = bytes[i++].charCodeAt();

			// One-octet hash algorithm.
			this.hashAlgorithm = bytes[i++].charCodeAt();
		break;
		case 4:
			this.signatureType = bytes[i++].charCodeAt();
			this.publicKeyAlgorithm = bytes[i++].charCodeAt();
			this.hashAlgorithm = bytes[i++].charCodeAt();


			function subpackets(bytes, signed) {
				// Two-octet scalar octet count for following hashed subpacket
				// data.
				var subpacket_length = util.readNumber(
					bytes.substr(0, 2));

				var i = 2;

				// Hashed subpacket data set (zero or more subpackets)
				var subpacked_read = 0;
				while (i < 2 + subpacket_length) {

					var len = packet.readSimpleLength(bytes.substr(i));
					i += len.offset;

					// Since it is trivial to add data to the unhashed portion of 
					// the packet we simply ignore all unauthenticated data.
					if(signed)
						this.read_sub_packet(bytes.substr(i, len.len));

					i += len.len;
				}
				
				return i;
			}
			
			i += subpackets.call(this, bytes.substr(i), true);

			// A V4 signature hashes the packet body
			// starting from its first field, the version number, through the end
			// of the hashed subpacket data.  Thus, the fields hashed are the
			// signature version, the signature type, the public-key algorithm, the
			// hash algorithm, the hashed subpacket length, and the hashed
			// subpacket body.
			this.signatureData = bytes.substr(0, i);

			i += subpackets.call(this, bytes.substr(i), false);

			break;
		default:
			throw new Error('Version ' + version + ' of the signature is unsupported.');
			break;
		}

		// Two-octet field holding left 16 bits of signed hash value.
		this.signedHashValue = bytes.substr(i, 2);
		i += 2;

		this.signature = bytes.substr(i);
	}

	this.write = function() {
		return this.signatureData + 
			util.writeNumber(0, 2) + // Number of unsigned subpackets.
			this.signedHashValue +
			this.signature;
	}

	/**
	 * Signs provided data. This needs to be done prior to serialization.
	 * @param {Object} data Contains packets to be signed.
	 * @param {openpgp_msg_privatekey} privatekey private key used to sign the message. 
	 */
	this.sign = function(key, data) {
		var signatureType = enums.write(enums.signature, this.signatureType),
			publicKeyAlgorithm = enums.write(enums.publicKey, this.publicKeyAlgorithm),
			hashAlgorithm = enums.write(enums.hash, this.hashAlgorithm);

		var result = String.fromCharCode(4); 
		result += String.fromCharCode(signatureType);
		result += String.fromCharCode(publicKeyAlgorithm);
		result += String.fromCharCode(hashAlgorithm);


		// Add subpackets here
		result += util.writeNumber(0, 2);


		this.signatureData = result;

		var trailer = this.calculateTrailer();
		
		var toHash = this.toSign(signatureType, data) + 
			this.signatureData + trailer;

		var hash = crypto.hash.digest(hashAlgorithm, toHash);
		
		this.signedHashValue = hash.substr(0, 2);


		this.signature = crypto.signature.sign(hashAlgorithm, 
			publicKeyAlgorithm, key.mpi, toHash);
	}

	/**
	 * creates a string representation of a sub signature packet (See RFC 4880 5.2.3.1)
	 * @param {Integer} type subpacket signature type. Signature types as described 
	 * in RFC4880 Section 5.2.3.2
	 * @param {String} data data to be included
	 * @return {String} a string-representation of a sub signature packet (See RFC 4880 5.2.3.1)
	 */
	function write_sub_packet(type, data) {
		var result = "";
		result += packet.writeSimpleLength(data.length+1);
		result += String.fromCharCode(type);
		result += data;
		return result;
	}
	
	// V4 signature sub packets
	
	this.read_sub_packet = function(bytes) {
		var mypos = 0;

		function read_array(prop, bytes) {
			this[prop] = [];

			for (var i = 0; i < bytes.length; i++) {
				this[prop].push(bytes[i].charCodeAt());
			}
		}
		
		// The leftwost bit denotes a "critical" packet, but we ignore it.
		var type = bytes[mypos++].charCodeAt() & 0x7F;

		// subpacket type
		switch (type) {
		case 2: // Signature Creation Time
			this.created = util.readDate(bytes.substr(mypos));
			break;
		case 3: // Signature Expiration Time
			var time = util.readDate(bytes.substr(mypos));

			this.signatureNeverExpires = time.getTime() == 0;
			this.signatureExpirationTime = time;
			
			break;
		case 4: // Exportable Certification
			this.exportable = bytes[mypos++].charCodeAt() == 1;
			break;
		case 5: // Trust Signature
			this.trustLevel = bytes[mypos++].charCodeAt();
			this.trustAmount = bytes[mypos++].charCodeAt();
			break;
		case 6: // Regular Expression
			this.regularExpression = bytes.substr(mypos);
			break;
		case 7: // Revocable
			this.revocable = bytes[mypos++].charCodeAt() == 1;
			break;
		case 9: // Key Expiration Time
			var time = util.readDate(bytes.substr(mypos));

			this.keyExpirationTime = time;
			this.keyNeverExpires = time.getTime() == 0;

			break;
		case 11: // Preferred Symmetric Algorithms
			this.preferredSymmetricAlgorithms = [];

			while(mypos != bytes.length) {
				this.preferredSymmetricAlgorithms.push(bytes[mypos++].charCodeAt());
			}

			break;
		case 12: // Revocation Key
			// (1 octet of class, 1 octet of public-key algorithm ID, 20
			// octets of
			// fingerprint)
			this.revocationKeyClass = bytes[mypos++].charCodeAt();
			this.revocationKeyAlgorithm = bytes[mypos++].charCodeAt();
			this.revocationKeyFingerprint = bytes.substr(mypos, 20);
			break;

		case 16: // Issuer
			this.issuerKeyId = bytes.substr(mypos, 8);
			break;

		case 20: // Notation Data
			// We don't know how to handle anything but a text flagged data.
			if(bytes[mypos].charCodeAt() == 0x80) {

				// We extract key/value tuple from the byte stream.
				mypos += 4;
				var m = util.writeNumber(bytes.substr(mypos, 2));
				mypos += 2
				var n = util.writeNumber(bytes.substr(mypos, 2));
				mypos += 2

				var name = bytes.substr(mypos, m),
					value = bytes.substr(mypos + m, n);

				this.notation[name] = value;
			}
			else throw new Error("Unsupported notation flag.");
			break;
		case 21: // Preferred Hash Algorithms
			read_array.call(this, 'preferredHashAlgorithms', bytes.substr(mypos));
			break;
		case 22: // Preferred Compression Algorithms
			read_array.call(this, 'preferredCompressionAlgorithms ', bytes.substr(mypos));
			break;
		case 23: // Key Server Preferences
			read_array.call(this, 'keyServerPreferencess', bytes.substr(mypos));
			break;
		case 24: // Preferred Key Server
			this.preferredKeyServer = bytes.substr(mypos);
			break;
		case 25: // Primary User ID
			this.isPrimaryUserID = bytes[mypos++] != 0;
			break;
		case 26: // Policy URI
			this.policyURI = bytes.substr(mypos);
			break;
		case 27: // Key Flags
			read_array.call(this, 'keyFlags', bytes.substr(mypos));
			break;
		case 28: // Signer's User ID
			this.signersUserId += bytes.substr(mypos);
			break;
		case 29: // Reason for Revocation
			this.reasonForRevocationFlag = bytes[mypos++].charCodeAt();
			this.reasonForRevocationString = bytes.substr(mypos);
			break;
		case 30: // Features
			read_array.call(this, 'features', bytes.substr(mypos));
			break;
		case 31: // Signature Target
			// (1 octet public-key algorithm, 1 octet hash algorithm, N octets hash)
			this.signatureTargetPublicKeyAlgorithm = bytes[mypos++].charCodeAt();
			this.signatureTargetHashAlgorithm = bytes[mypos++].charCodeAt();

			var len = crypto.getHashByteLength(this.signatureTargetHashAlgorithm);

			this.signatureTargetHash = bytes.substr(mypos, len);
			break;
		case 32: // Embedded Signature
			this.embeddedSignature = new packet_signature();
			this.embeddedSignature.read(bytes.substr(mypos));
			break;
		default:
			util.print_error("openpgp.packet.signature.js\n"+
				'unknown signature subpacket type '+type+" @:"+mypos+
				" subplen:"+subplen+" len:"+len);
			break;
		}
	};

	// Produces data to produce signature on
	this.toSign = function(type, data) {
		var t = enums.signature

		switch(type) {
		case t.binary:
			return data.literal.getBytes();

		case t.text:
			return this.toSign(t.binary, data)
				.replace(/\r\n/g, '\n')
				.replace(/\n/g, '\r\n');
				
		case t.standalone:
			return ''

		case t.cert_generic:
		case t.cert_persona:
		case t.cert_casual:
		case t.cert_positive:
		case t.cert_revocation:
		{
			var packet, tag;

			if(data.userid != undefined) {
				tag = 0xB4;
				packet = data.userid;
			}
			else if(data.userattribute != undefined) {
				tag = 0xD1
				packet = data.userattribute;
			}
			else throw new Error('Either a userid or userattribute packet needs to be ' +
				'supplied for certification.');


			var bytes = packet.write();

			
			return this.toSign(t.key, data) +
				String.fromCharCode(tag) +
				util.writeNumber(bytes.length, 4) +
				bytes;
		}
		case t.subkey_binding:
		case t.key_binding:
		{
			return this.toSign(t.key, data) + this.toSign(t.key, { key: data.bind });
		}
		case t.key:
		{
			if(data.key == undefined)
				throw new Error('Key packet is required for this sigtature.');
			
			return data.key.writeOld();
		}
		case t.key_revocation:
		case t.subkey_revocation:
			return this.toSign(t.key, data);
		case t.timestamp:
			return '';
		case t.thrid_party:
			throw new Error('Not implemented');
			break;
		default:
			throw new Error('Unknown signature type.')
		}
	}

	
	this.calculateTrailer = function() {
		// calculating the trailer
		var trailer = '';
		trailer += String.fromCharCode(4); // Version
		trailer += String.fromCharCode(0xFF);
		trailer += util.writeNumber(this.signatureData.length, 4);
		return trailer
	}


	/**
	 * verifys the signature packet. Note: not signature types are implemented
	 * @param {String} data data which on the signature applies
	 * @param {openpgp_msg_privatekey} key the public key to verify the signature
	 * @return {boolean} True if message is verified, else false.
	 */
	this.verify = function(key, data) {
		var signatureType = enums.write(enums.signature, this.signatureType),
			publicKeyAlgorithm = enums.write(enums.publicKey, this.publicKeyAlgorithm),
			hashAlgorithm = enums.write(enums.hash, this.hashAlgorithm);

		var bytes = this.toSign(signatureType, data),
			trailer = this.calculateTrailer();


		var mpicount = 0;
		// Algorithm-Specific Fields for RSA signatures:
		// 	    - multiprecision number (MPI) of RSA signature value m**d mod n.
		if (publicKeyAlgorithm > 0 && publicKeyAlgorithm < 4)
			mpicount = 1;
		//    Algorithm-Specific Fields for DSA signatures:
		//      - MPI of DSA value r.
		//      - MPI of DSA value s.
		else if (publicKeyAlgorithm == 17)
			mpicount = 2;
		
		var mpi = [], i = 0;
		for (var j = 0; j < mpicount; j++) {
			mpi[j] = new type_mpi();
			i += mpi[j].read(this.signature.substr(i));
		}

		this.verified = crypto.signature.verify(publicKeyAlgorithm, 
			hashAlgorithm, mpi, key.mpi, 
			bytes + this.signatureData + trailer);

		return this.verified;
	}
}


},{"./packet.js":20,"../enums.js":10,"../type/mpi.js":4,"../util":7,"../crypto":6}],38:[function(require,module,exports){

/* Rijndael (AES) Encryption
 * Copyright 2005 Herbert Hanewinkel, www.haneWIN.de
 * version 1.1, check www.haneWIN.de for the latest version

 * This software is provided as-is, without express or implied warranty.  
 * Permission to use, copy, modify, distribute or sell this software, with or
 * without fee, for any purpose and by any individual or organization, is hereby
 * granted, provided that the above copyright notice and this paragraph appear 
 * in all copies. Distribution as a part of an application or binary must
 * include the above copyright notice in the documentation and/or other
 * materials provided with the application or distribution.
 */

var util = require('../../util');

// The round constants used in subkey expansion
var Rcon = [ 
0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 
0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91 ];

// Precomputed lookup table for the SBox
var S = [
 99, 124, 119, 123, 242, 107, 111, 197,  48,   1, 103,  43, 254, 215, 171, 
118, 202, 130, 201, 125, 250,  89,  71, 240, 173, 212, 162, 175, 156, 164, 
114, 192, 183, 253, 147,  38,  54,  63, 247, 204,  52, 165, 229, 241, 113, 
216,  49,  21,   4, 199,  35, 195,  24, 150,   5, 154,   7,  18, 128, 226, 
235,  39, 178, 117,   9, 131,  44,  26,  27, 110,  90, 160,  82,  59, 214, 
179,  41, 227,  47, 132,  83, 209,   0, 237,  32, 252, 177,  91, 106, 203, 
190,  57,  74,  76,  88, 207, 208, 239, 170, 251,  67,  77,  51, 133,  69, 
249,   2, 127,  80,  60, 159, 168,  81, 163,  64, 143, 146, 157,  56, 245, 
188, 182, 218,  33,  16, 255, 243, 210, 205,  12,  19, 236,  95, 151,  68,  
23,  196, 167, 126,  61, 100,  93,  25, 115,  96, 129,  79, 220,  34,  42, 
144, 136,  70, 238, 184,  20, 222,  94,  11, 219, 224,  50,  58,  10,  73,
  6,  36,  92, 194, 211, 172,  98, 145, 149, 228, 121, 231, 200,  55, 109, 
141, 213,  78, 169, 108,  86, 244, 234, 101, 122, 174,   8, 186, 120,  37,  
 46,  28, 166, 180, 198, 232, 221, 116,  31,  75, 189, 139, 138, 112,  62, 
181, 102,  72,   3, 246,  14,  97,  53,  87, 185, 134, 193,  29, 158, 225,
248, 152,  17, 105, 217, 142, 148, 155,  30, 135, 233, 206,  85,  40, 223,
140, 161, 137,  13, 191, 230,  66, 104,  65, 153,  45,  15, 176,  84, 187,  
 22 ];

var T1 = [
0xa56363c6, 0x847c7cf8, 0x997777ee, 0x8d7b7bf6,
0x0df2f2ff, 0xbd6b6bd6, 0xb16f6fde, 0x54c5c591,
0x50303060, 0x03010102, 0xa96767ce, 0x7d2b2b56,
0x19fefee7, 0x62d7d7b5, 0xe6abab4d, 0x9a7676ec,
0x45caca8f, 0x9d82821f, 0x40c9c989, 0x877d7dfa,
0x15fafaef, 0xeb5959b2, 0xc947478e, 0x0bf0f0fb,
0xecadad41, 0x67d4d4b3, 0xfda2a25f, 0xeaafaf45,
0xbf9c9c23, 0xf7a4a453, 0x967272e4, 0x5bc0c09b,
0xc2b7b775, 0x1cfdfde1, 0xae93933d, 0x6a26264c,
0x5a36366c, 0x413f3f7e, 0x02f7f7f5, 0x4fcccc83,
0x5c343468, 0xf4a5a551, 0x34e5e5d1, 0x08f1f1f9,
0x937171e2, 0x73d8d8ab, 0x53313162, 0x3f15152a,
0x0c040408, 0x52c7c795, 0x65232346, 0x5ec3c39d,
0x28181830, 0xa1969637, 0x0f05050a, 0xb59a9a2f,
0x0907070e, 0x36121224, 0x9b80801b, 0x3de2e2df,
0x26ebebcd, 0x6927274e, 0xcdb2b27f, 0x9f7575ea,
0x1b090912, 0x9e83831d, 0x742c2c58, 0x2e1a1a34,
0x2d1b1b36, 0xb26e6edc, 0xee5a5ab4, 0xfba0a05b,
0xf65252a4, 0x4d3b3b76, 0x61d6d6b7, 0xceb3b37d,
0x7b292952, 0x3ee3e3dd, 0x712f2f5e, 0x97848413,
0xf55353a6, 0x68d1d1b9, 0x00000000, 0x2cededc1,
0x60202040, 0x1ffcfce3, 0xc8b1b179, 0xed5b5bb6,
0xbe6a6ad4, 0x46cbcb8d, 0xd9bebe67, 0x4b393972,
0xde4a4a94, 0xd44c4c98, 0xe85858b0, 0x4acfcf85,
0x6bd0d0bb, 0x2aefefc5, 0xe5aaaa4f, 0x16fbfbed,
0xc5434386, 0xd74d4d9a, 0x55333366, 0x94858511,
0xcf45458a, 0x10f9f9e9, 0x06020204, 0x817f7ffe,
0xf05050a0, 0x443c3c78, 0xba9f9f25, 0xe3a8a84b,
0xf35151a2, 0xfea3a35d, 0xc0404080, 0x8a8f8f05,
0xad92923f, 0xbc9d9d21, 0x48383870, 0x04f5f5f1,
0xdfbcbc63, 0xc1b6b677, 0x75dadaaf, 0x63212142,
0x30101020, 0x1affffe5, 0x0ef3f3fd, 0x6dd2d2bf,
0x4ccdcd81, 0x140c0c18, 0x35131326, 0x2fececc3,
0xe15f5fbe, 0xa2979735, 0xcc444488, 0x3917172e,
0x57c4c493, 0xf2a7a755, 0x827e7efc, 0x473d3d7a,
0xac6464c8, 0xe75d5dba, 0x2b191932, 0x957373e6,
0xa06060c0, 0x98818119, 0xd14f4f9e, 0x7fdcdca3,
0x66222244, 0x7e2a2a54, 0xab90903b, 0x8388880b,
0xca46468c, 0x29eeeec7, 0xd3b8b86b, 0x3c141428,
0x79dedea7, 0xe25e5ebc, 0x1d0b0b16, 0x76dbdbad,
0x3be0e0db, 0x56323264, 0x4e3a3a74, 0x1e0a0a14,
0xdb494992, 0x0a06060c, 0x6c242448, 0xe45c5cb8,
0x5dc2c29f, 0x6ed3d3bd, 0xefacac43, 0xa66262c4,
0xa8919139, 0xa4959531, 0x37e4e4d3, 0x8b7979f2,
0x32e7e7d5, 0x43c8c88b, 0x5937376e, 0xb76d6dda,
0x8c8d8d01, 0x64d5d5b1, 0xd24e4e9c, 0xe0a9a949,
0xb46c6cd8, 0xfa5656ac, 0x07f4f4f3, 0x25eaeacf,
0xaf6565ca, 0x8e7a7af4, 0xe9aeae47, 0x18080810,
0xd5baba6f, 0x887878f0, 0x6f25254a, 0x722e2e5c,
0x241c1c38, 0xf1a6a657, 0xc7b4b473, 0x51c6c697,
0x23e8e8cb, 0x7cdddda1, 0x9c7474e8, 0x211f1f3e,
0xdd4b4b96, 0xdcbdbd61, 0x868b8b0d, 0x858a8a0f,
0x907070e0, 0x423e3e7c, 0xc4b5b571, 0xaa6666cc,
0xd8484890, 0x05030306, 0x01f6f6f7, 0x120e0e1c,
0xa36161c2, 0x5f35356a, 0xf95757ae, 0xd0b9b969,
0x91868617, 0x58c1c199, 0x271d1d3a, 0xb99e9e27,
0x38e1e1d9, 0x13f8f8eb, 0xb398982b, 0x33111122,
0xbb6969d2, 0x70d9d9a9, 0x898e8e07, 0xa7949433,
0xb69b9b2d, 0x221e1e3c, 0x92878715, 0x20e9e9c9,
0x49cece87, 0xff5555aa, 0x78282850, 0x7adfdfa5,
0x8f8c8c03, 0xf8a1a159, 0x80898909, 0x170d0d1a,
0xdabfbf65, 0x31e6e6d7, 0xc6424284, 0xb86868d0,
0xc3414182, 0xb0999929, 0x772d2d5a, 0x110f0f1e,
0xcbb0b07b, 0xfc5454a8, 0xd6bbbb6d, 0x3a16162c ];

var T2 = [
0x6363c6a5, 0x7c7cf884, 0x7777ee99, 0x7b7bf68d,
0xf2f2ff0d, 0x6b6bd6bd, 0x6f6fdeb1, 0xc5c59154,
0x30306050, 0x01010203, 0x6767cea9, 0x2b2b567d,
0xfefee719, 0xd7d7b562, 0xabab4de6, 0x7676ec9a,
0xcaca8f45, 0x82821f9d, 0xc9c98940, 0x7d7dfa87,
0xfafaef15, 0x5959b2eb, 0x47478ec9, 0xf0f0fb0b,
0xadad41ec, 0xd4d4b367, 0xa2a25ffd, 0xafaf45ea,
0x9c9c23bf, 0xa4a453f7, 0x7272e496, 0xc0c09b5b,
0xb7b775c2, 0xfdfde11c, 0x93933dae, 0x26264c6a,
0x36366c5a, 0x3f3f7e41, 0xf7f7f502, 0xcccc834f,
0x3434685c, 0xa5a551f4, 0xe5e5d134, 0xf1f1f908,
0x7171e293, 0xd8d8ab73, 0x31316253, 0x15152a3f,
0x0404080c, 0xc7c79552, 0x23234665, 0xc3c39d5e,
0x18183028, 0x969637a1, 0x05050a0f, 0x9a9a2fb5,
0x07070e09, 0x12122436, 0x80801b9b, 0xe2e2df3d,
0xebebcd26, 0x27274e69, 0xb2b27fcd, 0x7575ea9f,
0x0909121b, 0x83831d9e, 0x2c2c5874, 0x1a1a342e,
0x1b1b362d, 0x6e6edcb2, 0x5a5ab4ee, 0xa0a05bfb,
0x5252a4f6, 0x3b3b764d, 0xd6d6b761, 0xb3b37dce,
0x2929527b, 0xe3e3dd3e, 0x2f2f5e71, 0x84841397,
0x5353a6f5, 0xd1d1b968, 0x00000000, 0xededc12c,
0x20204060, 0xfcfce31f, 0xb1b179c8, 0x5b5bb6ed,
0x6a6ad4be, 0xcbcb8d46, 0xbebe67d9, 0x3939724b,
0x4a4a94de, 0x4c4c98d4, 0x5858b0e8, 0xcfcf854a,
0xd0d0bb6b, 0xefefc52a, 0xaaaa4fe5, 0xfbfbed16,
0x434386c5, 0x4d4d9ad7, 0x33336655, 0x85851194,
0x45458acf, 0xf9f9e910, 0x02020406, 0x7f7ffe81,
0x5050a0f0, 0x3c3c7844, 0x9f9f25ba, 0xa8a84be3,
0x5151a2f3, 0xa3a35dfe, 0x404080c0, 0x8f8f058a,
0x92923fad, 0x9d9d21bc, 0x38387048, 0xf5f5f104,
0xbcbc63df, 0xb6b677c1, 0xdadaaf75, 0x21214263,
0x10102030, 0xffffe51a, 0xf3f3fd0e, 0xd2d2bf6d,
0xcdcd814c, 0x0c0c1814, 0x13132635, 0xececc32f,
0x5f5fbee1, 0x979735a2, 0x444488cc, 0x17172e39,
0xc4c49357, 0xa7a755f2, 0x7e7efc82, 0x3d3d7a47,
0x6464c8ac, 0x5d5dbae7, 0x1919322b, 0x7373e695,
0x6060c0a0, 0x81811998, 0x4f4f9ed1, 0xdcdca37f,
0x22224466, 0x2a2a547e, 0x90903bab, 0x88880b83,
0x46468cca, 0xeeeec729, 0xb8b86bd3, 0x1414283c,
0xdedea779, 0x5e5ebce2, 0x0b0b161d, 0xdbdbad76,
0xe0e0db3b, 0x32326456, 0x3a3a744e, 0x0a0a141e,
0x494992db, 0x06060c0a, 0x2424486c, 0x5c5cb8e4,
0xc2c29f5d, 0xd3d3bd6e, 0xacac43ef, 0x6262c4a6,
0x919139a8, 0x959531a4, 0xe4e4d337, 0x7979f28b,
0xe7e7d532, 0xc8c88b43, 0x37376e59, 0x6d6ddab7,
0x8d8d018c, 0xd5d5b164, 0x4e4e9cd2, 0xa9a949e0,
0x6c6cd8b4, 0x5656acfa, 0xf4f4f307, 0xeaeacf25,
0x6565caaf, 0x7a7af48e, 0xaeae47e9, 0x08081018,
0xbaba6fd5, 0x7878f088, 0x25254a6f, 0x2e2e5c72,
0x1c1c3824, 0xa6a657f1, 0xb4b473c7, 0xc6c69751,
0xe8e8cb23, 0xdddda17c, 0x7474e89c, 0x1f1f3e21,
0x4b4b96dd, 0xbdbd61dc, 0x8b8b0d86, 0x8a8a0f85,
0x7070e090, 0x3e3e7c42, 0xb5b571c4, 0x6666ccaa,
0x484890d8, 0x03030605, 0xf6f6f701, 0x0e0e1c12,
0x6161c2a3, 0x35356a5f, 0x5757aef9, 0xb9b969d0,
0x86861791, 0xc1c19958, 0x1d1d3a27, 0x9e9e27b9,
0xe1e1d938, 0xf8f8eb13, 0x98982bb3, 0x11112233,
0x6969d2bb, 0xd9d9a970, 0x8e8e0789, 0x949433a7,
0x9b9b2db6, 0x1e1e3c22, 0x87871592, 0xe9e9c920,
0xcece8749, 0x5555aaff, 0x28285078, 0xdfdfa57a,
0x8c8c038f, 0xa1a159f8, 0x89890980, 0x0d0d1a17,
0xbfbf65da, 0xe6e6d731, 0x424284c6, 0x6868d0b8,
0x414182c3, 0x999929b0, 0x2d2d5a77, 0x0f0f1e11,
0xb0b07bcb, 0x5454a8fc, 0xbbbb6dd6, 0x16162c3a ];

var T3 = [
0x63c6a563, 0x7cf8847c, 0x77ee9977, 0x7bf68d7b,
0xf2ff0df2, 0x6bd6bd6b, 0x6fdeb16f, 0xc59154c5,
0x30605030, 0x01020301, 0x67cea967, 0x2b567d2b,
0xfee719fe, 0xd7b562d7, 0xab4de6ab, 0x76ec9a76,
0xca8f45ca, 0x821f9d82, 0xc98940c9, 0x7dfa877d,
0xfaef15fa, 0x59b2eb59, 0x478ec947, 0xf0fb0bf0,
0xad41ecad, 0xd4b367d4, 0xa25ffda2, 0xaf45eaaf,
0x9c23bf9c, 0xa453f7a4, 0x72e49672, 0xc09b5bc0,
0xb775c2b7, 0xfde11cfd, 0x933dae93, 0x264c6a26,
0x366c5a36, 0x3f7e413f, 0xf7f502f7, 0xcc834fcc,
0x34685c34, 0xa551f4a5, 0xe5d134e5, 0xf1f908f1,
0x71e29371, 0xd8ab73d8, 0x31625331, 0x152a3f15,
0x04080c04, 0xc79552c7, 0x23466523, 0xc39d5ec3,
0x18302818, 0x9637a196, 0x050a0f05, 0x9a2fb59a,
0x070e0907, 0x12243612, 0x801b9b80, 0xe2df3de2,
0xebcd26eb, 0x274e6927, 0xb27fcdb2, 0x75ea9f75,
0x09121b09, 0x831d9e83, 0x2c58742c, 0x1a342e1a,
0x1b362d1b, 0x6edcb26e, 0x5ab4ee5a, 0xa05bfba0,
0x52a4f652, 0x3b764d3b, 0xd6b761d6, 0xb37dceb3,
0x29527b29, 0xe3dd3ee3, 0x2f5e712f, 0x84139784,
0x53a6f553, 0xd1b968d1, 0x00000000, 0xedc12ced,
0x20406020, 0xfce31ffc, 0xb179c8b1, 0x5bb6ed5b,
0x6ad4be6a, 0xcb8d46cb, 0xbe67d9be, 0x39724b39,
0x4a94de4a, 0x4c98d44c, 0x58b0e858, 0xcf854acf,
0xd0bb6bd0, 0xefc52aef, 0xaa4fe5aa, 0xfbed16fb,
0x4386c543, 0x4d9ad74d, 0x33665533, 0x85119485,
0x458acf45, 0xf9e910f9, 0x02040602, 0x7ffe817f,
0x50a0f050, 0x3c78443c, 0x9f25ba9f, 0xa84be3a8,
0x51a2f351, 0xa35dfea3, 0x4080c040, 0x8f058a8f,
0x923fad92, 0x9d21bc9d, 0x38704838, 0xf5f104f5,
0xbc63dfbc, 0xb677c1b6, 0xdaaf75da, 0x21426321,
0x10203010, 0xffe51aff, 0xf3fd0ef3, 0xd2bf6dd2,
0xcd814ccd, 0x0c18140c, 0x13263513, 0xecc32fec,
0x5fbee15f, 0x9735a297, 0x4488cc44, 0x172e3917,
0xc49357c4, 0xa755f2a7, 0x7efc827e, 0x3d7a473d,
0x64c8ac64, 0x5dbae75d, 0x19322b19, 0x73e69573,
0x60c0a060, 0x81199881, 0x4f9ed14f, 0xdca37fdc,
0x22446622, 0x2a547e2a, 0x903bab90, 0x880b8388,
0x468cca46, 0xeec729ee, 0xb86bd3b8, 0x14283c14,
0xdea779de, 0x5ebce25e, 0x0b161d0b, 0xdbad76db,
0xe0db3be0, 0x32645632, 0x3a744e3a, 0x0a141e0a,
0x4992db49, 0x060c0a06, 0x24486c24, 0x5cb8e45c,
0xc29f5dc2, 0xd3bd6ed3, 0xac43efac, 0x62c4a662,
0x9139a891, 0x9531a495, 0xe4d337e4, 0x79f28b79,
0xe7d532e7, 0xc88b43c8, 0x376e5937, 0x6ddab76d,
0x8d018c8d, 0xd5b164d5, 0x4e9cd24e, 0xa949e0a9,
0x6cd8b46c, 0x56acfa56, 0xf4f307f4, 0xeacf25ea,
0x65caaf65, 0x7af48e7a, 0xae47e9ae, 0x08101808,
0xba6fd5ba, 0x78f08878, 0x254a6f25, 0x2e5c722e,
0x1c38241c, 0xa657f1a6, 0xb473c7b4, 0xc69751c6,
0xe8cb23e8, 0xdda17cdd, 0x74e89c74, 0x1f3e211f,
0x4b96dd4b, 0xbd61dcbd, 0x8b0d868b, 0x8a0f858a,
0x70e09070, 0x3e7c423e, 0xb571c4b5, 0x66ccaa66,
0x4890d848, 0x03060503, 0xf6f701f6, 0x0e1c120e,
0x61c2a361, 0x356a5f35, 0x57aef957, 0xb969d0b9,
0x86179186, 0xc19958c1, 0x1d3a271d, 0x9e27b99e,
0xe1d938e1, 0xf8eb13f8, 0x982bb398, 0x11223311,
0x69d2bb69, 0xd9a970d9, 0x8e07898e, 0x9433a794,
0x9b2db69b, 0x1e3c221e, 0x87159287, 0xe9c920e9,
0xce8749ce, 0x55aaff55, 0x28507828, 0xdfa57adf,
0x8c038f8c, 0xa159f8a1, 0x89098089, 0x0d1a170d,
0xbf65dabf, 0xe6d731e6, 0x4284c642, 0x68d0b868,
0x4182c341, 0x9929b099, 0x2d5a772d, 0x0f1e110f,
0xb07bcbb0, 0x54a8fc54, 0xbb6dd6bb, 0x162c3a16 ];

var T4 = [
0xc6a56363, 0xf8847c7c, 0xee997777, 0xf68d7b7b,
0xff0df2f2, 0xd6bd6b6b, 0xdeb16f6f, 0x9154c5c5,
0x60503030, 0x02030101, 0xcea96767, 0x567d2b2b,
0xe719fefe, 0xb562d7d7, 0x4de6abab, 0xec9a7676,
0x8f45caca, 0x1f9d8282, 0x8940c9c9, 0xfa877d7d,
0xef15fafa, 0xb2eb5959, 0x8ec94747, 0xfb0bf0f0,
0x41ecadad, 0xb367d4d4, 0x5ffda2a2, 0x45eaafaf,
0x23bf9c9c, 0x53f7a4a4, 0xe4967272, 0x9b5bc0c0,
0x75c2b7b7, 0xe11cfdfd, 0x3dae9393, 0x4c6a2626,
0x6c5a3636, 0x7e413f3f, 0xf502f7f7, 0x834fcccc,
0x685c3434, 0x51f4a5a5, 0xd134e5e5, 0xf908f1f1,
0xe2937171, 0xab73d8d8, 0x62533131, 0x2a3f1515,
0x080c0404, 0x9552c7c7, 0x46652323, 0x9d5ec3c3,
0x30281818, 0x37a19696, 0x0a0f0505, 0x2fb59a9a,
0x0e090707, 0x24361212, 0x1b9b8080, 0xdf3de2e2,
0xcd26ebeb, 0x4e692727, 0x7fcdb2b2, 0xea9f7575,
0x121b0909, 0x1d9e8383, 0x58742c2c, 0x342e1a1a,
0x362d1b1b, 0xdcb26e6e, 0xb4ee5a5a, 0x5bfba0a0,
0xa4f65252, 0x764d3b3b, 0xb761d6d6, 0x7dceb3b3,
0x527b2929, 0xdd3ee3e3, 0x5e712f2f, 0x13978484,
0xa6f55353, 0xb968d1d1, 0x00000000, 0xc12ceded,
0x40602020, 0xe31ffcfc, 0x79c8b1b1, 0xb6ed5b5b,
0xd4be6a6a, 0x8d46cbcb, 0x67d9bebe, 0x724b3939,
0x94de4a4a, 0x98d44c4c, 0xb0e85858, 0x854acfcf,
0xbb6bd0d0, 0xc52aefef, 0x4fe5aaaa, 0xed16fbfb,
0x86c54343, 0x9ad74d4d, 0x66553333, 0x11948585,
0x8acf4545, 0xe910f9f9, 0x04060202, 0xfe817f7f,
0xa0f05050, 0x78443c3c, 0x25ba9f9f, 0x4be3a8a8,
0xa2f35151, 0x5dfea3a3, 0x80c04040, 0x058a8f8f,
0x3fad9292, 0x21bc9d9d, 0x70483838, 0xf104f5f5,
0x63dfbcbc, 0x77c1b6b6, 0xaf75dada, 0x42632121,
0x20301010, 0xe51affff, 0xfd0ef3f3, 0xbf6dd2d2,
0x814ccdcd, 0x18140c0c, 0x26351313, 0xc32fecec,
0xbee15f5f, 0x35a29797, 0x88cc4444, 0x2e391717,
0x9357c4c4, 0x55f2a7a7, 0xfc827e7e, 0x7a473d3d,
0xc8ac6464, 0xbae75d5d, 0x322b1919, 0xe6957373,
0xc0a06060, 0x19988181, 0x9ed14f4f, 0xa37fdcdc,
0x44662222, 0x547e2a2a, 0x3bab9090, 0x0b838888,
0x8cca4646, 0xc729eeee, 0x6bd3b8b8, 0x283c1414,
0xa779dede, 0xbce25e5e, 0x161d0b0b, 0xad76dbdb,
0xdb3be0e0, 0x64563232, 0x744e3a3a, 0x141e0a0a,
0x92db4949, 0x0c0a0606, 0x486c2424, 0xb8e45c5c,
0x9f5dc2c2, 0xbd6ed3d3, 0x43efacac, 0xc4a66262,
0x39a89191, 0x31a49595, 0xd337e4e4, 0xf28b7979,
0xd532e7e7, 0x8b43c8c8, 0x6e593737, 0xdab76d6d,
0x018c8d8d, 0xb164d5d5, 0x9cd24e4e, 0x49e0a9a9,
0xd8b46c6c, 0xacfa5656, 0xf307f4f4, 0xcf25eaea,
0xcaaf6565, 0xf48e7a7a, 0x47e9aeae, 0x10180808,
0x6fd5baba, 0xf0887878, 0x4a6f2525, 0x5c722e2e,
0x38241c1c, 0x57f1a6a6, 0x73c7b4b4, 0x9751c6c6,
0xcb23e8e8, 0xa17cdddd, 0xe89c7474, 0x3e211f1f,
0x96dd4b4b, 0x61dcbdbd, 0x0d868b8b, 0x0f858a8a,
0xe0907070, 0x7c423e3e, 0x71c4b5b5, 0xccaa6666,
0x90d84848, 0x06050303, 0xf701f6f6, 0x1c120e0e,
0xc2a36161, 0x6a5f3535, 0xaef95757, 0x69d0b9b9,
0x17918686, 0x9958c1c1, 0x3a271d1d, 0x27b99e9e,
0xd938e1e1, 0xeb13f8f8, 0x2bb39898, 0x22331111,
0xd2bb6969, 0xa970d9d9, 0x07898e8e, 0x33a79494,
0x2db69b9b, 0x3c221e1e, 0x15928787, 0xc920e9e9,
0x8749cece, 0xaaff5555, 0x50782828, 0xa57adfdf,
0x038f8c8c, 0x59f8a1a1, 0x09808989, 0x1a170d0d,
0x65dabfbf, 0xd731e6e6, 0x84c64242, 0xd0b86868,
0x82c34141, 0x29b09999, 0x5a772d2d, 0x1e110f0f,
0x7bcbb0b0, 0xa8fc5454, 0x6dd6bbbb, 0x2c3a1616 ];

function B0(x) { return (x&255); }
function B1(x) { return ((x>>8)&255); }
function B2(x) { return ((x>>16)&255); }
function B3(x) { return ((x>>24)&255); }

function F1(x0, x1, x2, x3)
{
  return B1(T1[x0&255]) | (B1(T1[(x1>>8)&255])<<8)
      | (B1(T1[(x2>>16)&255])<<16) | (B1(T1[x3>>>24])<<24);
}

function packBytes(octets)
{
  var i, j;
  var len=octets.length;
  var b=new Array(len/4);

  if (!octets || len % 4) return;

  for (i=0, j=0; j<len; j+= 4)
     b[i++] = octets[j] | (octets[j+1]<<8) | (octets[j+2]<<16) | (octets[j+3]<<24);

  return b;  
}

function unpackBytes(packed)
{
  var j;
  var i=0, l = packed.length;
  var r = new Array(l*4);

  for (j=0; j<l; j++)
  {
    r[i++] = B0(packed[j]);
    r[i++] = B1(packed[j]);
    r[i++] = B2(packed[j]);
    r[i++] = B3(packed[j]);
  }
  return r;
}

// ------------------------------------------------

var maxkc=8;
var maxrk=14;

function keyExpansion(key)
{
  var kc, i, j, r, t;
  var rounds;
  var keySched=new Array(maxrk+1);
  var keylen=key.length;
  var k=new Array(maxkc);
  var tk=new Array(maxkc);
  var rconpointer=0;

  if(keylen==16)
  {
   rounds=10;
   kc=4;
  }
  else if(keylen==24)
  {
   rounds=12;
   kc=6;
  }
  else if(keylen==32)
  {
   rounds=14;
   kc=8;
  }
  else
  {
	util.print_error('aes.js: Invalid key-length for AES key:'+keylen);
   return;
  }

  for(i=0; i<maxrk+1; i++) keySched[i]=new Array(4);

  for(i=0,j=0; j<keylen; j++,i+=4)
    k[j] = key.charCodeAt(i) | (key.charCodeAt(i+1)<<8)
                     | (key.charCodeAt(i+2)<<16) | (key.charCodeAt(i+3)<<24);

  for(j=kc-1; j>=0; j--) tk[j] = k[j];

  r=0;
  t=0;
  for(j=0; (j<kc)&&(r<rounds+1); )
  {
    for(; (j<kc)&&(t<4); j++,t++)
    {
      keySched[r][t]=tk[j];
    }
    if(t==4)
    {
      r++;
      t=0;
    }
  }

  while(r<rounds+1)
  {
    var temp = tk[kc-1];

    tk[0] ^= S[B1(temp)] | (S[B2(temp)]<<8) | (S[B3(temp)]<<16) | (S[B0(temp)]<<24);
    tk[0] ^= Rcon[rconpointer++];

    if(kc != 8)
    {
      for(j=1; j<kc; j++) tk[j] ^= tk[j-1];
    }
    else
    {
      for(j=1; j<kc/2; j++) tk[j] ^= tk[j-1];
 
      temp = tk[kc/2-1];
      tk[kc/2] ^= S[B0(temp)] | (S[B1(temp)]<<8) | (S[B2(temp)]<<16) | (S[B3(temp)]<<24);

      for(j=kc/2+1; j<kc; j++) tk[j] ^= tk[j-1];
    }

    for(j=0; (j<kc)&&(r<rounds+1); )
    {
      for(; (j<kc)&&(t<4); j++,t++)
      {
        keySched[r][t]=tk[j];
      }
      if(t==4)
      {
        r++;
        t=0;
      }
    }
  }
  this.rounds = rounds;
  this.rk = keySched;
  return this;
}

function AESencrypt(block, ctx)
{
  var r;
  var t0,t1,t2,t3;

  var b = packBytes(block);
  var rounds = ctx.rounds;
  var b0 = b[0];
  var b1 = b[1];
  var b2 = b[2];
  var b3 = b[3];

  for(r=0; r<rounds-1; r++)
  {
    t0 = b0 ^ ctx.rk[r][0];
    t1 = b1 ^ ctx.rk[r][1];
    t2 = b2 ^ ctx.rk[r][2];
    t3 = b3 ^ ctx.rk[r][3];

    b0 = T1[t0&255] ^ T2[(t1>>8)&255] ^ T3[(t2>>16)&255] ^ T4[t3>>>24];
    b1 = T1[t1&255] ^ T2[(t2>>8)&255] ^ T3[(t3>>16)&255] ^ T4[t0>>>24];
    b2 = T1[t2&255] ^ T2[(t3>>8)&255] ^ T3[(t0>>16)&255] ^ T4[t1>>>24];
    b3 = T1[t3&255] ^ T2[(t0>>8)&255] ^ T3[(t1>>16)&255] ^ T4[t2>>>24];
  }

  // last round is special
  r = rounds-1;

  t0 = b0 ^ ctx.rk[r][0];
  t1 = b1 ^ ctx.rk[r][1];
  t2 = b2 ^ ctx.rk[r][2];
  t3 = b3 ^ ctx.rk[r][3];

  b[0] = F1(t0, t1, t2, t3) ^ ctx.rk[rounds][0];
  b[1] = F1(t1, t2, t3, t0) ^ ctx.rk[rounds][1];
  b[2] = F1(t2, t3, t0, t1) ^ ctx.rk[rounds][2];
  b[3] = F1(t3, t0, t1, t2) ^ ctx.rk[rounds][3];

  return unpackBytes(b);
}

module.exports = {
	encrypt: AESencrypt,
	keyExpansion: keyExpansion
}

},{"../../util":7}],39:[function(require,module,exports){
//Paul Tero, July 2001
//http://www.tero.co.uk/des/
//
//Optimised for performance with large blocks by Michael Hayworth, November 2001
//http://www.netdealing.com
//
// Modified by Recurity Labs GmbH

//THIS SOFTWARE IS PROVIDED "AS IS" AND
//ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
//ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
//FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
//OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
//LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
//OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
//SUCH DAMAGE.

//des
//this takes the key, the message, and whether to encrypt or decrypt

var util = require('../../util');

// added by Recurity Labs
function desede(block,key) {
	var key1 = key.substring(0,8);
	var key2 = key.substring(8,16);
	var key3 = key.substring(16,24);
	return util.str2bin(des(des_createKeys(key3),des(des_createKeys(key2),des(des_createKeys(key1),util.bin2str(block), true, 0,null,null), false, 0,null,null), true, 0,null,null));
}


function des (keys, message, encrypt, mode, iv, padding) {
  //declaring this locally speeds things up a bit
  var spfunction1 = new Array (0x1010400,0,0x10000,0x1010404,0x1010004,0x10404,0x4,0x10000,0x400,0x1010400,0x1010404,0x400,0x1000404,0x1010004,0x1000000,0x4,0x404,0x1000400,0x1000400,0x10400,0x10400,0x1010000,0x1010000,0x1000404,0x10004,0x1000004,0x1000004,0x10004,0,0x404,0x10404,0x1000000,0x10000,0x1010404,0x4,0x1010000,0x1010400,0x1000000,0x1000000,0x400,0x1010004,0x10000,0x10400,0x1000004,0x400,0x4,0x1000404,0x10404,0x1010404,0x10004,0x1010000,0x1000404,0x1000004,0x404,0x10404,0x1010400,0x404,0x1000400,0x1000400,0,0x10004,0x10400,0,0x1010004);
  var spfunction2 = new Array (-0x7fef7fe0,-0x7fff8000,0x8000,0x108020,0x100000,0x20,-0x7fefffe0,-0x7fff7fe0,-0x7fffffe0,-0x7fef7fe0,-0x7fef8000,-0x80000000,-0x7fff8000,0x100000,0x20,-0x7fefffe0,0x108000,0x100020,-0x7fff7fe0,0,-0x80000000,0x8000,0x108020,-0x7ff00000,0x100020,-0x7fffffe0,0,0x108000,0x8020,-0x7fef8000,-0x7ff00000,0x8020,0,0x108020,-0x7fefffe0,0x100000,-0x7fff7fe0,-0x7ff00000,-0x7fef8000,0x8000,-0x7ff00000,-0x7fff8000,0x20,-0x7fef7fe0,0x108020,0x20,0x8000,-0x80000000,0x8020,-0x7fef8000,0x100000,-0x7fffffe0,0x100020,-0x7fff7fe0,-0x7fffffe0,0x100020,0x108000,0,-0x7fff8000,0x8020,-0x80000000,-0x7fefffe0,-0x7fef7fe0,0x108000);
  var spfunction3 = new Array (0x208,0x8020200,0,0x8020008,0x8000200,0,0x20208,0x8000200,0x20008,0x8000008,0x8000008,0x20000,0x8020208,0x20008,0x8020000,0x208,0x8000000,0x8,0x8020200,0x200,0x20200,0x8020000,0x8020008,0x20208,0x8000208,0x20200,0x20000,0x8000208,0x8,0x8020208,0x200,0x8000000,0x8020200,0x8000000,0x20008,0x208,0x20000,0x8020200,0x8000200,0,0x200,0x20008,0x8020208,0x8000200,0x8000008,0x200,0,0x8020008,0x8000208,0x20000,0x8000000,0x8020208,0x8,0x20208,0x20200,0x8000008,0x8020000,0x8000208,0x208,0x8020000,0x20208,0x8,0x8020008,0x20200);
  var spfunction4 = new Array (0x802001,0x2081,0x2081,0x80,0x802080,0x800081,0x800001,0x2001,0,0x802000,0x802000,0x802081,0x81,0,0x800080,0x800001,0x1,0x2000,0x800000,0x802001,0x80,0x800000,0x2001,0x2080,0x800081,0x1,0x2080,0x800080,0x2000,0x802080,0x802081,0x81,0x800080,0x800001,0x802000,0x802081,0x81,0,0,0x802000,0x2080,0x800080,0x800081,0x1,0x802001,0x2081,0x2081,0x80,0x802081,0x81,0x1,0x2000,0x800001,0x2001,0x802080,0x800081,0x2001,0x2080,0x800000,0x802001,0x80,0x800000,0x2000,0x802080);
  var spfunction5 = new Array (0x100,0x2080100,0x2080000,0x42000100,0x80000,0x100,0x40000000,0x2080000,0x40080100,0x80000,0x2000100,0x40080100,0x42000100,0x42080000,0x80100,0x40000000,0x2000000,0x40080000,0x40080000,0,0x40000100,0x42080100,0x42080100,0x2000100,0x42080000,0x40000100,0,0x42000000,0x2080100,0x2000000,0x42000000,0x80100,0x80000,0x42000100,0x100,0x2000000,0x40000000,0x2080000,0x42000100,0x40080100,0x2000100,0x40000000,0x42080000,0x2080100,0x40080100,0x100,0x2000000,0x42080000,0x42080100,0x80100,0x42000000,0x42080100,0x2080000,0,0x40080000,0x42000000,0x80100,0x2000100,0x40000100,0x80000,0,0x40080000,0x2080100,0x40000100);
  var spfunction6 = new Array (0x20000010,0x20400000,0x4000,0x20404010,0x20400000,0x10,0x20404010,0x400000,0x20004000,0x404010,0x400000,0x20000010,0x400010,0x20004000,0x20000000,0x4010,0,0x400010,0x20004010,0x4000,0x404000,0x20004010,0x10,0x20400010,0x20400010,0,0x404010,0x20404000,0x4010,0x404000,0x20404000,0x20000000,0x20004000,0x10,0x20400010,0x404000,0x20404010,0x400000,0x4010,0x20000010,0x400000,0x20004000,0x20000000,0x4010,0x20000010,0x20404010,0x404000,0x20400000,0x404010,0x20404000,0,0x20400010,0x10,0x4000,0x20400000,0x404010,0x4000,0x400010,0x20004010,0,0x20404000,0x20000000,0x400010,0x20004010);
  var spfunction7 = new Array (0x200000,0x4200002,0x4000802,0,0x800,0x4000802,0x200802,0x4200800,0x4200802,0x200000,0,0x4000002,0x2,0x4000000,0x4200002,0x802,0x4000800,0x200802,0x200002,0x4000800,0x4000002,0x4200000,0x4200800,0x200002,0x4200000,0x800,0x802,0x4200802,0x200800,0x2,0x4000000,0x200800,0x4000000,0x200800,0x200000,0x4000802,0x4000802,0x4200002,0x4200002,0x2,0x200002,0x4000000,0x4000800,0x200000,0x4200800,0x802,0x200802,0x4200800,0x802,0x4000002,0x4200802,0x4200000,0x200800,0,0x2,0x4200802,0,0x200802,0x4200000,0x800,0x4000002,0x4000800,0x800,0x200002);
  var spfunction8 = new Array (0x10001040,0x1000,0x40000,0x10041040,0x10000000,0x10001040,0x40,0x10000000,0x40040,0x10040000,0x10041040,0x41000,0x10041000,0x41040,0x1000,0x40,0x10040000,0x10000040,0x10001000,0x1040,0x41000,0x40040,0x10040040,0x10041000,0x1040,0,0,0x10040040,0x10000040,0x10001000,0x41040,0x40000,0x41040,0x40000,0x10041000,0x1000,0x40,0x10040040,0x1000,0x41040,0x10001000,0x40,0x10000040,0x10040000,0x10040040,0x10000000,0x40000,0x10001040,0,0x10041040,0x40040,0x10000040,0x10040000,0x10001000,0x10001040,0,0x10041040,0x41000,0x41000,0x1040,0x1040,0x40040,0x10000000,0x10041000);

  //create the 16 or 48 subkeys we will need
  var m=0, i, j, temp, temp2, right1, right2, left, right, looping;
  var cbcleft, cbcleft2, cbcright, cbcright2
  var endloop, loopinc;
  var len = message.length;
  var chunk = 0;
  //set up the loops for single and triple des
  var iterations = keys.length == 32 ? 3 : 9; //single or triple des
  if (iterations == 3) {looping = encrypt ? new Array (0, 32, 2) : new Array (30, -2, -2);}
  else {looping = encrypt ? new Array (0, 32, 2, 62, 30, -2, 64, 96, 2) : new Array (94, 62, -2, 32, 64, 2, 30, -2, -2);}

  //pad the message depending on the padding parameter
  if (padding == 2) message += "        "; //pad the message with spaces
  else if (padding == 1) {temp = 8-(len%8); message += String.fromCharCode (temp,temp,temp,temp,temp,temp,temp,temp); if (temp==8) len+=8;} //PKCS7 padding
  else if (!padding) message += "\0\0\0\0\0\0\0\0"; //pad the message out with null bytes

  //store the result here
  result = "";
  tempresult = "";

  if (mode == 1) { //CBC mode
    cbcleft = (iv.charCodeAt(m++) << 24) | (iv.charCodeAt(m++) << 16) | (iv.charCodeAt(m++) << 8) | iv.charCodeAt(m++);
    cbcright = (iv.charCodeAt(m++) << 24) | (iv.charCodeAt(m++) << 16) | (iv.charCodeAt(m++) << 8) | iv.charCodeAt(m++);
    m=0;
  }

  //loop through each 64 bit chunk of the message
  while (m < len) {
    left = (message.charCodeAt(m++) << 24) | (message.charCodeAt(m++) << 16) | (message.charCodeAt(m++) << 8) | message.charCodeAt(m++);
    right = (message.charCodeAt(m++) << 24) | (message.charCodeAt(m++) << 16) | (message.charCodeAt(m++) << 8) | message.charCodeAt(m++);

    //for Cipher Block Chaining mode, xor the message with the previous result
    if (mode == 1) {if (encrypt) {left ^= cbcleft; right ^= cbcright;} else {cbcleft2 = cbcleft; cbcright2 = cbcright; cbcleft = left; cbcright = right;}}

    //first each 64 but chunk of the message must be permuted according to IP
    temp = ((left >>> 4) ^ right) & 0x0f0f0f0f; right ^= temp; left ^= (temp << 4);
    temp = ((left >>> 16) ^ right) & 0x0000ffff; right ^= temp; left ^= (temp << 16);
    temp = ((right >>> 2) ^ left) & 0x33333333; left ^= temp; right ^= (temp << 2);
    temp = ((right >>> 8) ^ left) & 0x00ff00ff; left ^= temp; right ^= (temp << 8);
    temp = ((left >>> 1) ^ right) & 0x55555555; right ^= temp; left ^= (temp << 1);

    left = ((left << 1) | (left >>> 31)); 
    right = ((right << 1) | (right >>> 31)); 

    //do this either 1 or 3 times for each chunk of the message
    for (j=0; j<iterations; j+=3) {
      endloop = looping[j+1];
      loopinc = looping[j+2];
      //now go through and perform the encryption or decryption  
      for (i=looping[j]; i!=endloop; i+=loopinc) { //for efficiency
        right1 = right ^ keys[i]; 
        right2 = ((right >>> 4) | (right << 28)) ^ keys[i+1];
        //the result is attained by passing these bytes through the S selection functions
        temp = left;
        left = right;
        right = temp ^ (spfunction2[(right1 >>> 24) & 0x3f] | spfunction4[(right1 >>> 16) & 0x3f]
              | spfunction6[(right1 >>>  8) & 0x3f] | spfunction8[right1 & 0x3f]
              | spfunction1[(right2 >>> 24) & 0x3f] | spfunction3[(right2 >>> 16) & 0x3f]
              | spfunction5[(right2 >>>  8) & 0x3f] | spfunction7[right2 & 0x3f]);
      }
      temp = left; left = right; right = temp; //unreverse left and right
    } //for either 1 or 3 iterations

    //move then each one bit to the right
    left = ((left >>> 1) | (left << 31)); 
    right = ((right >>> 1) | (right << 31)); 

    //now perform IP-1, which is IP in the opposite direction
    temp = ((left >>> 1) ^ right) & 0x55555555; right ^= temp; left ^= (temp << 1);
    temp = ((right >>> 8) ^ left) & 0x00ff00ff; left ^= temp; right ^= (temp << 8);
    temp = ((right >>> 2) ^ left) & 0x33333333; left ^= temp; right ^= (temp << 2);
    temp = ((left >>> 16) ^ right) & 0x0000ffff; right ^= temp; left ^= (temp << 16);
    temp = ((left >>> 4) ^ right) & 0x0f0f0f0f; right ^= temp; left ^= (temp << 4);

    //for Cipher Block Chaining mode, xor the message with the previous result
    if (mode == 1) {if (encrypt) {cbcleft = left; cbcright = right;} else {left ^= cbcleft2; right ^= cbcright2;}}
    tempresult += String.fromCharCode ((left>>>24), ((left>>>16) & 0xff), ((left>>>8) & 0xff), (left & 0xff), (right>>>24), ((right>>>16) & 0xff), ((right>>>8) & 0xff), (right & 0xff));

    chunk += 8;
    if (chunk == 512) {result += tempresult; tempresult = ""; chunk = 0;}
  } //for every 8 characters, or 64 bits in the message

  //return the result as an array
  result += tempresult;
  result = result.replace(/\0*$/g, "");
  return result;
} //end of des



//des_createKeys
//this takes as input a 64 bit key (even though only 56 bits are used)
//as an array of 2 integers, and returns 16 48 bit keys
function des_createKeys (key) {
  //declaring this locally speeds things up a bit
  pc2bytes0  = new Array (0,0x4,0x20000000,0x20000004,0x10000,0x10004,0x20010000,0x20010004,0x200,0x204,0x20000200,0x20000204,0x10200,0x10204,0x20010200,0x20010204);
  pc2bytes1  = new Array (0,0x1,0x100000,0x100001,0x4000000,0x4000001,0x4100000,0x4100001,0x100,0x101,0x100100,0x100101,0x4000100,0x4000101,0x4100100,0x4100101);
  pc2bytes2  = new Array (0,0x8,0x800,0x808,0x1000000,0x1000008,0x1000800,0x1000808,0,0x8,0x800,0x808,0x1000000,0x1000008,0x1000800,0x1000808);
  pc2bytes3  = new Array (0,0x200000,0x8000000,0x8200000,0x2000,0x202000,0x8002000,0x8202000,0x20000,0x220000,0x8020000,0x8220000,0x22000,0x222000,0x8022000,0x8222000);
  pc2bytes4  = new Array (0,0x40000,0x10,0x40010,0,0x40000,0x10,0x40010,0x1000,0x41000,0x1010,0x41010,0x1000,0x41000,0x1010,0x41010);
  pc2bytes5  = new Array (0,0x400,0x20,0x420,0,0x400,0x20,0x420,0x2000000,0x2000400,0x2000020,0x2000420,0x2000000,0x2000400,0x2000020,0x2000420);
  pc2bytes6  = new Array (0,0x10000000,0x80000,0x10080000,0x2,0x10000002,0x80002,0x10080002,0,0x10000000,0x80000,0x10080000,0x2,0x10000002,0x80002,0x10080002);
  pc2bytes7  = new Array (0,0x10000,0x800,0x10800,0x20000000,0x20010000,0x20000800,0x20010800,0x20000,0x30000,0x20800,0x30800,0x20020000,0x20030000,0x20020800,0x20030800);
  pc2bytes8  = new Array (0,0x40000,0,0x40000,0x2,0x40002,0x2,0x40002,0x2000000,0x2040000,0x2000000,0x2040000,0x2000002,0x2040002,0x2000002,0x2040002);
  pc2bytes9  = new Array (0,0x10000000,0x8,0x10000008,0,0x10000000,0x8,0x10000008,0x400,0x10000400,0x408,0x10000408,0x400,0x10000400,0x408,0x10000408);
  pc2bytes10 = new Array (0,0x20,0,0x20,0x100000,0x100020,0x100000,0x100020,0x2000,0x2020,0x2000,0x2020,0x102000,0x102020,0x102000,0x102020);
  pc2bytes11 = new Array (0,0x1000000,0x200,0x1000200,0x200000,0x1200000,0x200200,0x1200200,0x4000000,0x5000000,0x4000200,0x5000200,0x4200000,0x5200000,0x4200200,0x5200200);
  pc2bytes12 = new Array (0,0x1000,0x8000000,0x8001000,0x80000,0x81000,0x8080000,0x8081000,0x10,0x1010,0x8000010,0x8001010,0x80010,0x81010,0x8080010,0x8081010);
  pc2bytes13 = new Array (0,0x4,0x100,0x104,0,0x4,0x100,0x104,0x1,0x5,0x101,0x105,0x1,0x5,0x101,0x105);

  //how many iterations (1 for des, 3 for triple des)
  var iterations = key.length > 8 ? 3 : 1; //changed by Paul 16/6/2007 to use Triple DES for 9+ byte keys
  //stores the return keys
  var keys = new Array (32 * iterations);
  //now define the left shifts which need to be done
  var shifts = new Array (0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0);
  //other variables
  var lefttemp, righttemp, m=0, n=0, temp;

  for (var j=0; j<iterations; j++) { //either 1 or 3 iterations
    left = (key.charCodeAt(m++) << 24) | (key.charCodeAt(m++) << 16) | (key.charCodeAt(m++) << 8) | key.charCodeAt(m++);
    right = (key.charCodeAt(m++) << 24) | (key.charCodeAt(m++) << 16) | (key.charCodeAt(m++) << 8) | key.charCodeAt(m++);

    temp = ((left >>> 4) ^ right) & 0x0f0f0f0f; right ^= temp; left ^= (temp << 4);
    temp = ((right >>> -16) ^ left) & 0x0000ffff; left ^= temp; right ^= (temp << -16);
    temp = ((left >>> 2) ^ right) & 0x33333333; right ^= temp; left ^= (temp << 2);
    temp = ((right >>> -16) ^ left) & 0x0000ffff; left ^= temp; right ^= (temp << -16);
    temp = ((left >>> 1) ^ right) & 0x55555555; right ^= temp; left ^= (temp << 1);
    temp = ((right >>> 8) ^ left) & 0x00ff00ff; left ^= temp; right ^= (temp << 8);
    temp = ((left >>> 1) ^ right) & 0x55555555; right ^= temp; left ^= (temp << 1);

    //the right side needs to be shifted and to get the last four bits of the left side
    temp = (left << 8) | ((right >>> 20) & 0x000000f0);
    //left needs to be put upside down
    left = (right << 24) | ((right << 8) & 0xff0000) | ((right >>> 8) & 0xff00) | ((right >>> 24) & 0xf0);
    right = temp;

    //now go through and perform these shifts on the left and right keys
    for (i=0; i < shifts.length; i++) {
      //shift the keys either one or two bits to the left
      if (shifts[i]) {left = (left << 2) | (left >>> 26); right = (right << 2) | (right >>> 26);}
      else {left = (left << 1) | (left >>> 27); right = (right << 1) | (right >>> 27);}
      left &= -0xf; right &= -0xf;

      //now apply PC-2, in such a way that E is easier when encrypting or decrypting
      //this conversion will look like PC-2 except only the last 6 bits of each byte are used
      //rather than 48 consecutive bits and the order of lines will be according to 
      //how the S selection functions will be applied: S2, S4, S6, S8, S1, S3, S5, S7
      lefttemp = pc2bytes0[left >>> 28] | pc2bytes1[(left >>> 24) & 0xf]
              | pc2bytes2[(left >>> 20) & 0xf] | pc2bytes3[(left >>> 16) & 0xf]
              | pc2bytes4[(left >>> 12) & 0xf] | pc2bytes5[(left >>> 8) & 0xf]
              | pc2bytes6[(left >>> 4) & 0xf];
      righttemp = pc2bytes7[right >>> 28] | pc2bytes8[(right >>> 24) & 0xf]
                | pc2bytes9[(right >>> 20) & 0xf] | pc2bytes10[(right >>> 16) & 0xf]
                | pc2bytes11[(right >>> 12) & 0xf] | pc2bytes12[(right >>> 8) & 0xf]
                | pc2bytes13[(right >>> 4) & 0xf];
      temp = ((righttemp >>> 16) ^ lefttemp) & 0x0000ffff; 
      keys[n++] = lefttemp ^ temp; keys[n++] = righttemp ^ (temp << 16);
    }
  } //for each iterations
  //return the keys we've created
  return keys;
} //end of des_createKeys


module.exports = desede;

},{"../../util":7}],40:[function(require,module,exports){

// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Copyright 2010 pjacobs@xeekr.com . All rights reserved.

// Modified by Recurity Labs GmbH

// fixed/modified by Herbert Hanewinkel, www.haneWIN.de
// check www.haneWIN.de for the latest version

// cast5.js is a Javascript implementation of CAST-128, as defined in RFC 2144.
// CAST-128 is a common OpenPGP cipher.


// CAST5 constructor

var util = require('../../util');

function cast5_encrypt(block, key) {
	var cast5 = new openpgp_symenc_cast5();
	cast5.setKey(util.str2bin(key));
	return cast5.encrypt(block);
}

function openpgp_symenc_cast5() {
	this.BlockSize= 8;
	this.KeySize = 16;

	this.setKey = function (key) {
		 this.masking = new Array(16);
		 this.rotate = new Array(16);

		 this.reset();

		 if (key.length == this.KeySize)
		 {
		   this.keySchedule(key);
		 }
		 else
		 {
		   util.print_error('cast5.js: CAST-128: keys must be 16 bytes');
		   return false;
		 }
		 return true;
	};
	
	this.reset = function() {
		 for (var i = 0; i < 16; i++)
		 {
		  this.masking[i] = 0;
		  this.rotate[i] = 0;
		 }
	};

	this.getBlockSize = function() {
		 return BlockSize;
	};

	this.encrypt = function(src) {
		 var dst = new Array(src.length);

		 for(var i = 0; i < src.length; i+=8)
		 {
		  var l = src[i]<<24 | src[i+1]<<16 | src[i+2]<<8 | src[i+3];
		  var r = src[i+4]<<24 | src[i+5]<<16 | src[i+6]<<8 | src[i+7];
		  var t;

		  t = r; r = l^f1(r, this.masking[0], this.rotate[0]); l = t;
		  t = r; r = l^f2(r, this.masking[1], this.rotate[1]); l = t;
		  t = r; r = l^f3(r, this.masking[2], this.rotate[2]); l = t;
		  t = r; r = l^f1(r, this.masking[3], this.rotate[3]); l = t;

		  t = r; r = l^f2(r, this.masking[4], this.rotate[4]); l = t;
		  t = r; r = l^f3(r, this.masking[5], this.rotate[5]); l = t;
		  t = r; r = l^f1(r, this.masking[6], this.rotate[6]); l = t;
		  t = r; r = l^f2(r, this.masking[7], this.rotate[7]); l = t;

		  t = r; r = l^f3(r, this.masking[8], this.rotate[8]); l = t;
		  t = r; r = l^f1(r, this.masking[9], this.rotate[9]); l = t;
		  t = r; r = l^f2(r, this.masking[10], this.rotate[10]); l = t;
		  t = r; r = l^f3(r, this.masking[11], this.rotate[11]); l = t;

		  t = r; r = l^f1(r, this.masking[12], this.rotate[12]); l = t;
		  t = r; r = l^f2(r, this.masking[13], this.rotate[13]); l = t;
		  t = r; r = l^f3(r, this.masking[14], this.rotate[14]); l = t;
		  t = r; r = l^f1(r, this.masking[15], this.rotate[15]); l = t;

		  dst[i]   = (r >>> 24)&255;
		  dst[i+1] = (r >>> 16)&255;
		  dst[i+2] = (r >>> 8)&255;
		  dst[i+3] = r&255;
		  dst[i+4] = (l >>> 24)&255;
		  dst[i+5] = (l >>> 16)&255;
		  dst[i+6] = (l >>> 8)&255;
		  dst[i+7] = l&255;
		 }

		 return dst;
	};
	
	this.decrypt = function(src) {
		 var dst = new Array(src.length);

		 for(var i = 0; i < src.length; i+=8)
		 {
		  var l = src[i]<<24 | src[i+1]<<16 | src[i+2]<<8 | src[i+3];
		  var r = src[i+4]<<24 | src[i+5]<<16 | src[i+6]<<8 | src[i+7];
		  var t;

		  t = r; r = l^f1(r, this.masking[15], this.rotate[15]); l = t;
		  t = r; r = l^f3(r, this.masking[14], this.rotate[14]); l = t;
		  t = r; r = l^f2(r, this.masking[13], this.rotate[13]); l = t;
		  t = r; r = l^f1(r, this.masking[12], this.rotate[12]); l = t;

		  t = r; r = l^f3(r, this.masking[11], this.rotate[11]); l = t;
		  t = r; r = l^f2(r, this.masking[10], this.rotate[10]); l = t;
		  t = r; r = l^f1(r, this.masking[9], this.rotate[9]); l = t;
		  t = r; r = l^f3(r, this.masking[8], this.rotate[8]); l = t;

		  t = r; r = l^f2(r, this.masking[7], this.rotate[7]); l = t;
		  t = r; r = l^f1(r, this.masking[6], this.rotate[6]); l = t;
		  t = r; r = l^f3(r, this.masking[5], this.rotate[5]); l = t;
		  t = r; r = l^f2(r, this.masking[4], this.rotate[4]); l = t;

		  t = r; r = l^f1(r, this.masking[3], this.rotate[3]); l = t;
		  t = r; r = l^f3(r, this.masking[2], this.rotate[2]); l = t;
		  t = r; r = l^f2(r, this.masking[1], this.rotate[1]); l = t;
		  t = r; r = l^f1(r, this.masking[0], this.rotate[0]); l = t;

		  dst[i]   = (r >>> 24)&255;
		  dst[i+1] = (r >>> 16)&255;
		  dst[i+2] = (r >>> 8)&255;
		  dst[i+3] = r&255;
		  dst[i+4] = (l >>> 24)&255;
		  dst[i+5] = (l >> 16)&255;
		  dst[i+6] = (l >> 8)&255;
		  dst[i+7] = l&255;
		 }

		 return dst;
		};
		var scheduleA = new Array(4);

		scheduleA[0] = new Array(4);
		scheduleA[0][0] = new Array(4, 0, 0xd, 0xf, 0xc, 0xe, 0x8);
		scheduleA[0][1] = new Array(5, 2, 16 + 0, 16 + 2, 16 + 1, 16 + 3, 0xa);
		scheduleA[0][2] = new Array(6, 3, 16 + 7, 16 + 6, 16 + 5, 16 + 4, 9);
		scheduleA[0][3] = new Array(7, 1, 16 + 0xa, 16 + 9, 16 + 0xb, 16 + 8, 0xb);

		scheduleA[1] = new Array(4);
		scheduleA[1][0] = new Array(0, 6, 16 + 5, 16 + 7, 16 + 4, 16 + 6, 16 + 0);
		scheduleA[1][1] = new Array(1, 4, 0, 2, 1, 3, 16 + 2);
		scheduleA[1][2] = new Array(2, 5, 7, 6, 5, 4, 16 + 1);
		scheduleA[1][3] = new Array(3, 7, 0xa, 9, 0xb, 8, 16 + 3);

		scheduleA[2] = new Array(4);
		scheduleA[2][0] = new Array(4, 0, 0xd, 0xf, 0xc, 0xe, 8);
		scheduleA[2][1] = new Array(5, 2, 16 + 0, 16 + 2, 16 + 1, 16 + 3, 0xa);
		scheduleA[2][2] = new Array(6, 3, 16 + 7, 16 + 6, 16 + 5, 16 + 4, 9);
		scheduleA[2][3] = new Array(7, 1, 16 + 0xa, 16 + 9, 16 + 0xb, 16 + 8, 0xb);


		scheduleA[3] = new Array(4);
		scheduleA[3][0] = new Array(0, 6, 16 + 5, 16 + 7, 16 + 4, 16 + 6, 16 + 0);
		scheduleA[3][1] = new Array(1, 4, 0, 2, 1, 3, 16 + 2);
		scheduleA[3][2] = new Array(2, 5, 7, 6, 5, 4, 16 + 1);
		scheduleA[3][3] = new Array(3, 7, 0xa, 9, 0xb, 8, 16 + 3);

		var scheduleB = new Array(4);

		scheduleB[0] = new Array(4);
		scheduleB[0][0] = new Array(16 + 8, 16 + 9, 16 + 7, 16 + 6, 16 + 2);
		scheduleB[0][1] = new Array(16 + 0xa, 16 + 0xb, 16 + 5, 16 + 4, 16 + 6);
		scheduleB[0][2] = new Array(16 + 0xc, 16 + 0xd, 16 + 3, 16 + 2, 16 + 9);
		scheduleB[0][3] = new Array(16 + 0xe, 16 + 0xf, 16 + 1, 16 + 0, 16 + 0xc);

		scheduleB[1] = new Array(4);
		scheduleB[1][0] = new Array(3, 2, 0xc, 0xd, 8);
		scheduleB[1][1] = new Array(1, 0, 0xe, 0xf, 0xd);
		scheduleB[1][2] = new Array(7, 6, 8, 9, 3);
		scheduleB[1][3] = new Array(5, 4, 0xa, 0xb, 7);


		scheduleB[2] = new Array(4);
		scheduleB[2][0] = new Array(16 + 3, 16 + 2, 16 + 0xc, 16 + 0xd, 16 + 9);
		scheduleB[2][1] = new Array(16 + 1, 16 + 0, 16 + 0xe, 16 + 0xf, 16 + 0xc);
		scheduleB[2][2] = new Array(16 + 7, 16 + 6, 16 + 8, 16 + 9, 16 + 2);
		scheduleB[2][3] = new Array(16 + 5, 16 + 4, 16 + 0xa, 16 + 0xb, 16 + 6);


		scheduleB[3] = new Array(4);
		scheduleB[3][0] = new Array(8, 9, 7, 6, 3);
		scheduleB[3][1] = new Array(0xa, 0xb, 5, 4, 7);
		scheduleB[3][2] = new Array(0xc, 0xd, 3, 2, 8);
		scheduleB[3][3] = new Array(0xe, 0xf, 1, 0, 0xd);

		// changed 'in' to 'inn' (in javascript 'in' is a reserved word)
		this.keySchedule = function(inn)
		{
		 var t = new Array(8);
		 var k = new Array(32);

		 for (var i = 0; i < 4; i++)
		 {
		  var j = i * 4;
		  t[i] = inn[j]<<24 | inn[j+1]<<16 | inn[j+2]<<8 | inn[j+3];
		 }

		 var x = [6, 7, 4, 5];
		 var ki = 0;

		 for (var half = 0; half < 2; half++)
		 {
		  for (var round = 0; round < 4; round++)
		  {
		   for (var j = 0; j < 4; j++)
		   {
		    var a = scheduleA[round][j];
		    var w = t[a[1]];

		    w ^= sBox[4][(t[a[2]>>>2]>>>(24-8*(a[2]&3)))&0xff];
		    w ^= sBox[5][(t[a[3]>>>2]>>>(24-8*(a[3]&3)))&0xff];
		    w ^= sBox[6][(t[a[4]>>>2]>>>(24-8*(a[4]&3)))&0xff];
		    w ^= sBox[7][(t[a[5]>>>2]>>>(24-8*(a[5]&3)))&0xff];
		    w ^= sBox[x[j]][(t[a[6]>>>2]>>>(24-8*(a[6]&3)))&0xff];
		    t[a[0]] = w;
		   }

		   for (var j = 0; j < 4; j++)
		   {
		    var b = scheduleB[round][j];
		    var w = sBox[4][(t[b[0]>>>2]>>>(24-8*(b[0]&3)))&0xff];

		    w ^= sBox[5][(t[b[1]>>>2]>>>(24-8*(b[1]&3)))&0xff];
		    w ^= sBox[6][(t[b[2]>>>2]>>>(24-8*(b[2]&3)))&0xff];
		    w ^= sBox[7][(t[b[3]>>>2]>>>(24-8*(b[3]&3)))&0xff];
		    w ^= sBox[4+j][(t[b[4]>>>2]>>>(24-8*(b[4]&3)))&0xff];
		    k[ki] = w;
		    ki++;
		   }
		  }
		 }

		 for (var i = 0; i < 16; i++)
		 {
		  this.masking[i] = k[i];
		  this.rotate[i]  = k[16+i] & 0x1f;
		 }
		};

		// These are the three 'f' functions. See RFC 2144, section 2.2.

		function f1(d, m, r)
		{
		 var t = m + d;
		 var I = (t << r) | (t >>> (32 - r));
		 return ((sBox[0][I>>>24] ^ sBox[1][(I>>>16)&255]) - sBox[2][(I>>>8)&255]) + sBox[3][I&255];
		}

		function f2(d, m, r)
		{
		 var t = m ^ d;
		 var I = (t << r) | (t >>> (32 - r));
		 return ((sBox[0][I>>>24] - sBox[1][(I>>>16)&255]) + sBox[2][(I>>>8)&255]) ^ sBox[3][I&255];
		}

		function f3(d, m, r)
		{
		 var t = m - d;
		 var I = (t << r) | (t >>> (32 - r));
		 return ((sBox[0][I>>>24] + sBox[1][(I>>>16)&255]) ^ sBox[2][(I>>>8)&255]) - sBox[3][I&255];
		}

		var sBox = new Array(8);
		sBox[0] = new Array(
		  0x30fb40d4, 0x9fa0ff0b, 0x6beccd2f, 0x3f258c7a, 0x1e213f2f, 0x9c004dd3, 0x6003e540, 0xcf9fc949,
		  0xbfd4af27, 0x88bbbdb5, 0xe2034090, 0x98d09675, 0x6e63a0e0, 0x15c361d2, 0xc2e7661d, 0x22d4ff8e,
		  0x28683b6f, 0xc07fd059, 0xff2379c8, 0x775f50e2, 0x43c340d3, 0xdf2f8656, 0x887ca41a, 0xa2d2bd2d,
		  0xa1c9e0d6, 0x346c4819, 0x61b76d87, 0x22540f2f, 0x2abe32e1, 0xaa54166b, 0x22568e3a, 0xa2d341d0,
		  0x66db40c8, 0xa784392f, 0x004dff2f, 0x2db9d2de, 0x97943fac, 0x4a97c1d8, 0x527644b7, 0xb5f437a7,
		  0xb82cbaef, 0xd751d159, 0x6ff7f0ed, 0x5a097a1f, 0x827b68d0, 0x90ecf52e, 0x22b0c054, 0xbc8e5935,
		  0x4b6d2f7f, 0x50bb64a2, 0xd2664910, 0xbee5812d, 0xb7332290, 0xe93b159f, 0xb48ee411, 0x4bff345d,
		  0xfd45c240, 0xad31973f, 0xc4f6d02e, 0x55fc8165, 0xd5b1caad, 0xa1ac2dae, 0xa2d4b76d, 0xc19b0c50,
		  0x882240f2, 0x0c6e4f38, 0xa4e4bfd7, 0x4f5ba272, 0x564c1d2f, 0xc59c5319, 0xb949e354, 0xb04669fe,
		  0xb1b6ab8a, 0xc71358dd, 0x6385c545, 0x110f935d, 0x57538ad5, 0x6a390493, 0xe63d37e0, 0x2a54f6b3,
		  0x3a787d5f, 0x6276a0b5, 0x19a6fcdf, 0x7a42206a, 0x29f9d4d5, 0xf61b1891, 0xbb72275e, 0xaa508167,
		  0x38901091, 0xc6b505eb, 0x84c7cb8c, 0x2ad75a0f, 0x874a1427, 0xa2d1936b, 0x2ad286af, 0xaa56d291,
		  0xd7894360, 0x425c750d, 0x93b39e26, 0x187184c9, 0x6c00b32d, 0x73e2bb14, 0xa0bebc3c, 0x54623779,
		  0x64459eab, 0x3f328b82, 0x7718cf82, 0x59a2cea6, 0x04ee002e, 0x89fe78e6, 0x3fab0950, 0x325ff6c2,
		  0x81383f05, 0x6963c5c8, 0x76cb5ad6, 0xd49974c9, 0xca180dcf, 0x380782d5, 0xc7fa5cf6, 0x8ac31511,
		  0x35e79e13, 0x47da91d0, 0xf40f9086, 0xa7e2419e, 0x31366241, 0x051ef495, 0xaa573b04, 0x4a805d8d,
		  0x548300d0, 0x00322a3c, 0xbf64cddf, 0xba57a68e, 0x75c6372b, 0x50afd341, 0xa7c13275, 0x915a0bf5,
		  0x6b54bfab, 0x2b0b1426, 0xab4cc9d7, 0x449ccd82, 0xf7fbf265, 0xab85c5f3, 0x1b55db94, 0xaad4e324,
		  0xcfa4bd3f, 0x2deaa3e2, 0x9e204d02, 0xc8bd25ac, 0xeadf55b3, 0xd5bd9e98, 0xe31231b2, 0x2ad5ad6c,
		  0x954329de, 0xadbe4528, 0xd8710f69, 0xaa51c90f, 0xaa786bf6, 0x22513f1e, 0xaa51a79b, 0x2ad344cc,
		  0x7b5a41f0, 0xd37cfbad, 0x1b069505, 0x41ece491, 0xb4c332e6, 0x032268d4, 0xc9600acc, 0xce387e6d,
		  0xbf6bb16c, 0x6a70fb78, 0x0d03d9c9, 0xd4df39de, 0xe01063da, 0x4736f464, 0x5ad328d8, 0xb347cc96,
		  0x75bb0fc3, 0x98511bfb, 0x4ffbcc35, 0xb58bcf6a, 0xe11f0abc, 0xbfc5fe4a, 0xa70aec10, 0xac39570a,
		  0x3f04442f, 0x6188b153, 0xe0397a2e, 0x5727cb79, 0x9ceb418f, 0x1cacd68d, 0x2ad37c96, 0x0175cb9d,
		  0xc69dff09, 0xc75b65f0, 0xd9db40d8, 0xec0e7779, 0x4744ead4, 0xb11c3274, 0xdd24cb9e, 0x7e1c54bd,
		  0xf01144f9, 0xd2240eb1, 0x9675b3fd, 0xa3ac3755, 0xd47c27af, 0x51c85f4d, 0x56907596, 0xa5bb15e6,
		  0x580304f0, 0xca042cf1, 0x011a37ea, 0x8dbfaadb, 0x35ba3e4a, 0x3526ffa0, 0xc37b4d09, 0xbc306ed9,
		  0x98a52666, 0x5648f725, 0xff5e569d, 0x0ced63d0, 0x7c63b2cf, 0x700b45e1, 0xd5ea50f1, 0x85a92872,
		  0xaf1fbda7, 0xd4234870, 0xa7870bf3, 0x2d3b4d79, 0x42e04198, 0x0cd0ede7, 0x26470db8, 0xf881814c,
		  0x474d6ad7, 0x7c0c5e5c, 0xd1231959, 0x381b7298, 0xf5d2f4db, 0xab838653, 0x6e2f1e23, 0x83719c9e,
		  0xbd91e046, 0x9a56456e, 0xdc39200c, 0x20c8c571, 0x962bda1c, 0xe1e696ff, 0xb141ab08, 0x7cca89b9,
		  0x1a69e783, 0x02cc4843, 0xa2f7c579, 0x429ef47d, 0x427b169c, 0x5ac9f049, 0xdd8f0f00, 0x5c8165bf);

		sBox[1] = new Array(
		  0x1f201094, 0xef0ba75b, 0x69e3cf7e, 0x393f4380, 0xfe61cf7a, 0xeec5207a, 0x55889c94, 0x72fc0651,
		  0xada7ef79, 0x4e1d7235, 0xd55a63ce, 0xde0436ba, 0x99c430ef, 0x5f0c0794, 0x18dcdb7d, 0xa1d6eff3,
		  0xa0b52f7b, 0x59e83605, 0xee15b094, 0xe9ffd909, 0xdc440086, 0xef944459, 0xba83ccb3, 0xe0c3cdfb,
		  0xd1da4181, 0x3b092ab1, 0xf997f1c1, 0xa5e6cf7b, 0x01420ddb, 0xe4e7ef5b, 0x25a1ff41, 0xe180f806,
		  0x1fc41080, 0x179bee7a, 0xd37ac6a9, 0xfe5830a4, 0x98de8b7f, 0x77e83f4e, 0x79929269, 0x24fa9f7b,
		  0xe113c85b, 0xacc40083, 0xd7503525, 0xf7ea615f, 0x62143154, 0x0d554b63, 0x5d681121, 0xc866c359,
		  0x3d63cf73, 0xcee234c0, 0xd4d87e87, 0x5c672b21, 0x071f6181, 0x39f7627f, 0x361e3084, 0xe4eb573b,
		  0x602f64a4, 0xd63acd9c, 0x1bbc4635, 0x9e81032d, 0x2701f50c, 0x99847ab4, 0xa0e3df79, 0xba6cf38c,
		  0x10843094, 0x2537a95e, 0xf46f6ffe, 0xa1ff3b1f, 0x208cfb6a, 0x8f458c74, 0xd9e0a227, 0x4ec73a34,
		  0xfc884f69, 0x3e4de8df, 0xef0e0088, 0x3559648d, 0x8a45388c, 0x1d804366, 0x721d9bfd, 0xa58684bb,
		  0xe8256333, 0x844e8212, 0x128d8098, 0xfed33fb4, 0xce280ae1, 0x27e19ba5, 0xd5a6c252, 0xe49754bd,
		  0xc5d655dd, 0xeb667064, 0x77840b4d, 0xa1b6a801, 0x84db26a9, 0xe0b56714, 0x21f043b7, 0xe5d05860,
		  0x54f03084, 0x066ff472, 0xa31aa153, 0xdadc4755, 0xb5625dbf, 0x68561be6, 0x83ca6b94, 0x2d6ed23b,
		  0xeccf01db, 0xa6d3d0ba, 0xb6803d5c, 0xaf77a709, 0x33b4a34c, 0x397bc8d6, 0x5ee22b95, 0x5f0e5304,
		  0x81ed6f61, 0x20e74364, 0xb45e1378, 0xde18639b, 0x881ca122, 0xb96726d1, 0x8049a7e8, 0x22b7da7b,
		  0x5e552d25, 0x5272d237, 0x79d2951c, 0xc60d894c, 0x488cb402, 0x1ba4fe5b, 0xa4b09f6b, 0x1ca815cf,
		  0xa20c3005, 0x8871df63, 0xb9de2fcb, 0x0cc6c9e9, 0x0beeff53, 0xe3214517, 0xb4542835, 0x9f63293c,
		  0xee41e729, 0x6e1d2d7c, 0x50045286, 0x1e6685f3, 0xf33401c6, 0x30a22c95, 0x31a70850, 0x60930f13,
		  0x73f98417, 0xa1269859, 0xec645c44, 0x52c877a9, 0xcdff33a6, 0xa02b1741, 0x7cbad9a2, 0x2180036f,
		  0x50d99c08, 0xcb3f4861, 0xc26bd765, 0x64a3f6ab, 0x80342676, 0x25a75e7b, 0xe4e6d1fc, 0x20c710e6,
		  0xcdf0b680, 0x17844d3b, 0x31eef84d, 0x7e0824e4, 0x2ccb49eb, 0x846a3bae, 0x8ff77888, 0xee5d60f6,
		  0x7af75673, 0x2fdd5cdb, 0xa11631c1, 0x30f66f43, 0xb3faec54, 0x157fd7fa, 0xef8579cc, 0xd152de58,
		  0xdb2ffd5e, 0x8f32ce19, 0x306af97a, 0x02f03ef8, 0x99319ad5, 0xc242fa0f, 0xa7e3ebb0, 0xc68e4906,
		  0xb8da230c, 0x80823028, 0xdcdef3c8, 0xd35fb171, 0x088a1bc8, 0xbec0c560, 0x61a3c9e8, 0xbca8f54d,
		  0xc72feffa, 0x22822e99, 0x82c570b4, 0xd8d94e89, 0x8b1c34bc, 0x301e16e6, 0x273be979, 0xb0ffeaa6,
		  0x61d9b8c6, 0x00b24869, 0xb7ffce3f, 0x08dc283b, 0x43daf65a, 0xf7e19798, 0x7619b72f, 0x8f1c9ba4,
		  0xdc8637a0, 0x16a7d3b1, 0x9fc393b7, 0xa7136eeb, 0xc6bcc63e, 0x1a513742, 0xef6828bc, 0x520365d6,
		  0x2d6a77ab, 0x3527ed4b, 0x821fd216, 0x095c6e2e, 0xdb92f2fb, 0x5eea29cb, 0x145892f5, 0x91584f7f,
		  0x5483697b, 0x2667a8cc, 0x85196048, 0x8c4bacea, 0x833860d4, 0x0d23e0f9, 0x6c387e8a, 0x0ae6d249,
		  0xb284600c, 0xd835731d, 0xdcb1c647, 0xac4c56ea, 0x3ebd81b3, 0x230eabb0, 0x6438bc87, 0xf0b5b1fa,
		  0x8f5ea2b3, 0xfc184642, 0x0a036b7a, 0x4fb089bd, 0x649da589, 0xa345415e, 0x5c038323, 0x3e5d3bb9,
		  0x43d79572, 0x7e6dd07c, 0x06dfdf1e, 0x6c6cc4ef, 0x7160a539, 0x73bfbe70, 0x83877605, 0x4523ecf1);

		sBox[2] = new Array(
		  0x8defc240, 0x25fa5d9f, 0xeb903dbf, 0xe810c907, 0x47607fff, 0x369fe44b, 0x8c1fc644, 0xaececa90,
		  0xbeb1f9bf, 0xeefbcaea, 0xe8cf1950, 0x51df07ae, 0x920e8806, 0xf0ad0548, 0xe13c8d83, 0x927010d5,
		  0x11107d9f, 0x07647db9, 0xb2e3e4d4, 0x3d4f285e, 0xb9afa820, 0xfade82e0, 0xa067268b, 0x8272792e,
		  0x553fb2c0, 0x489ae22b, 0xd4ef9794, 0x125e3fbc, 0x21fffcee, 0x825b1bfd, 0x9255c5ed, 0x1257a240,
		  0x4e1a8302, 0xbae07fff, 0x528246e7, 0x8e57140e, 0x3373f7bf, 0x8c9f8188, 0xa6fc4ee8, 0xc982b5a5,
		  0xa8c01db7, 0x579fc264, 0x67094f31, 0xf2bd3f5f, 0x40fff7c1, 0x1fb78dfc, 0x8e6bd2c1, 0x437be59b,
		  0x99b03dbf, 0xb5dbc64b, 0x638dc0e6, 0x55819d99, 0xa197c81c, 0x4a012d6e, 0xc5884a28, 0xccc36f71,
		  0xb843c213, 0x6c0743f1, 0x8309893c, 0x0feddd5f, 0x2f7fe850, 0xd7c07f7e, 0x02507fbf, 0x5afb9a04,
		  0xa747d2d0, 0x1651192e, 0xaf70bf3e, 0x58c31380, 0x5f98302e, 0x727cc3c4, 0x0a0fb402, 0x0f7fef82,
		  0x8c96fdad, 0x5d2c2aae, 0x8ee99a49, 0x50da88b8, 0x8427f4a0, 0x1eac5790, 0x796fb449, 0x8252dc15,
		  0xefbd7d9b, 0xa672597d, 0xada840d8, 0x45f54504, 0xfa5d7403, 0xe83ec305, 0x4f91751a, 0x925669c2,
		  0x23efe941, 0xa903f12e, 0x60270df2, 0x0276e4b6, 0x94fd6574, 0x927985b2, 0x8276dbcb, 0x02778176,
		  0xf8af918d, 0x4e48f79e, 0x8f616ddf, 0xe29d840e, 0x842f7d83, 0x340ce5c8, 0x96bbb682, 0x93b4b148,
		  0xef303cab, 0x984faf28, 0x779faf9b, 0x92dc560d, 0x224d1e20, 0x8437aa88, 0x7d29dc96, 0x2756d3dc,
		  0x8b907cee, 0xb51fd240, 0xe7c07ce3, 0xe566b4a1, 0xc3e9615e, 0x3cf8209d, 0x6094d1e3, 0xcd9ca341,
		  0x5c76460e, 0x00ea983b, 0xd4d67881, 0xfd47572c, 0xf76cedd9, 0xbda8229c, 0x127dadaa, 0x438a074e,
		  0x1f97c090, 0x081bdb8a, 0x93a07ebe, 0xb938ca15, 0x97b03cff, 0x3dc2c0f8, 0x8d1ab2ec, 0x64380e51,
		  0x68cc7bfb, 0xd90f2788, 0x12490181, 0x5de5ffd4, 0xdd7ef86a, 0x76a2e214, 0xb9a40368, 0x925d958f,
		  0x4b39fffa, 0xba39aee9, 0xa4ffd30b, 0xfaf7933b, 0x6d498623, 0x193cbcfa, 0x27627545, 0x825cf47a,
		  0x61bd8ba0, 0xd11e42d1, 0xcead04f4, 0x127ea392, 0x10428db7, 0x8272a972, 0x9270c4a8, 0x127de50b,
		  0x285ba1c8, 0x3c62f44f, 0x35c0eaa5, 0xe805d231, 0x428929fb, 0xb4fcdf82, 0x4fb66a53, 0x0e7dc15b,
		  0x1f081fab, 0x108618ae, 0xfcfd086d, 0xf9ff2889, 0x694bcc11, 0x236a5cae, 0x12deca4d, 0x2c3f8cc5,
		  0xd2d02dfe, 0xf8ef5896, 0xe4cf52da, 0x95155b67, 0x494a488c, 0xb9b6a80c, 0x5c8f82bc, 0x89d36b45,
		  0x3a609437, 0xec00c9a9, 0x44715253, 0x0a874b49, 0xd773bc40, 0x7c34671c, 0x02717ef6, 0x4feb5536,
		  0xa2d02fff, 0xd2bf60c4, 0xd43f03c0, 0x50b4ef6d, 0x07478cd1, 0x006e1888, 0xa2e53f55, 0xb9e6d4bc,
		  0xa2048016, 0x97573833, 0xd7207d67, 0xde0f8f3d, 0x72f87b33, 0xabcc4f33, 0x7688c55d, 0x7b00a6b0,
		  0x947b0001, 0x570075d2, 0xf9bb88f8, 0x8942019e, 0x4264a5ff, 0x856302e0, 0x72dbd92b, 0xee971b69,
		  0x6ea22fde, 0x5f08ae2b, 0xaf7a616d, 0xe5c98767, 0xcf1febd2, 0x61efc8c2, 0xf1ac2571, 0xcc8239c2,
		  0x67214cb8, 0xb1e583d1, 0xb7dc3e62, 0x7f10bdce, 0xf90a5c38, 0x0ff0443d, 0x606e6dc6, 0x60543a49,
		  0x5727c148, 0x2be98a1d, 0x8ab41738, 0x20e1be24, 0xaf96da0f, 0x68458425, 0x99833be5, 0x600d457d,
		  0x282f9350, 0x8334b362, 0xd91d1120, 0x2b6d8da0, 0x642b1e31, 0x9c305a00, 0x52bce688, 0x1b03588a,
		  0xf7baefd5, 0x4142ed9c, 0xa4315c11, 0x83323ec5, 0xdfef4636, 0xa133c501, 0xe9d3531c, 0xee353783);

		sBox[3] = new Array(
		  0x9db30420, 0x1fb6e9de, 0xa7be7bef, 0xd273a298, 0x4a4f7bdb, 0x64ad8c57, 0x85510443, 0xfa020ed1,
		  0x7e287aff, 0xe60fb663, 0x095f35a1, 0x79ebf120, 0xfd059d43, 0x6497b7b1, 0xf3641f63, 0x241e4adf,
		  0x28147f5f, 0x4fa2b8cd, 0xc9430040, 0x0cc32220, 0xfdd30b30, 0xc0a5374f, 0x1d2d00d9, 0x24147b15,
		  0xee4d111a, 0x0fca5167, 0x71ff904c, 0x2d195ffe, 0x1a05645f, 0x0c13fefe, 0x081b08ca, 0x05170121,
		  0x80530100, 0xe83e5efe, 0xac9af4f8, 0x7fe72701, 0xd2b8ee5f, 0x06df4261, 0xbb9e9b8a, 0x7293ea25,
		  0xce84ffdf, 0xf5718801, 0x3dd64b04, 0xa26f263b, 0x7ed48400, 0x547eebe6, 0x446d4ca0, 0x6cf3d6f5,
		  0x2649abdf, 0xaea0c7f5, 0x36338cc1, 0x503f7e93, 0xd3772061, 0x11b638e1, 0x72500e03, 0xf80eb2bb,
		  0xabe0502e, 0xec8d77de, 0x57971e81, 0xe14f6746, 0xc9335400, 0x6920318f, 0x081dbb99, 0xffc304a5,
		  0x4d351805, 0x7f3d5ce3, 0xa6c866c6, 0x5d5bcca9, 0xdaec6fea, 0x9f926f91, 0x9f46222f, 0x3991467d,
		  0xa5bf6d8e, 0x1143c44f, 0x43958302, 0xd0214eeb, 0x022083b8, 0x3fb6180c, 0x18f8931e, 0x281658e6,
		  0x26486e3e, 0x8bd78a70, 0x7477e4c1, 0xb506e07c, 0xf32d0a25, 0x79098b02, 0xe4eabb81, 0x28123b23,
		  0x69dead38, 0x1574ca16, 0xdf871b62, 0x211c40b7, 0xa51a9ef9, 0x0014377b, 0x041e8ac8, 0x09114003,
		  0xbd59e4d2, 0xe3d156d5, 0x4fe876d5, 0x2f91a340, 0x557be8de, 0x00eae4a7, 0x0ce5c2ec, 0x4db4bba6,
		  0xe756bdff, 0xdd3369ac, 0xec17b035, 0x06572327, 0x99afc8b0, 0x56c8c391, 0x6b65811c, 0x5e146119,
		  0x6e85cb75, 0xbe07c002, 0xc2325577, 0x893ff4ec, 0x5bbfc92d, 0xd0ec3b25, 0xb7801ab7, 0x8d6d3b24,
		  0x20c763ef, 0xc366a5fc, 0x9c382880, 0x0ace3205, 0xaac9548a, 0xeca1d7c7, 0x041afa32, 0x1d16625a,
		  0x6701902c, 0x9b757a54, 0x31d477f7, 0x9126b031, 0x36cc6fdb, 0xc70b8b46, 0xd9e66a48, 0x56e55a79,
		  0x026a4ceb, 0x52437eff, 0x2f8f76b4, 0x0df980a5, 0x8674cde3, 0xedda04eb, 0x17a9be04, 0x2c18f4df,
		  0xb7747f9d, 0xab2af7b4, 0xefc34d20, 0x2e096b7c, 0x1741a254, 0xe5b6a035, 0x213d42f6, 0x2c1c7c26,
		  0x61c2f50f, 0x6552daf9, 0xd2c231f8, 0x25130f69, 0xd8167fa2, 0x0418f2c8, 0x001a96a6, 0x0d1526ab,
		  0x63315c21, 0x5e0a72ec, 0x49bafefd, 0x187908d9, 0x8d0dbd86, 0x311170a7, 0x3e9b640c, 0xcc3e10d7,
		  0xd5cad3b6, 0x0caec388, 0xf73001e1, 0x6c728aff, 0x71eae2a1, 0x1f9af36e, 0xcfcbd12f, 0xc1de8417,
		  0xac07be6b, 0xcb44a1d8, 0x8b9b0f56, 0x013988c3, 0xb1c52fca, 0xb4be31cd, 0xd8782806, 0x12a3a4e2,
		  0x6f7de532, 0x58fd7eb6, 0xd01ee900, 0x24adffc2, 0xf4990fc5, 0x9711aac5, 0x001d7b95, 0x82e5e7d2,
		  0x109873f6, 0x00613096, 0xc32d9521, 0xada121ff, 0x29908415, 0x7fbb977f, 0xaf9eb3db, 0x29c9ed2a,
		  0x5ce2a465, 0xa730f32c, 0xd0aa3fe8, 0x8a5cc091, 0xd49e2ce7, 0x0ce454a9, 0xd60acd86, 0x015f1919,
		  0x77079103, 0xdea03af6, 0x78a8565e, 0xdee356df, 0x21f05cbe, 0x8b75e387, 0xb3c50651, 0xb8a5c3ef,
		  0xd8eeb6d2, 0xe523be77, 0xc2154529, 0x2f69efdf, 0xafe67afb, 0xf470c4b2, 0xf3e0eb5b, 0xd6cc9876,
		  0x39e4460c, 0x1fda8538, 0x1987832f, 0xca007367, 0xa99144f8, 0x296b299e, 0x492fc295, 0x9266beab,
		  0xb5676e69, 0x9bd3ddda, 0xdf7e052f, 0xdb25701c, 0x1b5e51ee, 0xf65324e6, 0x6afce36c, 0x0316cc04,
		  0x8644213e, 0xb7dc59d0, 0x7965291f, 0xccd6fd43, 0x41823979, 0x932bcdf6, 0xb657c34d, 0x4edfd282,
		  0x7ae5290c, 0x3cb9536b, 0x851e20fe, 0x9833557e, 0x13ecf0b0, 0xd3ffb372, 0x3f85c5c1, 0x0aef7ed2);

		sBox[4] = new Array(
		  0x7ec90c04, 0x2c6e74b9, 0x9b0e66df, 0xa6337911, 0xb86a7fff, 0x1dd358f5, 0x44dd9d44, 0x1731167f,
		  0x08fbf1fa, 0xe7f511cc, 0xd2051b00, 0x735aba00, 0x2ab722d8, 0x386381cb, 0xacf6243a, 0x69befd7a,
		  0xe6a2e77f, 0xf0c720cd, 0xc4494816, 0xccf5c180, 0x38851640, 0x15b0a848, 0xe68b18cb, 0x4caadeff,
		  0x5f480a01, 0x0412b2aa, 0x259814fc, 0x41d0efe2, 0x4e40b48d, 0x248eb6fb, 0x8dba1cfe, 0x41a99b02,
		  0x1a550a04, 0xba8f65cb, 0x7251f4e7, 0x95a51725, 0xc106ecd7, 0x97a5980a, 0xc539b9aa, 0x4d79fe6a,
		  0xf2f3f763, 0x68af8040, 0xed0c9e56, 0x11b4958b, 0xe1eb5a88, 0x8709e6b0, 0xd7e07156, 0x4e29fea7,
		  0x6366e52d, 0x02d1c000, 0xc4ac8e05, 0x9377f571, 0x0c05372a, 0x578535f2, 0x2261be02, 0xd642a0c9,
		  0xdf13a280, 0x74b55bd2, 0x682199c0, 0xd421e5ec, 0x53fb3ce8, 0xc8adedb3, 0x28a87fc9, 0x3d959981,
		  0x5c1ff900, 0xfe38d399, 0x0c4eff0b, 0x062407ea, 0xaa2f4fb1, 0x4fb96976, 0x90c79505, 0xb0a8a774,
		  0xef55a1ff, 0xe59ca2c2, 0xa6b62d27, 0xe66a4263, 0xdf65001f, 0x0ec50966, 0xdfdd55bc, 0x29de0655,
		  0x911e739a, 0x17af8975, 0x32c7911c, 0x89f89468, 0x0d01e980, 0x524755f4, 0x03b63cc9, 0x0cc844b2,
		  0xbcf3f0aa, 0x87ac36e9, 0xe53a7426, 0x01b3d82b, 0x1a9e7449, 0x64ee2d7e, 0xcddbb1da, 0x01c94910,
		  0xb868bf80, 0x0d26f3fd, 0x9342ede7, 0x04a5c284, 0x636737b6, 0x50f5b616, 0xf24766e3, 0x8eca36c1,
		  0x136e05db, 0xfef18391, 0xfb887a37, 0xd6e7f7d4, 0xc7fb7dc9, 0x3063fcdf, 0xb6f589de, 0xec2941da,
		  0x26e46695, 0xb7566419, 0xf654efc5, 0xd08d58b7, 0x48925401, 0xc1bacb7f, 0xe5ff550f, 0xb6083049,
		  0x5bb5d0e8, 0x87d72e5a, 0xab6a6ee1, 0x223a66ce, 0xc62bf3cd, 0x9e0885f9, 0x68cb3e47, 0x086c010f,
		  0xa21de820, 0xd18b69de, 0xf3f65777, 0xfa02c3f6, 0x407edac3, 0xcbb3d550, 0x1793084d, 0xb0d70eba,
		  0x0ab378d5, 0xd951fb0c, 0xded7da56, 0x4124bbe4, 0x94ca0b56, 0x0f5755d1, 0xe0e1e56e, 0x6184b5be,
		  0x580a249f, 0x94f74bc0, 0xe327888e, 0x9f7b5561, 0xc3dc0280, 0x05687715, 0x646c6bd7, 0x44904db3,
		  0x66b4f0a3, 0xc0f1648a, 0x697ed5af, 0x49e92ff6, 0x309e374f, 0x2cb6356a, 0x85808573, 0x4991f840,
		  0x76f0ae02, 0x083be84d, 0x28421c9a, 0x44489406, 0x736e4cb8, 0xc1092910, 0x8bc95fc6, 0x7d869cf4,
		  0x134f616f, 0x2e77118d, 0xb31b2be1, 0xaa90b472, 0x3ca5d717, 0x7d161bba, 0x9cad9010, 0xaf462ba2,
		  0x9fe459d2, 0x45d34559, 0xd9f2da13, 0xdbc65487, 0xf3e4f94e, 0x176d486f, 0x097c13ea, 0x631da5c7,
		  0x445f7382, 0x175683f4, 0xcdc66a97, 0x70be0288, 0xb3cdcf72, 0x6e5dd2f3, 0x20936079, 0x459b80a5,
		  0xbe60e2db, 0xa9c23101, 0xeba5315c, 0x224e42f2, 0x1c5c1572, 0xf6721b2c, 0x1ad2fff3, 0x8c25404e,
		  0x324ed72f, 0x4067b7fd, 0x0523138e, 0x5ca3bc78, 0xdc0fd66e, 0x75922283, 0x784d6b17, 0x58ebb16e,
		  0x44094f85, 0x3f481d87, 0xfcfeae7b, 0x77b5ff76, 0x8c2302bf, 0xaaf47556, 0x5f46b02a, 0x2b092801,
		  0x3d38f5f7, 0x0ca81f36, 0x52af4a8a, 0x66d5e7c0, 0xdf3b0874, 0x95055110, 0x1b5ad7a8, 0xf61ed5ad,
		  0x6cf6e479, 0x20758184, 0xd0cefa65, 0x88f7be58, 0x4a046826, 0x0ff6f8f3, 0xa09c7f70, 0x5346aba0,
		  0x5ce96c28, 0xe176eda3, 0x6bac307f, 0x376829d2, 0x85360fa9, 0x17e3fe2a, 0x24b79767, 0xf5a96b20,
		  0xd6cd2595, 0x68ff1ebf, 0x7555442c, 0xf19f06be, 0xf9e0659a, 0xeeb9491d, 0x34010718, 0xbb30cab8,
		  0xe822fe15, 0x88570983, 0x750e6249, 0xda627e55, 0x5e76ffa8, 0xb1534546, 0x6d47de08, 0xefe9e7d4);

		sBox[5] = new Array(
		  0xf6fa8f9d, 0x2cac6ce1, 0x4ca34867, 0xe2337f7c, 0x95db08e7, 0x016843b4, 0xeced5cbc, 0x325553ac,
		  0xbf9f0960, 0xdfa1e2ed, 0x83f0579d, 0x63ed86b9, 0x1ab6a6b8, 0xde5ebe39, 0xf38ff732, 0x8989b138,
		  0x33f14961, 0xc01937bd, 0xf506c6da, 0xe4625e7e, 0xa308ea99, 0x4e23e33c, 0x79cbd7cc, 0x48a14367,
		  0xa3149619, 0xfec94bd5, 0xa114174a, 0xeaa01866, 0xa084db2d, 0x09a8486f, 0xa888614a, 0x2900af98,
		  0x01665991, 0xe1992863, 0xc8f30c60, 0x2e78ef3c, 0xd0d51932, 0xcf0fec14, 0xf7ca07d2, 0xd0a82072,
		  0xfd41197e, 0x9305a6b0, 0xe86be3da, 0x74bed3cd, 0x372da53c, 0x4c7f4448, 0xdab5d440, 0x6dba0ec3,
		  0x083919a7, 0x9fbaeed9, 0x49dbcfb0, 0x4e670c53, 0x5c3d9c01, 0x64bdb941, 0x2c0e636a, 0xba7dd9cd,
		  0xea6f7388, 0xe70bc762, 0x35f29adb, 0x5c4cdd8d, 0xf0d48d8c, 0xb88153e2, 0x08a19866, 0x1ae2eac8,
		  0x284caf89, 0xaa928223, 0x9334be53, 0x3b3a21bf, 0x16434be3, 0x9aea3906, 0xefe8c36e, 0xf890cdd9,
		  0x80226dae, 0xc340a4a3, 0xdf7e9c09, 0xa694a807, 0x5b7c5ecc, 0x221db3a6, 0x9a69a02f, 0x68818a54,
		  0xceb2296f, 0x53c0843a, 0xfe893655, 0x25bfe68a, 0xb4628abc, 0xcf222ebf, 0x25ac6f48, 0xa9a99387,
		  0x53bddb65, 0xe76ffbe7, 0xe967fd78, 0x0ba93563, 0x8e342bc1, 0xe8a11be9, 0x4980740d, 0xc8087dfc,
		  0x8de4bf99, 0xa11101a0, 0x7fd37975, 0xda5a26c0, 0xe81f994f, 0x9528cd89, 0xfd339fed, 0xb87834bf,
		  0x5f04456d, 0x22258698, 0xc9c4c83b, 0x2dc156be, 0x4f628daa, 0x57f55ec5, 0xe2220abe, 0xd2916ebf,
		  0x4ec75b95, 0x24f2c3c0, 0x42d15d99, 0xcd0d7fa0, 0x7b6e27ff, 0xa8dc8af0, 0x7345c106, 0xf41e232f,
		  0x35162386, 0xe6ea8926, 0x3333b094, 0x157ec6f2, 0x372b74af, 0x692573e4, 0xe9a9d848, 0xf3160289,
		  0x3a62ef1d, 0xa787e238, 0xf3a5f676, 0x74364853, 0x20951063, 0x4576698d, 0xb6fad407, 0x592af950,
		  0x36f73523, 0x4cfb6e87, 0x7da4cec0, 0x6c152daa, 0xcb0396a8, 0xc50dfe5d, 0xfcd707ab, 0x0921c42f,
		  0x89dff0bb, 0x5fe2be78, 0x448f4f33, 0x754613c9, 0x2b05d08d, 0x48b9d585, 0xdc049441, 0xc8098f9b,
		  0x7dede786, 0xc39a3373, 0x42410005, 0x6a091751, 0x0ef3c8a6, 0x890072d6, 0x28207682, 0xa9a9f7be,
		  0xbf32679d, 0xd45b5b75, 0xb353fd00, 0xcbb0e358, 0x830f220a, 0x1f8fb214, 0xd372cf08, 0xcc3c4a13,
		  0x8cf63166, 0x061c87be, 0x88c98f88, 0x6062e397, 0x47cf8e7a, 0xb6c85283, 0x3cc2acfb, 0x3fc06976,
		  0x4e8f0252, 0x64d8314d, 0xda3870e3, 0x1e665459, 0xc10908f0, 0x513021a5, 0x6c5b68b7, 0x822f8aa0,
		  0x3007cd3e, 0x74719eef, 0xdc872681, 0x073340d4, 0x7e432fd9, 0x0c5ec241, 0x8809286c, 0xf592d891,
		  0x08a930f6, 0x957ef305, 0xb7fbffbd, 0xc266e96f, 0x6fe4ac98, 0xb173ecc0, 0xbc60b42a, 0x953498da,
		  0xfba1ae12, 0x2d4bd736, 0x0f25faab, 0xa4f3fceb, 0xe2969123, 0x257f0c3d, 0x9348af49, 0x361400bc,
		  0xe8816f4a, 0x3814f200, 0xa3f94043, 0x9c7a54c2, 0xbc704f57, 0xda41e7f9, 0xc25ad33a, 0x54f4a084,
		  0xb17f5505, 0x59357cbe, 0xedbd15c8, 0x7f97c5ab, 0xba5ac7b5, 0xb6f6deaf, 0x3a479c3a, 0x5302da25,
		  0x653d7e6a, 0x54268d49, 0x51a477ea, 0x5017d55b, 0xd7d25d88, 0x44136c76, 0x0404a8c8, 0xb8e5a121,
		  0xb81a928a, 0x60ed5869, 0x97c55b96, 0xeaec991b, 0x29935913, 0x01fdb7f1, 0x088e8dfa, 0x9ab6f6f5,
		  0x3b4cbf9f, 0x4a5de3ab, 0xe6051d35, 0xa0e1d855, 0xd36b4cf1, 0xf544edeb, 0xb0e93524, 0xbebb8fbd,
		  0xa2d762cf, 0x49c92f54, 0x38b5f331, 0x7128a454, 0x48392905, 0xa65b1db8, 0x851c97bd, 0xd675cf2f);

		sBox[6] = new Array(
		  0x85e04019, 0x332bf567, 0x662dbfff, 0xcfc65693, 0x2a8d7f6f, 0xab9bc912, 0xde6008a1, 0x2028da1f,
		  0x0227bce7, 0x4d642916, 0x18fac300, 0x50f18b82, 0x2cb2cb11, 0xb232e75c, 0x4b3695f2, 0xb28707de,
		  0xa05fbcf6, 0xcd4181e9, 0xe150210c, 0xe24ef1bd, 0xb168c381, 0xfde4e789, 0x5c79b0d8, 0x1e8bfd43,
		  0x4d495001, 0x38be4341, 0x913cee1d, 0x92a79c3f, 0x089766be, 0xbaeeadf4, 0x1286becf, 0xb6eacb19,
		  0x2660c200, 0x7565bde4, 0x64241f7a, 0x8248dca9, 0xc3b3ad66, 0x28136086, 0x0bd8dfa8, 0x356d1cf2,
		  0x107789be, 0xb3b2e9ce, 0x0502aa8f, 0x0bc0351e, 0x166bf52a, 0xeb12ff82, 0xe3486911, 0xd34d7516,
		  0x4e7b3aff, 0x5f43671b, 0x9cf6e037, 0x4981ac83, 0x334266ce, 0x8c9341b7, 0xd0d854c0, 0xcb3a6c88,
		  0x47bc2829, 0x4725ba37, 0xa66ad22b, 0x7ad61f1e, 0x0c5cbafa, 0x4437f107, 0xb6e79962, 0x42d2d816,
		  0x0a961288, 0xe1a5c06e, 0x13749e67, 0x72fc081a, 0xb1d139f7, 0xf9583745, 0xcf19df58, 0xbec3f756,
		  0xc06eba30, 0x07211b24, 0x45c28829, 0xc95e317f, 0xbc8ec511, 0x38bc46e9, 0xc6e6fa14, 0xbae8584a,
		  0xad4ebc46, 0x468f508b, 0x7829435f, 0xf124183b, 0x821dba9f, 0xaff60ff4, 0xea2c4e6d, 0x16e39264,
		  0x92544a8b, 0x009b4fc3, 0xaba68ced, 0x9ac96f78, 0x06a5b79a, 0xb2856e6e, 0x1aec3ca9, 0xbe838688,
		  0x0e0804e9, 0x55f1be56, 0xe7e5363b, 0xb3a1f25d, 0xf7debb85, 0x61fe033c, 0x16746233, 0x3c034c28,
		  0xda6d0c74, 0x79aac56c, 0x3ce4e1ad, 0x51f0c802, 0x98f8f35a, 0x1626a49f, 0xeed82b29, 0x1d382fe3,
		  0x0c4fb99a, 0xbb325778, 0x3ec6d97b, 0x6e77a6a9, 0xcb658b5c, 0xd45230c7, 0x2bd1408b, 0x60c03eb7,
		  0xb9068d78, 0xa33754f4, 0xf430c87d, 0xc8a71302, 0xb96d8c32, 0xebd4e7be, 0xbe8b9d2d, 0x7979fb06,
		  0xe7225308, 0x8b75cf77, 0x11ef8da4, 0xe083c858, 0x8d6b786f, 0x5a6317a6, 0xfa5cf7a0, 0x5dda0033,
		  0xf28ebfb0, 0xf5b9c310, 0xa0eac280, 0x08b9767a, 0xa3d9d2b0, 0x79d34217, 0x021a718d, 0x9ac6336a,
		  0x2711fd60, 0x438050e3, 0x069908a8, 0x3d7fedc4, 0x826d2bef, 0x4eeb8476, 0x488dcf25, 0x36c9d566,
		  0x28e74e41, 0xc2610aca, 0x3d49a9cf, 0xbae3b9df, 0xb65f8de6, 0x92aeaf64, 0x3ac7d5e6, 0x9ea80509,
		  0xf22b017d, 0xa4173f70, 0xdd1e16c3, 0x15e0d7f9, 0x50b1b887, 0x2b9f4fd5, 0x625aba82, 0x6a017962,
		  0x2ec01b9c, 0x15488aa9, 0xd716e740, 0x40055a2c, 0x93d29a22, 0xe32dbf9a, 0x058745b9, 0x3453dc1e,
		  0xd699296e, 0x496cff6f, 0x1c9f4986, 0xdfe2ed07, 0xb87242d1, 0x19de7eae, 0x053e561a, 0x15ad6f8c,
		  0x66626c1c, 0x7154c24c, 0xea082b2a, 0x93eb2939, 0x17dcb0f0, 0x58d4f2ae, 0x9ea294fb, 0x52cf564c,
		  0x9883fe66, 0x2ec40581, 0x763953c3, 0x01d6692e, 0xd3a0c108, 0xa1e7160e, 0xe4f2dfa6, 0x693ed285,
		  0x74904698, 0x4c2b0edd, 0x4f757656, 0x5d393378, 0xa132234f, 0x3d321c5d, 0xc3f5e194, 0x4b269301,
		  0xc79f022f, 0x3c997e7e, 0x5e4f9504, 0x3ffafbbd, 0x76f7ad0e, 0x296693f4, 0x3d1fce6f, 0xc61e45be,
		  0xd3b5ab34, 0xf72bf9b7, 0x1b0434c0, 0x4e72b567, 0x5592a33d, 0xb5229301, 0xcfd2a87f, 0x60aeb767,
		  0x1814386b, 0x30bcc33d, 0x38a0c07d, 0xfd1606f2, 0xc363519b, 0x589dd390, 0x5479f8e6, 0x1cb8d647,
		  0x97fd61a9, 0xea7759f4, 0x2d57539d, 0x569a58cf, 0xe84e63ad, 0x462e1b78, 0x6580f87e, 0xf3817914,
		  0x91da55f4, 0x40a230f3, 0xd1988f35, 0xb6e318d2, 0x3ffa50bc, 0x3d40f021, 0xc3c0bdae, 0x4958c24c,
		  0x518f36b2, 0x84b1d370, 0x0fedce83, 0x878ddada, 0xf2a279c7, 0x94e01be8, 0x90716f4b, 0x954b8aa3);

		sBox[7] = new Array(
		  0xe216300d, 0xbbddfffc, 0xa7ebdabd, 0x35648095, 0x7789f8b7, 0xe6c1121b, 0x0e241600, 0x052ce8b5,
		  0x11a9cfb0, 0xe5952f11, 0xece7990a, 0x9386d174, 0x2a42931c, 0x76e38111, 0xb12def3a, 0x37ddddfc,
		  0xde9adeb1, 0x0a0cc32c, 0xbe197029, 0x84a00940, 0xbb243a0f, 0xb4d137cf, 0xb44e79f0, 0x049eedfd,
		  0x0b15a15d, 0x480d3168, 0x8bbbde5a, 0x669ded42, 0xc7ece831, 0x3f8f95e7, 0x72df191b, 0x7580330d,
		  0x94074251, 0x5c7dcdfa, 0xabbe6d63, 0xaa402164, 0xb301d40a, 0x02e7d1ca, 0x53571dae, 0x7a3182a2,
		  0x12a8ddec, 0xfdaa335d, 0x176f43e8, 0x71fb46d4, 0x38129022, 0xce949ad4, 0xb84769ad, 0x965bd862,
		  0x82f3d055, 0x66fb9767, 0x15b80b4e, 0x1d5b47a0, 0x4cfde06f, 0xc28ec4b8, 0x57e8726e, 0x647a78fc,
		  0x99865d44, 0x608bd593, 0x6c200e03, 0x39dc5ff6, 0x5d0b00a3, 0xae63aff2, 0x7e8bd632, 0x70108c0c,
		  0xbbd35049, 0x2998df04, 0x980cf42a, 0x9b6df491, 0x9e7edd53, 0x06918548, 0x58cb7e07, 0x3b74ef2e,
		  0x522fffb1, 0xd24708cc, 0x1c7e27cd, 0xa4eb215b, 0x3cf1d2e2, 0x19b47a38, 0x424f7618, 0x35856039,
		  0x9d17dee7, 0x27eb35e6, 0xc9aff67b, 0x36baf5b8, 0x09c467cd, 0xc18910b1, 0xe11dbf7b, 0x06cd1af8,
		  0x7170c608, 0x2d5e3354, 0xd4de495a, 0x64c6d006, 0xbcc0c62c, 0x3dd00db3, 0x708f8f34, 0x77d51b42,
		  0x264f620f, 0x24b8d2bf, 0x15c1b79e, 0x46a52564, 0xf8d7e54e, 0x3e378160, 0x7895cda5, 0x859c15a5,
		  0xe6459788, 0xc37bc75f, 0xdb07ba0c, 0x0676a3ab, 0x7f229b1e, 0x31842e7b, 0x24259fd7, 0xf8bef472,
		  0x835ffcb8, 0x6df4c1f2, 0x96f5b195, 0xfd0af0fc, 0xb0fe134c, 0xe2506d3d, 0x4f9b12ea, 0xf215f225,
		  0xa223736f, 0x9fb4c428, 0x25d04979, 0x34c713f8, 0xc4618187, 0xea7a6e98, 0x7cd16efc, 0x1436876c,
		  0xf1544107, 0xbedeee14, 0x56e9af27, 0xa04aa441, 0x3cf7c899, 0x92ecbae6, 0xdd67016d, 0x151682eb,
		  0xa842eedf, 0xfdba60b4, 0xf1907b75, 0x20e3030f, 0x24d8c29e, 0xe139673b, 0xefa63fb8, 0x71873054,
		  0xb6f2cf3b, 0x9f326442, 0xcb15a4cc, 0xb01a4504, 0xf1e47d8d, 0x844a1be5, 0xbae7dfdc, 0x42cbda70,
		  0xcd7dae0a, 0x57e85b7a, 0xd53f5af6, 0x20cf4d8c, 0xcea4d428, 0x79d130a4, 0x3486ebfb, 0x33d3cddc,
		  0x77853b53, 0x37effcb5, 0xc5068778, 0xe580b3e6, 0x4e68b8f4, 0xc5c8b37e, 0x0d809ea2, 0x398feb7c,
		  0x132a4f94, 0x43b7950e, 0x2fee7d1c, 0x223613bd, 0xdd06caa2, 0x37df932b, 0xc4248289, 0xacf3ebc3,
		  0x5715f6b7, 0xef3478dd, 0xf267616f, 0xc148cbe4, 0x9052815e, 0x5e410fab, 0xb48a2465, 0x2eda7fa4,
		  0xe87b40e4, 0xe98ea084, 0x5889e9e1, 0xefd390fc, 0xdd07d35b, 0xdb485694, 0x38d7e5b2, 0x57720101,
		  0x730edebc, 0x5b643113, 0x94917e4f, 0x503c2fba, 0x646f1282, 0x7523d24a, 0xe0779695, 0xf9c17a8f,
		  0x7a5b2121, 0xd187b896, 0x29263a4d, 0xba510cdf, 0x81f47c9f, 0xad1163ed, 0xea7b5965, 0x1a00726e,
		  0x11403092, 0x00da6d77, 0x4a0cdd61, 0xad1f4603, 0x605bdfb0, 0x9eedc364, 0x22ebe6a8, 0xcee7d28a,
		  0xa0e736a0, 0x5564a6b9, 0x10853209, 0xc7eb8f37, 0x2de705ca, 0x8951570f, 0xdf09822b, 0xbd691a6c,
		  0xaa12e4f2, 0x87451c0f, 0xe0f6a27a, 0x3ada4819, 0x4cf1764f, 0x0d771c2b, 0x67cdb156, 0x350d8384,
		  0x5938fa0f, 0x42399ef3, 0x36997b07, 0x0e84093d, 0x4aa93e61, 0x8360d87b, 0x1fa98b0c, 0x1149382c,
		  0xe97625a5, 0x0614d1b7, 0x0e25244b, 0x0c768347, 0x589e8d82, 0x0d2059d1, 0xa466bb1e, 0xf8da0a82,
		  0x04f19130, 0xba6e4ec0, 0x99265164, 0x1ee7230d, 0x50b2ad80, 0xeaee6801, 0x8db2a283, 0xea8bf59e);

};


module.exports = cast5_encrypt;

},{"../../util":7}],41:[function(require,module,exports){
/* Modified by Recurity Labs GmbH 
 * 
 * Cipher.js
 * A block-cipher algorithm implementation on JavaScript
 * See Cipher.readme.txt for further information.
 *
 * Copyright(c) 2009 Atsushi Oka [ http://oka.nu/ ]
 * This script file is distributed under the LGPL
 *
 * ACKNOWLEDGMENT
 *
 *     The main subroutines are written by Michiel van Everdingen.
 * 
 *     Michiel van Everdingen
 *     http://home.versatel.nl/MAvanEverdingen/index.html
 * 
 *     All rights for these routines are reserved to Michiel van Everdingen.
 *
 */

var util = require('../../util');

// added by Recurity Labs
function TFencrypt(block, key) {
	var block_copy = [].concat(block);
	var tf = createTwofish();
	tf.open(util.str2bin(key),0);
	var result = tf.encrypt(block_copy, 0);
	tf.close();
	return result;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//Math
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

var MAXINT = 0xFFFFFFFF;

function rotb(b,n){ return ( b<<n | b>>>( 8-n) ) & 0xFF; }
function rotw(w,n){ return ( w<<n | w>>>(32-n) ) & MAXINT; }
function getW(a,i){ return a[i]|a[i+1]<<8|a[i+2]<<16|a[i+3]<<24; }
function setW(a,i,w){ a.splice(i,4,w&0xFF,(w>>>8)&0xFF,(w>>>16)&0xFF,(w>>>24)&0xFF); }
function setWInv(a,i,w){ a.splice(i,4,(w>>>24)&0xFF,(w>>>16)&0xFF,(w>>>8)&0xFF,w&0xFF); }
function getB(x,n){ return (x>>>(n*8))&0xFF; }

function getNrBits(i){ var n=0; while (i>0){ n++; i>>>=1; } return n; }
function getMask(n){ return (1<<n)-1; }

//added 2008/11/13 XXX MUST USE ONE-WAY HASH FUNCTION FOR SECURITY REASON
function randByte() {
 return Math.floor( Math.random() * 256 );
}
// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Twofish
// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

function createTwofish() {
	//
	var keyBytes = null;
	var dataBytes = null;
	var dataOffset = -1;
	// var dataLength = -1;
	var algorithmName = null;
	// var idx2 = -1;
	//

	algorithmName = "twofish";

	var tfsKey = [];
	var tfsM = [ [], [], [], [] ];

	function tfsInit(key) {
		keyBytes = key;
		var i, a, b, c, d, meKey = [], moKey = [], inKey = [];
		var kLen;
		var sKey = [];
		var f01, f5b, fef;

		var q0 = [ [ 8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4 ],
				[ 2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5 ] ];
		var q1 = [ [ 14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13 ],
				[ 1, 14, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8 ] ];
		var q2 = [ [ 11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1 ],
				[ 4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15 ] ];
		var q3 = [ [ 13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10 ],
				[ 11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10 ] ];
		var ror4 = [ 0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15 ];
		var ashx = [ 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 5, 14, 7 ];
		var q = [ [], [] ];
		var m = [ [], [], [], [] ];

		function ffm5b(x) {
			return x ^ (x >> 2) ^ [ 0, 90, 180, 238 ][x & 3];
		}
		function ffmEf(x) {
			return x ^ (x >> 1) ^ (x >> 2) ^ [ 0, 238, 180, 90 ][x & 3];
		}

		function mdsRem(p, q) {
			var i, t, u;
			for (i = 0; i < 8; i++) {
				t = q >>> 24;
				q = ((q << 8) & MAXINT) | p >>> 24;
				p = (p << 8) & MAXINT;
				u = t << 1;
				if (t & 128) {
					u ^= 333;
				}
				q ^= t ^ (u << 16);
				u ^= t >>> 1;
				if (t & 1) {
					u ^= 166;
				}
				q ^= u << 24 | u << 8;
			}
			return q;
		}

		function qp(n, x) {
			var a, b, c, d;
			a = x >> 4;
			b = x & 15;
			c = q0[n][a ^ b];
			d = q1[n][ror4[b] ^ ashx[a]];
			return q3[n][ror4[d] ^ ashx[c]] << 4 | q2[n][c ^ d];
		}

		function hFun(x, key) {
			var a = getB(x, 0), b = getB(x, 1), c = getB(x, 2), d = getB(x, 3);
			switch (kLen) {
			case 4:
				a = q[1][a] ^ getB(key[3], 0);
				b = q[0][b] ^ getB(key[3], 1);
				c = q[0][c] ^ getB(key[3], 2);
				d = q[1][d] ^ getB(key[3], 3);
			case 3:
				a = q[1][a] ^ getB(key[2], 0);
				b = q[1][b] ^ getB(key[2], 1);
				c = q[0][c] ^ getB(key[2], 2);
				d = q[0][d] ^ getB(key[2], 3);
			case 2:
				a = q[0][q[0][a] ^ getB(key[1], 0)] ^ getB(key[0], 0);
				b = q[0][q[1][b] ^ getB(key[1], 1)] ^ getB(key[0], 1);
				c = q[1][q[0][c] ^ getB(key[1], 2)] ^ getB(key[0], 2);
				d = q[1][q[1][d] ^ getB(key[1], 3)] ^ getB(key[0], 3);
			}
			return m[0][a] ^ m[1][b] ^ m[2][c] ^ m[3][d];
		}

		keyBytes = keyBytes.slice(0, 32);
		i = keyBytes.length;
		while (i != 16 && i != 24 && i != 32)
			keyBytes[i++] = 0;

		for (i = 0; i < keyBytes.length; i += 4) {
			inKey[i >> 2] = getW(keyBytes, i);
		}
		for (i = 0; i < 256; i++) {
			q[0][i] = qp(0, i);
			q[1][i] = qp(1, i);
		}
		for (i = 0; i < 256; i++) {
			f01 = q[1][i];
			f5b = ffm5b(f01);
			fef = ffmEf(f01);
			m[0][i] = f01 + (f5b << 8) + (fef << 16) + (fef << 24);
			m[2][i] = f5b + (fef << 8) + (f01 << 16) + (fef << 24);
			f01 = q[0][i];
			f5b = ffm5b(f01);
			fef = ffmEf(f01);
			m[1][i] = fef + (fef << 8) + (f5b << 16) + (f01 << 24);
			m[3][i] = f5b + (f01 << 8) + (fef << 16) + (f5b << 24);
		}

		kLen = inKey.length / 2;
		for (i = 0; i < kLen; i++) {
			a = inKey[i + i];
			meKey[i] = a;
			b = inKey[i + i + 1];
			moKey[i] = b;
			sKey[kLen - i - 1] = mdsRem(a, b);
		}
		for (i = 0; i < 40; i += 2) {
			a = 0x1010101 * i;
			b = a + 0x1010101;
			a = hFun(a, meKey);
			b = rotw(hFun(b, moKey), 8);
			tfsKey[i] = (a + b) & MAXINT;
			tfsKey[i + 1] = rotw(a + 2 * b, 9);
		}
		for (i = 0; i < 256; i++) {
			a = b = c = d = i;
			switch (kLen) {
			case 4:
				a = q[1][a] ^ getB(sKey[3], 0);
				b = q[0][b] ^ getB(sKey[3], 1);
				c = q[0][c] ^ getB(sKey[3], 2);
				d = q[1][d] ^ getB(sKey[3], 3);
			case 3:
				a = q[1][a] ^ getB(sKey[2], 0);
				b = q[1][b] ^ getB(sKey[2], 1);
				c = q[0][c] ^ getB(sKey[2], 2);
				d = q[0][d] ^ getB(sKey[2], 3);
			case 2:
				tfsM[0][i] = m[0][q[0][q[0][a] ^ getB(sKey[1], 0)]
						^ getB(sKey[0], 0)];
				tfsM[1][i] = m[1][q[0][q[1][b] ^ getB(sKey[1], 1)]
						^ getB(sKey[0], 1)];
				tfsM[2][i] = m[2][q[1][q[0][c] ^ getB(sKey[1], 2)]
						^ getB(sKey[0], 2)];
				tfsM[3][i] = m[3][q[1][q[1][d] ^ getB(sKey[1], 3)]
						^ getB(sKey[0], 3)];
			}
		}
	}

	function tfsG0(x) {
		return tfsM[0][getB(x, 0)] ^ tfsM[1][getB(x, 1)] ^ tfsM[2][getB(x, 2)]
				^ tfsM[3][getB(x, 3)];
	}
	function tfsG1(x) {
		return tfsM[0][getB(x, 3)] ^ tfsM[1][getB(x, 0)] ^ tfsM[2][getB(x, 1)]
				^ tfsM[3][getB(x, 2)];
	}

	function tfsFrnd(r, blk) {
		var a = tfsG0(blk[0]);
		var b = tfsG1(blk[1]);
		blk[2] = rotw(blk[2] ^ (a + b + tfsKey[4 * r + 8]) & MAXINT, 31);
		blk[3] = rotw(blk[3], 1) ^ (a + 2 * b + tfsKey[4 * r + 9]) & MAXINT;
		a = tfsG0(blk[2]);
		b = tfsG1(blk[3]);
		blk[0] = rotw(blk[0] ^ (a + b + tfsKey[4 * r + 10]) & MAXINT, 31);
		blk[1] = rotw(blk[1], 1) ^ (a + 2 * b + tfsKey[4 * r + 11]) & MAXINT;
	}

	function tfsIrnd(i, blk) {
		var a = tfsG0(blk[0]);
		var b = tfsG1(blk[1]);
		blk[2] = rotw(blk[2], 1) ^ (a + b + tfsKey[4 * i + 10]) & MAXINT;
		blk[3] = rotw(blk[3] ^ (a + 2 * b + tfsKey[4 * i + 11]) & MAXINT, 31);
		a = tfsG0(blk[2]);
		b = tfsG1(blk[3]);
		blk[0] = rotw(blk[0], 1) ^ (a + b + tfsKey[4 * i + 8]) & MAXINT;
		blk[1] = rotw(blk[1] ^ (a + 2 * b + tfsKey[4 * i + 9]) & MAXINT, 31);
	}

	function tfsClose() {
		tfsKey = [];
		tfsM = [ [], [], [], [] ];
	}

	function tfsEncrypt(data, offset) {
		dataBytes = data;
		dataOffset = offset;
		var blk = [ getW(dataBytes, dataOffset) ^ tfsKey[0],
				getW(dataBytes, dataOffset + 4) ^ tfsKey[1],
				getW(dataBytes, dataOffset + 8) ^ tfsKey[2],
				getW(dataBytes, dataOffset + 12) ^ tfsKey[3] ];
		for ( var j = 0; j < 8; j++) {
			tfsFrnd(j, blk);
		}
		setW(dataBytes, dataOffset, blk[2] ^ tfsKey[4]);
		setW(dataBytes, dataOffset + 4, blk[3] ^ tfsKey[5]);
		setW(dataBytes, dataOffset + 8, blk[0] ^ tfsKey[6]);
		setW(dataBytes, dataOffset + 12, blk[1] ^ tfsKey[7]);
		dataOffset += 16;
		return dataBytes;
	}

	function tfsDecrypt(data, offset) {
		dataBytes = data;
		dataOffset = offset;
		var blk = [ getW(dataBytes, dataOffset) ^ tfsKey[4],
				getW(dataBytes, dataOffset + 4) ^ tfsKey[5],
				getW(dataBytes, dataOffset + 8) ^ tfsKey[6],
				getW(dataBytes, dataOffset + 12) ^ tfsKey[7] ];
		for ( var j = 7; j >= 0; j--) {
			tfsIrnd(j, blk);
		}
		setW(dataBytes, dataOffset, blk[2] ^ tfsKey[0]);
		setW(dataBytes, dataOffset + 4, blk[3] ^ tfsKey[1]);
		setW(dataBytes, dataOffset + 8, blk[0] ^ tfsKey[2]);
		setW(dataBytes, dataOffset + 12, blk[1] ^ tfsKey[3]);
		dataOffset += 16;
	}
	
	// added by Recurity Labs
	function tfsFinal() {
		return dataBytes;
	}

	return {
		name : "twofish",
		blocksize : 128 / 8,
		open : tfsInit,
		close : tfsClose,
		encrypt : tfsEncrypt,
		decrypt : tfsDecrypt,
		// added by Recurity Labs
		finalize: tfsFinal
	};
}

module.exports = TFencrypt;

},{"../../util":7}],42:[function(require,module,exports){
/* Modified by Recurity Labs GmbH 
 * 
 * Originally written by nklein software (nklein.com)
 */

/* 
 * Javascript implementation based on Bruce Schneier's reference implementation.
 *
 *
 * The constructor doesn't do much of anything.  It's just here
 * so we can start defining properties and methods and such.
 */
function Blowfish() {
};

/*
 * Declare the block size so that protocols know what size
 * Initialization Vector (IV) they will need.
 */
Blowfish.prototype.BLOCKSIZE = 8;

/*
 * These are the default SBOXES.
 */
Blowfish.prototype.SBOXES = [
    [
	0xd1310ba6, 0x98dfb5ac, 0x2ffd72db, 0xd01adfb7, 0xb8e1afed, 0x6a267e96,
	0xba7c9045, 0xf12c7f99, 0x24a19947, 0xb3916cf7, 0x0801f2e2, 0x858efc16,
	0x636920d8, 0x71574e69, 0xa458fea3, 0xf4933d7e, 0x0d95748f, 0x728eb658,
	0x718bcd58, 0x82154aee, 0x7b54a41d, 0xc25a59b5, 0x9c30d539, 0x2af26013,
	0xc5d1b023, 0x286085f0, 0xca417918, 0xb8db38ef, 0x8e79dcb0, 0x603a180e,
	0x6c9e0e8b, 0xb01e8a3e, 0xd71577c1, 0xbd314b27, 0x78af2fda, 0x55605c60,
	0xe65525f3, 0xaa55ab94, 0x57489862, 0x63e81440, 0x55ca396a, 0x2aab10b6,
	0xb4cc5c34, 0x1141e8ce, 0xa15486af, 0x7c72e993, 0xb3ee1411, 0x636fbc2a,
	0x2ba9c55d, 0x741831f6, 0xce5c3e16, 0x9b87931e, 0xafd6ba33, 0x6c24cf5c,
	0x7a325381, 0x28958677, 0x3b8f4898, 0x6b4bb9af, 0xc4bfe81b, 0x66282193,
	0x61d809cc, 0xfb21a991, 0x487cac60, 0x5dec8032, 0xef845d5d, 0xe98575b1,
	0xdc262302, 0xeb651b88, 0x23893e81, 0xd396acc5, 0x0f6d6ff3, 0x83f44239,
	0x2e0b4482, 0xa4842004, 0x69c8f04a, 0x9e1f9b5e, 0x21c66842, 0xf6e96c9a,
	0x670c9c61, 0xabd388f0, 0x6a51a0d2, 0xd8542f68, 0x960fa728, 0xab5133a3,
	0x6eef0b6c, 0x137a3be4, 0xba3bf050, 0x7efb2a98, 0xa1f1651d, 0x39af0176,
	0x66ca593e, 0x82430e88, 0x8cee8619, 0x456f9fb4, 0x7d84a5c3, 0x3b8b5ebe,
	0xe06f75d8, 0x85c12073, 0x401a449f, 0x56c16aa6, 0x4ed3aa62, 0x363f7706,
	0x1bfedf72, 0x429b023d, 0x37d0d724, 0xd00a1248, 0xdb0fead3, 0x49f1c09b,
	0x075372c9, 0x80991b7b, 0x25d479d8, 0xf6e8def7, 0xe3fe501a, 0xb6794c3b,
	0x976ce0bd, 0x04c006ba, 0xc1a94fb6, 0x409f60c4, 0x5e5c9ec2, 0x196a2463,
	0x68fb6faf, 0x3e6c53b5, 0x1339b2eb, 0x3b52ec6f, 0x6dfc511f, 0x9b30952c,
	0xcc814544, 0xaf5ebd09, 0xbee3d004, 0xde334afd, 0x660f2807, 0x192e4bb3,
	0xc0cba857, 0x45c8740f, 0xd20b5f39, 0xb9d3fbdb, 0x5579c0bd, 0x1a60320a,
	0xd6a100c6, 0x402c7279, 0x679f25fe, 0xfb1fa3cc, 0x8ea5e9f8, 0xdb3222f8,
	0x3c7516df, 0xfd616b15, 0x2f501ec8, 0xad0552ab, 0x323db5fa, 0xfd238760,
	0x53317b48, 0x3e00df82, 0x9e5c57bb, 0xca6f8ca0, 0x1a87562e, 0xdf1769db,
	0xd542a8f6, 0x287effc3, 0xac6732c6, 0x8c4f5573, 0x695b27b0, 0xbbca58c8,
	0xe1ffa35d, 0xb8f011a0, 0x10fa3d98, 0xfd2183b8, 0x4afcb56c, 0x2dd1d35b,
	0x9a53e479, 0xb6f84565, 0xd28e49bc, 0x4bfb9790, 0xe1ddf2da, 0xa4cb7e33,
	0x62fb1341, 0xcee4c6e8, 0xef20cada, 0x36774c01, 0xd07e9efe, 0x2bf11fb4,
	0x95dbda4d, 0xae909198, 0xeaad8e71, 0x6b93d5a0, 0xd08ed1d0, 0xafc725e0,
	0x8e3c5b2f, 0x8e7594b7, 0x8ff6e2fb, 0xf2122b64, 0x8888b812, 0x900df01c,
	0x4fad5ea0, 0x688fc31c, 0xd1cff191, 0xb3a8c1ad, 0x2f2f2218, 0xbe0e1777,
	0xea752dfe, 0x8b021fa1, 0xe5a0cc0f, 0xb56f74e8, 0x18acf3d6, 0xce89e299,
	0xb4a84fe0, 0xfd13e0b7, 0x7cc43b81, 0xd2ada8d9, 0x165fa266, 0x80957705,
	0x93cc7314, 0x211a1477, 0xe6ad2065, 0x77b5fa86, 0xc75442f5, 0xfb9d35cf,
	0xebcdaf0c, 0x7b3e89a0, 0xd6411bd3, 0xae1e7e49, 0x00250e2d, 0x2071b35e,
	0x226800bb, 0x57b8e0af, 0x2464369b, 0xf009b91e, 0x5563911d, 0x59dfa6aa,
	0x78c14389, 0xd95a537f, 0x207d5ba2, 0x02e5b9c5, 0x83260376, 0x6295cfa9,
	0x11c81968, 0x4e734a41, 0xb3472dca, 0x7b14a94a, 0x1b510052, 0x9a532915,
	0xd60f573f, 0xbc9bc6e4, 0x2b60a476, 0x81e67400, 0x08ba6fb5, 0x571be91f,
	0xf296ec6b, 0x2a0dd915, 0xb6636521, 0xe7b9f9b6, 0xff34052e, 0xc5855664,
	0x53b02d5d, 0xa99f8fa1, 0x08ba4799, 0x6e85076a
    ], [
	0x4b7a70e9, 0xb5b32944, 0xdb75092e, 0xc4192623, 0xad6ea6b0, 0x49a7df7d,
	0x9cee60b8, 0x8fedb266, 0xecaa8c71, 0x699a17ff, 0x5664526c, 0xc2b19ee1,
	0x193602a5, 0x75094c29, 0xa0591340, 0xe4183a3e, 0x3f54989a, 0x5b429d65,
	0x6b8fe4d6, 0x99f73fd6, 0xa1d29c07, 0xefe830f5, 0x4d2d38e6, 0xf0255dc1,
	0x4cdd2086, 0x8470eb26, 0x6382e9c6, 0x021ecc5e, 0x09686b3f, 0x3ebaefc9,
	0x3c971814, 0x6b6a70a1, 0x687f3584, 0x52a0e286, 0xb79c5305, 0xaa500737,
	0x3e07841c, 0x7fdeae5c, 0x8e7d44ec, 0x5716f2b8, 0xb03ada37, 0xf0500c0d,
	0xf01c1f04, 0x0200b3ff, 0xae0cf51a, 0x3cb574b2, 0x25837a58, 0xdc0921bd,
	0xd19113f9, 0x7ca92ff6, 0x94324773, 0x22f54701, 0x3ae5e581, 0x37c2dadc,
	0xc8b57634, 0x9af3dda7, 0xa9446146, 0x0fd0030e, 0xecc8c73e, 0xa4751e41,
	0xe238cd99, 0x3bea0e2f, 0x3280bba1, 0x183eb331, 0x4e548b38, 0x4f6db908,
	0x6f420d03, 0xf60a04bf, 0x2cb81290, 0x24977c79, 0x5679b072, 0xbcaf89af,
	0xde9a771f, 0xd9930810, 0xb38bae12, 0xdccf3f2e, 0x5512721f, 0x2e6b7124,
	0x501adde6, 0x9f84cd87, 0x7a584718, 0x7408da17, 0xbc9f9abc, 0xe94b7d8c,
	0xec7aec3a, 0xdb851dfa, 0x63094366, 0xc464c3d2, 0xef1c1847, 0x3215d908,
	0xdd433b37, 0x24c2ba16, 0x12a14d43, 0x2a65c451, 0x50940002, 0x133ae4dd,
	0x71dff89e, 0x10314e55, 0x81ac77d6, 0x5f11199b, 0x043556f1, 0xd7a3c76b,
	0x3c11183b, 0x5924a509, 0xf28fe6ed, 0x97f1fbfa, 0x9ebabf2c, 0x1e153c6e,
	0x86e34570, 0xeae96fb1, 0x860e5e0a, 0x5a3e2ab3, 0x771fe71c, 0x4e3d06fa,
	0x2965dcb9, 0x99e71d0f, 0x803e89d6, 0x5266c825, 0x2e4cc978, 0x9c10b36a,
	0xc6150eba, 0x94e2ea78, 0xa5fc3c53, 0x1e0a2df4, 0xf2f74ea7, 0x361d2b3d,
	0x1939260f, 0x19c27960, 0x5223a708, 0xf71312b6, 0xebadfe6e, 0xeac31f66,
	0xe3bc4595, 0xa67bc883, 0xb17f37d1, 0x018cff28, 0xc332ddef, 0xbe6c5aa5,
	0x65582185, 0x68ab9802, 0xeecea50f, 0xdb2f953b, 0x2aef7dad, 0x5b6e2f84,
	0x1521b628, 0x29076170, 0xecdd4775, 0x619f1510, 0x13cca830, 0xeb61bd96,
	0x0334fe1e, 0xaa0363cf, 0xb5735c90, 0x4c70a239, 0xd59e9e0b, 0xcbaade14,
	0xeecc86bc, 0x60622ca7, 0x9cab5cab, 0xb2f3846e, 0x648b1eaf, 0x19bdf0ca,
	0xa02369b9, 0x655abb50, 0x40685a32, 0x3c2ab4b3, 0x319ee9d5, 0xc021b8f7,
	0x9b540b19, 0x875fa099, 0x95f7997e, 0x623d7da8, 0xf837889a, 0x97e32d77,
	0x11ed935f, 0x16681281, 0x0e358829, 0xc7e61fd6, 0x96dedfa1, 0x7858ba99,
	0x57f584a5, 0x1b227263, 0x9b83c3ff, 0x1ac24696, 0xcdb30aeb, 0x532e3054,
	0x8fd948e4, 0x6dbc3128, 0x58ebf2ef, 0x34c6ffea, 0xfe28ed61, 0xee7c3c73,
	0x5d4a14d9, 0xe864b7e3, 0x42105d14, 0x203e13e0, 0x45eee2b6, 0xa3aaabea,
	0xdb6c4f15, 0xfacb4fd0, 0xc742f442, 0xef6abbb5, 0x654f3b1d, 0x41cd2105,
	0xd81e799e, 0x86854dc7, 0xe44b476a, 0x3d816250, 0xcf62a1f2, 0x5b8d2646,
	0xfc8883a0, 0xc1c7b6a3, 0x7f1524c3, 0x69cb7492, 0x47848a0b, 0x5692b285,
	0x095bbf00, 0xad19489d, 0x1462b174, 0x23820e00, 0x58428d2a, 0x0c55f5ea,
	0x1dadf43e, 0x233f7061, 0x3372f092, 0x8d937e41, 0xd65fecf1, 0x6c223bdb,
	0x7cde3759, 0xcbee7460, 0x4085f2a7, 0xce77326e, 0xa6078084, 0x19f8509e,
	0xe8efd855, 0x61d99735, 0xa969a7aa, 0xc50c06c2, 0x5a04abfc, 0x800bcadc,
	0x9e447a2e, 0xc3453484, 0xfdd56705, 0x0e1e9ec9, 0xdb73dbd3, 0x105588cd,
	0x675fda79, 0xe3674340, 0xc5c43465, 0x713e38d8, 0x3d28f89e, 0xf16dff20,
	0x153e21e7, 0x8fb03d4a, 0xe6e39f2b, 0xdb83adf7
    ], [
	0xe93d5a68, 0x948140f7, 0xf64c261c, 0x94692934, 0x411520f7, 0x7602d4f7,
	0xbcf46b2e, 0xd4a20068, 0xd4082471, 0x3320f46a, 0x43b7d4b7, 0x500061af,
	0x1e39f62e, 0x97244546, 0x14214f74, 0xbf8b8840, 0x4d95fc1d, 0x96b591af,
	0x70f4ddd3, 0x66a02f45, 0xbfbc09ec, 0x03bd9785, 0x7fac6dd0, 0x31cb8504,
	0x96eb27b3, 0x55fd3941, 0xda2547e6, 0xabca0a9a, 0x28507825, 0x530429f4,
	0x0a2c86da, 0xe9b66dfb, 0x68dc1462, 0xd7486900, 0x680ec0a4, 0x27a18dee,
	0x4f3ffea2, 0xe887ad8c, 0xb58ce006, 0x7af4d6b6, 0xaace1e7c, 0xd3375fec,
	0xce78a399, 0x406b2a42, 0x20fe9e35, 0xd9f385b9, 0xee39d7ab, 0x3b124e8b,
	0x1dc9faf7, 0x4b6d1856, 0x26a36631, 0xeae397b2, 0x3a6efa74, 0xdd5b4332,
	0x6841e7f7, 0xca7820fb, 0xfb0af54e, 0xd8feb397, 0x454056ac, 0xba489527,
	0x55533a3a, 0x20838d87, 0xfe6ba9b7, 0xd096954b, 0x55a867bc, 0xa1159a58,
	0xcca92963, 0x99e1db33, 0xa62a4a56, 0x3f3125f9, 0x5ef47e1c, 0x9029317c,
	0xfdf8e802, 0x04272f70, 0x80bb155c, 0x05282ce3, 0x95c11548, 0xe4c66d22,
	0x48c1133f, 0xc70f86dc, 0x07f9c9ee, 0x41041f0f, 0x404779a4, 0x5d886e17,
	0x325f51eb, 0xd59bc0d1, 0xf2bcc18f, 0x41113564, 0x257b7834, 0x602a9c60,
	0xdff8e8a3, 0x1f636c1b, 0x0e12b4c2, 0x02e1329e, 0xaf664fd1, 0xcad18115,
	0x6b2395e0, 0x333e92e1, 0x3b240b62, 0xeebeb922, 0x85b2a20e, 0xe6ba0d99,
	0xde720c8c, 0x2da2f728, 0xd0127845, 0x95b794fd, 0x647d0862, 0xe7ccf5f0,
	0x5449a36f, 0x877d48fa, 0xc39dfd27, 0xf33e8d1e, 0x0a476341, 0x992eff74,
	0x3a6f6eab, 0xf4f8fd37, 0xa812dc60, 0xa1ebddf8, 0x991be14c, 0xdb6e6b0d,
	0xc67b5510, 0x6d672c37, 0x2765d43b, 0xdcd0e804, 0xf1290dc7, 0xcc00ffa3,
	0xb5390f92, 0x690fed0b, 0x667b9ffb, 0xcedb7d9c, 0xa091cf0b, 0xd9155ea3,
	0xbb132f88, 0x515bad24, 0x7b9479bf, 0x763bd6eb, 0x37392eb3, 0xcc115979,
	0x8026e297, 0xf42e312d, 0x6842ada7, 0xc66a2b3b, 0x12754ccc, 0x782ef11c,
	0x6a124237, 0xb79251e7, 0x06a1bbe6, 0x4bfb6350, 0x1a6b1018, 0x11caedfa,
	0x3d25bdd8, 0xe2e1c3c9, 0x44421659, 0x0a121386, 0xd90cec6e, 0xd5abea2a,
	0x64af674e, 0xda86a85f, 0xbebfe988, 0x64e4c3fe, 0x9dbc8057, 0xf0f7c086,
	0x60787bf8, 0x6003604d, 0xd1fd8346, 0xf6381fb0, 0x7745ae04, 0xd736fccc,
	0x83426b33, 0xf01eab71, 0xb0804187, 0x3c005e5f, 0x77a057be, 0xbde8ae24,
	0x55464299, 0xbf582e61, 0x4e58f48f, 0xf2ddfda2, 0xf474ef38, 0x8789bdc2,
	0x5366f9c3, 0xc8b38e74, 0xb475f255, 0x46fcd9b9, 0x7aeb2661, 0x8b1ddf84,
	0x846a0e79, 0x915f95e2, 0x466e598e, 0x20b45770, 0x8cd55591, 0xc902de4c,
	0xb90bace1, 0xbb8205d0, 0x11a86248, 0x7574a99e, 0xb77f19b6, 0xe0a9dc09,
	0x662d09a1, 0xc4324633, 0xe85a1f02, 0x09f0be8c, 0x4a99a025, 0x1d6efe10,
	0x1ab93d1d, 0x0ba5a4df, 0xa186f20f, 0x2868f169, 0xdcb7da83, 0x573906fe,
	0xa1e2ce9b, 0x4fcd7f52, 0x50115e01, 0xa70683fa, 0xa002b5c4, 0x0de6d027,
	0x9af88c27, 0x773f8641, 0xc3604c06, 0x61a806b5, 0xf0177a28, 0xc0f586e0,
	0x006058aa, 0x30dc7d62, 0x11e69ed7, 0x2338ea63, 0x53c2dd94, 0xc2c21634,
	0xbbcbee56, 0x90bcb6de, 0xebfc7da1, 0xce591d76, 0x6f05e409, 0x4b7c0188,
	0x39720a3d, 0x7c927c24, 0x86e3725f, 0x724d9db9, 0x1ac15bb4, 0xd39eb8fc,
	0xed545578, 0x08fca5b5, 0xd83d7cd3, 0x4dad0fc4, 0x1e50ef5e, 0xb161e6f8,
	0xa28514d9, 0x6c51133c, 0x6fd5c7e7, 0x56e14ec4, 0x362abfce, 0xddc6c837,
	0xd79a3234, 0x92638212, 0x670efa8e, 0x406000e0
    ], [
	0x3a39ce37, 0xd3faf5cf, 0xabc27737, 0x5ac52d1b, 0x5cb0679e, 0x4fa33742,
	0xd3822740, 0x99bc9bbe, 0xd5118e9d, 0xbf0f7315, 0xd62d1c7e, 0xc700c47b,
	0xb78c1b6b, 0x21a19045, 0xb26eb1be, 0x6a366eb4, 0x5748ab2f, 0xbc946e79,
	0xc6a376d2, 0x6549c2c8, 0x530ff8ee, 0x468dde7d, 0xd5730a1d, 0x4cd04dc6,
	0x2939bbdb, 0xa9ba4650, 0xac9526e8, 0xbe5ee304, 0xa1fad5f0, 0x6a2d519a,
	0x63ef8ce2, 0x9a86ee22, 0xc089c2b8, 0x43242ef6, 0xa51e03aa, 0x9cf2d0a4,
	0x83c061ba, 0x9be96a4d, 0x8fe51550, 0xba645bd6, 0x2826a2f9, 0xa73a3ae1,
	0x4ba99586, 0xef5562e9, 0xc72fefd3, 0xf752f7da, 0x3f046f69, 0x77fa0a59,
	0x80e4a915, 0x87b08601, 0x9b09e6ad, 0x3b3ee593, 0xe990fd5a, 0x9e34d797,
	0x2cf0b7d9, 0x022b8b51, 0x96d5ac3a, 0x017da67d, 0xd1cf3ed6, 0x7c7d2d28,
	0x1f9f25cf, 0xadf2b89b, 0x5ad6b472, 0x5a88f54c, 0xe029ac71, 0xe019a5e6,
	0x47b0acfd, 0xed93fa9b, 0xe8d3c48d, 0x283b57cc, 0xf8d56629, 0x79132e28,
	0x785f0191, 0xed756055, 0xf7960e44, 0xe3d35e8c, 0x15056dd4, 0x88f46dba,
	0x03a16125, 0x0564f0bd, 0xc3eb9e15, 0x3c9057a2, 0x97271aec, 0xa93a072a,
	0x1b3f6d9b, 0x1e6321f5, 0xf59c66fb, 0x26dcf319, 0x7533d928, 0xb155fdf5,
	0x03563482, 0x8aba3cbb, 0x28517711, 0xc20ad9f8, 0xabcc5167, 0xccad925f,
	0x4de81751, 0x3830dc8e, 0x379d5862, 0x9320f991, 0xea7a90c2, 0xfb3e7bce,
	0x5121ce64, 0x774fbe32, 0xa8b6e37e, 0xc3293d46, 0x48de5369, 0x6413e680,
	0xa2ae0810, 0xdd6db224, 0x69852dfd, 0x09072166, 0xb39a460a, 0x6445c0dd,
	0x586cdecf, 0x1c20c8ae, 0x5bbef7dd, 0x1b588d40, 0xccd2017f, 0x6bb4e3bb,
	0xdda26a7e, 0x3a59ff45, 0x3e350a44, 0xbcb4cdd5, 0x72eacea8, 0xfa6484bb,
	0x8d6612ae, 0xbf3c6f47, 0xd29be463, 0x542f5d9e, 0xaec2771b, 0xf64e6370,
	0x740e0d8d, 0xe75b1357, 0xf8721671, 0xaf537d5d, 0x4040cb08, 0x4eb4e2cc,
	0x34d2466a, 0x0115af84, 0xe1b00428, 0x95983a1d, 0x06b89fb4, 0xce6ea048,
	0x6f3f3b82, 0x3520ab82, 0x011a1d4b, 0x277227f8, 0x611560b1, 0xe7933fdc,
	0xbb3a792b, 0x344525bd, 0xa08839e1, 0x51ce794b, 0x2f32c9b7, 0xa01fbac9,
	0xe01cc87e, 0xbcc7d1f6, 0xcf0111c3, 0xa1e8aac7, 0x1a908749, 0xd44fbd9a,
	0xd0dadecb, 0xd50ada38, 0x0339c32a, 0xc6913667, 0x8df9317c, 0xe0b12b4f,
	0xf79e59b7, 0x43f5bb3a, 0xf2d519ff, 0x27d9459c, 0xbf97222c, 0x15e6fc2a,
	0x0f91fc71, 0x9b941525, 0xfae59361, 0xceb69ceb, 0xc2a86459, 0x12baa8d1,
	0xb6c1075e, 0xe3056a0c, 0x10d25065, 0xcb03a442, 0xe0ec6e0e, 0x1698db3b,
	0x4c98a0be, 0x3278e964, 0x9f1f9532, 0xe0d392df, 0xd3a0342b, 0x8971f21e,
	0x1b0a7441, 0x4ba3348c, 0xc5be7120, 0xc37632d8, 0xdf359f8d, 0x9b992f2e,
	0xe60b6f47, 0x0fe3f11d, 0xe54cda54, 0x1edad891, 0xce6279cf, 0xcd3e7e6f,
	0x1618b166, 0xfd2c1d05, 0x848fd2c5, 0xf6fb2299, 0xf523f357, 0xa6327623,
	0x93a83531, 0x56cccd02, 0xacf08162, 0x5a75ebb5, 0x6e163697, 0x88d273cc,
	0xde966292, 0x81b949d0, 0x4c50901b, 0x71c65614, 0xe6c6c7bd, 0x327a140a,
	0x45e1d006, 0xc3f27b9a, 0xc9aa53fd, 0x62a80f00, 0xbb25bfe2, 0x35bdd2f6,
	0x71126905, 0xb2040222, 0xb6cbcf7c, 0xcd769c2b, 0x53113ec0, 0x1640e3d3,
	0x38abbd60, 0x2547adf0, 0xba38209c, 0xf746ce76, 0x77afa1c5, 0x20756060,
	0x85cbfe4e, 0x8ae88dd8, 0x7aaaf9b0, 0x4cf9aa7e, 0x1948c25c, 0x02fb8a8c,
	0x01c36ae4, 0xd6ebe1f9, 0x90d4f869, 0xa65cdea0, 0x3f09252d, 0xc208e69f,
	0xb74e6132, 0xce77e25b, 0x578fdfe3, 0x3ac372e6
    ]
];

//*
//* This is the default PARRAY
//*
Blowfish.prototype.PARRAY = [
    0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0,
    0x082efa98, 0xec4e6c89, 0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
    0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917, 0x9216d5d9, 0x8979fb1b
];

//*
//* This is the number of rounds the cipher will go
//*
Blowfish.prototype.NN = 16;

//*
//* This function is needed to get rid of problems
//* with the high-bit getting set.  If we don't do
//* this, then sometimes ( aa & 0x00FFFFFFFF ) is not
//* equal to ( bb & 0x00FFFFFFFF ) even when they
//* agree bit-for-bit for the first 32 bits.
//*
Blowfish.prototype._clean = function( xx ) {
    if ( xx < 0 ) {
	var yy = xx & 0x7FFFFFFF;
	xx = yy + 0x80000000;
    }
    return xx;
};

//*
//* This is the mixing function that uses the sboxes
//*
Blowfish.prototype._F = function ( xx ) {
    var aa;
    var bb;
    var cc;
    var dd;
    var yy;

    dd = xx & 0x00FF;
    xx >>>= 8;
    cc = xx & 0x00FF;
    xx >>>= 8;
    bb = xx & 0x00FF;
    xx >>>= 8;
    aa = xx & 0x00FF;

    yy = this.sboxes[ 0 ][ aa ] + this.sboxes[ 1 ][ bb ];
    yy = yy ^ this.sboxes[ 2 ][ cc ];
    yy = yy + this.sboxes[ 3 ][ dd ];

    return yy;
};

//*
//* This method takes an array with two values, left and right
//* and does NN rounds of Blowfish on them.
//*
Blowfish.prototype._encrypt_block = function ( vals ) {
    var dataL = vals[ 0 ];
    var dataR = vals[ 1 ];

    var ii;

    for ( ii=0; ii < this.NN; ++ii ) {
	dataL = dataL ^ this.parray[ ii ];
	dataR = this._F( dataL ) ^ dataR;

	var tmp = dataL;
	dataL = dataR;
	dataR = tmp;
    }

    dataL = dataL ^ this.parray[ this.NN + 0 ];
    dataR = dataR ^ this.parray[ this.NN + 1 ];

    vals[ 0 ] = this._clean( dataR );
    vals[ 1 ] = this._clean( dataL );
};

//*
//* This method takes a vector of numbers and turns them
//* into long words so that they can be processed by the
//* real algorithm.
//*
//* Maybe I should make the real algorithm above take a vector
//* instead.  That will involve more looping, but it won't require
//* the F() method to deconstruct the vector.
//*
Blowfish.prototype.encrypt_block = function ( vector ) {
    var ii;
    var vals = [ 0, 0 ];
    var off  = this.BLOCKSIZE/2;
    for ( ii = 0; ii < this.BLOCKSIZE/2; ++ii ) {
	vals[0] = ( vals[0] << 8 ) | ( vector[ ii + 0   ] & 0x00FF );
	vals[1] = ( vals[1] << 8 ) | ( vector[ ii + off ] & 0x00FF );
    }

    this._encrypt_block( vals );

    var ret = [ ];
    for ( ii = 0; ii < this.BLOCKSIZE/2; ++ii ) {
	ret[ ii + 0   ] = ( vals[ 0 ] >>> (24 - 8*(ii)) & 0x00FF );
	ret[ ii + off ] = ( vals[ 1 ] >>> (24 - 8*(ii)) & 0x00FF );
	// vals[ 0 ] = ( vals[ 0 ] >>> 8 );
	// vals[ 1 ] = ( vals[ 1 ] >>> 8 );
    }

    return ret;
};

//*
//* This method takes an array with two values, left and right
//* and undoes NN rounds of Blowfish on them.
//*
Blowfish.prototype._decrypt_block = function ( vals ) {
    var dataL = vals[ 0 ];
    var dataR = vals[ 1 ];

    var ii;

    for ( ii=this.NN+1; ii > 1; --ii ) {
	dataL = dataL ^ this.parray[ ii ];
	dataR = this._F( dataL ) ^ dataR;

	var tmp = dataL;
	dataL = dataR;
	dataR = tmp;
    }

    dataL = dataL ^ this.parray[ 1 ];
    dataR = dataR ^ this.parray[ 0 ];

    vals[ 0 ] = this._clean( dataR );
    vals[ 1 ] = this._clean( dataL );
};

//*
//* This method takes a key array and initializes the
//* sboxes and parray for this encryption.
//*
Blowfish.prototype.init = function ( key ) {
    var ii;
    var jj = 0;

    this.parray = [];
    for ( ii=0; ii < this.NN + 2; ++ii ) {
	var data = 0x00000000;
	var kk;
	for ( kk=0; kk < 4; ++kk ) {
	    data = ( data << 8 ) | ( key[ jj ] & 0x00FF );
	    if ( ++jj >= key.length ) {
		jj = 0;
	    }
	}
	this.parray[ ii ] = this.PARRAY[ ii ] ^ data;
    }

    this.sboxes = [];
    for ( ii=0; ii < 4; ++ii ) {
	this.sboxes[ ii ] = [];
	for ( jj=0; jj < 256; ++jj ) {
	    this.sboxes[ ii ][ jj ] = this.SBOXES[ ii ][ jj ];
	}
    }

    var vals = [ 0x00000000, 0x00000000 ];

    for ( ii=0; ii < this.NN+2; ii += 2 ) {
	this._encrypt_block( vals );
	this.parray[ ii + 0 ] = vals[ 0 ];
	this.parray[ ii + 1 ] = vals[ 1 ];
    }

    for ( ii=0; ii < 4; ++ii ) {
	for ( jj=0; jj < 256; jj += 2 ) {
	    this._encrypt_block( vals );
	    this.sboxes[ ii ][ jj + 0 ] = vals[ 0 ];
	    this.sboxes[ ii ][ jj + 1 ] = vals[ 1 ];
	}
    }
};

var util = require('../../util');

// added by Recurity Labs
function BFencrypt(block,key) {
	var bf = new Blowfish();
	bf.init(util.str2bin(key));
	return bf.encrypt_block(block);
}

module.exports = BFencrypt;

},{"../../util":7}],47:[function(require,module,exports){
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
//
// ElGamal implementation

var BigInteger = require('./jsbn.js'),
	util = require('../../util');

function Elgamal() {
	
	function encrypt(m,g,p,y) {
		//  choose k in {2,...,p-2}
		var two = BigInteger.ONE.add(BigInteger.ONE);
		var pMinus2 = p.subtract(two);
		var k = openpgp_crypto_getRandomBigIntegerInRange(two, pMinus2);
		var k = k.mod(pMinus2).add(BigInteger.ONE);
		var c = new Array();
		c[0] = g.modPow(k, p);
		c[1] = y.modPow(k, p).multiply(m).mod(p).toMPI();
		c[0] = c[0].toMPI();
		return c;
	}
	
	function decrypt(c1,c2,p,x) {
		util.print_debug("Elgamal Decrypt:\nc1:"+util.hexstrdump(c1.toMPI())+"\n"+
			  "c2:"+util.hexstrdump(c2.toMPI())+"\n"+
			  "p:"+util.hexstrdump(p.toMPI())+"\n"+
			  "x:"+util.hexstrdump(x.toMPI()));
		return (c1.modPow(x, p).modInverse(p)).multiply(c2).mod(p);
		//var c = c1.pow(x).modInverse(p); // c0^-a mod p
	    //return c.multiply(c2).mod(p);
	}
	
	// signing and signature verification using Elgamal is not required by OpenPGP.
	this.encrypt = encrypt;
	this.decrypt = decrypt;
}

module.exports = Elgamal;

},{"./jsbn.js":13,"../../util":7}]},{},[])
//@ sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZ2VuZXJhdGVkLmpzIiwic291cmNlcyI6WyIvaG9tZS9wYW5jYWtlL2NvZGUvb3BlbnBncGpzL3NyYy9vcGVucGdwLmpzIiwiL2hvbWUvcGFuY2FrZS9jb2RlL29wZW5wZ3Bqcy9zcmMvdHlwZS9zMmsuanMiLCIvaG9tZS9wYW5jYWtlL2NvZGUvb3BlbnBncGpzL3NyYy90eXBlL2tleWlkLmpzIiwiL2hvbWUvcGFuY2FrZS9jb2RlL29wZW5wZ3Bqcy9zcmMvaW5kZXguanMiLCIvaG9tZS9wYW5jYWtlL2NvZGUvb3BlbnBncGpzL3NyYy91dGlsL3V0aWwuanMiLCIvaG9tZS9wYW5jYWtlL2NvZGUvb3BlbnBncGpzL3NyYy9lbmNvZGluZy9hcm1vci5qcyIsIi9ob21lL3BhbmNha2UvY29kZS9vcGVucGdwanMvc3JjL2VuY29kaW5nL2Jhc2U2NC5qcyIsIi9ob21lL3BhbmNha2UvY29kZS9vcGVucGdwanMvc3JjL3BhY2tldC9pbmRleC5qcyIsIi9ob21lL3BhbmNha2UvY29kZS9vcGVucGdwanMvc3JjL3R5cGUvbXBpLmpzIiwiL2hvbWUvcGFuY2FrZS9jb2RlL29wZW5wZ3Bqcy9zcmMvZW51bXMuanMiLCIvaG9tZS9wYW5jYWtlL2NvZGUvb3BlbnBncGpzL3NyYy9jcnlwdG8vaW5kZXguanMiLCIvaG9tZS9wYW5jYWtlL2NvZGUvb3BlbnBncGpzL3NyYy9wYWNrZXQvcGFja2V0bGlzdC5qcyIsIi9ob21lL3BhbmNha2UvY29kZS9vcGVucGdwanMvc3JjL3BhY2tldC9hbGxfcGFja2V0cy5qcyIsIi9ob21lL3BhbmNha2UvY29kZS9vcGVucGdwanMvc3JjL2NyeXB0by9wdWJsaWNfa2V5L2pzYm4uanMiLCIvaG9tZS9wYW5jYWtlL2NvZGUvb3BlbnBncGpzL3NyYy9jcnlwdG8vcmFuZG9tLmpzIiwiL2hvbWUvcGFuY2FrZS9jb2RlL29wZW5wZ3Bqcy9zcmMvcGFja2V0L3N5bV9lbmNyeXB0ZWRfaW50ZWdyaXR5X3Byb3RlY3RlZC5qcyIsIi9ob21lL3BhbmNha2UvY29kZS9vcGVucGdwanMvc3JjL3BhY2tldC9wdWJsaWNfa2V5X2VuY3J5cHRlZF9zZXNzaW9uX2tleS5qcyIsIi9ob21lL3BhbmNha2UvY29kZS9vcGVucGdwanMvc3JjL3BhY2tldC9zeW1fZW5jcnlwdGVkX3Nlc3Npb25fa2V5LmpzIiwiL2hvbWUvcGFuY2FrZS9jb2RlL29wZW5wZ3Bqcy9zcmMvcGFja2V0L3N5bW1ldHJpY2FsbHlfZW5jcnlwdGVkLmpzIiwiL2hvbWUvcGFuY2FrZS9jb2RlL29wZW5wZ3Bqcy9zcmMvcGFja2V0L3B1YmxpY19rZXkuanMiLCIvaG9tZS9wYW5jYWtlL2NvZGUvb3BlbnBncGpzL3NyYy9wYWNrZXQvbWFya2VyLmpzIiwiL2hvbWUvcGFuY2FrZS9jb2RlL29wZW5wZ3Bqcy9zcmMvcGFja2V0L3VzZXJfYXR0cmlidXRlLmpzIiwiL2hvbWUvcGFuY2FrZS9jb2RlL29wZW5wZ3Bqcy9zcmMvcGFja2V0L3RydXN0LmpzIiwiL2hvbWUvcGFuY2FrZS9jb2RlL29wZW5wZ3Bqcy9zcmMvY3J5cHRvL2NpcGhlci9pbmRleC5qcyIsIi9ob21lL3BhbmNha2UvY29kZS9vcGVucGdwanMvc3JjL2NyeXB0by9oYXNoL2luZGV4LmpzIiwiL2hvbWUvcGFuY2FrZS9jb2RlL29wZW5wZ3Bqcy9zcmMvY3J5cHRvL2NmYi5qcyIsIi9ob21lL3BhbmNha2UvY29kZS9vcGVucGdwanMvc3JjL2NyeXB0by9wdWJsaWNfa2V5L2luZGV4LmpzIiwiL2hvbWUvcGFuY2FrZS9jb2RlL29wZW5wZ3Bqcy9zcmMvY3J5cHRvL3NpZ25hdHVyZS5qcyIsIi9ob21lL3BhbmNha2UvY29kZS9vcGVucGdwanMvc3JjL2NyeXB0by9jcnlwdG8uanMiLCIvaG9tZS9wYW5jYWtlL2NvZGUvb3BlbnBncGpzL3NyYy9wYWNrZXQvY29tcHJlc3NlZC5qcyIsIi9ob21lL3BhbmNha2UvY29kZS9vcGVucGdwanMvc3JjL3BhY2tldC9wdWJsaWNfc3Via2V5LmpzIiwiL2hvbWUvcGFuY2FrZS9jb2RlL29wZW5wZ3Bqcy9zcmMvcGFja2V0L29uZV9wYXNzX3NpZ25hdHVyZS5qcyIsIi9ob21lL3BhbmNha2UvY29kZS9vcGVucGdwanMvc3JjL3BhY2tldC9zZWNyZXRfc3Via2V5LmpzIiwiL2hvbWUvcGFuY2FrZS9jb2RlL29wZW5wZ3Bqcy9zcmMvY3J5cHRvL2hhc2gvc2hhLmpzIiwiL2hvbWUvcGFuY2FrZS9jb2RlL29wZW5wZ3Bqcy9zcmMvY3J5cHRvL2hhc2gvcmlwZS1tZC5qcyIsIi9ob21lL3BhbmNha2UvY29kZS9vcGVucGdwanMvc3JjL2NyeXB0by9wdWJsaWNfa2V5L2RzYS5qcyIsIi9ob21lL3BhbmNha2UvY29kZS9vcGVucGdwanMvc3JjL2NyeXB0by9oYXNoL21kNS5qcyIsIi9ob21lL3BhbmNha2UvY29kZS9vcGVucGdwanMvc3JjL2NyeXB0by9wdWJsaWNfa2V5L3JzYS5qcyIsIi9ob21lL3BhbmNha2UvY29kZS9vcGVucGdwanMvc3JjL2NyeXB0by9wa2NzMS5qcyIsIi9ob21lL3BhbmNha2UvY29kZS9vcGVucGdwanMvc3JjL3BhY2tldC9wYWNrZXQuanMiLCIvaG9tZS9wYW5jYWtlL2NvZGUvb3BlbnBncGpzL3NyYy9wYWNrZXQvbGl0ZXJhbC5qcyIsIi9ob21lL3BhbmNha2UvY29kZS9vcGVucGdwanMvc3JjL3BhY2tldC9zZWNyZXRfa2V5LmpzIiwiL2hvbWUvcGFuY2FrZS9jb2RlL29wZW5wZ3Bqcy9zcmMvcGFja2V0L3VzZXJpZC5qcyIsIi9ob21lL3BhbmNha2UvY29kZS9vcGVucGdwanMvc3JjL3BhY2tldC9zaWduYXR1cmUuanMiLCIvaG9tZS9wYW5jYWtlL2NvZGUvb3BlbnBncGpzL3NyYy9jcnlwdG8vY2lwaGVyL2Flcy5qcyIsIi9ob21lL3BhbmNha2UvY29kZS9vcGVucGdwanMvc3JjL2NyeXB0by9jaXBoZXIvZGVzLmpzIiwiL2hvbWUvcGFuY2FrZS9jb2RlL29wZW5wZ3Bqcy9zcmMvY3J5cHRvL2NpcGhlci9jYXN0NS5qcyIsIi9ob21lL3BhbmNha2UvY29kZS9vcGVucGdwanMvc3JjL2NyeXB0by9jaXBoZXIvdHdvZmlzaC5qcyIsIi9ob21lL3BhbmNha2UvY29kZS9vcGVucGdwanMvc3JjL2NyeXB0by9jaXBoZXIvYmxvd2Zpc2guanMiLCIvaG9tZS9wYW5jYWtlL2NvZGUvb3BlbnBncGpzL3NyYy9jcnlwdG8vcHVibGljX2tleS9lbGdhbWFsLmpzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFBQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQzVjQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDdExBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7OztBQ3JEQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ2hCQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDclZBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ3RTQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNqRkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ1hBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNsR0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDOU5BO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDaEJBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ3JFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDN0JBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ3B6Q0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNoRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDM0hBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ2pMQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDbklBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNwRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDdklBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ25EQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDeERBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDSkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDVEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDbEVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDdlNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDUEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDaEdBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDalZBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUM5SkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUN0QkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ3JHQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ3RCQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNsc0NBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDdlNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ3pKQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDak5BO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUM1SUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQzdIQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQzVRQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUN4SEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUN6VEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ3hEQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDM2VBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUMzZUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNuTkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ3ZpQkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ2pUQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQzdZQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EiLCJzb3VyY2VzQ29udGVudCI6WyIvLyBHUEc0QnJvd3NlcnMgLSBBbiBPcGVuUEdQIGltcGxlbWVudGF0aW9uIGluIGphdmFzY3JpcHRcbi8vIENvcHlyaWdodCAoQykgMjAxMSBSZWN1cml0eSBMYWJzIEdtYkhcbi8vIFxuLy8gVGhpcyBsaWJyYXJ5IGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vclxuLy8gbW9kaWZ5IGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIExlc3NlciBHZW5lcmFsIFB1YmxpY1xuLy8gTGljZW5zZSBhcyBwdWJsaXNoZWQgYnkgdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyXG4vLyB2ZXJzaW9uIDIuMSBvZiB0aGUgTGljZW5zZSwgb3IgKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbi8vIFxuLy8gVGhpcyBsaWJyYXJ5IGlzIGRpc3RyaWJ1dGVkIGluIHRoZSBob3BlIHRoYXQgaXQgd2lsbCBiZSB1c2VmdWwsXG4vLyBidXQgV0lUSE9VVCBBTlkgV0FSUkFOVFk7IHdpdGhvdXQgZXZlbiB0aGUgaW1wbGllZCB3YXJyYW50eSBvZlxuLy8gTUVSQ0hBTlRBQklMSVRZIG9yIEZJVE5FU1MgRk9SIEEgUEFSVElDVUxBUiBQVVJQT1NFLiAgU2VlIHRoZSBHTlVcbi8vIExlc3NlciBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGZvciBtb3JlIGRldGFpbHMuXG4vLyBcbi8vIFlvdSBzaG91bGQgaGF2ZSByZWNlaXZlZCBhIGNvcHkgb2YgdGhlIEdOVSBMZXNzZXIgR2VuZXJhbCBQdWJsaWNcbi8vIExpY2Vuc2UgYWxvbmcgd2l0aCB0aGlzIGxpYnJhcnk7IGlmIG5vdCwgd3JpdGUgdG8gdGhlIEZyZWUgU29mdHdhcmVcbi8vIEZvdW5kYXRpb24sIEluYy4sIDUxIEZyYW5rbGluIFN0cmVldCwgRmlmdGggRmxvb3IsIEJvc3RvbiwgTUEgIDAyMTEwLTEzMDEgIFVTQVxuXG4vKipcbiAqIEBmaWxlb3ZlcnZpZXcgVGhlIG9wZW5wZ3AgYmFzZSBjbGFzcyBzaG91bGQgcHJvdmlkZSBhbGwgb2YgdGhlIGZ1bmN0aW9uYWxpdHkgXG4gKiB0byBjb25zdW1lIHRoZSBvcGVucGdwLmpzIGxpYnJhcnkuIEFsbCBhZGRpdGlvbmFsIGNsYXNzZXMgYXJlIGRvY3VtZW50ZWQgXG4gKiBmb3IgZXh0ZW5kaW5nIGFuZCBkZXZlbG9waW5nIG9uIHRvcCBvZiB0aGUgYmFzZSBsaWJyYXJ5LlxuICovXG5cbi8qKlxuICogR1BHNEJyb3dzZXJzIENvcmUgaW50ZXJmYWNlLiBBIHNpbmdsZSBpbnN0YW5jZSBpcyBob2xkXG4gKiBmcm9tIHRoZSBiZWdpbm5pbmcuIFRvIHVzZSB0aGlzIGxpYnJhcnkgY2FsbCBcIm9wZW5wZ3AuaW5pdCgpXCJcbiAqIEBhbGlhcyBvcGVucGdwXG4gKiBAY2xhc3NcbiAqIEBjbGFzc2Rlc2MgTWFpbiBPcGVucGdwLmpzIGNsYXNzLiBVc2UgdGhpcyB0byBpbml0aWF0ZSBhbmQgbWFrZSBhbGwgY2FsbHMgdG8gdGhpcyBsaWJyYXJ5LlxuICovXG5mdW5jdGlvbiBfb3BlbnBncCAoKSB7XG5cdHRoaXMudG9zdHJpbmcgPSBcIlwiO1xuXHRcblx0LyoqXG5cdCAqIGluaXRpYWxpemVzIHRoZSBsaWJyYXJ5OlxuXHQgKiAtIHJlYWRpbmcgdGhlIGtleXJpbmcgZnJvbSBsb2NhbCBzdG9yYWdlXG5cdCAqIC0gcmVhZGluZyB0aGUgY29uZmlnIGZyb20gbG9jYWwgc3RvcmFnZVxuXHQgKi9cblx0ZnVuY3Rpb24gaW5pdCgpIHtcblx0XHR0aGlzLmNvbmZpZyA9IG5ldyBvcGVucGdwX2NvbmZpZygpO1xuXHRcdHRoaXMuY29uZmlnLnJlYWQoKTtcblx0XHR0aGlzLmtleXJpbmcgPSBuZXcgb3BlbnBncF9rZXlyaW5nKCk7XG5cdFx0dGhpcy5rZXlyaW5nLmluaXQoKTtcblx0fVxuXHRcblx0LyoqXG5cdCAqIHJlYWRzIHNldmVyYWwgcHVibGljS2V5IG9iamVjdHMgZnJvbSBhIGFzY2lpIGFybW9yZWRcblx0ICogcmVwcmVzZW50YXRpb24gYW4gcmV0dXJucyBvcGVucGdwX21zZ19wdWJsaWNrZXkgcGFja2V0c1xuXHQgKiBAcGFyYW0ge1N0cmluZ30gYXJtb3JlZFRleHQgT3BlblBHUCBhcm1vcmVkIHRleHQgY29udGFpbmluZ1xuXHQgKiB0aGUgcHVibGljIGtleShzKVxuXHQgKiBAcmV0dXJuIHtvcGVucGdwX21zZ19wdWJsaWNrZXlbXX0gb24gZXJyb3IgdGhlIGZ1bmN0aW9uXG5cdCAqIHJldHVybnMgbnVsbFxuXHQgKi9cblx0ZnVuY3Rpb24gcmVhZF9wdWJsaWNLZXkoYXJtb3JlZFRleHQpIHtcblx0XHR2YXIgbXlwb3MgPSAwO1xuXHRcdHZhciBwdWJsaWNLZXlzID0gbmV3IEFycmF5KCk7XG5cdFx0dmFyIHB1YmxpY0tleUNvdW50ID0gMDtcblx0XHR2YXIgaW5wdXQgPSBvcGVucGdwX2VuY29kaW5nX2RlQXJtb3IoYXJtb3JlZFRleHQucmVwbGFjZSgvXFxyL2csJycpKS5vcGVucGdwO1xuXHRcdHZhciBsID0gaW5wdXQubGVuZ3RoO1xuXHRcdHdoaWxlIChteXBvcyAhPSBpbnB1dC5sZW5ndGgpIHtcblx0XHRcdHZhciBmaXJzdF9wYWNrZXQgPSBvcGVucGdwX3BhY2tldC5yZWFkX3BhY2tldChpbnB1dCwgbXlwb3MsIGwpO1xuXHRcdFx0Ly8gcHVibGljIGtleSBwYXJzZXJcblx0XHRcdGlmIChpbnB1dFtteXBvc10uY2hhckNvZGVBdCgpID09IDB4OTkgfHwgZmlyc3RfcGFja2V0LnRhZ1R5cGUgPT0gNikge1xuXHRcdFx0XHRwdWJsaWNLZXlzW3B1YmxpY0tleUNvdW50XSA9IG5ldyBvcGVucGdwX21zZ19wdWJsaWNrZXkoKTtcdFx0XHRcdFxuXHRcdFx0XHRwdWJsaWNLZXlzW3B1YmxpY0tleUNvdW50XS5oZWFkZXIgPSBpbnB1dC5zdWJzdHJpbmcobXlwb3MsbXlwb3MrMyk7XG5cdFx0XHRcdGlmIChpbnB1dFtteXBvc10uY2hhckNvZGVBdCgpID09IDB4OTkpIHtcblx0XHRcdFx0XHQvLyBwYXJzZSB0aGUgbGVuZ3RoIGFuZCByZWFkIGEgdGFnNiBwYWNrZXRcblx0XHRcdFx0XHRteXBvcysrO1xuXHRcdFx0XHRcdHZhciBsID0gKGlucHV0W215cG9zKytdLmNoYXJDb2RlQXQoKSA8PCA4KVxuXHRcdFx0XHRcdFx0XHR8IGlucHV0W215cG9zKytdLmNoYXJDb2RlQXQoKTtcblx0XHRcdFx0XHRwdWJsaWNLZXlzW3B1YmxpY0tleUNvdW50XS5wdWJsaWNLZXlQYWNrZXQgPSBuZXcgb3BlbnBncF9wYWNrZXRfa2V5bWF0ZXJpYWwoKTtcblx0XHRcdFx0XHRwdWJsaWNLZXlzW3B1YmxpY0tleUNvdW50XS5wdWJsaWNLZXlQYWNrZXQuaGVhZGVyID0gcHVibGljS2V5c1twdWJsaWNLZXlDb3VudF0uaGVhZGVyO1xuXHRcdFx0XHRcdHB1YmxpY0tleXNbcHVibGljS2V5Q291bnRdLnB1YmxpY0tleVBhY2tldC5yZWFkX3RhZzYoaW5wdXQsIG15cG9zLCBsKTtcblx0XHRcdFx0XHRteXBvcyArPSBwdWJsaWNLZXlzW3B1YmxpY0tleUNvdW50XS5wdWJsaWNLZXlQYWNrZXQucGFja2V0TGVuZ3RoO1xuXHRcdFx0XHRcdG15cG9zICs9IHB1YmxpY0tleXNbcHVibGljS2V5Q291bnRdLnJlYWRfbm9kZXMocHVibGljS2V5c1twdWJsaWNLZXlDb3VudF0ucHVibGljS2V5UGFja2V0LCBpbnB1dCwgbXlwb3MsIChpbnB1dC5sZW5ndGggLSBteXBvcykpO1xuXHRcdFx0XHR9IGVsc2Uge1xuXHRcdFx0XHRcdHB1YmxpY0tleXNbcHVibGljS2V5Q291bnRdID0gbmV3IG9wZW5wZ3BfbXNnX3B1YmxpY2tleSgpO1xuXHRcdFx0XHRcdHB1YmxpY0tleXNbcHVibGljS2V5Q291bnRdLnB1YmxpY0tleVBhY2tldCA9IGZpcnN0X3BhY2tldDtcblx0XHRcdFx0XHRteXBvcyArPSBmaXJzdF9wYWNrZXQuaGVhZGVyTGVuZ3RoK2ZpcnN0X3BhY2tldC5wYWNrZXRMZW5ndGg7XG5cdFx0XHRcdFx0bXlwb3MgKz0gcHVibGljS2V5c1twdWJsaWNLZXlDb3VudF0ucmVhZF9ub2RlcyhmaXJzdF9wYWNrZXQsIGlucHV0LCBteXBvcywgaW5wdXQubGVuZ3RoIC1teXBvcyk7XG5cdFx0XHRcdH1cblx0XHRcdH0gZWxzZSB7XG5cdFx0XHRcdHV0aWwucHJpbnRfZXJyb3IoXCJubyBwdWJsaWMga2V5IGZvdW5kIVwiKTtcblx0XHRcdFx0cmV0dXJuIG51bGw7XG5cdFx0XHR9XG5cdFx0XHRwdWJsaWNLZXlzW3B1YmxpY0tleUNvdW50XS5kYXRhID0gaW5wdXQuc3Vic3RyaW5nKDAsbXlwb3MpO1xuXHRcdFx0cHVibGljS2V5Q291bnQrKztcblx0XHR9XG5cdFx0cmV0dXJuIHB1YmxpY0tleXM7XG5cdH1cblx0XG5cdC8qKlxuXHQgKiByZWFkcyBzZXZlcmFsIHByaXZhdGVLZXkgb2JqZWN0cyBmcm9tIGEgYXNjaWkgYXJtb3JlZFxuXHQgKiByZXByZXNlbnRhdGlvbiBhbiByZXR1cm5zIG9wZW5wZ3BfbXNnX3ByaXZhdGVrZXkgb2JqZWN0c1xuXHQgKiBAcGFyYW0ge1N0cmluZ30gYXJtb3JlZFRleHQgT3BlblBHUCBhcm1vcmVkIHRleHQgY29udGFpbmluZ1xuXHQgKiB0aGUgcHJpdmF0ZSBrZXkocylcblx0ICogQHJldHVybiB7b3BlbnBncF9tc2dfcHJpdmF0ZWtleVtdfSBvbiBlcnJvciB0aGUgZnVuY3Rpb25cblx0ICogcmV0dXJucyBudWxsXG5cdCAqL1xuXHRmdW5jdGlvbiByZWFkX3ByaXZhdGVLZXkoYXJtb3JlZFRleHQpIHtcblx0XHR2YXIgcHJpdmF0ZUtleXMgPSBuZXcgQXJyYXkoKTtcblx0XHR2YXIgcHJpdmF0ZUtleUNvdW50ID0gMDtcblx0XHR2YXIgbXlwb3MgPSAwO1xuXHRcdHZhciBpbnB1dCA9IG9wZW5wZ3BfZW5jb2RpbmdfZGVBcm1vcihhcm1vcmVkVGV4dC5yZXBsYWNlKC9cXHIvZywnJykpLm9wZW5wZ3A7XG5cdFx0dmFyIGwgPSBpbnB1dC5sZW5ndGg7XG5cdFx0d2hpbGUgKG15cG9zICE9IGlucHV0Lmxlbmd0aCkge1xuXHRcdFx0dmFyIGZpcnN0X3BhY2tldCA9IG9wZW5wZ3BfcGFja2V0LnJlYWRfcGFja2V0KGlucHV0LCBteXBvcywgbCk7XG5cdFx0XHRpZiAoZmlyc3RfcGFja2V0LnRhZ1R5cGUgPT0gNSkge1xuXHRcdFx0XHRwcml2YXRlS2V5c1twcml2YXRlS2V5cy5sZW5ndGhdID0gbmV3IG9wZW5wZ3BfbXNnX3ByaXZhdGVrZXkoKTtcblx0XHRcdFx0bXlwb3MgKz0gZmlyc3RfcGFja2V0LmhlYWRlckxlbmd0aCtmaXJzdF9wYWNrZXQucGFja2V0TGVuZ3RoO1xuXHRcdFx0XHRteXBvcyArPSBwcml2YXRlS2V5c1twcml2YXRlS2V5Q291bnRdLnJlYWRfbm9kZXMoZmlyc3RfcGFja2V0LCBpbnB1dCwgbXlwb3MsIGwpO1xuXHRcdFx0Ly8gb3RoZXIgYmxvY2tzXHQgICAgICAgICAgICBcblx0XHRcdH0gZWxzZSB7XG5cdFx0XHRcdHV0aWwucHJpbnRfZXJyb3IoJ25vIGJsb2NrIHBhY2tldCBmb3VuZCEnKTtcblx0XHRcdFx0cmV0dXJuIG51bGw7XG5cdFx0XHR9XG5cdFx0XHRwcml2YXRlS2V5c1twcml2YXRlS2V5Q291bnRdLmRhdGEgPSBpbnB1dC5zdWJzdHJpbmcoMCxteXBvcyk7XG5cdFx0XHRwcml2YXRlS2V5Q291bnQrKztcblx0XHR9XG5cdFx0cmV0dXJuIHByaXZhdGVLZXlzO1x0XHRcblx0fVxuXG5cdC8qKlxuXHQgKiByZWFkcyBtZXNzYWdlIHBhY2tldHMgb3V0IG9mIGFuIE9wZW5QR1AgYXJtb3JlZCB0ZXh0IGFuZFxuXHQgKiByZXR1cm5zIGFuIGFycmF5IG9mIG1lc3NhZ2Ugb2JqZWN0c1xuXHQgKiBAcGFyYW0ge1N0cmluZ30gYXJtb3JlZFRleHQgdGV4dCB0byBiZSBwYXJzZWRcblx0ICogQHJldHVybiB7b3BlbnBncF9tc2dfbWVzc2FnZVtdfSBvbiBlcnJvciB0aGUgZnVuY3Rpb25cblx0ICogcmV0dXJucyBudWxsXG5cdCAqL1xuXHRmdW5jdGlvbiByZWFkX21lc3NhZ2UoYXJtb3JlZFRleHQpIHtcblx0XHR2YXIgZGVhcm1vcmVkO1xuXHRcdHRyeXtcbiAgICBcdFx0ZGVhcm1vcmVkID0gb3BlbnBncF9lbmNvZGluZ19kZUFybW9yKGFybW9yZWRUZXh0LnJlcGxhY2UoL1xcci9nLCcnKSk7XG5cdFx0fVxuXHRcdGNhdGNoKGUpe1xuICAgIFx0XHR1dGlsLnByaW50X2Vycm9yKCdubyBtZXNzYWdlIGZvdW5kIScpO1xuICAgIFx0XHRyZXR1cm4gbnVsbDtcblx0XHR9XG5cdFx0cmV0dXJuIHJlYWRfbWVzc2FnZXNfZGVhcm1vcmVkKGRlYXJtb3JlZCk7XG5cdFx0fVxuXHRcdFxuXHQvKipcblx0ICogcmVhZHMgbWVzc2FnZSBwYWNrZXRzIG91dCBvZiBhbiBPcGVuUEdQIGFybW9yZWQgdGV4dCBhbmRcblx0ICogcmV0dXJucyBhbiBhcnJheSBvZiBtZXNzYWdlIG9iamVjdHMuIENhbiBiZSBjYWxsZWQgZXh0ZXJuYWxseSBvciBpbnRlcm5hbGx5LlxuXHQgKiBFeHRlcm5hbCBjYWxsIHdpbGwgcGFyc2UgYSBkZS1hcm1vcmVkIG1lc3NhZ2VkIGFuZCByZXR1cm4gbWVzc2FnZXMgZm91bmQuXG5cdCAqIEludGVybmFsIHdpbGwgYmUgY2FsbGVkIHRvIHJlYWQgcGFja2V0cyB3cmFwcGVkIGluIG90aGVyIHBhY2tldHMgKGkuZS4gY29tcHJlc3NlZClcblx0ICogQHBhcmFtIHtTdHJpbmd9IGlucHV0IGRlYXJtb3JlZCB0ZXh0IG9mIE9wZW5QR1AgcGFja2V0cywgdG8gYmUgcGFyc2VkXG5cdCAqIEByZXR1cm4ge29wZW5wZ3BfbXNnX21lc3NhZ2VbXX0gb24gZXJyb3IgdGhlIGZ1bmN0aW9uXG5cdCAqIHJldHVybnMgbnVsbFxuXHQgKi9cblx0ZnVuY3Rpb24gcmVhZF9tZXNzYWdlc19kZWFybW9yZWQoaW5wdXQpe1xuXHRcdHZhciBtZXNzYWdlU3RyaW5nID0gaW5wdXQub3BlbnBncDtcblx0XHR2YXIgc2lnbmF0dXJlVGV4dCA9IGlucHV0LnRleHQ7IC8vdGV4dCB0byB2ZXJpZnkgc2lnbmF0dXJlcyBhZ2FpbnN0LiBNb2RpZmllZCBieSBUYWcxMS5cblx0XHR2YXIgbWVzc2FnZXMgPSBuZXcgQXJyYXkoKTtcblx0XHR2YXIgbWVzc2FnZUNvdW50ID0gMDtcblx0XHR2YXIgbXlwb3MgPSAwO1xuXHRcdHZhciBsID0gbWVzc2FnZVN0cmluZy5sZW5ndGg7XG5cdFx0d2hpbGUgKG15cG9zIDwgbWVzc2FnZVN0cmluZy5sZW5ndGgpIHtcblx0XHRcdHZhciBmaXJzdF9wYWNrZXQgPSBvcGVucGdwX3BhY2tldC5yZWFkX3BhY2tldChtZXNzYWdlU3RyaW5nLCBteXBvcywgbCk7XG5cdFx0XHRpZiAoIWZpcnN0X3BhY2tldCkge1xuXHRcdFx0XHRicmVhaztcblx0XHRcdH1cblx0XHRcdC8vIHB1YmxpYyBrZXkgcGFyc2VyIChkZWZpbml0aW9uIGZyb20gdGhlIHN0YW5kYXJkOilcblx0XHRcdC8vIE9wZW5QR1AgTWVzc2FnZSAgICAgIDotIEVuY3J5cHRlZCBNZXNzYWdlIHwgU2lnbmVkIE1lc3NhZ2UgfFxuXHRcdFx0Ly8gICAgICAgICAgICAgICAgICAgICAgICAgQ29tcHJlc3NlZCBNZXNzYWdlIHwgTGl0ZXJhbCBNZXNzYWdlLlxuXHRcdFx0Ly8gQ29tcHJlc3NlZCBNZXNzYWdlICAgOi0gQ29tcHJlc3NlZCBEYXRhIFBhY2tldC5cblx0XHRcdC8vIFxuXHRcdFx0Ly8gTGl0ZXJhbCBNZXNzYWdlICAgICAgOi0gTGl0ZXJhbCBEYXRhIFBhY2tldC5cblx0XHRcdC8vIFxuXHRcdFx0Ly8gRVNLICAgICAgICAgICAgICAgICAgOi0gUHVibGljLUtleSBFbmNyeXB0ZWQgU2Vzc2lvbiBLZXkgUGFja2V0IHxcblx0XHRcdC8vICAgICAgICAgICAgICAgICAgICAgICAgIFN5bW1ldHJpYy1LZXkgRW5jcnlwdGVkIFNlc3Npb24gS2V5IFBhY2tldC5cblx0XHRcdC8vIFxuXHRcdFx0Ly8gRVNLIFNlcXVlbmNlICAgICAgICAgOi0gRVNLIHwgRVNLIFNlcXVlbmNlLCBFU0suXG5cdFx0XHQvLyBcblx0XHRcdC8vIEVuY3J5cHRlZCBEYXRhICAgICAgIDotIFN5bW1ldHJpY2FsbHkgRW5jcnlwdGVkIERhdGEgUGFja2V0IHxcblx0XHRcdC8vICAgICAgICAgICAgICAgICAgICAgICAgIFN5bW1ldHJpY2FsbHkgRW5jcnlwdGVkIEludGVncml0eSBQcm90ZWN0ZWQgRGF0YSBQYWNrZXRcblx0XHRcdC8vIFxuXHRcdFx0Ly8gRW5jcnlwdGVkIE1lc3NhZ2UgICAgOi0gRW5jcnlwdGVkIERhdGEgfCBFU0sgU2VxdWVuY2UsIEVuY3J5cHRlZCBEYXRhLlxuXHRcdFx0Ly8gXG5cdFx0XHQvLyBPbmUtUGFzcyBTaWduZWQgTWVzc2FnZSA6LSBPbmUtUGFzcyBTaWduYXR1cmUgUGFja2V0LFxuXHRcdFx0Ly8gICAgICAgICAgICAgICAgICAgICAgICAgT3BlblBHUCBNZXNzYWdlLCBDb3JyZXNwb25kaW5nIFNpZ25hdHVyZSBQYWNrZXQuXG5cblx0XHRcdC8vIFNpZ25lZCBNZXNzYWdlICAgICAgIDotIFNpZ25hdHVyZSBQYWNrZXQsIE9wZW5QR1AgTWVzc2FnZSB8XG5cdFx0XHQvLyAgICAgICAgICAgICAgICAgICAgICAgICBPbmUtUGFzcyBTaWduZWQgTWVzc2FnZS5cblx0XHRcdGlmIChmaXJzdF9wYWNrZXQudGFnVHlwZSA9PSAgMSB8fFxuXHRcdFx0ICAgIChmaXJzdF9wYWNrZXQudGFnVHlwZSA9PSAyICYmIGZpcnN0X3BhY2tldC5zaWduYXR1cmVUeXBlIDwgMTYpIHx8XG5cdFx0XHQgICAgIGZpcnN0X3BhY2tldC50YWdUeXBlID09ICAzIHx8XG5cdFx0XHQgICAgIGZpcnN0X3BhY2tldC50YWdUeXBlID09ICA0IHx8XG5cdFx0XHRcdCBmaXJzdF9wYWNrZXQudGFnVHlwZSA9PSAgOCB8fFxuXHRcdFx0XHQgZmlyc3RfcGFja2V0LnRhZ1R5cGUgPT0gIDkgfHxcblx0XHRcdFx0IGZpcnN0X3BhY2tldC50YWdUeXBlID09IDEwIHx8XG5cdFx0XHRcdCBmaXJzdF9wYWNrZXQudGFnVHlwZSA9PSAxMSB8fFxuXHRcdFx0XHQgZmlyc3RfcGFja2V0LnRhZ1R5cGUgPT0gMTggfHxcblx0XHRcdFx0IGZpcnN0X3BhY2tldC50YWdUeXBlID09IDE5KSB7XG5cdFx0XHRcdG1lc3NhZ2VzW21lc3NhZ2VzLmxlbmd0aF0gPSBuZXcgb3BlbnBncF9tc2dfbWVzc2FnZSgpO1xuXHRcdFx0XHRtZXNzYWdlc1ttZXNzYWdlQ291bnRdLm1lc3NhZ2VQYWNrZXQgPSBmaXJzdF9wYWNrZXQ7XG5cdFx0XHRcdG1lc3NhZ2VzW21lc3NhZ2VDb3VudF0udHlwZSA9IGlucHV0LnR5cGU7XG5cdFx0XHRcdC8vIEVuY3J5cHRlZCBNZXNzYWdlXG5cdFx0XHRcdGlmIChmaXJzdF9wYWNrZXQudGFnVHlwZSA9PSA5IHx8XG5cdFx0XHRcdCAgICBmaXJzdF9wYWNrZXQudGFnVHlwZSA9PSAxIHx8XG5cdFx0XHRcdCAgICBmaXJzdF9wYWNrZXQudGFnVHlwZSA9PSAzIHx8XG5cdFx0XHRcdCAgICBmaXJzdF9wYWNrZXQudGFnVHlwZSA9PSAxOCkge1xuXHRcdFx0XHRcdGlmIChmaXJzdF9wYWNrZXQudGFnVHlwZSA9PSA5KSB7XG5cdFx0XHRcdFx0XHR1dGlsLnByaW50X2Vycm9yKFwidW5leHBlY3RlZCBvcGVucGdwIHBhY2tldFwiKTtcblx0XHRcdFx0XHRcdGJyZWFrO1xuXHRcdFx0XHRcdH0gZWxzZSBpZiAoZmlyc3RfcGFja2V0LnRhZ1R5cGUgPT0gMSkge1xuXHRcdFx0XHRcdFx0dXRpbC5wcmludF9kZWJ1ZyhcInNlc3Npb24ga2V5IGZvdW5kOlxcbiBcIitmaXJzdF9wYWNrZXQudG9TdHJpbmcoKSk7XG5cdFx0XHRcdFx0XHR2YXIgaXNzZXNzaW9ua2V5ID0gdHJ1ZTtcblx0XHRcdFx0XHRcdG1lc3NhZ2VzW21lc3NhZ2VDb3VudF0uc2Vzc2lvbktleXMgPSBuZXcgQXJyYXkoKTtcblx0XHRcdFx0XHRcdHZhciBzZXNzaW9uS2V5Q291bnQgPSAwO1xuXHRcdFx0XHRcdFx0d2hpbGUgKGlzc2Vzc2lvbmtleSkge1xuXHRcdFx0XHRcdFx0XHRtZXNzYWdlc1ttZXNzYWdlQ291bnRdLnNlc3Npb25LZXlzW3Nlc3Npb25LZXlDb3VudF0gPSBmaXJzdF9wYWNrZXQ7XG5cdFx0XHRcdFx0XHRcdG15cG9zICs9IGZpcnN0X3BhY2tldC5wYWNrZXRMZW5ndGggKyBmaXJzdF9wYWNrZXQuaGVhZGVyTGVuZ3RoO1xuXHRcdFx0XHRcdFx0XHRsIC09IChmaXJzdF9wYWNrZXQucGFja2V0TGVuZ3RoICsgZmlyc3RfcGFja2V0LmhlYWRlckxlbmd0aCk7XG5cdFx0XHRcdFx0XHRcdGZpcnN0X3BhY2tldCA9IG9wZW5wZ3BfcGFja2V0LnJlYWRfcGFja2V0KG1lc3NhZ2VTdHJpbmcsIG15cG9zLCBsKTtcblx0XHRcdFx0XHRcdFx0XG5cdFx0XHRcdFx0XHRcdGlmIChmaXJzdF9wYWNrZXQudGFnVHlwZSAhPSAxICYmIGZpcnN0X3BhY2tldC50YWdUeXBlICE9IDMpXG5cdFx0XHRcdFx0XHRcdFx0aXNzZXNzaW9ua2V5ID0gZmFsc2U7XG5cdFx0XHRcdFx0XHRcdHNlc3Npb25LZXlDb3VudCsrO1xuXHRcdFx0XHRcdFx0fVxuXHRcdFx0XHRcdFx0aWYgKGZpcnN0X3BhY2tldC50YWdUeXBlID09IDE4IHx8IGZpcnN0X3BhY2tldC50YWdUeXBlID09IDkpIHtcblx0XHRcdFx0XHRcdFx0dXRpbC5wcmludF9kZWJ1ZyhcImVuY3J5cHRlZCBkYXRhIGZvdW5kOlxcbiBcIitmaXJzdF9wYWNrZXQudG9TdHJpbmcoKSk7XG5cdFx0XHRcdFx0XHRcdG1lc3NhZ2VzW21lc3NhZ2VDb3VudF0uZW5jcnlwdGVkRGF0YSA9IGZpcnN0X3BhY2tldDtcblx0XHRcdFx0XHRcdFx0bXlwb3MgKz0gZmlyc3RfcGFja2V0LnBhY2tldExlbmd0aCtmaXJzdF9wYWNrZXQuaGVhZGVyTGVuZ3RoO1xuXHRcdFx0XHRcdFx0XHRsIC09IChmaXJzdF9wYWNrZXQucGFja2V0TGVuZ3RoK2ZpcnN0X3BhY2tldC5oZWFkZXJMZW5ndGgpO1xuXHRcdFx0XHRcdFx0XHRtZXNzYWdlQ291bnQrKztcblx0XHRcdFx0XHRcdFx0XG5cdFx0XHRcdFx0XHR9IGVsc2Uge1xuXHRcdFx0XHRcdFx0XHR1dGlsLnByaW50X2RlYnVnKFwic29tZXRoaW5nIGlzIHdyb25nOiBcIitmaXJzdF9wYWNrZXQudGFnVHlwZSk7XG5cdFx0XHRcdFx0XHR9XG5cdFx0XHRcdFx0XHRcblx0XHRcdFx0XHR9IGVsc2UgaWYgKGZpcnN0X3BhY2tldC50YWdUeXBlID09IDE4KSB7XG5cdFx0XHRcdFx0XHR1dGlsLnByaW50X2RlYnVnKFwic3ltbWV0cmljIGVuY3J5cHRlZCBkYXRhXCIpO1xuXHRcdFx0XHRcdFx0YnJlYWs7XG5cdFx0XHRcdFx0fVxuXHRcdFx0XHR9IGVsc2UgXG5cdFx0XHRcdFx0aWYgKGZpcnN0X3BhY2tldC50YWdUeXBlID09IDIgJiYgZmlyc3RfcGFja2V0LnNpZ25hdHVyZVR5cGUgPCAzKSB7XG5cdFx0XHRcdFx0Ly8gU2lnbmVkIE1lc3NhZ2Vcblx0XHRcdFx0XHRcdG15cG9zICs9IGZpcnN0X3BhY2tldC5wYWNrZXRMZW5ndGggKyBmaXJzdF9wYWNrZXQuaGVhZGVyTGVuZ3RoO1xuXHRcdFx0XHRcdFx0bCAtPSAoZmlyc3RfcGFja2V0LnBhY2tldExlbmd0aCArIGZpcnN0X3BhY2tldC5oZWFkZXJMZW5ndGgpO1xuXHRcdFx0XHRcdFx0bWVzc2FnZXNbbWVzc2FnZUNvdW50XS50ZXh0ID0gc2lnbmF0dXJlVGV4dDtcblx0XHRcdFx0XHRcdG1lc3NhZ2VzW21lc3NhZ2VDb3VudF0uc2lnbmF0dXJlID0gZmlyc3RfcGFja2V0O1xuXHRcdFx0XHQgICAgICAgIG1lc3NhZ2VDb3VudCsrO1xuXHRcdFx0XHR9IGVsc2UgXG5cdFx0XHRcdFx0Ly8gU2lnbmVkIE1lc3NhZ2Vcblx0XHRcdFx0XHRpZiAoZmlyc3RfcGFja2V0LnRhZ1R5cGUgPT0gNCkge1xuXHRcdFx0XHRcdFx0Ly9UT0RPOiBJbXBsZW1lbnQgY2hlY2tcblx0XHRcdFx0XHRcdG15cG9zICs9IGZpcnN0X3BhY2tldC5wYWNrZXRMZW5ndGggKyBmaXJzdF9wYWNrZXQuaGVhZGVyTGVuZ3RoO1xuXHRcdFx0XHRcdFx0bCAtPSAoZmlyc3RfcGFja2V0LnBhY2tldExlbmd0aCArIGZpcnN0X3BhY2tldC5oZWFkZXJMZW5ndGgpO1xuXHRcdFx0XHR9IGVsc2UgXG5cdFx0XHRcdFx0aWYgKGZpcnN0X3BhY2tldC50YWdUeXBlID09IDgpIHtcblx0XHRcdFx0XHQvLyBDb21wcmVzc2VkIE1lc3NhZ2Vcblx0XHRcdFx0XHRcdG15cG9zICs9IGZpcnN0X3BhY2tldC5wYWNrZXRMZW5ndGggKyBmaXJzdF9wYWNrZXQuaGVhZGVyTGVuZ3RoO1xuXHRcdFx0XHRcdFx0bCAtPSAoZmlyc3RfcGFja2V0LnBhY2tldExlbmd0aCArIGZpcnN0X3BhY2tldC5oZWFkZXJMZW5ndGgpO1xuXHRcdFx0XHQgICAgICAgIHZhciBkZWNvbXByZXNzZWRUZXh0ID0gZmlyc3RfcGFja2V0LmRlY29tcHJlc3MoKTtcblx0XHRcdFx0ICAgICAgICBtZXNzYWdlcyA9IG1lc3NhZ2VzLmNvbmNhdChvcGVucGdwLnJlYWRfbWVzc2FnZXNfZGVhcm1vcmVkKHt0ZXh0OiBkZWNvbXByZXNzZWRUZXh0LCBvcGVucGdwOiBkZWNvbXByZXNzZWRUZXh0fSkpO1xuXHRcdFx0XHR9IGVsc2Vcblx0XHRcdFx0XHQvLyBNYXJrZXIgUGFja2V0IChPYnNvbGV0ZSBMaXRlcmFsIFBhY2tldCkgKFRhZyAxMClcblx0XHRcdFx0XHQvLyBcIlN1Y2ggYSBwYWNrZXQgTVVTVCBiZSBpZ25vcmVkIHdoZW4gcmVjZWl2ZWQuXCIgc2VlIGh0dHA6Ly90b29scy5pZXRmLm9yZy9odG1sL3JmYzQ4ODAjc2VjdGlvbi01Ljhcblx0XHRcdFx0XHRpZiAoZmlyc3RfcGFja2V0LnRhZ1R5cGUgPT0gMTApIHtcblx0XHRcdFx0XHRcdC8vIHJlc2V0IG1lc3NhZ2VzXG5cdFx0XHRcdFx0XHRtZXNzYWdlcy5sZW5ndGggPSAwO1xuXHRcdFx0XHRcdFx0Ly8gY29udGludWUgd2l0aCBuZXh0IHBhY2tldFxuXHRcdFx0XHRcdFx0bXlwb3MgKz0gZmlyc3RfcGFja2V0LnBhY2tldExlbmd0aCArIGZpcnN0X3BhY2tldC5oZWFkZXJMZW5ndGg7XG5cdFx0XHRcdFx0XHRsIC09IChmaXJzdF9wYWNrZXQucGFja2V0TGVuZ3RoICsgZmlyc3RfcGFja2V0LmhlYWRlckxlbmd0aCk7XG5cdFx0XHRcdH0gZWxzZSBcblx0XHRcdFx0XHRpZiAoZmlyc3RfcGFja2V0LnRhZ1R5cGUgPT0gMTEpIHtcblx0XHRcdFx0XHQvLyBMaXRlcmFsIE1lc3NhZ2UgLS0gd29yayBpcyBhbHJlYWR5IGRvbmUgaW4gcmVhZF9wYWNrZXRcblx0XHRcdFx0XHRteXBvcyArPSBmaXJzdF9wYWNrZXQucGFja2V0TGVuZ3RoICsgZmlyc3RfcGFja2V0LmhlYWRlckxlbmd0aDtcblx0XHRcdFx0XHRsIC09IChmaXJzdF9wYWNrZXQucGFja2V0TGVuZ3RoICsgZmlyc3RfcGFja2V0LmhlYWRlckxlbmd0aCk7XG5cdFx0XHRcdFx0c2lnbmF0dXJlVGV4dCA9IGZpcnN0X3BhY2tldC5kYXRhO1xuXHRcdFx0XHRcdG1lc3NhZ2VzW21lc3NhZ2VDb3VudF0uZGF0YSA9IGZpcnN0X3BhY2tldC5kYXRhO1xuXHRcdFx0XHRcdG1lc3NhZ2VDb3VudCsrO1xuXHRcdFx0XHR9IGVsc2UgXG5cdFx0XHRcdFx0aWYgKGZpcnN0X3BhY2tldC50YWdUeXBlID09IDE5KSB7XG5cdFx0XHRcdFx0Ly8gTW9kaWZpY2F0aW9uIERldGVjdCBDb2RlXG5cdFx0XHRcdFx0XHRteXBvcyArPSBmaXJzdF9wYWNrZXQucGFja2V0TGVuZ3RoICsgZmlyc3RfcGFja2V0LmhlYWRlckxlbmd0aDtcblx0XHRcdFx0XHRcdGwgLT0gKGZpcnN0X3BhY2tldC5wYWNrZXRMZW5ndGggKyBmaXJzdF9wYWNrZXQuaGVhZGVyTGVuZ3RoKTtcblx0XHRcdFx0fVxuXHRcdFx0fSBlbHNlIHtcblx0XHRcdFx0dXRpbC5wcmludF9lcnJvcignbm8gbWVzc2FnZSBmb3VuZCEnKTtcblx0XHRcdFx0cmV0dXJuIG51bGw7XG5cdFx0XHR9XG5cdFx0fVxuXHRcdFxuXHRcdHJldHVybiBtZXNzYWdlcztcblx0fVxuXHRcblx0LyoqXG5cdCAqIGNyZWF0ZXMgYSBiaW5hcnkgc3RyaW5nIHJlcHJlc2VudGF0aW9uIG9mIGFuIGVuY3J5cHRlZCBhbmQgc2lnbmVkIG1lc3NhZ2UuXG5cdCAqIFRoZSBtZXNzYWdlIHdpbGwgYmUgZW5jcnlwdGVkIHdpdGggdGhlIHB1YmxpYyBrZXlzIHNwZWNpZmllZCBhbmQgc2lnbmVkXG5cdCAqIHdpdGggdGhlIHNwZWNpZmllZCBwcml2YXRlIGtleS5cblx0ICogQHBhcmFtIHtPYmplY3R9IHByaXZhdGVrZXkge29iajogW29wZW5wZ3BfbXNnX3ByaXZhdGVrZXldfSBQcml2YXRlIGtleSBcblx0ICogdG8gYmUgdXNlZCB0byBzaWduIHRoZSBtZXNzYWdlXG5cdCAqIEBwYXJhbSB7T2JqZWN0W119IHB1YmxpY2tleXMgQW4gYXJyYWYgb2Yge29iajogW29wZW5wZ3BfbXNnX3B1YmxpY2tleV19XG5cdCAqIC0gcHVibGljIGtleXMgdG8gYmUgdXNlZCB0byBlbmNyeXB0IHRoZSBtZXNzYWdlIFxuXHQgKiBAcGFyYW0ge1N0cmluZ30gbWVzc2FnZXRleHQgbWVzc2FnZSB0ZXh0IHRvIGVuY3J5cHQgYW5kIHNpZ25cblx0ICogQHJldHVybiB7U3RyaW5nfSBhIGJpbmFyeSBzdHJpbmcgcmVwcmVzZW50YXRpb24gb2YgdGhlIG1lc3NhZ2Ugd2hpY2ggXG5cdCAqIGNhbiBiZSBPcGVuUEdQIGFybW9yZWRcblx0ICovXG5cdGZ1bmN0aW9uIHdyaXRlX3NpZ25lZF9hbmRfZW5jcnlwdGVkX21lc3NhZ2UocHJpdmF0ZWtleSwgcHVibGlja2V5cywgbWVzc2FnZXRleHQpIHtcblx0XHR2YXIgcmVzdWx0ID0gXCJcIjtcblx0XHR2YXIgbGl0ZXJhbCA9IG5ldyBvcGVucGdwX3BhY2tldF9saXRlcmFsZGF0YSgpLndyaXRlX3BhY2tldChtZXNzYWdldGV4dC5yZXBsYWNlKC9cXHJcXG4vZyxcIlxcblwiKS5yZXBsYWNlKC9cXG4vZyxcIlxcclxcblwiKSk7XG5cdFx0dXRpbC5wcmludF9kZWJ1Z19oZXhzdHJfZHVtcChcImxpdGVyYWxfcGFja2V0OiB8XCIrbGl0ZXJhbCtcInxcXG5cIixsaXRlcmFsKTtcblx0XHRmb3IgKHZhciBpID0gMDsgaSA8IHB1YmxpY2tleXMubGVuZ3RoOyBpKyspIHtcblx0XHRcdHZhciBvbmVwYXNzc2lnbmF0dXJlID0gbmV3IG9wZW5wZ3BfcGFja2V0X29uZXBhc3NzaWduYXR1cmUoKTtcblx0XHRcdHZhciBvbmVwYXNzc2lnc3RyID0gXCJcIjtcblx0XHRcdGlmIChpID09IDApXG5cdFx0XHRcdG9uZXBhc3NzaWdzdHIgPSBvbmVwYXNzc2lnbmF0dXJlLndyaXRlX3BhY2tldCgxLCBvcGVucGdwLmNvbmZpZy5jb25maWcucHJlZmVyX2hhc2hfYWxnb3JpdGhtLCAgcHJpdmF0ZWtleSwgZmFsc2UpO1xuXHRcdFx0ZWxzZVxuXHRcdFx0XHRvbmVwYXNzc2lnc3RyID0gb25lcGFzc3NpZ25hdHVyZS53cml0ZV9wYWNrZXQoMSwgb3BlbnBncC5jb25maWcuY29uZmlnLnByZWZlcl9oYXNoX2FsZ29yaXRobSwgIHByaXZhdGVrZXksIGZhbHNlKTtcblx0XHRcdHV0aWwucHJpbnRfZGVidWdfaGV4c3RyX2R1bXAoXCJvbmVwYXNzc2lnc3RyOiB8XCIrb25lcGFzc3NpZ3N0citcInxcXG5cIixvbmVwYXNzc2lnc3RyKTtcblx0XHRcdHZhciBkYXRhc2lnbmF0dXJlID0gbmV3IG9wZW5wZ3BfcGFja2V0X3NpZ25hdHVyZSgpLndyaXRlX21lc3NhZ2Vfc2lnbmF0dXJlKDEsIG1lc3NhZ2V0ZXh0LnJlcGxhY2UoL1xcclxcbi9nLFwiXFxuXCIpLnJlcGxhY2UoL1xcbi9nLFwiXFxyXFxuXCIpLCBwcml2YXRla2V5KTtcblx0XHRcdHV0aWwucHJpbnRfZGVidWdfaGV4c3RyX2R1bXAoXCJkYXRhc2lnbmF0dXJlOiB8XCIrZGF0YXNpZ25hdHVyZS5vcGVucGdwK1wifFxcblwiLGRhdGFzaWduYXR1cmUub3BlbnBncCk7XG5cdFx0XHRpZiAoaSA9PSAwKSB7XG5cdFx0XHRcdHJlc3VsdCA9IG9uZXBhc3NzaWdzdHIrbGl0ZXJhbCtkYXRhc2lnbmF0dXJlLm9wZW5wZ3A7XG5cdFx0XHR9IGVsc2Uge1xuXHRcdFx0XHRyZXN1bHQgPSBvbmVwYXNzc2lnc3RyK3Jlc3VsdCtkYXRhc2lnbmF0dXJlLm9wZW5wZ3A7XG5cdFx0XHR9XG5cdFx0fVxuXHRcdFxuXHRcdHV0aWwucHJpbnRfZGVidWdfaGV4c3RyX2R1bXAoXCJzaWduZWQgcGFja2V0OiB8XCIrcmVzdWx0K1wifFxcblwiLHJlc3VsdCk7XG5cdFx0Ly8gc2lnbmF0dXJlcyBkb25lLi4gbm93IGVuY3J5cHRpb25cblx0XHR2YXIgc2Vzc2lvbmtleSA9IG9wZW5wZ3BfY3J5cHRvX2dlbmVyYXRlU2Vzc2lvbktleShvcGVucGdwLmNvbmZpZy5jb25maWcuZW5jcnlwdGlvbl9jaXBoZXIpOyBcblx0XHR2YXIgcmVzdWx0MiA9IFwiXCI7XG5cdFx0XG5cdFx0Ly8gY3JlYXRpbmcgc2Vzc2lvbiBrZXlzIGZvciBlYWNoIHJlY2lwaWVudFxuXHRcdGZvciAodmFyIGkgPSAwOyBpIDwgcHVibGlja2V5cy5sZW5ndGg7IGkrKykge1xuXHRcdFx0dmFyIHBrZXkgPSBwdWJsaWNrZXlzW2ldLmdldEVuY3J5cHRpb25LZXkoKTtcblx0XHRcdGlmIChwa2V5ID09IG51bGwpIHtcblx0XHRcdFx0dXRpbC5wcmludF9lcnJvcihcIm5vIGVuY3J5cHRpb24ga2V5IGZvdW5kISBLZXkgaXMgZm9yIHNpZ25pbmcgb25seS5cIik7XG5cdFx0XHRcdHJldHVybiBudWxsO1xuXHRcdFx0fVxuXHRcdFx0cmVzdWx0MiArPSBuZXcgb3BlbnBncF9wYWNrZXRfZW5jcnlwdGVkc2Vzc2lvbmtleSgpLlxuXHRcdFx0XHRcdHdyaXRlX3B1Yl9rZXlfcGFja2V0KFxuXHRcdFx0XHRcdFx0cGtleS5nZXRLZXlJZCgpLFxuXHRcdFx0XHRcdFx0cGtleS5NUElzLFxuXHRcdFx0XHRcdFx0cGtleS5wdWJsaWNLZXlBbGdvcml0aG0sXG5cdFx0XHRcdFx0XHRvcGVucGdwLmNvbmZpZy5jb25maWcuZW5jcnlwdGlvbl9jaXBoZXIsXG5cdFx0XHRcdFx0XHRzZXNzaW9ua2V5KTtcblx0XHR9XG5cdFx0aWYgKG9wZW5wZ3AuY29uZmlnLmNvbmZpZy5pbnRlZ3JpdHlfcHJvdGVjdCkge1xuXHRcdFx0cmVzdWx0MiArPSBuZXcgb3BlbnBncF9wYWNrZXRfZW5jcnlwdGVkaW50ZWdyaXR5cHJvdGVjdGVkZGF0YSgpLndyaXRlX3BhY2tldChvcGVucGdwLmNvbmZpZy5jb25maWcuZW5jcnlwdGlvbl9jaXBoZXIsIHNlc3Npb25rZXksIHJlc3VsdCk7XG5cdFx0fSBlbHNlIHtcblx0XHRcdHJlc3VsdDIgKz0gbmV3IG9wZW5wZ3BfcGFja2V0X2VuY3J5cHRlZGRhdGEoKS53cml0ZV9wYWNrZXQob3BlbnBncC5jb25maWcuY29uZmlnLmVuY3J5cHRpb25fY2lwaGVyLCBzZXNzaW9ua2V5LCByZXN1bHQpO1xuXHRcdH1cblx0XHRyZXR1cm4gb3BlbnBncF9lbmNvZGluZ19hcm1vcigzLHJlc3VsdDIsbnVsbCxudWxsKTtcblx0fVxuXHQvKipcblx0ICogY3JlYXRlcyBhIGJpbmFyeSBzdHJpbmcgcmVwcmVzZW50YXRpb24gb2YgYW4gZW5jcnlwdGVkIG1lc3NhZ2UuXG5cdCAqIFRoZSBtZXNzYWdlIHdpbGwgYmUgZW5jcnlwdGVkIHdpdGggdGhlIHB1YmxpYyBrZXlzIHNwZWNpZmllZCBcblx0ICogQHBhcmFtIHtPYmplY3RbXX0gcHVibGlja2V5cyBBbiBhcnJheSBvZiB7b2JqOiBbb3BlbnBncF9tc2dfcHVibGlja2V5XX1cblx0ICogLXB1YmxpYyBrZXlzIHRvIGJlIHVzZWQgdG8gZW5jcnlwdCB0aGUgbWVzc2FnZSBcblx0ICogQHBhcmFtIHtTdHJpbmd9IG1lc3NhZ2V0ZXh0IG1lc3NhZ2UgdGV4dCB0byBlbmNyeXB0XG5cdCAqIEByZXR1cm4ge1N0cmluZ30gYSBiaW5hcnkgc3RyaW5nIHJlcHJlc2VudGF0aW9uIG9mIHRoZSBtZXNzYWdlXG5cdCAqIHdoaWNoIGNhbiBiZSBPcGVuUEdQIGFybW9yZWRcblx0ICovXG5cdGZ1bmN0aW9uIHdyaXRlX2VuY3J5cHRlZF9tZXNzYWdlKHB1YmxpY2tleXMsIG1lc3NhZ2V0ZXh0KSB7XG5cdFx0dmFyIHJlc3VsdCA9IFwiXCI7XG5cdFx0dmFyIGxpdGVyYWwgPSBuZXcgb3BlbnBncF9wYWNrZXRfbGl0ZXJhbGRhdGEoKS53cml0ZV9wYWNrZXQobWVzc2FnZXRleHQucmVwbGFjZSgvXFxyXFxuL2csXCJcXG5cIikucmVwbGFjZSgvXFxuL2csXCJcXHJcXG5cIikpO1xuXHRcdHV0aWwucHJpbnRfZGVidWdfaGV4c3RyX2R1bXAoXCJsaXRlcmFsX3BhY2tldDogfFwiK2xpdGVyYWwrXCJ8XFxuXCIsbGl0ZXJhbCk7XG5cdFx0cmVzdWx0ID0gbGl0ZXJhbDtcblx0XHRcblx0XHQvLyBzaWduYXR1cmVzIGRvbmUuLiBub3cgZW5jcnlwdGlvblxuXHRcdHZhciBzZXNzaW9ua2V5ID0gb3BlbnBncF9jcnlwdG9fZ2VuZXJhdGVTZXNzaW9uS2V5KG9wZW5wZ3AuY29uZmlnLmNvbmZpZy5lbmNyeXB0aW9uX2NpcGhlcik7IFxuXHRcdHZhciByZXN1bHQyID0gXCJcIjtcblx0XHRcblx0XHQvLyBjcmVhdGluZyBzZXNzaW9uIGtleXMgZm9yIGVhY2ggcmVjaXBpZW50XG5cdFx0Zm9yICh2YXIgaSA9IDA7IGkgPCBwdWJsaWNrZXlzLmxlbmd0aDsgaSsrKSB7XG5cdFx0XHR2YXIgcGtleSA9IHB1YmxpY2tleXNbaV0uZ2V0RW5jcnlwdGlvbktleSgpO1xuXHRcdFx0aWYgKHBrZXkgPT0gbnVsbCkge1xuXHRcdFx0XHR1dGlsLnByaW50X2Vycm9yKFwibm8gZW5jcnlwdGlvbiBrZXkgZm91bmQhIEtleSBpcyBmb3Igc2lnbmluZyBvbmx5LlwiKTtcblx0XHRcdFx0cmV0dXJuIG51bGw7XG5cdFx0XHR9XG5cdFx0XHRyZXN1bHQyICs9IG5ldyBvcGVucGdwX3BhY2tldF9lbmNyeXB0ZWRzZXNzaW9ua2V5KCkuXG5cdFx0XHRcdFx0d3JpdGVfcHViX2tleV9wYWNrZXQoXG5cdFx0XHRcdFx0XHRwa2V5LmdldEtleUlkKCksXG5cdFx0XHRcdFx0XHRwa2V5Lk1QSXMsXG5cdFx0XHRcdFx0XHRwa2V5LnB1YmxpY0tleUFsZ29yaXRobSxcblx0XHRcdFx0XHRcdG9wZW5wZ3AuY29uZmlnLmNvbmZpZy5lbmNyeXB0aW9uX2NpcGhlcixcblx0XHRcdFx0XHRcdHNlc3Npb25rZXkpO1xuXHRcdH1cblx0XHRpZiAob3BlbnBncC5jb25maWcuY29uZmlnLmludGVncml0eV9wcm90ZWN0KSB7XG5cdFx0XHRyZXN1bHQyICs9IG5ldyBvcGVucGdwX3BhY2tldF9lbmNyeXB0ZWRpbnRlZ3JpdHlwcm90ZWN0ZWRkYXRhKCkud3JpdGVfcGFja2V0KG9wZW5wZ3AuY29uZmlnLmNvbmZpZy5lbmNyeXB0aW9uX2NpcGhlciwgc2Vzc2lvbmtleSwgcmVzdWx0KTtcblx0XHR9IGVsc2Uge1xuXHRcdFx0cmVzdWx0MiArPSBuZXcgb3BlbnBncF9wYWNrZXRfZW5jcnlwdGVkZGF0YSgpLndyaXRlX3BhY2tldChvcGVucGdwLmNvbmZpZy5jb25maWcuZW5jcnlwdGlvbl9jaXBoZXIsIHNlc3Npb25rZXksIHJlc3VsdCk7XG5cdFx0fVxuXHRcdHJldHVybiBvcGVucGdwX2VuY29kaW5nX2FybW9yKDMscmVzdWx0MixudWxsLG51bGwpO1xuXHR9XG5cdFxuXHQvKipcblx0ICogY3JlYXRlcyBhIGJpbmFyeSBzdHJpbmcgcmVwcmVzZW50YXRpb24gYSBzaWduZWQgbWVzc2FnZS5cblx0ICogVGhlIG1lc3NhZ2Ugd2lsbCBiZSBzaWduZWQgd2l0aCB0aGUgc3BlY2lmaWVkIHByaXZhdGUga2V5LlxuXHQgKiBAcGFyYW0ge09iamVjdH0gcHJpdmF0ZWtleSB7b2JqOiBbb3BlbnBncF9tc2dfcHJpdmF0ZWtleV19XG5cdCAqIC0gdGhlIHByaXZhdGUga2V5IHRvIGJlIHVzZWQgdG8gc2lnbiB0aGUgbWVzc2FnZSBcblx0ICogQHBhcmFtIHtTdHJpbmd9IG1lc3NhZ2V0ZXh0IG1lc3NhZ2UgdGV4dCB0byBzaWduXG5cdCAqIEByZXR1cm4ge09iamVjdH0ge09iamVjdDogdGV4dCBbU3RyaW5nXX0sIG9wZW5wZ3A6IHtTdHJpbmd9IGEgYmluYXJ5XG5cdCAqICBzdHJpbmcgcmVwcmVzZW50YXRpb24gb2YgdGhlIG1lc3NhZ2Ugd2hpY2ggY2FuIGJlIE9wZW5QR1Bcblx0ICogICBhcm1vcmVkKG9wZW5wZ3ApIGFuZCBhIHRleHQgcmVwcmVzZW50YXRpb24gb2YgdGhlIG1lc3NhZ2UgKHRleHQpLiBcblx0ICogVGhpcyBjYW4gYmUgZGlyZWN0bHkgdXNlZCB0byBPcGVuUEdQIGFybW9yIHRoZSBtZXNzYWdlXG5cdCAqL1xuXHRmdW5jdGlvbiB3cml0ZV9zaWduZWRfbWVzc2FnZShwcml2YXRla2V5LCBtZXNzYWdldGV4dCkge1xuXHRcdHZhciBzaWcgPSBuZXcgb3BlbnBncF9wYWNrZXRfc2lnbmF0dXJlKCkud3JpdGVfbWVzc2FnZV9zaWduYXR1cmUoMSwgbWVzc2FnZXRleHQucmVwbGFjZSgvXFxyXFxuL2csXCJcXG5cIikucmVwbGFjZSgvXFxuLyxcIlxcclxcblwiKSwgcHJpdmF0ZWtleSk7XG5cdFx0dmFyIHJlc3VsdCA9IHt0ZXh0OiBtZXNzYWdldGV4dC5yZXBsYWNlKC9cXHJcXG4vZyxcIlxcblwiKS5yZXBsYWNlKC9cXG4vLFwiXFxyXFxuXCIpLCBvcGVucGdwOiBzaWcub3BlbnBncCwgaGFzaDogc2lnLmhhc2h9O1xuXHRcdHJldHVybiBvcGVucGdwX2VuY29kaW5nX2FybW9yKDIscmVzdWx0LCBudWxsLCBudWxsKVxuXHR9XG5cdFxuXHQvKipcblx0ICogZ2VuZXJhdGVzIGEgbmV3IGtleSBwYWlyIGZvciBvcGVucGdwLiBCZXRhIHN0YWdlLiBDdXJyZW50bHkgb25seSBcblx0ICogc3VwcG9ydHMgUlNBIGtleXMsIGFuZCBubyBzdWJrZXlzLlxuXHQgKiBAcGFyYW0ge0ludGVnZXJ9IGtleVR5cGUgdG8gaW5kaWNhdGUgd2hhdCB0eXBlIG9mIGtleSB0byBtYWtlLiBcblx0ICogUlNBIGlzIDEuIEZvbGxvd3MgYWxnb3JpdGhtcyBvdXRsaW5lZCBpbiBPcGVuUEdQLlxuXHQgKiBAcGFyYW0ge0ludGVnZXJ9IG51bUJpdHMgbnVtYmVyIG9mIGJpdHMgZm9yIHRoZSBrZXkgY3JlYXRpb24uIChzaG91bGQgXG5cdCAqIGJlIDEwMjQrLCBnZW5lcmFsbHkpXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSB1c2VySWQgYXNzdW1lcyBhbHJlYWR5IGluIGZvcm0gb2YgXCJVc2VyIE5hbWUgXG5cdCAqIDx1c2VybmFtZUBlbWFpbC5jb20+XCJcblx0ICogQHBhcmFtIHtTdHJpbmd9IHBhc3NwaHJhc2UgVGhlIHBhc3NwaHJhc2UgdXNlZCB0byBlbmNyeXB0IHRoZSByZXN1bHRpbmcgcHJpdmF0ZSBrZXlcblx0ICogQHJldHVybiB7T2JqZWN0fSB7cHJpdmF0ZUtleTogW29wZW5wZ3BfbXNnX3ByaXZhdGVrZXldLCBcblx0ICogcHJpdmF0ZUtleUFybW9yZWQ6IFtzdHJpbmddLCBwdWJsaWNLZXlBcm1vcmVkOiBbc3RyaW5nXX1cblx0ICovXG5cdGZ1bmN0aW9uIGdlbmVyYXRlX2tleV9wYWlyKGtleVR5cGUsIG51bUJpdHMsIHVzZXJJZCwgcGFzc3BocmFzZSl7XG5cdFx0dmFyIHVzZXJJZFBhY2tldCA9IG5ldyBvcGVucGdwX3BhY2tldF91c2VyaWQoKTtcblx0XHR2YXIgdXNlcklkU3RyaW5nID0gdXNlcklkUGFja2V0LndyaXRlX3BhY2tldCh1c2VySWQpO1xuXHRcdFxuXHRcdHZhciBrZXlQYWlyID0gb3BlbnBncF9jcnlwdG9fZ2VuZXJhdGVLZXlQYWlyKGtleVR5cGUsbnVtQml0cywgcGFzc3BocmFzZSwgb3BlbnBncC5jb25maWcuY29uZmlnLnByZWZlcl9oYXNoX2FsZ29yaXRobSwgMyk7XG5cdFx0dmFyIHByaXZLZXlTdHJpbmcgPSBrZXlQYWlyLnByaXZhdGVLZXk7XG5cdFx0dmFyIHByaXZLZXlQYWNrZXQgPSBuZXcgb3BlbnBncF9wYWNrZXRfa2V5bWF0ZXJpYWwoKS5yZWFkX3ByaXZfa2V5KHByaXZLZXlTdHJpbmcuc3RyaW5nLDMscHJpdktleVN0cmluZy5zdHJpbmcubGVuZ3RoKTtcblx0XHRpZighcHJpdktleVBhY2tldC5kZWNyeXB0U2VjcmV0TVBJcyhwYXNzcGhyYXNlKSlcblx0XHQgICAgdXRpbC5wcmludF9lcnJvcignSXNzdWUgY3JlYXRpbmcga2V5LiBVbmFibGUgdG8gcmVhZCByZXN1bHRpbmcgcHJpdmF0ZSBrZXknKTtcblx0XHR2YXIgcHJpdktleSA9IG5ldyBvcGVucGdwX21zZ19wcml2YXRla2V5KCk7XG5cdFx0cHJpdktleS5wcml2YXRlS2V5UGFja2V0ID0gcHJpdktleVBhY2tldDtcblx0XHRwcml2S2V5LmdldFByZWZlcnJlZFNpZ25hdHVyZUhhc2hBbGdvcml0aG0gPSBmdW5jdGlvbigpe3JldHVybiBvcGVucGdwLmNvbmZpZy5jb25maWcucHJlZmVyX2hhc2hfYWxnb3JpdGhtfTsvL25lZWQgdG8gb3ZlcnJpZGUgdGhpcyB0byBzb2x2ZSBjYXRjaCAyMiB0byBnZW5lcmF0ZSBzaWduYXR1cmUuIDggaXMgdmFsdWUgZm9yIFNIQTI1NlxuXHRcdFxuXHRcdHZhciBwdWJsaWNLZXlTdHJpbmcgPSBwcml2S2V5LnByaXZhdGVLZXlQYWNrZXQucHVibGljS2V5LmRhdGE7XG5cdFx0dmFyIGhhc2hEYXRhID0gU3RyaW5nLmZyb21DaGFyQ29kZSgweDk5KSsgU3RyaW5nLmZyb21DaGFyQ29kZSgoKHB1YmxpY0tleVN0cmluZy5sZW5ndGgpID4+IDgpICYgMHhGRikgXG5cdFx0XHQrIFN0cmluZy5mcm9tQ2hhckNvZGUoKHB1YmxpY0tleVN0cmluZy5sZW5ndGgpICYgMHhGRikgK3B1YmxpY0tleVN0cmluZytTdHJpbmcuZnJvbUNoYXJDb2RlKDB4QjQpICtcblx0XHRcdFN0cmluZy5mcm9tQ2hhckNvZGUoKHVzZXJJZC5sZW5ndGgpID4+IDI0KSArU3RyaW5nLmZyb21DaGFyQ29kZSgoKHVzZXJJZC5sZW5ndGgpID4+IDE2KSAmIDB4RkYpIFxuXHRcdFx0KyBTdHJpbmcuZnJvbUNoYXJDb2RlKCgodXNlcklkLmxlbmd0aCkgPj4gOCkgJiAweEZGKSArIFN0cmluZy5mcm9tQ2hhckNvZGUoKHVzZXJJZC5sZW5ndGgpICYgMHhGRikgKyB1c2VySWRcblx0XHR2YXIgc2lnbmF0dXJlID0gbmV3IG9wZW5wZ3BfcGFja2V0X3NpZ25hdHVyZSgpO1xuXHRcdHNpZ25hdHVyZSA9IHNpZ25hdHVyZS53cml0ZV9tZXNzYWdlX3NpZ25hdHVyZSgxNixoYXNoRGF0YSwgcHJpdktleSk7XG5cdFx0dmFyIHB1YmxpY0FybW9yZWQgPSBvcGVucGdwX2VuY29kaW5nX2FybW9yKDQsIGtleVBhaXIucHVibGljS2V5LnN0cmluZyArIHVzZXJJZFN0cmluZyArIHNpZ25hdHVyZS5vcGVucGdwICk7XG5cblx0XHR2YXIgcHJpdkFybW9yZWQgPSBvcGVucGdwX2VuY29kaW5nX2FybW9yKDUscHJpdktleVN0cmluZy5zdHJpbmcrdXNlcklkU3RyaW5nK3NpZ25hdHVyZS5vcGVucGdwKTtcblx0XHRcblx0XHRyZXR1cm4ge3ByaXZhdGVLZXkgOiBwcml2S2V5LCBwcml2YXRlS2V5QXJtb3JlZDogcHJpdkFybW9yZWQsIHB1YmxpY0tleUFybW9yZWQ6IHB1YmxpY0FybW9yZWR9XG5cdH1cblx0XG5cdHRoaXMuZ2VuZXJhdGVfa2V5X3BhaXIgPSBnZW5lcmF0ZV9rZXlfcGFpcjtcblx0dGhpcy53cml0ZV9zaWduZWRfbWVzc2FnZSA9IHdyaXRlX3NpZ25lZF9tZXNzYWdlOyBcblx0dGhpcy53cml0ZV9zaWduZWRfYW5kX2VuY3J5cHRlZF9tZXNzYWdlID0gd3JpdGVfc2lnbmVkX2FuZF9lbmNyeXB0ZWRfbWVzc2FnZTtcblx0dGhpcy53cml0ZV9lbmNyeXB0ZWRfbWVzc2FnZSA9IHdyaXRlX2VuY3J5cHRlZF9tZXNzYWdlO1xuXHR0aGlzLnJlYWRfbWVzc2FnZSA9IHJlYWRfbWVzc2FnZTtcblx0dGhpcy5yZWFkX21lc3NhZ2VzX2RlYXJtb3JlZCA9IHJlYWRfbWVzc2FnZXNfZGVhcm1vcmVkO1xuXHR0aGlzLnJlYWRfcHVibGljS2V5ID0gcmVhZF9wdWJsaWNLZXk7XG5cdHRoaXMucmVhZF9wcml2YXRlS2V5ID0gcmVhZF9wcml2YXRlS2V5O1xuXHR0aGlzLmluaXQgPSBpbml0O1xufVxuXG5tb2R1bGUuZXhwb3J0cyA9IG5ldyBfb3BlbnBncCgpO1xuXG4iLCIvLyBHUEc0QnJvd3NlcnMgLSBBbiBPcGVuUEdQIGltcGxlbWVudGF0aW9uIGluIGphdmFzY3JpcHRcbi8vIENvcHlyaWdodCAoQykgMjAxMSBSZWN1cml0eSBMYWJzIEdtYkhcbi8vIFxuLy8gVGhpcyBsaWJyYXJ5IGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vclxuLy8gbW9kaWZ5IGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIExlc3NlciBHZW5lcmFsIFB1YmxpY1xuLy8gTGljZW5zZSBhcyBwdWJsaXNoZWQgYnkgdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyXG4vLyB2ZXJzaW9uIDIuMSBvZiB0aGUgTGljZW5zZSwgb3IgKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbi8vIFxuLy8gVGhpcyBsaWJyYXJ5IGlzIGRpc3RyaWJ1dGVkIGluIHRoZSBob3BlIHRoYXQgaXQgd2lsbCBiZSB1c2VmdWwsXG4vLyBidXQgV0lUSE9VVCBBTlkgV0FSUkFOVFk7IHdpdGhvdXQgZXZlbiB0aGUgaW1wbGllZCB3YXJyYW50eSBvZlxuLy8gTUVSQ0hBTlRBQklMSVRZIG9yIEZJVE5FU1MgRk9SIEEgUEFSVElDVUxBUiBQVVJQT1NFLiAgU2VlIHRoZSBHTlVcbi8vIExlc3NlciBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGZvciBtb3JlIGRldGFpbHMuXG4vLyBcbi8vIFlvdSBzaG91bGQgaGF2ZSByZWNlaXZlZCBhIGNvcHkgb2YgdGhlIEdOVSBMZXNzZXIgR2VuZXJhbCBQdWJsaWNcbi8vIExpY2Vuc2UgYWxvbmcgd2l0aCB0aGlzIGxpYnJhcnk7IGlmIG5vdCwgd3JpdGUgdG8gdGhlIEZyZWUgU29mdHdhcmVcbi8vIEZvdW5kYXRpb24sIEluYy4sIDUxIEZyYW5rbGluIFN0cmVldCwgRmlmdGggRmxvb3IsIEJvc3RvbiwgTUEgIDAyMTEwLTEzMDEgIFVTQVxuXG4vKipcbiAqIEBjbGFzc1xuICogQGNsYXNzZGVzYyBJbXBsZW1lbnRhdGlvbiBvZiB0aGUgU3RyaW5nLXRvLWtleSBzcGVjaWZpZXIgKFJGQzQ4ODAgMy43KVxuICogU3RyaW5nLXRvLWtleSAoUzJLKSBzcGVjaWZpZXJzIGFyZSB1c2VkIHRvIGNvbnZlcnQgcGFzc3BocmFzZSBzdHJpbmdzXG4gICBpbnRvIHN5bW1ldHJpYy1rZXkgZW5jcnlwdGlvbi9kZWNyeXB0aW9uIGtleXMuICBUaGV5IGFyZSB1c2VkIGluIHR3b1xuICAgcGxhY2VzLCBjdXJyZW50bHk6IHRvIGVuY3J5cHQgdGhlIHNlY3JldCBwYXJ0IG9mIHByaXZhdGUga2V5cyBpbiB0aGVcbiAgIHByaXZhdGUga2V5cmluZywgYW5kIHRvIGNvbnZlcnQgcGFzc3BocmFzZXMgdG8gZW5jcnlwdGlvbiBrZXlzIGZvclxuICAgc3ltbWV0cmljYWxseSBlbmNyeXB0ZWQgbWVzc2FnZXMuXG4gKi9cbmZ1bmN0aW9uIG9wZW5wZ3BfdHlwZV9zMmsoKSB7XG5cdC8qKiBAdHlwZSB7b3BlbnBncC5oYXNofSAqL1xuXHR0aGlzLmFsZ29yaXRobSA9IG9wZW5wZ3AuaGFzaC5zaGEyNTY7XG5cdC8qKiBAdHlwZSB7b3BlbnBncF90eXBlX3Myay50eXBlfSAqL1xuXHR0aGlzLnR5cGUgPSBvcGVucGdwX3R5cGVfczJrLnR5cGUuaXRlcmF0ZWQ7XG5cdHRoaXMuYyA9IDk2O1xuXHQvKiogQHR5cGUge29wZW5wZ3BfYnl0ZWFycmF5fSBcblx0ICogRWlnaHQgYnl0ZXMgb2Ygc2FsdC4gKi9cblx0dGhpcy5zYWx0ID0gb3BlbnBncF9jcnlwdG9fZ2V0UmFuZG9tQnl0ZXMoOCk7XG5cblxuXHQvLyBFeHBvbmVuIGJpYXMsIGRlZmluZWQgaW4gUkZDNDg4MFxuXHR2YXIgZXhwYmlhcyA9IDY7XG5cblx0dGhpcy5nZXRfY291bnQgPSBmdW5jdGlvbigpIHtcblx0XHRyZXR1cm4gKDE2ICsgKHRoaXMuYyAmIDE1KSkgPDwgKCh0aGlzLmMgPj4gNCkgKyBleHBiaWFzKTtcblx0fVxuXG5cdC8qKlxuXHQgKiBQYXJzaW5nIGZ1bmN0aW9uIGZvciBhIHN0cmluZy10by1rZXkgc3BlY2lmaWVyIChSRkMgNDg4MCAzLjcpLlxuXHQgKiBAcGFyYW0ge1N0cmluZ30gaW5wdXQgUGF5bG9hZCBvZiBzdHJpbmctdG8ta2V5IHNwZWNpZmllclxuXHQgKiBAcmV0dXJuIHtJbnRlZ2VyfSBBY3R1YWwgbGVuZ3RoIG9mIHRoZSBvYmplY3Rcblx0ICovXG5cdHRoaXMucmVhZCA9IGZ1bmN0aW9uKGJ5dGVzKSB7XG5cdFx0dmFyIGkgPSAwO1xuXHRcdHRoaXMudHlwZSA9IGJ5dGVzW2krK10uY2hhckNvZGVBdCgpO1xuXHRcdHRoaXMuYWxnb3JpdGhtID0gYnl0ZXNbaSsrXS5jaGFyQ29kZUF0KCk7XG5cblx0XHR2YXIgdCA9IG9wZW5wZ3BfdHlwZV9zMmsudHlwZTtcblxuXHRcdHN3aXRjaCAodGhpcy50eXBlKSB7XG5cdFx0Y2FzZSB0LnNpbXBsZTpcblx0XHRcdGJyZWFrO1xuXG5cdFx0Y2FzZSB0LnNhbHRlZDpcblx0XHRcdHRoaXMuc2FsdCA9IGJ5dGVzLnN1YnN0cihpLCA4KTtcblx0XHRcdGkgKz0gODtcblx0XHRcdGJyZWFrO1xuXG5cdFx0Y2FzZSB0Lml0ZXJhdGVkOlxuXHRcdFx0dGhpcy5zYWx0ID0gYnl0ZXMuc3Vic3RyKGksIDgpO1xuXHRcdFx0aSArPSA4O1xuXG5cdFx0XHQvLyBPY3RldCAxMDogY291bnQsIGEgb25lLW9jdGV0LCBjb2RlZCB2YWx1ZVxuXHRcdFx0dGhpcy5jID0gYnl0ZXNbaSsrXS5jaGFyQ29kZUF0KCk7XG5cdFx0XHRicmVhaztcblxuXHRcdGNhc2UgdC5nbnU6XG5cdFx0XHRpZihieXRlcy5zdWJzdHIoaSwgMykgPT0gXCJHTlVcIikge1xuXHRcdFx0XHRpICs9IDM7IC8vIEdOVVxuXHRcdFx0XHR2YXIgZ251RXh0VHlwZSA9IDEwMDAgKyBieXRlc1tpKytdLmNoYXJDb2RlQXQoKTtcblx0XHRcdFx0aWYoZ251RXh0VHlwZSA9PSAxMDAxKSB7XG5cdFx0XHRcdFx0dGhpcy50eXBlID0gZ251RXh0VHlwZTtcblx0XHRcdFx0XHQvLyBHbnVQRyBleHRlbnNpb24gbW9kZSAxMDAxIC0tIGRvbid0IHdyaXRlIHNlY3JldCBrZXkgYXQgYWxsXG5cdFx0XHRcdH0gZWxzZSB7XG5cdFx0XHRcdFx0dXRpbC5wcmludF9lcnJvcihcInVua25vd24gczJrIGdudSBwcm90ZWN0aW9uIG1vZGUhIFwiK3RoaXMudHlwZSk7XG5cdFx0XHRcdH1cblx0XHRcdH0gZWxzZSB7XG5cdFx0XHRcdHV0aWwucHJpbnRfZXJyb3IoXCJ1bmtub3duIHMyayB0eXBlISBcIit0aGlzLnR5cGUpO1xuXHRcdFx0fVxuXHRcdFx0YnJlYWs7XG5cblx0XHRkZWZhdWx0OlxuXHRcdFx0dXRpbC5wcmludF9lcnJvcihcInVua25vd24gczJrIHR5cGUhIFwiK3RoaXMudHlwZSk7XG5cdFx0XHRicmVhaztcblx0XHR9XG5cblx0XHRyZXR1cm4gaTtcblx0fVxuXHRcblx0XG5cdC8qKlxuXHQgKiB3cml0ZXMgYW4gczJrIGhhc2ggYmFzZWQgb24gdGhlIGlucHV0cy5cblx0ICogQHJldHVybiB7U3RyaW5nfSBQcm9kdWNlZCBrZXkgb2YgaGFzaEFsZ29yaXRobSBoYXNoIGxlbmd0aFxuXHQgKi9cblx0dGhpcy53cml0ZSA9IGZ1bmN0aW9uKCkge1xuXHRcdHZhciBieXRlcyA9IFN0cmluZy5mcm9tQ2hhckNvZGUodGhpcy50eXBlKTtcblx0XHRieXRlcyArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKHRoaXMuYWxnb3JpdGhtKTtcblxuXHRcdHZhciB0ID0gb3BlbnBncF90eXBlX3Myay50eXBlO1xuXHRcdHN3aXRjaCh0aGlzLnR5cGUpIHtcblx0XHRcdGNhc2UgdC5zaW1wbGU6XG5cdFx0XHRcdGJyZWFrO1xuXHRcdFx0Y2FzZSB0LnNhbHRlZDpcblx0XHRcdFx0Ynl0ZXMgKz0gdGhpcy5zYWx0O1xuXHRcdFx0XHRicmVhaztcblx0XHRcdGNhc2UgdC5pdGVyYXRlZDpcblx0XHRcdFx0Ynl0ZXMgKz0gdGhpcy5zYWx0O1xuXHRcdFx0XHRieXRlcyArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKHRoaXMuYyk7XG5cdFx0XHRcdGJyZWFrO1xuXHRcdH07XG5cblx0XHRyZXR1cm4gYnl0ZXM7XG5cdH1cblxuXHQvKipcblx0ICogUHJvZHVjZXMgYSBrZXkgdXNpbmcgdGhlIHNwZWNpZmllZCBwYXNzcGhyYXNlIGFuZCB0aGUgZGVmaW5lZCBcblx0ICogaGFzaEFsZ29yaXRobSBcblx0ICogQHBhcmFtIHtTdHJpbmd9IHBhc3NwaHJhc2UgUGFzc3BocmFzZSBjb250YWluaW5nIHVzZXIgaW5wdXRcblx0ICogQHJldHVybiB7U3RyaW5nfSBQcm9kdWNlZCBrZXkgd2l0aCBhIGxlbmd0aCBjb3JyZXNwb25kaW5nIHRvIFxuXHQgKiBoYXNoQWxnb3JpdGhtIGhhc2ggbGVuZ3RoXG5cdCAqL1xuXHR0aGlzLnByb2R1Y2Vfa2V5ID0gZnVuY3Rpb24ocGFzc3BocmFzZSwgbnVtQnl0ZXMpIHtcblx0XHRwYXNzcGhyYXNlID0gdXRpbC5lbmNvZGVfdXRmOChwYXNzcGhyYXNlKTtcblxuXHRcdGZ1bmN0aW9uIHJvdW5kKHByZWZpeCwgczJrKSB7XG5cblx0XHRcdHZhciB0ID0gb3BlbnBncF90eXBlX3Myay50eXBlO1xuXHRcdFx0c3dpdGNoKHMyay50eXBlKSB7XG5cdFx0XHRcdGNhc2UgdC5zaW1wbGU6XG5cdFx0XHRcdFx0cmV0dXJuIG9wZW5wZ3BfY3J5cHRvX2hhc2hEYXRhKHMyay5hbGdvcml0aG0sIHByZWZpeCArIHBhc3NwaHJhc2UpO1xuXG5cdFx0XHRcdGNhc2UgdC5zYWx0ZWQ6XG5cdFx0XHRcdFx0cmV0dXJuIG9wZW5wZ3BfY3J5cHRvX2hhc2hEYXRhKHMyay5hbGdvcml0aG0sIFxuXHRcdFx0XHRcdFx0cHJlZml4ICsgczJrLnNhbHQgKyBwYXNzcGhyYXNlKTtcblxuXHRcdFx0XHRjYXNlIHQuaXRlcmF0ZWQ6XG5cdFx0XHRcdFx0dmFyIGlzcCA9IFtdLFxuXHRcdFx0XHRcdFx0Y291bnQgPSBzMmsuZ2V0X2NvdW50KCk7XG5cdFx0XHRcdFx0XHRkYXRhID0gczJrLnNhbHQgKyBwYXNzcGhyYXNlO1xuXG5cdFx0XHRcdFx0d2hpbGUgKGlzcC5sZW5ndGggKiBkYXRhLmxlbmd0aCA8IGNvdW50KVxuXHRcdFx0XHRcdFx0aXNwLnB1c2goZGF0YSk7XG5cblx0XHRcdFx0XHRpc3AgPSBpc3Auam9pbignJyk7XHRcdFx0XG5cblx0XHRcdFx0XHRpZiAoaXNwLmxlbmd0aCA+IGNvdW50KVxuXHRcdFx0XHRcdFx0aXNwID0gaXNwLnN1YnN0cigwLCBjb3VudCk7XG5cblx0XHRcdFx0XHRyZXR1cm4gb3BlbnBncF9jcnlwdG9faGFzaERhdGEoczJrLmFsZ29yaXRobSwgcHJlZml4ICsgaXNwKTtcblx0XHRcdH07XG5cdFx0fVxuXHRcdFxuXHRcdHZhciByZXN1bHQgPSAnJyxcblx0XHRcdHByZWZpeCA9ICcnO1xuXG5cdFx0d2hpbGUocmVzdWx0Lmxlbmd0aCA8PSBudW1CeXRlcykge1xuXHRcdFx0cmVzdWx0ICs9IHJvdW5kKHByZWZpeCwgdGhpcyk7XG5cdFx0XHRwcmVmaXggKz0gU3RyaW5nLmZyb21DaGFyQ29kZSgwKTtcblx0XHR9XG5cblx0XHRyZXR1cm4gcmVzdWx0LnN1YnN0cigwLCBudW1CeXRlcyk7XG5cdH1cbn1cblxuXG5cbi8qKiBBIHN0cmluZyB0byBrZXkgc3BlY2lmaWVyIHR5cGVcbiAqIEBlbnVtIHtJbnRlZ2VyfVxuICovXG5vcGVucGdwX3R5cGVfczJrLnR5cGUgPSB7XG5cdHNpbXBsZTogMCxcblx0c2FsdGVkOiAxLFxuXHRpdGVyYXRlZDogMyxcblx0Z251OiAxMDFcbn1cbiIsIi8vIEdQRzRCcm93c2VycyAtIEFuIE9wZW5QR1AgaW1wbGVtZW50YXRpb24gaW4gamF2YXNjcmlwdFxuLy8gQ29weXJpZ2h0IChDKSAyMDExIFJlY3VyaXR5IExhYnMgR21iSFxuLy8gXG4vLyBUaGlzIGxpYnJhcnkgaXMgZnJlZSBzb2Z0d2FyZTsgeW91IGNhbiByZWRpc3RyaWJ1dGUgaXQgYW5kL29yXG4vLyBtb2RpZnkgaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgTGVzc2VyIEdlbmVyYWwgUHVibGljXG4vLyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieSB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uOyBlaXRoZXJcbi8vIHZlcnNpb24gMi4xIG9mIHRoZSBMaWNlbnNlLCBvciAoYXQgeW91ciBvcHRpb24pIGFueSBsYXRlciB2ZXJzaW9uLlxuLy8gXG4vLyBUaGlzIGxpYnJhcnkgaXMgZGlzdHJpYnV0ZWQgaW4gdGhlIGhvcGUgdGhhdCBpdCB3aWxsIGJlIHVzZWZ1bCxcbi8vIGJ1dCBXSVRIT1VUIEFOWSBXQVJSQU5UWTsgd2l0aG91dCBldmVuIHRoZSBpbXBsaWVkIHdhcnJhbnR5IG9mXG4vLyBNRVJDSEFOVEFCSUxJVFkgb3IgRklUTkVTUyBGT1IgQSBQQVJUSUNVTEFSIFBVUlBPU0UuICBTZWUgdGhlIEdOVVxuLy8gTGVzc2VyIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgZm9yIG1vcmUgZGV0YWlscy5cbi8vIFxuLy8gWW91IHNob3VsZCBoYXZlIHJlY2VpdmVkIGEgY29weSBvZiB0aGUgR05VIExlc3NlciBHZW5lcmFsIFB1YmxpY1xuLy8gTGljZW5zZSBhbG9uZyB3aXRoIHRoaXMgbGlicmFyeTsgaWYgbm90LCB3cml0ZSB0byB0aGUgRnJlZSBTb2Z0d2FyZVxuLy8gRm91bmRhdGlvbiwgSW5jLiwgNTEgRnJhbmtsaW4gU3RyZWV0LCBGaWZ0aCBGbG9vciwgQm9zdG9uLCBNQSAgMDIxMTAtMTMwMSAgVVNBXG5cbi8qKlxuICogQGNsYXNzXG4gKiBAY2xhc3NkZXNjIEltcGxlbWVudGF0aW9uIG9mIHR5cGUga2V5IGlkIChSRkM0ODgwIDMuMylcbiAqICBBIEtleSBJRCBpcyBhbiBlaWdodC1vY3RldCBzY2FsYXIgdGhhdCBpZGVudGlmaWVzIGEga2V5LlxuICAgSW1wbGVtZW50YXRpb25zIFNIT1VMRCBOT1QgYXNzdW1lIHRoYXQgS2V5IElEcyBhcmUgdW5pcXVlLiAgVGhlXG4gICBzZWN0aW9uIFwiRW5oYW5jZWQgS2V5IEZvcm1hdHNcIiBiZWxvdyBkZXNjcmliZXMgaG93IEtleSBJRHMgYXJlXG4gICBmb3JtZWQuXG4gKi9cbmZ1bmN0aW9uIG9wZW5wZ3BfdHlwZV9rZXlpZCgpIHtcblx0dmFyIGJ5dGVzID0gJyc7XG5cblx0Zm9yKHZhciBpID0gMDsgaSA8IDg7IGkrKylcblx0XHRieXRlcyArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKDApO1xuXHQvKipcblx0ICogUGFyc2luZyBtZXRob2QgZm9yIGEga2V5IGlkXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBpbnB1dCBJbnB1dCB0byByZWFkIHRoZSBrZXkgaWQgZnJvbSBcblx0ICogQHBhcmFtIHtpbnRlZ2VyfSBwb3NpdGlvbiBQb3NpdGlvbiB3aGVyZSB0byBzdGFydCByZWFkaW5nIHRoZSBrZXkgXG5cdCAqIGlkIGZyb20gaW5wdXRcblx0ICogQHJldHVybiB7b3BlbnBncF90eXBlX2tleWlkfSBUaGlzIG9iamVjdFxuXHQgKi9cblx0ZnVuY3Rpb24gcmVhZF9wYWNrZXQoaW5wdXQsIHBvc2l0aW9uKSB7XG5cdFx0dGhpcy5ieXRlcyA9IGlucHV0LnN1YnN0cmluZyhwb3NpdGlvbiwgcG9zaXRpb24rOCk7XG5cdFx0cmV0dXJuIHRoaXM7XG5cdH1cblx0XG5cdC8qKlxuXHQgKiBHZW5lcmF0ZXMgZGVidWcgb3V0cHV0IChwcmV0dHkgcHJpbnQpXG5cdCAqIEByZXR1cm4ge1N0cmluZ30gS2V5IElkIGFzIGhleGFkZWNpbWFsIHN0cmluZ1xuXHQgKi9cblx0ZnVuY3Rpb24gdG9TdHJpbmcoKSB7XG5cdFx0cmV0dXJuIHV0aWwuaGV4c3RyZHVtcCh0aGlzLmJ5dGVzKTtcblx0fVxuXHRcblx0dGhpcy5yZWFkX3BhY2tldCA9IHJlYWRfcGFja2V0O1xuXHR0aGlzLnRvU3RyaW5nID0gdG9TdHJpbmc7XG59O1xuIiwiXG5cblxudmFyIGNyeXB0byA9IHJlcXVpcmUoJy4vY3J5cHRvJyk7XG5cbm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZSgnLi9vcGVucGdwLmpzJyk7XG5tb2R1bGUuZXhwb3J0cy51dGlsID0gcmVxdWlyZSgnLi91dGlsJyk7XG5tb2R1bGUuZXhwb3J0cy5wYWNrZXQgPSByZXF1aXJlKCcuL3BhY2tldCcpO1xubW9kdWxlLmV4cG9ydHMubXBpID0gcmVxdWlyZSgnLi90eXBlL21waS5qcycpO1xubW9kdWxlLmV4cG9ydHMuczJrID0gcmVxdWlyZSgnLi90eXBlL3Myay5qcycpO1xubW9kdWxlLmV4cG9ydHMua2V5aWQgPSByZXF1aXJlKCcuL3R5cGUva2V5aWQuanMnKTtcbm1vZHVsZS5leHBvcnRzLmFybW9yID0gcmVxdWlyZSgnLi9lbmNvZGluZy9hcm1vci5qcycpO1xuXG5mb3IodmFyIGkgaW4gY3J5cHRvKVxuXHRtb2R1bGUuZXhwb3J0c1tpXSA9IGNyeXB0b1tpXTtcblxuIiwiLy8gR1BHNEJyb3dzZXJzIC0gQW4gT3BlblBHUCBpbXBsZW1lbnRhdGlvbiBpbiBqYXZhc2NyaXB0XG4vLyBDb3B5cmlnaHQgKEMpIDIwMTEgUmVjdXJpdHkgTGFicyBHbWJIXG4vLyBcbi8vIFRoaXMgbGlicmFyeSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3Jcbi8vIG1vZGlmeSBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBMZXNzZXIgR2VuZXJhbCBQdWJsaWNcbi8vIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5IHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlclxuLy8gdmVyc2lvbiAyLjEgb2YgdGhlIExpY2Vuc2UsIG9yIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4vLyBcbi8vIFRoaXMgbGlicmFyeSBpcyBkaXN0cmlidXRlZCBpbiB0aGUgaG9wZSB0aGF0IGl0IHdpbGwgYmUgdXNlZnVsLFxuLy8gYnV0IFdJVEhPVVQgQU5ZIFdBUlJBTlRZOyB3aXRob3V0IGV2ZW4gdGhlIGltcGxpZWQgd2FycmFudHkgb2Zcbi8vIE1FUkNIQU5UQUJJTElUWSBvciBGSVRORVNTIEZPUiBBIFBBUlRJQ1VMQVIgUFVSUE9TRS4gIFNlZSB0aGUgR05VXG4vLyBMZXNzZXIgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBmb3IgbW9yZSBkZXRhaWxzLlxuLy8gXG4vLyBZb3Ugc2hvdWxkIGhhdmUgcmVjZWl2ZWQgYSBjb3B5IG9mIHRoZSBHTlUgTGVzc2VyIEdlbmVyYWwgUHVibGljXG4vLyBMaWNlbnNlIGFsb25nIHdpdGggdGhpcyBsaWJyYXJ5OyBpZiBub3QsIHdyaXRlIHRvIHRoZSBGcmVlIFNvZnR3YXJlXG4vLyBGb3VuZGF0aW9uLCBJbmMuLCA1MSBGcmFua2xpbiBTdHJlZXQsIEZpZnRoIEZsb29yLCBCb3N0b24sIE1BICAwMjExMC0xMzAxICBVU0FcblxudmFyIFV0aWwgPSBmdW5jdGlvbigpIHtcblxuXG5cblx0dGhpcy5yZWFkTnVtYmVyID0gZnVuY3Rpb24gKGJ5dGVzKSB7XG5cdFx0dmFyIG4gPSAwO1xuXG5cdFx0Zm9yKHZhciBpID0gMDsgaSA8IGJ5dGVzLmxlbmd0aDsgaSsrKSB7XG5cdFx0XHRuIDw8PSA4O1xuXHRcdFx0biArPSBieXRlc1tpXS5jaGFyQ29kZUF0KClcblx0XHR9XG5cblx0XHRyZXR1cm4gbjtcblx0fVxuXG5cdHRoaXMud3JpdGVOdW1iZXIgPSBmdW5jdGlvbihuLCBieXRlcykge1xuXHRcdHZhciBiID0gJyc7XG5cdFx0Zm9yKHZhciBpID0gMDsgaSA8IGJ5dGVzOyBpKyspIHtcblx0XHRcdGIgKz0gU3RyaW5nLmZyb21DaGFyQ29kZSgobiA+PiAoOCAqIChieXRlcy0gaSAtIDEpKSkgJiAweEZGKTtcblx0XHR9XG5cblx0XHRyZXR1cm4gYjtcblx0fVxuXG5cblxuXHR0aGlzLnJlYWREYXRlID0gZnVuY3Rpb24oYnl0ZXMpIHtcblx0XHR2YXIgbiA9IHRoaXMucmVhZE51bWJlcihieXRlcyk7XG5cdFx0dmFyIGQgPSBuZXcgRGF0ZSgpO1xuXHRcdGQuc2V0VGltZShuICogMTAwMCk7XG5cdFx0cmV0dXJuIGQ7XG5cdH1cblxuXHR0aGlzLndyaXRlRGF0ZSA9IGZ1bmN0aW9uKHRpbWUpIHtcblx0XHR2YXIgbnVtZXJpYyA9IE1hdGgucm91bmQodGltZS5nZXRUaW1lKCkgLyAxMDAwKTtcblxuXHRcdHJldHVybiB0aGlzLndyaXRlTnVtYmVyKG51bWVyaWMsIDQpO1xuXHR9XG5cbiAgICB0aGlzLmVtYWlsUmVnRXggPSAvW2EtejAtOSEjJCUmJyorLz0/Xl9ge3x9fi1dKyg/OlxcLlthLXowLTkhIyQlJicqKy89P15fYHt8fX4tXSspKkAoPzpbYS16MC05XSg/OlthLXowLTktXSpbYS16MC05XSk/XFwuKStbYS16MC05XSg/OlthLXowLTktXSpbYS16MC05XSk/Lztcblx0XG5cdHRoaXMuZGVidWcgPSBmYWxzZTtcblxuXHR0aGlzLmhleGR1bXAgPSBmdW5jdGlvbihzdHIpIHtcblx0ICAgIHZhciByPVtdO1xuXHQgICAgdmFyIGU9c3RyLmxlbmd0aDtcblx0ICAgIHZhciBjPTA7XG5cdCAgICB2YXIgaDtcblx0ICAgIHZhciBpID0gMDtcblx0ICAgIHdoaWxlKGM8ZSl7XG5cdCAgICAgICAgaD1zdHIuY2hhckNvZGVBdChjKyspLnRvU3RyaW5nKDE2KTtcblx0ICAgICAgICB3aGlsZShoLmxlbmd0aDwyKSBoPVwiMFwiK2g7XG5cdCAgICAgICAgci5wdXNoKFwiIFwiK2gpO1xuXHQgICAgICAgIGkrKztcblx0ICAgICAgICBpZiAoaSAlIDMyID09IDApXG5cdCAgICAgICAgXHRyLnB1c2goXCJcXG4gICAgICAgICAgIFwiKTtcblx0ICAgIH1cblx0ICAgIHJldHVybiByLmpvaW4oJycpO1xuXHR9O1xuXHRcblx0LyoqXG5cdCAqIENyZWF0ZSBoZXhzdHJpbmcgZnJvbSBhIGJpbmFyeVxuXHQgKiBAcGFyYW0ge1N0cmluZ30gc3RyIFN0cmluZyB0byBjb252ZXJ0XG5cdCAqIEByZXR1cm4ge1N0cmluZ30gU3RyaW5nIGNvbnRhaW5pbmcgdGhlIGhleGFkZWNpbWFsIHZhbHVlc1xuXHQgKi9cblx0dGhpcy5oZXhzdHJkdW1wID0gZnVuY3Rpb24oc3RyKSB7XG5cdFx0aWYgKHN0ciA9PSBudWxsKVxuXHRcdFx0cmV0dXJuIFwiXCI7XG5cdCAgICB2YXIgcj1bXTtcblx0ICAgIHZhciBlPXN0ci5sZW5ndGg7XG5cdCAgICB2YXIgYz0wO1xuXHQgICAgdmFyIGg7XG5cdCAgICB3aGlsZShjPGUpe1xuXHQgICAgICAgIGg9c3RyW2MrK10uY2hhckNvZGVBdCgpLnRvU3RyaW5nKDE2KTtcblx0ICAgICAgICB3aGlsZShoLmxlbmd0aDwyKSBoPVwiMFwiK2g7XG5cdCAgICAgICAgci5wdXNoKFwiXCIraCk7XG5cdCAgICB9XG5cdCAgICByZXR1cm4gci5qb2luKCcnKTtcblx0fTtcblx0XG5cdC8qKlxuXHQgKiBDcmVhdGUgYmluYXJ5IHN0cmluZyBmcm9tIGEgaGV4IGVuY29kZWQgc3RyaW5nXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBzdHIgSGV4IHN0cmluZyB0byBjb252ZXJ0XG5cdCAqIEByZXR1cm4ge1N0cmluZ30gU3RyaW5nIGNvbnRhaW5pbmcgdGhlIGJpbmFyeSB2YWx1ZXNcblx0ICovXG5cdHRoaXMuaGV4MmJpbiA9IGZ1bmN0aW9uKGhleCkge1xuXHQgICAgdmFyIHN0ciA9ICcnO1xuXHQgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBoZXgubGVuZ3RoOyBpICs9IDIpXG5cdCAgICAgICAgc3RyICs9IFN0cmluZy5mcm9tQ2hhckNvZGUocGFyc2VJbnQoaGV4LnN1YnN0cihpLCAyKSwgMTYpKTtcblx0ICAgIHJldHVybiBzdHI7XG5cdH07XG5cdFxuXHQvKipcblx0ICogQ3JlYXRpbmcgYSBoZXggc3RyaW5nIGZyb20gYW4gYmluYXJ5IGFycmF5IG9mIGludGVnZXJzICgwLi4yNTUpXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBzdHIgQXJyYXkgb2YgYnl0ZXMgdG8gY29udmVydFxuXHQgKiBAcmV0dXJuIHtTdHJpbmd9IEhleGFkZWNpbWFsIHJlcHJlc2VudGF0aW9uIG9mIHRoZSBhcnJheVxuXHQgKi9cblx0dGhpcy5oZXhpZHVtcCA9IGZ1bmN0aW9uKHN0cikge1xuXHQgICAgdmFyIHI9W107XG5cdCAgICB2YXIgZT1zdHIubGVuZ3RoO1xuXHQgICAgdmFyIGM9MDtcblx0ICAgIHZhciBoO1xuXHQgICAgd2hpbGUoYzxlKXtcblx0ICAgICAgICBoPXN0cltjKytdLnRvU3RyaW5nKDE2KTtcblx0ICAgICAgICB3aGlsZShoLmxlbmd0aDwyKSBoPVwiMFwiK2g7XG5cdCAgICAgICAgci5wdXNoKFwiXCIraCk7XG5cdCAgICB9XG5cdCAgICByZXR1cm4gci5qb2luKCcnKTtcblx0fTtcblxuXG5cdC8qKlxuXHQgKiBDb252ZXJ0IGEgbmF0aXZlIGphdmFzY3JpcHQgc3RyaW5nIHRvIGEgc3RyaW5nIG9mIHV0ZjggYnl0ZXNcblx0ICogQHBhcmFtIHtTdHJpbmd9IHN0ciBUaGUgc3RyaW5nIHRvIGNvbnZlcnRcblx0ICogQHJldHVybiB7U3RyaW5nfSBBIHZhbGlkIHNxdWVuY2Ugb2YgdXRmOCBieXRlc1xuXHQgKi9cblx0dGhpcy5lbmNvZGVfdXRmOCA9IGZ1bmN0aW9uKHN0cikge1xuXHRcdHJldHVybiB1bmVzY2FwZShlbmNvZGVVUklDb21wb25lbnQoc3RyKSk7XG5cdH07XG5cblx0LyoqXG5cdCAqIENvbnZlcnQgYSBzdHJpbmcgb2YgdXRmOCBieXRlcyB0byBhIG5hdGl2ZSBqYXZhc2NyaXB0IHN0cmluZ1xuXHQgKiBAcGFyYW0ge1N0cmluZ30gdXRmOCBBIHZhbGlkIHNxdWVuY2Ugb2YgdXRmOCBieXRlc1xuXHQgKiBAcmV0dXJuIHtTdHJpbmd9IEEgbmF0aXZlIGphdmFzY3JpcHQgc3RyaW5nXG5cdCAqL1xuXHR0aGlzLmRlY29kZV91dGY4ID0gZnVuY3Rpb24odXRmOCkge1xuXHRcdHJldHVybiBkZWNvZGVVUklDb21wb25lbnQoZXNjYXBlKHV0ZjgpKTtcblx0fTtcblxuXHR2YXIgc3RyMmJpbiA9IGZ1bmN0aW9uKHN0ciwgcmVzdWx0KSB7XG5cdFx0Zm9yICh2YXIgaSA9IDA7IGkgPCBzdHIubGVuZ3RoOyBpKyspIHtcblx0XHRcdHJlc3VsdFtpXSA9IHN0ci5jaGFyQ29kZUF0KGkpO1xuXHRcdH1cblxuXHRcdHJldHVybiByZXN1bHQ7XG5cdH07XG5cdFxuXHR2YXIgYmluMnN0ciA9IGZ1bmN0aW9uKGJpbikge1xuXHRcdHZhciByZXN1bHQgPSBbXTtcblxuXHRcdGZvciAodmFyIGkgPSAwOyBpIDwgYmluLmxlbmd0aDsgaSsrKSB7XG5cdFx0XHRyZXN1bHQucHVzaChTdHJpbmcuZnJvbUNoYXJDb2RlKGJpbltpXSkpO1xuXHRcdH1cblxuXHRcdHJldHVybiByZXN1bHQuam9pbignJyk7XG5cdH07XG5cblx0LyoqXG5cdCAqIENvbnZlcnQgYSBzdHJpbmcgdG8gYW4gYXJyYXkgb2YgaW50ZWdlcnMoMC4yNTUpXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBzdHIgU3RyaW5nIHRvIGNvbnZlcnRcblx0ICogQHJldHVybiB7SW50ZWdlcltdfSBBbiBhcnJheSBvZiAoYmluYXJ5KSBpbnRlZ2Vyc1xuXHQgKi9cblx0dGhpcy5zdHIyYmluID0gZnVuY3Rpb24oc3RyKSB7IFxuXHRcdHJldHVybiBzdHIyYmluKHN0ciwgbmV3IEFycmF5KHN0ci5sZW5ndGgpKTtcblx0fTtcblx0XG5cdFxuXHQvKipcblx0ICogQ29udmVydCBhbiBhcnJheSBvZiBpbnRlZ2VycygwLjI1NSkgdG8gYSBzdHJpbmcgXG5cdCAqIEBwYXJhbSB7SW50ZWdlcltdfSBiaW4gQW4gYXJyYXkgb2YgKGJpbmFyeSkgaW50ZWdlcnMgdG8gY29udmVydFxuXHQgKiBAcmV0dXJuIHtTdHJpbmd9IFRoZSBzdHJpbmcgcmVwcmVzZW50YXRpb24gb2YgdGhlIGFycmF5XG5cdCAqL1xuXHR0aGlzLmJpbjJzdHIgPSBiaW4yc3RyO1xuXHRcblx0LyoqXG5cdCAqIENvbnZlcnQgYSBzdHJpbmcgdG8gYSBVaW50OEFycmF5XG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBzdHIgU3RyaW5nIHRvIGNvbnZlcnRcblx0ICogQHJldHVybiB7VWludDhBcnJheX0gVGhlIGFycmF5IG9mIChiaW5hcnkpIGludGVnZXJzXG5cdCAqL1xuXHR0aGlzLnN0cjJVaW50OEFycmF5ID0gZnVuY3Rpb24oc3RyKSB7IFxuXHRcdHJldHVybiBzdHIyYmluKHN0ciwgbmV3IFVpbnQ4QXJyYXkobmV3IEFycmF5QnVmZmVyKHN0ci5sZW5ndGgpKSk7IFxuXHR9O1xuXHRcblx0LyoqXG5cdCAqIENvbnZlcnQgYSBVaW50OEFycmF5IHRvIGEgc3RyaW5nLiBUaGlzIGN1cnJlbnRseSBmdW5jdGlvbnMgXG5cdCAqIHRoZSBzYW1lIGFzIGJpbjJzdHIuIFxuXHQgKiBAcGFyYW0ge1VpbnQ4QXJyYXl9IGJpbiBBbiBhcnJheSBvZiAoYmluYXJ5KSBpbnRlZ2VycyB0byBjb252ZXJ0XG5cdCAqIEByZXR1cm4ge1N0cmluZ30gU3RyaW5nIHJlcHJlc2VudGF0aW9uIG9mIHRoZSBhcnJheVxuXHQgKi9cblx0dGhpcy5VaW50OEFycmF5MnN0ciA9IGJpbjJzdHI7XG5cdFxuXHQvKipcblx0ICogQ2FsY3VsYXRlcyBhIDE2Yml0IHN1bSBvZiBhIHN0cmluZyBieSBhZGRpbmcgZWFjaCBjaGFyYWN0ZXIgXG5cdCAqIGNvZGVzIG1vZHVsdXMgNjU1MzVcblx0ICogQHBhcmFtIHtTdHJpbmd9IHRleHQgU3RyaW5nIHRvIGNyZWF0ZSBhIHN1bSBvZlxuXHQgKiBAcmV0dXJuIHtJbnRlZ2VyfSBBbiBpbnRlZ2VyIGNvbnRhaW5pbmcgdGhlIHN1bSBvZiBhbGwgY2hhcmFjdGVyIFxuXHQgKiBjb2RlcyAlIDY1NTM1XG5cdCAqL1xuXHR0aGlzLmNhbGNfY2hlY2tzdW0gPSBmdW5jdGlvbih0ZXh0KSB7XG5cdFx0dmFyIGNoZWNrc3VtID0geyAgczogMCwgYWRkOiBmdW5jdGlvbiAoc2FkZCkgeyB0aGlzLnMgPSAodGhpcy5zICsgc2FkZCkgJSA2NTUzNjsgfX07XG5cdFx0Zm9yICh2YXIgaSA9IDA7IGkgPCB0ZXh0Lmxlbmd0aDsgaSsrKSB7XG5cdFx0XHRjaGVja3N1bS5hZGQodGV4dC5jaGFyQ29kZUF0KGkpKTtcblx0XHR9XG5cdFx0cmV0dXJuIGNoZWNrc3VtLnM7XG5cdH07XG5cdFxuXHQvKipcblx0ICogSGVscGVyIGZ1bmN0aW9uIHRvIHByaW50IGEgZGVidWcgbWVzc2FnZS4gRGVidWcgXG5cdCAqIG1lc3NhZ2VzIGFyZSBvbmx5IHByaW50ZWQgaWZcblx0ICogb3BlbnBncC5jb25maWcuZGVidWcgaXMgc2V0IHRvIHRydWUuIFRoZSBjYWxsaW5nXG5cdCAqIEphdmFzY3JpcHQgY29udGV4dCBNVVNUIGRlZmluZVxuXHQgKiBhIFwic2hvd01lc3NhZ2VzKHRleHQpXCIgZnVuY3Rpb24uIExpbmUgZmVlZHMgKCdcXG4nKVxuXHQgKiBhcmUgYXV0b21hdGljYWxseSBjb252ZXJ0ZWQgdG8gSFRNTCBsaW5lIGZlZWRzICc8YnIvPidcblx0ICogQHBhcmFtIHtTdHJpbmd9IHN0ciBTdHJpbmcgb2YgdGhlIGRlYnVnIG1lc3NhZ2Vcblx0ICogQHJldHVybiB7U3RyaW5nfSBBbiBIVE1MIHR0IGVudGl0eSBjb250YWluaW5nIGEgcGFyYWdyYXBoIHdpdGggYSBcblx0ICogc3R5bGUgYXR0cmlidXRlIHdoZXJlIHRoZSBkZWJ1ZyBtZXNzYWdlIGlzIEhUTUxlbmNvZGVkIGluLiBcblx0ICovXG5cdHRoaXMucHJpbnRfZGVidWcgPSBmdW5jdGlvbihzdHIpIHtcblx0XHRpZiAodGhpcy5kZWJ1Zykge1xuXHRcdFx0Y29uc29sZS5sb2coc3RyKTtcblx0XHR9XG5cdH07XG5cdFxuXHQvKipcblx0ICogSGVscGVyIGZ1bmN0aW9uIHRvIHByaW50IGEgZGVidWcgbWVzc2FnZS4gRGVidWcgXG5cdCAqIG1lc3NhZ2VzIGFyZSBvbmx5IHByaW50ZWQgaWZcblx0ICogb3BlbnBncC5jb25maWcuZGVidWcgaXMgc2V0IHRvIHRydWUuIFRoZSBjYWxsaW5nXG5cdCAqIEphdmFzY3JpcHQgY29udGV4dCBNVVNUIGRlZmluZVxuXHQgKiBhIFwic2hvd01lc3NhZ2VzKHRleHQpXCIgZnVuY3Rpb24uIExpbmUgZmVlZHMgKCdcXG4nKVxuXHQgKiBhcmUgYXV0b21hdGljYWxseSBjb252ZXJ0ZWQgdG8gSFRNTCBsaW5lIGZlZWRzICc8YnIvPidcblx0ICogRGlmZmVyZW50IHRoYW4gcHJpbnRfZGVidWcgYmVjYXVzZSB3aWxsIGNhbGwgaGV4c3RyZHVtcCBpZmYgbmVjZXNzYXJ5LlxuXHQgKiBAcGFyYW0ge1N0cmluZ30gc3RyIFN0cmluZyBvZiB0aGUgZGVidWcgbWVzc2FnZVxuXHQgKiBAcmV0dXJuIHtTdHJpbmd9IEFuIEhUTUwgdHQgZW50aXR5IGNvbnRhaW5pbmcgYSBwYXJhZ3JhcGggd2l0aCBhIFxuXHQgKiBzdHlsZSBhdHRyaWJ1dGUgd2hlcmUgdGhlIGRlYnVnIG1lc3NhZ2UgaXMgSFRNTGVuY29kZWQgaW4uIFxuXHQgKi9cblx0dGhpcy5wcmludF9kZWJ1Z19oZXhzdHJfZHVtcCA9IGZ1bmN0aW9uKHN0cixzdHJUb0hleCkge1xuXHRcdGlmICh0aGlzLmRlYnVnKSB7XG5cdFx0XHRzdHIgPSBzdHIgKyB0aGlzLmhleHN0cmR1bXAoc3RyVG9IZXgpO1xuXHRcdFx0Y29uc29sZS5sb2coc3RyKTtcblx0XHR9XG5cdH07XG5cdFxuXHQvKipcblx0ICogSGVscGVyIGZ1bmN0aW9uIHRvIHByaW50IGFuIGVycm9yIG1lc3NhZ2UuIFxuXHQgKiBUaGUgY2FsbGluZyBKYXZhc2NyaXB0IGNvbnRleHQgTVVTVCBkZWZpbmVcblx0ICogYSBcInNob3dNZXNzYWdlcyh0ZXh0KVwiIGZ1bmN0aW9uLiBMaW5lIGZlZWRzICgnXFxuJylcblx0ICogYXJlIGF1dG9tYXRpY2FsbHkgY29udmVydGVkIHRvIEhUTUwgbGluZSBmZWVkcyAnPGJyLz4nXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBzdHIgU3RyaW5nIG9mIHRoZSBlcnJvciBtZXNzYWdlXG5cdCAqIEByZXR1cm4ge1N0cmluZ30gQSBIVE1MIHBhcmFncmFwaCBlbnRpdHkgd2l0aCBhIHN0eWxlIGF0dHJpYnV0ZSBcblx0ICogY29udGFpbmluZyB0aGUgSFRNTCBlbmNvZGVkIGVycm9yIG1lc3NhZ2Vcblx0ICovXG5cdHRoaXMucHJpbnRfZXJyb3IgPSBmdW5jdGlvbihzdHIpIHtcblx0XHRpZih0aGlzLmRlYnVnKVxuXHRcdFx0dGhyb3cgc3RyO1xuXHRcdGNvbnNvbGUubG9nKHN0cik7XG5cdH07XG5cdFxuXHQvKipcblx0ICogSGVscGVyIGZ1bmN0aW9uIHRvIHByaW50IGFuIGluZm8gbWVzc2FnZS4gXG5cdCAqIFRoZSBjYWxsaW5nIEphdmFzY3JpcHQgY29udGV4dCBNVVNUIGRlZmluZVxuXHQgKiBhIFwic2hvd01lc3NhZ2VzKHRleHQpXCIgZnVuY3Rpb24uIExpbmUgZmVlZHMgKCdcXG4nKVxuXHQgKiBhcmUgYXV0b21hdGljYWxseSBjb252ZXJ0ZWQgdG8gSFRNTCBsaW5lIGZlZWRzICc8YnIvPicuXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBzdHIgU3RyaW5nIG9mIHRoZSBpbmZvIG1lc3NhZ2Vcblx0ICogQHJldHVybiB7U3RyaW5nfSBBIEhUTUwgcGFyYWdyYXBoIGVudGl0eSB3aXRoIGEgc3R5bGUgYXR0cmlidXRlIFxuXHQgKiBjb250YWluaW5nIHRoZSBIVE1MIGVuY29kZWQgaW5mbyBtZXNzYWdlXG5cdCAqL1xuXHR0aGlzLnByaW50X2luZm8gPSBmdW5jdGlvbihzdHIpIHtcblx0XHRpZih0aGlzLmRlYnVnKVxuXHRcdFx0Y29uc29sZS5sb2coc3RyKTtcblx0fTtcblx0XG5cdHRoaXMucHJpbnRfd2FybmluZyA9IGZ1bmN0aW9uKHN0cikge1xuXHRcdGNvbnNvbGUubG9nKHN0cik7XG5cdH07XG5cdFxuXHR0aGlzLmdldExlZnROQml0cyA9IGZ1bmN0aW9uIChzdHJpbmcsIGJpdGNvdW50KSB7XG5cdFx0dmFyIHJlc3QgPSBiaXRjb3VudCAlIDg7XG5cdFx0aWYgKHJlc3QgPT0gMClcblx0XHRcdHJldHVybiBzdHJpbmcuc3Vic3RyaW5nKDAsIGJpdGNvdW50IC8gOCk7XG5cdFx0dmFyIGJ5dGVzID0gKGJpdGNvdW50IC0gcmVzdCkgLyA4ICsxO1xuXHRcdHZhciByZXN1bHQgPSBzdHJpbmcuc3Vic3RyaW5nKDAsIGJ5dGVzKTtcblx0XHRyZXR1cm4gdGhpcy5zaGlmdFJpZ2h0KHJlc3VsdCwgOC1yZXN0KTsgLy8gK1N0cmluZy5mcm9tQ2hhckNvZGUoc3RyaW5nLmNoYXJDb2RlQXQoYnl0ZXMgLTEpIDw8ICg4LXJlc3QpICYgMHhGRik7XG5cdH07XG5cblx0LyoqXG5cdCAqIFNoaWZ0aW5nIGEgc3RyaW5nIHRvIG4gYml0cyByaWdodFxuXHQgKiBAcGFyYW0ge1N0cmluZ30gdmFsdWUgVGhlIHN0cmluZyB0byBzaGlmdFxuXHQgKiBAcGFyYW0ge0ludGVnZXJ9IGJpdGNvdW50IEFtb3VudCBvZiBiaXRzIHRvIHNoaWZ0IChNVVNUIGJlIHNtYWxsZXIgXG5cdCAqIHRoYW4gOSlcblx0ICogQHJldHVybiB7U3RyaW5nfSBSZXN1bHRpbmcgc3RyaW5nLiBcblx0ICovXG5cdHRoaXMuc2hpZnRSaWdodCA9IGZ1bmN0aW9uKHZhbHVlLCBiaXRjb3VudCkge1xuXHRcdHZhciB0ZW1wID0gdXRpbC5zdHIyYmluKHZhbHVlKTtcbiAgICAgICAgaWYgKGJpdGNvdW50ICUgOCAhPSAwKSB7XG4gICAgICAgIFx0Zm9yICh2YXIgaSA9IHRlbXAubGVuZ3RoLTE7IGkgPj0gMDsgaS0tKSB7XG4gICAgICAgIFx0XHR0ZW1wW2ldID4+PSBiaXRjb3VudCAlIDg7XG4gICAgICAgIFx0XHRpZiAoaSA+IDApXG4gICAgICAgIFx0XHRcdHRlbXBbaV0gfD0gKHRlbXBbaSAtIDFdIDw8ICg4IC0gKGJpdGNvdW50ICUgOCkpKSAmIDB4RkY7XG4gICAgICAgIFx0fVxuICAgICAgICB9IGVsc2Uge1xuICAgICAgICBcdHJldHVybiB2YWx1ZTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gdXRpbC5iaW4yc3RyKHRlbXApO1xuXHR9O1xuXHRcblx0LyoqXG5cdCAqIFJldHVybiB0aGUgYWxnb3JpdGhtIHR5cGUgYXMgc3RyaW5nXG5cdCAqIEByZXR1cm4ge1N0cmluZ30gU3RyaW5nIHJlcHJlc2VudGluZyB0aGUgbWVzc2FnZSB0eXBlXG5cdCAqL1xuXHR0aGlzLmdldF9oYXNoQWxnb3JpdGhtU3RyaW5nID0gZnVuY3Rpb24oYWxnbykge1xuXHRcdHN3aXRjaChhbGdvKSB7XG5cdFx0Y2FzZSAxOlxuXHRcdFx0cmV0dXJuIFwiTUQ1XCI7XG5cdFx0Y2FzZSAyOlxuXHRcdFx0cmV0dXJuIFwiU0hBMVwiO1xuXHRcdGNhc2UgMzpcblx0XHRcdHJldHVybiBcIlJJUEVNRDE2MFwiO1xuXHRcdGNhc2UgODpcblx0XHRcdHJldHVybiBcIlNIQTI1NlwiO1xuXHRcdGNhc2UgOTpcblx0XHRcdHJldHVybiBcIlNIQTM4NFwiO1xuXHRcdGNhc2UgMTA6XG5cdFx0XHRyZXR1cm4gXCJTSEE1MTJcIjtcblx0XHRjYXNlIDExOlxuXHRcdFx0cmV0dXJuIFwiU0hBMjI0XCI7XG5cdFx0fVxuXHRcdHJldHVybiBcInVua25vd25cIjtcblx0fTtcbn07XG5cbi8qKlxuICogYW4gaW5zdGFuY2UgdGhhdCBzaG91bGQgYmUgdXNlZC4gXG4gKi9cbm1vZHVsZS5leHBvcnRzID0gbmV3IFV0aWwoKTtcbiIsIi8vIEdQRzRCcm93c2VycyAtIEFuIE9wZW5QR1AgaW1wbGVtZW50YXRpb24gaW4gamF2YXNjcmlwdFxuLy8gQ29weXJpZ2h0IChDKSAyMDExIFJlY3VyaXR5IExhYnMgR21iSFxuLy9cbi8vIFRoaXMgbGlicmFyeSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3Jcbi8vIG1vZGlmeSBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBMZXNzZXIgR2VuZXJhbCBQdWJsaWNcbi8vIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5IHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlclxuLy8gdmVyc2lvbiAyLjEgb2YgdGhlIExpY2Vuc2UsIG9yIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4vL1xuLy8gVGhpcyBsaWJyYXJ5IGlzIGRpc3RyaWJ1dGVkIGluIHRoZSBob3BlIHRoYXQgaXQgd2lsbCBiZSB1c2VmdWwsXG4vLyBidXQgV0lUSE9VVCBBTlkgV0FSUkFOVFk7IHdpdGhvdXQgZXZlbiB0aGUgaW1wbGllZCB3YXJyYW50eSBvZlxuLy8gTUVSQ0hBTlRBQklMSVRZIG9yIEZJVE5FU1MgRk9SIEEgUEFSVElDVUxBUiBQVVJQT1NFLiAgU2VlIHRoZSBHTlVcbi8vIExlc3NlciBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGZvciBtb3JlIGRldGFpbHMuXG4vL1xuLy8gWW91IHNob3VsZCBoYXZlIHJlY2VpdmVkIGEgY29weSBvZiB0aGUgR05VIExlc3NlciBHZW5lcmFsIFB1YmxpY1xuLy8gTGljZW5zZSBhbG9uZyB3aXRoIHRoaXMgbGlicmFyeTsgaWYgbm90LCB3cml0ZSB0byB0aGUgRnJlZSBTb2Z0d2FyZVxuLy8gRm91bmRhdGlvbiwgSW5jLiwgNTEgRnJhbmtsaW4gU3RyZWV0LCBGaWZ0aCBGbG9vciwgQm9zdG9uLCBNQSAgMDIxMTAtMTMwMSAgVVNBXG5cbnZhciBiYXNlNjQgPSByZXF1aXJlKCcuL2Jhc2U2NC5qcycpO1xuXG5cblxuLyoqXG4gKiBGaW5kcyBvdXQgd2hpY2ggQXNjaWkgQXJtb3JpbmcgdHlwZSBpcyB1c2VkLiBUaGlzIGlzIGFuIGludGVybmFsIGZ1bmN0aW9uXG4gKiBAcGFyYW0ge1N0cmluZ30gdGV4dCBbU3RyaW5nXSBhc2NpaSBhcm1vcmVkIHRleHRcbiAqIEByZXR1cm5zIHtJbnRlZ2VyfSAwID0gTUVTU0FHRSBQQVJUIG4gb2YgbVxuICogICAgICAgICAxID0gTUVTU0FHRSBQQVJUIG5cbiAqICAgICAgICAgMiA9IFNJR05FRCBNRVNTQUdFXG4gKiAgICAgICAgIDMgPSBQR1AgTUVTU0FHRVxuICogICAgICAgICA0ID0gUFVCTElDIEtFWSBCTE9DS1xuICogICAgICAgICA1ID0gUFJJVkFURSBLRVkgQkxPQ0tcbiAqICAgICAgICAgbnVsbCA9IHVua25vd25cbiAqL1xuZnVuY3Rpb24gZ2V0X3R5cGUodGV4dCkge1xuXHR2YXIgc3BsaXR0ZWR0ZXh0ID0gdGV4dC5zcGxpdCgnLS0tLS0nKTtcblx0Ly8gQkVHSU4gUEdQIE1FU1NBR0UsIFBBUlQgWC9ZXG5cdC8vIFVzZWQgZm9yIG11bHRpLXBhcnQgbWVzc2FnZXMsIHdoZXJlIHRoZSBhcm1vciBpcyBzcGxpdCBhbW9uZ3N0IFlcblx0Ly8gcGFydHMsIGFuZCB0aGlzIGlzIHRoZSBYdGggcGFydCBvdXQgb2YgWS5cblx0aWYgKHNwbGl0dGVkdGV4dFsxXS5tYXRjaCgvQkVHSU4gUEdQIE1FU1NBR0UsIFBBUlQgXFxkK1xcL1xcZCsvKSkge1xuXHRcdHJldHVybiAwO1xuXHR9IGVsc2Vcblx0XHQvLyBCRUdJTiBQR1AgTUVTU0FHRSwgUEFSVCBYXG5cdFx0Ly8gVXNlZCBmb3IgbXVsdGktcGFydCBtZXNzYWdlcywgd2hlcmUgdGhpcyBpcyB0aGUgWHRoIHBhcnQgb2YgYW5cblx0XHQvLyB1bnNwZWNpZmllZCBudW1iZXIgb2YgcGFydHMuIFJlcXVpcmVzIHRoZSBNRVNTQUdFLUlEIEFybW9yXG5cdFx0Ly8gSGVhZGVyIHRvIGJlIHVzZWQuXG5cdGlmIChzcGxpdHRlZHRleHRbMV0ubWF0Y2goL0JFR0lOIFBHUCBNRVNTQUdFLCBQQVJUIFxcZCsvKSkge1xuXHRcdHJldHVybiAxO1xuXG5cdH0gZWxzZVxuXHRcdC8vIEJFR0lOIFBHUCBTSUdOQVRVUkVcblx0XHQvLyBVc2VkIGZvciBkZXRhY2hlZCBzaWduYXR1cmVzLCBPcGVuUEdQL01JTUUgc2lnbmF0dXJlcywgYW5kXG5cdFx0Ly8gY2xlYXJ0ZXh0IHNpZ25hdHVyZXMuIE5vdGUgdGhhdCBQR1AgMi54IHVzZXMgQkVHSU4gUEdQIE1FU1NBR0Vcblx0XHQvLyBmb3IgZGV0YWNoZWQgc2lnbmF0dXJlcy5cblx0aWYgKHNwbGl0dGVkdGV4dFsxXS5tYXRjaCgvQkVHSU4gUEdQIFNJR05FRCBNRVNTQUdFLykpIHtcblx0XHRyZXR1cm4gMjtcblxuXHR9IGVsc2VcbiAgXHQgICAgLy8gQkVHSU4gUEdQIE1FU1NBR0Vcblx0ICAgIC8vIFVzZWQgZm9yIHNpZ25lZCwgZW5jcnlwdGVkLCBvciBjb21wcmVzc2VkIGZpbGVzLlxuXHRpZiAoc3BsaXR0ZWR0ZXh0WzFdLm1hdGNoKC9CRUdJTiBQR1AgTUVTU0FHRS8pKSB7XG5cdFx0cmV0dXJuIDM7XG5cblx0fSBlbHNlXG5cdFx0Ly8gQkVHSU4gUEdQIFBVQkxJQyBLRVkgQkxPQ0tcblx0XHQvLyBVc2VkIGZvciBhcm1vcmluZyBwdWJsaWMga2V5cy5cblx0aWYgKHNwbGl0dGVkdGV4dFsxXS5tYXRjaCgvQkVHSU4gUEdQIFBVQkxJQyBLRVkgQkxPQ0svKSkge1xuXHRcdHJldHVybiA0O1xuXG5cdH0gZWxzZVxuXHRcdC8vIEJFR0lOIFBHUCBQUklWQVRFIEtFWSBCTE9DS1xuXHRcdC8vIFVzZWQgZm9yIGFybW9yaW5nIHByaXZhdGUga2V5cy5cblx0aWYgKHNwbGl0dGVkdGV4dFsxXS5tYXRjaCgvQkVHSU4gUEdQIFBSSVZBVEUgS0VZIEJMT0NLLykpIHtcblx0XHRyZXR1cm4gNTtcblx0fVxufVxuXG4vKipcbiAqIEFkZCBhZGRpdGlvbmFsIGluZm9ybWF0aW9uIHRvIHRoZSBhcm1vciB2ZXJzaW9uIG9mIGFuIE9wZW5QR1AgYmluYXJ5XG4gKiBwYWNrZXQgYmxvY2suXG4gKiBAYXV0aG9yICBBbGV4XG4gKiBAdmVyc2lvbiAyMDExLTEyLTE2XG4gKiBAcmV0dXJucyB7U3RyaW5nfSBUaGUgaGVhZGVyIGluZm9ybWF0aW9uXG4gKi9cbmZ1bmN0aW9uIGFybW9yX2FkZGhlYWRlcigpIHtcbiAgICB2YXIgcmVzdWx0ID0gXCJcIjtcblx0aWYgKG9wZW5wZ3AuY29uZmlnLmNvbmZpZy5zaG93X3ZlcnNpb24pIHtcbiAgICAgICAgcmVzdWx0ICs9IFwiVmVyc2lvbjogXCIrb3BlbnBncC5jb25maWcudmVyc2lvbnN0cmluZysnXFxyXFxuJztcbiAgICB9XG5cdGlmIChvcGVucGdwLmNvbmZpZy5jb25maWcuc2hvd19jb21tZW50KSB7XG4gICAgICAgIHJlc3VsdCArPSBcIkNvbW1lbnQ6IFwiK29wZW5wZ3AuY29uZmlnLmNvbW1lbnRzdHJpbmcrJ1xcclxcbic7XG4gICAgfVxuICAgIHJlc3VsdCArPSAnXFxyXFxuJztcbiAgICByZXR1cm4gcmVzdWx0O1xufVxuXG5cblxuLyoqXG4gKiBDYWxjdWxhdGVzIGEgY2hlY2tzdW0gb3ZlciB0aGUgZ2l2ZW4gZGF0YSBhbmQgcmV0dXJucyBpdCBiYXNlNjQgZW5jb2RlZFxuICogQHBhcmFtIHtTdHJpbmd9IGRhdGEgRGF0YSB0byBjcmVhdGUgYSBDUkMtMjQgY2hlY2tzdW0gZm9yXG4gKiBAcmV0dXJuIHtTdHJpbmd9IEJhc2U2NCBlbmNvZGVkIGNoZWNrc3VtXG4gKi9cbmZ1bmN0aW9uIGdldENoZWNrU3VtKGRhdGEpIHtcblx0dmFyIGMgPSBjcmVhdGVjcmMyNChkYXRhKTtcblx0dmFyIHN0ciA9IFwiXCIgKyBTdHJpbmcuZnJvbUNoYXJDb2RlKGMgPj4gMTYpK1xuXHRcdFx0XHQgICBTdHJpbmcuZnJvbUNoYXJDb2RlKChjID4+IDgpICYgMHhGRikrXG5cdFx0XHRcdCAgIFN0cmluZy5mcm9tQ2hhckNvZGUoYyAmIDB4RkYpO1xuXHRyZXR1cm4gYmFzZTY0X2VuY29kZShzdHIpO1xufVxuXG4vKipcbiAqIENhbGN1bGF0ZXMgdGhlIGNoZWNrc3VtIG92ZXIgdGhlIGdpdmVuIGRhdGEgYW5kIGNvbXBhcmVzIGl0IHdpdGggdGhlIFxuICogZ2l2ZW4gYmFzZTY0IGVuY29kZWQgY2hlY2tzdW1cbiAqIEBwYXJhbSB7U3RyaW5nfSBkYXRhIERhdGEgdG8gY3JlYXRlIGEgQ1JDLTI0IGNoZWNrc3VtIGZvclxuICogQHBhcmFtIHtTdHJpbmd9IGNoZWNrc3VtIEJhc2U2NCBlbmNvZGVkIGNoZWNrc3VtXG4gKiBAcmV0dXJuIHtCb29sZWFufSBUcnVlIGlmIHRoZSBnaXZlbiBjaGVja3N1bSBpcyBjb3JyZWN0OyBvdGhlcndpc2UgZmFsc2VcbiAqL1xuZnVuY3Rpb24gdmVyaWZ5Q2hlY2tTdW0oZGF0YSwgY2hlY2tzdW0pIHtcblx0dmFyIGMgPSBnZXRDaGVja1N1bShkYXRhKTtcblx0dmFyIGQgPSBjaGVja3N1bTtcblx0cmV0dXJuIGNbMF0gPT0gZFswXSAmJiBjWzFdID09IGRbMV0gJiYgY1syXSA9PSBkWzJdO1xufVxuLyoqXG4gKiBJbnRlcm5hbCBmdW5jdGlvbiB0byBjYWxjdWxhdGUgYSBDUkMtMjQgY2hlY2tzdW0gb3ZlciBhIGdpdmVuIHN0cmluZyAoZGF0YSlcbiAqIEBwYXJhbSB7U3RyaW5nfSBkYXRhIERhdGEgdG8gY3JlYXRlIGEgQ1JDLTI0IGNoZWNrc3VtIGZvclxuICogQHJldHVybiB7SW50ZWdlcn0gVGhlIENSQy0yNCBjaGVja3N1bSBhcyBudW1iZXJcbiAqL1xudmFyIGNyY190YWJsZSA9IFtcbjB4MDAwMDAwMDAsIDB4MDA4NjRjZmIsIDB4MDE4YWQ1MGQsIDB4MDEwYzk5ZjYsIDB4MDM5M2U2ZTEsIDB4MDMxNWFhMWEsIDB4MDIxOTMzZWMsIDB4MDI5ZjdmMTcsIDB4MDdhMTgxMzksIDB4MDcyN2NkYzIsIDB4MDYyYjU0MzQsIDB4MDZhZDE4Y2YsIDB4MDQzMjY3ZDgsIDB4MDRiNDJiMjMsIDB4MDViOGIyZDUsIDB4MDUzZWZlMmUsIDB4MGZjNTRlODksIDB4MGY0MzAyNzIsIDB4MGU0ZjliODQsIDB4MGVjOWQ3N2YsIDB4MGM1NmE4NjgsIDB4MGNkMGU0OTMsIDB4MGRkYzdkNjUsIDB4MGQ1YTMxOWUsIDB4MDg2NGNmYjAsIDB4MDhlMjgzNGIsIDB4MDllZTFhYmQsIDB4MDk2ODU2NDYsIDB4MGJmNzI5NTEsIDB4MGI3MTY1YWEsIDB4MGE3ZGZjNWMsIDB4MGFmYmIwYTcsIDB4MWYwY2QxZTksIDB4MWY4YTlkMTIsIDB4MWU4NjA0ZTQsIDB4MWUwMDQ4MWYsIDB4MWM5ZjM3MDgsIDB4MWMxOTdiZjMsIDB4MWQxNWUyMDUsIDB4MWQ5M2FlZmUsIDB4MThhZDUwZDAsIDB4MTgyYjFjMmIsIDB4MTkyNzg1ZGQsIDB4MTlhMWM5MjYsIDB4MWIzZWI2MzEsIDB4MWJiOGZhY2EsIDB4MWFiNDYzM2MsIDB4MWEzMjJmYzcsIDB4MTBjOTlmNjAsIDB4MTA0ZmQzOWIsIDB4MTE0MzRhNmQsIDB4MTFjNTA2OTYsIDB4MTM1YTc5ODEsIDB4MTNkYzM1N2EsIDB4MTJkMGFjOGMsIDB4MTI1NmUwNzcsIDB4MTc2ODFlNTksIDB4MTdlZTUyYTIsIDB4MTZlMmNiNTQsIDB4MTY2NDg3YWYsIDB4MTRmYmY4YjgsIDB4MTQ3ZGI0NDMsIDB4MTU3MTJkYjUsIDB4MTVmNzYxNGUsIDB4M2UxOWEzZDIsIDB4M2U5ZmVmMjksIDB4M2Y5Mzc2ZGYsIDB4M2YxNTNhMjQsIDB4M2Q4YTQ1MzMsIDB4M2QwYzA5YzgsIDB4M2MwMDkwM2UsIDB4M2M4NmRjYzUsIDB4MzliODIyZWIsIDB4MzkzZTZlMTAsIDB4MzgzMmY3ZTYsIDB4MzhiNGJiMWQsIDB4M2EyYmM0MGEsIDB4M2FhZDg4ZjEsIDB4M2JhMTExMDcsIDB4M2IyNzVkZmMsIDB4MzFkY2VkNWIsIDB4MzE1YWExYTAsXG4weDMwNTYzODU2LCAweDMwZDA3NGFkLCAweDMyNGYwYmJhLCAweDMyYzk0NzQxLCAweDMzYzVkZWI3LCAweDMzNDM5MjRjLCAweDM2N2Q2YzYyLCAweDM2ZmIyMDk5LCAweDM3ZjdiOTZmLCAweDM3NzFmNTk0LCAweDM1ZWU4YTgzLCAweDM1NjhjNjc4LCAweDM0NjQ1ZjhlLCAweDM0ZTIxMzc1LCAweDIxMTU3MjNiLCAweDIxOTMzZWMwLCAweDIwOWZhNzM2LCAweDIwMTllYmNkLCAweDIyODY5NGRhLCAweDIyMDBkODIxLCAweDIzMGM0MWQ3LCAweDIzOGEwZDJjLCAweDI2YjRmMzAyLCAweDI2MzJiZmY5LCAweDI3M2UyNjBmLCAweDI3Yjg2YWY0LCAweDI1MjcxNWUzLCAweDI1YTE1OTE4LCAweDI0YWRjMGVlLCAweDI0MmI4YzE1LCAweDJlZDAzY2IyLCAweDJlNTY3MDQ5LCAweDJmNWFlOWJmLCAweDJmZGNhNTQ0LCAweDJkNDNkYTUzLCAweDJkYzU5NmE4LCAweDJjYzkwZjVlLCAweDJjNGY0M2E1LCAweDI5NzFiZDhiLCAweDI5ZjdmMTcwLCAweDI4ZmI2ODg2LCAweDI4N2QyNDdkLCAweDJhZTI1YjZhLCAweDJhNjQxNzkxLCAweDJiNjg4ZTY3LCAweDJiZWVjMjljLCAweDdjMzM0N2E0LCAweDdjYjUwYjVmLCAweDdkYjk5MmE5LCAweDdkM2ZkZTUyLCAweDdmYTBhMTQ1LCAweDdmMjZlZGJlLCAweDdlMmE3NDQ4LCAweDdlYWMzOGIzLCAweDdiOTJjNjlkLCAweDdiMTQ4YTY2LCAweDdhMTgxMzkwLCAweDdhOWU1ZjZiLCAweDc4MDEyMDdjLCAweDc4ODc2Yzg3LCAweDc5OGJmNTcxLCAweDc5MGRiOThhLCAweDczZjYwOTJkLCAweDczNzA0NWQ2LCAweDcyN2NkYzIwLCAweDcyZmE5MGRiLCAweDcwNjVlZmNjLCAweDcwZTNhMzM3LCAweDcxZWYzYWMxLCAweDcxNjk3NjNhLCAweDc0NTc4ODE0LCAweDc0ZDFjNGVmLCAweDc1ZGQ1ZDE5LCAweDc1NWIxMWUyLCAweDc3YzQ2ZWY1LCAweDc3NDIyMjBlLCAweDc2NGViYmY4LCAweDc2YzhmNzAzLCAweDYzM2Y5NjRkLCAweDYzYjlkYWI2LCAweDYyYjU0MzQwLCAweDYyMzMwZmJiLFxuMHg2MGFjNzBhYywgMHg2MDJhM2M1NywgMHg2MTI2YTVhMSwgMHg2MWEwZTk1YSwgMHg2NDllMTc3NCwgMHg2NDE4NWI4ZiwgMHg2NTE0YzI3OSwgMHg2NTkyOGU4MiwgMHg2NzBkZjE5NSwgMHg2NzhiYmQ2ZSwgMHg2Njg3MjQ5OCwgMHg2NjAxNjg2MywgMHg2Y2ZhZDhjNCwgMHg2YzdjOTQzZiwgMHg2ZDcwMGRjOSwgMHg2ZGY2NDEzMiwgMHg2ZjY5M2UyNSwgMHg2ZmVmNzJkZSwgMHg2ZWUzZWIyOCwgMHg2ZTY1YTdkMywgMHg2YjViNTlmZCwgMHg2YmRkMTUwNiwgMHg2YWQxOGNmMCwgMHg2YTU3YzAwYiwgMHg2OGM4YmYxYywgMHg2ODRlZjNlNywgMHg2OTQyNmExMSwgMHg2OWM0MjZlYSwgMHg0MjJhZTQ3NiwgMHg0MmFjYTg4ZCwgMHg0M2EwMzE3YiwgMHg0MzI2N2Q4MCwgMHg0MWI5MDI5NywgMHg0MTNmNGU2YywgMHg0MDMzZDc5YSwgMHg0MGI1OWI2MSwgMHg0NThiNjU0ZiwgMHg0NTBkMjliNCwgMHg0NDAxYjA0MiwgMHg0NDg3ZmNiOSwgMHg0NjE4ODNhZSwgMHg0NjllY2Y1NSwgMHg0NzkyNTZhMywgMHg0NzE0MWE1OCwgMHg0ZGVmYWFmZiwgMHg0ZDY5ZTYwNCwgMHg0YzY1N2ZmMiwgMHg0Y2UzMzMwOSwgMHg0ZTdjNGMxZSwgMHg0ZWZhMDBlNSwgMHg0ZmY2OTkxMywgMHg0ZjcwZDVlOCwgMHg0YTRlMmJjNiwgMHg0YWM4NjczZCwgMHg0YmM0ZmVjYiwgMHg0YjQyYjIzMCwgMHg0OWRkY2QyNywgMHg0OTViODFkYywgMHg0ODU3MTgyYSwgMHg0OGQxNTRkMSwgMHg1ZDI2MzU5ZiwgMHg1ZGEwNzk2NCwgMHg1Y2FjZTA5MiwgMHg1YzJhYWM2OSwgMHg1ZWI1ZDM3ZSwgMHg1ZTMzOWY4NSwgMHg1ZjNmMDY3MywgMHg1ZmI5NGE4OCwgMHg1YTg3YjRhNiwgMHg1YTAxZjg1ZCwgMHg1YjBkNjFhYiwgMHg1YjhiMmQ1MCwgMHg1OTE0NTI0NywgMHg1OTkyMWViYywgMHg1ODllODc0YSwgMHg1ODE4Y2JiMSwgMHg1MmUzN2IxNiwgMHg1MjY1MzdlZCwgMHg1MzY5YWUxYiwgMHg1M2VmZTJlMCwgMHg1MTcwOWRmNywgMHg1MWY2ZDEwYyxcbjB4NTBmYTQ4ZmEsIDB4NTA3YzA0MDEsIDB4NTU0MmZhMmYsIDB4NTVjNGI2ZDQsIDB4NTRjODJmMjIsIDB4NTQ0ZTYzZDksIDB4NTZkMTFjY2UsIDB4NTY1NzUwMzUsIDB4NTc1YmM5YzMsIDB4NTdkZDg1MzhdO1xuXG5mdW5jdGlvbiBjcmVhdGVjcmMyNChpbnB1dCkge1xuICB2YXIgY3JjID0gMHhCNzA0Q0U7XG4gIHZhciBpbmRleCA9IDA7XG5cbiAgd2hpbGUoKGlucHV0Lmxlbmd0aCAtIGluZGV4KSA+IDE2KSAge1xuICAgY3JjID0gKGNyYyA8PCA4KSBeIGNyY190YWJsZVsoKGNyYyA+PiAxNikgXiBpbnB1dC5jaGFyQ29kZUF0KGluZGV4KSkgJiAweGZmXTtcbiAgIGNyYyA9IChjcmMgPDwgOCkgXiBjcmNfdGFibGVbKChjcmMgPj4gMTYpIF4gaW5wdXQuY2hhckNvZGVBdChpbmRleCsxKSkgJiAweGZmXTtcbiAgIGNyYyA9IChjcmMgPDwgOCkgXiBjcmNfdGFibGVbKChjcmMgPj4gMTYpIF4gaW5wdXQuY2hhckNvZGVBdChpbmRleCsyKSkgJiAweGZmXTtcbiAgIGNyYyA9IChjcmMgPDwgOCkgXiBjcmNfdGFibGVbKChjcmMgPj4gMTYpIF4gaW5wdXQuY2hhckNvZGVBdChpbmRleCszKSkgJiAweGZmXTtcbiAgIGNyYyA9IChjcmMgPDwgOCkgXiBjcmNfdGFibGVbKChjcmMgPj4gMTYpIF4gaW5wdXQuY2hhckNvZGVBdChpbmRleCs0KSkgJiAweGZmXTtcbiAgIGNyYyA9IChjcmMgPDwgOCkgXiBjcmNfdGFibGVbKChjcmMgPj4gMTYpIF4gaW5wdXQuY2hhckNvZGVBdChpbmRleCs1KSkgJiAweGZmXTtcbiAgIGNyYyA9IChjcmMgPDwgOCkgXiBjcmNfdGFibGVbKChjcmMgPj4gMTYpIF4gaW5wdXQuY2hhckNvZGVBdChpbmRleCs2KSkgJiAweGZmXTtcbiAgIGNyYyA9IChjcmMgPDwgOCkgXiBjcmNfdGFibGVbKChjcmMgPj4gMTYpIF4gaW5wdXQuY2hhckNvZGVBdChpbmRleCs3KSkgJiAweGZmXTtcbiAgIGNyYyA9IChjcmMgPDwgOCkgXiBjcmNfdGFibGVbKChjcmMgPj4gMTYpIF4gaW5wdXQuY2hhckNvZGVBdChpbmRleCs4KSkgJiAweGZmXTtcbiAgIGNyYyA9IChjcmMgPDwgOCkgXiBjcmNfdGFibGVbKChjcmMgPj4gMTYpIF4gaW5wdXQuY2hhckNvZGVBdChpbmRleCs5KSkgJiAweGZmXTtcbiAgIGNyYyA9IChjcmMgPDwgOCkgXiBjcmNfdGFibGVbKChjcmMgPj4gMTYpIF4gaW5wdXQuY2hhckNvZGVBdChpbmRleCsxMCkpICYgMHhmZl07XG4gICBjcmMgPSAoY3JjIDw8IDgpIF4gY3JjX3RhYmxlWygoY3JjID4+IDE2KSBeIGlucHV0LmNoYXJDb2RlQXQoaW5kZXgrMTEpKSAmIDB4ZmZdO1xuICAgY3JjID0gKGNyYyA8PCA4KSBeIGNyY190YWJsZVsoKGNyYyA+PiAxNikgXiBpbnB1dC5jaGFyQ29kZUF0KGluZGV4KzEyKSkgJiAweGZmXTtcbiAgIGNyYyA9IChjcmMgPDwgOCkgXiBjcmNfdGFibGVbKChjcmMgPj4gMTYpIF4gaW5wdXQuY2hhckNvZGVBdChpbmRleCsxMykpICYgMHhmZl07XG4gICBjcmMgPSAoY3JjIDw8IDgpIF4gY3JjX3RhYmxlWygoY3JjID4+IDE2KSBeIGlucHV0LmNoYXJDb2RlQXQoaW5kZXgrMTQpKSAmIDB4ZmZdO1xuICAgY3JjID0gKGNyYyA8PCA4KSBeIGNyY190YWJsZVsoKGNyYyA+PiAxNikgXiBpbnB1dC5jaGFyQ29kZUF0KGluZGV4KzE1KSkgJiAweGZmXTtcbiAgIGluZGV4ICs9IDE2O1xuICB9XG5cbiAgZm9yKHZhciBqID0gaW5kZXg7IGogPCBpbnB1dC5sZW5ndGg7IGorKykge1xuICAgY3JjID0gKGNyYyA8PCA4KSBeIGNyY190YWJsZVsoKGNyYyA+PiAxNikgXiBpbnB1dC5jaGFyQ29kZUF0KGluZGV4KyspKSAmIDB4ZmZdXG4gIH1cbiAgcmV0dXJuIGNyYyAmIDB4ZmZmZmZmO1xufVxuXG4vKipcbiAqIERlQXJtb3IgYW4gT3BlblBHUCBhcm1vcmVkIG1lc3NhZ2U7IHZlcmlmeSB0aGUgY2hlY2tzdW0gYW5kIHJldHVybiBcbiAqIHRoZSBlbmNvZGVkIGJ5dGVzXG4gKiBAcGFyYW0ge1N0cmluZ30gdGV4dCBPcGVuUEdQIGFybW9yZWQgbWVzc2FnZVxuICogQHJldHVybnMgeyhCb29sZWFufE9iamVjdCl9IEVpdGhlciBmYWxzZSBpbiBjYXNlIG9mIGFuIGVycm9yIFxuICogb3IgYW4gb2JqZWN0IHdpdGggYXR0cmlidXRlIFwidGV4dFwiIGNvbnRhaW5pbmcgdGhlIG1lc3NhZ2UgdGV4dFxuICogYW5kIGFuIGF0dHJpYnV0ZSBcIm9wZW5wZ3BcIiBjb250YWluaW5nIHRoZSBieXRlcy5cbiAqL1xuZnVuY3Rpb24gZGVhcm1vcih0ZXh0KSB7XG5cdHRleHQgPSB0ZXh0LnJlcGxhY2UoL1xcci9nLCAnJylcblxuXHR2YXIgdHlwZSA9IGdldF90eXBlKHRleHQpO1xuXG5cdGlmICh0eXBlICE9IDIpIHtcblx0XHR2YXIgc3BsaXR0ZWR0ZXh0ID0gdGV4dC5zcGxpdCgnLS0tLS0nKTtcblxuXHRcdHZhciBkYXRhID0geyBcblx0XHRcdG9wZW5wZ3A6IGJhc2U2NF9kZWNvZGUoXG5cdFx0XHRcdHNwbGl0dGVkdGV4dFsyXVxuXHRcdFx0XHRcdC5zcGxpdCgnXFxuXFxuJylbMV1cblx0XHRcdFx0XHQuc3BsaXQoXCJcXG49XCIpWzBdXG5cdFx0XHRcdFx0LnJlcGxhY2UoL1xcbi0gL2csXCJcXG5cIikpLFxuXHRcdFx0dHlwZTogdHlwZVxuXHRcdH07XG5cblx0XHRpZiAodmVyaWZ5Q2hlY2tTdW0oZGF0YS5vcGVucGdwLCBcblx0XHRcdHNwbGl0dGVkdGV4dFsyXVxuXHRcdFx0XHQuc3BsaXQoJ1xcblxcbicpWzFdXG5cdFx0XHRcdC5zcGxpdChcIlxcbj1cIilbMV1cblx0XHRcdFx0LnNwbGl0KCdcXG4nKVswXSkpXG5cblx0XHRcdHJldHVybiBkYXRhO1xuXHRcdGVsc2Uge1xuXHRcdFx0dXRpbC5wcmludF9lcnJvcihcIkFzY2lpIGFybW9yIGludGVncml0eSBjaGVjayBvbiBtZXNzYWdlIGZhaWxlZDogJ1wiXG5cdFx0XHRcdCsgc3BsaXR0ZWR0ZXh0WzJdXG5cdFx0XHRcdFx0LnNwbGl0KCdcXG5cXG4nKVsxXVxuXHRcdFx0XHRcdC5zcGxpdChcIlxcbj1cIilbMV1cblx0XHRcdFx0XHQuc3BsaXQoJ1xcbicpWzBdIFxuXHRcdFx0XHQrIFwiJyBzaG91bGQgYmUgJ1wiXG5cdFx0XHRcdCsgZ2V0Q2hlY2tTdW0oZGF0YSkpICsgXCInXCI7XG5cdFx0XHRyZXR1cm4gZmFsc2U7XG5cdFx0fVxuXHR9IGVsc2Uge1xuXHRcdHZhciBzcGxpdHRlZHRleHQgPSB0ZXh0LnNwbGl0KCctLS0tLScpO1xuXG5cdFx0dmFyIHJlc3VsdCA9IHtcblx0XHRcdHRleHQ6IHNwbGl0dGVkdGV4dFsyXVxuXHRcdFx0XHQucmVwbGFjZSgvXFxuLSAvZyxcIlxcblwiKVxuXHRcdFx0XHQuc3BsaXQoXCJcXG5cXG5cIilbMV0sXG5cdFx0XHRvcGVucGdwOiBiYXNlNjRfZGVjb2RlKHNwbGl0dGVkdGV4dFs0XVxuXHRcdFx0XHQuc3BsaXQoXCJcXG5cXG5cIilbMV1cblx0XHRcdFx0LnNwbGl0KFwiXFxuPVwiKVswXSksXG5cdFx0XHR0eXBlOiB0eXBlXG5cdFx0fTtcblxuXHRcdGlmICh2ZXJpZnlDaGVja1N1bShyZXN1bHQub3BlbnBncCwgc3BsaXR0ZWR0ZXh0WzRdXG5cdFx0XHQuc3BsaXQoXCJcXG5cXG5cIilbMV1cblx0XHRcdC5zcGxpdChcIlxcbj1cIilbMV0pKVxuXG5cdFx0XHRcdHJldHVybiByZXN1bHQ7XG5cdFx0ZWxzZSB7XG5cdFx0XHR1dGlsLnByaW50X2Vycm9yKFwiQXNjaWkgYXJtb3IgaW50ZWdyaXR5IGNoZWNrIG9uIG1lc3NhZ2UgZmFpbGVkXCIpO1xuXHRcdFx0cmV0dXJuIGZhbHNlO1xuXHRcdH1cblx0fVxufVxuXG5cbi8qKlxuICogQXJtb3IgYW4gT3BlblBHUCBiaW5hcnkgcGFja2V0IGJsb2NrXG4gKiBAcGFyYW0ge0ludGVnZXJ9IG1lc3NhZ2V0eXBlIHR5cGUgb2YgdGhlIG1lc3NhZ2VcbiAqIEBwYXJhbSBkYXRhXG4gKiBAcGFyYW0ge0ludGVnZXJ9IHBhcnRpbmRleFxuICogQHBhcmFtIHtJbnRlZ2VyfSBwYXJ0dG90YWxcbiAqIEByZXR1cm5zIHtTdHJpbmd9IEFybW9yZWQgdGV4dFxuICovXG5mdW5jdGlvbiBhcm1vcihtZXNzYWdldHlwZSwgZGF0YSwgcGFydGluZGV4LCBwYXJ0dG90YWwpIHtcblx0dmFyIHJlc3VsdCA9IFwiXCI7XG5cdHN3aXRjaChtZXNzYWdldHlwZSkge1xuXHRjYXNlIDA6XG5cdFx0cmVzdWx0ICs9IFwiLS0tLS1CRUdJTiBQR1AgTUVTU0FHRSwgUEFSVCBcIitwYXJ0aW5kZXgrXCIvXCIrcGFydHRvdGFsK1wiLS0tLS1cXHJcXG5cIjtcblx0XHRyZXN1bHQgKz0gYXJtb3JfYWRkaGVhZGVyKCk7XG5cdFx0cmVzdWx0ICs9IGJhc2U2NC5lbmNvZGUoZGF0YSk7XG5cdFx0cmVzdWx0ICs9IFwiXFxyXFxuPVwiK2dldENoZWNrU3VtKGRhdGEpK1wiXFxyXFxuXCI7XG5cdFx0cmVzdWx0ICs9IFwiLS0tLS1FTkQgUEdQIE1FU1NBR0UsIFBBUlQgXCIrcGFydGluZGV4K1wiL1wiK3BhcnR0b3RhbCtcIi0tLS0tXFxyXFxuXCI7XG5cdFx0YnJlYWs7XG5cdGNhc2UgMTpcblx0XHRyZXN1bHQgKz0gXCItLS0tLUJFR0lOIFBHUCBNRVNTQUdFLCBQQVJUIFwiK3BhcnRpbmRleCtcIi0tLS0tXFxyXFxuXCI7XG5cdFx0cmVzdWx0ICs9IGFybW9yX2FkZGhlYWRlcigpO1xuXHRcdHJlc3VsdCArPSBiYXNlNjQuZW5jb2RlKGRhdGEpO1xuXHRcdHJlc3VsdCArPSBcIlxcclxcbj1cIitnZXRDaGVja1N1bShkYXRhKStcIlxcclxcblwiO1xuXHRcdHJlc3VsdCArPSBcIi0tLS0tRU5EIFBHUCBNRVNTQUdFLCBQQVJUIFwiK3BhcnRpbmRleCtcIi0tLS0tXFxyXFxuXCI7XG5cdFx0YnJlYWs7XG5cdGNhc2UgMjpcblx0XHRyZXN1bHQgKz0gXCJcXHJcXG4tLS0tLUJFR0lOIFBHUCBTSUdORUQgTUVTU0FHRS0tLS0tXFxyXFxuSGFzaDogXCIrZGF0YS5oYXNoK1wiXFxyXFxuXFxyXFxuXCI7XG5cdFx0cmVzdWx0ICs9IGRhdGEudGV4dC5yZXBsYWNlKC9cXG4tL2csXCJcXG4tIC1cIik7XG5cdFx0cmVzdWx0ICs9IFwiXFxyXFxuLS0tLS1CRUdJTiBQR1AgU0lHTkFUVVJFLS0tLS1cXHJcXG5cIjtcblx0XHRyZXN1bHQgKz0gYXJtb3JfYWRkaGVhZGVyKCk7XG5cdFx0cmVzdWx0ICs9IGJhc2U2NC5lbmNvZGUoZGF0YS5vcGVucGdwKTtcblx0XHRyZXN1bHQgKz0gXCJcXHJcXG49XCIrZ2V0Q2hlY2tTdW0oZGF0YS5vcGVucGdwKStcIlxcclxcblwiO1xuXHRcdHJlc3VsdCArPSBcIi0tLS0tRU5EIFBHUCBTSUdOQVRVUkUtLS0tLVxcclxcblwiO1xuXHRcdGJyZWFrO1xuXHRjYXNlIDM6XG5cdFx0cmVzdWx0ICs9IFwiLS0tLS1CRUdJTiBQR1AgTUVTU0FHRS0tLS0tXFxyXFxuXCI7XG5cdFx0cmVzdWx0ICs9IGFybW9yX2FkZGhlYWRlcigpO1xuXHRcdHJlc3VsdCArPSBiYXNlNjQuZW5jb2RlKGRhdGEpO1xuXHRcdHJlc3VsdCArPSBcIlxcclxcbj1cIitnZXRDaGVja1N1bShkYXRhKStcIlxcclxcblwiO1xuXHRcdHJlc3VsdCArPSBcIi0tLS0tRU5EIFBHUCBNRVNTQUdFLS0tLS1cXHJcXG5cIjtcblx0XHRicmVhaztcblx0Y2FzZSA0OlxuXHRcdHJlc3VsdCArPSBcIi0tLS0tQkVHSU4gUEdQIFBVQkxJQyBLRVkgQkxPQ0stLS0tLVxcclxcblwiO1xuXHRcdHJlc3VsdCArPSBhcm1vcl9hZGRoZWFkZXIoKTtcblx0XHRyZXN1bHQgKz0gYmFzZTY0LmVuY29kZShkYXRhKTtcblx0XHRyZXN1bHQgKz0gXCJcXHJcXG49XCIrZ2V0Q2hlY2tTdW0oZGF0YSkrXCJcXHJcXG5cIjtcblx0XHRyZXN1bHQgKz0gXCItLS0tLUVORCBQR1AgUFVCTElDIEtFWSBCTE9DSy0tLS0tXFxyXFxuXFxyXFxuXCI7XG5cdFx0YnJlYWs7XG5cdGNhc2UgNTpcblx0XHRyZXN1bHQgKz0gXCItLS0tLUJFR0lOIFBHUCBQUklWQVRFIEtFWSBCTE9DSy0tLS0tXFxyXFxuXCI7XG5cdFx0cmVzdWx0ICs9IGFybW9yX2FkZGhlYWRlcigpO1xuXHRcdHJlc3VsdCArPSBiYXNlNjQuZW5jb2RlKGRhdGEpO1xuXHRcdHJlc3VsdCArPSBcIlxcclxcbj1cIitnZXRDaGVja1N1bShkYXRhKStcIlxcclxcblwiO1xuXHRcdHJlc3VsdCArPSBcIi0tLS0tRU5EIFBHUCBQUklWQVRFIEtFWSBCTE9DSy0tLS0tXFxyXFxuXCI7XG5cdFx0YnJlYWs7XG5cdH1cblxuXHRyZXR1cm4gcmVzdWx0O1xufVxuXG5tb2R1bGUuZXhwb3J0cyA9IHtcblx0ZW5jb2RlOiBhcm1vcixcblx0ZGVjb2RlOiBkZWFybW9yXG59XG4iLCIvKiBPcGVuUEdQIHJhZGl4LTY0L2Jhc2U2NCBzdHJpbmcgZW5jb2RpbmcvZGVjb2RpbmdcclxuICogQ29weXJpZ2h0IDIwMDUgSGVyYmVydCBIYW5ld2lua2VsLCB3d3cuaGFuZVdJTi5kZVxyXG4gKiB2ZXJzaW9uIDEuMCwgY2hlY2sgd3d3LmhhbmVXSU4uZGUgZm9yIHRoZSBsYXRlc3QgdmVyc2lvblxyXG4gKlxyXG4gKiBUaGlzIHNvZnR3YXJlIGlzIHByb3ZpZGVkIGFzLWlzLCB3aXRob3V0IGV4cHJlc3Mgb3IgaW1wbGllZCB3YXJyYW50eS4gIFxyXG4gKiBQZXJtaXNzaW9uIHRvIHVzZSwgY29weSwgbW9kaWZ5LCBkaXN0cmlidXRlIG9yIHNlbGwgdGhpcyBzb2Z0d2FyZSwgd2l0aCBvclxyXG4gKiB3aXRob3V0IGZlZSwgZm9yIGFueSBwdXJwb3NlIGFuZCBieSBhbnkgaW5kaXZpZHVhbCBvciBvcmdhbml6YXRpb24sIGlzIGhlcmVieVxyXG4gKiBncmFudGVkLCBwcm92aWRlZCB0aGF0IHRoZSBhYm92ZSBjb3B5cmlnaHQgbm90aWNlIGFuZCB0aGlzIHBhcmFncmFwaCBhcHBlYXIgXHJcbiAqIGluIGFsbCBjb3BpZXMuIERpc3RyaWJ1dGlvbiBhcyBhIHBhcnQgb2YgYW4gYXBwbGljYXRpb24gb3IgYmluYXJ5IG11c3RcclxuICogaW5jbHVkZSB0aGUgYWJvdmUgY29weXJpZ2h0IG5vdGljZSBpbiB0aGUgZG9jdW1lbnRhdGlvbiBhbmQvb3Igb3RoZXIgbWF0ZXJpYWxzXHJcbiAqIHByb3ZpZGVkIHdpdGggdGhlIGFwcGxpY2F0aW9uIG9yIGRpc3RyaWJ1dGlvbi5cclxuICovXHJcblxyXG52YXIgYjY0cyA9ICdBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OSsvJztcclxuXHJcbmZ1bmN0aW9uIHMycih0KSB7XHJcblx0dmFyIGEsIGMsIG47XHJcblx0dmFyIHIgPSAnJywgbCA9IDAsIHMgPSAwO1xyXG5cdHZhciB0bCA9IHQubGVuZ3RoO1xyXG5cclxuXHRmb3IgKG4gPSAwOyBuIDwgdGw7IG4rKykge1xyXG5cdFx0YyA9IHQuY2hhckNvZGVBdChuKTtcclxuXHRcdGlmIChzID09IDApIHtcclxuXHRcdFx0ciArPSBiNjRzLmNoYXJBdCgoYyA+PiAyKSAmIDYzKTtcclxuXHRcdFx0YSA9IChjICYgMykgPDwgNDtcclxuXHRcdH0gZWxzZSBpZiAocyA9PSAxKSB7XHJcblx0XHRcdHIgKz0gYjY0cy5jaGFyQXQoKGEgfCAoYyA+PiA0KSAmIDE1KSk7XHJcblx0XHRcdGEgPSAoYyAmIDE1KSA8PCAyO1xyXG5cdFx0fSBlbHNlIGlmIChzID09IDIpIHtcclxuXHRcdFx0ciArPSBiNjRzLmNoYXJBdChhIHwgKChjID4+IDYpICYgMykpO1xyXG5cdFx0XHRsICs9IDE7XHJcblx0XHRcdGlmICgobCAlIDYwKSA9PSAwKVxyXG5cdFx0XHRcdHIgKz0gXCJcXG5cIjtcclxuXHRcdFx0ciArPSBiNjRzLmNoYXJBdChjICYgNjMpO1xyXG5cdFx0fVxyXG5cdFx0bCArPSAxO1xyXG5cdFx0aWYgKChsICUgNjApID09IDApXHJcblx0XHRcdHIgKz0gXCJcXG5cIjtcclxuXHJcblx0XHRzICs9IDE7XHJcblx0XHRpZiAocyA9PSAzKVxyXG5cdFx0XHRzID0gMDtcclxuXHR9XHJcblx0aWYgKHMgPiAwKSB7XHJcblx0XHRyICs9IGI2NHMuY2hhckF0KGEpO1xyXG5cdFx0bCArPSAxO1xyXG5cdFx0aWYgKChsICUgNjApID09IDApXHJcblx0XHRcdHIgKz0gXCJcXG5cIjtcclxuXHRcdHIgKz0gJz0nO1xyXG5cdFx0bCArPSAxO1xyXG5cdH1cclxuXHRpZiAocyA9PSAxKSB7XHJcblx0XHRpZiAoKGwgJSA2MCkgPT0gMClcclxuXHRcdFx0ciArPSBcIlxcblwiO1xyXG5cdFx0ciArPSAnPSc7XHJcblx0fVxyXG5cclxuXHRyZXR1cm4gcjtcclxufVxyXG5cclxuZnVuY3Rpb24gcjJzKHQpIHtcclxuXHR2YXIgYywgbjtcclxuXHR2YXIgciA9ICcnLCBzID0gMCwgYSA9IDA7XHJcblx0dmFyIHRsID0gdC5sZW5ndGg7XHJcblxyXG5cdGZvciAobiA9IDA7IG4gPCB0bDsgbisrKSB7XHJcblx0XHRjID0gYjY0cy5pbmRleE9mKHQuY2hhckF0KG4pKTtcclxuXHRcdGlmIChjID49IDApIHtcclxuXHRcdFx0aWYgKHMpXHJcblx0XHRcdFx0ciArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKGEgfCAoYyA+PiAoNiAtIHMpKSAmIDI1NSk7XHJcblx0XHRcdHMgPSAocyArIDIpICYgNztcclxuXHRcdFx0YSA9IChjIDw8IHMpICYgMjU1O1xyXG5cdFx0fVxyXG5cdH1cclxuXHRyZXR1cm4gcjtcclxufVxyXG5cclxubW9kdWxlLmV4cG9ydHMgPSB7XHJcblx0ZW5jb2RlOiBzMnIsXHJcblx0ZGVjb2RlOiByMnNcclxufVxyXG4iLCJcbnZhciBlbnVtcyA9IHJlcXVpcmUoJy4uL2VudW1zLmpzJyk7XG5cbm1vZHVsZS5leHBvcnRzID0ge1xuXHRsaXN0OiByZXF1aXJlKCcuL3BhY2tldGxpc3QuanMnKSxcbn1cblxudmFyIHBhY2tldHMgPSByZXF1aXJlKCcuL2FsbF9wYWNrZXRzLmpzJyk7XG5cbmZvcih2YXIgaSBpbiBwYWNrZXRzKVxuXHRtb2R1bGUuZXhwb3J0c1tpXSA9IHBhY2tldHNbaV07XG4iLCIvLyBHUEc0QnJvd3NlcnMgLSBBbiBPcGVuUEdQIGltcGxlbWVudGF0aW9uIGluIGphdmFzY3JpcHRcbi8vIENvcHlyaWdodCAoQykgMjAxMSBSZWN1cml0eSBMYWJzIEdtYkhcbi8vIFxuLy8gVGhpcyBsaWJyYXJ5IGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vclxuLy8gbW9kaWZ5IGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIExlc3NlciBHZW5lcmFsIFB1YmxpY1xuLy8gTGljZW5zZSBhcyBwdWJsaXNoZWQgYnkgdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyXG4vLyB2ZXJzaW9uIDIuMSBvZiB0aGUgTGljZW5zZSwgb3IgKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbi8vIFxuLy8gVGhpcyBsaWJyYXJ5IGlzIGRpc3RyaWJ1dGVkIGluIHRoZSBob3BlIHRoYXQgaXQgd2lsbCBiZSB1c2VmdWwsXG4vLyBidXQgV0lUSE9VVCBBTlkgV0FSUkFOVFk7IHdpdGhvdXQgZXZlbiB0aGUgaW1wbGllZCB3YXJyYW50eSBvZlxuLy8gTUVSQ0hBTlRBQklMSVRZIG9yIEZJVE5FU1MgRk9SIEEgUEFSVElDVUxBUiBQVVJQT1NFLiAgU2VlIHRoZSBHTlVcbi8vIExlc3NlciBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGZvciBtb3JlIGRldGFpbHMuXG4vLyBcbi8vIFlvdSBzaG91bGQgaGF2ZSByZWNlaXZlZCBhIGNvcHkgb2YgdGhlIEdOVSBMZXNzZXIgR2VuZXJhbCBQdWJsaWNcbi8vIExpY2Vuc2UgYWxvbmcgd2l0aCB0aGlzIGxpYnJhcnk7IGlmIG5vdCwgd3JpdGUgdG8gdGhlIEZyZWUgU29mdHdhcmVcbi8vIEZvdW5kYXRpb24sIEluYy4sIDUxIEZyYW5rbGluIFN0cmVldCwgRmlmdGggRmxvb3IsIEJvc3RvbiwgTUEgIDAyMTEwLTEzMDEgIFVTQVxuXG4vLyBIaW50OiBXZSBob2xkIG91ciBNUElzIGFzIGFuIGFycmF5IG9mIG9jdGV0cyBpbiBiaWcgZW5kaWFuIGZvcm1hdCBwcmVjZWVkaW5nIGEgdHdvXG4vLyBvY3RldCBzY2FsYXI6IE1QSTogW2EsYixjLGQsZSxmXVxuLy8gLSBNUEkgc2l6ZTogKGEgPDwgOCkgfCBiIFxuLy8gLSBNUEkgPSBjIHwgZCA8PCA4IHwgZSA8PCAoKE1QSS5sZW5ndGggLTIpKjgpIHwgZiAoKE1QSS5sZW5ndGggLTIpKjgpXG5cbnZhciBCaWdJbnRlZ2VyID0gcmVxdWlyZSgnLi4vY3J5cHRvL3B1YmxpY19rZXkvanNibi5qcycpLFxuXHR1dGlsID0gcmVxdWlyZSgnLi4vdXRpbCcpO1xuXG4vKipcbiAqIEBjbGFzc1xuICogQGNsYXNzZGVzY0ltcGxlbWVudGF0aW9uIG9mIHR5cGUgTVBJIChSRkM0ODgwIDMuMilcbiAqIE11bHRpcHJlY2lzaW9uIGludGVnZXJzIChhbHNvIGNhbGxlZCBNUElzKSBhcmUgdW5zaWduZWQgaW50ZWdlcnMgdXNlZFxuICogdG8gaG9sZCBsYXJnZSBpbnRlZ2VycyBzdWNoIGFzIHRoZSBvbmVzIHVzZWQgaW4gY3J5cHRvZ3JhcGhpY1xuICogY2FsY3VsYXRpb25zLlxuICogQW4gTVBJIGNvbnNpc3RzIG9mIHR3byBwaWVjZXM6IGEgdHdvLW9jdGV0IHNjYWxhciB0aGF0IGlzIHRoZSBsZW5ndGhcbiAqIG9mIHRoZSBNUEkgaW4gYml0cyBmb2xsb3dlZCBieSBhIHN0cmluZyBvZiBvY3RldHMgdGhhdCBjb250YWluIHRoZVxuICogYWN0dWFsIGludGVnZXIuXG4gKi9cbm1vZHVsZS5leHBvcnRzID0gZnVuY3Rpb24gbXBpKCkge1xuXHQvKiogQW4gaW1wbGVtZW50YXRpb24gZGVwZW5kZW50IGludGVnZXIgKi9cblx0dGhpcy5kYXRhID0gbnVsbDtcblxuXHQvKipcblx0ICogUGFyc2luZyBmdW5jdGlvbiBmb3IgYSBtcGkgKFJGQyA0ODgwIDMuMikuXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBpbnB1dCBQYXlsb2FkIG9mIG1waSBkYXRhXG5cdCAqIEBwYXJhbSB7SW50ZWdlcn0gcG9zaXRpb24gUG9zaXRpb24gdG8gc3RhcnQgcmVhZGluZyBmcm9tIHRoZSBpbnB1dCBcblx0ICogc3RyaW5nXG5cdCAqIEBwYXJhbSB7SW50ZWdlcn0gbGVuIExlbmd0aCBvZiB0aGUgcGFja2V0IG9yIHRoZSByZW1haW5pbmcgbGVuZ3RoIG9mIFxuXHQgKiBpbnB1dCBhdCBwb3NpdGlvblxuXHQgKiBAcmV0dXJuIHtvcGVucGdwX3R5cGVfbXBpfSBPYmplY3QgcmVwcmVzZW50YXRpb25cblx0ICovXG5cdHRoaXMucmVhZCA9IGZ1bmN0aW9uKGJ5dGVzKSB7XG5cdFx0dmFyIGJpdHMgPSAoYnl0ZXNbMF0uY2hhckNvZGVBdCgpIDw8IDgpIHwgYnl0ZXNbMV0uY2hhckNvZGVBdCgpO1xuXHRcdFxuXHRcdC8vIEFkZGl0aW9uYWwgcnVsZXM6XG5cdFx0Ly9cblx0XHQvLyAgICBUaGUgc2l6ZSBvZiBhbiBNUEkgaXMgKChNUEkubGVuZ3RoICsgNykgLyA4KSArIDIgb2N0ZXRzLlxuXHRcdC8vXG5cdFx0Ly8gICAgVGhlIGxlbmd0aCBmaWVsZCBvZiBhbiBNUEkgZGVzY3JpYmVzIHRoZSBsZW5ndGggc3RhcnRpbmcgZnJvbSBpdHNcblx0XHQvL1x0ICBtb3N0IHNpZ25pZmljYW50IG5vbi16ZXJvIGJpdC4gIFRodXMsIHRoZSBNUEkgWzAwIDAyIDAxXSBpcyBub3Rcblx0XHQvLyAgICBmb3JtZWQgY29ycmVjdGx5LiAgSXQgc2hvdWxkIGJlIFswMCAwMSAwMV0uXG5cblx0XHQvLyBUT0RPOiBWZXJpZmljYXRpb24gb2YgdGhpcyBzaXplIG1ldGhvZCEgVGhpcyBzaXplIGNhbGN1bGF0aW9uIGFzXG5cdFx0Ly8gXHRcdCBzcGVjaWZpZWQgYWJvdmUgaXMgbm90IGFwcGxpY2FibGUgaW4gSmF2YVNjcmlwdFxuXHRcdHZhciBieXRlbGVuID0gTWF0aC5jZWlsKGJpdHMgLyA4KTtcblx0XHRcblx0XHR2YXIgcmF3ID0gYnl0ZXMuc3Vic3RyKDIsIGJ5dGVsZW4pO1xuXHRcdHRoaXMuZnJvbUJ5dGVzKHJhdyk7XG5cblx0XHRyZXR1cm4gMiArIGJ5dGVsZW47XG5cdH1cblxuXHR0aGlzLmZyb21CeXRlcyA9IGZ1bmN0aW9uKGJ5dGVzKSB7XG5cdFx0dGhpcy5kYXRhID0gbmV3IEJpZ0ludGVnZXIodXRpbC5oZXhzdHJkdW1wKGJ5dGVzKSwgMTYpOyBcblx0fVxuXG5cdHRoaXMudG9CeXRlcyA9IGZ1bmN0aW9uKCkge1xuXHRcdHJldHVybiB0aGlzLndyaXRlKCkuc3Vic3RyKDIpO1xuXHR9XG5cblx0dGhpcy5ieXRlTGVuZ3RoID0gZnVuY3Rpb24oKSB7XG5cdFx0cmV0dXJuIHRoaXMudG9CeXRlcygpLmxlbmd0aDtcblx0fVxuXG5cdC8qKlxuXHQgKiBDb252ZXJ0cyB0aGUgbXBpIG9iamVjdCB0byBhIHN0cmluZyBhcyBzcGVjaWZpZWQgaW4gUkZDNDg4MCAzLjJcblx0ICogQHJldHVybiB7U3RyaW5nfSBtcGkgQnl0ZSByZXByZXNlbnRhdGlvblxuXHQgKi9cblx0dGhpcy53cml0ZSA9IGZ1bmN0aW9uKCkge1xuXHRcdHJldHVybiB0aGlzLmRhdGEudG9NUEkoKTtcblx0fVxuXG5cdHRoaXMudG9CaWdJbnRlZ2VyID0gZnVuY3Rpb24oKSB7XG5cdFx0cmV0dXJuIHRoaXMuZGF0YS5jbG9uZSgpO1xuXHR9XG5cblx0dGhpcy5mcm9tQmlnSW50ZWdlciA9IGZ1bmN0aW9uKGJuKSB7XG5cdFx0dGhpcy5kYXRhID0gYm4uY2xvbmUoKTtcblx0fVxufVxuXG4iLCJtb2R1bGUuZXhwb3J0cyA9IHtcblx0LyoqIFJGQzQ4ODAsIHNlY3Rpb24gOS4xIFxuXHQgKiBAZW51bSB7U3RyaW5nfVxuXHQgKi9cblx0cHVibGljS2V5OiB7XG5cdFx0cnNhX2VuY3J5cHRfc2lnbjogMSxcblx0XHRyc2FfZW5jcnlwdDogMixcblx0XHRyc2Ffc2lnbjogMyxcblx0XHRlbGdhbWFsOiAxNixcblx0XHRkc2E6IDE3XG5cdH0sXG5cblx0LyoqIFJGQzQ4ODAsIHNlY3Rpb24gOS4yIFxuXHQgKiBAZW51bSB7U3RyaW5nfVxuXHQgKi9cblx0c3ltbWV0cmljOiB7XG5cdFx0cGxhaW50ZXh0OiAwLFxuXHRcdC8qKiBOb3QgaW1wbGVtZW50ZWQhICovXG5cdFx0aWRlYTogMSxcblx0XHR0cmlwbGVkZXM6IDIsXG5cdFx0Y2FzdDU6IDMsXG5cdFx0Ymxvd2Zpc2g6IDQsXG5cdFx0YWVzMTI4OiA3LFxuXHRcdGFlczE5MjogOCxcblx0XHRhZXMyNTY6IDksXG5cdFx0dHdvZmlzaDogMTBcblx0fSxcblxuXHQvKiogUkZDNDg4MCwgc2VjdGlvbiA5LjNcblx0ICogQGVudW0ge1N0cmluZ31cblx0ICovXG5cdGNvbXByZXNzaW9uOiB7XG5cdFx0dW5jb21wcmVzc2VkOiAwLFxuXHRcdC8qKiBSRkMxOTUxICovXG5cdFx0emlwOiAxLFxuXHRcdC8qKiBSRkMxOTUwICovXG5cdFx0emxpYjogMixcblx0XHRiemlwMjogM1xuXHR9LFxuXG5cdC8qKiBSRkM0ODgwLCBzZWN0aW9uIDkuNFxuXHQgKiBAZW51bSB7U3RyaW5nfVxuXHQgKi9cblx0aGFzaDoge1xuXHRcdG1kNTogMSxcblx0XHRzaGExOiAyLFxuXHRcdHJpcGVtZDogMyxcblx0XHRzaGEyNTY6IDgsXG5cdFx0c2hhMzg0OiA5LFxuXHRcdHNoYTUxMjogMTAsXG5cdFx0c2hhMjI0OiAxMVxuXHR9LFxuXG5cblx0LyoqXG5cdCAqIEBlbnVtIHtTdHJpbmd9XG5cdCAqIEEgbGlzdCBvZiBwYWNrZXQgdHlwZXMgYW5kIG51bWVyaWMgdGFncyBhc3NvY2lhdGVkIHdpdGggdGhlbS5cblx0ICovXG5cdHBhY2tldDoge1xuXHRcdHB1YmxpY19rZXlfZW5jcnlwdGVkX3Nlc3Npb25fa2V5OiAxLFxuXHRcdHNpZ25hdHVyZTogMixcblx0XHRzeW1fZW5jcnlwdGVkX3Nlc3Npb25fa2V5OiAzLFxuXHRcdG9uZV9wYXNzX3NpZ25hdHVyZTogNCxcblx0XHRzZWNyZXRfa2V5OiA1LFxuXHRcdHB1YmxpY19rZXk6IDYsXG5cdFx0c2VjcmV0X3N1YmtleTogNyxcblx0XHRjb21wcmVzc2VkOiA4LFxuXHRcdHN5bW1ldHJpY2FsbHlfZW5jcnlwdGVkOiA5LFxuXHRcdG1hcmtlcjogMTAsXG5cdFx0bGl0ZXJhbDogMTEsXG5cdFx0dHJ1c3Q6IDEyLFxuXHRcdHVzZXJpZDogMTMsXG5cdFx0cHVibGljX3N1YmtleTogMTQsXG5cdFx0dXNlcl9hdHRyaWJ1dGU6IDE3LFxuXHRcdHN5bV9lbmNyeXB0ZWRfaW50ZWdyaXR5X3Byb3RlY3RlZDogMTgsXG5cdFx0bW9kaWZpY2F0aW9uX2RldGVjdGlvbl9jb2RlOiAxOVxuXHR9LFxuXG5cblx0LyoqXG5cdCAqIERhdGEgdHlwZXMgaW4gdGhlIGxpdGVyYWwgcGFja2V0XG5cdCAqIEByZWFkb25seVxuXHQgKiBAZW51bSB7U3RyaW5nfVxuXHQgKi9cblx0bGl0ZXJhbDoge1xuXHRcdC8qKiBCaW5hcnkgZGF0YSAqL1xuXHRcdGJpbmFyeTogJ2InLmNoYXJDb2RlQXQoKSxcblx0XHQvKiogVGV4dCBkYXRhICovXG5cdFx0dGV4dDogJ3QnLmNoYXJDb2RlQXQoKSxcblx0XHQvKiogVXRmOCBkYXRhICovXG5cdFx0dXRmODogJ3UnLmNoYXJDb2RlQXQoKVxuXHR9LFxuXG5cblx0LyoqIE9uZSBwYXNzIHNpZ25hdHVyZSBwYWNrZXQgdHlwZVxuXHQgKiBAZW51bSB7U3RyaW5nfSAqL1xuXHRzaWduYXR1cmU6IHtcblx0XHQvKiogMHgwMDogU2lnbmF0dXJlIG9mIGEgYmluYXJ5IGRvY3VtZW50LiAqL1xuXHRcdGJpbmFyeTogMCxcblx0XHQvKiogMHgwMTogU2lnbmF0dXJlIG9mIGEgY2Fub25pY2FsIHRleHQgZG9jdW1lbnQuXG5cdFx0ICogQ2Fub25pY2FseXppbmcgdGhlIGRvY3VtZW50IGJ5IGNvbnZlcnRpbmcgbGluZSBlbmRpbmdzLiAqL1xuXHRcdHRleHQ6IDEsXG5cdFx0LyoqIDB4MDI6IFN0YW5kYWxvbmUgc2lnbmF0dXJlLlxuXHRcdCogVGhpcyBzaWduYXR1cmUgaXMgYSBzaWduYXR1cmUgb2Ygb25seSBpdHMgb3duIHN1YnBhY2tldCBjb250ZW50cy5cblx0XHQqIEl0IGlzIGNhbGN1bGF0ZWQgaWRlbnRpY2FsbHkgdG8gYSBzaWduYXR1cmUgb3ZlciBhIHplcm8tbGVuZ2hcblx0XHQqIGJpbmFyeSBkb2N1bWVudC4gIE5vdGUgdGhhdCBpdCBkb2Vzbid0IG1ha2Ugc2Vuc2UgdG8gaGF2ZSBhIFYzXG5cdFx0KiBzdGFuZGFsb25lIHNpZ25hdHVyZS4gKi9cblx0XHRzdGFuZGFsb25lOiAyLFxuXHRcdC8qKiAweDEwOiBHZW5lcmljIGNlcnRpZmljYXRpb24gb2YgYSBVc2VyIElEIGFuZCBQdWJsaWMtS2V5IHBhY2tldC5cblx0XHQqIFRoZSBpc3N1ZXIgb2YgdGhpcyBjZXJ0aWZpY2F0aW9uIGRvZXMgbm90IG1ha2UgYW55IHBhcnRpY3VsYXJcblx0XHQqIGFzc2VydGlvbiBhcyB0byBob3cgd2VsbCB0aGUgY2VydGlmaWVyIGhhcyBjaGVja2VkIHRoYXQgdGhlIG93bmVyXG5cdFx0KiBvZiB0aGUga2V5IGlzIGluIGZhY3QgdGhlIHBlcnNvbiBkZXNjcmliZWQgYnkgdGhlIFVzZXIgSUQuICovXG5cdFx0Y2VydF9nZW5lcmljOiAxNixcblx0XHQvKiogMHgxMTogUGVyc29uYSBjZXJ0aWZpY2F0aW9uIG9mIGEgVXNlciBJRCBhbmQgUHVibGljLUtleSBwYWNrZXQuXG5cdFx0KiBUaGUgaXNzdWVyIG9mIHRoaXMgY2VydGlmaWNhdGlvbiBoYXMgbm90IGRvbmUgYW55IHZlcmlmaWNhdGlvbiBvZlxuXHRcdCogdGhlIGNsYWltIHRoYXQgdGhlIG93bmVyIG9mIHRoaXMga2V5IGlzIHRoZSBVc2VyIElEIHNwZWNpZmllZC4gKi9cblx0XHRjZXJ0X3BlcnNvbmE6IDE3LFxuXHRcdC8qKiAweDEyOiBDYXN1YWwgY2VydGlmaWNhdGlvbiBvZiBhIFVzZXIgSUQgYW5kIFB1YmxpYy1LZXkgcGFja2V0LlxuXHRcdCogVGhlIGlzc3VlciBvZiB0aGlzIGNlcnRpZmljYXRpb24gaGFzIGRvbmUgc29tZSBjYXN1YWxcblx0XHQqIHZlcmlmaWNhdGlvbiBvZiB0aGUgY2xhaW0gb2YgaWRlbnRpdHkuICovXG5cdFx0Y2VydF9jYXN1YWw6IDE4LFxuXHRcdC8qKiAweDEzOiBQb3NpdGl2ZSBjZXJ0aWZpY2F0aW9uIG9mIGEgVXNlciBJRCBhbmQgUHVibGljLUtleSBwYWNrZXQuXG5cdFx0KiBUaGUgaXNzdWVyIG9mIHRoaXMgY2VydGlmaWNhdGlvbiBoYXMgZG9uZSBzdWJzdGFudGlhbFxuXHRcdCogdmVyaWZpY2F0aW9uIG9mIHRoZSBjbGFpbSBvZiBpZGVudGl0eS5cblx0XHQqIFxuXHRcdCogTW9zdCBPcGVuUEdQIGltcGxlbWVudGF0aW9ucyBtYWtlIHRoZWlyIFwia2V5IHNpZ25hdHVyZXNcIiBhcyAweDEwXG5cdFx0KiBjZXJ0aWZpY2F0aW9ucy4gIFNvbWUgaW1wbGVtZW50YXRpb25zIGNhbiBpc3N1ZSAweDExLTB4MTNcblx0XHQqIGNlcnRpZmljYXRpb25zLCBidXQgZmV3IGRpZmZlcmVudGlhdGUgYmV0d2VlbiB0aGUgdHlwZXMuICovXG5cdFx0Y2VydF9wb3NpdGl2ZTogMTksXG5cdFx0LyoqIDB4MzA6IENlcnRpZmljYXRpb24gcmV2b2NhdGlvbiBzaWduYXR1cmVcblx0XHQqIFRoaXMgc2lnbmF0dXJlIHJldm9rZXMgYW4gZWFybGllciBVc2VyIElEIGNlcnRpZmljYXRpb24gc2lnbmF0dXJlXG5cdFx0KiAoc2lnbmF0dXJlIGNsYXNzIDB4MTAgdGhyb3VnaCAweDEzKSBvciBkaXJlY3Qta2V5IHNpZ25hdHVyZVxuXHRcdCogKDB4MUYpLiAgSXQgc2hvdWxkIGJlIGlzc3VlZCBieSB0aGUgc2FtZSBrZXkgdGhhdCBpc3N1ZWQgdGhlXG5cdFx0KiByZXZva2VkIHNpZ25hdHVyZSBvciBhbiBhdXRob3JpemVkIHJldm9jYXRpb24ga2V5LiAgVGhlIHNpZ25hdHVyZVxuXHRcdCogaXMgY29tcHV0ZWQgb3ZlciB0aGUgc2FtZSBkYXRhIGFzIHRoZSBjZXJ0aWZpY2F0ZSB0aGF0IGl0XG5cdFx0KiByZXZva2VzLCBhbmQgc2hvdWxkIGhhdmUgYSBsYXRlciBjcmVhdGlvbiBkYXRlIHRoYW4gdGhhdFxuXHRcdCogY2VydGlmaWNhdGUuICovXG5cdFx0Y2VydF9yZXZvY2F0aW9uOiA0OCxcblx0XHQvKiogMHgxODogU3Via2V5IEJpbmRpbmcgU2lnbmF0dXJlXG5cdFx0KiBUaGlzIHNpZ25hdHVyZSBpcyBhIHN0YXRlbWVudCBieSB0aGUgdG9wLWxldmVsIHNpZ25pbmcga2V5IHRoYXRcblx0XHQqIGluZGljYXRlcyB0aGF0IGl0IG93bnMgdGhlIHN1YmtleS4gIFRoaXMgc2lnbmF0dXJlIGlzIGNhbGN1bGF0ZWRcblx0XHQqIGRpcmVjdGx5IG9uIHRoZSBwcmltYXJ5IGtleSBhbmQgc3Via2V5LCBhbmQgbm90IG9uIGFueSBVc2VyIElEIG9yXG5cdFx0KiBvdGhlciBwYWNrZXRzLiAgQSBzaWduYXR1cmUgdGhhdCBiaW5kcyBhIHNpZ25pbmcgc3Via2V5IE1VU1QgaGF2ZVxuXHRcdCogYW4gRW1iZWRkZWQgU2lnbmF0dXJlIHN1YnBhY2tldCBpbiB0aGlzIGJpbmRpbmcgc2lnbmF0dXJlIHRoYXRcblx0XHQqIGNvbnRhaW5zIGEgMHgxOSBzaWduYXR1cmUgbWFkZSBieSB0aGUgc2lnbmluZyBzdWJrZXkgb24gdGhlXG5cdFx0KiBwcmltYXJ5IGtleSBhbmQgc3Via2V5LiAqL1xuXHRcdHN1YmtleV9iaW5kaW5nOiAyNCxcblx0XHQvKiogMHgxOTogUHJpbWFyeSBLZXkgQmluZGluZyBTaWduYXR1cmVcblx0XHQqIFRoaXMgc2lnbmF0dXJlIGlzIGEgc3RhdGVtZW50IGJ5IGEgc2lnbmluZyBzdWJrZXksIGluZGljYXRpbmdcblx0XHQqIHRoYXQgaXQgaXMgb3duZWQgYnkgdGhlIHByaW1hcnkga2V5IGFuZCBzdWJrZXkuICBUaGlzIHNpZ25hdHVyZVxuXHRcdCogaXMgY2FsY3VsYXRlZCB0aGUgc2FtZSB3YXkgYXMgYSAweDE4IHNpZ25hdHVyZTogZGlyZWN0bHkgb24gdGhlXG5cdFx0KiBwcmltYXJ5IGtleSBhbmQgc3Via2V5LCBhbmQgbm90IG9uIGFueSBVc2VyIElEIG9yIG90aGVyIHBhY2tldHMuXG5cdFx0XG5cdFx0KiBXaGVuIGEgc2lnbmF0dXJlIGlzIG1hZGUgb3ZlciBhIGtleSwgdGhlIGhhc2ggZGF0YSBzdGFydHMgd2l0aCB0aGVcblx0XHQqIG9jdGV0IDB4OTksIGZvbGxvd2VkIGJ5IGEgdHdvLW9jdGV0IGxlbmd0aCBvZiB0aGUga2V5LCBhbmQgdGhlbiBib2R5XG5cdFx0KiBvZiB0aGUga2V5IHBhY2tldC4gIChOb3RlIHRoYXQgdGhpcyBpcyBhbiBvbGQtc3R5bGUgcGFja2V0IGhlYWRlciBmb3Jcblx0XHQqIGEga2V5IHBhY2tldCB3aXRoIHR3by1vY3RldCBsZW5ndGguKSAgQSBzdWJrZXkgYmluZGluZyBzaWduYXR1cmVcblx0XHQqICh0eXBlIDB4MTgpIG9yIHByaW1hcnkga2V5IGJpbmRpbmcgc2lnbmF0dXJlICh0eXBlIDB4MTkpIHRoZW4gaGFzaGVzXG5cdFx0KiB0aGUgc3Via2V5IHVzaW5nIHRoZSBzYW1lIGZvcm1hdCBhcyB0aGUgbWFpbiBrZXkgKGFsc28gdXNpbmcgMHg5OSBhc1xuXHRcdCogdGhlIGZpcnN0IG9jdGV0KS4gKi9cblx0XHRrZXlfYmluZGluZzogMjUsXG5cdFx0LyoqIDB4MUY6IFNpZ25hdHVyZSBkaXJlY3RseSBvbiBhIGtleVxuXHRcdCogVGhpcyBzaWduYXR1cmUgaXMgY2FsY3VsYXRlZCBkaXJlY3RseSBvbiBhIGtleS4gIEl0IGJpbmRzIHRoZVxuXHRcdCogaW5mb3JtYXRpb24gaW4gdGhlIFNpZ25hdHVyZSBzdWJwYWNrZXRzIHRvIHRoZSBrZXksIGFuZCBpc1xuXHRcdCogYXBwcm9wcmlhdGUgdG8gYmUgdXNlZCBmb3Igc3VicGFja2V0cyB0aGF0IHByb3ZpZGUgaW5mb3JtYXRpb25cblx0XHQqIGFib3V0IHRoZSBrZXksIHN1Y2ggYXMgdGhlIFJldm9jYXRpb24gS2V5IHN1YnBhY2tldC4gIEl0IGlzIGFsc29cblx0XHQqIGFwcHJvcHJpYXRlIGZvciBzdGF0ZW1lbnRzIHRoYXQgbm9uLXNlbGYgY2VydGlmaWVycyB3YW50IHRvIG1ha2Vcblx0XHQqIGFib3V0IHRoZSBrZXkgaXRzZWxmLCByYXRoZXIgdGhhbiB0aGUgYmluZGluZyBiZXR3ZWVuIGEga2V5IGFuZCBhXG5cdFx0KiBuYW1lLiAqL1xuXHRcdGtleTogMzEsXG5cdFx0LyoqIDB4MjA6IEtleSByZXZvY2F0aW9uIHNpZ25hdHVyZVxuXHRcdCogVGhlIHNpZ25hdHVyZSBpcyBjYWxjdWxhdGVkIGRpcmVjdGx5IG9uIHRoZSBrZXkgYmVpbmcgcmV2b2tlZC4gIEFcblx0XHQqIHJldm9rZWQga2V5IGlzIG5vdCB0byBiZSB1c2VkLiAgT25seSByZXZvY2F0aW9uIHNpZ25hdHVyZXMgYnkgdGhlXG5cdFx0KiBrZXkgYmVpbmcgcmV2b2tlZCwgb3IgYnkgYW4gYXV0aG9yaXplZCByZXZvY2F0aW9uIGtleSwgc2hvdWxkIGJlXG5cdFx0KiBjb25zaWRlcmVkIHZhbGlkIHJldm9jYXRpb24gc2lnbmF0dXJlcy5hICovXG5cdFx0a2V5X3Jldm9jYXRpb246IDMyLFxuXHRcdC8qKiAweDI4OiBTdWJrZXkgcmV2b2NhdGlvbiBzaWduYXR1cmVcblx0XHQqIFRoZSBzaWduYXR1cmUgaXMgY2FsY3VsYXRlZCBkaXJlY3RseSBvbiB0aGUgc3Via2V5IGJlaW5nIHJldm9rZWQuXG5cdFx0KiBBIHJldm9rZWQgc3Via2V5IGlzIG5vdCB0byBiZSB1c2VkLiAgT25seSByZXZvY2F0aW9uIHNpZ25hdHVyZXNcblx0XHQqIGJ5IHRoZSB0b3AtbGV2ZWwgc2lnbmF0dXJlIGtleSB0aGF0IGlzIGJvdW5kIHRvIHRoaXMgc3Via2V5LCBvclxuXHRcdCogYnkgYW4gYXV0aG9yaXplZCByZXZvY2F0aW9uIGtleSwgc2hvdWxkIGJlIGNvbnNpZGVyZWQgdmFsaWRcblx0XHQqIHJldm9jYXRpb24gc2lnbmF0dXJlcy5cblx0XHQqIEtleSByZXZvY2F0aW9uIHNpZ25hdHVyZXMgKHR5cGVzIDB4MjAgYW5kIDB4MjgpXG5cdFx0KiBoYXNoIG9ubHkgdGhlIGtleSBiZWluZyByZXZva2VkLiAqL1xuXHRcdHN1YmtleV9yZXZvY2F0aW9uOiA0MCxcblx0XHQvKiogMHg0MDogVGltZXN0YW1wIHNpZ25hdHVyZS5cblx0XHQqIFRoaXMgc2lnbmF0dXJlIGlzIG9ubHkgbWVhbmluZ2Z1bCBmb3IgdGhlIHRpbWVzdGFtcCBjb250YWluZWQgaW5cblx0XHQqIGl0LiAqL1xuXHRcdHRpbWVzdGFtcDogNjQsXG5cdFx0LyoqICAgIDB4NTA6IFRoaXJkLVBhcnR5IENvbmZpcm1hdGlvbiBzaWduYXR1cmUuXG5cdFx0KiBUaGlzIHNpZ25hdHVyZSBpcyBhIHNpZ25hdHVyZSBvdmVyIHNvbWUgb3RoZXIgT3BlblBHUCBTaWduYXR1cmVcblx0XHQqIHBhY2tldChzKS4gIEl0IGlzIGFuYWxvZ291cyB0byBhIG5vdGFyeSBzZWFsIG9uIHRoZSBzaWduZWQgZGF0YS5cblx0XHQqIEEgdGhpcmQtcGFydHkgc2lnbmF0dXJlIFNIT1VMRCBpbmNsdWRlIFNpZ25hdHVyZSBUYXJnZXRcblx0XHQqIHN1YnBhY2tldChzKSB0byBnaXZlIGVhc3kgaWRlbnRpZmljYXRpb24uICBOb3RlIHRoYXQgd2UgcmVhbGx5IGRvXG5cdFx0KiBtZWFuIFNIT1VMRC4gIFRoZXJlIGFyZSBwbGF1c2libGUgdXNlcyBmb3IgdGhpcyAoc3VjaCBhcyBhIGJsaW5kXG5cdFx0KiBwYXJ0eSB0aGF0IG9ubHkgc2VlcyB0aGUgc2lnbmF0dXJlLCBub3QgdGhlIGtleSBvciBzb3VyY2Vcblx0XHQqIGRvY3VtZW50KSB0aGF0IGNhbm5vdCBpbmNsdWRlIGEgdGFyZ2V0IHN1YnBhY2tldC4gKi9cblx0XHR0aGlyZF9wYXJ0eTogODBcblx0fSxcblxuXHQvLyBBc3NlcnRzIHZhbGlkaXR5IGFuZCBjb252ZXJ0cyBmcm9tIHN0cmluZy9pbnRlZ2VyIHRvIGludGVnZXIuXG5cdHdyaXRlOiBmdW5jdGlvbih0eXBlLCBlKSB7XG5cdFx0aWYodHlwZW9mIGUgPT0gJ251bWJlcicpIHtcblx0XHRcdGUgPSB0aGlzLnJlYWQodHlwZSwgZSk7XG5cdFx0fVxuXHRcdFxuXHRcdGlmKHR5cGVbZV0gIT0gdW5kZWZpbmVkKSB7XG5cdFx0XHRyZXR1cm4gdHlwZVtlXTtcblx0XHR9IGVsc2UgdGhyb3cgbmV3IEVycm9yKCdJbnZhbGlkIGVudW0gdmFsdWUuJyk7XG5cdH0sXG5cdC8vIENvbnZlcnRzIGZyb20gYW4gaW50ZWdlciB0byBzdHJpbmcuXG5cdHJlYWQ6IGZ1bmN0aW9uKHR5cGUsIGUpIHtcblx0XHRmb3IodmFyIGkgaW4gdHlwZSlcblx0XHRcdGlmKHR5cGVbaV0gPT0gZSkgcmV0dXJuIGk7XG5cblx0XHR0aHJvdyBuZXcgRXJyb3IoJ0ludmFsaWQgZW51bSB2YWx1ZS4nKTtcblx0fVxufVxuXG5cblxuXG4iLCJcbm1vZHVsZS5leHBvcnRzID0ge1xuXHRjaXBoZXI6IHJlcXVpcmUoJy4vY2lwaGVyJyksXG5cdGhhc2g6IHJlcXVpcmUoJy4vaGFzaCcpLFxuXHRjZmI6IHJlcXVpcmUoJy4vY2ZiLmpzJyksXG5cdHB1YmxpY0tleTogcmVxdWlyZSgnLi9wdWJsaWNfa2V5JyksXG5cdHNpZ25hdHVyZTogcmVxdWlyZSgnLi9zaWduYXR1cmUuanMnKSxcbn1cblxudmFyIGNyeXB0byA9IHJlcXVpcmUoJy4vY3J5cHRvLmpzJyk7XG5cbmZvcih2YXIgaSBpbiBjcnlwdG8pXG5cdG1vZHVsZS5leHBvcnRzW2ldID0gY3J5cHRvW2ldO1xuXG5cblxuIiwiXG5cbnZhciBwYWNrZXRQYXJzZXIgPSByZXF1aXJlKCcuL3BhY2tldC5qcycpLFxuXHRwYWNrZXRzID0gcmVxdWlyZSgnLi9hbGxfcGFja2V0cy5qcycpLFxuXHRlbnVtcyA9IHJlcXVpcmUoJy4uL2VudW1zLmpzJyk7XG5cbi8qKlxuICogQGNsYXNzXG4gKiBAY2xhc3NkZXNjIFRoaXMgY2xhc3MgcmVwcmVzZW50cyBhIGxpc3Qgb2Ygb3BlbnBncCBwYWNrZXRzLlxuICogVGFrZSBjYXJlIHdoZW4gaXRlcmF0aW5nIG92ZXIgaXQgLSB0aGUgcGFja2V0cyB0aGVtc2VsdmVzXG4gKiBhcmUgc3RvcmVkIGFzIG51bWVyaWNhbCBpbmRpY2VzLlxuICovXG5tb2R1bGUuZXhwb3J0cyA9IGZ1bmN0aW9uIHBhY2tldGxpc3QoKSB7XG5cdC8qKiBUaGUgbnVtYmVyIG9mIHBhY2tldHMgY29udGFpbmVkIHdpdGhpbiB0aGUgbGlzdC5cblx0ICogQHJlYWRvbmx5XG5cdCAqIEB0eXBlIHtJbnRlZ2VyfSAqL1xuXHR0aGlzLmxlbmd0aCA9IDA7XG5cblxuXG5cdC8qKlxuXHQgKiBSZWFkcyBhIHN0cmVhbSBvZiBiaW5hcnkgZGF0YSBhbmQgaW50ZXJwcmVudHMgaXQgYXMgYSBsaXN0IG9mIHBhY2tldHMuXG5cdCAqIEBwYXJhbSB7b3BlbnBncF9ieXRlYXJyYXl9IEFuIGFycmF5IG9mIGJ5dGVzLlxuXHQgKi9cblx0dGhpcy5yZWFkID0gZnVuY3Rpb24oYnl0ZXMpIHtcblx0XHR2YXIgaSA9IDA7XG5cblx0XHR3aGlsZShpIDwgYnl0ZXMubGVuZ3RoKSB7XG5cdFx0XHR2YXIgcGFyc2VkID0gcGFja2V0UGFyc2VyLnJlYWQoYnl0ZXMsIGksIGJ5dGVzLmxlbmd0aCAtIGkpO1xuXHRcdFx0aSA9IHBhcnNlZC5vZmZzZXQ7XG5cblx0XHRcdHZhciB0YWcgPSBlbnVtcy5yZWFkKGVudW1zLnBhY2tldCwgcGFyc2VkLnRhZyk7XG5cdFx0XHR2YXIgcGFja2V0ID0gbmV3IHBhY2tldHNbdGFnXSgpO1xuXG5cdFx0XHR0aGlzLnB1c2gocGFja2V0KTtcblxuXHRcdFx0cGFja2V0LnJlYWQocGFyc2VkLnBhY2tldCk7XG5cdFx0fVxuXHR9XG5cblx0LyoqXG5cdCAqIENyZWF0ZXMgYSBiaW5hcnkgcmVwcmVzZW50YXRpb24gb2Ygb3BlbnBncCBvYmplY3RzIGNvbnRhaW5lZCB3aXRoaW4gdGhlXG5cdCAqIGNsYXNzIGluc3RhbmNlLlxuXHQgKiBAcmV0dXJucyB7b3BlbnBncF9ieXRlYXJyYXl9IEFuIGFycmF5IG9mIGJ5dGVzIGNvbnRhaW5pbmcgdmFsaWQgb3BlbnBncCBwYWNrZXRzLlxuXHQgKi9cblx0dGhpcy53cml0ZSA9IGZ1bmN0aW9uKCkge1xuXHRcdHZhciBieXRlcyA9ICcnO1xuXG5cdFx0Zm9yKHZhciBpID0gMDsgaSA8IHRoaXMubGVuZ3RoOyBpKyspIHtcblx0XHRcdHZhciBwYWNrZXRieXRlcyA9IHRoaXNbaV0ud3JpdGUoKTtcblx0XHRcdGJ5dGVzICs9IHBhY2tldFBhcnNlci53cml0ZUhlYWRlcih0aGlzW2ldLnRhZywgcGFja2V0Ynl0ZXMubGVuZ3RoKTtcblx0XHRcdGJ5dGVzICs9IHBhY2tldGJ5dGVzO1xuXHRcdH1cblx0XHRcblx0XHRyZXR1cm4gYnl0ZXM7XG5cdH1cblxuXHQvKipcblx0ICogQWRkcyBhIHBhY2tldCB0byB0aGUgbGlzdC4gVGhpcyBpcyB0aGUgb25seSBzdXBwb3J0ZWQgbWV0aG9kIG9mIGRvaW5nIHNvO1xuXHQgKiB3cml0aW5nIHRvIHBhY2tldGxpc3RbaV0gZGlyZWN0bHkgd2lsbCByZXN1bHQgaW4gYW4gZXJyb3IuXG5cdCAqL1xuXHR0aGlzLnB1c2ggPSBmdW5jdGlvbihwYWNrZXQpIHtcblx0XHRwYWNrZXQucGFja2V0cyA9IG5ldyBwYWNrZXRsaXN0KCk7XG5cblx0XHR0aGlzW3RoaXMubGVuZ3RoXSA9IHBhY2tldDtcblx0XHR0aGlzLmxlbmd0aCsrO1xuXHR9XG5cbn1cbiIsIlxudmFyIGVudW1zID0gcmVxdWlyZSgnLi4vZW51bXMuanMnKTtcblxuLy8gVGhpcyBpcyBwcmV0dHkgdWdseSwgYnV0IGJyb3dzZXJpZnkgbmVlZHMgdG8gaGF2ZSB0aGUgcmVxdWlyZXMgZXhwbGljaXRseSB3cml0dGVuLlxubW9kdWxlLmV4cG9ydHMgPSB7XG5cdGNvbXByZXNzZWQ6IHJlcXVpcmUoJy4vY29tcHJlc3NlZC5qcycpLFxuXHRzeW1fZW5jcnlwdGVkX2ludGVncml0eV9wcm90ZWN0ZWQ6IHJlcXVpcmUoJy4vc3ltX2VuY3J5cHRlZF9pbnRlZ3JpdHlfcHJvdGVjdGVkLmpzJyksXG5cdHB1YmxpY19rZXlfZW5jcnlwdGVkX3Nlc3Npb25fa2V5OiByZXF1aXJlKCcuL3B1YmxpY19rZXlfZW5jcnlwdGVkX3Nlc3Npb25fa2V5LmpzJyksXG5cdHN5bV9lbmNyeXB0ZWRfc2Vzc2lvbl9rZXk6IHJlcXVpcmUoJy4vc3ltX2VuY3J5cHRlZF9zZXNzaW9uX2tleS5qcycpLFxuXHRsaXRlcmFsOiByZXF1aXJlKCcuL2xpdGVyYWwuanMnKSxcblx0cHVibGljX2tleTogcmVxdWlyZSgnLi9wdWJsaWNfa2V5LmpzJyksXG5cdHN5bW1ldHJpY2FsbHlfZW5jcnlwdGVkOiByZXF1aXJlKCcuL3N5bW1ldHJpY2FsbHlfZW5jcnlwdGVkLmpzJyksXG5cdG1hcmtlcjogcmVxdWlyZSgnLi9tYXJrZXIuanMnKSxcblx0cHVibGljX3N1YmtleTogcmVxdWlyZSgnLi9wdWJsaWNfc3Via2V5LmpzJyksXG5cdHVzZXJfYXR0cmlidXRlOiByZXF1aXJlKCcuL3VzZXJfYXR0cmlidXRlLmpzJyksXG5cdG9uZV9wYXNzX3NpZ25hdHVyZTogcmVxdWlyZSgnLi9vbmVfcGFzc19zaWduYXR1cmUuanMnKSxcblx0c2VjcmV0X2tleTogcmVxdWlyZSgnLi9zZWNyZXRfa2V5LmpzJyksXG5cdHVzZXJpZDogcmVxdWlyZSgnLi91c2VyaWQuanMnKSxcblx0c2VjcmV0X3N1YmtleTogcmVxdWlyZSgnLi9zZWNyZXRfc3Via2V5LmpzJyksXG5cdHNpZ25hdHVyZTogcmVxdWlyZSgnLi9zaWduYXR1cmUuanMnKSxcblx0dHJ1c3Q6IHJlcXVpcmUoJy4vdHJ1c3QuanMnKVxufVxuXG5mb3IodmFyIGkgaW4gZW51bXMucGFja2V0KSB7XG5cdHZhciBwYWNrZXRDbGFzcyA9IG1vZHVsZS5leHBvcnRzW2ldO1xuXG5cdGlmKHBhY2tldENsYXNzICE9IHVuZGVmaW5lZClcblx0XHRwYWNrZXRDbGFzcy5wcm90b3R5cGUudGFnID0gZW51bXMucGFja2V0W2ldO1xufVxuIiwiLypcbiAqIENvcHlyaWdodCAoYykgMjAwMy0yMDA1ICBUb20gV3UgKHRqd0Bjcy5TdGFuZm9yZC5FRFUpIFxuICogQWxsIFJpZ2h0cyBSZXNlcnZlZC5cbiAqXG4gKiBNb2RpZmllZCBieSBSZWN1cml0eSBMYWJzIEdtYkggXG4gKiBcbiAqIFBlcm1pc3Npb24gaXMgaGVyZWJ5IGdyYW50ZWQsIGZyZWUgb2YgY2hhcmdlLCB0byBhbnkgcGVyc29uIG9idGFpbmluZ1xuICogYSBjb3B5IG9mIHRoaXMgc29mdHdhcmUgYW5kIGFzc29jaWF0ZWQgZG9jdW1lbnRhdGlvbiBmaWxlcyAodGhlXG4gKiBcIlNvZnR3YXJlXCIpLCB0byBkZWFsIGluIHRoZSBTb2Z0d2FyZSB3aXRob3V0IHJlc3RyaWN0aW9uLCBpbmNsdWRpbmdcbiAqIHdpdGhvdXQgbGltaXRhdGlvbiB0aGUgcmlnaHRzIHRvIHVzZSwgY29weSwgbW9kaWZ5LCBtZXJnZSwgcHVibGlzaCxcbiAqIGRpc3RyaWJ1dGUsIHN1YmxpY2Vuc2UsIGFuZC9vciBzZWxsIGNvcGllcyBvZiB0aGUgU29mdHdhcmUsIGFuZCB0b1xuICogcGVybWl0IHBlcnNvbnMgdG8gd2hvbSB0aGUgU29mdHdhcmUgaXMgZnVybmlzaGVkIHRvIGRvIHNvLCBzdWJqZWN0IHRvXG4gKiB0aGUgZm9sbG93aW5nIGNvbmRpdGlvbnM6XG4gKlxuICogVGhlIGFib3ZlIGNvcHlyaWdodCBub3RpY2UgYW5kIHRoaXMgcGVybWlzc2lvbiBub3RpY2Ugc2hhbGwgYmVcbiAqIGluY2x1ZGVkIGluIGFsbCBjb3BpZXMgb3Igc3Vic3RhbnRpYWwgcG9ydGlvbnMgb2YgdGhlIFNvZnR3YXJlLlxuICpcbiAqIFRIRSBTT0ZUV0FSRSBJUyBQUk9WSURFRCBcIkFTLUlTXCIgQU5EIFdJVEhPVVQgV0FSUkFOVFkgT0YgQU5ZIEtJTkQsIFxuICogRVhQUkVTUywgSU1QTElFRCBPUiBPVEhFUldJU0UsIElOQ0xVRElORyBXSVRIT1VUIExJTUlUQVRJT04sIEFOWSBcbiAqIFdBUlJBTlRZIE9GIE1FUkNIQU5UQUJJTElUWSBPUiBGSVRORVNTIEZPUiBBIFBBUlRJQ1VMQVIgUFVSUE9TRS4gIFxuICpcbiAqIElOIE5PIEVWRU5UIFNIQUxMIFRPTSBXVSBCRSBMSUFCTEUgRk9SIEFOWSBTUEVDSUFMLCBJTkNJREVOVEFMLFxuICogSU5ESVJFQ1QgT1IgQ09OU0VRVUVOVElBTCBEQU1BR0VTIE9GIEFOWSBLSU5ELCBPUiBBTlkgREFNQUdFUyBXSEFUU09FVkVSXG4gKiBSRVNVTFRJTkcgRlJPTSBMT1NTIE9GIFVTRSwgREFUQSBPUiBQUk9GSVRTLCBXSEVUSEVSIE9SIE5PVCBBRFZJU0VEIE9GXG4gKiBUSEUgUE9TU0lCSUxJVFkgT0YgREFNQUdFLCBBTkQgT04gQU5ZIFRIRU9SWSBPRiBMSUFCSUxJVFksIEFSSVNJTkcgT1VUXG4gKiBPRiBPUiBJTiBDT05ORUNUSU9OIFdJVEggVEhFIFVTRSBPUiBQRVJGT1JNQU5DRSBPRiBUSElTIFNPRlRXQVJFLlxuICpcbiAqIEluIGFkZGl0aW9uLCB0aGUgZm9sbG93aW5nIGNvbmRpdGlvbiBhcHBsaWVzOlxuICpcbiAqIEFsbCByZWRpc3RyaWJ1dGlvbnMgbXVzdCByZXRhaW4gYW4gaW50YWN0IGNvcHkgb2YgdGhpcyBjb3B5cmlnaHQgbm90aWNlXG4gKiBhbmQgZGlzY2xhaW1lci5cbiAqL1xuXG5cbnZhciB1dGlsID0gcmVxdWlyZSgnLi4vLi4vdXRpbCcpO1xuXG4vLyBCYXNpYyBKYXZhU2NyaXB0IEJOIGxpYnJhcnkgLSBzdWJzZXQgdXNlZnVsIGZvciBSU0EgZW5jcnlwdGlvbi5cblxuLy8gQml0cyBwZXIgZGlnaXRcbnZhciBkYml0cztcblxuLy8gSmF2YVNjcmlwdCBlbmdpbmUgYW5hbHlzaXNcbnZhciBjYW5hcnkgPSAweGRlYWRiZWVmY2FmZTtcbnZhciBqX2xtID0gKChjYW5hcnkmMHhmZmZmZmYpPT0weGVmY2FmZSk7XG5cbi8vIChwdWJsaWMpIENvbnN0cnVjdG9yXG5mdW5jdGlvbiBCaWdJbnRlZ2VyKGEsYixjKSB7XG4gIGlmKGEgIT0gbnVsbClcbiAgICBpZihcIm51bWJlclwiID09IHR5cGVvZiBhKSB0aGlzLmZyb21OdW1iZXIoYSxiLGMpO1xuICAgIGVsc2UgaWYoYiA9PSBudWxsICYmIFwic3RyaW5nXCIgIT0gdHlwZW9mIGEpIHRoaXMuZnJvbVN0cmluZyhhLDI1Nik7XG4gICAgZWxzZSB0aGlzLmZyb21TdHJpbmcoYSxiKTtcbn1cblxuLy8gcmV0dXJuIG5ldywgdW5zZXQgQmlnSW50ZWdlclxuZnVuY3Rpb24gbmJpKCkgeyByZXR1cm4gbmV3IEJpZ0ludGVnZXIobnVsbCk7IH1cblxuLy8gYW06IENvbXB1dGUgd19qICs9ICh4KnRoaXNfaSksIHByb3BhZ2F0ZSBjYXJyaWVzLFxuLy8gYyBpcyBpbml0aWFsIGNhcnJ5LCByZXR1cm5zIGZpbmFsIGNhcnJ5LlxuLy8gYyA8IDMqZHZhbHVlLCB4IDwgMipkdmFsdWUsIHRoaXNfaSA8IGR2YWx1ZVxuLy8gV2UgbmVlZCB0byBzZWxlY3QgdGhlIGZhc3Rlc3Qgb25lIHRoYXQgd29ya3MgaW4gdGhpcyBlbnZpcm9ubWVudC5cblxuLy8gYW0xOiB1c2UgYSBzaW5nbGUgbXVsdCBhbmQgZGl2aWRlIHRvIGdldCB0aGUgaGlnaCBiaXRzLFxuLy8gbWF4IGRpZ2l0IGJpdHMgc2hvdWxkIGJlIDI2IGJlY2F1c2Vcbi8vIG1heCBpbnRlcm5hbCB2YWx1ZSA9IDIqZHZhbHVlXjItMipkdmFsdWUgKDwgMl41MylcbmZ1bmN0aW9uIGFtMShpLHgsdyxqLGMsbikge1xuICB3aGlsZSgtLW4gPj0gMCkge1xuICAgIHZhciB2ID0geCp0aGlzW2krK10rd1tqXStjO1xuICAgIGMgPSBNYXRoLmZsb29yKHYvMHg0MDAwMDAwKTtcbiAgICB3W2orK10gPSB2JjB4M2ZmZmZmZjtcbiAgfVxuICByZXR1cm4gYztcbn1cbi8vIGFtMiBhdm9pZHMgYSBiaWcgbXVsdC1hbmQtZXh0cmFjdCBjb21wbGV0ZWx5LlxuLy8gTWF4IGRpZ2l0IGJpdHMgc2hvdWxkIGJlIDw9IDMwIGJlY2F1c2Ugd2UgZG8gYml0d2lzZSBvcHNcbi8vIG9uIHZhbHVlcyB1cCB0byAyKmhkdmFsdWVeMi1oZHZhbHVlLTEgKDwgMl4zMSlcbmZ1bmN0aW9uIGFtMihpLHgsdyxqLGMsbikge1xuICB2YXIgeGwgPSB4JjB4N2ZmZiwgeGggPSB4Pj4xNTtcbiAgd2hpbGUoLS1uID49IDApIHtcbiAgICB2YXIgbCA9IHRoaXNbaV0mMHg3ZmZmO1xuICAgIHZhciBoID0gdGhpc1tpKytdPj4xNTtcbiAgICB2YXIgbSA9IHhoKmwraCp4bDtcbiAgICBsID0geGwqbCsoKG0mMHg3ZmZmKTw8MTUpK3dbal0rKGMmMHgzZmZmZmZmZik7XG4gICAgYyA9IChsPj4+MzApKyhtPj4+MTUpK3hoKmgrKGM+Pj4zMCk7XG4gICAgd1tqKytdID0gbCYweDNmZmZmZmZmO1xuICB9XG4gIHJldHVybiBjO1xufVxuLy8gQWx0ZXJuYXRlbHksIHNldCBtYXggZGlnaXQgYml0cyB0byAyOCBzaW5jZSBzb21lXG4vLyBicm93c2VycyBzbG93IGRvd24gd2hlbiBkZWFsaW5nIHdpdGggMzItYml0IG51bWJlcnMuXG5mdW5jdGlvbiBhbTMoaSx4LHcsaixjLG4pIHtcbiAgdmFyIHhsID0geCYweDNmZmYsIHhoID0geD4+MTQ7XG4gIHdoaWxlKC0tbiA+PSAwKSB7XG4gICAgdmFyIGwgPSB0aGlzW2ldJjB4M2ZmZjtcbiAgICB2YXIgaCA9IHRoaXNbaSsrXT4+MTQ7XG4gICAgdmFyIG0gPSB4aCpsK2gqeGw7XG4gICAgbCA9IHhsKmwrKChtJjB4M2ZmZik8PDE0KSt3W2pdK2M7XG4gICAgYyA9IChsPj4yOCkrKG0+PjE0KSt4aCpoO1xuICAgIHdbaisrXSA9IGwmMHhmZmZmZmZmO1xuICB9XG4gIHJldHVybiBjO1xufVxuaWYoal9sbSAmJiAobmF2aWdhdG9yLmFwcE5hbWUgPT0gXCJNaWNyb3NvZnQgSW50ZXJuZXQgRXhwbG9yZXJcIikpIHtcbiAgQmlnSW50ZWdlci5wcm90b3R5cGUuYW0gPSBhbTI7XG4gIGRiaXRzID0gMzA7XG59XG5lbHNlIGlmKGpfbG0gJiYgKG5hdmlnYXRvci5hcHBOYW1lICE9IFwiTmV0c2NhcGVcIikpIHtcbiAgQmlnSW50ZWdlci5wcm90b3R5cGUuYW0gPSBhbTE7XG4gIGRiaXRzID0gMjY7XG59XG5lbHNlIHsgLy8gTW96aWxsYS9OZXRzY2FwZSBzZWVtcyB0byBwcmVmZXIgYW0zXG4gIEJpZ0ludGVnZXIucHJvdG90eXBlLmFtID0gYW0zO1xuICBkYml0cyA9IDI4O1xufVxuXG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5EQiA9IGRiaXRzO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuRE0gPSAoKDE8PGRiaXRzKS0xKTtcbkJpZ0ludGVnZXIucHJvdG90eXBlLkRWID0gKDE8PGRiaXRzKTtcblxudmFyIEJJX0ZQID0gNTI7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5GViA9IE1hdGgucG93KDIsQklfRlApO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuRjEgPSBCSV9GUC1kYml0cztcbkJpZ0ludGVnZXIucHJvdG90eXBlLkYyID0gMipkYml0cy1CSV9GUDtcblxuLy8gRGlnaXQgY29udmVyc2lvbnNcbnZhciBCSV9STSA9IFwiMDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6XCI7XG52YXIgQklfUkMgPSBuZXcgQXJyYXkoKTtcbnZhciBycix2djtcbnJyID0gXCIwXCIuY2hhckNvZGVBdCgwKTtcbmZvcih2diA9IDA7IHZ2IDw9IDk7ICsrdnYpIEJJX1JDW3JyKytdID0gdnY7XG5yciA9IFwiYVwiLmNoYXJDb2RlQXQoMCk7XG5mb3IodnYgPSAxMDsgdnYgPCAzNjsgKyt2dikgQklfUkNbcnIrK10gPSB2djtcbnJyID0gXCJBXCIuY2hhckNvZGVBdCgwKTtcbmZvcih2diA9IDEwOyB2diA8IDM2OyArK3Z2KSBCSV9SQ1tycisrXSA9IHZ2O1xuXG5mdW5jdGlvbiBpbnQyY2hhcihuKSB7IHJldHVybiBCSV9STS5jaGFyQXQobik7IH1cbmZ1bmN0aW9uIGludEF0KHMsaSkge1xuICB2YXIgYyA9IEJJX1JDW3MuY2hhckNvZGVBdChpKV07XG4gIHJldHVybiAoYz09bnVsbCk/LTE6Yztcbn1cblxuLy8gKHByb3RlY3RlZCkgY29weSB0aGlzIHRvIHJcbmZ1bmN0aW9uIGJucENvcHlUbyhyKSB7XG4gIGZvcih2YXIgaSA9IHRoaXMudC0xOyBpID49IDA7IC0taSkgcltpXSA9IHRoaXNbaV07XG4gIHIudCA9IHRoaXMudDtcbiAgci5zID0gdGhpcy5zO1xufVxuXG4vLyAocHJvdGVjdGVkKSBzZXQgZnJvbSBpbnRlZ2VyIHZhbHVlIHgsIC1EViA8PSB4IDwgRFZcbmZ1bmN0aW9uIGJucEZyb21JbnQoeCkge1xuICB0aGlzLnQgPSAxO1xuICB0aGlzLnMgPSAoeDwwKT8tMTowO1xuICBpZih4ID4gMCkgdGhpc1swXSA9IHg7XG4gIGVsc2UgaWYoeCA8IC0xKSB0aGlzWzBdID0geCtEVjtcbiAgZWxzZSB0aGlzLnQgPSAwO1xufVxuXG4vLyByZXR1cm4gYmlnaW50IGluaXRpYWxpemVkIHRvIHZhbHVlXG5mdW5jdGlvbiBuYnYoaSkgeyB2YXIgciA9IG5iaSgpOyByLmZyb21JbnQoaSk7IHJldHVybiByOyB9XG5cbi8vIChwcm90ZWN0ZWQpIHNldCBmcm9tIHN0cmluZyBhbmQgcmFkaXhcbmZ1bmN0aW9uIGJucEZyb21TdHJpbmcocyxiKSB7XG4gIHZhciBrO1xuICBpZihiID09IDE2KSBrID0gNDtcbiAgZWxzZSBpZihiID09IDgpIGsgPSAzO1xuICBlbHNlIGlmKGIgPT0gMjU2KSBrID0gODsgLy8gYnl0ZSBhcnJheVxuICBlbHNlIGlmKGIgPT0gMikgayA9IDE7XG4gIGVsc2UgaWYoYiA9PSAzMikgayA9IDU7XG4gIGVsc2UgaWYoYiA9PSA0KSBrID0gMjtcbiAgZWxzZSB7IHRoaXMuZnJvbVJhZGl4KHMsYik7IHJldHVybjsgfVxuICB0aGlzLnQgPSAwO1xuICB0aGlzLnMgPSAwO1xuICB2YXIgaSA9IHMubGVuZ3RoLCBtaSA9IGZhbHNlLCBzaCA9IDA7XG4gIHdoaWxlKC0taSA+PSAwKSB7XG4gICAgdmFyIHggPSAoaz09OCk/c1tpXSYweGZmOmludEF0KHMsaSk7XG4gICAgaWYoeCA8IDApIHtcbiAgICAgIGlmKHMuY2hhckF0KGkpID09IFwiLVwiKSBtaSA9IHRydWU7XG4gICAgICBjb250aW51ZTtcbiAgICB9XG4gICAgbWkgPSBmYWxzZTtcbiAgICBpZihzaCA9PSAwKVxuICAgICAgdGhpc1t0aGlzLnQrK10gPSB4O1xuICAgIGVsc2UgaWYoc2grayA+IHRoaXMuREIpIHtcbiAgICAgIHRoaXNbdGhpcy50LTFdIHw9ICh4JigoMTw8KHRoaXMuREItc2gpKS0xKSk8PHNoO1xuICAgICAgdGhpc1t0aGlzLnQrK10gPSAoeD4+KHRoaXMuREItc2gpKTtcbiAgICB9XG4gICAgZWxzZVxuICAgICAgdGhpc1t0aGlzLnQtMV0gfD0geDw8c2g7XG4gICAgc2ggKz0gaztcbiAgICBpZihzaCA+PSB0aGlzLkRCKSBzaCAtPSB0aGlzLkRCO1xuICB9XG4gIGlmKGsgPT0gOCAmJiAoc1swXSYweDgwKSAhPSAwKSB7XG4gICAgdGhpcy5zID0gLTE7XG4gICAgaWYoc2ggPiAwKSB0aGlzW3RoaXMudC0xXSB8PSAoKDE8PCh0aGlzLkRCLXNoKSktMSk8PHNoO1xuICB9XG4gIHRoaXMuY2xhbXAoKTtcbiAgaWYobWkpIEJpZ0ludGVnZXIuWkVSTy5zdWJUbyh0aGlzLHRoaXMpO1xufVxuXG4vLyAocHJvdGVjdGVkKSBjbGFtcCBvZmYgZXhjZXNzIGhpZ2ggd29yZHNcbmZ1bmN0aW9uIGJucENsYW1wKCkge1xuICB2YXIgYyA9IHRoaXMucyZ0aGlzLkRNO1xuICB3aGlsZSh0aGlzLnQgPiAwICYmIHRoaXNbdGhpcy50LTFdID09IGMpIC0tdGhpcy50O1xufVxuXG4vLyAocHVibGljKSByZXR1cm4gc3RyaW5nIHJlcHJlc2VudGF0aW9uIGluIGdpdmVuIHJhZGl4XG5mdW5jdGlvbiBiblRvU3RyaW5nKGIpIHtcbiAgaWYodGhpcy5zIDwgMCkgcmV0dXJuIFwiLVwiK3RoaXMubmVnYXRlKCkudG9TdHJpbmcoYik7XG4gIHZhciBrO1xuICBpZihiID09IDE2KSBrID0gNDtcbiAgZWxzZSBpZihiID09IDgpIGsgPSAzO1xuICBlbHNlIGlmKGIgPT0gMikgayA9IDE7XG4gIGVsc2UgaWYoYiA9PSAzMikgayA9IDU7XG4gIGVsc2UgaWYoYiA9PSA0KSBrID0gMjtcbiAgZWxzZSByZXR1cm4gdGhpcy50b1JhZGl4KGIpO1xuICB2YXIga20gPSAoMTw8ayktMSwgZCwgbSA9IGZhbHNlLCByID0gXCJcIiwgaSA9IHRoaXMudDtcbiAgdmFyIHAgPSB0aGlzLkRCLShpKnRoaXMuREIpJWs7XG4gIGlmKGktLSA+IDApIHtcbiAgICBpZihwIDwgdGhpcy5EQiAmJiAoZCA9IHRoaXNbaV0+PnApID4gMCkgeyBtID0gdHJ1ZTsgciA9IGludDJjaGFyKGQpOyB9XG4gICAgd2hpbGUoaSA+PSAwKSB7XG4gICAgICBpZihwIDwgaykge1xuICAgICAgICBkID0gKHRoaXNbaV0mKCgxPDxwKS0xKSk8PChrLXApO1xuICAgICAgICBkIHw9IHRoaXNbLS1pXT4+KHArPXRoaXMuREItayk7XG4gICAgICB9XG4gICAgICBlbHNlIHtcbiAgICAgICAgZCA9ICh0aGlzW2ldPj4ocC09aykpJmttO1xuICAgICAgICBpZihwIDw9IDApIHsgcCArPSB0aGlzLkRCOyAtLWk7IH1cbiAgICAgIH1cbiAgICAgIGlmKGQgPiAwKSBtID0gdHJ1ZTtcbiAgICAgIGlmKG0pIHIgKz0gaW50MmNoYXIoZCk7XG4gICAgfVxuICB9XG4gIHJldHVybiBtP3I6XCIwXCI7XG59XG5cbi8vIChwdWJsaWMpIC10aGlzXG5mdW5jdGlvbiBibk5lZ2F0ZSgpIHsgdmFyIHIgPSBuYmkoKTsgQmlnSW50ZWdlci5aRVJPLnN1YlRvKHRoaXMscik7IHJldHVybiByOyB9XG5cbi8vIChwdWJsaWMpIHx0aGlzfFxuZnVuY3Rpb24gYm5BYnMoKSB7IHJldHVybiAodGhpcy5zPDApP3RoaXMubmVnYXRlKCk6dGhpczsgfVxuXG4vLyAocHVibGljKSByZXR1cm4gKyBpZiB0aGlzID4gYSwgLSBpZiB0aGlzIDwgYSwgMCBpZiBlcXVhbFxuZnVuY3Rpb24gYm5Db21wYXJlVG8oYSkge1xuICB2YXIgciA9IHRoaXMucy1hLnM7XG4gIGlmKHIgIT0gMCkgcmV0dXJuIHI7XG4gIHZhciBpID0gdGhpcy50O1xuICByID0gaS1hLnQ7XG4gIGlmKHIgIT0gMCkgcmV0dXJuIHI7XG4gIHdoaWxlKC0taSA+PSAwKSBpZigocj10aGlzW2ldLWFbaV0pICE9IDApIHJldHVybiByO1xuICByZXR1cm4gMDtcbn1cblxuLy8gcmV0dXJucyBiaXQgbGVuZ3RoIG9mIHRoZSBpbnRlZ2VyIHhcbmZ1bmN0aW9uIG5iaXRzKHgpIHtcbiAgdmFyIHIgPSAxLCB0O1xuICBpZigodD14Pj4+MTYpICE9IDApIHsgeCA9IHQ7IHIgKz0gMTY7IH1cbiAgaWYoKHQ9eD4+OCkgIT0gMCkgeyB4ID0gdDsgciArPSA4OyB9XG4gIGlmKCh0PXg+PjQpICE9IDApIHsgeCA9IHQ7IHIgKz0gNDsgfVxuICBpZigodD14Pj4yKSAhPSAwKSB7IHggPSB0OyByICs9IDI7IH1cbiAgaWYoKHQ9eD4+MSkgIT0gMCkgeyB4ID0gdDsgciArPSAxOyB9XG4gIHJldHVybiByO1xufVxuXG4vLyAocHVibGljKSByZXR1cm4gdGhlIG51bWJlciBvZiBiaXRzIGluIFwidGhpc1wiXG5mdW5jdGlvbiBibkJpdExlbmd0aCgpIHtcbiAgaWYodGhpcy50IDw9IDApIHJldHVybiAwO1xuICByZXR1cm4gdGhpcy5EQioodGhpcy50LTEpK25iaXRzKHRoaXNbdGhpcy50LTFdXih0aGlzLnMmdGhpcy5ETSkpO1xufVxuXG4vLyAocHJvdGVjdGVkKSByID0gdGhpcyA8PCBuKkRCXG5mdW5jdGlvbiBibnBETFNoaWZ0VG8obixyKSB7XG4gIHZhciBpO1xuICBmb3IoaSA9IHRoaXMudC0xOyBpID49IDA7IC0taSkgcltpK25dID0gdGhpc1tpXTtcbiAgZm9yKGkgPSBuLTE7IGkgPj0gMDsgLS1pKSByW2ldID0gMDtcbiAgci50ID0gdGhpcy50K247XG4gIHIucyA9IHRoaXMucztcbn1cblxuLy8gKHByb3RlY3RlZCkgciA9IHRoaXMgPj4gbipEQlxuZnVuY3Rpb24gYm5wRFJTaGlmdFRvKG4scikge1xuICBmb3IodmFyIGkgPSBuOyBpIDwgdGhpcy50OyArK2kpIHJbaS1uXSA9IHRoaXNbaV07XG4gIHIudCA9IE1hdGgubWF4KHRoaXMudC1uLDApO1xuICByLnMgPSB0aGlzLnM7XG59XG5cbi8vIChwcm90ZWN0ZWQpIHIgPSB0aGlzIDw8IG5cbmZ1bmN0aW9uIGJucExTaGlmdFRvKG4scikge1xuICB2YXIgYnMgPSBuJXRoaXMuREI7XG4gIHZhciBjYnMgPSB0aGlzLkRCLWJzO1xuICB2YXIgYm0gPSAoMTw8Y2JzKS0xO1xuICB2YXIgZHMgPSBNYXRoLmZsb29yKG4vdGhpcy5EQiksIGMgPSAodGhpcy5zPDxicykmdGhpcy5ETSwgaTtcbiAgZm9yKGkgPSB0aGlzLnQtMTsgaSA+PSAwOyAtLWkpIHtcbiAgICByW2krZHMrMV0gPSAodGhpc1tpXT4+Y2JzKXxjO1xuICAgIGMgPSAodGhpc1tpXSZibSk8PGJzO1xuICB9XG4gIGZvcihpID0gZHMtMTsgaSA+PSAwOyAtLWkpIHJbaV0gPSAwO1xuICByW2RzXSA9IGM7XG4gIHIudCA9IHRoaXMudCtkcysxO1xuICByLnMgPSB0aGlzLnM7XG4gIHIuY2xhbXAoKTtcbn1cblxuLy8gKHByb3RlY3RlZCkgciA9IHRoaXMgPj4gblxuZnVuY3Rpb24gYm5wUlNoaWZ0VG8obixyKSB7XG4gIHIucyA9IHRoaXMucztcbiAgdmFyIGRzID0gTWF0aC5mbG9vcihuL3RoaXMuREIpO1xuICBpZihkcyA+PSB0aGlzLnQpIHsgci50ID0gMDsgcmV0dXJuOyB9XG4gIHZhciBicyA9IG4ldGhpcy5EQjtcbiAgdmFyIGNicyA9IHRoaXMuREItYnM7XG4gIHZhciBibSA9ICgxPDxicyktMTtcbiAgclswXSA9IHRoaXNbZHNdPj5icztcbiAgZm9yKHZhciBpID0gZHMrMTsgaSA8IHRoaXMudDsgKytpKSB7XG4gICAgcltpLWRzLTFdIHw9ICh0aGlzW2ldJmJtKTw8Y2JzO1xuICAgIHJbaS1kc10gPSB0aGlzW2ldPj5icztcbiAgfVxuICBpZihicyA+IDApIHJbdGhpcy50LWRzLTFdIHw9ICh0aGlzLnMmYm0pPDxjYnM7XG4gIHIudCA9IHRoaXMudC1kcztcbiAgci5jbGFtcCgpO1xufVxuXG4vLyAocHJvdGVjdGVkKSByID0gdGhpcyAtIGFcbmZ1bmN0aW9uIGJucFN1YlRvKGEscikge1xuICB2YXIgaSA9IDAsIGMgPSAwLCBtID0gTWF0aC5taW4oYS50LHRoaXMudCk7XG4gIHdoaWxlKGkgPCBtKSB7XG4gICAgYyArPSB0aGlzW2ldLWFbaV07XG4gICAgcltpKytdID0gYyZ0aGlzLkRNO1xuICAgIGMgPj49IHRoaXMuREI7XG4gIH1cbiAgaWYoYS50IDwgdGhpcy50KSB7XG4gICAgYyAtPSBhLnM7XG4gICAgd2hpbGUoaSA8IHRoaXMudCkge1xuICAgICAgYyArPSB0aGlzW2ldO1xuICAgICAgcltpKytdID0gYyZ0aGlzLkRNO1xuICAgICAgYyA+Pj0gdGhpcy5EQjtcbiAgICB9XG4gICAgYyArPSB0aGlzLnM7XG4gIH1cbiAgZWxzZSB7XG4gICAgYyArPSB0aGlzLnM7XG4gICAgd2hpbGUoaSA8IGEudCkge1xuICAgICAgYyAtPSBhW2ldO1xuICAgICAgcltpKytdID0gYyZ0aGlzLkRNO1xuICAgICAgYyA+Pj0gdGhpcy5EQjtcbiAgICB9XG4gICAgYyAtPSBhLnM7XG4gIH1cbiAgci5zID0gKGM8MCk/LTE6MDtcbiAgaWYoYyA8IC0xKSByW2krK10gPSB0aGlzLkRWK2M7XG4gIGVsc2UgaWYoYyA+IDApIHJbaSsrXSA9IGM7XG4gIHIudCA9IGk7XG4gIHIuY2xhbXAoKTtcbn1cblxuLy8gKHByb3RlY3RlZCkgciA9IHRoaXMgKiBhLCByICE9IHRoaXMsYSAoSEFDIDE0LjEyKVxuLy8gXCJ0aGlzXCIgc2hvdWxkIGJlIHRoZSBsYXJnZXIgb25lIGlmIGFwcHJvcHJpYXRlLlxuZnVuY3Rpb24gYm5wTXVsdGlwbHlUbyhhLHIpIHtcbiAgdmFyIHggPSB0aGlzLmFicygpLCB5ID0gYS5hYnMoKTtcbiAgdmFyIGkgPSB4LnQ7XG4gIHIudCA9IGkreS50O1xuICB3aGlsZSgtLWkgPj0gMCkgcltpXSA9IDA7XG4gIGZvcihpID0gMDsgaSA8IHkudDsgKytpKSByW2kreC50XSA9IHguYW0oMCx5W2ldLHIsaSwwLHgudCk7XG4gIHIucyA9IDA7XG4gIHIuY2xhbXAoKTtcbiAgaWYodGhpcy5zICE9IGEucykgQmlnSW50ZWdlci5aRVJPLnN1YlRvKHIscik7XG59XG5cbi8vIChwcm90ZWN0ZWQpIHIgPSB0aGlzXjIsIHIgIT0gdGhpcyAoSEFDIDE0LjE2KVxuZnVuY3Rpb24gYm5wU3F1YXJlVG8ocikge1xuICB2YXIgeCA9IHRoaXMuYWJzKCk7XG4gIHZhciBpID0gci50ID0gMip4LnQ7XG4gIHdoaWxlKC0taSA+PSAwKSByW2ldID0gMDtcbiAgZm9yKGkgPSAwOyBpIDwgeC50LTE7ICsraSkge1xuICAgIHZhciBjID0geC5hbShpLHhbaV0sciwyKmksMCwxKTtcbiAgICBpZigocltpK3gudF0rPXguYW0oaSsxLDIqeFtpXSxyLDIqaSsxLGMseC50LWktMSkpID49IHguRFYpIHtcbiAgICAgIHJbaSt4LnRdIC09IHguRFY7XG4gICAgICByW2kreC50KzFdID0gMTtcbiAgICB9XG4gIH1cbiAgaWYoci50ID4gMCkgcltyLnQtMV0gKz0geC5hbShpLHhbaV0sciwyKmksMCwxKTtcbiAgci5zID0gMDtcbiAgci5jbGFtcCgpO1xufVxuXG4vLyAocHJvdGVjdGVkKSBkaXZpZGUgdGhpcyBieSBtLCBxdW90aWVudCBhbmQgcmVtYWluZGVyIHRvIHEsIHIgKEhBQyAxNC4yMClcbi8vIHIgIT0gcSwgdGhpcyAhPSBtLiAgcSBvciByIG1heSBiZSBudWxsLlxuZnVuY3Rpb24gYm5wRGl2UmVtVG8obSxxLHIpIHtcbiAgdmFyIHBtID0gbS5hYnMoKTtcbiAgaWYocG0udCA8PSAwKSByZXR1cm47XG4gIHZhciBwdCA9IHRoaXMuYWJzKCk7XG4gIGlmKHB0LnQgPCBwbS50KSB7XG4gICAgaWYocSAhPSBudWxsKSBxLmZyb21JbnQoMCk7XG4gICAgaWYociAhPSBudWxsKSB0aGlzLmNvcHlUbyhyKTtcbiAgICByZXR1cm47XG4gIH1cbiAgaWYociA9PSBudWxsKSByID0gbmJpKCk7XG4gIHZhciB5ID0gbmJpKCksIHRzID0gdGhpcy5zLCBtcyA9IG0ucztcbiAgdmFyIG5zaCA9IHRoaXMuREItbmJpdHMocG1bcG0udC0xXSk7XHQvLyBub3JtYWxpemUgbW9kdWx1c1xuICBpZihuc2ggPiAwKSB7IHBtLmxTaGlmdFRvKG5zaCx5KTsgcHQubFNoaWZ0VG8obnNoLHIpOyB9XG4gIGVsc2UgeyBwbS5jb3B5VG8oeSk7IHB0LmNvcHlUbyhyKTsgfVxuICB2YXIgeXMgPSB5LnQ7XG4gIHZhciB5MCA9IHlbeXMtMV07XG4gIGlmKHkwID09IDApIHJldHVybjtcbiAgdmFyIHl0ID0geTAqKDE8PHRoaXMuRjEpKygoeXM+MSk/eVt5cy0yXT4+dGhpcy5GMjowKTtcbiAgdmFyIGQxID0gdGhpcy5GVi95dCwgZDIgPSAoMTw8dGhpcy5GMSkveXQsIGUgPSAxPDx0aGlzLkYyO1xuICB2YXIgaSA9IHIudCwgaiA9IGkteXMsIHQgPSAocT09bnVsbCk/bmJpKCk6cTtcbiAgeS5kbFNoaWZ0VG8oaix0KTtcbiAgaWYoci5jb21wYXJlVG8odCkgPj0gMCkge1xuICAgIHJbci50KytdID0gMTtcbiAgICByLnN1YlRvKHQscik7XG4gIH1cbiAgQmlnSW50ZWdlci5PTkUuZGxTaGlmdFRvKHlzLHQpO1xuICB0LnN1YlRvKHkseSk7XHQvLyBcIm5lZ2F0aXZlXCIgeSBzbyB3ZSBjYW4gcmVwbGFjZSBzdWIgd2l0aCBhbSBsYXRlclxuICB3aGlsZSh5LnQgPCB5cykgeVt5LnQrK10gPSAwO1xuICB3aGlsZSgtLWogPj0gMCkge1xuICAgIC8vIEVzdGltYXRlIHF1b3RpZW50IGRpZ2l0XG4gICAgdmFyIHFkID0gKHJbLS1pXT09eTApP3RoaXMuRE06TWF0aC5mbG9vcihyW2ldKmQxKyhyW2ktMV0rZSkqZDIpO1xuICAgIGlmKChyW2ldKz15LmFtKDAscWQscixqLDAseXMpKSA8IHFkKSB7XHQvLyBUcnkgaXQgb3V0XG4gICAgICB5LmRsU2hpZnRUbyhqLHQpO1xuICAgICAgci5zdWJUbyh0LHIpO1xuICAgICAgd2hpbGUocltpXSA8IC0tcWQpIHIuc3ViVG8odCxyKTtcbiAgICB9XG4gIH1cbiAgaWYocSAhPSBudWxsKSB7XG4gICAgci5kclNoaWZ0VG8oeXMscSk7XG4gICAgaWYodHMgIT0gbXMpIEJpZ0ludGVnZXIuWkVSTy5zdWJUbyhxLHEpO1xuICB9XG4gIHIudCA9IHlzO1xuICByLmNsYW1wKCk7XG4gIGlmKG5zaCA+IDApIHIuclNoaWZ0VG8obnNoLHIpO1x0Ly8gRGVub3JtYWxpemUgcmVtYWluZGVyXG4gIGlmKHRzIDwgMCkgQmlnSW50ZWdlci5aRVJPLnN1YlRvKHIscik7XG59XG5cbi8vIChwdWJsaWMpIHRoaXMgbW9kIGFcbmZ1bmN0aW9uIGJuTW9kKGEpIHtcbiAgdmFyIHIgPSBuYmkoKTtcbiAgdGhpcy5hYnMoKS5kaXZSZW1UbyhhLG51bGwscik7XG4gIGlmKHRoaXMucyA8IDAgJiYgci5jb21wYXJlVG8oQmlnSW50ZWdlci5aRVJPKSA+IDApIGEuc3ViVG8ocixyKTtcbiAgcmV0dXJuIHI7XG59XG5cbi8vIE1vZHVsYXIgcmVkdWN0aW9uIHVzaW5nIFwiY2xhc3NpY1wiIGFsZ29yaXRobVxuZnVuY3Rpb24gQ2xhc3NpYyhtKSB7IHRoaXMubSA9IG07IH1cbmZ1bmN0aW9uIGNDb252ZXJ0KHgpIHtcbiAgaWYoeC5zIDwgMCB8fCB4LmNvbXBhcmVUbyh0aGlzLm0pID49IDApIHJldHVybiB4Lm1vZCh0aGlzLm0pO1xuICBlbHNlIHJldHVybiB4O1xufVxuZnVuY3Rpb24gY1JldmVydCh4KSB7IHJldHVybiB4OyB9XG5mdW5jdGlvbiBjUmVkdWNlKHgpIHsgeC5kaXZSZW1Ubyh0aGlzLm0sbnVsbCx4KTsgfVxuZnVuY3Rpb24gY011bFRvKHgseSxyKSB7IHgubXVsdGlwbHlUbyh5LHIpOyB0aGlzLnJlZHVjZShyKTsgfVxuZnVuY3Rpb24gY1NxclRvKHgscikgeyB4LnNxdWFyZVRvKHIpOyB0aGlzLnJlZHVjZShyKTsgfVxuXG5DbGFzc2ljLnByb3RvdHlwZS5jb252ZXJ0ID0gY0NvbnZlcnQ7XG5DbGFzc2ljLnByb3RvdHlwZS5yZXZlcnQgPSBjUmV2ZXJ0O1xuQ2xhc3NpYy5wcm90b3R5cGUucmVkdWNlID0gY1JlZHVjZTtcbkNsYXNzaWMucHJvdG90eXBlLm11bFRvID0gY011bFRvO1xuQ2xhc3NpYy5wcm90b3R5cGUuc3FyVG8gPSBjU3FyVG87XG5cbi8vIChwcm90ZWN0ZWQpIHJldHVybiBcIi0xL3RoaXMgJSAyXkRCXCI7IHVzZWZ1bCBmb3IgTW9udC4gcmVkdWN0aW9uXG4vLyBqdXN0aWZpY2F0aW9uOlxuLy8gICAgICAgICB4eSA9PSAxIChtb2QgbSlcbi8vICAgICAgICAgeHkgPSAgMStrbVxuLy8gICB4eSgyLXh5KSA9ICgxK2ttKSgxLWttKVxuLy8geFt5KDIteHkpXSA9IDEta14ybV4yXG4vLyB4W3koMi14eSldID09IDEgKG1vZCBtXjIpXG4vLyBpZiB5IGlzIDEveCBtb2QgbSwgdGhlbiB5KDIteHkpIGlzIDEveCBtb2QgbV4yXG4vLyBzaG91bGQgcmVkdWNlIHggYW5kIHkoMi14eSkgYnkgbV4yIGF0IGVhY2ggc3RlcCB0byBrZWVwIHNpemUgYm91bmRlZC5cbi8vIEpTIG11bHRpcGx5IFwib3ZlcmZsb3dzXCIgZGlmZmVyZW50bHkgZnJvbSBDL0MrKywgc28gY2FyZSBpcyBuZWVkZWQgaGVyZS5cbmZ1bmN0aW9uIGJucEludkRpZ2l0KCkge1xuICBpZih0aGlzLnQgPCAxKSByZXR1cm4gMDtcbiAgdmFyIHggPSB0aGlzWzBdO1xuICBpZigoeCYxKSA9PSAwKSByZXR1cm4gMDtcbiAgdmFyIHkgPSB4JjM7XHRcdC8vIHkgPT0gMS94IG1vZCAyXjJcbiAgeSA9ICh5KigyLSh4JjB4ZikqeSkpJjB4ZjtcdC8vIHkgPT0gMS94IG1vZCAyXjRcbiAgeSA9ICh5KigyLSh4JjB4ZmYpKnkpKSYweGZmO1x0Ly8geSA9PSAxL3ggbW9kIDJeOFxuICB5ID0gKHkqKDItKCgoeCYweGZmZmYpKnkpJjB4ZmZmZikpKSYweGZmZmY7XHQvLyB5ID09IDEveCBtb2QgMl4xNlxuICAvLyBsYXN0IHN0ZXAgLSBjYWxjdWxhdGUgaW52ZXJzZSBtb2QgRFYgZGlyZWN0bHk7XG4gIC8vIGFzc3VtZXMgMTYgPCBEQiA8PSAzMiBhbmQgYXNzdW1lcyBhYmlsaXR5IHRvIGhhbmRsZSA0OC1iaXQgaW50c1xuICB5ID0gKHkqKDIteCp5JXRoaXMuRFYpKSV0aGlzLkRWO1x0XHQvLyB5ID09IDEveCBtb2QgMl5kYml0c1xuICAvLyB3ZSByZWFsbHkgd2FudCB0aGUgbmVnYXRpdmUgaW52ZXJzZSwgYW5kIC1EViA8IHkgPCBEVlxuICByZXR1cm4gKHk+MCk/dGhpcy5EVi15Oi15O1xufVxuXG4vLyBNb250Z29tZXJ5IHJlZHVjdGlvblxuZnVuY3Rpb24gTW9udGdvbWVyeShtKSB7XG4gIHRoaXMubSA9IG07XG4gIHRoaXMubXAgPSBtLmludkRpZ2l0KCk7XG4gIHRoaXMubXBsID0gdGhpcy5tcCYweDdmZmY7XG4gIHRoaXMubXBoID0gdGhpcy5tcD4+MTU7XG4gIHRoaXMudW0gPSAoMTw8KG0uREItMTUpKS0xO1xuICB0aGlzLm10MiA9IDIqbS50O1xufVxuXG4vLyB4UiBtb2QgbVxuZnVuY3Rpb24gbW9udENvbnZlcnQoeCkge1xuICB2YXIgciA9IG5iaSgpO1xuICB4LmFicygpLmRsU2hpZnRUbyh0aGlzLm0udCxyKTtcbiAgci5kaXZSZW1Ubyh0aGlzLm0sbnVsbCxyKTtcbiAgaWYoeC5zIDwgMCAmJiByLmNvbXBhcmVUbyhCaWdJbnRlZ2VyLlpFUk8pID4gMCkgdGhpcy5tLnN1YlRvKHIscik7XG4gIHJldHVybiByO1xufVxuXG4vLyB4L1IgbW9kIG1cbmZ1bmN0aW9uIG1vbnRSZXZlcnQoeCkge1xuICB2YXIgciA9IG5iaSgpO1xuICB4LmNvcHlUbyhyKTtcbiAgdGhpcy5yZWR1Y2Uocik7XG4gIHJldHVybiByO1xufVxuXG4vLyB4ID0geC9SIG1vZCBtIChIQUMgMTQuMzIpXG5mdW5jdGlvbiBtb250UmVkdWNlKHgpIHtcbiAgd2hpbGUoeC50IDw9IHRoaXMubXQyKVx0Ly8gcGFkIHggc28gYW0gaGFzIGVub3VnaCByb29tIGxhdGVyXG4gICAgeFt4LnQrK10gPSAwO1xuICBmb3IodmFyIGkgPSAwOyBpIDwgdGhpcy5tLnQ7ICsraSkge1xuICAgIC8vIGZhc3RlciB3YXkgb2YgY2FsY3VsYXRpbmcgdTAgPSB4W2ldKm1wIG1vZCBEVlxuICAgIHZhciBqID0geFtpXSYweDdmZmY7XG4gICAgdmFyIHUwID0gKGoqdGhpcy5tcGwrKCgoaip0aGlzLm1waCsoeFtpXT4+MTUpKnRoaXMubXBsKSZ0aGlzLnVtKTw8MTUpKSZ4LkRNO1xuICAgIC8vIHVzZSBhbSB0byBjb21iaW5lIHRoZSBtdWx0aXBseS1zaGlmdC1hZGQgaW50byBvbmUgY2FsbFxuICAgIGogPSBpK3RoaXMubS50O1xuICAgIHhbal0gKz0gdGhpcy5tLmFtKDAsdTAseCxpLDAsdGhpcy5tLnQpO1xuICAgIC8vIHByb3BhZ2F0ZSBjYXJyeVxuICAgIHdoaWxlKHhbal0gPj0geC5EVikgeyB4W2pdIC09IHguRFY7IHhbKytqXSsrOyB9XG4gIH1cbiAgeC5jbGFtcCgpO1xuICB4LmRyU2hpZnRUbyh0aGlzLm0udCx4KTtcbiAgaWYoeC5jb21wYXJlVG8odGhpcy5tKSA+PSAwKSB4LnN1YlRvKHRoaXMubSx4KTtcbn1cblxuLy8gciA9IFwieF4yL1IgbW9kIG1cIjsgeCAhPSByXG5mdW5jdGlvbiBtb250U3FyVG8oeCxyKSB7IHguc3F1YXJlVG8ocik7IHRoaXMucmVkdWNlKHIpOyB9XG5cbi8vIHIgPSBcInh5L1IgbW9kIG1cIjsgeCx5ICE9IHJcbmZ1bmN0aW9uIG1vbnRNdWxUbyh4LHkscikgeyB4Lm11bHRpcGx5VG8oeSxyKTsgdGhpcy5yZWR1Y2Uocik7IH1cblxuTW9udGdvbWVyeS5wcm90b3R5cGUuY29udmVydCA9IG1vbnRDb252ZXJ0O1xuTW9udGdvbWVyeS5wcm90b3R5cGUucmV2ZXJ0ID0gbW9udFJldmVydDtcbk1vbnRnb21lcnkucHJvdG90eXBlLnJlZHVjZSA9IG1vbnRSZWR1Y2U7XG5Nb250Z29tZXJ5LnByb3RvdHlwZS5tdWxUbyA9IG1vbnRNdWxUbztcbk1vbnRnb21lcnkucHJvdG90eXBlLnNxclRvID0gbW9udFNxclRvO1xuXG4vLyAocHJvdGVjdGVkKSB0cnVlIGlmZiB0aGlzIGlzIGV2ZW5cbmZ1bmN0aW9uIGJucElzRXZlbigpIHsgcmV0dXJuICgodGhpcy50PjApPyh0aGlzWzBdJjEpOnRoaXMucykgPT0gMDsgfVxuXG4vLyAocHJvdGVjdGVkKSB0aGlzXmUsIGUgPCAyXjMyLCBkb2luZyBzcXIgYW5kIG11bCB3aXRoIFwiclwiIChIQUMgMTQuNzkpXG5mdW5jdGlvbiBibnBFeHAoZSx6KSB7XG4gIGlmKGUgPiAweGZmZmZmZmZmIHx8IGUgPCAxKSByZXR1cm4gQmlnSW50ZWdlci5PTkU7XG4gIHZhciByID0gbmJpKCksIHIyID0gbmJpKCksIGcgPSB6LmNvbnZlcnQodGhpcyksIGkgPSBuYml0cyhlKS0xO1xuICBnLmNvcHlUbyhyKTtcbiAgd2hpbGUoLS1pID49IDApIHtcbiAgICB6LnNxclRvKHIscjIpO1xuICAgIGlmKChlJigxPDxpKSkgPiAwKSB6Lm11bFRvKHIyLGcscik7XG4gICAgZWxzZSB7IHZhciB0ID0gcjsgciA9IHIyOyByMiA9IHQ7IH1cbiAgfVxuICByZXR1cm4gei5yZXZlcnQocik7XG59XG5cbi8vIChwdWJsaWMpIHRoaXNeZSAlIG0sIDAgPD0gZSA8IDJeMzJcbmZ1bmN0aW9uIGJuTW9kUG93SW50KGUsbSkge1xuICB2YXIgejtcbiAgaWYoZSA8IDI1NiB8fCBtLmlzRXZlbigpKSB6ID0gbmV3IENsYXNzaWMobSk7IGVsc2UgeiA9IG5ldyBNb250Z29tZXJ5KG0pO1xuICByZXR1cm4gdGhpcy5leHAoZSx6KTtcbn1cblxuLy8gcHJvdGVjdGVkXG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5jb3B5VG8gPSBibnBDb3B5VG87XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5mcm9tSW50ID0gYm5wRnJvbUludDtcbkJpZ0ludGVnZXIucHJvdG90eXBlLmZyb21TdHJpbmcgPSBibnBGcm9tU3RyaW5nO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuY2xhbXAgPSBibnBDbGFtcDtcbkJpZ0ludGVnZXIucHJvdG90eXBlLmRsU2hpZnRUbyA9IGJucERMU2hpZnRUbztcbkJpZ0ludGVnZXIucHJvdG90eXBlLmRyU2hpZnRUbyA9IGJucERSU2hpZnRUbztcbkJpZ0ludGVnZXIucHJvdG90eXBlLmxTaGlmdFRvID0gYm5wTFNoaWZ0VG87XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5yU2hpZnRUbyA9IGJucFJTaGlmdFRvO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuc3ViVG8gPSBibnBTdWJUbztcbkJpZ0ludGVnZXIucHJvdG90eXBlLm11bHRpcGx5VG8gPSBibnBNdWx0aXBseVRvO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuc3F1YXJlVG8gPSBibnBTcXVhcmVUbztcbkJpZ0ludGVnZXIucHJvdG90eXBlLmRpdlJlbVRvID0gYm5wRGl2UmVtVG87XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5pbnZEaWdpdCA9IGJucEludkRpZ2l0O1xuQmlnSW50ZWdlci5wcm90b3R5cGUuaXNFdmVuID0gYm5wSXNFdmVuO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuZXhwID0gYm5wRXhwO1xuXG4vLyBwdWJsaWNcbkJpZ0ludGVnZXIucHJvdG90eXBlLnRvU3RyaW5nID0gYm5Ub1N0cmluZztcbkJpZ0ludGVnZXIucHJvdG90eXBlLm5lZ2F0ZSA9IGJuTmVnYXRlO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuYWJzID0gYm5BYnM7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5jb21wYXJlVG8gPSBibkNvbXBhcmVUbztcbkJpZ0ludGVnZXIucHJvdG90eXBlLmJpdExlbmd0aCA9IGJuQml0TGVuZ3RoO1xuQmlnSW50ZWdlci5wcm90b3R5cGUubW9kID0gYm5Nb2Q7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5tb2RQb3dJbnQgPSBibk1vZFBvd0ludDtcblxuLy8gXCJjb25zdGFudHNcIlxuQmlnSW50ZWdlci5aRVJPID0gbmJ2KDApO1xuQmlnSW50ZWdlci5PTkUgPSBuYnYoMSk7XG5cbm1vZHVsZS5leHBvcnRzID0gQmlnSW50ZWdlcjtcblxuXG5cblxuXG5cblxuXG5cblxuXG5cblxuXG5cblxuXG5cblxuLypcbiAqIENvcHlyaWdodCAoYykgMjAwMy0yMDA1ICBUb20gV3UgKHRqd0Bjcy5TdGFuZm9yZC5FRFUpIFxuICogQWxsIFJpZ2h0cyBSZXNlcnZlZC5cbiAqXG4gKiBNb2RpZmllZCBieSBSZWN1cml0eSBMYWJzIEdtYkhcbiAqXG4gKiBQZXJtaXNzaW9uIGlzIGhlcmVieSBncmFudGVkLCBmcmVlIG9mIGNoYXJnZSwgdG8gYW55IHBlcnNvbiBvYnRhaW5pbmdcbiAqIGEgY29weSBvZiB0aGlzIHNvZnR3YXJlIGFuZCBhc3NvY2lhdGVkIGRvY3VtZW50YXRpb24gZmlsZXMgKHRoZVxuICogXCJTb2Z0d2FyZVwiKSwgdG8gZGVhbCBpbiB0aGUgU29mdHdhcmUgd2l0aG91dCByZXN0cmljdGlvbiwgaW5jbHVkaW5nXG4gKiB3aXRob3V0IGxpbWl0YXRpb24gdGhlIHJpZ2h0cyB0byB1c2UsIGNvcHksIG1vZGlmeSwgbWVyZ2UsIHB1Ymxpc2gsXG4gKiBkaXN0cmlidXRlLCBzdWJsaWNlbnNlLCBhbmQvb3Igc2VsbCBjb3BpZXMgb2YgdGhlIFNvZnR3YXJlLCBhbmQgdG9cbiAqIHBlcm1pdCBwZXJzb25zIHRvIHdob20gdGhlIFNvZnR3YXJlIGlzIGZ1cm5pc2hlZCB0byBkbyBzbywgc3ViamVjdCB0b1xuICogdGhlIGZvbGxvd2luZyBjb25kaXRpb25zOlxuICpcbiAqIFRoZSBhYm92ZSBjb3B5cmlnaHQgbm90aWNlIGFuZCB0aGlzIHBlcm1pc3Npb24gbm90aWNlIHNoYWxsIGJlXG4gKiBpbmNsdWRlZCBpbiBhbGwgY29waWVzIG9yIHN1YnN0YW50aWFsIHBvcnRpb25zIG9mIHRoZSBTb2Z0d2FyZS5cbiAqXG4gKiBUSEUgU09GVFdBUkUgSVMgUFJPVklERUQgXCJBUy1JU1wiIEFORCBXSVRIT1VUIFdBUlJBTlRZIE9GIEFOWSBLSU5ELCBcbiAqIEVYUFJFU1MsIElNUExJRUQgT1IgT1RIRVJXSVNFLCBJTkNMVURJTkcgV0lUSE9VVCBMSU1JVEFUSU9OLCBBTlkgXG4gKiBXQVJSQU5UWSBPRiBNRVJDSEFOVEFCSUxJVFkgT1IgRklUTkVTUyBGT1IgQSBQQVJUSUNVTEFSIFBVUlBPU0UuICBcbiAqXG4gKiBJTiBOTyBFVkVOVCBTSEFMTCBUT00gV1UgQkUgTElBQkxFIEZPUiBBTlkgU1BFQ0lBTCwgSU5DSURFTlRBTCxcbiAqIElORElSRUNUIE9SIENPTlNFUVVFTlRJQUwgREFNQUdFUyBPRiBBTlkgS0lORCwgT1IgQU5ZIERBTUFHRVMgV0hBVFNPRVZFUlxuICogUkVTVUxUSU5HIEZST00gTE9TUyBPRiBVU0UsIERBVEEgT1IgUFJPRklUUywgV0hFVEhFUiBPUiBOT1QgQURWSVNFRCBPRlxuICogVEhFIFBPU1NJQklMSVRZIE9GIERBTUFHRSwgQU5EIE9OIEFOWSBUSEVPUlkgT0YgTElBQklMSVRZLCBBUklTSU5HIE9VVFxuICogT0YgT1IgSU4gQ09OTkVDVElPTiBXSVRIIFRIRSBVU0UgT1IgUEVSRk9STUFOQ0UgT0YgVEhJUyBTT0ZUV0FSRS5cbiAqXG4gKiBJbiBhZGRpdGlvbiwgdGhlIGZvbGxvd2luZyBjb25kaXRpb24gYXBwbGllczpcbiAqXG4gKiBBbGwgcmVkaXN0cmlidXRpb25zIG11c3QgcmV0YWluIGFuIGludGFjdCBjb3B5IG9mIHRoaXMgY29weXJpZ2h0IG5vdGljZVxuICogYW5kIGRpc2NsYWltZXIuXG4gKi9cblxuXG4vLyBFeHRlbmRlZCBKYXZhU2NyaXB0IEJOIGZ1bmN0aW9ucywgcmVxdWlyZWQgZm9yIFJTQSBwcml2YXRlIG9wcy5cblxuLy8gVmVyc2lvbiAxLjE6IG5ldyBCaWdJbnRlZ2VyKFwiMFwiLCAxMCkgcmV0dXJucyBcInByb3BlclwiIHplcm9cbi8vIFZlcnNpb24gMS4yOiBzcXVhcmUoKSBBUEksIGlzUHJvYmFibGVQcmltZSBmaXhcblxuLy8gKHB1YmxpYylcbmZ1bmN0aW9uIGJuQ2xvbmUoKSB7IHZhciByID0gbmJpKCk7IHRoaXMuY29weVRvKHIpOyByZXR1cm4gcjsgfVxuXG4vLyAocHVibGljKSByZXR1cm4gdmFsdWUgYXMgaW50ZWdlclxuZnVuY3Rpb24gYm5JbnRWYWx1ZSgpIHtcbiAgaWYodGhpcy5zIDwgMCkge1xuICAgIGlmKHRoaXMudCA9PSAxKSByZXR1cm4gdGhpc1swXS10aGlzLkRWO1xuICAgIGVsc2UgaWYodGhpcy50ID09IDApIHJldHVybiAtMTtcbiAgfVxuICBlbHNlIGlmKHRoaXMudCA9PSAxKSByZXR1cm4gdGhpc1swXTtcbiAgZWxzZSBpZih0aGlzLnQgPT0gMCkgcmV0dXJuIDA7XG4gIC8vIGFzc3VtZXMgMTYgPCBEQiA8IDMyXG4gIHJldHVybiAoKHRoaXNbMV0mKCgxPDwoMzItdGhpcy5EQikpLTEpKTw8dGhpcy5EQil8dGhpc1swXTtcbn1cblxuLy8gKHB1YmxpYykgcmV0dXJuIHZhbHVlIGFzIGJ5dGVcbmZ1bmN0aW9uIGJuQnl0ZVZhbHVlKCkgeyByZXR1cm4gKHRoaXMudD09MCk/dGhpcy5zOih0aGlzWzBdPDwyNCk+PjI0OyB9XG5cbi8vIChwdWJsaWMpIHJldHVybiB2YWx1ZSBhcyBzaG9ydCAoYXNzdW1lcyBEQj49MTYpXG5mdW5jdGlvbiBiblNob3J0VmFsdWUoKSB7IHJldHVybiAodGhpcy50PT0wKT90aGlzLnM6KHRoaXNbMF08PDE2KT4+MTY7IH1cblxuLy8gKHByb3RlY3RlZCkgcmV0dXJuIHggcy50LiByXnggPCBEVlxuZnVuY3Rpb24gYm5wQ2h1bmtTaXplKHIpIHsgcmV0dXJuIE1hdGguZmxvb3IoTWF0aC5MTjIqdGhpcy5EQi9NYXRoLmxvZyhyKSk7IH1cblxuLy8gKHB1YmxpYykgMCBpZiB0aGlzID09IDAsIDEgaWYgdGhpcyA+IDBcbmZ1bmN0aW9uIGJuU2lnTnVtKCkge1xuICBpZih0aGlzLnMgPCAwKSByZXR1cm4gLTE7XG4gIGVsc2UgaWYodGhpcy50IDw9IDAgfHwgKHRoaXMudCA9PSAxICYmIHRoaXNbMF0gPD0gMCkpIHJldHVybiAwO1xuICBlbHNlIHJldHVybiAxO1xufVxuXG4vLyAocHJvdGVjdGVkKSBjb252ZXJ0IHRvIHJhZGl4IHN0cmluZ1xuZnVuY3Rpb24gYm5wVG9SYWRpeChiKSB7XG4gIGlmKGIgPT0gbnVsbCkgYiA9IDEwO1xuICBpZih0aGlzLnNpZ251bSgpID09IDAgfHwgYiA8IDIgfHwgYiA+IDM2KSByZXR1cm4gXCIwXCI7XG4gIHZhciBjcyA9IHRoaXMuY2h1bmtTaXplKGIpO1xuICB2YXIgYSA9IE1hdGgucG93KGIsY3MpO1xuICB2YXIgZCA9IG5idihhKSwgeSA9IG5iaSgpLCB6ID0gbmJpKCksIHIgPSBcIlwiO1xuICB0aGlzLmRpdlJlbVRvKGQseSx6KTtcbiAgd2hpbGUoeS5zaWdudW0oKSA+IDApIHtcbiAgICByID0gKGErei5pbnRWYWx1ZSgpKS50b1N0cmluZyhiKS5zdWJzdHIoMSkgKyByO1xuICAgIHkuZGl2UmVtVG8oZCx5LHopO1xuICB9XG4gIHJldHVybiB6LmludFZhbHVlKCkudG9TdHJpbmcoYikgKyByO1xufVxuXG4vLyAocHJvdGVjdGVkKSBjb252ZXJ0IGZyb20gcmFkaXggc3RyaW5nXG5mdW5jdGlvbiBibnBGcm9tUmFkaXgocyxiKSB7XG4gIHRoaXMuZnJvbUludCgwKTtcbiAgaWYoYiA9PSBudWxsKSBiID0gMTA7XG4gIHZhciBjcyA9IHRoaXMuY2h1bmtTaXplKGIpO1xuICB2YXIgZCA9IE1hdGgucG93KGIsY3MpLCBtaSA9IGZhbHNlLCBqID0gMCwgdyA9IDA7XG4gIGZvcih2YXIgaSA9IDA7IGkgPCBzLmxlbmd0aDsgKytpKSB7XG4gICAgdmFyIHggPSBpbnRBdChzLGkpO1xuICAgIGlmKHggPCAwKSB7XG4gICAgICBpZihzLmNoYXJBdChpKSA9PSBcIi1cIiAmJiB0aGlzLnNpZ251bSgpID09IDApIG1pID0gdHJ1ZTtcbiAgICAgIGNvbnRpbnVlO1xuICAgIH1cbiAgICB3ID0gYip3K3g7XG4gICAgaWYoKytqID49IGNzKSB7XG4gICAgICB0aGlzLmRNdWx0aXBseShkKTtcbiAgICAgIHRoaXMuZEFkZE9mZnNldCh3LDApO1xuICAgICAgaiA9IDA7XG4gICAgICB3ID0gMDtcbiAgICB9XG4gIH1cbiAgaWYoaiA+IDApIHtcbiAgICB0aGlzLmRNdWx0aXBseShNYXRoLnBvdyhiLGopKTtcbiAgICB0aGlzLmRBZGRPZmZzZXQodywwKTtcbiAgfVxuICBpZihtaSkgQmlnSW50ZWdlci5aRVJPLnN1YlRvKHRoaXMsdGhpcyk7XG59XG5cbi8vIChwcm90ZWN0ZWQpIGFsdGVybmF0ZSBjb25zdHJ1Y3RvclxuZnVuY3Rpb24gYm5wRnJvbU51bWJlcihhLGIsYykge1xuICBpZihcIm51bWJlclwiID09IHR5cGVvZiBiKSB7XG4gICAgLy8gbmV3IEJpZ0ludGVnZXIoaW50LGludCxSTkcpXG4gICAgaWYoYSA8IDIpIHRoaXMuZnJvbUludCgxKTtcbiAgICBlbHNlIHtcbiAgICAgIHRoaXMuZnJvbU51bWJlcihhLGMpO1xuICAgICAgaWYoIXRoaXMudGVzdEJpdChhLTEpKVx0Ly8gZm9yY2UgTVNCIHNldFxuICAgICAgICB0aGlzLmJpdHdpc2VUbyhCaWdJbnRlZ2VyLk9ORS5zaGlmdExlZnQoYS0xKSxvcF9vcix0aGlzKTtcbiAgICAgIGlmKHRoaXMuaXNFdmVuKCkpIHRoaXMuZEFkZE9mZnNldCgxLDApOyAvLyBmb3JjZSBvZGRcbiAgICAgIHdoaWxlKCF0aGlzLmlzUHJvYmFibGVQcmltZShiKSkge1xuICAgICAgICB0aGlzLmRBZGRPZmZzZXQoMiwwKTtcbiAgICAgICAgaWYodGhpcy5iaXRMZW5ndGgoKSA+IGEpIHRoaXMuc3ViVG8oQmlnSW50ZWdlci5PTkUuc2hpZnRMZWZ0KGEtMSksdGhpcyk7XG4gICAgICB9XG4gICAgfVxuICB9XG4gIGVsc2Uge1xuICAgIC8vIG5ldyBCaWdJbnRlZ2VyKGludCxSTkcpXG4gICAgdmFyIHggPSBuZXcgQXJyYXkoKSwgdCA9IGEmNztcbiAgICB4Lmxlbmd0aCA9IChhPj4zKSsxO1xuICAgIGIubmV4dEJ5dGVzKHgpO1xuICAgIGlmKHQgPiAwKSB4WzBdICY9ICgoMTw8dCktMSk7IGVsc2UgeFswXSA9IDA7XG4gICAgdGhpcy5mcm9tU3RyaW5nKHgsMjU2KTtcbiAgfVxufVxuXG4vLyAocHVibGljKSBjb252ZXJ0IHRvIGJpZ2VuZGlhbiBieXRlIGFycmF5XG5mdW5jdGlvbiBiblRvQnl0ZUFycmF5KCkge1xuICB2YXIgaSA9IHRoaXMudCwgciA9IG5ldyBBcnJheSgpO1xuICByWzBdID0gdGhpcy5zO1xuICB2YXIgcCA9IHRoaXMuREItKGkqdGhpcy5EQiklOCwgZCwgayA9IDA7XG4gIGlmKGktLSA+IDApIHtcbiAgICBpZihwIDwgdGhpcy5EQiAmJiAoZCA9IHRoaXNbaV0+PnApICE9ICh0aGlzLnMmdGhpcy5ETSk+PnApXG4gICAgICByW2srK10gPSBkfCh0aGlzLnM8PCh0aGlzLkRCLXApKTtcbiAgICB3aGlsZShpID49IDApIHtcbiAgICAgIGlmKHAgPCA4KSB7XG4gICAgICAgIGQgPSAodGhpc1tpXSYoKDE8PHApLTEpKTw8KDgtcCk7XG4gICAgICAgIGQgfD0gdGhpc1stLWldPj4ocCs9dGhpcy5EQi04KTtcbiAgICAgIH1cbiAgICAgIGVsc2Uge1xuICAgICAgICBkID0gKHRoaXNbaV0+PihwLT04KSkmMHhmZjtcbiAgICAgICAgaWYocCA8PSAwKSB7IHAgKz0gdGhpcy5EQjsgLS1pOyB9XG4gICAgICB9XG4gICAgICAvL2lmKChkJjB4ODApICE9IDApIGQgfD0gLTI1NjtcbiAgICAgIC8vaWYoayA9PSAwICYmICh0aGlzLnMmMHg4MCkgIT0gKGQmMHg4MCkpICsraztcbiAgICAgIGlmKGsgPiAwIHx8IGQgIT0gdGhpcy5zKSByW2srK10gPSBkO1xuICAgIH1cbiAgfVxuICByZXR1cm4gcjtcbn1cblxuZnVuY3Rpb24gYm5FcXVhbHMoYSkgeyByZXR1cm4odGhpcy5jb21wYXJlVG8oYSk9PTApOyB9XG5mdW5jdGlvbiBibk1pbihhKSB7IHJldHVybih0aGlzLmNvbXBhcmVUbyhhKTwwKT90aGlzOmE7IH1cbmZ1bmN0aW9uIGJuTWF4KGEpIHsgcmV0dXJuKHRoaXMuY29tcGFyZVRvKGEpPjApP3RoaXM6YTsgfVxuXG4vLyAocHJvdGVjdGVkKSByID0gdGhpcyBvcCBhIChiaXR3aXNlKVxuZnVuY3Rpb24gYm5wQml0d2lzZVRvKGEsb3Ascikge1xuICB2YXIgaSwgZiwgbSA9IE1hdGgubWluKGEudCx0aGlzLnQpO1xuICBmb3IoaSA9IDA7IGkgPCBtOyArK2kpIHJbaV0gPSBvcCh0aGlzW2ldLGFbaV0pO1xuICBpZihhLnQgPCB0aGlzLnQpIHtcbiAgICBmID0gYS5zJnRoaXMuRE07XG4gICAgZm9yKGkgPSBtOyBpIDwgdGhpcy50OyArK2kpIHJbaV0gPSBvcCh0aGlzW2ldLGYpO1xuICAgIHIudCA9IHRoaXMudDtcbiAgfVxuICBlbHNlIHtcbiAgICBmID0gdGhpcy5zJnRoaXMuRE07XG4gICAgZm9yKGkgPSBtOyBpIDwgYS50OyArK2kpIHJbaV0gPSBvcChmLGFbaV0pO1xuICAgIHIudCA9IGEudDtcbiAgfVxuICByLnMgPSBvcCh0aGlzLnMsYS5zKTtcbiAgci5jbGFtcCgpO1xufVxuXG4vLyAocHVibGljKSB0aGlzICYgYVxuZnVuY3Rpb24gb3BfYW5kKHgseSkgeyByZXR1cm4geCZ5OyB9XG5mdW5jdGlvbiBibkFuZChhKSB7IHZhciByID0gbmJpKCk7IHRoaXMuYml0d2lzZVRvKGEsb3BfYW5kLHIpOyByZXR1cm4gcjsgfVxuXG4vLyAocHVibGljKSB0aGlzIHwgYVxuZnVuY3Rpb24gb3Bfb3IoeCx5KSB7IHJldHVybiB4fHk7IH1cbmZ1bmN0aW9uIGJuT3IoYSkgeyB2YXIgciA9IG5iaSgpOyB0aGlzLmJpdHdpc2VUbyhhLG9wX29yLHIpOyByZXR1cm4gcjsgfVxuXG4vLyAocHVibGljKSB0aGlzIF4gYVxuZnVuY3Rpb24gb3BfeG9yKHgseSkgeyByZXR1cm4geF55OyB9XG5mdW5jdGlvbiBiblhvcihhKSB7IHZhciByID0gbmJpKCk7IHRoaXMuYml0d2lzZVRvKGEsb3BfeG9yLHIpOyByZXR1cm4gcjsgfVxuXG4vLyAocHVibGljKSB0aGlzICYgfmFcbmZ1bmN0aW9uIG9wX2FuZG5vdCh4LHkpIHsgcmV0dXJuIHgmfnk7IH1cbmZ1bmN0aW9uIGJuQW5kTm90KGEpIHsgdmFyIHIgPSBuYmkoKTsgdGhpcy5iaXR3aXNlVG8oYSxvcF9hbmRub3Qscik7IHJldHVybiByOyB9XG5cbi8vIChwdWJsaWMpIH50aGlzXG5mdW5jdGlvbiBibk5vdCgpIHtcbiAgdmFyIHIgPSBuYmkoKTtcbiAgZm9yKHZhciBpID0gMDsgaSA8IHRoaXMudDsgKytpKSByW2ldID0gdGhpcy5ETSZ+dGhpc1tpXTtcbiAgci50ID0gdGhpcy50O1xuICByLnMgPSB+dGhpcy5zO1xuICByZXR1cm4gcjtcbn1cblxuLy8gKHB1YmxpYykgdGhpcyA8PCBuXG5mdW5jdGlvbiBiblNoaWZ0TGVmdChuKSB7XG4gIHZhciByID0gbmJpKCk7XG4gIGlmKG4gPCAwKSB0aGlzLnJTaGlmdFRvKC1uLHIpOyBlbHNlIHRoaXMubFNoaWZ0VG8obixyKTtcbiAgcmV0dXJuIHI7XG59XG5cbi8vIChwdWJsaWMpIHRoaXMgPj4gblxuZnVuY3Rpb24gYm5TaGlmdFJpZ2h0KG4pIHtcbiAgdmFyIHIgPSBuYmkoKTtcbiAgaWYobiA8IDApIHRoaXMubFNoaWZ0VG8oLW4scik7IGVsc2UgdGhpcy5yU2hpZnRUbyhuLHIpO1xuICByZXR1cm4gcjtcbn1cblxuLy8gcmV0dXJuIGluZGV4IG9mIGxvd2VzdCAxLWJpdCBpbiB4LCB4IDwgMl4zMVxuZnVuY3Rpb24gbGJpdCh4KSB7XG4gIGlmKHggPT0gMCkgcmV0dXJuIC0xO1xuICB2YXIgciA9IDA7XG4gIGlmKCh4JjB4ZmZmZikgPT0gMCkgeyB4ID4+PSAxNjsgciArPSAxNjsgfVxuICBpZigoeCYweGZmKSA9PSAwKSB7IHggPj49IDg7IHIgKz0gODsgfVxuICBpZigoeCYweGYpID09IDApIHsgeCA+Pj0gNDsgciArPSA0OyB9XG4gIGlmKCh4JjMpID09IDApIHsgeCA+Pj0gMjsgciArPSAyOyB9XG4gIGlmKCh4JjEpID09IDApICsrcjtcbiAgcmV0dXJuIHI7XG59XG5cbi8vIChwdWJsaWMpIHJldHVybnMgaW5kZXggb2YgbG93ZXN0IDEtYml0IChvciAtMSBpZiBub25lKVxuZnVuY3Rpb24gYm5HZXRMb3dlc3RTZXRCaXQoKSB7XG4gIGZvcih2YXIgaSA9IDA7IGkgPCB0aGlzLnQ7ICsraSlcbiAgICBpZih0aGlzW2ldICE9IDApIHJldHVybiBpKnRoaXMuREIrbGJpdCh0aGlzW2ldKTtcbiAgaWYodGhpcy5zIDwgMCkgcmV0dXJuIHRoaXMudCp0aGlzLkRCO1xuICByZXR1cm4gLTE7XG59XG5cbi8vIHJldHVybiBudW1iZXIgb2YgMSBiaXRzIGluIHhcbmZ1bmN0aW9uIGNiaXQoeCkge1xuICB2YXIgciA9IDA7XG4gIHdoaWxlKHggIT0gMCkgeyB4ICY9IHgtMTsgKytyOyB9XG4gIHJldHVybiByO1xufVxuXG4vLyAocHVibGljKSByZXR1cm4gbnVtYmVyIG9mIHNldCBiaXRzXG5mdW5jdGlvbiBibkJpdENvdW50KCkge1xuICB2YXIgciA9IDAsIHggPSB0aGlzLnMmdGhpcy5ETTtcbiAgZm9yKHZhciBpID0gMDsgaSA8IHRoaXMudDsgKytpKSByICs9IGNiaXQodGhpc1tpXV54KTtcbiAgcmV0dXJuIHI7XG59XG5cbi8vIChwdWJsaWMpIHRydWUgaWZmIG50aCBiaXQgaXMgc2V0XG5mdW5jdGlvbiBiblRlc3RCaXQobikge1xuICB2YXIgaiA9IE1hdGguZmxvb3Iobi90aGlzLkRCKTtcbiAgaWYoaiA+PSB0aGlzLnQpIHJldHVybih0aGlzLnMhPTApO1xuICByZXR1cm4oKHRoaXNbal0mKDE8PChuJXRoaXMuREIpKSkhPTApO1xufVxuXG4vLyAocHJvdGVjdGVkKSB0aGlzIG9wICgxPDxuKVxuZnVuY3Rpb24gYm5wQ2hhbmdlQml0KG4sb3ApIHtcbiAgdmFyIHIgPSBCaWdJbnRlZ2VyLk9ORS5zaGlmdExlZnQobik7XG4gIHRoaXMuYml0d2lzZVRvKHIsb3Ascik7XG4gIHJldHVybiByO1xufVxuXG4vLyAocHVibGljKSB0aGlzIHwgKDE8PG4pXG5mdW5jdGlvbiBiblNldEJpdChuKSB7IHJldHVybiB0aGlzLmNoYW5nZUJpdChuLG9wX29yKTsgfVxuXG4vLyAocHVibGljKSB0aGlzICYgfigxPDxuKVxuZnVuY3Rpb24gYm5DbGVhckJpdChuKSB7IHJldHVybiB0aGlzLmNoYW5nZUJpdChuLG9wX2FuZG5vdCk7IH1cblxuLy8gKHB1YmxpYykgdGhpcyBeICgxPDxuKVxuZnVuY3Rpb24gYm5GbGlwQml0KG4pIHsgcmV0dXJuIHRoaXMuY2hhbmdlQml0KG4sb3BfeG9yKTsgfVxuXG4vLyAocHJvdGVjdGVkKSByID0gdGhpcyArIGFcbmZ1bmN0aW9uIGJucEFkZFRvKGEscikge1xuICB2YXIgaSA9IDAsIGMgPSAwLCBtID0gTWF0aC5taW4oYS50LHRoaXMudCk7XG4gIHdoaWxlKGkgPCBtKSB7XG4gICAgYyArPSB0aGlzW2ldK2FbaV07XG4gICAgcltpKytdID0gYyZ0aGlzLkRNO1xuICAgIGMgPj49IHRoaXMuREI7XG4gIH1cbiAgaWYoYS50IDwgdGhpcy50KSB7XG4gICAgYyArPSBhLnM7XG4gICAgd2hpbGUoaSA8IHRoaXMudCkge1xuICAgICAgYyArPSB0aGlzW2ldO1xuICAgICAgcltpKytdID0gYyZ0aGlzLkRNO1xuICAgICAgYyA+Pj0gdGhpcy5EQjtcbiAgICB9XG4gICAgYyArPSB0aGlzLnM7XG4gIH1cbiAgZWxzZSB7XG4gICAgYyArPSB0aGlzLnM7XG4gICAgd2hpbGUoaSA8IGEudCkge1xuICAgICAgYyArPSBhW2ldO1xuICAgICAgcltpKytdID0gYyZ0aGlzLkRNO1xuICAgICAgYyA+Pj0gdGhpcy5EQjtcbiAgICB9XG4gICAgYyArPSBhLnM7XG4gIH1cbiAgci5zID0gKGM8MCk/LTE6MDtcbiAgaWYoYyA+IDApIHJbaSsrXSA9IGM7XG4gIGVsc2UgaWYoYyA8IC0xKSByW2krK10gPSB0aGlzLkRWK2M7XG4gIHIudCA9IGk7XG4gIHIuY2xhbXAoKTtcbn1cblxuLy8gKHB1YmxpYykgdGhpcyArIGFcbmZ1bmN0aW9uIGJuQWRkKGEpIHsgdmFyIHIgPSBuYmkoKTsgdGhpcy5hZGRUbyhhLHIpOyByZXR1cm4gcjsgfVxuXG4vLyAocHVibGljKSB0aGlzIC0gYVxuZnVuY3Rpb24gYm5TdWJ0cmFjdChhKSB7IHZhciByID0gbmJpKCk7IHRoaXMuc3ViVG8oYSxyKTsgcmV0dXJuIHI7IH1cblxuLy8gKHB1YmxpYykgdGhpcyAqIGFcbmZ1bmN0aW9uIGJuTXVsdGlwbHkoYSkgeyB2YXIgciA9IG5iaSgpOyB0aGlzLm11bHRpcGx5VG8oYSxyKTsgcmV0dXJuIHI7IH1cblxuLy8gKHB1YmxpYykgdGhpc14yXG5mdW5jdGlvbiBiblNxdWFyZSgpIHsgdmFyIHIgPSBuYmkoKTsgdGhpcy5zcXVhcmVUbyhyKTsgcmV0dXJuIHI7IH1cblxuLy8gKHB1YmxpYykgdGhpcyAvIGFcbmZ1bmN0aW9uIGJuRGl2aWRlKGEpIHsgdmFyIHIgPSBuYmkoKTsgdGhpcy5kaXZSZW1UbyhhLHIsbnVsbCk7IHJldHVybiByOyB9XG5cbi8vIChwdWJsaWMpIHRoaXMgJSBhXG5mdW5jdGlvbiBiblJlbWFpbmRlcihhKSB7IHZhciByID0gbmJpKCk7IHRoaXMuZGl2UmVtVG8oYSxudWxsLHIpOyByZXR1cm4gcjsgfVxuXG4vLyAocHVibGljKSBbdGhpcy9hLHRoaXMlYV1cbmZ1bmN0aW9uIGJuRGl2aWRlQW5kUmVtYWluZGVyKGEpIHtcbiAgdmFyIHEgPSBuYmkoKSwgciA9IG5iaSgpO1xuICB0aGlzLmRpdlJlbVRvKGEscSxyKTtcbiAgcmV0dXJuIG5ldyBBcnJheShxLHIpO1xufVxuXG4vLyAocHJvdGVjdGVkKSB0aGlzICo9IG4sIHRoaXMgPj0gMCwgMSA8IG4gPCBEVlxuZnVuY3Rpb24gYm5wRE11bHRpcGx5KG4pIHtcbiAgdGhpc1t0aGlzLnRdID0gdGhpcy5hbSgwLG4tMSx0aGlzLDAsMCx0aGlzLnQpO1xuICArK3RoaXMudDtcbiAgdGhpcy5jbGFtcCgpO1xufVxuXG4vLyAocHJvdGVjdGVkKSB0aGlzICs9IG4gPDwgdyB3b3JkcywgdGhpcyA+PSAwXG5mdW5jdGlvbiBibnBEQWRkT2Zmc2V0KG4sdykge1xuICBpZihuID09IDApIHJldHVybjtcbiAgd2hpbGUodGhpcy50IDw9IHcpIHRoaXNbdGhpcy50KytdID0gMDtcbiAgdGhpc1t3XSArPSBuO1xuICB3aGlsZSh0aGlzW3ddID49IHRoaXMuRFYpIHtcbiAgICB0aGlzW3ddIC09IHRoaXMuRFY7XG4gICAgaWYoKyt3ID49IHRoaXMudCkgdGhpc1t0aGlzLnQrK10gPSAwO1xuICAgICsrdGhpc1t3XTtcbiAgfVxufVxuXG4vLyBBIFwibnVsbFwiIHJlZHVjZXJcbmZ1bmN0aW9uIE51bGxFeHAoKSB7fVxuZnVuY3Rpb24gbk5vcCh4KSB7IHJldHVybiB4OyB9XG5mdW5jdGlvbiBuTXVsVG8oeCx5LHIpIHsgeC5tdWx0aXBseVRvKHkscik7IH1cbmZ1bmN0aW9uIG5TcXJUbyh4LHIpIHsgeC5zcXVhcmVUbyhyKTsgfVxuXG5OdWxsRXhwLnByb3RvdHlwZS5jb252ZXJ0ID0gbk5vcDtcbk51bGxFeHAucHJvdG90eXBlLnJldmVydCA9IG5Ob3A7XG5OdWxsRXhwLnByb3RvdHlwZS5tdWxUbyA9IG5NdWxUbztcbk51bGxFeHAucHJvdG90eXBlLnNxclRvID0gblNxclRvO1xuXG4vLyAocHVibGljKSB0aGlzXmVcbmZ1bmN0aW9uIGJuUG93KGUpIHsgcmV0dXJuIHRoaXMuZXhwKGUsbmV3IE51bGxFeHAoKSk7IH1cblxuLy8gKHByb3RlY3RlZCkgciA9IGxvd2VyIG4gd29yZHMgb2YgXCJ0aGlzICogYVwiLCBhLnQgPD0gblxuLy8gXCJ0aGlzXCIgc2hvdWxkIGJlIHRoZSBsYXJnZXIgb25lIGlmIGFwcHJvcHJpYXRlLlxuZnVuY3Rpb24gYm5wTXVsdGlwbHlMb3dlclRvKGEsbixyKSB7XG4gIHZhciBpID0gTWF0aC5taW4odGhpcy50K2EudCxuKTtcbiAgci5zID0gMDsgLy8gYXNzdW1lcyBhLHRoaXMgPj0gMFxuICByLnQgPSBpO1xuICB3aGlsZShpID4gMCkgclstLWldID0gMDtcbiAgdmFyIGo7XG4gIGZvcihqID0gci50LXRoaXMudDsgaSA8IGo7ICsraSkgcltpK3RoaXMudF0gPSB0aGlzLmFtKDAsYVtpXSxyLGksMCx0aGlzLnQpO1xuICBmb3IoaiA9IE1hdGgubWluKGEudCxuKTsgaSA8IGo7ICsraSkgdGhpcy5hbSgwLGFbaV0scixpLDAsbi1pKTtcbiAgci5jbGFtcCgpO1xufVxuXG4vLyAocHJvdGVjdGVkKSByID0gXCJ0aGlzICogYVwiIHdpdGhvdXQgbG93ZXIgbiB3b3JkcywgbiA+IDBcbi8vIFwidGhpc1wiIHNob3VsZCBiZSB0aGUgbGFyZ2VyIG9uZSBpZiBhcHByb3ByaWF0ZS5cbmZ1bmN0aW9uIGJucE11bHRpcGx5VXBwZXJUbyhhLG4scikge1xuICAtLW47XG4gIHZhciBpID0gci50ID0gdGhpcy50K2EudC1uO1xuICByLnMgPSAwOyAvLyBhc3N1bWVzIGEsdGhpcyA+PSAwXG4gIHdoaWxlKC0taSA+PSAwKSByW2ldID0gMDtcbiAgZm9yKGkgPSBNYXRoLm1heChuLXRoaXMudCwwKTsgaSA8IGEudDsgKytpKVxuICAgIHJbdGhpcy50K2ktbl0gPSB0aGlzLmFtKG4taSxhW2ldLHIsMCwwLHRoaXMudCtpLW4pO1xuICByLmNsYW1wKCk7XG4gIHIuZHJTaGlmdFRvKDEscik7XG59XG5cbi8vIEJhcnJldHQgbW9kdWxhciByZWR1Y3Rpb25cbmZ1bmN0aW9uIEJhcnJldHQobSkge1xuICAvLyBzZXR1cCBCYXJyZXR0XG4gIHRoaXMucjIgPSBuYmkoKTtcbiAgdGhpcy5xMyA9IG5iaSgpO1xuICBCaWdJbnRlZ2VyLk9ORS5kbFNoaWZ0VG8oMiptLnQsdGhpcy5yMik7XG4gIHRoaXMubXUgPSB0aGlzLnIyLmRpdmlkZShtKTtcbiAgdGhpcy5tID0gbTtcbn1cblxuZnVuY3Rpb24gYmFycmV0dENvbnZlcnQoeCkge1xuICBpZih4LnMgPCAwIHx8IHgudCA+IDIqdGhpcy5tLnQpIHJldHVybiB4Lm1vZCh0aGlzLm0pO1xuICBlbHNlIGlmKHguY29tcGFyZVRvKHRoaXMubSkgPCAwKSByZXR1cm4geDtcbiAgZWxzZSB7IHZhciByID0gbmJpKCk7IHguY29weVRvKHIpOyB0aGlzLnJlZHVjZShyKTsgcmV0dXJuIHI7IH1cbn1cblxuZnVuY3Rpb24gYmFycmV0dFJldmVydCh4KSB7IHJldHVybiB4OyB9XG5cbi8vIHggPSB4IG1vZCBtIChIQUMgMTQuNDIpXG5mdW5jdGlvbiBiYXJyZXR0UmVkdWNlKHgpIHtcbiAgeC5kclNoaWZ0VG8odGhpcy5tLnQtMSx0aGlzLnIyKTtcbiAgaWYoeC50ID4gdGhpcy5tLnQrMSkgeyB4LnQgPSB0aGlzLm0udCsxOyB4LmNsYW1wKCk7IH1cbiAgdGhpcy5tdS5tdWx0aXBseVVwcGVyVG8odGhpcy5yMix0aGlzLm0udCsxLHRoaXMucTMpO1xuICB0aGlzLm0ubXVsdGlwbHlMb3dlclRvKHRoaXMucTMsdGhpcy5tLnQrMSx0aGlzLnIyKTtcbiAgd2hpbGUoeC5jb21wYXJlVG8odGhpcy5yMikgPCAwKSB4LmRBZGRPZmZzZXQoMSx0aGlzLm0udCsxKTtcbiAgeC5zdWJUbyh0aGlzLnIyLHgpO1xuICB3aGlsZSh4LmNvbXBhcmVUbyh0aGlzLm0pID49IDApIHguc3ViVG8odGhpcy5tLHgpO1xufVxuXG4vLyByID0geF4yIG1vZCBtOyB4ICE9IHJcbmZ1bmN0aW9uIGJhcnJldHRTcXJUbyh4LHIpIHsgeC5zcXVhcmVUbyhyKTsgdGhpcy5yZWR1Y2Uocik7IH1cblxuLy8gciA9IHgqeSBtb2QgbTsgeCx5ICE9IHJcbmZ1bmN0aW9uIGJhcnJldHRNdWxUbyh4LHkscikgeyB4Lm11bHRpcGx5VG8oeSxyKTsgdGhpcy5yZWR1Y2Uocik7IH1cblxuQmFycmV0dC5wcm90b3R5cGUuY29udmVydCA9IGJhcnJldHRDb252ZXJ0O1xuQmFycmV0dC5wcm90b3R5cGUucmV2ZXJ0ID0gYmFycmV0dFJldmVydDtcbkJhcnJldHQucHJvdG90eXBlLnJlZHVjZSA9IGJhcnJldHRSZWR1Y2U7XG5CYXJyZXR0LnByb3RvdHlwZS5tdWxUbyA9IGJhcnJldHRNdWxUbztcbkJhcnJldHQucHJvdG90eXBlLnNxclRvID0gYmFycmV0dFNxclRvO1xuXG4vLyAocHVibGljKSB0aGlzXmUgJSBtIChIQUMgMTQuODUpXG5mdW5jdGlvbiBibk1vZFBvdyhlLG0pIHtcbiAgdmFyIGkgPSBlLmJpdExlbmd0aCgpLCBrLCByID0gbmJ2KDEpLCB6O1xuICBpZihpIDw9IDApIHJldHVybiByO1xuICBlbHNlIGlmKGkgPCAxOCkgayA9IDE7XG4gIGVsc2UgaWYoaSA8IDQ4KSBrID0gMztcbiAgZWxzZSBpZihpIDwgMTQ0KSBrID0gNDtcbiAgZWxzZSBpZihpIDwgNzY4KSBrID0gNTtcbiAgZWxzZSBrID0gNjtcbiAgaWYoaSA8IDgpXG4gICAgeiA9IG5ldyBDbGFzc2ljKG0pO1xuICBlbHNlIGlmKG0uaXNFdmVuKCkpXG4gICAgeiA9IG5ldyBCYXJyZXR0KG0pO1xuICBlbHNlXG4gICAgeiA9IG5ldyBNb250Z29tZXJ5KG0pO1xuXG4gIC8vIHByZWNvbXB1dGF0aW9uXG4gIHZhciBnID0gbmV3IEFycmF5KCksIG4gPSAzLCBrMSA9IGstMSwga20gPSAoMTw8ayktMTtcbiAgZ1sxXSA9IHouY29udmVydCh0aGlzKTtcbiAgaWYoayA+IDEpIHtcbiAgICB2YXIgZzIgPSBuYmkoKTtcbiAgICB6LnNxclRvKGdbMV0sZzIpO1xuICAgIHdoaWxlKG4gPD0ga20pIHtcbiAgICAgIGdbbl0gPSBuYmkoKTtcbiAgICAgIHoubXVsVG8oZzIsZ1tuLTJdLGdbbl0pO1xuICAgICAgbiArPSAyO1xuICAgIH1cbiAgfVxuXG4gIHZhciBqID0gZS50LTEsIHcsIGlzMSA9IHRydWUsIHIyID0gbmJpKCksIHQ7XG4gIGkgPSBuYml0cyhlW2pdKS0xO1xuICB3aGlsZShqID49IDApIHtcbiAgICBpZihpID49IGsxKSB3ID0gKGVbal0+PihpLWsxKSkma207XG4gICAgZWxzZSB7XG4gICAgICB3ID0gKGVbal0mKCgxPDwoaSsxKSktMSkpPDwoazEtaSk7XG4gICAgICBpZihqID4gMCkgdyB8PSBlW2otMV0+Pih0aGlzLkRCK2ktazEpO1xuICAgIH1cblxuICAgIG4gPSBrO1xuICAgIHdoaWxlKCh3JjEpID09IDApIHsgdyA+Pj0gMTsgLS1uOyB9XG4gICAgaWYoKGkgLT0gbikgPCAwKSB7IGkgKz0gdGhpcy5EQjsgLS1qOyB9XG4gICAgaWYoaXMxKSB7XHQvLyByZXQgPT0gMSwgZG9uJ3QgYm90aGVyIHNxdWFyaW5nIG9yIG11bHRpcGx5aW5nIGl0XG4gICAgICBnW3ddLmNvcHlUbyhyKTtcbiAgICAgIGlzMSA9IGZhbHNlO1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgIHdoaWxlKG4gPiAxKSB7IHouc3FyVG8ocixyMik7IHouc3FyVG8ocjIscik7IG4gLT0gMjsgfVxuICAgICAgaWYobiA+IDApIHouc3FyVG8ocixyMik7IGVsc2UgeyB0ID0gcjsgciA9IHIyOyByMiA9IHQ7IH1cbiAgICAgIHoubXVsVG8ocjIsZ1t3XSxyKTtcbiAgICB9XG5cbiAgICB3aGlsZShqID49IDAgJiYgKGVbal0mKDE8PGkpKSA9PSAwKSB7XG4gICAgICB6LnNxclRvKHIscjIpOyB0ID0gcjsgciA9IHIyOyByMiA9IHQ7XG4gICAgICBpZigtLWkgPCAwKSB7IGkgPSB0aGlzLkRCLTE7IC0tajsgfVxuICAgIH1cbiAgfVxuICByZXR1cm4gei5yZXZlcnQocik7XG59XG5cbi8vIChwdWJsaWMpIGdjZCh0aGlzLGEpIChIQUMgMTQuNTQpXG5mdW5jdGlvbiBibkdDRChhKSB7XG4gIHZhciB4ID0gKHRoaXMuczwwKT90aGlzLm5lZ2F0ZSgpOnRoaXMuY2xvbmUoKTtcbiAgdmFyIHkgPSAoYS5zPDApP2EubmVnYXRlKCk6YS5jbG9uZSgpO1xuICBpZih4LmNvbXBhcmVUbyh5KSA8IDApIHsgdmFyIHQgPSB4OyB4ID0geTsgeSA9IHQ7IH1cbiAgdmFyIGkgPSB4LmdldExvd2VzdFNldEJpdCgpLCBnID0geS5nZXRMb3dlc3RTZXRCaXQoKTtcbiAgaWYoZyA8IDApIHJldHVybiB4O1xuICBpZihpIDwgZykgZyA9IGk7XG4gIGlmKGcgPiAwKSB7XG4gICAgeC5yU2hpZnRUbyhnLHgpO1xuICAgIHkuclNoaWZ0VG8oZyx5KTtcbiAgfVxuICB3aGlsZSh4LnNpZ251bSgpID4gMCkge1xuICAgIGlmKChpID0geC5nZXRMb3dlc3RTZXRCaXQoKSkgPiAwKSB4LnJTaGlmdFRvKGkseCk7XG4gICAgaWYoKGkgPSB5LmdldExvd2VzdFNldEJpdCgpKSA+IDApIHkuclNoaWZ0VG8oaSx5KTtcbiAgICBpZih4LmNvbXBhcmVUbyh5KSA+PSAwKSB7XG4gICAgICB4LnN1YlRvKHkseCk7XG4gICAgICB4LnJTaGlmdFRvKDEseCk7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgeS5zdWJUbyh4LHkpO1xuICAgICAgeS5yU2hpZnRUbygxLHkpO1xuICAgIH1cbiAgfVxuICBpZihnID4gMCkgeS5sU2hpZnRUbyhnLHkpO1xuICByZXR1cm4geTtcbn1cblxuLy8gKHByb3RlY3RlZCkgdGhpcyAlIG4sIG4gPCAyXjI2XG5mdW5jdGlvbiBibnBNb2RJbnQobikge1xuICBpZihuIDw9IDApIHJldHVybiAwO1xuICB2YXIgZCA9IHRoaXMuRFYlbiwgciA9ICh0aGlzLnM8MCk/bi0xOjA7XG4gIGlmKHRoaXMudCA+IDApXG4gICAgaWYoZCA9PSAwKSByID0gdGhpc1swXSVuO1xuICAgIGVsc2UgZm9yKHZhciBpID0gdGhpcy50LTE7IGkgPj0gMDsgLS1pKSByID0gKGQqcit0aGlzW2ldKSVuO1xuICByZXR1cm4gcjtcbn1cblxuLy8gKHB1YmxpYykgMS90aGlzICUgbSAoSEFDIDE0LjYxKVxuZnVuY3Rpb24gYm5Nb2RJbnZlcnNlKG0pIHtcbiAgdmFyIGFjID0gbS5pc0V2ZW4oKTtcbiAgaWYoKHRoaXMuaXNFdmVuKCkgJiYgYWMpIHx8IG0uc2lnbnVtKCkgPT0gMCkgcmV0dXJuIEJpZ0ludGVnZXIuWkVSTztcbiAgdmFyIHUgPSBtLmNsb25lKCksIHYgPSB0aGlzLmNsb25lKCk7XG4gIHZhciBhID0gbmJ2KDEpLCBiID0gbmJ2KDApLCBjID0gbmJ2KDApLCBkID0gbmJ2KDEpO1xuICB3aGlsZSh1LnNpZ251bSgpICE9IDApIHtcbiAgICB3aGlsZSh1LmlzRXZlbigpKSB7XG4gICAgICB1LnJTaGlmdFRvKDEsdSk7XG4gICAgICBpZihhYykge1xuICAgICAgICBpZighYS5pc0V2ZW4oKSB8fCAhYi5pc0V2ZW4oKSkgeyBhLmFkZFRvKHRoaXMsYSk7IGIuc3ViVG8obSxiKTsgfVxuICAgICAgICBhLnJTaGlmdFRvKDEsYSk7XG4gICAgICB9XG4gICAgICBlbHNlIGlmKCFiLmlzRXZlbigpKSBiLnN1YlRvKG0sYik7XG4gICAgICBiLnJTaGlmdFRvKDEsYik7XG4gICAgfVxuICAgIHdoaWxlKHYuaXNFdmVuKCkpIHtcbiAgICAgIHYuclNoaWZ0VG8oMSx2KTtcbiAgICAgIGlmKGFjKSB7XG4gICAgICAgIGlmKCFjLmlzRXZlbigpIHx8ICFkLmlzRXZlbigpKSB7IGMuYWRkVG8odGhpcyxjKTsgZC5zdWJUbyhtLGQpOyB9XG4gICAgICAgIGMuclNoaWZ0VG8oMSxjKTtcbiAgICAgIH1cbiAgICAgIGVsc2UgaWYoIWQuaXNFdmVuKCkpIGQuc3ViVG8obSxkKTtcbiAgICAgIGQuclNoaWZ0VG8oMSxkKTtcbiAgICB9XG4gICAgaWYodS5jb21wYXJlVG8odikgPj0gMCkge1xuICAgICAgdS5zdWJUbyh2LHUpO1xuICAgICAgaWYoYWMpIGEuc3ViVG8oYyxhKTtcbiAgICAgIGIuc3ViVG8oZCxiKTtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICB2LnN1YlRvKHUsdik7XG4gICAgICBpZihhYykgYy5zdWJUbyhhLGMpO1xuICAgICAgZC5zdWJUbyhiLGQpO1xuICAgIH1cbiAgfVxuICBpZih2LmNvbXBhcmVUbyhCaWdJbnRlZ2VyLk9ORSkgIT0gMCkgcmV0dXJuIEJpZ0ludGVnZXIuWkVSTztcbiAgaWYoZC5jb21wYXJlVG8obSkgPj0gMCkgcmV0dXJuIGQuc3VidHJhY3QobSk7XG4gIGlmKGQuc2lnbnVtKCkgPCAwKSBkLmFkZFRvKG0sZCk7IGVsc2UgcmV0dXJuIGQ7XG4gIGlmKGQuc2lnbnVtKCkgPCAwKSByZXR1cm4gZC5hZGQobSk7IGVsc2UgcmV0dXJuIGQ7XG59XG5cbnZhciBsb3dwcmltZXMgPSBbMiwzLDUsNywxMSwxMywxNywxOSwyMywyOSwzMSwzNyw0MSw0Myw0Nyw1Myw1OSw2MSw2Nyw3MSw3Myw3OSw4Myw4OSw5NywxMDEsMTAzLDEwNywxMDksMTEzLDEyNywxMzEsMTM3LDEzOSwxNDksMTUxLDE1NywxNjMsMTY3LDE3MywxNzksMTgxLDE5MSwxOTMsMTk3LDE5OSwyMTEsMjIzLDIyNywyMjksMjMzLDIzOSwyNDEsMjUxLDI1NywyNjMsMjY5LDI3MSwyNzcsMjgxLDI4MywyOTMsMzA3LDMxMSwzMTMsMzE3LDMzMSwzMzcsMzQ3LDM0OSwzNTMsMzU5LDM2NywzNzMsMzc5LDM4MywzODksMzk3LDQwMSw0MDksNDE5LDQyMSw0MzEsNDMzLDQzOSw0NDMsNDQ5LDQ1Nyw0NjEsNDYzLDQ2Nyw0NzksNDg3LDQ5MSw0OTksNTAzLDUwOSw1MjEsNTIzLDU0MSw1NDcsNTU3LDU2Myw1NjksNTcxLDU3Nyw1ODcsNTkzLDU5OSw2MDEsNjA3LDYxMyw2MTcsNjE5LDYzMSw2NDEsNjQzLDY0Nyw2NTMsNjU5LDY2MSw2NzMsNjc3LDY4Myw2OTEsNzAxLDcwOSw3MTksNzI3LDczMyw3MzksNzQzLDc1MSw3NTcsNzYxLDc2OSw3NzMsNzg3LDc5Nyw4MDksODExLDgyMSw4MjMsODI3LDgyOSw4MzksODUzLDg1Nyw4NTksODYzLDg3Nyw4ODEsODgzLDg4Nyw5MDcsOTExLDkxOSw5MjksOTM3LDk0MSw5NDcsOTUzLDk2Nyw5NzEsOTc3LDk4Myw5OTEsOTk3XTtcbnZhciBscGxpbSA9ICgxPDwyNikvbG93cHJpbWVzW2xvd3ByaW1lcy5sZW5ndGgtMV07XG5cbi8vIChwdWJsaWMpIHRlc3QgcHJpbWFsaXR5IHdpdGggY2VydGFpbnR5ID49IDEtLjVedFxuZnVuY3Rpb24gYm5Jc1Byb2JhYmxlUHJpbWUodCkge1xuICB2YXIgaSwgeCA9IHRoaXMuYWJzKCk7XG4gIGlmKHgudCA9PSAxICYmIHhbMF0gPD0gbG93cHJpbWVzW2xvd3ByaW1lcy5sZW5ndGgtMV0pIHtcbiAgICBmb3IoaSA9IDA7IGkgPCBsb3dwcmltZXMubGVuZ3RoOyArK2kpXG4gICAgICBpZih4WzBdID09IGxvd3ByaW1lc1tpXSkgcmV0dXJuIHRydWU7XG4gICAgcmV0dXJuIGZhbHNlO1xuICB9XG4gIGlmKHguaXNFdmVuKCkpIHJldHVybiBmYWxzZTtcbiAgaSA9IDE7XG4gIHdoaWxlKGkgPCBsb3dwcmltZXMubGVuZ3RoKSB7XG4gICAgdmFyIG0gPSBsb3dwcmltZXNbaV0sIGogPSBpKzE7XG4gICAgd2hpbGUoaiA8IGxvd3ByaW1lcy5sZW5ndGggJiYgbSA8IGxwbGltKSBtICo9IGxvd3ByaW1lc1tqKytdO1xuICAgIG0gPSB4Lm1vZEludChtKTtcbiAgICB3aGlsZShpIDwgaikgaWYobSVsb3dwcmltZXNbaSsrXSA9PSAwKSByZXR1cm4gZmFsc2U7XG4gIH1cbiAgcmV0dXJuIHgubWlsbGVyUmFiaW4odCk7XG59XG5cbi8qIGFkZGVkIGJ5IFJlY3VyaXR5IExhYnMgKi9cblxuZnVuY3Rpb24gbmJpdHMoeCkge1xuXHR2YXIgbiA9IDEsIHQ7XG5cdGlmICgodCA9IHggPj4+IDE2KSAhPSAwKSB7XG5cdFx0eCA9IHQ7XG5cdFx0biArPSAxNjtcblx0fVxuXHRpZiAoKHQgPSB4ID4+IDgpICE9IDApIHtcblx0XHR4ID0gdDtcblx0XHRuICs9IDg7XG5cdH1cblx0aWYgKCh0ID0geCA+PiA0KSAhPSAwKSB7XG5cdFx0eCA9IHQ7XG5cdFx0biArPSA0O1xuXHR9XG5cdGlmICgodCA9IHggPj4gMikgIT0gMCkge1xuXHRcdHggPSB0O1xuXHRcdG4gKz0gMjtcblx0fVxuXHRpZiAoKHQgPSB4ID4+IDEpICE9IDApIHtcblx0XHR4ID0gdDtcblx0XHRuICs9IDE7XG5cdH1cblx0cmV0dXJuIG47XG59XG5cbmZ1bmN0aW9uIGJuVG9NUEkgKCkge1xuXHR2YXIgYmEgPSB0aGlzLnRvQnl0ZUFycmF5KCk7XG5cdHZhciBzaXplID0gKGJhLmxlbmd0aC0xKSo4K25iaXRzKGJhWzBdKTtcblx0dmFyIHJlc3VsdCA9IFwiXCI7XG5cdHJlc3VsdCArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKChzaXplICYgMHhGRjAwKSA+PiA4KTtcblx0cmVzdWx0ICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoc2l6ZSAmIDB4RkYpO1xuXHRyZXN1bHQgKz0gdXRpbC5iaW4yc3RyKGJhKTtcblx0cmV0dXJuIHJlc3VsdDtcbn1cbi8qIEVORCBvZiBhZGRpdGlvbiAqL1xuXG4vLyAocHJvdGVjdGVkKSB0cnVlIGlmIHByb2JhYmx5IHByaW1lIChIQUMgNC4yNCwgTWlsbGVyLVJhYmluKVxuZnVuY3Rpb24gYm5wTWlsbGVyUmFiaW4odCkge1xuICB2YXIgbjEgPSB0aGlzLnN1YnRyYWN0KEJpZ0ludGVnZXIuT05FKTtcbiAgdmFyIGsgPSBuMS5nZXRMb3dlc3RTZXRCaXQoKTtcbiAgaWYoayA8PSAwKSByZXR1cm4gZmFsc2U7XG4gIHZhciByID0gbjEuc2hpZnRSaWdodChrKTtcbiAgdCA9ICh0KzEpPj4xO1xuICBpZih0ID4gbG93cHJpbWVzLmxlbmd0aCkgdCA9IGxvd3ByaW1lcy5sZW5ndGg7XG4gIHZhciBhID0gbmJpKCk7XG4gIGZvcih2YXIgaSA9IDA7IGkgPCB0OyArK2kpIHtcbiAgICAvL1BpY2sgYmFzZXMgYXQgcmFuZG9tLCBpbnN0ZWFkIG9mIHN0YXJ0aW5nIGF0IDJcbiAgICBhLmZyb21JbnQobG93cHJpbWVzW01hdGguZmxvb3IoTWF0aC5yYW5kb20oKSpsb3dwcmltZXMubGVuZ3RoKV0pO1xuICAgIHZhciB5ID0gYS5tb2RQb3cocix0aGlzKTtcbiAgICBpZih5LmNvbXBhcmVUbyhCaWdJbnRlZ2VyLk9ORSkgIT0gMCAmJiB5LmNvbXBhcmVUbyhuMSkgIT0gMCkge1xuICAgICAgdmFyIGogPSAxO1xuICAgICAgd2hpbGUoaisrIDwgayAmJiB5LmNvbXBhcmVUbyhuMSkgIT0gMCkge1xuICAgICAgICB5ID0geS5tb2RQb3dJbnQoMix0aGlzKTtcbiAgICAgICAgaWYoeS5jb21wYXJlVG8oQmlnSW50ZWdlci5PTkUpID09IDApIHJldHVybiBmYWxzZTtcbiAgICAgIH1cbiAgICAgIGlmKHkuY29tcGFyZVRvKG4xKSAhPSAwKSByZXR1cm4gZmFsc2U7XG4gICAgfVxuICB9XG4gIHJldHVybiB0cnVlO1xufVxuXG52YXIgQmlnSW50ZWdlciA9IHJlcXVpcmUoJy4vanNibi5qcycpO1xuXG4vLyBwcm90ZWN0ZWRcbkJpZ0ludGVnZXIucHJvdG90eXBlLmNodW5rU2l6ZSA9IGJucENodW5rU2l6ZTtcbkJpZ0ludGVnZXIucHJvdG90eXBlLnRvUmFkaXggPSBibnBUb1JhZGl4O1xuQmlnSW50ZWdlci5wcm90b3R5cGUuZnJvbVJhZGl4ID0gYm5wRnJvbVJhZGl4O1xuQmlnSW50ZWdlci5wcm90b3R5cGUuZnJvbU51bWJlciA9IGJucEZyb21OdW1iZXI7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5iaXR3aXNlVG8gPSBibnBCaXR3aXNlVG87XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5jaGFuZ2VCaXQgPSBibnBDaGFuZ2VCaXQ7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5hZGRUbyA9IGJucEFkZFRvO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuZE11bHRpcGx5ID0gYm5wRE11bHRpcGx5O1xuQmlnSW50ZWdlci5wcm90b3R5cGUuZEFkZE9mZnNldCA9IGJucERBZGRPZmZzZXQ7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5tdWx0aXBseUxvd2VyVG8gPSBibnBNdWx0aXBseUxvd2VyVG87XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5tdWx0aXBseVVwcGVyVG8gPSBibnBNdWx0aXBseVVwcGVyVG87XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5tb2RJbnQgPSBibnBNb2RJbnQ7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5taWxsZXJSYWJpbiA9IGJucE1pbGxlclJhYmluO1xuXG4vLyBwdWJsaWNcbkJpZ0ludGVnZXIucHJvdG90eXBlLmNsb25lID0gYm5DbG9uZTtcbkJpZ0ludGVnZXIucHJvdG90eXBlLmludFZhbHVlID0gYm5JbnRWYWx1ZTtcbkJpZ0ludGVnZXIucHJvdG90eXBlLmJ5dGVWYWx1ZSA9IGJuQnl0ZVZhbHVlO1xuQmlnSW50ZWdlci5wcm90b3R5cGUuc2hvcnRWYWx1ZSA9IGJuU2hvcnRWYWx1ZTtcbkJpZ0ludGVnZXIucHJvdG90eXBlLnNpZ251bSA9IGJuU2lnTnVtO1xuQmlnSW50ZWdlci5wcm90b3R5cGUudG9CeXRlQXJyYXkgPSBiblRvQnl0ZUFycmF5O1xuQmlnSW50ZWdlci5wcm90b3R5cGUuZXF1YWxzID0gYm5FcXVhbHM7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5taW4gPSBibk1pbjtcbkJpZ0ludGVnZXIucHJvdG90eXBlLm1heCA9IGJuTWF4O1xuQmlnSW50ZWdlci5wcm90b3R5cGUuYW5kID0gYm5BbmQ7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5vciA9IGJuT3I7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS54b3IgPSBiblhvcjtcbkJpZ0ludGVnZXIucHJvdG90eXBlLmFuZE5vdCA9IGJuQW5kTm90O1xuQmlnSW50ZWdlci5wcm90b3R5cGUubm90ID0gYm5Ob3Q7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5zaGlmdExlZnQgPSBiblNoaWZ0TGVmdDtcbkJpZ0ludGVnZXIucHJvdG90eXBlLnNoaWZ0UmlnaHQgPSBiblNoaWZ0UmlnaHQ7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5nZXRMb3dlc3RTZXRCaXQgPSBibkdldExvd2VzdFNldEJpdDtcbkJpZ0ludGVnZXIucHJvdG90eXBlLmJpdENvdW50ID0gYm5CaXRDb3VudDtcbkJpZ0ludGVnZXIucHJvdG90eXBlLnRlc3RCaXQgPSBiblRlc3RCaXQ7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5zZXRCaXQgPSBiblNldEJpdDtcbkJpZ0ludGVnZXIucHJvdG90eXBlLmNsZWFyQml0ID0gYm5DbGVhckJpdDtcbkJpZ0ludGVnZXIucHJvdG90eXBlLmZsaXBCaXQgPSBibkZsaXBCaXQ7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5hZGQgPSBibkFkZDtcbkJpZ0ludGVnZXIucHJvdG90eXBlLnN1YnRyYWN0ID0gYm5TdWJ0cmFjdDtcbkJpZ0ludGVnZXIucHJvdG90eXBlLm11bHRpcGx5ID0gYm5NdWx0aXBseTtcbkJpZ0ludGVnZXIucHJvdG90eXBlLmRpdmlkZSA9IGJuRGl2aWRlO1xuQmlnSW50ZWdlci5wcm90b3R5cGUucmVtYWluZGVyID0gYm5SZW1haW5kZXI7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5kaXZpZGVBbmRSZW1haW5kZXIgPSBibkRpdmlkZUFuZFJlbWFpbmRlcjtcbkJpZ0ludGVnZXIucHJvdG90eXBlLm1vZFBvdyA9IGJuTW9kUG93O1xuQmlnSW50ZWdlci5wcm90b3R5cGUubW9kSW52ZXJzZSA9IGJuTW9kSW52ZXJzZTtcbkJpZ0ludGVnZXIucHJvdG90eXBlLnBvdyA9IGJuUG93O1xuQmlnSW50ZWdlci5wcm90b3R5cGUuZ2NkID0gYm5HQ0Q7XG5CaWdJbnRlZ2VyLnByb3RvdHlwZS5pc1Byb2JhYmxlUHJpbWUgPSBibklzUHJvYmFibGVQcmltZTtcbkJpZ0ludGVnZXIucHJvdG90eXBlLnRvTVBJID0gYm5Ub01QSTtcblxuLy8gSlNCTi1zcGVjaWZpYyBleHRlbnNpb25cbkJpZ0ludGVnZXIucHJvdG90eXBlLnNxdWFyZSA9IGJuU3F1YXJlO1xuXG5cbiIsIi8vIEdQRzRCcm93c2VycyAtIEFuIE9wZW5QR1AgaW1wbGVtZW50YXRpb24gaW4gamF2YXNjcmlwdFxuLy8gQ29weXJpZ2h0IChDKSAyMDExIFJlY3VyaXR5IExhYnMgR21iSFxuLy8gXG4vLyBUaGlzIGxpYnJhcnkgaXMgZnJlZSBzb2Z0d2FyZTsgeW91IGNhbiByZWRpc3RyaWJ1dGUgaXQgYW5kL29yXG4vLyBtb2RpZnkgaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgTGVzc2VyIEdlbmVyYWwgUHVibGljXG4vLyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieSB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uOyBlaXRoZXJcbi8vIHZlcnNpb24gMi4xIG9mIHRoZSBMaWNlbnNlLCBvciAoYXQgeW91ciBvcHRpb24pIGFueSBsYXRlciB2ZXJzaW9uLlxuLy8gXG4vLyBUaGlzIGxpYnJhcnkgaXMgZGlzdHJpYnV0ZWQgaW4gdGhlIGhvcGUgdGhhdCBpdCB3aWxsIGJlIHVzZWZ1bCxcbi8vIGJ1dCBXSVRIT1VUIEFOWSBXQVJSQU5UWTsgd2l0aG91dCBldmVuIHRoZSBpbXBsaWVkIHdhcnJhbnR5IG9mXG4vLyBNRVJDSEFOVEFCSUxJVFkgb3IgRklUTkVTUyBGT1IgQSBQQVJUSUNVTEFSIFBVUlBPU0UuICBTZWUgdGhlIEdOVVxuLy8gTGVzc2VyIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgZm9yIG1vcmUgZGV0YWlscy5cbi8vIFxuLy8gWW91IHNob3VsZCBoYXZlIHJlY2VpdmVkIGEgY29weSBvZiB0aGUgR05VIExlc3NlciBHZW5lcmFsIFB1YmxpY1xuLy8gTGljZW5zZSBhbG9uZyB3aXRoIHRoaXMgbGlicmFyeTsgaWYgbm90LCB3cml0ZSB0byB0aGUgRnJlZSBTb2Z0d2FyZVxuLy8gRm91bmRhdGlvbiwgSW5jLiwgNTEgRnJhbmtsaW4gU3RyZWV0LCBGaWZ0aCBGbG9vciwgQm9zdG9uLCBNQSAgMDIxMTAtMTMwMSAgVVNBIFxuXG4vLyBUaGUgR1BHNEJyb3dzZXJzIGNyeXB0byBpbnRlcmZhY2VcblxubW9kdWxlLmV4cG9ydHMgPSB7XG5cdC8qKlxuXHQgKiBSZXRyaWV2ZSBzZWN1cmUgcmFuZG9tIGJ5dGUgc3RyaW5nIG9mIHRoZSBzcGVjaWZpZWQgbGVuZ3RoXG5cdCAqIEBwYXJhbSB7SW50ZWdlcn0gbGVuZ3RoIExlbmd0aCBpbiBieXRlcyB0byBnZW5lcmF0ZVxuXHQgKiBAcmV0dXJuIHtTdHJpbmd9IFJhbmRvbSBieXRlIHN0cmluZ1xuXHQgKi9cblx0Z2V0UmFuZG9tQnl0ZXM6IGZ1bmN0aW9uKGxlbmd0aCkge1xuXHRcdHZhciByZXN1bHQgPSAnJztcblx0XHRmb3IgKHZhciBpID0gMDsgaSA8IGxlbmd0aDsgaSsrKSB7XG5cdFx0XHRyZXN1bHQgKz0gU3RyaW5nLmZyb21DaGFyQ29kZShvcGVucGdwX2NyeXB0b19nZXRTZWN1cmVSYW5kb21PY3RldCgpKTtcblx0XHR9XG5cdFx0cmV0dXJuIHJlc3VsdDtcblx0fSxcblxuXHQvKipcblx0ICogUmV0dXJuIGEgcHNldWRvLXJhbmRvbSBudW1iZXIgaW4gdGhlIHNwZWNpZmllZCByYW5nZVxuXHQgKiBAcGFyYW0ge0ludGVnZXJ9IGZyb20gTWluIG9mIHRoZSByYW5kb20gbnVtYmVyXG5cdCAqIEBwYXJhbSB7SW50ZWdlcn0gdG8gTWF4IG9mIHRoZSByYW5kb20gbnVtYmVyIChtYXggMzJiaXQpXG5cdCAqIEByZXR1cm4ge0ludGVnZXJ9IEEgcHNldWRvIHJhbmRvbSBudW1iZXJcblx0ICovXG5cdGdldFBzZXVkb1JhbmRvbTogZnVuY3Rpb24oZnJvbSwgdG8pIHtcblx0XHRyZXR1cm4gTWF0aC5yb3VuZChNYXRoLnJhbmRvbSgpKih0by1mcm9tKSkrZnJvbTtcblx0fSxcblxuXHQvKipcblx0ICogUmV0dXJuIGEgc2VjdXJlIHJhbmRvbSBudW1iZXIgaW4gdGhlIHNwZWNpZmllZCByYW5nZVxuXHQgKiBAcGFyYW0ge0ludGVnZXJ9IGZyb20gTWluIG9mIHRoZSByYW5kb20gbnVtYmVyXG5cdCAqIEBwYXJhbSB7SW50ZWdlcn0gdG8gTWF4IG9mIHRoZSByYW5kb20gbnVtYmVyIChtYXggMzJiaXQpXG5cdCAqIEByZXR1cm4ge0ludGVnZXJ9IEEgc2VjdXJlIHJhbmRvbSBudW1iZXJcblx0ICovXG5cdGdldFNlY3VyZVJhbmRvbTogZnVuY3Rpb24oZnJvbSwgdG8pIHtcblx0XHR2YXIgYnVmID0gbmV3IFVpbnQzMkFycmF5KDEpO1xuXHRcdHdpbmRvdy5jcnlwdG8uZ2V0UmFuZG9tVmFsdWVzKGJ1Zik7XG5cdFx0dmFyIGJpdHMgPSAoKHRvLWZyb20pKS50b1N0cmluZygyKS5sZW5ndGg7XG5cdFx0d2hpbGUgKChidWZbMF0gJiAoTWF0aC5wb3coMiwgYml0cykgLTEpKSA+ICh0by1mcm9tKSlcblx0XHRcdHdpbmRvdy5jcnlwdG8uZ2V0UmFuZG9tVmFsdWVzKGJ1Zik7XG5cdFx0cmV0dXJuIGZyb20rKE1hdGguYWJzKGJ1ZlswXSAmIChNYXRoLnBvdygyLCBiaXRzKSAtMSkpKTtcblx0fSxcblxuXHRnZXRTZWN1cmVSYW5kb21PY3RldDogZnVuY3Rpb24oKSB7XG5cdFx0dmFyIGJ1ZiA9IG5ldyBVaW50MzJBcnJheSgxKTtcblx0XHR3aW5kb3cuY3J5cHRvLmdldFJhbmRvbVZhbHVlcyhidWYpO1xuXHRcdHJldHVybiBidWZbMF0gJiAweEZGO1xuXHR9XG59XG4iLCIvLyBHUEc0QnJvd3NlcnMgLSBBbiBPcGVuUEdQIGltcGxlbWVudGF0aW9uIGluIGphdmFzY3JpcHRcbi8vIENvcHlyaWdodCAoQykgMjAxMSBSZWN1cml0eSBMYWJzIEdtYkhcbi8vIFxuLy8gVGhpcyBsaWJyYXJ5IGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vclxuLy8gbW9kaWZ5IGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIExlc3NlciBHZW5lcmFsIFB1YmxpY1xuLy8gTGljZW5zZSBhcyBwdWJsaXNoZWQgYnkgdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyXG4vLyB2ZXJzaW9uIDIuMSBvZiB0aGUgTGljZW5zZSwgb3IgKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbi8vIFxuLy8gVGhpcyBsaWJyYXJ5IGlzIGRpc3RyaWJ1dGVkIGluIHRoZSBob3BlIHRoYXQgaXQgd2lsbCBiZSB1c2VmdWwsXG4vLyBidXQgV0lUSE9VVCBBTlkgV0FSUkFOVFk7IHdpdGhvdXQgZXZlbiB0aGUgaW1wbGllZCB3YXJyYW50eSBvZlxuLy8gTUVSQ0hBTlRBQklMSVRZIG9yIEZJVE5FU1MgRk9SIEEgUEFSVElDVUxBUiBQVVJQT1NFLiAgU2VlIHRoZSBHTlVcbi8vIExlc3NlciBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGZvciBtb3JlIGRldGFpbHMuXG4vLyBcbi8vIFlvdSBzaG91bGQgaGF2ZSByZWNlaXZlZCBhIGNvcHkgb2YgdGhlIEdOVSBMZXNzZXIgR2VuZXJhbCBQdWJsaWNcbi8vIExpY2Vuc2UgYWxvbmcgd2l0aCB0aGlzIGxpYnJhcnk7IGlmIG5vdCwgd3JpdGUgdG8gdGhlIEZyZWUgU29mdHdhcmVcbi8vIEZvdW5kYXRpb24sIEluYy4sIDUxIEZyYW5rbGluIFN0cmVldCwgRmlmdGggRmxvb3IsIEJvc3RvbiwgTUEgIDAyMTEwLTEzMDEgIFVTQVxuXG4vKipcbiAqIEBjbGFzc1xuICogQGNsYXNzZGVzYyBJbXBsZW1lbnRhdGlvbiBvZiB0aGUgU3ltLiBFbmNyeXB0ZWQgSW50ZWdyaXR5IFByb3RlY3RlZCBEYXRhIFxuICogUGFja2V0IChUYWcgMTgpXG4gKiBcbiAqIFJGQzQ4ODAgNS4xMzogVGhlIFN5bW1ldHJpY2FsbHkgRW5jcnlwdGVkIEludGVncml0eSBQcm90ZWN0ZWQgRGF0YSBwYWNrZXQgaXNcbiAqIGEgdmFyaWFudCBvZiB0aGUgU3ltbWV0cmljYWxseSBFbmNyeXB0ZWQgRGF0YSBwYWNrZXQuIEl0IGlzIGEgbmV3IGZlYXR1cmVcbiAqIGNyZWF0ZWQgZm9yIE9wZW5QR1AgdGhhdCBhZGRyZXNzZXMgdGhlIHByb2JsZW0gb2YgZGV0ZWN0aW5nIGEgbW9kaWZpY2F0aW9uIHRvXG4gKiBlbmNyeXB0ZWQgZGF0YS4gSXQgaXMgdXNlZCBpbiBjb21iaW5hdGlvbiB3aXRoIGEgTW9kaWZpY2F0aW9uIERldGVjdGlvbiBDb2RlXG4gKiBwYWNrZXQuXG4gKi9cblxubW9kdWxlLmV4cG9ydHMgPSBmdW5jdGlvbiBwYWNrZXRfc3ltX2VuY3J5cHRlZF9pbnRlZ3JpdHlfcHJvdGVjdGVkKCkge1xuXHQvKiogVGhlIGVuY3J5cHRlZCBwYXlsb2FkLiAqL1xuXHR0aGlzLmVuY3J5cHRlZCA9IG51bGw7IC8vIHN0cmluZ1xuXHQvKiogQHR5cGUge0Jvb2xlYW59XG5cdCAqIElmIGFmdGVyIGRlY3J5cHRpbmcgdGhlIHBhY2tldCB0aGlzIGlzIHNldCB0byB0cnVlLFxuXHQgKiBhIG1vZGlmaWNhdGlvbiBoYXMgYmVlbiBkZXRlY3RlZCBhbmQgdGh1cyB0aGUgY29udGVudHNcblx0ICogc2hvdWxkIGJlIGRpc2NhcmRlZC5cblx0ICovXG5cdHRoaXMubW9kaWZpY2F0aW9uID0gZmFsc2U7XG5cdHRoaXMucGFja2V0cztcblxuXG5cdHRoaXMucmVhZCA9IGZ1bmN0aW9uKGJ5dGVzKSB7XG5cdFx0Ly8gLSBBIG9uZS1vY3RldCB2ZXJzaW9uIG51bWJlci4gVGhlIG9ubHkgY3VycmVudGx5IGRlZmluZWQgdmFsdWUgaXNcblx0XHQvLyAxLlxuXHRcdHZhciB2ZXJzaW9uID0gYnl0ZXNbMF0uY2hhckNvZGVBdCgpO1xuXG5cdFx0aWYgKHZlcnNpb24gIT0gMSkge1xuXHRcdFx0dGhyb3cgbmV3IEVycm9yKCdWZXJzaW9uICcgKyB2ZXJzaW9uICsgJyBvZiBlbmNyeXB0ZWQgaW50ZWdyaXR5IHByb3RlY3RlZCcgK1xuXHRcdFx0XHQnIHBhY2tldCBpcyB1bnN1cHBvcnRlZCcpO1xuXHRcdH1cblxuXHRcdC8vIC0gRW5jcnlwdGVkIGRhdGEsIHRoZSBvdXRwdXQgb2YgdGhlIHNlbGVjdGVkIHN5bW1ldHJpYy1rZXkgY2lwaGVyXG5cdFx0Ly8gICBvcGVyYXRpbmcgaW4gQ2lwaGVyIEZlZWRiYWNrIG1vZGUgd2l0aCBzaGlmdCBhbW91bnQgZXF1YWwgdG8gdGhlXG5cdFx0Ly8gICBibG9jayBzaXplIG9mIHRoZSBjaXBoZXIgKENGQi1uIHdoZXJlIG4gaXMgdGhlIGJsb2NrIHNpemUpLlxuXHRcdHRoaXMuZW5jcnlwdGVkID0gYnl0ZXMuc3Vic3RyKDEpO1xuXHR9XG5cblx0dGhpcy53cml0ZSA9IGZ1bmN0aW9uKCkge1xuXHRcdFxuXHRcdHJldHVybiBTdHJpbmcuZnJvbUNoYXJDb2RlKDEpIC8vIFZlcnNpb25cblx0XHRcdCsgdGhpcy5lbmNyeXB0ZWQ7XG5cdH1cblxuXHR0aGlzLmVuY3J5cHQgPSBmdW5jdGlvbihzeW1tZXRyaWNfYWxnb3JpdGhtLCBrZXkpIHtcblx0XHR2YXIgYnl0ZXMgPSB0aGlzLnBhY2tldHMud3JpdGUoKVxuXHRcdFxuXHRcdHZhciBwcmVmaXhyYW5kb20gPSBvcGVucGdwX2NyeXB0b19nZXRQcmVmaXhSYW5kb20oc3ltbWV0cmljX2FsZ29yaXRobSk7XG5cdFx0dmFyIHByZWZpeCA9IHByZWZpeHJhbmRvbVxuXHRcdFx0XHQrIHByZWZpeHJhbmRvbS5jaGFyQXQocHJlZml4cmFuZG9tLmxlbmd0aCAtIDIpXG5cdFx0XHRcdCsgcHJlZml4cmFuZG9tLmNoYXJBdChwcmVmaXhyYW5kb20ubGVuZ3RoIC0gMSlcblxuXHRcdHZhciB0b2hhc2ggPSBieXRlcztcblxuXG5cdFx0Ly8gTW9kaWZpY2F0aW9uIGRldGVjdGlvbiBjb2RlIHBhY2tldC5cblx0XHR0b2hhc2ggKz0gU3RyaW5nLmZyb21DaGFyQ29kZSgweEQzKTtcblx0XHR0b2hhc2ggKz0gU3RyaW5nLmZyb21DaGFyQ29kZSgweDE0KTtcblxuXHRcdHV0aWwucHJpbnRfZGVidWdfaGV4c3RyX2R1bXAoXCJkYXRhIHRvIGJlIGhhc2hlZDpcIlxuXHRcdFx0XHQsIHByZWZpeCArIHRvaGFzaCk7XG5cblx0XHR0b2hhc2ggKz0gc3RyX3NoYTEocHJlZml4ICsgdG9oYXNoKTtcblxuXHRcdHV0aWwucHJpbnRfZGVidWdfaGV4c3RyX2R1bXAoXCJoYXNoOlwiXG5cdFx0XHRcdCwgdG9oYXNoLnN1YnN0cmluZyh0b2hhc2gubGVuZ3RoIC0gMjAsXG5cdFx0XHRcdFx0XHR0b2hhc2gubGVuZ3RoKSk7XG5cblx0XHR0aGlzLmVuY3J5cHRlZCA9IG9wZW5wZ3BfY3J5cHRvX3N5bW1ldHJpY0VuY3J5cHQocHJlZml4cmFuZG9tLFxuXHRcdFx0XHRzeW1tZXRyaWNfYWxnb3JpdGhtLCBrZXksIHRvaGFzaCwgZmFsc2UpLnN1YnN0cmluZygwLFxuXHRcdFx0XHRwcmVmaXgubGVuZ3RoICsgdG9oYXNoLmxlbmd0aCk7XG5cdH1cblxuXHQvKipcblx0ICogRGVjcnlwdHMgdGhlIGVuY3J5cHRlZCBkYXRhIGNvbnRhaW5lZCBpbiB0aGlzIG9iamVjdCByZWFkX3BhY2tldCBtdXN0XG5cdCAqIGhhdmUgYmVlbiBjYWxsZWQgYmVmb3JlXG5cdCAqIFxuXHQgKiBAcGFyYW0ge0ludGVnZXJ9IHN5bW1ldHJpY19hbGdvcml0aG1fdHlwZVxuXHQgKiAgICAgICAgICAgIFRoZSBzZWxlY3RlZCBzeW1tZXRyaWMgZW5jcnlwdGlvbiBhbGdvcml0aG0gdG8gYmUgdXNlZFxuXHQgKiBAcGFyYW0ge1N0cmluZ30ga2V5IFRoZSBrZXkgb2YgY2lwaGVyIGJsb2Nrc2l6ZSBsZW5ndGggdG8gYmUgdXNlZFxuXHQgKiBAcmV0dXJuIHtTdHJpbmd9IFRoZSBkZWNyeXB0ZWQgZGF0YSBvZiB0aGlzIHBhY2tldFxuXHQgKi9cblx0dGhpcy5kZWNyeXB0ID0gZnVuY3Rpb24oc3ltbWV0cmljX2FsZ29yaXRobV90eXBlLCBrZXkpIHtcblx0XHR2YXIgZGVjcnlwdGVkID0gb3BlbnBncF9jcnlwdG9fc3ltbWV0cmljRGVjcnlwdChcblx0XHRcdFx0c3ltbWV0cmljX2FsZ29yaXRobV90eXBlLCBrZXksIHRoaXMuZW5jcnlwdGVkLCBmYWxzZSk7XG5cblxuXHRcdC8vIHRoZXJlIG11c3QgYmUgYSBtb2RpZmljYXRpb24gZGV0ZWN0aW9uIGNvZGUgcGFja2V0IGFzIHRoZVxuXHRcdC8vIGxhc3QgcGFja2V0IGFuZCBldmVyeXRoaW5nIGdldHMgaGFzaGVkIGV4Y2VwdCB0aGUgaGFzaCBpdHNlbGZcblx0XHR0aGlzLmhhc2ggPSBzdHJfc2hhMShcblx0XHRcdG9wZW5wZ3BfY3J5cHRvX01EQ1N5c3RlbUJ5dGVzKHN5bW1ldHJpY19hbGdvcml0aG1fdHlwZSwga2V5LCB0aGlzLmVuY3J5cHRlZClcblx0XHRcdCsgZGVjcnlwdGVkLnN1YnN0cmluZygwLCBkZWNyeXB0ZWQubGVuZ3RoIC0gMjApKTtcblxuXHRcdHV0aWwucHJpbnRfZGVidWdfaGV4c3RyX2R1bXAoXCJjYWxjIGhhc2ggPSBcIiwgdGhpcy5oYXNoKTtcblxuXHRcdHZhciBtZGMgPSBkZWNyeXB0ZWQuc3Vic3RyKGRlY3J5cHRlZC5sZW5ndGggLSAyMCwgMjApO1xuXG5cdFx0aWYodGhpcy5oYXNoICE9IG1kYykge1xuXHRcdFx0dGhyb3cgbmV3IEVycm9yKCdNb2RpZmljYXRpb24gZGV0ZWN0ZWQuJyk7XG5cdFx0fVxuXHRcdGVsc2Vcblx0XHRcdHRoaXMucGFja2V0cy5yZWFkKGRlY3J5cHRlZC5zdWJzdHIoMCwgZGVjcnlwdGVkLmxlbmd0aCAtIDIyKSk7XG5cdH1cbn07XG4iLCIvLyBHUEc0QnJvd3NlcnMgLSBBbiBPcGVuUEdQIGltcGxlbWVudGF0aW9uIGluIGphdmFzY3JpcHRcbi8vIENvcHlyaWdodCAoQykgMjAxMSBSZWN1cml0eSBMYWJzIEdtYkhcbi8vIFxuLy8gVGhpcyBsaWJyYXJ5IGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vclxuLy8gbW9kaWZ5IGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIExlc3NlciBHZW5lcmFsIFB1YmxpY1xuLy8gTGljZW5zZSBhcyBwdWJsaXNoZWQgYnkgdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyXG4vLyB2ZXJzaW9uIDIuMSBvZiB0aGUgTGljZW5zZSwgb3IgKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbi8vIFxuLy8gVGhpcyBsaWJyYXJ5IGlzIGRpc3RyaWJ1dGVkIGluIHRoZSBob3BlIHRoYXQgaXQgd2lsbCBiZSB1c2VmdWwsXG4vLyBidXQgV0lUSE9VVCBBTlkgV0FSUkFOVFk7IHdpdGhvdXQgZXZlbiB0aGUgaW1wbGllZCB3YXJyYW50eSBvZlxuLy8gTUVSQ0hBTlRBQklMSVRZIG9yIEZJVE5FU1MgRk9SIEEgUEFSVElDVUxBUiBQVVJQT1NFLiAgU2VlIHRoZSBHTlVcbi8vIExlc3NlciBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGZvciBtb3JlIGRldGFpbHMuXG4vLyBcbi8vIFlvdSBzaG91bGQgaGF2ZSByZWNlaXZlZCBhIGNvcHkgb2YgdGhlIEdOVSBMZXNzZXIgR2VuZXJhbCBQdWJsaWNcbi8vIExpY2Vuc2UgYWxvbmcgd2l0aCB0aGlzIGxpYnJhcnk7IGlmIG5vdCwgd3JpdGUgdG8gdGhlIEZyZWUgU29mdHdhcmVcbi8vIEZvdW5kYXRpb24sIEluYy4sIDUxIEZyYW5rbGluIFN0cmVldCwgRmlmdGggRmxvb3IsIEJvc3RvbiwgTUEgIDAyMTEwLTEzMDEgIFVTQVxuXG4vKipcbiAqIEBjbGFzc1xuICogQGNsYXNzZGVzYyBQdWJsaWMtS2V5IEVuY3J5cHRlZCBTZXNzaW9uIEtleSBQYWNrZXRzIChUYWcgMSlcbiAqIFxuICogUkZDNDg4MCA1LjE6IEEgUHVibGljLUtleSBFbmNyeXB0ZWQgU2Vzc2lvbiBLZXkgcGFja2V0IGhvbGRzIHRoZSBzZXNzaW9uIGtleVxuICogdXNlZCB0byBlbmNyeXB0IGEgbWVzc2FnZS4gWmVybyBvciBtb3JlIFB1YmxpYy1LZXkgRW5jcnlwdGVkIFNlc3Npb24gS2V5XG4gKiBwYWNrZXRzIGFuZC9vciBTeW1tZXRyaWMtS2V5IEVuY3J5cHRlZCBTZXNzaW9uIEtleSBwYWNrZXRzIG1heSBwcmVjZWRlIGFcbiAqIFN5bW1ldHJpY2FsbHkgRW5jcnlwdGVkIERhdGEgUGFja2V0LCB3aGljaCBob2xkcyBhbiBlbmNyeXB0ZWQgbWVzc2FnZS4gVGhlXG4gKiBtZXNzYWdlIGlzIGVuY3J5cHRlZCB3aXRoIHRoZSBzZXNzaW9uIGtleSwgYW5kIHRoZSBzZXNzaW9uIGtleSBpcyBpdHNlbGZcbiAqIGVuY3J5cHRlZCBhbmQgc3RvcmVkIGluIHRoZSBFbmNyeXB0ZWQgU2Vzc2lvbiBLZXkgcGFja2V0KHMpLiBUaGVcbiAqIFN5bW1ldHJpY2FsbHkgRW5jcnlwdGVkIERhdGEgUGFja2V0IGlzIHByZWNlZGVkIGJ5IG9uZSBQdWJsaWMtS2V5IEVuY3J5cHRlZFxuICogU2Vzc2lvbiBLZXkgcGFja2V0IGZvciBlYWNoIE9wZW5QR1Aga2V5IHRvIHdoaWNoIHRoZSBtZXNzYWdlIGlzIGVuY3J5cHRlZC5cbiAqIFRoZSByZWNpcGllbnQgb2YgdGhlIG1lc3NhZ2UgZmluZHMgYSBzZXNzaW9uIGtleSB0aGF0IGlzIGVuY3J5cHRlZCB0byB0aGVpclxuICogcHVibGljIGtleSwgZGVjcnlwdHMgdGhlIHNlc3Npb24ga2V5LCBhbmQgdGhlbiB1c2VzIHRoZSBzZXNzaW9uIGtleSB0b1xuICogZGVjcnlwdCB0aGUgbWVzc2FnZS5cbiAqL1xubW9kdWxlLmV4cG9ydHMgPSBmdW5jdGlvbiBwYWNrZXRfcHVibGljX2tleV9lbmNyeXB0ZWRfc2Vzc2lvbl9rZXkoKSB7XG5cdHRoaXMudmVyc2lvbiA9IDM7XG5cblx0dGhpcy5wdWJsaWNLZXlJZCA9IG5ldyBvcGVucGdwX3R5cGVfa2V5aWQoKTtcblx0dGhpcy5wdWJsaWNLZXlBbGdvcml0aG0gPSAncnNhX2VuY3J5cHQnO1xuXG5cdHRoaXMuc2Vzc2lvbktleSA9IG51bGw7XG5cdHRoaXMuc2Vzc2lvbktleUFsZ29yaXRobSA9ICdhZXMyNTYnO1xuXG5cdC8qKiBAdHlwZSB7b3BlbnBncF90eXBlX21waVtdfSAqL1xuXHR0aGlzLmVuY3J5cHRlZCA9IFtdO1xuXG5cdC8qKlxuXHQgKiBQYXJzaW5nIGZ1bmN0aW9uIGZvciBhIHB1YmxpY2tleSBlbmNyeXB0ZWQgc2Vzc2lvbiBrZXkgcGFja2V0ICh0YWcgMSkuXG5cdCAqIFxuXHQgKiBAcGFyYW0ge1N0cmluZ30gaW5wdXQgUGF5bG9hZCBvZiBhIHRhZyAxIHBhY2tldFxuXHQgKiBAcGFyYW0ge0ludGVnZXJ9IHBvc2l0aW9uIFBvc2l0aW9uIHRvIHN0YXJ0IHJlYWRpbmcgZnJvbSB0aGUgaW5wdXQgc3RyaW5nXG5cdCAqIEBwYXJhbSB7SW50ZWdlcn0gbGVuIExlbmd0aCBvZiB0aGUgcGFja2V0IG9yIHRoZSByZW1haW5pbmcgbGVuZ3RoIG9mXG5cdCAqICAgICAgICAgICAgaW5wdXQgYXQgcG9zaXRpb25cblx0ICogQHJldHVybiB7b3BlbnBncF9wYWNrZXRfZW5jcnlwdGVkZGF0YX0gT2JqZWN0IHJlcHJlc2VudGF0aW9uXG5cdCAqL1xuXHR0aGlzLnJlYWQgPSBmdW5jdGlvbihieXRlcykge1xuXHRcdGlmIChieXRlcy5sZW5ndGggPCAxMCkge1xuXHRcdFx0dXRpbC5wcmludF9lcnJvcihcIm9wZW5wZ3AucGFja2V0LmVuY3J5cHRlZHNlc3Npb25rZXkuanNcXG5cIiBcblx0XHRcdFx0KyAnaW52YWxpZCBsZW5ndGgnKTtcblx0XHRcdHJldHVybiBudWxsO1xuXHRcdH1cblxuXHRcdHRoaXMudmVyc2lvbiA9IGJ5dGVzWzBdLmNoYXJDb2RlQXQoKTtcblx0XHR0aGlzLnB1YmxpY19rZXlfaWQucmVhZF9wYWNrZXQoYnl0ZXMsIDEpO1xuXHRcdHRoaXMucHVibGljX2tleV9hbGdvcml0aG0gPSBieXRlc1s5XS5jaGFyQ29kZUF0KCk7XG5cblx0XHR2YXIgaSA9IDEwO1xuXG5cdFx0c3dpdGNoICh0aGlzLnB1YmxpY19rZXlfYWxnb3JpdGhtKSB7XG5cblx0XHRjYXNlIG9wZW5wZ3AucHVibGlja2V5LnJzYV9lbmNyeXB0OlxuXHRcdGNhc2Ugb3BlbnBncC5wdWJsaWNrZXkucnNhX2VuY3J5cHRfc2lnbjpcblx0XHRcdHRoaXMuZW5jcnlwdGVkID0gW107XG5cdFx0XHR0aGlzLmVuY3J5cHRlZFswXSA9IG5ldyBvcGVucGdwX3R5cGVfbXBpKCk7XG5cdFx0XHR0aGlzLmVuY3J5cHRlZFswXS5yZWFkKGJ5dGVzLnN1YnN0cihpKSk7XG5cdFx0XHRicmVhaztcblxuXHRcdGNhc2Ugb3BlbnBncC5wdWJsaWNrZXkuZWxnYW1hbDpcblx0XHRcdHRoaXMuZW5jcnlwdGVkID0gW107XG5cdFx0XHR0aGlzLmVuY3J5cHRlZFswXSA9IG5ldyBvcGVucGdwX3R5cGVfbXBpKCk7XG5cdFx0XHRpICs9IHRoaXMuZW5jcnlwdGVkWzBdLnJlYWQoYnl0ZXMuc3Vic3RyKGkpKTtcblx0XHRcdHRoaXMuZW5jcnlwdGVkWzFdID0gbmV3IG9wZW5wZ3BfdHlwZV9tcGkoKTtcblx0XHRcdHRoaXMuZW5jcnlwdGVkWzFdLnJlYWQoYnl0ZXMuc3Vic3RyKGkpKTtcblx0XHRcdGJyZWFrO1xuXG5cdFx0ZGVmYXVsdDpcblx0XHRcdHV0aWwucHJpbnRfZXJyb3IoXCJvcGVucGdwLnBhY2tldC5lbmNyeXB0ZWRzZXNzaW9ua2V5LmpzXFxuXCJcblx0XHRcdFx0XHQrIFwidW5rbm93biBwdWJsaWMga2V5IHBhY2tldCBhbGdvcml0aG0gdHlwZSBcIlxuXHRcdFx0XHRcdCsgdGhpcy5wdWJsaWNfa2V5X2FsZ29yaXRobSk7XG5cdFx0XHRicmVhaztcblx0XHR9XG5cdH1cblxuXHQvKipcblx0ICogQ3JlYXRlIGEgc3RyaW5nIHJlcHJlc2VudGF0aW9uIG9mIGEgdGFnIDEgcGFja2V0XG5cdCAqIFxuXHQgKiBAcGFyYW0ge1N0cmluZ30gcHVibGljS2V5SWRcblx0ICogICAgICAgICAgICAgVGhlIHB1YmxpYyBrZXkgaWQgY29ycmVzcG9uZGluZyB0byBwdWJsaWNNUElzIGtleSBhcyBzdHJpbmdcblx0ICogQHBhcmFtIHtvcGVucGdwX3R5cGVfbXBpW119IHB1YmxpY01QSXNcblx0ICogICAgICAgICAgICBNdWx0aXByZWNpc2lvbiBpbnRlZ2VyIG9iamVjdHMgZGVzY3JpYmluZyB0aGUgcHVibGljIGtleVxuXHQgKiBAcGFyYW0ge0ludGVnZXJ9IHB1YmFsZ29cblx0ICogICAgICAgICAgICBUaGUgY29ycmVzcG9uZGluZyBwdWJsaWMga2V5IGFsZ29yaXRobSAvLyBTZWUgUkZDNDg4MCA5LjFcblx0ICogQHBhcmFtIHtJbnRlZ2VyfSBzeW1tYWxnb1xuXHQgKiAgICAgICAgICAgIFRoZSBzeW1tZXRyaWMgY2lwaGVyIGFsZ29yaXRobSB1c2VkIHRvIGVuY3J5cHQgdGhlIGRhdGEgXG5cdCAqICAgICAgICAgICAgd2l0aGluIGFuIGVuY3J5cHRlZGRhdGFwYWNrZXQgb3IgZW5jcnlwdGVkaW50ZWdyaXR5LVxuXHQgKiAgICAgICAgICAgIHByb3RlY3RlZGRhdGFwYWNrZXQgXG5cdCAqICAgICAgICAgICAgZm9sbG93aW5nIHRoaXMgcGFja2V0IC8vU2VlIFJGQzQ4ODAgOS4yXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBzZXNzaW9ua2V5XG5cdCAqICAgICAgICAgICAgQSBzdHJpbmcgb2YgcmFuZG9tYnl0ZXMgcmVwcmVzZW50aW5nIHRoZSBzZXNzaW9uIGtleVxuXHQgKiBAcmV0dXJuIHtTdHJpbmd9IFRoZSBzdHJpbmcgcmVwcmVzZW50YXRpb25cblx0ICovXG5cdHRoaXMud3JpdGUgPSBmdW5jdGlvbigpIHtcblxuXHRcdHZhciByZXN1bHQgPSBTdHJpbmcuZnJvbUNoYXJDb2RlKHRoaXMudmVyc2lvbik7XG5cdFx0cmVzdWx0ICs9IHRoaXMucHVibGljX2tleV9pZC5ieXRlcztcblx0XHRyZXN1bHQgKz0gU3RyaW5nLmZyb21DaGFyQ29kZSh0aGlzLnB1YmxpY19rZXlfYWxnb3JpdGhtKTtcblxuXHRcdGZvciAoIHZhciBpID0gMDsgaSA8IHRoaXMuZW5jcnlwdGVkLmxlbmd0aDsgaSsrKSB7XG5cdFx0XHRyZXN1bHQgKz0gdGhpcy5lbmNyeXB0ZWRbaV0ud3JpdGUoKVxuXHRcdH1cblxuXHRcdHJldHVybiByZXN1bHQ7XG5cdH1cblxuXHR0aGlzLmVuY3J5cHQgPSBmdW5jdGlvbihrZXkpIHtcblx0XHRcblx0XHR2YXIgZGF0YSA9IFN0cmluZy5mcm9tQ2hhckNvZGUodGhpcy5zeW1tZXRyaWNfYWxnb3JpdGhtKTtcblx0XHRkYXRhICs9IHRoaXMuc3ltbWV0cmljX2tleTtcblx0XHR2YXIgY2hlY2tzdW0gPSB1dGlsLmNhbGNfY2hlY2tzdW0odGhpcy5zeW1tZXRyaWNfa2V5KTtcblx0XHRkYXRhICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoKGNoZWNrc3VtID4+IDgpICYgMHhGRik7XG5cdFx0ZGF0YSArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKChjaGVja3N1bSkgJiAweEZGKTtcblxuXHRcdHZhciBtcGkgPSBuZXcgb3BlbnBncF90eXBlX21waSgpO1xuXHRcdG1waS5mcm9tQnl0ZXMob3BlbnBncF9lbmNvZGluZ19lbWVfcGtjczFfZW5jb2RlKFxuXHRcdFx0ZGF0YSxcblx0XHRcdGtleS5tcGlbMF0uYnl0ZUxlbmd0aCgpKSk7XG5cblx0XHR0aGlzLmVuY3J5cHRlZCA9IG9wZW5wZ3BfY3J5cHRvX2FzeW1ldHJpY0VuY3J5cHQoXG5cdFx0XHR0aGlzLnB1YmxpY19rZXlfYWxnb3JpdGhtLCBcblx0XHRcdGtleS5tcGksXG5cdFx0XHRtcGkpO1xuXHR9XG5cblx0LyoqXG5cdCAqIERlY3J5cHRzIHRoZSBzZXNzaW9uIGtleSAob25seSBmb3IgcHVibGljIGtleSBlbmNyeXB0ZWQgc2Vzc2lvbiBrZXlcblx0ICogcGFja2V0cyAodGFnIDEpXG5cdCAqIFxuXHQgKiBAcGFyYW0ge29wZW5wZ3BfbXNnX21lc3NhZ2V9IG1zZ1xuXHQgKiAgICAgICAgICAgIFRoZSBtZXNzYWdlIG9iamVjdCAod2l0aCBtZW1iZXIgZW5jcnlwdGVkRGF0YVxuXHQgKiBAcGFyYW0ge29wZW5wZ3BfbXNnX3ByaXZhdGVrZXl9IGtleVxuXHQgKiAgICAgICAgICAgIFByaXZhdGUga2V5IHdpdGggc2VjTVBJcyB1bmxvY2tlZFxuXHQgKiBAcmV0dXJuIHtTdHJpbmd9IFRoZSB1bmVuY3J5cHRlZCBzZXNzaW9uIGtleVxuXHQgKi9cblx0dGhpcy5kZWNyeXB0ID0gZnVuY3Rpb24oa2V5KSB7XG5cdFx0dmFyIHJlc3VsdCA9IG9wZW5wZ3BfY3J5cHRvX2FzeW1ldHJpY0RlY3J5cHQoXG5cdFx0XHRcdHRoaXMucHVibGljX2tleV9hbGdvcml0aG0sXG5cdFx0XHRcdGtleS5tcGksXG5cdFx0XHRcdHRoaXMuZW5jcnlwdGVkKS50b0J5dGVzKCk7XG5cblx0XHR2YXIgY2hlY2tzdW0gPSAoKHJlc3VsdC5jaGFyQ29kZUF0KHJlc3VsdC5sZW5ndGggLSAyKSA8PCA4KSBcblx0XHRcdCsgcmVzdWx0LmNoYXJDb2RlQXQocmVzdWx0Lmxlbmd0aCAtIDEpKTtcblxuXHRcdHZhciBkZWNvZGVkID0gb3BlbnBncF9lbmNvZGluZ19lbWVfcGtjczFfZGVjb2RlKFxuXHRcdFx0cmVzdWx0LFxuXHRcdFx0a2V5Lm1waVswXS5ieXRlTGVuZ3RoKCkpO1xuXG5cdFx0dmFyIGtleSA9IGRlY29kZWQuc3Vic3RyaW5nKDEsIGRlY29kZWQubGVuZ3RoIC0gMik7XG5cblx0XHRpZihjaGVja3N1bSAhPSB1dGlsLmNhbGNfY2hlY2tzdW0oa2V5KSkge1xuXHRcdFx0dXRpbC5wcmludF9lcnJvcihcIkNoZWNrc3VtIG1pc21hdGNoXCIpO1xuXHRcdH1cblx0XHRlbHNlIHtcblx0XHRcdHRoaXMuc3ltbWV0cmljX2tleSA9IGtleTtcblx0XHRcdHRoaXMuc3ltbWV0cmljX2FsZ29yaXRobSA9IGRlY29kZWQuY2hhckNvZGVBdCgwKTtcblx0XHR9XG5cdH1cbn07XG5cbiIsIi8vIEdQRzRCcm93c2VycyAtIEFuIE9wZW5QR1AgaW1wbGVtZW50YXRpb24gaW4gamF2YXNjcmlwdFxuLy8gQ29weXJpZ2h0IChDKSAyMDExIFJlY3VyaXR5IExhYnMgR21iSFxuLy8gXG4vLyBUaGlzIGxpYnJhcnkgaXMgZnJlZSBzb2Z0d2FyZTsgeW91IGNhbiByZWRpc3RyaWJ1dGUgaXQgYW5kL29yXG4vLyBtb2RpZnkgaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgTGVzc2VyIEdlbmVyYWwgUHVibGljXG4vLyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieSB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uOyBlaXRoZXJcbi8vIHZlcnNpb24gMi4xIG9mIHRoZSBMaWNlbnNlLCBvciAoYXQgeW91ciBvcHRpb24pIGFueSBsYXRlciB2ZXJzaW9uLlxuLy8gXG4vLyBUaGlzIGxpYnJhcnkgaXMgZGlzdHJpYnV0ZWQgaW4gdGhlIGhvcGUgdGhhdCBpdCB3aWxsIGJlIHVzZWZ1bCxcbi8vIGJ1dCBXSVRIT1VUIEFOWSBXQVJSQU5UWTsgd2l0aG91dCBldmVuIHRoZSBpbXBsaWVkIHdhcnJhbnR5IG9mXG4vLyBNRVJDSEFOVEFCSUxJVFkgb3IgRklUTkVTUyBGT1IgQSBQQVJUSUNVTEFSIFBVUlBPU0UuICBTZWUgdGhlIEdOVVxuLy8gTGVzc2VyIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgZm9yIG1vcmUgZGV0YWlscy5cbi8vIFxuLy8gWW91IHNob3VsZCBoYXZlIHJlY2VpdmVkIGEgY29weSBvZiB0aGUgR05VIExlc3NlciBHZW5lcmFsIFB1YmxpY1xuLy8gTGljZW5zZSBhbG9uZyB3aXRoIHRoaXMgbGlicmFyeTsgaWYgbm90LCB3cml0ZSB0byB0aGUgRnJlZSBTb2Z0d2FyZVxuLy8gRm91bmRhdGlvbiwgSW5jLiwgNTEgRnJhbmtsaW4gU3RyZWV0LCBGaWZ0aCBGbG9vciwgQm9zdG9uLCBNQSAgMDIxMTAtMTMwMSAgVVNBXG5cbi8qKlxuICogQGNsYXNzXG4gKiBAY2xhc3NkZXNjIFB1YmxpYy1LZXkgRW5jcnlwdGVkIFNlc3Npb24gS2V5IFBhY2tldHMgKFRhZyAxKVxuICogXG4gKiBSRkM0ODgwIDUuMTogQSBQdWJsaWMtS2V5IEVuY3J5cHRlZCBTZXNzaW9uIEtleSBwYWNrZXQgaG9sZHMgdGhlIHNlc3Npb24ga2V5XG4gKiB1c2VkIHRvIGVuY3J5cHQgYSBtZXNzYWdlLiBaZXJvIG9yIG1vcmUgUHVibGljLUtleSBFbmNyeXB0ZWQgU2Vzc2lvbiBLZXlcbiAqIHBhY2tldHMgYW5kL29yIFN5bW1ldHJpYy1LZXkgRW5jcnlwdGVkIFNlc3Npb24gS2V5IHBhY2tldHMgbWF5IHByZWNlZGUgYVxuICogU3ltbWV0cmljYWxseSBFbmNyeXB0ZWQgRGF0YSBQYWNrZXQsIHdoaWNoIGhvbGRzIGFuIGVuY3J5cHRlZCBtZXNzYWdlLiBUaGVcbiAqIG1lc3NhZ2UgaXMgZW5jcnlwdGVkIHdpdGggdGhlIHNlc3Npb24ga2V5LCBhbmQgdGhlIHNlc3Npb24ga2V5IGlzIGl0c2VsZlxuICogZW5jcnlwdGVkIGFuZCBzdG9yZWQgaW4gdGhlIEVuY3J5cHRlZCBTZXNzaW9uIEtleSBwYWNrZXQocykuIFRoZVxuICogU3ltbWV0cmljYWxseSBFbmNyeXB0ZWQgRGF0YSBQYWNrZXQgaXMgcHJlY2VkZWQgYnkgb25lIFB1YmxpYy1LZXkgRW5jcnlwdGVkXG4gKiBTZXNzaW9uIEtleSBwYWNrZXQgZm9yIGVhY2ggT3BlblBHUCBrZXkgdG8gd2hpY2ggdGhlIG1lc3NhZ2UgaXMgZW5jcnlwdGVkLlxuICogVGhlIHJlY2lwaWVudCBvZiB0aGUgbWVzc2FnZSBmaW5kcyBhIHNlc3Npb24ga2V5IHRoYXQgaXMgZW5jcnlwdGVkIHRvIHRoZWlyXG4gKiBwdWJsaWMga2V5LCBkZWNyeXB0cyB0aGUgc2Vzc2lvbiBrZXksIGFuZCB0aGVuIHVzZXMgdGhlIHNlc3Npb24ga2V5IHRvXG4gKiBkZWNyeXB0IHRoZSBtZXNzYWdlLlxuICovXG5tb2R1bGUuZXhwb3J0cyA9IGZ1bmN0aW9uIHBhY2tldF9zeW1fZW5jcnlwdGVkX3Nlc3Npb25fa2V5KCkge1xuXHR0aGlzLnRhZyA9IDM7XG5cdHRoaXMucHJpdmF0ZV9hbGdvcml0aG0gPSBudWxsO1xuXHR0aGlzLmFsZ29yaXRobSA9IG9wZW5wZ3Auc3ltbWV0cmljLmFlczI1Njtcblx0dGhpcy5lbmNyeXB0ZWQgPSBudWxsO1xuXHR0aGlzLnMyayA9IG5ldyBvcGVucGdwX3R5cGVfczJrKCk7XG5cblx0LyoqXG5cdCAqIFBhcnNpbmcgZnVuY3Rpb24gZm9yIGEgc3ltbWV0cmljIGVuY3J5cHRlZCBzZXNzaW9uIGtleSBwYWNrZXQgKHRhZyAzKS5cblx0ICogXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBpbnB1dCBQYXlsb2FkIG9mIGEgdGFnIDEgcGFja2V0XG5cdCAqIEBwYXJhbSB7SW50ZWdlcn0gcG9zaXRpb24gUG9zaXRpb24gdG8gc3RhcnQgcmVhZGluZyBmcm9tIHRoZSBpbnB1dCBzdHJpbmdcblx0ICogQHBhcmFtIHtJbnRlZ2VyfSBsZW5cblx0ICogICAgICAgICAgICBMZW5ndGggb2YgdGhlIHBhY2tldCBvciB0aGUgcmVtYWluaW5nIGxlbmd0aCBvZlxuXHQgKiAgICAgICAgICAgIGlucHV0IGF0IHBvc2l0aW9uXG5cdCAqIEByZXR1cm4ge29wZW5wZ3BfcGFja2V0X2VuY3J5cHRlZGRhdGF9IE9iamVjdCByZXByZXNlbnRhdGlvblxuXHQgKi9cblx0dGhpcy5yZWFkID0gZnVuY3Rpb24oYnl0ZXMpIHtcblx0XHQvLyBBIG9uZS1vY3RldCB2ZXJzaW9uIG51bWJlci4gVGhlIG9ubHkgY3VycmVudGx5IGRlZmluZWQgdmVyc2lvbiBpcyA0LlxuXHRcdHRoaXMudmVyc2lvbiA9IGJ5dGVzWzBdLmNoYXJDb2RlQXQoKTtcblxuXHRcdC8vIEEgb25lLW9jdGV0IG51bWJlciBkZXNjcmliaW5nIHRoZSBzeW1tZXRyaWMgYWxnb3JpdGhtIHVzZWQuXG5cdFx0dmFyIGFsZ28gPSBieXRlc1sxXS5jaGFyQ29kZUF0KCk7XG5cblx0XHQvLyBBIHN0cmluZy10by1rZXkgKFMySykgc3BlY2lmaWVyLCBsZW5ndGggYXMgZGVmaW5lZCBhYm92ZS5cblx0XHR2YXIgczJrbGVuZ3RoID0gdGhpcy5zMmsucmVhZChieXRlcy5zdWJzdHIoMikpO1xuXG5cdFx0Ly8gT3B0aW9uYWxseSwgdGhlIGVuY3J5cHRlZCBzZXNzaW9uIGtleSBpdHNlbGYsIHdoaWNoIGlzIGRlY3J5cHRlZFxuXHRcdC8vIHdpdGggdGhlIHN0cmluZy10by1rZXkgb2JqZWN0LlxuXHRcdHZhciBkb25lID0gczJrbGVuZ3RoICsgMjtcblxuXHRcdGlmKGRvbmUgPCBieXRlcy5sZW5ndGgpIHtcblx0XHRcdHRoaXMuZW5jcnlwdGVkID0gYnl0ZXMuc3Vic3RyKGRvbmUpO1xuXHRcdFx0dGhpcy5wcml2YXRlX2FsZ29yaXRobSA9IGFsZ29cblx0XHR9XG5cdFx0ZWxzZVxuXHRcdFx0dGhpcy5hbGdvcml0aG0gPSBhbGdvO1xuXHR9XG5cblx0dGhpcy53cml0ZSA9IGZ1bmN0aW9uKCkge1xuXHRcdHZhciBhbGdvID0gdGhpcy5lbmNyeXB0ZWQgPT0gbnVsbCA/IHRoaXMuYWxnb3JpdGhtIDpcblx0XHRcdHRoaXMucHJpdmF0ZV9hbGdvcml0aG07XG5cblx0XHR2YXIgYnl0ZXMgPSBTdHJpbmcuZnJvbUNoYXJDb2RlKHRoaXMudmVyc2lvbikgK1xuXHRcdFx0U3RyaW5nLmZyb21DaGFyQ29kZShhbGdvKSArXG5cdFx0XHR0aGlzLnMyay53cml0ZSgpO1xuXG5cdFx0aWYodGhpcy5lbmNyeXB0ZWQgIT0gbnVsbClcblx0XHRcdGJ5dGVzICs9IHRoaXMuZW5jcnlwdGVkO1xuXHRcdHJldHVybiBieXRlcztcblx0fVxuXG5cdC8qKlxuXHQgKiBEZWNyeXB0cyB0aGUgc2Vzc2lvbiBrZXkgKG9ubHkgZm9yIHB1YmxpYyBrZXkgZW5jcnlwdGVkIHNlc3Npb24ga2V5XG5cdCAqIHBhY2tldHMgKHRhZyAxKVxuXHQgKiBcblx0ICogQHBhcmFtIHtvcGVucGdwX21zZ19tZXNzYWdlfSBtc2dcblx0ICogICAgICAgICAgICBUaGUgbWVzc2FnZSBvYmplY3QgKHdpdGggbWVtYmVyIGVuY3J5cHRlZERhdGFcblx0ICogQHBhcmFtIHtvcGVucGdwX21zZ19wcml2YXRla2V5fSBrZXlcblx0ICogICAgICAgICAgICBQcml2YXRlIGtleSB3aXRoIHNlY01QSXMgdW5sb2NrZWRcblx0ICogQHJldHVybiB7U3RyaW5nfSBUaGUgdW5lbmNyeXB0ZWQgc2Vzc2lvbiBrZXlcblx0ICovXG5cdHRoaXMuZGVjcnlwdCA9IGZ1bmN0aW9uKHBhc3NwaHJhc2UpIHtcblx0XHR2YXIgYWxnbyA9IHRoaXMucHJpdmF0ZV9hbGdvcml0aG0gIT0gbnVsbCA/XG5cdFx0XHR0aGlzLnByaXZhdGVfYWxnb3JpdGhtIDpcblx0XHRcdHRoaXMuYWxnb3JpdGhtXG5cblx0XHR2YXIgbGVuZ3RoID0gb3BlbnBncF9jcnlwdG9fZ2V0S2V5TGVuZ3RoKGFsZ28pO1xuXHRcdHZhciBrZXkgPSB0aGlzLnMyay5wcm9kdWNlX2tleShwYXNzcGhyYXNlLCBsZW5ndGgpO1xuXG5cdFx0aWYodGhpcy5lbmNyeXB0ZWQgPT0gbnVsbCkge1xuXHRcdFx0dGhpcy5rZXkgPSBrZXk7XG5cblx0XHR9IGVsc2Uge1xuXHRcdFx0dmFyIGRlY3J5cHRlZCA9IG9wZW5wZ3BfY3J5cHRvX3N5bW1ldHJpY0RlY3J5cHQoXG5cdFx0XHRcdHRoaXMucHJpdmF0ZV9hbGdvcml0aG0sIGtleSwgdGhpcy5lbmNyeXB0ZWQsIHRydWUpO1xuXG5cdFx0XHR0aGlzLmFsZ29yaXRobSA9IGRlY3J5cHRlZFswXS5rZXlDb2RlQXQoKTtcblx0XHRcdHRoaXMua2V5ID0gZGVjcnlwdGVkLnN1YnN0cigxKTtcblx0XHR9XG5cdH1cblxuXHR0aGlzLmVuY3J5cHQgPSBmdW5jdGlvbihwYXNzcGhyYXNlKSB7XG5cdFx0dmFyIGxlbmd0aCA9IG9wZW5wZ3BfY3J5cHRvX2dldEtleUxlbmd0aCh0aGlzLnByaXZhdGVfYWxnb3JpdGhtKTtcblx0XHR2YXIga2V5ID0gdGhpcy5zMmsucHJvZHVjZV9rZXkocGFzc3BocmFzZSwgbGVuZ3RoKTtcblxuXG5cdFx0XG5cdFx0dmFyIHByaXZhdGVfa2V5ID0gU3RyaW5nLmZyb21DaGFyQ29kZSh0aGlzLmFsZ29yaXRobSkgK1xuXHRcdFx0b3BlbnBncF9jcnlwdG9fZ2V0UmFuZG9tQnl0ZXMoXG5cdFx0XHRcdG9wZW5wZ3BfY3J5cHRvX2dldEtleUxlbmd0aCh0aGlzLmFsZ29yaXRobSkpO1xuXG5cdFx0dGhpcy5lbmNyeXB0ZWQgPSBvcGVucGdwX2NyeXB0b19zeW1tZXRyaWNFbmNyeXB0KFxuXHRcdFx0XHRvcGVucGdwX2NyeXB0b19nZXRQcmVmaXhSYW5kb20odGhpcy5wcml2YXRlX2FsZ29yaXRobSksIFxuXHRcdFx0XHR0aGlzLnByaXZhdGVfYWxnb3JpdGhtLCBrZXksIHByaXZhdGVfa2V5LCB0cnVlKTtcblx0fVxufTtcblxuIiwiLy8gR1BHNEJyb3dzZXJzIC0gQW4gT3BlblBHUCBpbXBsZW1lbnRhdGlvbiBpbiBqYXZhc2NyaXB0XG4vLyBDb3B5cmlnaHQgKEMpIDIwMTEgUmVjdXJpdHkgTGFicyBHbWJIXG4vLyBcbi8vIFRoaXMgbGlicmFyeSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3Jcbi8vIG1vZGlmeSBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBMZXNzZXIgR2VuZXJhbCBQdWJsaWNcbi8vIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5IHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlclxuLy8gdmVyc2lvbiAyLjEgb2YgdGhlIExpY2Vuc2UsIG9yIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4vLyBcbi8vIFRoaXMgbGlicmFyeSBpcyBkaXN0cmlidXRlZCBpbiB0aGUgaG9wZSB0aGF0IGl0IHdpbGwgYmUgdXNlZnVsLFxuLy8gYnV0IFdJVEhPVVQgQU5ZIFdBUlJBTlRZOyB3aXRob3V0IGV2ZW4gdGhlIGltcGxpZWQgd2FycmFudHkgb2Zcbi8vIE1FUkNIQU5UQUJJTElUWSBvciBGSVRORVNTIEZPUiBBIFBBUlRJQ1VMQVIgUFVSUE9TRS4gIFNlZSB0aGUgR05VXG4vLyBMZXNzZXIgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBmb3IgbW9yZSBkZXRhaWxzLlxuLy8gXG4vLyBZb3Ugc2hvdWxkIGhhdmUgcmVjZWl2ZWQgYSBjb3B5IG9mIHRoZSBHTlUgTGVzc2VyIEdlbmVyYWwgUHVibGljXG4vLyBMaWNlbnNlIGFsb25nIHdpdGggdGhpcyBsaWJyYXJ5OyBpZiBub3QsIHdyaXRlIHRvIHRoZSBGcmVlIFNvZnR3YXJlXG4vLyBGb3VuZGF0aW9uLCBJbmMuLCA1MSBGcmFua2xpbiBTdHJlZXQsIEZpZnRoIEZsb29yLCBCb3N0b24sIE1BICAwMjExMC0xMzAxICBVU0FcblxuLyoqXG4gKiBAY2xhc3NcbiAqIEBjbGFzc2Rlc2MgSW1wbGVtZW50YXRpb24gb2YgdGhlIFN5bW1ldHJpY2FsbHkgRW5jcnlwdGVkIERhdGEgUGFja2V0IChUYWcgOSlcbiAqIFxuICogUkZDNDg4MCA1Ljc6IFRoZSBTeW1tZXRyaWNhbGx5IEVuY3J5cHRlZCBEYXRhIHBhY2tldCBjb250YWlucyBkYXRhIGVuY3J5cHRlZFxuICogd2l0aCBhIHN5bW1ldHJpYy1rZXkgYWxnb3JpdGhtLiBXaGVuIGl0IGhhcyBiZWVuIGRlY3J5cHRlZCwgaXQgY29udGFpbnMgb3RoZXJcbiAqIHBhY2tldHMgKHVzdWFsbHkgYSBsaXRlcmFsIGRhdGEgcGFja2V0IG9yIGNvbXByZXNzZWQgZGF0YSBwYWNrZXQsIGJ1dCBpblxuICogdGhlb3J5IG90aGVyIFN5bW1ldHJpY2FsbHkgRW5jcnlwdGVkIERhdGEgcGFja2V0cyBvciBzZXF1ZW5jZXMgb2YgcGFja2V0c1xuICogdGhhdCBmb3JtIHdob2xlIE9wZW5QR1AgbWVzc2FnZXMpLlxuICovXG5cbm1vZHVsZS5leHBvcnRzID0gZnVuY3Rpb24gcGFja2V0X3N5bW1ldHJpY2FsbHlfZW5jcnlwdGVkKCkge1xuXHR0aGlzLmVuY3J5cHRlZCA9IG51bGw7XG5cdC8qKiBEZWNyeXB0ZWQgcGFja2V0cyBjb250YWluZWQgd2l0aGluLiBcblx0ICogQHR5cGUge29wZW5wZ3BfcGFja2V0bGlzdH0gKi9cblx0dGhpcy5wYWNrZXRzO1xuXG5cdFxuXG5cdHRoaXMucmVhZCA9IGZ1bmN0aW9uKGJ5dGVzKSB7XG5cdFx0dGhpcy5lbmNyeXB0ZWQgPSBieXRlcztcblx0fVxuXG5cdHRoaXMud3JpdGUgPSBmdW5jdGlvbigpIHtcblx0XHRyZXR1cm4gdGhpcy5lbmNyeXB0ZWQ7XG5cdH1cblxuXHQvKipcblx0ICogU3ltbWV0cmljYWxseSBkZWNyeXB0IHRoZSBwYWNrZXQgZGF0YVxuXHQgKiBcblx0ICogQHBhcmFtIHtJbnRlZ2VyfSBzeW1tZXRyaWNfYWxnb3JpdGhtX3R5cGVcblx0ICogICAgICAgICAgICAgU3ltbWV0cmljIGtleSBhbGdvcml0aG0gdG8gdXNlIC8vIFNlZSBSRkM0ODgwIDkuMlxuXHQgKiBAcGFyYW0ge1N0cmluZ30ga2V5XG5cdCAqICAgICAgICAgICAgIEtleSBhcyBzdHJpbmcgd2l0aCB0aGUgY29ycmVzcG9uZGluZyBsZW5ndGggdG8gdGhlXG5cdCAqICAgICAgICAgICAgYWxnb3JpdGhtXG5cdCAqIEByZXR1cm4gVGhlIGRlY3J5cHRlZCBkYXRhO1xuXHQgKi9cblx0dGhpcy5kZWNyeXB0ID0gZnVuY3Rpb24oc3ltbWV0cmljX2FsZ29yaXRobV90eXBlLCBrZXkpIHtcblx0XHR2YXIgZGVjcnlwdGVkID0gb3BlbnBncF9jcnlwdG9fc3ltbWV0cmljRGVjcnlwdChcblx0XHRcdFx0c3ltbWV0cmljX2FsZ29yaXRobV90eXBlLCBrZXksIHRoaXMuZW5jcnlwdGVkLCB0cnVlKTtcblxuXHRcdHRoaXMucGFja2V0cy5yZWFkKGRlY3J5cHRlZCk7XG5cdH1cblxuXHR0aGlzLmVuY3J5cHQgPSBmdW5jdGlvbihhbGdvLCBrZXkpIHtcblx0XHR2YXIgZGF0YSA9IHRoaXMucGFja2V0cy53cml0ZSgpO1xuXG5cdFx0dGhpcy5lbmNyeXB0ZWQgPSBvcGVucGdwX2NyeXB0b19zeW1tZXRyaWNFbmNyeXB0KFxuXHRcdFx0XHRvcGVucGdwX2NyeXB0b19nZXRQcmVmaXhSYW5kb20oYWxnbyksIGFsZ28sIGtleSwgZGF0YSwgdHJ1ZSk7XG5cdH1cbn07XG4iLCIvLyBHUEc0QnJvd3NlcnMgLSBBbiBPcGVuUEdQIGltcGxlbWVudGF0aW9uIGluIGphdmFzY3JpcHRcbi8vIENvcHlyaWdodCAoQykgMjAxMSBSZWN1cml0eSBMYWJzIEdtYkhcbi8vIFxuLy8gVGhpcyBsaWJyYXJ5IGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vclxuLy8gbW9kaWZ5IGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIExlc3NlciBHZW5lcmFsIFB1YmxpY1xuLy8gTGljZW5zZSBhcyBwdWJsaXNoZWQgYnkgdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyXG4vLyB2ZXJzaW9uIDIuMSBvZiB0aGUgTGljZW5zZSwgb3IgKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbi8vIFxuLy8gVGhpcyBsaWJyYXJ5IGlzIGRpc3RyaWJ1dGVkIGluIHRoZSBob3BlIHRoYXQgaXQgd2lsbCBiZSB1c2VmdWwsXG4vLyBidXQgV0lUSE9VVCBBTlkgV0FSUkFOVFk7IHdpdGhvdXQgZXZlbiB0aGUgaW1wbGllZCB3YXJyYW50eSBvZlxuLy8gTUVSQ0hBTlRBQklMSVRZIG9yIEZJVE5FU1MgRk9SIEEgUEFSVElDVUxBUiBQVVJQT1NFLiAgU2VlIHRoZSBHTlVcbi8vIExlc3NlciBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGZvciBtb3JlIGRldGFpbHMuXG4vLyBcbi8vIFlvdSBzaG91bGQgaGF2ZSByZWNlaXZlZCBhIGNvcHkgb2YgdGhlIEdOVSBMZXNzZXIgR2VuZXJhbCBQdWJsaWNcbi8vIExpY2Vuc2UgYWxvbmcgd2l0aCB0aGlzIGxpYnJhcnk7IGlmIG5vdCwgd3JpdGUgdG8gdGhlIEZyZWUgU29mdHdhcmVcbi8vIEZvdW5kYXRpb24sIEluYy4sIDUxIEZyYW5rbGluIFN0cmVldCwgRmlmdGggRmxvb3IsIEJvc3RvbiwgTUEgIDAyMTEwLTEzMDEgIFVTQVxuXG4vKipcbiAqIEBjbGFzc1xuICogQGNsYXNzZGVzYyBJbXBsZW1lbnRhdGlvbiBvZiB0aGUgS2V5IE1hdGVyaWFsIFBhY2tldCAoVGFnIDUsNiw3LDE0KVxuICogICBcbiAqIFJGQzQ0ODAgNS41OlxuICogQSBrZXkgbWF0ZXJpYWwgcGFja2V0IGNvbnRhaW5zIGFsbCB0aGUgaW5mb3JtYXRpb24gYWJvdXQgYSBwdWJsaWMgb3JcbiAqIHByaXZhdGUga2V5LiAgVGhlcmUgYXJlIGZvdXIgdmFyaWFudHMgb2YgdGhpcyBwYWNrZXQgdHlwZSwgYW5kIHR3b1xuICogbWFqb3IgdmVyc2lvbnMuICBDb25zZXF1ZW50bHksIHRoaXMgc2VjdGlvbiBpcyBjb21wbGV4LlxuICovXG5tb2R1bGUuZXhwb3J0cyA9IGZ1bmN0aW9uIHBhY2tldF9wdWJsaWNfa2V5KCkge1xuXHQvKiogS2V5IGNyZWF0aW9uIGRhdGUuXG5cdCAqIEB0eXBlIHtEYXRlfSAqL1xuXHR0aGlzLmNyZWF0ZWQgPSBuZXcgRGF0ZSgpO1xuXHQvKiogQSBsaXN0IG9mIG11bHRpcHJlY2lzaW9uIGludGVnZXJzXG5cdCAqIEB0eXBlIHtvcGVucGdwX3R5cGVfbXBpfSAqL1xuXHR0aGlzLm1waSA9IFtdO1xuXHQvKiogUHVibGljIGtleSBhbGdvcml0aG1cblx0ICogQHR5cGUge29wZW5wZ3AucHVibGlja2V5fSAqL1xuXHR0aGlzLmFsZ29yaXRobSA9ICdyc2Ffc2lnbic7XG5cblxuXHQvKipcblx0ICogSW50ZXJuYWwgUGFyc2VyIGZvciBwdWJsaWMga2V5cyBhcyBzcGVjaWZpZWQgaW4gUkZDIDQ4ODAgc2VjdGlvbiBcblx0ICogNS41LjIgUHVibGljLUtleSBQYWNrZXQgRm9ybWF0c1xuXHQgKiBjYWxsZWQgYnkgcmVhZF90YWcmbHQ7bnVtJmd0O1xuXHQgKiBAcGFyYW0ge1N0cmluZ30gaW5wdXQgSW5wdXQgc3RyaW5nIHRvIHJlYWQgdGhlIHBhY2tldCBmcm9tXG5cdCAqIEBwYXJhbSB7SW50ZWdlcn0gcG9zaXRpb24gU3RhcnQgcG9zaXRpb24gZm9yIHRoZSBwYXJzZXJcblx0ICogQHBhcmFtIHtJbnRlZ2VyfSBsZW4gTGVuZ3RoIG9mIHRoZSBwYWNrZXQgb3IgcmVtYWluaW5nIGxlbmd0aCBvZiBpbnB1dFxuXHQgKiBAcmV0dXJuIHtPYmplY3R9IFRoaXMgb2JqZWN0IHdpdGggYXR0cmlidXRlcyBzZXQgYnkgdGhlIHBhcnNlclxuXHQgKi8gIFxuXHR0aGlzLnJlYWRQdWJsaWNLZXkgPSB0aGlzLnJlYWQgPSBmdW5jdGlvbihieXRlcykge1xuXHRcdC8vIEEgb25lLW9jdGV0IHZlcnNpb24gbnVtYmVyICgzIG9yIDQpLlxuXHRcdHZhciB2ZXJzaW9uID0gYnl0ZXNbMF0uY2hhckNvZGVBdCgpO1xuXG5cdFx0aWYgKHZlcnNpb24gPT0gNCkge1xuXHRcdFx0Ly8gLSBBIGZvdXItb2N0ZXQgbnVtYmVyIGRlbm90aW5nIHRoZSB0aW1lIHRoYXQgdGhlIGtleSB3YXMgY3JlYXRlZC5cblx0XHRcdHRoaXMuY3JlYXRlZCA9IG9wZW5wZ3BfcGFja2V0X3RpbWVfcmVhZChieXRlcy5zdWJzdHIoMSwgNCkpO1xuXHRcdFx0XG5cdFx0XHQvLyAtIEEgb25lLW9jdGV0IG51bWJlciBkZW5vdGluZyB0aGUgcHVibGljLWtleSBhbGdvcml0aG0gb2YgdGhpcyBrZXkuXG5cdFx0XHR0aGlzLmFsZ29yaXRobSA9IGJ5dGVzWzVdLmNoYXJDb2RlQXQoKTtcblxuXHRcdFx0dmFyIG1waWNvdW50ID0gb3BlbnBncF9jcnlwdG9fZ2V0UHVibGljTXBpQ291bnQodGhpcy5hbGdvcml0aG0pO1xuXHRcdFx0dGhpcy5tcGkgPSBbXTtcblxuXHRcdFx0dmFyIGJtcGkgPSBieXRlcy5zdWJzdHIoNik7XG5cdFx0XHR2YXIgcCA9IDA7XG5cblx0XHRcdGZvciAodmFyIGkgPSAwOyBcblx0XHRcdFx0aSA8IG1waWNvdW50ICYmIHAgPCBibXBpLmxlbmd0aDsgXG5cdFx0XHRcdGkrKykge1xuXG5cdFx0XHRcdHRoaXMubXBpW2ldID0gbmV3IG9wZW5wZ3BfdHlwZV9tcGkoKTtcblxuXHRcdFx0XHRwICs9IHRoaXMubXBpW2ldLnJlYWQoYm1waS5zdWJzdHIocCkpXG5cblx0XHRcdFx0aWYocCA+IGJtcGkubGVuZ3RoKVxuXHRcdFx0XHRcdHV0aWwucHJpbnRfZXJyb3IoXCJvcGVucGdwLnBhY2tldC5rZXltYXRlcmlhbC5qc1xcblwiXG5cdFx0XHRcdFx0XHQrJ2Vycm9yIHJlYWRpbmcgTVBJIEA6JytwKTtcblx0XHRcdH1cblxuXHRcdFx0cmV0dXJuIHAgKyA2O1xuXHRcdH0gZWxzZSB7XG5cdFx0XHR0aHJvdyBuZXcgRXJyb3IoJ1ZlcnNpb24gJyArIHZlcnNpb24gKyAnIG9mIHRoZSBrZXkgcGFja2V0IGlzIHVuc3VwcG9ydGVkLicpO1xuXHRcdH1cblx0fVxuXG5cdC8qXG4gICAgICogU2FtZSBhcyB3cml0ZV9wcml2YXRlX2tleSwgYnV0IGhhcyBsZXNzIGluZm9ybWF0aW9uIGJlY2F1c2Ugb2YgXG5cdCAqIHB1YmxpYyBrZXkuXG4gICAgICogQHBhcmFtIHtJbnRlZ2VyfSBrZXlUeXBlIEZvbGxvd3MgdGhlIE9wZW5QR1AgYWxnb3JpdGhtIHN0YW5kYXJkLCBcblx0ICogSUUgMSBjb3JyZXNwb25kcyB0byBSU0EuXG4gICAgICogQHBhcmFtIHtSU0Eua2V5T2JqZWN0fSBrZXlcbiAgICAgKiBAcGFyYW0gdGltZVBhY2tldFxuICAgICAqIEByZXR1cm4ge09iamVjdH0ge2JvZHk6IFtzdHJpbmddT3BlblBHUCBwYWNrZXQgYm9keSBjb250ZW50cywgXG5cdCAqIGhlYWRlcjogW3N0cmluZ10gT3BlblBHUCBwYWNrZXQgaGVhZGVyLCBzdHJpbmc6IFtzdHJpbmddIGhlYWRlcitib2R5fVxuICAgICAqL1xuICAgIHRoaXMud3JpdGVQdWJsaWNLZXkgPSB0aGlzLndyaXRlID0gZnVuY3Rpb24oKSB7XG5cdFx0Ly8gVmVyc2lvblxuXHRcdHZhciByZXN1bHQgPSBTdHJpbmcuZnJvbUNoYXJDb2RlKDQpO1xuICAgICAgICByZXN1bHQgKz0gb3BlbnBncF9wYWNrZXRfdGltZV93cml0ZSh0aGlzLmNyZWF0ZWQpO1xuXHRcdHJlc3VsdCArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKHRoaXMuYWxnb3JpdGhtKTtcblxuXHRcdHZhciBtcGljb3VudCA9IG9wZW5wZ3BfY3J5cHRvX2dldFB1YmxpY01waUNvdW50KHRoaXMuYWxnb3JpdGhtKTtcblxuXHRcdGZvcih2YXIgaSA9IDA7IGkgPCBtcGljb3VudDsgaSsrKSB7XG5cdFx0XHRyZXN1bHQgKz0gdGhpcy5tcGlbaV0ud3JpdGUoKTtcblx0XHR9XG5cblx0XHRyZXR1cm4gcmVzdWx0O1xuXHR9XG5cblx0Ly8gV3JpdGUgYW4gb2xkIHZlcnNpb24gcGFja2V0IC0gaXQncyB1c2VkIGJ5IHNvbWUgb2YgdGhlIGludGVybmFsIHJvdXRpbmVzLlxuXHR0aGlzLndyaXRlT2xkID0gZnVuY3Rpb24oKSB7XG5cdFx0dmFyIGJ5dGVzID0gdGhpcy53cml0ZVB1YmxpY0tleSgpO1xuXG5cdFx0cmV0dXJuIFN0cmluZy5mcm9tQ2hhckNvZGUoMHg5OSkgK1xuXHRcdFx0b3BlbnBncF9wYWNrZXRfbnVtYmVyX3dyaXRlKGJ5dGVzLmxlbmd0aCwgMikgK1xuXHRcdFx0Ynl0ZXM7XG5cdH1cblxuXHQvKipcblx0ICogQ2FsY3VsYXRlcyB0aGUga2V5IGlkIG9mIHRoZSBrZXkgXG5cdCAqIEByZXR1cm4ge1N0cmluZ30gQSA4IGJ5dGUga2V5IGlkXG5cdCAqL1xuXHR0aGlzLmdldEtleUlkID0gZnVuY3Rpb24oKSB7XG5cdFx0cmV0dXJuIHRoaXMuZ2V0RmluZ2VycHJpbnQoKS5zdWJzdHIoMTIsIDgpO1xuXHR9XG5cdFxuXHQvKipcblx0ICogQ2FsY3VsYXRlcyB0aGUgZmluZ2VycHJpbnQgb2YgdGhlIGtleVxuXHQgKiBAcmV0dXJuIHtTdHJpbmd9IEEgc3RyaW5nIGNvbnRhaW5pbmcgdGhlIGZpbmdlcnByaW50XG5cdCAqL1xuXHR0aGlzLmdldEZpbmdlcnByaW50ID0gZnVuY3Rpb24oKSB7XG5cdFx0dmFyIHRvSGFzaCA9IHRoaXMud3JpdGVPbGQoKTtcblx0XHRyZXR1cm4gc3RyX3NoYTEodG9IYXNoLCB0b0hhc2gubGVuZ3RoKTtcblx0fVxuXG59XG4iLCIvLyBHUEc0QnJvd3NlcnMgLSBBbiBPcGVuUEdQIGltcGxlbWVudGF0aW9uIGluIGphdmFzY3JpcHRcbi8vIENvcHlyaWdodCAoQykgMjAxMSBSZWN1cml0eSBMYWJzIEdtYkhcbi8vIFxuLy8gVGhpcyBsaWJyYXJ5IGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vclxuLy8gbW9kaWZ5IGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIExlc3NlciBHZW5lcmFsIFB1YmxpY1xuLy8gTGljZW5zZSBhcyBwdWJsaXNoZWQgYnkgdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyXG4vLyB2ZXJzaW9uIDIuMSBvZiB0aGUgTGljZW5zZSwgb3IgKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbi8vIFxuLy8gVGhpcyBsaWJyYXJ5IGlzIGRpc3RyaWJ1dGVkIGluIHRoZSBob3BlIHRoYXQgaXQgd2lsbCBiZSB1c2VmdWwsXG4vLyBidXQgV0lUSE9VVCBBTlkgV0FSUkFOVFk7IHdpdGhvdXQgZXZlbiB0aGUgaW1wbGllZCB3YXJyYW50eSBvZlxuLy8gTUVSQ0hBTlRBQklMSVRZIG9yIEZJVE5FU1MgRk9SIEEgUEFSVElDVUxBUiBQVVJQT1NFLiAgU2VlIHRoZSBHTlVcbi8vIExlc3NlciBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGZvciBtb3JlIGRldGFpbHMuXG4vLyBcbi8vIFlvdSBzaG91bGQgaGF2ZSByZWNlaXZlZCBhIGNvcHkgb2YgdGhlIEdOVSBMZXNzZXIgR2VuZXJhbCBQdWJsaWNcbi8vIExpY2Vuc2UgYWxvbmcgd2l0aCB0aGlzIGxpYnJhcnk7IGlmIG5vdCwgd3JpdGUgdG8gdGhlIEZyZWUgU29mdHdhcmVcbi8vIEZvdW5kYXRpb24sIEluYy4sIDUxIEZyYW5rbGluIFN0cmVldCwgRmlmdGggRmxvb3IsIEJvc3RvbiwgTUEgIDAyMTEwLTEzMDEgIFVTQVxuXG4vKipcbiAqIEBjbGFzc1xuICogQGNsYXNzZGVzYyBJbXBsZW1lbnRhdGlvbiBvZiB0aGUgc3RyYW5nZSBcIk1hcmtlciBwYWNrZXRcIiAoVGFnIDEwKVxuICogXG4gKiBSRkM0ODgwIDUuODogQW4gZXhwZXJpbWVudGFsIHZlcnNpb24gb2YgUEdQIHVzZWQgdGhpcyBwYWNrZXQgYXMgdGhlIExpdGVyYWxcbiAqIHBhY2tldCwgYnV0IG5vIHJlbGVhc2VkIHZlcnNpb24gb2YgUEdQIGdlbmVyYXRlZCBMaXRlcmFsIHBhY2tldHMgd2l0aCB0aGlzXG4gKiB0YWcuIFdpdGggUEdQIDUueCwgdGhpcyBwYWNrZXQgaGFzIGJlZW4gcmVhc3NpZ25lZCBhbmQgaXMgcmVzZXJ2ZWQgZm9yIHVzZSBhc1xuICogdGhlIE1hcmtlciBwYWNrZXQuXG4gKiBcbiAqIFN1Y2ggYSBwYWNrZXQgTVVTVCBiZSBpZ25vcmVkIHdoZW4gcmVjZWl2ZWQuXG4gKi9cbmZ1bmN0aW9uIHBhY2tldF9tYXJrZXIoKSB7XG5cdC8qKlxuXHQgKiBQYXJzaW5nIGZ1bmN0aW9uIGZvciBhIGxpdGVyYWwgZGF0YSBwYWNrZXQgKHRhZyAxMCkuXG5cdCAqIFxuXHQgKiBAcGFyYW0ge1N0cmluZ30gaW5wdXQgUGF5bG9hZCBvZiBhIHRhZyAxMCBwYWNrZXRcblx0ICogQHBhcmFtIHtJbnRlZ2VyfSBwb3NpdGlvblxuXHQgKiAgICAgICAgICAgIFBvc2l0aW9uIHRvIHN0YXJ0IHJlYWRpbmcgZnJvbSB0aGUgaW5wdXQgc3RyaW5nXG5cdCAqIEBwYXJhbSB7SW50ZWdlcn0gbGVuXG5cdCAqICAgICAgICAgICAgTGVuZ3RoIG9mIHRoZSBwYWNrZXQgb3IgdGhlIHJlbWFpbmluZyBsZW5ndGggb2Zcblx0ICogICAgICAgICAgICBpbnB1dCBhdCBwb3NpdGlvblxuXHQgKiBAcmV0dXJuIHtvcGVucGdwX3BhY2tldF9lbmNyeXB0ZWRkYXRhfSBPYmplY3QgcmVwcmVzZW50YXRpb25cblx0ICovXG5cdHRoaXMucmVhZCA9IGZ1bmN0aW9uKGJ5dGVzKSB7XG5cdFx0aWYgKGJ5dGVzWzBdLmNoYXJDb2RlQXQoKSA9PSAweDUwICYmIC8vIFBcblx0XHRcdFx0Ynl0ZXNbMV0uY2hhckNvZGVBdCgpID09IDB4NDcgJiYgLy8gR1xuXHRcdFx0XHRieXRlc1syXS5jaGFyQ29kZUF0KCkgPT0gMHg1MCkgLy8gUFxuXHRcdFx0cmV0dXJuIHRydWU7XG5cdFx0Ly8gbWFya2VyIHBhY2tldCBkb2VzIG5vdCBjb250YWluIFwiUEdQXCJcblx0XHRyZXR1cm4gZmFsc2U7XG5cdH1cbn1cblxubW9kdWxlLmV4cG9ydHMgPSBwYWNrZXRfbWFya2VyO1xuIiwiLy8gR1BHNEJyb3dzZXJzIC0gQW4gT3BlblBHUCBpbXBsZW1lbnRhdGlvbiBpbiBqYXZhc2NyaXB0XG4vLyBDb3B5cmlnaHQgKEMpIDIwMTEgUmVjdXJpdHkgTGFicyBHbWJIXG4vLyBcbi8vIFRoaXMgbGlicmFyeSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3Jcbi8vIG1vZGlmeSBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBMZXNzZXIgR2VuZXJhbCBQdWJsaWNcbi8vIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5IHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlclxuLy8gdmVyc2lvbiAyLjEgb2YgdGhlIExpY2Vuc2UsIG9yIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4vLyBcbi8vIFRoaXMgbGlicmFyeSBpcyBkaXN0cmlidXRlZCBpbiB0aGUgaG9wZSB0aGF0IGl0IHdpbGwgYmUgdXNlZnVsLFxuLy8gYnV0IFdJVEhPVVQgQU5ZIFdBUlJBTlRZOyB3aXRob3V0IGV2ZW4gdGhlIGltcGxpZWQgd2FycmFudHkgb2Zcbi8vIE1FUkNIQU5UQUJJTElUWSBvciBGSVRORVNTIEZPUiBBIFBBUlRJQ1VMQVIgUFVSUE9TRS4gIFNlZSB0aGUgR05VXG4vLyBMZXNzZXIgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBmb3IgbW9yZSBkZXRhaWxzLlxuLy8gXG4vLyBZb3Ugc2hvdWxkIGhhdmUgcmVjZWl2ZWQgYSBjb3B5IG9mIHRoZSBHTlUgTGVzc2VyIEdlbmVyYWwgUHVibGljXG4vLyBMaWNlbnNlIGFsb25nIHdpdGggdGhpcyBsaWJyYXJ5OyBpZiBub3QsIHdyaXRlIHRvIHRoZSBGcmVlIFNvZnR3YXJlXG4vLyBGb3VuZGF0aW9uLCBJbmMuLCA1MSBGcmFua2xpbiBTdHJlZXQsIEZpZnRoIEZsb29yLCBCb3N0b24sIE1BICAwMjExMC0xMzAxICBVU0FcblxuLyoqIFxuICogQGNsYXNzXG4gKiBAY2xhc3NkZXNjIEltcGxlbWVudGF0aW9uIG9mIHRoZSBVc2VyIEF0dHJpYnV0ZSBQYWNrZXQgKFRhZyAxNylcbiAqICBUaGUgVXNlciBBdHRyaWJ1dGUgcGFja2V0IGlzIGEgdmFyaWF0aW9uIG9mIHRoZSBVc2VyIElEIHBhY2tldC4gIEl0XG4gKiAgaXMgY2FwYWJsZSBvZiBzdG9yaW5nIG1vcmUgdHlwZXMgb2YgZGF0YSB0aGFuIHRoZSBVc2VyIElEIHBhY2tldCxcbiAqICB3aGljaCBpcyBsaW1pdGVkIHRvIHRleHQuICBMaWtlIHRoZSBVc2VyIElEIHBhY2tldCwgYSBVc2VyIEF0dHJpYnV0ZVxuICogIHBhY2tldCBtYXkgYmUgY2VydGlmaWVkIGJ5IHRoZSBrZXkgb3duZXIgKFwic2VsZi1zaWduZWRcIikgb3IgYW55IG90aGVyXG4gKiAga2V5IG93bmVyIHdobyBjYXJlcyB0byBjZXJ0aWZ5IGl0LiAgRXhjZXB0IGFzIG5vdGVkLCBhIFVzZXIgQXR0cmlidXRlXG4gKiAgcGFja2V0IG1heSBiZSB1c2VkIGFueXdoZXJlIHRoYXQgYSBVc2VyIElEIHBhY2tldCBtYXkgYmUgdXNlZC5cbiAqXG4gKiAgV2hpbGUgVXNlciBBdHRyaWJ1dGUgcGFja2V0cyBhcmUgbm90IGEgcmVxdWlyZWQgcGFydCBvZiB0aGUgT3BlblBHUFxuICogIHN0YW5kYXJkLCBpbXBsZW1lbnRhdGlvbnMgU0hPVUxEIHByb3ZpZGUgYXQgbGVhc3QgZW5vdWdoXG4gKiAgY29tcGF0aWJpbGl0eSB0byBwcm9wZXJseSBoYW5kbGUgYSBjZXJ0aWZpY2F0aW9uIHNpZ25hdHVyZSBvbiB0aGVcbiAqICBVc2VyIEF0dHJpYnV0ZSBwYWNrZXQuICBBIHNpbXBsZSB3YXkgdG8gZG8gdGhpcyBpcyBieSB0cmVhdGluZyB0aGVcbiAqICBVc2VyIEF0dHJpYnV0ZSBwYWNrZXQgYXMgYSBVc2VyIElEIHBhY2tldCB3aXRoIG9wYXF1ZSBjb250ZW50cywgYnV0XG4gKiAgYW4gaW1wbGVtZW50YXRpb24gbWF5IHVzZSBhbnkgbWV0aG9kIGRlc2lyZWQuXG4gKi9cbm1vZHVsZS5leHBvcnRzID0gZnVuY3Rpb24gcGFja2V0X3VzZXJfYXR0cmlidXRlKCkge1xuXHR0aGlzLnRhZyA9IDE3O1xuXHR0aGlzLmF0dHJpYnV0ZXMgPSBbXTtcblxuXHQvKipcblx0ICogcGFyc2luZyBmdW5jdGlvbiBmb3IgYSB1c2VyIGF0dHJpYnV0ZSBwYWNrZXQgKHRhZyAxNykuXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBpbnB1dCBwYXlsb2FkIG9mIGEgdGFnIDE3IHBhY2tldFxuXHQgKiBAcGFyYW0ge0ludGVnZXJ9IHBvc2l0aW9uIHBvc2l0aW9uIHRvIHN0YXJ0IHJlYWRpbmcgZnJvbSB0aGUgaW5wdXQgc3RyaW5nXG5cdCAqIEBwYXJhbSB7SW50ZWdlcn0gbGVuIGxlbmd0aCBvZiB0aGUgcGFja2V0IG9yIHRoZSByZW1haW5pbmcgbGVuZ3RoIG9mIGlucHV0IGF0IHBvc2l0aW9uXG5cdCAqIEByZXR1cm4ge29wZW5wZ3BfcGFja2V0X2VuY3J5cHRlZGRhdGF9IG9iamVjdCByZXByZXNlbnRhdGlvblxuXHQgKi9cblx0dGhpcy5yZWFkID0gZnVuY3Rpb24oYnl0ZXMpIHtcblx0XHR2YXIgaSA9IDA7XG5cdFx0d2hpbGUoaSA8IGJ5dGVzLmxlbmd0aCkge1xuXHRcdFx0dmFyIGxlbiA9IG9wZW5wZ3BfcGFja2V0LnJlYWRfc2ltcGxlX2xlbmd0aChieXRlcyk7XG5cblx0XHRcdGkgKz0gbGVuLm9mZnNldDtcblx0XHRcdHRoaXMuYXR0cmlidXRlcy5wdXNoKGJ5dGVzLnN1YnN0cihpLCBsZW4ubGVuKSk7XG5cdFx0XHRpICs9IGxlbi5sZW47XG5cdFx0fVxuXHR9XG59O1xuIiwiXG5tb2R1bGUuZXhwb3J0cyA9IGZ1bmN0aW9uIHBhY2tldF90cnVzdCgpIHtcblxufTtcbiIsIlxubW9kdWxlLmV4cG9ydHMgPSB7XG5cdGFlczogcmVxdWlyZSgnLi9hZXMuanMnKSxcblx0ZGVzOiByZXF1aXJlKCcuL2Rlcy5qcycpLFxuXHRjYXN0NTogcmVxdWlyZSgnLi9jYXN0NS5qcycpLFxuXHR0d29maXNoOiByZXF1aXJlKCcuL3R3b2Zpc2guanMnKSxcblx0Ymxvd2Zpc2g6IHJlcXVpcmUoJy4vYmxvd2Zpc2guanMnKVxufVxuXG4iLCJcbnZhciBzaGEgPSByZXF1aXJlKCcuL3NoYS5qcycpO1xuXG5tb2R1bGUuZXhwb3J0cyA9IHtcblx0bWQ1OiByZXF1aXJlKCcuL21kNS5qcycpLFxuXHRzaGExOiBzaGEuc2hhMSxcblx0c2hhMjU2OiBzaGEuc2hhMjU2LFxuXHRzaGEyMjQ6IHNoYS5zaGEyMjQsXG5cdHNoYTM4NDogc2hhLnNoYTM4NCxcblx0c2hhNTEyOiBzaGEuc2hhNTEyLFxuXHRyaXBlbWQ6IHJlcXVpcmUoJy4vcmlwZS1tZC5qcycpLFxuXG5cdC8qKlxuXHQgKiBDcmVhdGUgYSBoYXNoIG9uIHRoZSBzcGVjaWZpZWQgZGF0YSB1c2luZyB0aGUgc3BlY2lmaWVkIGFsZ29yaXRobVxuXHQgKiBAcGFyYW0ge0ludGVnZXJ9IGFsZ28gSGFzaCBhbGdvcml0aG0gdHlwZSAoc2VlIFJGQzQ4ODAgOS40KVxuXHQgKiBAcGFyYW0ge1N0cmluZ30gZGF0YSBEYXRhIHRvIGJlIGhhc2hlZFxuXHQgKiBAcmV0dXJuIHtTdHJpbmd9IGhhc2ggdmFsdWVcblx0ICovXG5cdGRpZ2VzdDogZnVuY3Rpb24oYWxnbywgZGF0YSkge1xuXHRcdHN3aXRjaChhbGdvKSB7XG5cdFx0Y2FzZSAxOiAvLyAtIE1ENSBbSEFDXVxuXHRcdFx0cmV0dXJuIHRoaXMubWQ1KGRhdGEpO1xuXHRcdGNhc2UgMjogLy8gLSBTSEEtMSBbRklQUzE4MF1cblx0XHRcdHJldHVybiB0aGlzLnNoYTEoZGF0YSk7XG5cdFx0Y2FzZSAzOiAvLyAtIFJJUEUtTUQvMTYwIFtIQUNdXG5cdFx0XHRyZXR1cm4gdGhpcy5yaXBlbWQoZGF0YSk7XG5cdFx0Y2FzZSA4OiAvLyAtIFNIQTI1NiBbRklQUzE4MF1cblx0XHRcdHJldHVybiB0aGlzLnNoYTI1NihkYXRhKTtcblx0XHRjYXNlIDk6IC8vIC0gU0hBMzg0IFtGSVBTMTgwXVxuXHRcdFx0cmV0dXJuIHRoaXMuc2hhMzg0KGRhdGEpO1xuXHRcdGNhc2UgMTA6Ly8gLSBTSEE1MTIgW0ZJUFMxODBdXG5cdFx0XHRyZXR1cm4gdGhpcy5zaGE1MTIoZGF0YSk7XG5cdFx0Y2FzZSAxMTovLyAtIFNIQTIyNCBbRklQUzE4MF1cblx0XHRcdHJldHVybiB0aGlzLnNoYTIyNChkYXRhKTtcblx0XHRkZWZhdWx0OlxuXHRcdFx0dGhyb3cgbmV3IEVycm9yKCdJbnZhbGlkIGhhc2ggZnVuY3Rpb24uJyk7XG5cdFx0fVxuXHR9LFxuXG5cdC8qKlxuXHQgKiBSZXR1cm5zIHRoZSBoYXNoIHNpemUgaW4gYnl0ZXMgb2YgdGhlIHNwZWNpZmllZCBoYXNoIGFsZ29yaXRobSB0eXBlXG5cdCAqIEBwYXJhbSB7SW50ZWdlcn0gYWxnbyBIYXNoIGFsZ29yaXRobSB0eXBlIChTZWUgUkZDNDg4MCA5LjQpXG5cdCAqIEByZXR1cm4ge0ludGVnZXJ9IFNpemUgaW4gYnl0ZXMgb2YgdGhlIHJlc3VsdGluZyBoYXNoXG5cdCAqL1xuXHRnZXRIYXNoQnl0ZUxlbmd0aDogZnVuY3Rpb24oYWxnbykge1xuXHRcdHN3aXRjaChhbGdvKSB7XG5cdFx0Y2FzZSAxOiAvLyAtIE1ENSBbSEFDXVxuXHRcdFx0cmV0dXJuIDE2O1xuXHRcdGNhc2UgMjogLy8gLSBTSEEtMSBbRklQUzE4MF1cblx0XHRjYXNlIDM6IC8vIC0gUklQRS1NRC8xNjAgW0hBQ11cblx0XHRcdHJldHVybiAyMDtcblx0XHRjYXNlIDg6IC8vIC0gU0hBMjU2IFtGSVBTMTgwXVxuXHRcdFx0cmV0dXJuIDMyO1xuXHRcdGNhc2UgOTogLy8gLSBTSEEzODQgW0ZJUFMxODBdXG5cdFx0XHRyZXR1cm4gNDhcblx0XHRjYXNlIDEwOi8vIC0gU0hBNTEyIFtGSVBTMTgwXVxuXHRcdFx0cmV0dXJuIDY0O1xuXHRcdGNhc2UgMTE6Ly8gLSBTSEEyMjQgW0ZJUFMxODBdXG5cdFx0XHRyZXR1cm4gMjg7XG5cdFx0ZGVmYXVsdDpcblx0XHRcdHRocm93IG5ldyBFcnJvcignSW52YWxpZCBoYXNoIGFsZ29yaXRobS4nKTtcblx0XHR9XG5cdH1cblxufVxuXG4iLCIoZnVuY3Rpb24oKXsvLyBNb2RpZmllZCBieSBSZWN1cml0eSBMYWJzIEdtYkggXG5cbi8vIG1vZGlmaWVkIHZlcnNpb24gb2YgaHR0cDovL3d3dy5oYW5ld2luLm5ldC9lbmNyeXB0L1BHZGVjb2RlLmpzOlxuXG4vKiBPcGVuUEdQIGVuY3J5cHRpb24gdXNpbmcgUlNBL0FFU1xuICogQ29weXJpZ2h0IDIwMDUtMjAwNiBIZXJiZXJ0IEhhbmV3aW5rZWwsIHd3dy5oYW5lV0lOLmRlXG4gKiB2ZXJzaW9uIDIuMCwgY2hlY2sgd3d3LmhhbmVXSU4uZGUgZm9yIHRoZSBsYXRlc3QgdmVyc2lvblxuXG4gKiBUaGlzIHNvZnR3YXJlIGlzIHByb3ZpZGVkIGFzLWlzLCB3aXRob3V0IGV4cHJlc3Mgb3IgaW1wbGllZCB3YXJyYW50eS4gIFxuICogUGVybWlzc2lvbiB0byB1c2UsIGNvcHksIG1vZGlmeSwgZGlzdHJpYnV0ZSBvciBzZWxsIHRoaXMgc29mdHdhcmUsIHdpdGggb3JcbiAqIHdpdGhvdXQgZmVlLCBmb3IgYW55IHB1cnBvc2UgYW5kIGJ5IGFueSBpbmRpdmlkdWFsIG9yIG9yZ2FuaXphdGlvbiwgaXMgaGVyZWJ5XG4gKiBncmFudGVkLCBwcm92aWRlZCB0aGF0IHRoZSBhYm92ZSBjb3B5cmlnaHQgbm90aWNlIGFuZCB0aGlzIHBhcmFncmFwaCBhcHBlYXIgXG4gKiBpbiBhbGwgY29waWVzLiBEaXN0cmlidXRpb24gYXMgYSBwYXJ0IG9mIGFuIGFwcGxpY2F0aW9uIG9yIGJpbmFyeSBtdXN0XG4gKiBpbmNsdWRlIHRoZSBhYm92ZSBjb3B5cmlnaHQgbm90aWNlIGluIHRoZSBkb2N1bWVudGF0aW9uIGFuZC9vciBvdGhlclxuICogbWF0ZXJpYWxzIHByb3ZpZGVkIHdpdGggdGhlIGFwcGxpY2F0aW9uIG9yIGRpc3RyaWJ1dGlvbi5cbiAqL1xuXG52YXIgdXRpbCA9IHJlcXVpcmUoJy4uL3V0aWwnKTtcblxubW9kdWxlLmV4cG9ydHMgPSB7XG5cblx0LyoqXG5cdCAqIEFuIGFycmF5IG9mIGJ5dGVzLCB0aGF0IGlzIGludGVnZXJzIHdpdGggdmFsdWVzIGZyb20gMCB0byAyNTVcblx0ICogQHR5cGVkZWYgeyhBcnJheXxVaW50OEFycmF5KX0gb3BlbnBncF9ieXRlX2FycmF5XG5cdCAqL1xuXG5cdC8qKlxuXHQgKiBCbG9jayBjaXBoZXIgZnVuY3Rpb25cblx0ICogQGNhbGxiYWNrIG9wZW5wZ3BfY2lwaGVyX2Jsb2NrX2ZuXG5cdCAqIEBwYXJhbSB7b3BlbnBncF9ieXRlX2FycmF5fSBibG9jayBBIGJsb2NrIHRvIHBlcmZvcm0gb3BlcmF0aW9ucyBvblxuXHQgKiBAcGFyYW0ge29wZW5wZ3BfYnl0ZV9hcnJheX0ga2V5IHRvIHVzZSBpbiBlbmNyeXB0aW9uL2RlY3J5cHRpb25cblx0ICogQHJldHVybiB7b3BlbnBncF9ieXRlX2FycmF5fSBFbmNyeXB0ZWQvZGVjcnlwdGVkIGJsb2NrXG5cdCAqL1xuXG5cblx0Ly8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cblx0LyoqXG5cdCAqIFRoaXMgZnVuY3Rpb24gZW5jcnlwdHMgYSBnaXZlbiB3aXRoIHRoZSBzcGVjaWZpZWQgcHJlZml4cmFuZG9tIFxuXHQgKiB1c2luZyB0aGUgc3BlY2lmaWVkIGJsb2NrY2lwaGVyIHRvIGVuY3J5cHQgYSBtZXNzYWdlXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBwcmVmaXhyYW5kb20gcmFuZG9tIGJ5dGVzIG9mIGJsb2NrX3NpemUgbGVuZ3RoIHByb3ZpZGVkIFxuXHQgKiAgYXMgYSBzdHJpbmcgdG8gYmUgdXNlZCBpbiBwcmVmaXhpbmcgdGhlIGRhdGFcblx0ICogQHBhcmFtIHtvcGVucGdwX2NpcGhlcl9ibG9ja19mbn0gYmxvY2tjaXBoZXJmbiB0aGUgYWxnb3JpdGhtIGVuY3J5cHQgZnVuY3Rpb24gdG8gZW5jcnlwdFxuXHQgKiAgZGF0YSBpbiBvbmUgYmxvY2tfc2l6ZSBlbmNyeXB0aW9uLiBcblx0ICogQHBhcmFtIHtJbnRlZ2VyfSBibG9ja19zaXplIHRoZSBibG9jayBzaXplIGluIGJ5dGVzIG9mIHRoZSBhbGdvcml0aG0gdXNlZFxuXHQgKiBAcGFyYW0ge1N0cmluZ30gcGxhaW50ZXh0IGRhdGEgdG8gYmUgZW5jcnlwdGVkIHByb3ZpZGVkIGFzIGEgc3RyaW5nXG5cdCAqIEBwYXJhbSB7b3BlbnBncF9ieXRlX2FycmF5fSBrZXkga2V5IHRvIGJlIHVzZWQgdG8gZW5jcnlwdCB0aGUgZGF0YS4gVGhpcyB3aWxsIGJlIHBhc3NlZCB0byB0aGUgXG5cdCAqICBibG9ja2NpcGhlcmZuXG5cdCAqIEBwYXJhbSB7Qm9vbGVhbn0gcmVzeW5jIGEgYm9vbGVhbiB2YWx1ZSBzcGVjaWZ5aW5nIGlmIGEgcmVzeW5jIG9mIHRoZSBcblx0ICogIElWIHNob3VsZCBiZSB1c2VkIG9yIG5vdC4gVGhlIGVuY3J5cHRlZGRhdGFwYWNrZXQgdXNlcyB0aGUgXG5cdCAqICBcIm9sZFwiIHN0eWxlIHdpdGggYSByZXN5bmMuIEVuY3J5cHRpb24gd2l0aGluIGFuIFxuXHQgKiAgZW5jcnlwdGVkaW50ZWdyaXR5cHJvdGVjdGVkZGF0YSBwYWNrZXQgaXMgbm90IHJlc3luY2luZyB0aGUgSVYuXG5cdCAqIEByZXR1cm4ge1N0cmluZ30gYSBzdHJpbmcgd2l0aCB0aGUgZW5jcnlwdGVkIGRhdGFcblx0ICovXG5cdGVuY3J5cHQ6IGZ1bmN0aW9uIChwcmVmaXhyYW5kb20sIGJsb2NrY2lwaGVyZW5jcnlwdGZuLCBwbGFpbnRleHQsIGJsb2NrX3NpemUsIGtleSwgcmVzeW5jKSB7XG5cdFx0dmFyIEZSID0gbmV3IEFycmF5KGJsb2NrX3NpemUpO1xuXHRcdHZhciBGUkUgPSBuZXcgQXJyYXkoYmxvY2tfc2l6ZSk7XG5cblx0XHRwcmVmaXhyYW5kb20gPSBwcmVmaXhyYW5kb20gKyBwcmVmaXhyYW5kb20uY2hhckF0KGJsb2NrX3NpemUtMikgK3ByZWZpeHJhbmRvbS5jaGFyQXQoYmxvY2tfc2l6ZS0xKTtcblx0XHR1dGlsLnByaW50X2RlYnVnKFwicHJlZml4cmFuZG9tOlwiK3V0aWwuaGV4c3RyZHVtcChwcmVmaXhyYW5kb20pKTtcblx0XHR2YXIgY2lwaGVydGV4dCA9IFwiXCI7XG5cdFx0Ly8gMS4gIFRoZSBmZWVkYmFjayByZWdpc3RlciAoRlIpIGlzIHNldCB0byB0aGUgSVYsIHdoaWNoIGlzIGFsbCB6ZXJvcy5cblx0XHRmb3IgKHZhciBpID0gMDsgaSA8IGJsb2NrX3NpemU7IGkrKykgRlJbaV0gPSAwO1xuXHRcdFxuXHRcdC8vIDIuICBGUiBpcyBlbmNyeXB0ZWQgdG8gcHJvZHVjZSBGUkUgKEZSIEVuY3J5cHRlZCkuICBUaGlzIGlzIHRoZVxuXHRcdC8vICAgICBlbmNyeXB0aW9uIG9mIGFuIGFsbC16ZXJvIHZhbHVlLlxuXHRcdEZSRSA9IGJsb2NrY2lwaGVyZW5jcnlwdGZuKEZSLCBrZXkpO1xuXHRcdC8vIDMuICBGUkUgaXMgeG9yZWQgd2l0aCB0aGUgZmlyc3QgQlMgb2N0ZXRzIG9mIHJhbmRvbSBkYXRhIHByZWZpeGVkIHRvXG5cdFx0Ly8gICAgIHRoZSBwbGFpbnRleHQgdG8gcHJvZHVjZSBDWzFdIHRocm91Z2ggQ1tCU10sIHRoZSBmaXJzdCBCUyBvY3RldHNcblx0XHQvLyAgICAgb2YgY2lwaGVydGV4dC5cblx0XHRmb3IgKHZhciBpID0gMDsgaSA8IGJsb2NrX3NpemU7IGkrKykgY2lwaGVydGV4dCArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKEZSRVtpXSBeIHByZWZpeHJhbmRvbS5jaGFyQ29kZUF0KGkpKTtcblx0XHRcblx0XHQvLyA0LiAgRlIgaXMgbG9hZGVkIHdpdGggQ1sxXSB0aHJvdWdoIENbQlNdLlxuXHRcdGZvciAodmFyIGkgPSAwOyBpIDwgYmxvY2tfc2l6ZTsgaSsrKSBGUltpXSA9IGNpcGhlcnRleHQuY2hhckNvZGVBdChpKTtcblx0XHRcblx0XHQvLyA1LiAgRlIgaXMgZW5jcnlwdGVkIHRvIHByb2R1Y2UgRlJFLCB0aGUgZW5jcnlwdGlvbiBvZiB0aGUgZmlyc3QgQlNcblx0XHQvLyBcdCAgIG9jdGV0cyBvZiBjaXBoZXJ0ZXh0LlxuXHRcdEZSRSA9IGJsb2NrY2lwaGVyZW5jcnlwdGZuKEZSLCBrZXkpO1xuXG5cdFx0Ly8gNi4gIFRoZSBsZWZ0IHR3byBvY3RldHMgb2YgRlJFIGdldCB4b3JlZCB3aXRoIHRoZSBuZXh0IHR3byBvY3RldHMgb2Zcblx0XHQvLyAgICAgZGF0YSB0aGF0IHdlcmUgcHJlZml4ZWQgdG8gdGhlIHBsYWludGV4dC4gIFRoaXMgcHJvZHVjZXMgQ1tCUysxXVxuXHRcdC8vICAgICBhbmQgQ1tCUysyXSwgdGhlIG5leHQgdHdvIG9jdGV0cyBvZiBjaXBoZXJ0ZXh0LlxuXHRcdGNpcGhlcnRleHQgKz0gU3RyaW5nLmZyb21DaGFyQ29kZShGUkVbMF0gXiBwcmVmaXhyYW5kb20uY2hhckNvZGVBdChibG9ja19zaXplKSk7XG5cdFx0Y2lwaGVydGV4dCArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKEZSRVsxXSBeIHByZWZpeHJhbmRvbS5jaGFyQ29kZUF0KGJsb2NrX3NpemUrMSkpO1xuXG5cdFx0aWYgKHJlc3luYykge1xuXHRcdFx0Ly8gNy4gIChUaGUgcmVzeW5jIHN0ZXApIEZSIGlzIGxvYWRlZCB3aXRoIEMzLUMxMC5cblx0XHRcdGZvciAodmFyIGkgPSAwOyBpIDwgYmxvY2tfc2l6ZTsgaSsrKSBGUltpXSA9IGNpcGhlcnRleHQuY2hhckNvZGVBdChpKzIpO1xuXHRcdH0gZWxzZSB7XG5cdFx0XHRmb3IgKHZhciBpID0gMDsgaSA8IGJsb2NrX3NpemU7IGkrKykgRlJbaV0gPSBjaXBoZXJ0ZXh0LmNoYXJDb2RlQXQoaSk7XG5cdFx0fVxuXHRcdC8vIDguICBGUiBpcyBlbmNyeXB0ZWQgdG8gcHJvZHVjZSBGUkUuXG5cdFx0RlJFID0gYmxvY2tjaXBoZXJlbmNyeXB0Zm4oRlIsIGtleSk7XG5cdFx0XG5cdFx0aWYgKHJlc3luYykge1xuXHRcdFx0Ly8gOS4gIEZSRSBpcyB4b3JlZCB3aXRoIHRoZSBmaXJzdCA4IG9jdGV0cyBvZiB0aGUgZ2l2ZW4gcGxhaW50ZXh0LCBub3dcblx0XHRcdC8vXHQgICB0aGF0IHdlIGhhdmUgZmluaXNoZWQgZW5jcnlwdGluZyB0aGUgMTAgb2N0ZXRzIG9mIHByZWZpeGVkIGRhdGEuXG5cdFx0XHQvLyBcdCAgIFRoaXMgcHJvZHVjZXMgQzExLUMxOCwgdGhlIG5leHQgOCBvY3RldHMgb2YgY2lwaGVydGV4dC5cblx0XHRcdGZvciAodmFyIGkgPSAwOyBpIDwgYmxvY2tfc2l6ZTsgaSsrKVxuXHRcdFx0XHRjaXBoZXJ0ZXh0ICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoRlJFW2ldIF4gcGxhaW50ZXh0LmNoYXJDb2RlQXQoaSkpO1xuXHRcdFx0Zm9yKG49YmxvY2tfc2l6ZSsyOyBuIDwgcGxhaW50ZXh0Lmxlbmd0aDsgbis9YmxvY2tfc2l6ZSkge1xuXHRcdFx0XHQvLyAxMC4gRlIgaXMgbG9hZGVkIHdpdGggQzExLUMxOFxuXHRcdFx0XHRmb3IgKHZhciBpID0gMDsgaSA8IGJsb2NrX3NpemU7IGkrKykgRlJbaV0gPSBjaXBoZXJ0ZXh0LmNoYXJDb2RlQXQobitpKTtcblx0XHRcdFxuXHRcdFx0XHQvLyAxMS4gRlIgaXMgZW5jcnlwdGVkIHRvIHByb2R1Y2UgRlJFLlxuXHRcdFx0XHRGUkUgPSBibG9ja2NpcGhlcmVuY3J5cHRmbihGUiwga2V5KTtcblx0XHRcdFxuXHRcdFx0XHQvLyAxMi4gRlJFIGlzIHhvcmVkIHdpdGggdGhlIG5leHQgOCBvY3RldHMgb2YgcGxhaW50ZXh0LCB0byBwcm9kdWNlIHRoZVxuXHRcdFx0XHQvLyBuZXh0IDggb2N0ZXRzIG9mIGNpcGhlcnRleHQuICBUaGVzZSBhcmUgbG9hZGVkIGludG8gRlIgYW5kIHRoZVxuXHRcdFx0XHQvLyBwcm9jZXNzIGlzIHJlcGVhdGVkIHVudGlsIHRoZSBwbGFpbnRleHQgaXMgdXNlZCB1cC5cblx0XHRcdFx0Zm9yICh2YXIgaSA9IDA7IGkgPCBibG9ja19zaXplOyBpKyspIGNpcGhlcnRleHQgKz0gU3RyaW5nLmZyb21DaGFyQ29kZShGUkVbaV0gXiBwbGFpbnRleHQuY2hhckNvZGVBdCgobi0yKStpKSk7XG5cdFx0XHR9XG5cdFx0fVxuXHRcdGVsc2Uge1xuXHRcdFx0cGxhaW50ZXh0ID0gXCIgIFwiK3BsYWludGV4dDtcblx0XHRcdC8vIDkuICBGUkUgaXMgeG9yZWQgd2l0aCB0aGUgZmlyc3QgOCBvY3RldHMgb2YgdGhlIGdpdmVuIHBsYWludGV4dCwgbm93XG5cdFx0XHQvL1x0ICAgdGhhdCB3ZSBoYXZlIGZpbmlzaGVkIGVuY3J5cHRpbmcgdGhlIDEwIG9jdGV0cyBvZiBwcmVmaXhlZCBkYXRhLlxuXHRcdFx0Ly8gXHQgICBUaGlzIHByb2R1Y2VzIEMxMS1DMTgsIHRoZSBuZXh0IDggb2N0ZXRzIG9mIGNpcGhlcnRleHQuXG5cdFx0XHRmb3IgKHZhciBpID0gMjsgaSA8IGJsb2NrX3NpemU7IGkrKykgY2lwaGVydGV4dCArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKEZSRVtpXSBeIHBsYWludGV4dC5jaGFyQ29kZUF0KGkpKTtcblx0XHRcdHZhciB0ZW1wQ2lwaGVydGV4dCA9IGNpcGhlcnRleHQuc3Vic3RyaW5nKDAsMipibG9ja19zaXplKS5zcGxpdCgnJyk7XG5cdFx0XHR2YXIgdGVtcENpcGhlcnRleHRTdHJpbmcgPSBjaXBoZXJ0ZXh0LnN1YnN0cmluZyhibG9ja19zaXplKTtcblx0XHRcdGZvcihuPWJsb2NrX3NpemU7IG48cGxhaW50ZXh0Lmxlbmd0aDsgbis9YmxvY2tfc2l6ZSkge1xuXHRcdFx0XHQvLyAxMC4gRlIgaXMgbG9hZGVkIHdpdGggQzExLUMxOFxuXHRcdFx0XHRmb3IgKHZhciBpID0gMDsgaSA8IGJsb2NrX3NpemU7IGkrKykgRlJbaV0gPSB0ZW1wQ2lwaGVydGV4dFN0cmluZy5jaGFyQ29kZUF0KGkpO1xuXHRcdFx0XHR0ZW1wQ2lwaGVydGV4dFN0cmluZz0nJztcblx0XHRcdFx0XG5cdFx0XHRcdC8vIDExLiBGUiBpcyBlbmNyeXB0ZWQgdG8gcHJvZHVjZSBGUkUuXG5cdFx0XHRcdEZSRSA9IGJsb2NrY2lwaGVyZW5jcnlwdGZuKEZSLCBrZXkpO1xuXHRcdFx0XHRcblx0XHRcdFx0Ly8gMTIuIEZSRSBpcyB4b3JlZCB3aXRoIHRoZSBuZXh0IDggb2N0ZXRzIG9mIHBsYWludGV4dCwgdG8gcHJvZHVjZSB0aGVcblx0XHRcdFx0Ly8gICAgIG5leHQgOCBvY3RldHMgb2YgY2lwaGVydGV4dC4gIFRoZXNlIGFyZSBsb2FkZWQgaW50byBGUiBhbmQgdGhlXG5cdFx0XHRcdC8vICAgICBwcm9jZXNzIGlzIHJlcGVhdGVkIHVudGlsIHRoZSBwbGFpbnRleHQgaXMgdXNlZCB1cC5cblx0XHRcdFx0Zm9yICh2YXIgaSA9IDA7IGkgPCBibG9ja19zaXplOyBpKyspeyB0ZW1wQ2lwaGVydGV4dC5wdXNoKFN0cmluZy5mcm9tQ2hhckNvZGUoRlJFW2ldIF4gcGxhaW50ZXh0LmNoYXJDb2RlQXQobitpKSkpO1xuXHRcdFx0XHR0ZW1wQ2lwaGVydGV4dFN0cmluZyArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKEZSRVtpXSBeIHBsYWludGV4dC5jaGFyQ29kZUF0KG4raSkpO1xuXHRcdFx0XHR9XG5cdFx0XHR9XG5cdFx0XHRjaXBoZXJ0ZXh0ID0gdGVtcENpcGhlcnRleHQuam9pbignJyk7XG5cdFx0XHRcblx0XHR9XG5cdFx0cmV0dXJuIGNpcGhlcnRleHQ7XG5cdH0sXG5cblx0LyoqXG5cdCAqIERlY3J5cHRzIHRoZSBwcmVmaXhlZCBkYXRhIGZvciB0aGUgTW9kaWZpY2F0aW9uIERldGVjdGlvbiBDb2RlIChNREMpIGNvbXB1dGF0aW9uXG5cdCAqIEBwYXJhbSB7b3BlbnBncF9ibG9ja19jaXBoZXJfZm59IGJsb2NrY2lwaGVyZW5jcnlwdGZuIENpcGhlciBmdW5jdGlvbiB0byB1c2Vcblx0ICogQHBhcmFtIHtJbnRlZ2VyfSBibG9ja19zaXplIEJsb2Nrc2l6ZSBvZiB0aGUgYWxnb3JpdGhtXG5cdCAqIEBwYXJhbSB7b3BlbnBncF9ieXRlX2FycmF5fSBrZXkgVGhlIGtleSBmb3IgZW5jcnlwdGlvblxuXHQgKiBAcGFyYW0ge1N0cmluZ30gY2lwaGVydGV4dCBUaGUgZW5jcnlwdGVkIGRhdGFcblx0ICogQHJldHVybiB7U3RyaW5nfSBwbGFpbnRleHQgRGF0YSBvZiBEKGNpcGhlcnRleHQpIHdpdGggYmxvY2tzaXplIGxlbmd0aCArMlxuXHQgKi9cblx0bWRjOiBmdW5jdGlvbiAoYmxvY2tjaXBoZXJlbmNyeXB0Zm4sIGJsb2NrX3NpemUsIGtleSwgY2lwaGVydGV4dCkge1xuXHRcdHZhciBpYmxvY2sgPSBuZXcgQXJyYXkoYmxvY2tfc2l6ZSk7XG5cdFx0dmFyIGFibG9jayA9IG5ldyBBcnJheShibG9ja19zaXplKTtcblx0XHR2YXIgaTtcblxuXHRcdC8vIGluaXRpYWxpc2F0aW9uIHZlY3RvclxuXHRcdGZvcihpPTA7IGkgPCBibG9ja19zaXplOyBpKyspIGlibG9ja1tpXSA9IDA7XG5cblx0XHRpYmxvY2sgPSBibG9ja2NpcGhlcmVuY3J5cHRmbihpYmxvY2ssIGtleSk7XG5cdFx0Zm9yKGkgPSAwOyBpIDwgYmxvY2tfc2l6ZTsgaSsrKVxuXHRcdHtcblx0XHRcdGFibG9ja1tpXSA9IGNpcGhlcnRleHQuY2hhckNvZGVBdChpKTtcblx0XHRcdGlibG9ja1tpXSBePSBhYmxvY2tbaV07XG5cdFx0fVxuXG5cdFx0YWJsb2NrID0gYmxvY2tjaXBoZXJlbmNyeXB0Zm4oYWJsb2NrLCBrZXkpO1xuXG5cdFx0cmV0dXJuIHV0aWwuYmluMnN0cihpYmxvY2spK1xuXHRcdFx0U3RyaW5nLmZyb21DaGFyQ29kZShhYmxvY2tbMF1eY2lwaGVydGV4dC5jaGFyQ29kZUF0KGJsb2NrX3NpemUpKStcblx0XHRcdFN0cmluZy5mcm9tQ2hhckNvZGUoYWJsb2NrWzFdXmNpcGhlcnRleHQuY2hhckNvZGVBdChibG9ja19zaXplKzEpKTtcblx0fSxcblx0LyoqXG5cdCAqIFRoaXMgZnVuY3Rpb24gZGVjcnlwdHMgYSBnaXZlbiBwbGFpbnRleHQgdXNpbmcgdGhlIHNwZWNpZmllZFxuXHQgKiBibG9ja2NpcGhlciB0byBkZWNyeXB0IGEgbWVzc2FnZVxuXHQgKiBAcGFyYW0ge29wZW5wZ3BfY2lwaGVyX2Jsb2NrX2ZufSBibG9ja2NpcGhlcmZuIFRoZSBhbGdvcml0aG0gX2VuY3J5cHRfIGZ1bmN0aW9uIHRvIGVuY3J5cHRcblx0ICogIGRhdGEgaW4gb25lIGJsb2NrX3NpemUgZW5jcnlwdGlvbi5cblx0ICogQHBhcmFtIHtJbnRlZ2VyfSBibG9ja19zaXplIHRoZSBibG9jayBzaXplIGluIGJ5dGVzIG9mIHRoZSBhbGdvcml0aG0gdXNlZFxuXHQgKiBAcGFyYW0ge1N0cmluZ30gcGxhaW50ZXh0IGNpcGhlcnRleHQgdG8gYmUgZGVjcnlwdGVkIHByb3ZpZGVkIGFzIGEgc3RyaW5nXG5cdCAqIEBwYXJhbSB7b3BlbnBncF9ieXRlX2FycmF5fSBrZXkga2V5IHRvIGJlIHVzZWQgdG8gZGVjcnlwdCB0aGUgY2lwaGVydGV4dC4gVGhpcyB3aWxsIGJlIHBhc3NlZCB0byB0aGUgXG5cdCAqICBibG9ja2NpcGhlcmZuXG5cdCAqIEBwYXJhbSB7Qm9vbGVhbn0gcmVzeW5jIGEgYm9vbGVhbiB2YWx1ZSBzcGVjaWZ5aW5nIGlmIGEgcmVzeW5jIG9mIHRoZSBcblx0ICogIElWIHNob3VsZCBiZSB1c2VkIG9yIG5vdC4gVGhlIGVuY3J5cHRlZGRhdGFwYWNrZXQgdXNlcyB0aGUgXG5cdCAqICBcIm9sZFwiIHN0eWxlIHdpdGggYSByZXN5bmMuIERlY3J5cHRpb24gd2l0aGluIGFuIFxuXHQgKiAgZW5jcnlwdGVkaW50ZWdyaXR5cHJvdGVjdGVkZGF0YSBwYWNrZXQgaXMgbm90IHJlc3luY2luZyB0aGUgSVYuXG5cdCAqIEByZXR1cm4ge1N0cmluZ30gYSBzdHJpbmcgd2l0aCB0aGUgcGxhaW50ZXh0IGRhdGFcblx0ICovXG5cblx0ZGVjcnlwdDogZnVuY3Rpb24gKGJsb2NrY2lwaGVyZW5jcnlwdGZuLCBibG9ja19zaXplLCBrZXksIGNpcGhlcnRleHQsIHJlc3luYylcblx0e1xuXHRcdHV0aWwucHJpbnRfZGVidWcoXCJyZXN5bmM6XCIrcmVzeW5jKTtcblx0XHR2YXIgaWJsb2NrID0gbmV3IEFycmF5KGJsb2NrX3NpemUpO1xuXHRcdHZhciBhYmxvY2sgPSBuZXcgQXJyYXkoYmxvY2tfc2l6ZSk7XG5cdFx0dmFyIGksIG4gPSAnJztcblx0XHR2YXIgdGV4dCA9IFtdO1xuXG5cdFx0Ly8gaW5pdGlhbGlzYXRpb24gdmVjdG9yXG5cdFx0Zm9yKGk9MDsgaSA8IGJsb2NrX3NpemU7IGkrKykgaWJsb2NrW2ldID0gMDtcblxuXHRcdGlibG9jayA9IGJsb2NrY2lwaGVyZW5jcnlwdGZuKGlibG9jaywga2V5KTtcblx0XHRmb3IoaSA9IDA7IGkgPCBibG9ja19zaXplOyBpKyspXG5cdFx0e1xuXHRcdFx0YWJsb2NrW2ldID0gY2lwaGVydGV4dC5jaGFyQ29kZUF0KGkpO1xuXHRcdFx0aWJsb2NrW2ldIF49IGFibG9ja1tpXTtcblx0XHR9XG5cblx0XHRhYmxvY2sgPSBibG9ja2NpcGhlcmVuY3J5cHRmbihhYmxvY2ssIGtleSk7XG5cblx0XHR1dGlsLnByaW50X2RlYnVnKFwib3BlbnBncF9jZmJfZGVjcnlwdDpcXG5pYmxvY2s6XCIrdXRpbC5oZXhpZHVtcChpYmxvY2spK1wiXFxuYWJsb2NrOlwiK3V0aWwuaGV4aWR1bXAoYWJsb2NrKStcIlxcblwiKTtcblx0XHR1dGlsLnByaW50X2RlYnVnKChhYmxvY2tbMF1eY2lwaGVydGV4dC5jaGFyQ29kZUF0KGJsb2NrX3NpemUpKS50b1N0cmluZygxNikrKGFibG9ja1sxXV5jaXBoZXJ0ZXh0LmNoYXJDb2RlQXQoYmxvY2tfc2l6ZSsxKSkudG9TdHJpbmcoMTYpKTtcblx0XHRcblx0XHQvLyB0ZXN0IGNoZWNrIG9jdGV0c1xuXHRcdGlmKGlibG9ja1tibG9ja19zaXplLTJdIT0oYWJsb2NrWzBdXmNpcGhlcnRleHQuY2hhckNvZGVBdChibG9ja19zaXplKSlcblx0XHR8fCBpYmxvY2tbYmxvY2tfc2l6ZS0xXSE9KGFibG9ja1sxXV5jaXBoZXJ0ZXh0LmNoYXJDb2RlQXQoYmxvY2tfc2l6ZSsxKSkpXG5cdFx0e1xuXHRcdFx0dXRpbC5wcmludF9lcm9yKFwiZXJyb3IgZHVkaW5nIGRlY3J5cHRpb24uIFN5bW1lY3RyaWMgZW5jcnlwdGVkIGRhdGEgbm90IHZhbGlkLlwiKTtcblx0XHRcdHJldHVybiB0ZXh0LmpvaW4oJycpO1xuXHRcdH1cblx0XHRcblx0XHQvKiAgUkZDNDg4MDogVGFnIDE4IGFuZCBSZXN5bmM6XG5cdFx0ICogIFsuLi5dIFVubGlrZSB0aGUgU3ltbWV0cmljYWxseSBFbmNyeXB0ZWQgRGF0YSBQYWNrZXQsIG5vXG5cdFx0ICogIHNwZWNpYWwgQ0ZCIHJlc3luY2hyb25pemF0aW9uIGlzIGRvbmUgYWZ0ZXIgZW5jcnlwdGluZyB0aGlzIHByZWZpeFxuXHRcdCAqICBkYXRhLiAgU2VlIFwiT3BlblBHUCBDRkIgTW9kZVwiIGJlbG93IGZvciBtb3JlIGRldGFpbHMuXG5cblx0XHQgKi9cblx0XHRcblx0XHRpZiAocmVzeW5jKSB7XG5cdFx0XHRmb3IoaT0wOyBpPGJsb2NrX3NpemU7IGkrKykgaWJsb2NrW2ldID0gY2lwaGVydGV4dC5jaGFyQ29kZUF0KGkrMik7XG5cdFx0XHRmb3Iobj1ibG9ja19zaXplKzI7IG48Y2lwaGVydGV4dC5sZW5ndGg7IG4rPWJsb2NrX3NpemUpXG5cdFx0XHR7XG5cdFx0XHRcdGFibG9jayA9IGJsb2NrY2lwaGVyZW5jcnlwdGZuKGlibG9jaywga2V5KTtcblxuXHRcdFx0XHRmb3IoaSA9IDA7IGk8YmxvY2tfc2l6ZSAmJiBpK24gPCBjaXBoZXJ0ZXh0Lmxlbmd0aDsgaSsrKVxuXHRcdFx0XHR7XG5cdFx0XHRcdFx0aWJsb2NrW2ldID0gY2lwaGVydGV4dC5jaGFyQ29kZUF0KG4raSk7XG5cdFx0XHRcdFx0dGV4dC5wdXNoKFN0cmluZy5mcm9tQ2hhckNvZGUoYWJsb2NrW2ldXmlibG9ja1tpXSkpOyBcblx0XHRcdFx0fVxuXHRcdFx0fVxuXHRcdH0gZWxzZSB7XG5cdFx0XHRmb3IoaT0wOyBpPGJsb2NrX3NpemU7IGkrKykgaWJsb2NrW2ldID0gY2lwaGVydGV4dC5jaGFyQ29kZUF0KGkpO1xuXHRcdFx0Zm9yKG49YmxvY2tfc2l6ZTsgbjxjaXBoZXJ0ZXh0Lmxlbmd0aDsgbis9YmxvY2tfc2l6ZSlcblx0XHRcdHtcblx0XHRcdFx0YWJsb2NrID0gYmxvY2tjaXBoZXJlbmNyeXB0Zm4oaWJsb2NrLCBrZXkpO1xuXHRcdFx0XHRmb3IoaSA9IDA7IGk8YmxvY2tfc2l6ZSAmJiBpK24gPCBjaXBoZXJ0ZXh0Lmxlbmd0aDsgaSsrKVxuXHRcdFx0XHR7XG5cdFx0XHRcdFx0aWJsb2NrW2ldID0gY2lwaGVydGV4dC5jaGFyQ29kZUF0KG4raSk7XG5cdFx0XHRcdFx0dGV4dC5wdXNoKFN0cmluZy5mcm9tQ2hhckNvZGUoYWJsb2NrW2ldXmlibG9ja1tpXSkpOyBcblx0XHRcdFx0fVxuXHRcdFx0fVxuXHRcdH1cblx0XHRcblx0XHRyZXR1cm4gdGV4dC5qb2luKCcnKTtcblx0fSxcblxuXG5cdG5vcm1hbEVuY3J5cHQ6IGZ1bmN0aW9uKGJsb2NrY2lwaGVyZW5jcnlwdGZuLCBibG9ja19zaXplLCBrZXksIHBsYWludGV4dCwgaXYpIHtcblx0XHR2YXIgYmxvY2tpID1cIlwiO1xuXHRcdHZhciBibG9ja2MgPSBcIlwiO1xuXHRcdHZhciBwb3MgPSAwO1xuXHRcdHZhciBjeXBoZXJ0ZXh0ID0gW107XG5cdFx0dmFyIHRlbXBCbG9jayA9IFtdO1xuXHRcdGJsb2NrYyA9IGl2LnN1YnN0cmluZygwLGJsb2NrX3NpemUpO1xuXHRcdHdoaWxlIChwbGFpbnRleHQubGVuZ3RoID4gYmxvY2tfc2l6ZSpwb3MpIHtcblx0XHRcdHZhciBlbmNibG9jayA9IGJsb2NrY2lwaGVyZW5jcnlwdGZuKGJsb2NrYywga2V5KTtcblx0XHRcdGJsb2NraSA9IHBsYWludGV4dC5zdWJzdHJpbmcoKHBvcypibG9ja19zaXplKSwocG9zKmJsb2NrX3NpemUpK2Jsb2NrX3NpemUpO1xuXHRcdFx0Zm9yICh2YXIgaT0wOyBpIDwgYmxvY2tpLmxlbmd0aDsgaSsrKVxuXHRcdFx0XHR0ZW1wQmxvY2sucHVzaChTdHJpbmcuZnJvbUNoYXJDb2RlKGJsb2NraS5jaGFyQ29kZUF0KGkpIF4gZW5jYmxvY2tbaV0pKTtcblx0XHRcdGJsb2NrYyA9IHRlbXBCbG9jay5qb2luKCcnKTtcblx0XHRcdHRlbXBCbG9jayA9IFtdO1xuXHRcdFx0Y3lwaGVydGV4dC5wdXNoKGJsb2NrYyk7XG5cdFx0XHRwb3MrKztcblx0XHR9XG5cdFx0cmV0dXJuIGN5cGhlcnRleHQuam9pbignJyk7XG5cdH0sXG5cblx0bm9ybWFsRGVjcnlwdDogZnVuY3Rpb24oYmxvY2tjaXBoZXJlbmNyeXB0Zm4sIGJsb2NrX3NpemUsIGtleSwgY2lwaGVydGV4dCwgaXYpIHsgXG5cdFx0dmFyIGJsb2NrcCA9XCJcIjtcblx0XHR2YXIgcG9zID0gMDtcblx0XHR2YXIgcGxhaW50ZXh0ID0gW107XG5cdFx0dmFyIG9mZnNldCA9IDA7XG5cdFx0aWYgKGl2ID09IG51bGwpXG5cdFx0XHRmb3IgKHZhciBpID0gMDsgaSA8IGJsb2NrX3NpemU7IGkrKykgYmxvY2twICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoMCk7XG5cdFx0ZWxzZVxuXHRcdFx0YmxvY2twID0gaXYuc3Vic3RyaW5nKDAsYmxvY2tfc2l6ZSk7XG5cdFx0d2hpbGUgKGNpcGhlcnRleHQubGVuZ3RoID4gKGJsb2NrX3NpemUqcG9zKSkge1xuXHRcdFx0dmFyIGRlY2Jsb2NrID0gYmxvY2tjaXBoZXJlbmNyeXB0Zm4oYmxvY2twLCBrZXkpO1xuXHRcdFx0YmxvY2twID0gY2lwaGVydGV4dC5zdWJzdHJpbmcoKHBvcyooYmxvY2tfc2l6ZSkpK29mZnNldCwocG9zKihibG9ja19zaXplKSkrKGJsb2NrX3NpemUpK29mZnNldCk7XG5cdFx0XHRmb3IgKHZhciBpPTA7IGkgPCBibG9ja3AubGVuZ3RoOyBpKyspIHtcblx0XHRcdFx0cGxhaW50ZXh0LnB1c2goU3RyaW5nLmZyb21DaGFyQ29kZShibG9ja3AuY2hhckNvZGVBdChpKSBeIGRlY2Jsb2NrW2ldKSk7XG5cdFx0XHR9XG5cdFx0XHRwb3MrKztcblx0XHR9XG5cdFx0XG5cdFx0cmV0dXJuIHBsYWludGV4dC5qb2luKCcnKTtcblx0fVxufVxuXG59KSgpIiwiXG5tb2R1bGUuZXhwb3J0cyA9IHtcblx0cnNhOiByZXF1aXJlKCcuL3JzYS5qcycpLFxuXHRlbGdhbWFsOiByZXF1aXJlKCcuL2VsZ2FtYWwuanMnKSxcblx0ZHNhOiByZXF1aXJlKCcuL2RzYS5qcycpXG59XG5cbiIsIlxudmFyIHB1YmxpY0tleSA9IHJlcXVpcmUoJy4vcHVibGljX2tleScpLFxuXHRwa2NzMSA9IHJlcXVpcmUoJy4vcGtjczEuanMnKSxcblx0aGFzaE1vZHVsZSA9IHJlcXVpcmUoJy4vaGFzaCcpO1xuXG5tb2R1bGUuZXhwb3J0cyA9IHtcblx0LyoqXG5cdCAqIFxuXHQgKiBAcGFyYW0ge0ludGVnZXJ9IGFsZ28gcHVibGljIEtleSBhbGdvcml0aG1cblx0ICogQHBhcmFtIHtJbnRlZ2VyfSBoYXNoX2FsZ28gSGFzaCBhbGdvcml0aG1cblx0ICogQHBhcmFtIHtvcGVucGdwX3R5cGVfbXBpW119IG1zZ19NUElzIFNpZ25hdHVyZSBtdWx0aXByZWNpc2lvbiBpbnRlZ2Vyc1xuXHQgKiBAcGFyYW0ge29wZW5wZ3BfdHlwZV9tcGlbXX0gcHVibGlja2V5X01QSXMgUHVibGljIGtleSBtdWx0aXByZWNpc2lvbiBpbnRlZ2VycyBcblx0ICogQHBhcmFtIHtTdHJpbmd9IGRhdGEgRGF0YSBvbiB3aGVyZSB0aGUgc2lnbmF0dXJlIHdhcyBjb21wdXRlZCBvbi5cblx0ICogQHJldHVybiB7Qm9vbGVhbn0gdHJ1ZSBpZiBzaWduYXR1cmUgKHNpZ19kYXRhIHdhcyBlcXVhbCB0byBkYXRhIG92ZXIgaGFzaClcblx0ICovXG5cdHZlcmlmeTogZnVuY3Rpb24oYWxnbywgaGFzaF9hbGdvLCBtc2dfTVBJcywgcHVibGlja2V5X01QSXMsIGRhdGEpIHtcblx0XHR2YXIgY2FsY19oYXNoID0gaGFzaE1vZHVsZS5kaWdlc3QoaGFzaF9hbGdvLCBkYXRhKTtcblxuXHRcdHN3aXRjaChhbGdvKSB7XG5cdFx0Y2FzZSAxOiAvLyBSU0EgKEVuY3J5cHQgb3IgU2lnbikgW0hBQ10gIFxuXHRcdGNhc2UgMjogLy8gUlNBIEVuY3J5cHQtT25seSBbSEFDXVxuXHRcdGNhc2UgMzogLy8gUlNBIFNpZ24tT25seSBbSEFDXVxuXHRcdFx0dmFyIHJzYSA9IG5ldyBwdWJsaWNLZXkucnNhKCk7XG5cdFx0XHR2YXIgbiA9IHB1YmxpY2tleV9NUElzWzBdLnRvQmlnSW50ZWdlcigpO1xuXHRcdFx0dmFyIGUgPSBwdWJsaWNrZXlfTVBJc1sxXS50b0JpZ0ludGVnZXIoKTtcblx0XHRcdHZhciB4ID0gbXNnX01QSXNbMF0udG9CaWdJbnRlZ2VyKCk7XG5cdFx0XHR2YXIgZG9wdWJsaWMgPSByc2EudmVyaWZ5KHgsZSxuKTtcblx0XHRcdHZhciBoYXNoICA9IHBrY3MxLmVtc2EuZGVjb2RlKGhhc2hfYWxnbyxkb3B1YmxpYy50b01QSSgpLnN1YnN0cmluZygyKSk7XG5cdFx0XHRpZiAoaGFzaCA9PSAtMSkge1xuXHRcdFx0XHR0aHJvdyBuZXcgRXJyb3IoJ1BLQ1MxIHBhZGRpbmcgaW4gbWVzc2FnZSBvciBrZXkgaW5jb3JyZWN0LiBBYm9ydGluZy4uLicpO1xuXHRcdFx0fVxuXHRcdFx0cmV0dXJuIGhhc2ggPT0gY2FsY19oYXNoO1xuXHRcdFx0XG5cdFx0Y2FzZSAxNjogLy8gRWxnYW1hbCAoRW5jcnlwdC1Pbmx5KSBbRUxHQU1BTF0gW0hBQ11cblx0XHRcdHRocm93IG5ldyBFcnJvcihcInNpZ25pbmcgd2l0aCBFbGdhbWFsIGlzIG5vdCBkZWZpbmVkIGluIHRoZSBPcGVuUEdQIHN0YW5kYXJkLlwiKTtcblx0XHRjYXNlIDE3OiAvLyBEU0EgKERpZ2l0YWwgU2lnbmF0dXJlIEFsZ29yaXRobSkgW0ZJUFMxODZdIFtIQUNdXG5cdFx0XHR2YXIgZHNhID0gbmV3IHB1YmxpY0tleS5kc2EoKTtcblx0XHRcdHZhciBzMSA9IG1zZ19NUElzWzBdLnRvQmlnSW50ZWdlcigpO1xuXHRcdFx0dmFyIHMyID0gbXNnX01QSXNbMV0udG9CaWdJbnRlZ2VyKCk7XG5cdFx0XHR2YXIgcCA9IHB1YmxpY2tleV9NUElzWzBdLnRvQmlnSW50ZWdlcigpO1xuXHRcdFx0dmFyIHEgPSBwdWJsaWNrZXlfTVBJc1sxXS50b0JpZ0ludGVnZXIoKTtcblx0XHRcdHZhciBnID0gcHVibGlja2V5X01QSXNbMl0udG9CaWdJbnRlZ2VyKCk7XG5cdFx0XHR2YXIgeSA9IHB1YmxpY2tleV9NUElzWzNdLnRvQmlnSW50ZWdlcigpO1xuXHRcdFx0dmFyIG0gPSBkYXRhO1xuXHRcdFx0dmFyIGRvcHVibGljID0gZHNhLnZlcmlmeShoYXNoX2FsZ28sczEsczIsbSxwLHEsZyx5KTtcblx0XHRcdHJldHVybiBkb3B1YmxpYy5jb21wYXJlVG8oczEpID09IDA7XG5cdFx0ZGVmYXVsdDpcblx0XHRcdHRocm93IG5ldyBFcnJvcignSW52YWxpZCBzaWduYXR1cmUgYWxnb3JpdGhtLicpO1xuXHRcdH1cblx0XHRcblx0fSxcblx0ICAgXG5cdC8qKlxuXHQgKiBDcmVhdGUgYSBzaWduYXR1cmUgb24gZGF0YSB1c2luZyB0aGUgc3BlY2lmaWVkIGFsZ29yaXRobVxuXHQgKiBAcGFyYW0ge0ludGVnZXJ9IGhhc2hfYWxnbyBoYXNoIEFsZ29yaXRobSB0byB1c2UgKFNlZSBSRkM0ODgwIDkuNClcblx0ICogQHBhcmFtIHtJbnRlZ2VyfSBhbGdvIEFzeW1tZXRyaWMgY2lwaGVyIGFsZ29yaXRobSB0byB1c2UgKFNlZSBSRkM0ODgwIDkuMSlcblx0ICogQHBhcmFtIHtvcGVucGdwX3R5cGVfbXBpW119IHB1YmxpY01QSXMgUHVibGljIGtleSBtdWx0aXByZWNpc2lvbiBpbnRlZ2VycyBcblx0ICogb2YgdGhlIHByaXZhdGUga2V5IFxuXHQgKiBAcGFyYW0ge29wZW5wZ3BfdHlwZV9tcGlbXX0gc2VjcmV0TVBJcyBQcml2YXRlIGtleSBtdWx0aXByZWNpc2lvbiBcblx0ICogaW50ZWdlcnMgd2hpY2ggaXMgdXNlZCB0byBzaWduIHRoZSBkYXRhXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBkYXRhIERhdGEgdG8gYmUgc2lnbmVkXG5cdCAqIEByZXR1cm4ge29wZW5wZ3BfdHlwZV9tcGlbXX1cblx0ICovXG5cdHNpZ246IGZ1bmN0aW9uKGhhc2hfYWxnbywgYWxnbywga2V5SW50ZWdlcnMsIGRhdGEpIHtcblx0XHRcblx0XHRzd2l0Y2goYWxnbykge1xuXHRcdGNhc2UgMTogLy8gUlNBIChFbmNyeXB0IG9yIFNpZ24pIFtIQUNdICBcblx0XHRjYXNlIDI6IC8vIFJTQSBFbmNyeXB0LU9ubHkgW0hBQ11cblx0XHRjYXNlIDM6IC8vIFJTQSBTaWduLU9ubHkgW0hBQ11cblx0XHRcdHZhciByc2EgPSBuZXcgcHVibGljS2V5LnJzYSgpO1xuXHRcdFx0dmFyIGQgPSBrZXlJbnRlZ2Vyc1syXS50b0JpZ0ludGVnZXIoKTtcblx0XHRcdHZhciBuID0ga2V5SW50ZWdlcnNbMF0udG9CaWdJbnRlZ2VyKCk7XG5cdFx0XHR2YXIgbSA9IHBrY3MxLmVtc2EuZW5jb2RlKGhhc2hfYWxnbywgXG5cdFx0XHRcdGRhdGEsIGtleUludGVnZXJzWzBdLmJ5dGVMZW5ndGgoKSk7XG5cblx0XHRcdHJldHVybiByc2Euc2lnbihtLCBkLCBuKS50b01QSSgpO1xuXG5cdFx0Y2FzZSAxNzogLy8gRFNBIChEaWdpdGFsIFNpZ25hdHVyZSBBbGdvcml0aG0pIFtGSVBTMTg2XSBbSEFDXVxuXHRcdFx0dmFyIGRzYSA9IG5ldyBwdWJsaWNLZXkuZHNhKCk7XG5cblx0XHRcdHZhciBwID0ga2V5SW50ZWdlcnNbMF0udG9CaWdJbnRlZ2VyKCk7XG5cdFx0XHR2YXIgcSA9IGtleUludGVnZXJzWzFdLnRvQmlnSW50ZWdlcigpO1xuXHRcdFx0dmFyIGcgPSBrZXlJbnRlZ2Vyc1syXS50b0JpZ0ludGVnZXIoKTtcblx0XHRcdHZhciB5ID0ga2V5SW50ZWdlcnNbM10udG9CaWdJbnRlZ2VyKCk7XG5cdFx0XHR2YXIgeCA9IGtleUludGVnZXJzWzRdLnRvQmlnSW50ZWdlcigpO1xuXHRcdFx0dmFyIG0gPSBkYXRhO1xuXHRcdFx0dmFyIHJlc3VsdCA9IGRzYS5zaWduKGhhc2hfYWxnbyxtLCBnLCBwLCBxLCB4KTtcblxuXHRcdFx0cmV0dXJuIHJlc3VsdFswXS50b1N0cmluZygpICsgcmVzdWx0WzFdLnRvU3RyaW5nKCk7XG5cdFx0Y2FzZSAxNjogLy8gRWxnYW1hbCAoRW5jcnlwdC1Pbmx5KSBbRUxHQU1BTF0gW0hBQ11cblx0XHRcdHRocm93IG5ldyBFcnJvcignU2lnbmluZyB3aXRoIEVsZ2FtYWwgaXMgbm90IGRlZmluZWQgaW4gdGhlIE9wZW5QR1Agc3RhbmRhcmQuJyk7XG5cdFx0ZGVmYXVsdDpcblx0XHRcdHRocm93IG5ldyBFcnJvcignSW52YWxpZCBzaWduYXR1cmUgYWxnb3JpdGhtLicpO1xuXHRcdH1cdFxuXHR9XG59XG4iLCIvLyBHUEc0QnJvd3NlcnMgLSBBbiBPcGVuUEdQIGltcGxlbWVudGF0aW9uIGluIGphdmFzY3JpcHRcbi8vIENvcHlyaWdodCAoQykgMjAxMSBSZWN1cml0eSBMYWJzIEdtYkhcbi8vIFxuLy8gVGhpcyBsaWJyYXJ5IGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vclxuLy8gbW9kaWZ5IGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIExlc3NlciBHZW5lcmFsIFB1YmxpY1xuLy8gTGljZW5zZSBhcyBwdWJsaXNoZWQgYnkgdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyXG4vLyB2ZXJzaW9uIDIuMSBvZiB0aGUgTGljZW5zZSwgb3IgKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbi8vIFxuLy8gVGhpcyBsaWJyYXJ5IGlzIGRpc3RyaWJ1dGVkIGluIHRoZSBob3BlIHRoYXQgaXQgd2lsbCBiZSB1c2VmdWwsXG4vLyBidXQgV0lUSE9VVCBBTlkgV0FSUkFOVFk7IHdpdGhvdXQgZXZlbiB0aGUgaW1wbGllZCB3YXJyYW50eSBvZlxuLy8gTUVSQ0hBTlRBQklMSVRZIG9yIEZJVE5FU1MgRk9SIEEgUEFSVElDVUxBUiBQVVJQT1NFLiAgU2VlIHRoZSBHTlVcbi8vIExlc3NlciBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGZvciBtb3JlIGRldGFpbHMuXG4vLyBcbi8vIFlvdSBzaG91bGQgaGF2ZSByZWNlaXZlZCBhIGNvcHkgb2YgdGhlIEdOVSBMZXNzZXIgR2VuZXJhbCBQdWJsaWNcbi8vIExpY2Vuc2UgYWxvbmcgd2l0aCB0aGlzIGxpYnJhcnk7IGlmIG5vdCwgd3JpdGUgdG8gdGhlIEZyZWUgU29mdHdhcmVcbi8vIEZvdW5kYXRpb24sIEluYy4sIDUxIEZyYW5rbGluIFN0cmVldCwgRmlmdGggRmxvb3IsIEJvc3RvbiwgTUEgIDAyMTEwLTEzMDEgIFVTQSBcblxuLy8gVGhlIEdQRzRCcm93c2VycyBjcnlwdG8gaW50ZXJmYWNlXG5cbnZhciByYW5kb20gPSByZXF1aXJlKCcuL3JhbmRvbS5qcycpLFxuXHRwdWJsaWNLZXk9IHJlcXVpcmUoJy4vcHVibGljX2tleScpLFxuXHR0eXBlX21waSA9IHJlcXVpcmUoJy4uL3R5cGUvbXBpLmpzJyk7XG5cbm1vZHVsZS5leHBvcnRzID0ge1xuLyoqXG4gKiBFbmNyeXB0cyBkYXRhIHVzaW5nIHRoZSBzcGVjaWZpZWQgcHVibGljIGtleSBtdWx0aXByZWNpc2lvbiBpbnRlZ2VycyBcbiAqIGFuZCB0aGUgc3BlY2lmaWVkIGFsZ29yaXRobS5cbiAqIEBwYXJhbSB7SW50ZWdlcn0gYWxnbyBBbGdvcml0aG0gdG8gYmUgdXNlZCAoU2VlIFJGQzQ4ODAgOS4xKVxuICogQHBhcmFtIHtvcGVucGdwX3R5cGVfbXBpW119IHB1YmxpY01QSXMgQWxnb3JpdGhtIGRlcGVuZGVudCBtdWx0aXByZWNpc2lvbiBpbnRlZ2Vyc1xuICogQHBhcmFtIHtvcGVucGdwX3R5cGVfbXBpfSBkYXRhIERhdGEgdG8gYmUgZW5jcnlwdGVkIGFzIE1QSVxuICogQHJldHVybiB7b3BlbnBncF90eXBlX21waVtdfSBpZiBSU0EgYW4gb3BlbnBncF90eXBlX21waTsgXG4gKiBpZiBlbGdhbWFsIGVuY3J5cHRpb24gYW4gYXJyYXkgb2YgdHdvIG9wZW5wZ3BfdHlwZV9tcGkgaXMgcmV0dXJuZWQ7IG90aGVyd2lzZSBudWxsXG4gKi9cbnB1YmxpY0tleUVuY3J5cHQ6IGZ1bmN0aW9uKGFsZ28sIHB1YmxpY01QSXMsIGRhdGEpIHtcblx0dmFyIHJlc3VsdCA9IChmdW5jdGlvbigpIHtcblx0XHRzd2l0Y2goYWxnbykge1xuXHRcdGNhc2UgMTogLy8gUlNBIChFbmNyeXB0IG9yIFNpZ24pIFtIQUNdXG5cdFx0Y2FzZSAyOiAvLyBSU0EgRW5jcnlwdC1Pbmx5IFtIQUNdXG5cdFx0Y2FzZSAzOiAvLyBSU0EgU2lnbi1Pbmx5IFtIQUNdXG5cdFx0XHR2YXIgcnNhID0gbmV3IHB1YmxpY0tleS5yc2EoKTtcblx0XHRcdHZhciBuID0gcHVibGljTVBJc1swXS50b0JpZ0ludGVnZXIoKTtcblx0XHRcdHZhciBlID0gcHVibGljTVBJc1sxXS50b0JpZ0ludGVnZXIoKTtcblx0XHRcdHZhciBtID0gZGF0YS50b0JpZ0ludGVnZXIoKTtcblx0XHRcdHJldHVybiBbcnNhLmVuY3J5cHQobSxlLG4pXTtcblx0XHRjYXNlIDE2OiAvLyBFbGdhbWFsIChFbmNyeXB0LU9ubHkpIFtFTEdBTUFMXSBbSEFDXVxuXHRcdFx0dmFyIGVsZ2FtYWwgPSBuZXcgcHVibGljS2V5LmVsZ2FtYWwoKTtcblx0XHRcdHZhciBwID0gcHVibGljTVBJc1swXS50b0JpZ0ludGVnZXIoKTtcblx0XHRcdHZhciBnID0gcHVibGljTVBJc1sxXS50b0JpZ0ludGVnZXIoKTtcblx0XHRcdHZhciB5ID0gcHVibGljTVBJc1syXS50b0JpZ0ludGVnZXIoKTtcblx0XHRcdHZhciBtID0gZGF0YS50b0JpZ0ludGVnZXIoKTtcblx0XHRcdHJldHVybiBlbGdhbWFsLmVuY3J5cHQobSxnLHAseSk7XG5cdFx0ZGVmYXVsdDpcblx0XHRcdHJldHVybiBbXTtcblx0XHR9XG5cdH0pKCk7XG5cblx0cmV0dXJuIHJlc3VsdC5tYXAoZnVuY3Rpb24oYm4pIHtcblx0XHR2YXIgbXBpID0gbmV3IHR5cGVfbXBpKCk7XG5cdFx0bXBpLmZyb21CaWdJbnRlZ2VyKGJuKTtcblx0XHRyZXR1cm4gbXBpO1xuXHR9KTtcbn0sXG5cbi8qKlxuICogRGVjcnlwdHMgZGF0YSB1c2luZyB0aGUgc3BlY2lmaWVkIHB1YmxpYyBrZXkgbXVsdGlwcmVjaXNpb24gaW50ZWdlcnMgb2YgdGhlIHByaXZhdGUga2V5LFxuICogdGhlIHNwZWNpZmllZCBzZWNyZXRNUElzIG9mIHRoZSBwcml2YXRlIGtleSBhbmQgdGhlIHNwZWNpZmllZCBhbGdvcml0aG0uXG4gKiBAcGFyYW0ge0ludGVnZXJ9IGFsZ28gQWxnb3JpdGhtIHRvIGJlIHVzZWQgKFNlZSBSRkM0ODgwIDkuMSlcbiAqIEBwYXJhbSB7b3BlbnBncF90eXBlX21waVtdfSBwdWJsaWNNUElzIEFsZ29yaXRobSBkZXBlbmRlbnQgbXVsdGlwcmVjaXNpb24gaW50ZWdlcnMgXG4gKiBvZiB0aGUgcHVibGljIGtleSBwYXJ0IG9mIHRoZSBwcml2YXRlIGtleVxuICogQHBhcmFtIHtvcGVucGdwX3R5cGVfbXBpW119IHNlY3JldE1QSXMgQWxnb3JpdGhtIGRlcGVuZGVudCBtdWx0aXByZWNpc2lvbiBpbnRlZ2VycyBcbiAqIG9mIHRoZSBwcml2YXRlIGtleSB1c2VkXG4gKiBAcGFyYW0ge29wZW5wZ3BfdHlwZV9tcGl9IGRhdGEgRGF0YSB0byBiZSBlbmNyeXB0ZWQgYXMgTVBJXG4gKiBAcmV0dXJuIHtvcGVucGdwX3R5cGVfbXBpfSByZXR1cm5zIGEgYmlnIGludGVnZXIgY29udGFpbmluZyB0aGUgZGVjcnlwdGVkIGRhdGE7IG90aGVyd2lzZSBudWxsXG4gKi9cblxucHVibGljS2V5RGVjcnlwdDogZnVuY3Rpb24gKGFsZ28sIGtleUludGVnZXJzLCBkYXRhSW50ZWdlcnMpIHtcblx0dmFyIGJuID0gKGZ1bmN0aW9uKCkge1xuXHRcdHN3aXRjaChhbGdvKSB7XG5cdFx0Y2FzZSAxOiAvLyBSU0EgKEVuY3J5cHQgb3IgU2lnbikgW0hBQ10gIFxuXHRcdGNhc2UgMjogLy8gUlNBIEVuY3J5cHQtT25seSBbSEFDXVxuXHRcdGNhc2UgMzogLy8gUlNBIFNpZ24tT25seSBbSEFDXVxuXHRcdFx0dmFyIHJzYSA9IG5ldyBwdWJsaWNLZXkucnNhKCk7XG5cdFx0XHQvLyAwIGFuZCAxIGFyZSB0aGUgcHVibGljIGtleS5cblx0XHRcdHZhciBkID0ga2V5SW50ZWdlcnNbMl0udG9CaWdJbnRlZ2VyKCk7XG5cdFx0XHR2YXIgcCA9IGtleUludGVnZXJzWzNdLnRvQmlnSW50ZWdlcigpO1xuXHRcdFx0dmFyIHEgPSBrZXlJbnRlZ2Vyc1s0XS50b0JpZ0ludGVnZXIoKTtcblx0XHRcdHZhciB1ID0ga2V5SW50ZWdlcnNbNV0udG9CaWdJbnRlZ2VyKCk7XG5cdFx0XHR2YXIgbSA9IGRhdGFJbnRlZ2Vyc1swXS50b0JpZ0ludGVnZXIoKTtcblx0XHRcdHJldHVybiByc2EuZGVjcnlwdChtLCBkLCBwLCBxLCB1KTtcblx0XHRjYXNlIDE2OiAvLyBFbGdhbWFsIChFbmNyeXB0LU9ubHkpIFtFTEdBTUFMXSBbSEFDXVxuXHRcdFx0dmFyIGVsZ2FtYWwgPSBuZXcgcHVibGljS2V5LmVsZ2FtYWwoKTtcblx0XHRcdHZhciB4ID0ga2V5SW50ZWdlcnNbM10udG9CaWdJbnRlZ2VyKCk7XG5cdFx0XHR2YXIgYzEgPSBkYXRhSW50ZWdlcnNbMF0udG9CaWdJbnRlZ2VyKCk7XG5cdFx0XHR2YXIgYzIgPSBkYXRhSW50ZWdlcnNbMV0udG9CaWdJbnRlZ2VyKCk7XG5cdFx0XHR2YXIgcCA9IGtleUludGVnZXJzWzBdLnRvQmlnSW50ZWdlcigpO1xuXHRcdFx0cmV0dXJuIGVsZ2FtYWwuZGVjcnlwdChjMSxjMixwLHgpO1xuXHRcdGRlZmF1bHQ6XG5cdFx0XHRyZXR1cm4gbnVsbDtcblx0XHR9XG5cdH0pKCk7XG5cblx0dmFyIHJlc3VsdCA9IG5ldyB0eXBlX21waSgpO1xuXHRyZXN1bHQuZnJvbUJpZ0ludGVnZXIoYm4pO1xuXHRyZXR1cm4gcmVzdWx0O1xufSxcblxuLyoqIFJldHVybnMgdGhlIG51bWJlciBvZiBpbnRlZ2VycyBjb21wcmlzaW5nIHRoZSBwcml2YXRlIGtleSBvZiBhbiBhbGdvcml0aG1cbiAqIEBwYXJhbSB7b3BlbnBncC5wdWJsaWNrZXl9IGFsZ28gVGhlIHB1YmxpYyBrZXkgYWxnb3JpdGhtXG4gKiBAcmV0dXJuIHtJbnRlZ2VyfSBUaGUgbnVtYmVyIG9mIGludGVnZXJzLlxuICovXG5nZXRQcml2YXRlTXBpQ291bnQ6IGZ1bmN0aW9uKGFsZ28pIHtcblx0aWYgKGFsZ28gPiAwICYmIGFsZ28gPCA0KSB7XG5cdFx0Ly8gICBBbGdvcml0aG0tU3BlY2lmaWMgRmllbGRzIGZvciBSU0Egc2VjcmV0IGtleXM6XG5cdFx0Ly8gICAtIG11bHRpcHJlY2lzaW9uIGludGVnZXIgKE1QSSkgb2YgUlNBIHNlY3JldCBleHBvbmVudCBkLlxuXHRcdC8vICAgLSBNUEkgb2YgUlNBIHNlY3JldCBwcmltZSB2YWx1ZSBwLlxuXHRcdC8vICAgLSBNUEkgb2YgUlNBIHNlY3JldCBwcmltZSB2YWx1ZSBxIChwIDwgcSkuXG5cdFx0Ly8gICAtIE1QSSBvZiB1LCB0aGUgbXVsdGlwbGljYXRpdmUgaW52ZXJzZSBvZiBwLCBtb2QgcS5cblx0XHRyZXR1cm4gNDtcblx0fSBlbHNlIGlmIChhbGdvID09IDE2KSB7XG5cdFx0Ly8gQWxnb3JpdGhtLVNwZWNpZmljIEZpZWxkcyBmb3IgRWxnYW1hbCBzZWNyZXQga2V5czpcblx0XHQvLyAgIC0gTVBJIG9mIEVsZ2FtYWwgc2VjcmV0IGV4cG9uZW50IHguXG5cdFx0cmV0dXJuIDE7XG5cdH0gZWxzZSBpZiAoYWxnbyA9PSAxNykge1xuXHRcdC8vIEFsZ29yaXRobS1TcGVjaWZpYyBGaWVsZHMgZm9yIERTQSBzZWNyZXQga2V5czpcblx0XHQvLyAgIC0gTVBJIG9mIERTQSBzZWNyZXQgZXhwb25lbnQgeC5cblx0XHRyZXR1cm4gMTtcblx0fVxuXHRlbHNlIHJldHVybiAwO1xufSxcblx0XG5nZXRQdWJsaWNNcGlDb3VudDogZnVuY3Rpb24oYWxnb3JpdGhtKSB7XG5cdC8vIC0gQSBzZXJpZXMgb2YgbXVsdGlwcmVjaXNpb24gaW50ZWdlcnMgY29tcHJpc2luZyB0aGUga2V5IG1hdGVyaWFsOlxuXHQvLyAgIEFsZ29yaXRobS1TcGVjaWZpYyBGaWVsZHMgZm9yIFJTQSBwdWJsaWMga2V5czpcblx0Ly8gICAgICAgLSBhIG11bHRpcHJlY2lzaW9uIGludGVnZXIgKE1QSSkgb2YgUlNBIHB1YmxpYyBtb2R1bHVzIG47XG5cdC8vICAgICAgIC0gYW4gTVBJIG9mIFJTQSBwdWJsaWMgZW5jcnlwdGlvbiBleHBvbmVudCBlLlxuXHRpZiAoYWxnb3JpdGhtID4gMCAmJiBhbGdvcml0aG0gPCA0KVxuXHRcdHJldHVybiAyO1xuXG5cdC8vICAgQWxnb3JpdGhtLVNwZWNpZmljIEZpZWxkcyBmb3IgRWxnYW1hbCBwdWJsaWMga2V5czpcblx0Ly8gICAgIC0gTVBJIG9mIEVsZ2FtYWwgcHJpbWUgcDtcblx0Ly8gICAgIC0gTVBJIG9mIEVsZ2FtYWwgZ3JvdXAgZ2VuZXJhdG9yIGc7XG5cdC8vICAgICAtIE1QSSBvZiBFbGdhbWFsIHB1YmxpYyBrZXkgdmFsdWUgeSAoPSBnKip4IG1vZCBwIHdoZXJlIHggIGlzIHNlY3JldCkuXG5cdGVsc2UgaWYgKGFsZ29yaXRobSA9PSAxNilcblx0XHRyZXR1cm4gMztcblxuXHQvLyAgIEFsZ29yaXRobS1TcGVjaWZpYyBGaWVsZHMgZm9yIERTQSBwdWJsaWMga2V5czpcblx0Ly8gICAgICAgLSBNUEkgb2YgRFNBIHByaW1lIHA7XG5cdC8vICAgICAgIC0gTVBJIG9mIERTQSBncm91cCBvcmRlciBxIChxIGlzIGEgcHJpbWUgZGl2aXNvciBvZiBwLTEpO1xuXHQvLyAgICAgICAtIE1QSSBvZiBEU0EgZ3JvdXAgZ2VuZXJhdG9yIGc7XG5cdC8vICAgICAgIC0gTVBJIG9mIERTQSBwdWJsaWMta2V5IHZhbHVlIHkgKD0gZyoqeCBtb2QgcCB3aGVyZSB4ICBpcyBzZWNyZXQpLlxuXHRlbHNlIGlmIChhbGdvcml0aG0gPT0gMTcpXG5cdFx0cmV0dXJuIDQ7XG5cdGVsc2Vcblx0XHRyZXR1cm4gMDtcbn0sXG5cblxuLyoqXG4gKiBnZW5lcmF0ZSByYW5kb20gYnl0ZSBwcmVmaXggYXMgc3RyaW5nIGZvciB0aGUgc3BlY2lmaWVkIGFsZ29yaXRobVxuICogQHBhcmFtIHtJbnRlZ2VyfSBhbGdvIEFsZ29yaXRobSB0byB1c2UgKHNlZSBSRkM0ODgwIDkuMilcbiAqIEByZXR1cm4ge1N0cmluZ30gUmFuZG9tIGJ5dGVzIHdpdGggbGVuZ3RoIGVxdWFsIHRvIHRoZSBibG9ja1xuICogc2l6ZSBvZiB0aGUgY2lwaGVyXG4gKi9cbmdldFByZWZpeFJhbmRvbTogZnVuY3Rpb24oYWxnbykge1xuXHRzd2l0Y2goYWxnbykge1xuXHRjYXNlIDI6XG5cdGNhc2UgMzpcblx0Y2FzZSA0OlxuXHRcdHJldHVybiByYW5kb20uZ2V0UmFuZG9tQnl0ZXMoOCk7XG5cdGNhc2UgNzpcblx0Y2FzZSA4OlxuXHRjYXNlIDk6XG5cdGNhc2UgMTA6XG5cdFx0cmV0dXJuIHJhbmRvbS5nZXRSYW5kb21CeXRlcygxNik7XG5cdGRlZmF1bHQ6XG5cdFx0cmV0dXJuIG51bGw7XG5cdH1cbn0sXG5cbi8qKlxuICogcmV0cmlldmUgdGhlIE1EQyBwcmVmaXhlZCBieXRlcyBieSBkZWNyeXB0aW5nIHRoZW1cbiAqIEBwYXJhbSB7SW50ZWdlcn0gYWxnbyBBbGdvcml0aG0gdG8gdXNlIChzZWUgUkZDNDg4MCA5LjIpXG4gKiBAcGFyYW0ge1N0cmluZ30ga2V5IEtleSBhcyBzdHJpbmcuIGxlbmd0aCBpcyBkZXBlbmRpbmcgb24gdGhlIGFsZ29yaXRobSB1c2VkXG4gKiBAcGFyYW0ge1N0cmluZ30gZGF0YSBFbmNyeXB0ZWQgZGF0YSB3aGVyZSB0aGUgcHJlZml4IGlzIGRlY3J5cHRlZCBmcm9tXG4gKiBAcmV0dXJuIHtTdHJpbmd9IFBsYWluIHRleHQgZGF0YSBvZiB0aGUgcHJlZml4ZWQgZGF0YVxuICovXG5NRENTeXN0ZW1CeXRlczogZnVuY3Rpb24oYWxnbywga2V5LCBkYXRhKSB7XG5cdHN3aXRjaChhbGdvKSB7XG5cdGNhc2UgMDogLy8gUGxhaW50ZXh0IG9yIHVuZW5jcnlwdGVkIGRhdGFcblx0XHRyZXR1cm4gZGF0YTtcblx0Y2FzZSAyOiAvLyBUcmlwbGVERVMgKERFUy1FREUsIFtTQ0hORUlFUl0gW0hBQ10gLSAxNjggYml0IGtleSBkZXJpdmVkIGZyb20gMTkyKVxuXHRcdHJldHVybiBvcGVucGdwX2NmYl9tZGMoZGVzZWRlLCA4LCBrZXksIGRhdGEsIG9wZW5wZ3BfY2ZiKTtcblx0Y2FzZSAzOiAvLyBDQVNUNSAoMTI4IGJpdCBrZXksIGFzIHBlciBbUkZDMjE0NF0pXG5cdFx0cmV0dXJuIG9wZW5wZ3BfY2ZiX21kYyhjYXN0NV9lbmNyeXB0LCA4LCBrZXksIGRhdGEpO1xuXHRjYXNlIDQ6IC8vIEJsb3dmaXNoICgxMjggYml0IGtleSwgMTYgcm91bmRzKSBbQkxPV0ZJU0hdXG5cdFx0cmV0dXJuIG9wZW5wZ3BfY2ZiX21kYyhCRmVuY3J5cHQsIDgsIGtleSwgZGF0YSk7XG5cdGNhc2UgNzogLy8gQUVTIHdpdGggMTI4LWJpdCBrZXkgW0FFU11cblx0Y2FzZSA4OiAvLyBBRVMgd2l0aCAxOTItYml0IGtleVxuXHRjYXNlIDk6IC8vIEFFUyB3aXRoIDI1Ni1iaXQga2V5XG5cdFx0cmV0dXJuIG9wZW5wZ3BfY2ZiX21kYyhBRVNlbmNyeXB0LCAxNiwga2V5RXhwYW5zaW9uKGtleSksIGRhdGEpO1xuXHRjYXNlIDEwOiBcblx0XHRyZXR1cm4gb3BlbnBncF9jZmJfbWRjKFRGZW5jcnlwdCwgMTYsIGtleSwgZGF0YSk7XG5cdGNhc2UgMTogLy8gSURFQSBbSURFQV1cblx0XHR0aHJvdyBuZXcgRXJyb3IoJ0lERUEgQWxnb3JpdGhtIG5vdCBpbXBsZW1lbnRlZCcpO1xuXHRkZWZhdWx0OlxuXHRcdHRocm93IG5ldyBFcnJvcignSW52YWxpZCBhbGdvcml0aG0uJyk7XG5cdH1cbn0sXG4vKipcbiAqIEdlbmVyYXRpbmcgYSBzZXNzaW9uIGtleSBmb3IgdGhlIHNwZWNpZmllZCBzeW1tZXRyaWMgYWxnb3JpdGhtXG4gKiBAcGFyYW0ge0ludGVnZXJ9IGFsZ28gQWxnb3JpdGhtIHRvIHVzZSAoc2VlIFJGQzQ4ODAgOS4yKVxuICogQHJldHVybiB7U3RyaW5nfSBSYW5kb20gYnl0ZXMgYXMgYSBzdHJpbmcgdG8gYmUgdXNlZCBhcyBhIGtleVxuICovXG5nZW5lcmF0ZVNlc3Npb25LZXk6IGZ1bmN0aW9uKGFsZ28pIHtcblx0cmV0dXJuIHJhbmRvbS5nZXRSYW5kb21CeXRlcyh0aGlzLmdldEtleUxlbmd0aChhbGdvKSk7IFxufSxcblxuLyoqXG4gKiBHZXQgdGhlIGtleSBsZW5ndGggYnkgc3ltbWV0cmljIGFsZ29yaXRobSBpZC5cbiAqIEBwYXJhbSB7SW50ZWdlcn0gYWxnbyBBbGdvcml0aG0gdG8gdXNlIChzZWUgUkZDNDg4MCA5LjIpXG4gKiBAcmV0dXJuIHtTdHJpbmd9IFJhbmRvbSBieXRlcyBhcyBhIHN0cmluZyB0byBiZSB1c2VkIGFzIGEga2V5XG4gKi9cbmdldEtleUxlbmd0aDogZnVuY3Rpb24oYWxnbykge1xuXHRzd2l0Y2ggKGFsZ28pIHtcblx0Y2FzZSAyOiAvLyBUcmlwbGVERVMgKERFUy1FREUsIFtTQ0hORUlFUl0gW0hBQ10gLSAxNjggYml0IGtleSBkZXJpdmVkIGZyb20gMTkyKVxuXHRjYXNlIDg6IC8vIEFFUyB3aXRoIDE5Mi1iaXQga2V5XG5cdFx0cmV0dXJuIDI0O1xuXHRjYXNlIDM6IC8vIENBU1Q1ICgxMjggYml0IGtleSwgYXMgcGVyIFtSRkMyMTQ0XSlcblx0Y2FzZSA0OiAvLyBCbG93ZmlzaCAoMTI4IGJpdCBrZXksIDE2IHJvdW5kcykgW0JMT1dGSVNIXVxuXHRjYXNlIDc6IC8vIEFFUyB3aXRoIDEyOC1iaXQga2V5IFtBRVNdXG5cdFx0cmV0dXJuIDE2O1xuXHRjYXNlIDk6IC8vIEFFUyB3aXRoIDI1Ni1iaXQga2V5XG5cdGNhc2UgMTA6Ly8gVHdvZmlzaCB3aXRoIDI1Ni1iaXQga2V5IFtUV09GSVNIXVxuXHRcdHJldHVybiAzMjtcblx0fVxuXHRyZXR1cm4gbnVsbDtcbn0sXG5cbi8qKlxuICogUmV0dXJucyB0aGUgYmxvY2sgbGVuZ3RoIG9mIHRoZSBzcGVjaWZpZWQgc3ltbWV0cmljIGVuY3J5cHRpb24gYWxnb3JpdGhtXG4gKiBAcGFyYW0ge29wZW5wZ3Auc3ltbWV0cmljfSBhbGdvIFN5bW1ldHJpYyBhbGdvcml0aG0gaWRlbmhpZmllclxuICogQHJldHVybiB7SW50ZWdlcn0gVGhlIG51bWJlciBvZiBieXRlcyBpbiBhIHNpbmdsZSBibG9jayBlbmNyeXB0ZWQgYnkgdGhlIGFsZ29yaXRobVxuICovXG5nZXRCbG9ja0xlbmd0aDogZnVuY3Rpb24oYWxnbykge1xuXHRzd2l0Y2ggKGFsZ28pIHtcblx0Y2FzZSAgMTogLy8gLSBJREVBIFtJREVBXVxuXHRjYXNlICAyOiAvLyAtIFRyaXBsZURFUyAoREVTLUVERSwgW1NDSE5FSUVSXSBbSEFDXSAtIDE2OCBiaXQga2V5IGRlcml2ZWQgZnJvbSAxOTIpXG5cdGNhc2UgIDM6IC8vIC0gQ0FTVDUgKDEyOCBiaXQga2V5LCBhcyBwZXIgW1JGQzIxNDRdKVxuXHRcdHJldHVybiA4O1xuXHRjYXNlICA0OiAvLyAtIEJsb3dmaXNoICgxMjggYml0IGtleSwgMTYgcm91bmRzKSBbQkxPV0ZJU0hdXG5cdGNhc2UgIDc6IC8vIC0gQUVTIHdpdGggMTI4LWJpdCBrZXkgW0FFU11cblx0Y2FzZSAgODogLy8gLSBBRVMgd2l0aCAxOTItYml0IGtleVxuXHRjYXNlICA5OiAvLyAtIEFFUyB3aXRoIDI1Ni1iaXQga2V5XG5cdFx0cmV0dXJuIDE2O1xuXHRjYXNlIDEwOiAvLyAtIFR3b2Zpc2ggd2l0aCAyNTYtYml0IGtleSBbVFdPRklTSF1cblx0XHRyZXR1cm4gMzI7XHQgICAgXHRcdFxuXHRkZWZhdWx0OlxuXHRcdHJldHVybiAwO1xuXHR9XG59LFxuXG4vKipcbiAqIENyZWF0ZSBhIHNlY3VyZSByYW5kb20gYmlnIGludGVnZXIgb2YgYml0cyBsZW5ndGhcbiAqIEBwYXJhbSB7SW50ZWdlcn0gYml0cyBCaXQgbGVuZ3RoIG9mIHRoZSBNUEkgdG8gY3JlYXRlXG4gKiBAcmV0dXJuIHtCaWdJbnRlZ2VyfSBSZXN1bHRpbmcgYmlnIGludGVnZXJcbiAqL1xuZ2V0UmFuZG9tQmlnSW50ZWdlcjogZnVuY3Rpb24oYml0cykge1xuXHRpZiAoYml0cyA8IDApXG5cdCAgIHJldHVybiBudWxsO1xuXHR2YXIgbnVtQnl0ZXMgPSBNYXRoLmZsb29yKChiaXRzKzcpLzgpO1xuXG5cdHZhciByYW5kb21CaXRzID0gcmFuZG9tLmdldFJhbmRvbUJ5dGVzKG51bUJ5dGVzKTtcblx0aWYgKGJpdHMgJSA4ID4gMCkge1xuXHRcdFxuXHRcdHJhbmRvbUJpdHMgPSBTdHJpbmcuZnJvbUNoYXJDb2RlKFxuXHRcdFx0XHRcdFx0KE1hdGgucG93KDIsYml0cyAlIDgpLTEpICZcblx0XHRcdFx0XHRcdHJhbmRvbUJpdHMuY2hhckNvZGVBdCgwKSkgK1xuXHRcdFx0cmFuZG9tQml0cy5zdWJzdHJpbmcoMSk7XG5cdH1cblx0cmV0dXJuIG5ldyBvcGVucGdwX3R5cGVfbXBpKCkuY3JlYXRlKHJhbmRvbUJpdHMpLnRvQmlnSW50ZWdlcigpO1xufSxcblxuZ2V0UmFuZG9tQmlnSW50ZWdlckluUmFuZ2U6IGZ1bmN0aW9uKG1pbiwgbWF4KSB7XG5cdGlmIChtYXguY29tcGFyZVRvKG1pbikgPD0gMClcblx0XHRyZXR1cm47XG5cdHZhciByYW5nZSA9IG1heC5zdWJ0cmFjdChtaW4pO1xuXHR2YXIgciA9IG9wZW5wZ3BfY3J5cHRvX2dldFJhbmRvbUJpZ0ludGVnZXIocmFuZ2UuYml0TGVuZ3RoKCkpO1xuXHR3aGlsZSAociA+IHJhbmdlKSB7XG5cdFx0ciA9IG9wZW5wZ3BfY3J5cHRvX2dldFJhbmRvbUJpZ0ludGVnZXIocmFuZ2UuYml0TGVuZ3RoKCkpO1xuXHR9XG5cdHJldHVybiBtaW4uYWRkKHIpO1xufSxcblxuXG4vL1RoaXMgaXMgYSB0ZXN0IG1ldGhvZCB0byBlbnN1cmUgdGhhdCBlbmNyeXB0aW9uL2RlY3J5cHRpb24gd2l0aCBhIGdpdmVuIDEwMjRiaXQgUlNBS2V5IG9iamVjdCBmdW5jdGlvbnMgYXMgaW50ZW5kZWRcbnRlc3RSU0E6IGZ1bmN0aW9uKGtleSl7XG5cdGRlYnVnZ2VyO1xuICAgIHZhciByc2EgPSBuZXcgUlNBKCk7XG5cdHZhciBtcGkgPSBuZXcgb3BlbnBncF90eXBlX21waSgpO1xuXHRtcGkuY3JlYXRlKG9wZW5wZ3BfZW5jb2RpbmdfZW1lX3BrY3MxX2VuY29kZSgnQUJBQkFCQUInLCAxMjgpKTtcblx0dmFyIG1zZyA9IHJzYS5lbmNyeXB0KG1waS50b0JpZ0ludGVnZXIoKSxrZXkuZWUsa2V5Lm4pO1xuXHR2YXIgcmVzdWx0ID0gcnNhLmRlY3J5cHQobXNnLCBrZXkuZCwga2V5LnAsIGtleS5xLCBrZXkudSk7XG59LFxuXG4vKipcbiAqIEB0eXBlZGVmIHtPYmplY3R9IG9wZW5wZ3Bfa2V5cGFpclxuICogQHByb3BlcnR5IHtvcGVucGdwX3BhY2tldF9rZXltYXRlcmlhbH0gcHJpdmF0ZUtleSBcbiAqIEBwcm9wZXJ0eSB7b3BlbnBncF9wYWNrZXRfa2V5bWF0ZXJpYWx9IHB1YmxpY0tleVxuICovXG5cbi8qKlxuICogQ2FsbHMgdGhlIG5lY2Vzc2FyeSBjcnlwdG8gZnVuY3Rpb25zIHRvIGdlbmVyYXRlIGEga2V5cGFpci4gXG4gKiBDYWxsZWQgZGlyZWN0bHkgYnkgb3BlbnBncC5qc1xuICogQHBhcmFtIHtJbnRlZ2VyfSBrZXlUeXBlIEZvbGxvd3MgT3BlblBHUCBhbGdvcml0aG0gY29udmVudGlvbi5cbiAqIEBwYXJhbSB7SW50ZWdlcn0gbnVtQml0cyBOdW1iZXIgb2YgYml0cyB0byBtYWtlIHRoZSBrZXkgdG8gYmUgZ2VuZXJhdGVkXG4gKiBAcmV0dXJuIHtvcGVucGdwX2tleXBhaXJ9XG4gKi9cbmdlbmVyYXRlS2V5UGFpcjogZnVuY3Rpb24oa2V5VHlwZSwgbnVtQml0cywgcGFzc3BocmFzZSwgczJrSGFzaCwgc3ltbWV0cmljRW5jcnlwdGlvbkFsZ29yaXRobSl7XG5cdHZhciBwcml2S2V5UGFja2V0O1xuXHR2YXIgcHVibGljS2V5UGFja2V0O1xuXHR2YXIgZCA9IG5ldyBEYXRlKCk7XG5cdGQgPSBkLmdldFRpbWUoKS8xMDAwO1xuXHR2YXIgdGltZVBhY2tldCA9IFN0cmluZy5mcm9tQ2hhckNvZGUoTWF0aC5mbG9vcihkLzB4MTAwMDAwMCUweDEwMCkpICsgU3RyaW5nLmZyb21DaGFyQ29kZShNYXRoLmZsb29yKGQvMHgxMDAwMCUweDEwMCkpICsgU3RyaW5nLmZyb21DaGFyQ29kZShNYXRoLmZsb29yKGQvMHgxMDAlMHgxMDApKSArIFN0cmluZy5mcm9tQ2hhckNvZGUoTWF0aC5mbG9vcihkJTB4MTAwKSk7XG5cdHN3aXRjaChrZXlUeXBlKXtcblx0Y2FzZSAxOlxuXHQgICAgdmFyIHJzYSA9IG5ldyBSU0EoKTtcblx0ICAgIHZhciBrZXkgPSByc2EuZ2VuZXJhdGUobnVtQml0cyxcIjEwMDAxXCIpO1xuXHQgICAgcHJpdktleVBhY2tldCA9IG5ldyBvcGVucGdwX3BhY2tldF9rZXltYXRlcmlhbCgpLndyaXRlX3ByaXZhdGVfa2V5KGtleVR5cGUsIGtleSwgcGFzc3BocmFzZSwgczJrSGFzaCwgc3ltbWV0cmljRW5jcnlwdGlvbkFsZ29yaXRobSwgdGltZVBhY2tldCk7XG5cdCAgICBwdWJsaWNLZXlQYWNrZXQgPSAgbmV3IG9wZW5wZ3BfcGFja2V0X2tleW1hdGVyaWFsKCkud3JpdGVfcHVibGljX2tleShrZXlUeXBlLCBrZXksIHRpbWVQYWNrZXQpO1xuXHQgICAgYnJlYWs7XG5cdGRlZmF1bHQ6XG5cdFx0dXRpbC5wcmludF9lcnJvcihcIlVua25vd24ga2V5dHlwZSBcIitrZXlUeXBlKVxuXHR9XG5cdHJldHVybiB7cHJpdmF0ZUtleTogcHJpdktleVBhY2tldCwgcHVibGljS2V5OiBwdWJsaWNLZXlQYWNrZXR9O1xufVxuXG59XG4iLCIvLyBHUEc0QnJvd3NlcnMgLSBBbiBPcGVuUEdQIGltcGxlbWVudGF0aW9uIGluIGphdmFzY3JpcHRcbi8vIENvcHlyaWdodCAoQykgMjAxMSBSZWN1cml0eSBMYWJzIEdtYkhcbi8vIFxuLy8gVGhpcyBsaWJyYXJ5IGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vclxuLy8gbW9kaWZ5IGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIExlc3NlciBHZW5lcmFsIFB1YmxpY1xuLy8gTGljZW5zZSBhcyBwdWJsaXNoZWQgYnkgdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyXG4vLyB2ZXJzaW9uIDIuMSBvZiB0aGUgTGljZW5zZSwgb3IgKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbi8vIFxuLy8gVGhpcyBsaWJyYXJ5IGlzIGRpc3RyaWJ1dGVkIGluIHRoZSBob3BlIHRoYXQgaXQgd2lsbCBiZSB1c2VmdWwsXG4vLyBidXQgV0lUSE9VVCBBTlkgV0FSUkFOVFk7IHdpdGhvdXQgZXZlbiB0aGUgaW1wbGllZCB3YXJyYW50eSBvZlxuLy8gTUVSQ0hBTlRBQklMSVRZIG9yIEZJVE5FU1MgRk9SIEEgUEFSVElDVUxBUiBQVVJQT1NFLiAgU2VlIHRoZSBHTlVcbi8vIExlc3NlciBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGZvciBtb3JlIGRldGFpbHMuXG4vLyBcbi8vIFlvdSBzaG91bGQgaGF2ZSByZWNlaXZlZCBhIGNvcHkgb2YgdGhlIEdOVSBMZXNzZXIgR2VuZXJhbCBQdWJsaWNcbi8vIExpY2Vuc2UgYWxvbmcgd2l0aCB0aGlzIGxpYnJhcnk7IGlmIG5vdCwgd3JpdGUgdG8gdGhlIEZyZWUgU29mdHdhcmVcbi8vIEZvdW5kYXRpb24sIEluYy4sIDUxIEZyYW5rbGluIFN0cmVldCwgRmlmdGggRmxvb3IsIEJvc3RvbiwgTUEgIDAyMTEwLTEzMDEgIFVTQVxuXG52YXIgZW51bXMgPSByZXF1aXJlKCcuLi9lbnVtcy5qcycpO1xuXG4vKipcbiAqIEBjbGFzc1xuICogQGNsYXNzZGVzYyBJbXBsZW1lbnRhdGlvbiBvZiB0aGUgQ29tcHJlc3NlZCBEYXRhIFBhY2tldCAoVGFnIDgpXG4gKiBcbiAqIFJGQzQ4ODAgNS42OlxuICogVGhlIENvbXByZXNzZWQgRGF0YSBwYWNrZXQgY29udGFpbnMgY29tcHJlc3NlZCBkYXRhLiAgVHlwaWNhbGx5LCB0aGlzXG4gKiBwYWNrZXQgaXMgZm91bmQgYXMgdGhlIGNvbnRlbnRzIG9mIGFuIGVuY3J5cHRlZCBwYWNrZXQsIG9yIGZvbGxvd2luZ1xuICogYSBTaWduYXR1cmUgb3IgT25lLVBhc3MgU2lnbmF0dXJlIHBhY2tldCwgYW5kIGNvbnRhaW5zIGEgbGl0ZXJhbCBkYXRhXG4gKiBwYWNrZXQuXG4gKi8gICBcbm1vZHVsZS5leHBvcnRzID0gZnVuY3Rpb24gcGFja2V0X2NvbXByZXNzZWQoKSB7XG5cdC8qKiBAdHlwZSB7cGFja2V0bGlzdH0gKi9cblx0dGhpcy5wYWNrZXRzO1xuXHQvKiogQHR5cGUge2NvbXByZXNzaW9ufSAqL1xuXHR0aGlzLmFsZ29yaXRobSA9ICd1bmNvbXByZXNzZWQnO1xuXG5cdHRoaXMuY29tcHJlc3NlZCA9IG51bGw7XG5cblx0XG5cdC8qKlxuXHQgKiBQYXJzaW5nIGZ1bmN0aW9uIGZvciB0aGUgcGFja2V0LlxuXHQgKiBAcGFyYW0ge1N0cmluZ30gaW5wdXQgUGF5bG9hZCBvZiBhIHRhZyA4IHBhY2tldFxuXHQgKiBAcGFyYW0ge0ludGVnZXJ9IHBvc2l0aW9uIFBvc2l0aW9uIHRvIHN0YXJ0IHJlYWRpbmcgZnJvbSB0aGUgaW5wdXQgc3RyaW5nXG5cdCAqIEBwYXJBTSB7aU5URUdFUn0gTEVOIGxFTkdUSCBPRiB0aGUgcGFja2V0IG9yIHRoZSByZW1haW5pbmcgbGVuZ3RoIG9mIFxuXHQgKiBpbnB1dCBhdCBwb3NpdGlvblxuXHQgKiBAcmV0dXJuIHtvcGVucGdwX3BhY2tldF9jb21wcmVzc2VkfSBPYmplY3QgcmVwcmVzZW50YXRpb25cblx0ICovXG5cdHRoaXMucmVhZCA9IGZ1bmN0aW9uKGJ5dGVzKSB7XG5cdFx0Ly8gT25lIG9jdGV0IHRoYXQgZ2l2ZXMgdGhlIGFsZ29yaXRobSB1c2VkIHRvIGNvbXByZXNzIHRoZSBwYWNrZXQuXG5cdFx0dGhpcy5hbGdvcml0aG0gPSBlbnVtcy5yZWFkKGVudW1zLmNvbXByZXNzaW9uLCBieXRlcy5jaGFyQ29kZUF0KDApKTtcblxuXHRcdC8vIENvbXByZXNzZWQgZGF0YSwgd2hpY2ggbWFrZXMgdXAgdGhlIHJlbWFpbmRlciBvZiB0aGUgcGFja2V0LlxuXHRcdHRoaXMuY29tcHJlc3NlZCA9IGJ5dGVzLnN1YnN0cigxKTtcblxuXHRcdHRoaXMuZGVjb21wcmVzcygpO1xuXHR9XG5cblx0XG5cdFxuXHR0aGlzLndyaXRlID0gZnVuY3Rpb24oKSB7XG5cdFx0aWYodGhpcy5jb21wcmVzc2VkID09IG51bGwpXG5cdFx0XHR0aGlzLmNvbXByZXNzKCk7XG5cblx0XHRyZXR1cm4gU3RyaW5nLmZyb21DaGFyQ29kZShlbnVtcy53cml0ZShlbnVtcy5jb21wcmVzc2lvbiwgdGhpcy5hbGdvcml0aG0pKSBcblx0XHRcdCsgdGhpcy5jb21wcmVzc2VkO1xuXHR9XG5cblxuXHQvKipcblx0ICogRGVjb21wcmVzc2lvbiBtZXRob2QgZm9yIGRlY29tcHJlc3NpbmcgdGhlIGNvbXByZXNzZWQgZGF0YVxuXHQgKiByZWFkIGJ5IHJlYWRfcGFja2V0XG5cdCAqIEByZXR1cm4ge1N0cmluZ30gVGhlIGRlY29tcHJlc3NlZCBkYXRhXG5cdCAqL1xuXHR0aGlzLmRlY29tcHJlc3MgPSBmdW5jdGlvbigpIHtcblx0XHR2YXIgZGVjb21wcmVzc2VkO1xuXG5cdFx0c3dpdGNoICh0aGlzLmFsZ29yaXRobSkge1xuXHRcdGNhc2UgJ3VuY29tcHJlc3NlZCc6XG5cdFx0XHRkZWNvbXByZXNzZWQgPSB0aGlzLmNvbXByZXNzZWQ7XG5cdFx0XHRicmVhaztcblxuXHRcdGNhc2UgJ3ppcCc6XG5cdFx0XHR2YXIgY29tcERhdGEgPSB0aGlzLmNvbXByZXNzZWQ7XG5cblx0XHRcdHZhciByYWRpeCA9IHMycihjb21wRGF0YSkucmVwbGFjZSgvXFxuL2csXCJcIik7XG5cdFx0XHQvLyBubyBoZWFkZXIgaW4gdGhpcyBjYXNlLCBkaXJlY3RseSBjYWxsIGRlZmxhdGVcblx0XHRcdHZhciBqeGdfb2JqID0gbmV3IEpYRy5VdGlsLlVuemlwKEpYRy5VdGlsLkJhc2U2NC5kZWNvZGVBc0FycmF5KHJhZGl4KSk7XG5cblx0XHRcdGRlY29tcHJlc3NlZCA9IHVuZXNjYXBlKGp4Z19vYmouZGVmbGF0ZSgpWzBdWzBdKTtcblx0XHRcdGJyZWFrO1xuXG5cdFx0Y2FzZSAnemxpYic6XG5cdFx0XHQvL1JGQyAxOTUwLiBCaXRzIDAtMyBDb21wcmVzc2lvbiBNZXRob2Rcblx0XHRcdHZhciBjb21wcmVzc2lvbk1ldGhvZCA9IHRoaXMuY29tcHJlc3NlZC5jaGFyQ29kZUF0KDApICUgMHgxMDtcblxuXHRcdFx0Ly9CaXRzIDQtNyBSRkMgMTk1MCBhcmUgTFo3NyBXaW5kb3cuIEdlbmVyYWxseSB0aGlzIHZhbHVlIGlzIDcgPT0gMzJrIHdpbmRvdyBzaXplLlxuXHRcdFx0Ly8gMm5kIEJ5dGUgaW4gUkZDIDE5NTAgaXMgZm9yIFwiRkxBR3NcIiBBbGxvd3MgZm9yIGEgRGljdGlvbmFyeSBcblx0XHRcdC8vIChob3cgaXMgdGhpcyBkZWZpbmVkKS4gQmFzaWMgY2hlY2tzdW0sIGFuZCBjb21wcmVzc2lvbiBsZXZlbC5cblxuXHRcdFx0aWYgKGNvbXByZXNzaW9uTWV0aG9kID09IDgpIHsgLy9DTSA4IGlzIGZvciBERUZMQVRFLCBSRkMgMTk1MVxuXHRcdFx0XHQvLyByZW1vdmUgNCBieXRlcyBBRExFUjMyIGNoZWNrc3VtIGZyb20gdGhlIGVuZFxuXHRcdFx0XHR2YXIgY29tcERhdGEgPSB0aGlzLmNvbXByZXNzZWQuc3Vic3RyaW5nKDAsIHRoaXMuY29tcHJlc3NlZC5sZW5ndGggLSA0KTtcblx0XHRcdFx0dmFyIHJhZGl4ID0gczJyKGNvbXBEYXRhKS5yZXBsYWNlKC9cXG4vZyxcIlwiKTtcblx0XHRcdFx0Ly9UT0RPIGNoZWNrIEFETEVSMzIgY2hlY2tzdW1cblx0XHRcdFx0ZGVjb21wcmVzc2VkID0gSlhHLmRlY29tcHJlc3MocmFkaXgpO1xuXHRcdFx0XHRicmVhaztcblxuXHRcdFx0fSBlbHNlIHtcblx0XHRcdFx0dXRpbC5wcmludF9lcnJvcihcIkNvbXByZXNzaW9uIGFsZ29yaXRobSBaTElCIG9ubHkgc3VwcG9ydHMgXCIgK1xuXHRcdFx0XHRcdFwiREVGTEFURSBjb21wcmVzc2lvbiBtZXRob2QuXCIpO1xuXHRcdFx0fVxuXHRcdFx0YnJlYWs7XG5cblx0XHRjYXNlICdiemlwMic6XG5cdFx0XHQvLyBUT0RPOiBuZWVkIHRvIGltcGxlbWVudCB0aGlzXG5cdFx0XHR0aHJvdyBuZXcgRXJyb3IoJ0NvbXByZXNzaW9uIGFsZ29yaXRobSBCWmlwMiBbQloyXSBpcyBub3QgaW1wbGVtZW50ZWQuJyk7XG5cdFx0XHRicmVhaztcblxuXHRcdGRlZmF1bHQ6XG5cdFx0XHR0aHJvdyBuZXcgRXJyb3IoXCJDb21wcmVzc2lvbiBhbGdvcml0aG0gdW5rbm93biA6XCIgKyB0aGlzLmFsb2dyaXRobSk7XG5cdFx0XHRicmVhaztcblx0XHR9XG5cblx0XHR0aGlzLnBhY2tldHMucmVhZChkZWNvbXByZXNzZWQpO1xuXHR9XG5cblx0LyoqXG5cdCAqIENvbXByZXNzIHRoZSBwYWNrZXQgZGF0YSAobWVtYmVyIGRlY29tcHJlc3NlZERhdGEpXG5cdCAqIEBwYXJhbSB7SW50ZWdlcn0gdHlwZSBBbGdvcml0aG0gdG8gYmUgdXNlZCAvLyBTZWUgUkZDIDQ4ODAgOS4zXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBkYXRhIERhdGEgdG8gYmUgY29tcHJlc3NlZFxuXHQgKiBAcmV0dXJuIHtTdHJpbmd9IFRoZSBjb21wcmVzc2VkIGRhdGEgc3RvcmVkIGluIGF0dHJpYnV0ZSBjb21wcmVzc2VkRGF0YVxuXHQgKi9cblx0dGhpcy5jb21wcmVzcyA9IGZ1bmN0aW9uKCkge1xuXHRcdHN3aXRjaCAodGhpcy5hbGdvcml0aG0pIHtcblxuXHRcdGNhc2UgJ3VuY29tcHJlc3NlZCc6IC8vIC0gVW5jb21wcmVzc2VkXG5cdFx0XHR0aGlzLmNvbXByZXNzZWQgPSB0aGlzLnBhY2tldHMud3JpdGUoKTtcblx0XHRcdGJyZWFrO1xuXG5cdFx0Y2FzZSAnemlwJzogLy8gLSBaSVAgW1JGQzE5NTFdXG5cdFx0XHR1dGlsLnByaW50X2Vycm9yKFwiQ29tcHJlc3Npb24gYWxnb3JpdGhtIFpJUCBbUkZDMTk1MV0gaXMgbm90IGltcGxlbWVudGVkLlwiKTtcblx0XHRcdGJyZWFrO1xuXG5cdFx0Y2FzZSAnemxpYic6IC8vIC0gWkxJQiBbUkZDMTk1MF1cblx0XHRcdC8vIFRPRE86IG5lZWQgdG8gaW1wbGVtZW50IHRoaXNcblx0XHRcdHV0aWwucHJpbnRfZXJyb3IoXCJDb21wcmVzc2lvbiBhbGdvcml0aG0gWkxJQiBbUkZDMTk1MF0gaXMgbm90IGltcGxlbWVudGVkLlwiKTtcblx0XHRcdGJyZWFrO1xuXG5cdFx0Y2FzZSAnYnppcDInOiAvLyAgLSBCWmlwMiBbQloyXVxuXHRcdFx0Ly8gVE9ETzogbmVlZCB0byBpbXBsZW1lbnQgdGhpc1xuXHRcdFx0dXRpbC5wcmludF9lcnJvcihcIkNvbXByZXNzaW9uIGFsZ29yaXRobSBCWmlwMiBbQloyXSBpcyBub3QgaW1wbGVtZW50ZWQuXCIpO1xuXHRcdFx0YnJlYWs7XG5cblx0XHRkZWZhdWx0OlxuXHRcdFx0dXRpbC5wcmludF9lcnJvcihcIkNvbXByZXNzaW9uIGFsZ29yaXRobSB1bmtub3duIDpcIit0aGlzLnR5cGUpO1xuXHRcdFx0YnJlYWs7XG5cdFx0fVxuXHR9XG59O1xuIiwiLy8gR1BHNEJyb3dzZXJzIC0gQW4gT3BlblBHUCBpbXBsZW1lbnRhdGlvbiBpbiBqYXZhc2NyaXB0XG4vLyBDb3B5cmlnaHQgKEMpIDIwMTEgUmVjdXJpdHkgTGFicyBHbWJIXG4vLyBcbi8vIFRoaXMgbGlicmFyeSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3Jcbi8vIG1vZGlmeSBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBMZXNzZXIgR2VuZXJhbCBQdWJsaWNcbi8vIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5IHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlclxuLy8gdmVyc2lvbiAyLjEgb2YgdGhlIExpY2Vuc2UsIG9yIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4vLyBcbi8vIFRoaXMgbGlicmFyeSBpcyBkaXN0cmlidXRlZCBpbiB0aGUgaG9wZSB0aGF0IGl0IHdpbGwgYmUgdXNlZnVsLFxuLy8gYnV0IFdJVEhPVVQgQU5ZIFdBUlJBTlRZOyB3aXRob3V0IGV2ZW4gdGhlIGltcGxpZWQgd2FycmFudHkgb2Zcbi8vIE1FUkNIQU5UQUJJTElUWSBvciBGSVRORVNTIEZPUiBBIFBBUlRJQ1VMQVIgUFVSUE9TRS4gIFNlZSB0aGUgR05VXG4vLyBMZXNzZXIgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBmb3IgbW9yZSBkZXRhaWxzLlxuLy8gXG4vLyBZb3Ugc2hvdWxkIGhhdmUgcmVjZWl2ZWQgYSBjb3B5IG9mIHRoZSBHTlUgTGVzc2VyIEdlbmVyYWwgUHVibGljXG4vLyBMaWNlbnNlIGFsb25nIHdpdGggdGhpcyBsaWJyYXJ5OyBpZiBub3QsIHdyaXRlIHRvIHRoZSBGcmVlIFNvZnR3YXJlXG4vLyBGb3VuZGF0aW9uLCBJbmMuLCA1MSBGcmFua2xpbiBTdHJlZXQsIEZpZnRoIEZsb29yLCBCb3N0b24sIE1BICAwMjExMC0xMzAxICBVU0FcblxudmFyIHB1YmxpY19rZXkgPSByZXF1aXJlKCcuL3B1YmxpY19rZXkuanMnKTtcblxubW9kdWxlLmV4cG9ydHMgPSBmdW5jdGlvbiBwdWJsaWNfc3Via2V5KCkge1xuXHRwdWJsaWNfa2V5LmNhbGwodGhpcyk7XG59XG4iLCIvLyBHUEc0QnJvd3NlcnMgLSBBbiBPcGVuUEdQIGltcGxlbWVudGF0aW9uIGluIGphdmFzY3JpcHRcbi8vIENvcHlyaWdodCAoQykgMjAxMSBSZWN1cml0eSBMYWJzIEdtYkhcbi8vIFxuLy8gVGhpcyBsaWJyYXJ5IGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vclxuLy8gbW9kaWZ5IGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIExlc3NlciBHZW5lcmFsIFB1YmxpY1xuLy8gTGljZW5zZSBhcyBwdWJsaXNoZWQgYnkgdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyXG4vLyB2ZXJzaW9uIDIuMSBvZiB0aGUgTGljZW5zZSwgb3IgKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbi8vIFxuLy8gVGhpcyBsaWJyYXJ5IGlzIGRpc3RyaWJ1dGVkIGluIHRoZSBob3BlIHRoYXQgaXQgd2lsbCBiZSB1c2VmdWwsXG4vLyBidXQgV0lUSE9VVCBBTlkgV0FSUkFOVFk7IHdpdGhvdXQgZXZlbiB0aGUgaW1wbGllZCB3YXJyYW50eSBvZlxuLy8gTUVSQ0hBTlRBQklMSVRZIG9yIEZJVE5FU1MgRk9SIEEgUEFSVElDVUxBUiBQVVJQT1NFLiAgU2VlIHRoZSBHTlVcbi8vIExlc3NlciBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGZvciBtb3JlIGRldGFpbHMuXG4vLyBcbi8vIFlvdSBzaG91bGQgaGF2ZSByZWNlaXZlZCBhIGNvcHkgb2YgdGhlIEdOVSBMZXNzZXIgR2VuZXJhbCBQdWJsaWNcbi8vIExpY2Vuc2UgYWxvbmcgd2l0aCB0aGlzIGxpYnJhcnk7IGlmIG5vdCwgd3JpdGUgdG8gdGhlIEZyZWUgU29mdHdhcmVcbi8vIEZvdW5kYXRpb24sIEluYy4sIDUxIEZyYW5rbGluIFN0cmVldCwgRmlmdGggRmxvb3IsIEJvc3RvbiwgTUEgIDAyMTEwLTEzMDEgIFVTQVxuXG4vKipcbiAqIEBjbGFzc1xuICogQGNsYXNzZGVzYyBJbXBsZW1lbnRhdGlvbiBvZiB0aGUgT25lLVBhc3MgU2lnbmF0dXJlIFBhY2tldHMgKFRhZyA0KVxuICogXG4gKiBSRkM0ODgwIDUuNDpcbiAqIFRoZSBPbmUtUGFzcyBTaWduYXR1cmUgcGFja2V0IHByZWNlZGVzIHRoZSBzaWduZWQgZGF0YSBhbmQgY29udGFpbnNcbiAqIGVub3VnaCBpbmZvcm1hdGlvbiB0byBhbGxvdyB0aGUgcmVjZWl2ZXIgdG8gYmVnaW4gY2FsY3VsYXRpbmcgYW55XG4gKiBoYXNoZXMgbmVlZGVkIHRvIHZlcmlmeSB0aGUgc2lnbmF0dXJlLiAgSXQgYWxsb3dzIHRoZSBTaWduYXR1cmVcbiAqIHBhY2tldCB0byBiZSBwbGFjZWQgYXQgdGhlIGVuZCBvZiB0aGUgbWVzc2FnZSwgc28gdGhhdCB0aGUgc2lnbmVyXG4gKiBjYW4gY29tcHV0ZSB0aGUgZW50aXJlIHNpZ25lZCBtZXNzYWdlIGluIG9uZSBwYXNzLlxuICovXG5cbnZhciBlbnVtcyA9IHJlcXVpcmUoJy4uL2VudW1zLmpzJyk7XG5cbm1vZHVsZS5leHBvcnRzID0gZnVuY3Rpb24gcGFja2V0X29uZV9wYXNzX3NpZ25hdHVyZSgpIHtcblx0dGhpcy52ZXJzaW9uID0gbnVsbDsgLy8gQSBvbmUtb2N0ZXQgdmVyc2lvbiBudW1iZXIuICBUaGUgY3VycmVudCB2ZXJzaW9uIGlzIDMuXG5cdHRoaXMudHlwZSA9IG51bGw7IFx0IC8vIEEgb25lLW9jdGV0IHNpZ25hdHVyZSB0eXBlLiAgU2lnbmF0dXJlIHR5cGVzIGFyZSBkZXNjcmliZWQgaW4gUkZDNDg4MCBTZWN0aW9uIDUuMi4xLlxuXHR0aGlzLmhhc2hBbGdvcml0aG0gPSBudWxsOyBcdCAgIC8vIEEgb25lLW9jdGV0IG51bWJlciBkZXNjcmliaW5nIHRoZSBoYXNoIGFsZ29yaXRobSB1c2VkLiAoU2VlIFJGQzQ4ODAgOS40KVxuXHR0aGlzLnB1YmxpY0tleUFsZ29yaXRobSA9IG51bGw7XHQgICAgIC8vIEEgb25lLW9jdGV0IG51bWJlciBkZXNjcmliaW5nIHRoZSBwdWJsaWMta2V5IGFsZ29yaXRobSB1c2VkLiAoU2VlIFJGQzQ4ODAgOS4xKVxuXHR0aGlzLnNpZ25pbmdLZXlJZCA9IG51bGw7IC8vIEFuIGVpZ2h0LW9jdGV0IG51bWJlciBob2xkaW5nIHRoZSBLZXkgSUQgb2YgdGhlIHNpZ25pbmcga2V5LlxuXHR0aGlzLmZsYWdzID0gbnVsbDsgXHQvLyAgQSBvbmUtb2N0ZXQgbnVtYmVyIGhvbGRpbmcgYSBmbGFnIHNob3dpbmcgd2hldGhlciB0aGUgc2lnbmF0dXJlIGlzIG5lc3RlZC4gIEEgemVybyB2YWx1ZSBpbmRpY2F0ZXMgdGhhdCB0aGUgbmV4dCBwYWNrZXQgaXMgYW5vdGhlciBPbmUtUGFzcyBTaWduYXR1cmUgcGFja2V0IHRoYXQgZGVzY3JpYmVzIGFub3RoZXIgc2lnbmF0dXJlIHRvIGJlIGFwcGxpZWQgdG8gdGhlIHNhbWUgbWVzc2FnZSBkYXRhLlxuXG5cdC8qKlxuXHQgKiBwYXJzaW5nIGZ1bmN0aW9uIGZvciBhIG9uZS1wYXNzIHNpZ25hdHVyZSBwYWNrZXQgKHRhZyA0KS5cblx0ICogQHBhcmFtIHtTdHJpbmd9IGJ5dGVzIHBheWxvYWQgb2YgYSB0YWcgNCBwYWNrZXRcblx0ICogQHBhcmFtIHtJbnRlZ2VyfSBwb3NpdGlvbiBwb3NpdGlvbiB0byBzdGFydCByZWFkaW5nIGZyb20gdGhlIGJ5dGVzIHN0cmluZ1xuXHQgKiBAcGFyYW0ge0ludGVnZXJ9IGxlbiBsZW5ndGggb2YgdGhlIHBhY2tldCBvciB0aGUgcmVtYWluaW5nIGxlbmd0aCBvZiBieXRlcyBhdCBwb3NpdGlvblxuXHQgKiBAcmV0dXJuIHtvcGVucGdwX3BhY2tldF9lbmNyeXB0ZWRkYXRhfSBvYmplY3QgcmVwcmVzZW50YXRpb25cblx0ICovXG5cdHRoaXMucmVhZCA9IGZ1bmN0aW9uKGJ5dGVzKSB7XG5cdFx0dmFyIG15cG9zID0gMDtcblx0XHQvLyBBIG9uZS1vY3RldCB2ZXJzaW9uIG51bWJlci4gIFRoZSBjdXJyZW50IHZlcnNpb24gaXMgMy5cblx0XHR0aGlzLnZlcnNpb24gPSBieXRlcy5jaGFyQ29kZUF0KG15cG9zKyspO1xuXG5cdCAgICAgLy8gQSBvbmUtb2N0ZXQgc2lnbmF0dXJlIHR5cGUuICBTaWduYXR1cmUgdHlwZXMgYXJlIGRlc2NyaWJlZCBpblxuXHQgICAgIC8vICAgU2VjdGlvbiA1LjIuMS5cblx0XHR0aGlzLnR5cGUgPSBlbnVtcy5yZWFkKGVudW1zLnNpZ25hdHVyZSwgYnl0ZXMuY2hhckNvZGVBdChteXBvcysrKSk7XG5cblx0ICAgICAvLyBBIG9uZS1vY3RldCBudW1iZXIgZGVzY3JpYmluZyB0aGUgaGFzaCBhbGdvcml0aG0gdXNlZC5cblx0XHR0aGlzLmhhc2hBbGdvcml0aG0gPSBlbnVtcy5yZWFkKGVudW1zLmhhc2gsIGJ5dGVzLmNoYXJDb2RlQXQobXlwb3MrKykpO1xuXG5cdCAgICAgLy8gQSBvbmUtb2N0ZXQgbnVtYmVyIGRlc2NyaWJpbmcgdGhlIHB1YmxpYy1rZXkgYWxnb3JpdGhtIHVzZWQuXG5cdFx0dGhpcy5wdWJsaWNLZXlBbGdvcml0aG0gPSBlbnVtcy5yZWFkKGVudW1zLnB1YmxpY0tleSwgYnl0ZXMuY2hhckNvZGVBdChteXBvcysrKSk7XG5cblx0ICAgICAvLyBBbiBlaWdodC1vY3RldCBudW1iZXIgaG9sZGluZyB0aGUgS2V5IElEIG9mIHRoZSBzaWduaW5nIGtleS5cblx0XHR0aGlzLnNpZ25pbmdLZXlJZCA9IG5ldyBvcGVucGdwX3R5cGVfa2V5aWQoKTtcblx0XHR0aGlzLnNpZ25pbmdLZXlJZC5yZWFkX3BhY2tldChieXRlcyxteXBvcyk7XG5cdFx0bXlwb3MgKz0gODtcblx0XHRcblx0ICAgICAvLyBBIG9uZS1vY3RldCBudW1iZXIgaG9sZGluZyBhIGZsYWcgc2hvd2luZyB3aGV0aGVyIHRoZSBzaWduYXR1cmVcblx0ICAgICAvLyAgIGlzIG5lc3RlZC4gIEEgemVybyB2YWx1ZSBpbmRpY2F0ZXMgdGhhdCB0aGUgbmV4dCBwYWNrZXQgaXNcblx0ICAgICAvLyAgIGFub3RoZXIgT25lLVBhc3MgU2lnbmF0dXJlIHBhY2tldCB0aGF0IGRlc2NyaWJlcyBhbm90aGVyXG5cdCAgICAgLy8gICBzaWduYXR1cmUgdG8gYmUgYXBwbGllZCB0byB0aGUgc2FtZSBtZXNzYWdlIGRhdGEuXG5cdFx0dGhpcy5mbGFncyA9IGJ5dGVzLmNoYXJDb2RlQXQobXlwb3MrKyk7XG5cdFx0cmV0dXJuIHRoaXM7XG5cdH1cblxuXHQvKipcblx0ICogY3JlYXRlcyBhIHN0cmluZyByZXByZXNlbnRhdGlvbiBvZiBhIG9uZS1wYXNzIHNpZ25hdHVyZSBwYWNrZXRcblx0ICogQHBhcmFtIHtJbnRlZ2VyfSB0eXBlIFNpZ25hdHVyZSB0eXBlcyBhcyBkZXNjcmliZWQgaW4gUkZDNDg4MCBTZWN0aW9uIDUuMi4xLlxuXHQgKiBAcGFyYW0ge0ludGVnZXJ9IGhhc2hhbGdvcml0aG0gdGhlIGhhc2ggYWxnb3JpdGhtIHVzZWQgd2l0aGluIHRoZSBzaWduYXR1cmVcblx0ICogQHBhcmFtIHtvcGVucGdwX21zZ19wcml2YXRla2V5fSBwcml2YXRla2V5IHRoZSBwcml2YXRlIGtleSB1c2VkIHRvIGdlbmVyYXRlIHRoZSBzaWduYXR1cmVcblx0ICogQHBhcmFtIHtJbnRlZ2VyfSBsZW5ndGggbGVuZ3RoIG9mIGRhdGEgdG8gYmUgc2lnbmVkXG5cdCAqIEBwYXJhbSB7Ym9vbGVhbn0gbmVzdGVkIGJvb2xlYW4gc2hvd2luZyB3aGV0aGVyIHRoZSBzaWduYXR1cmUgaXMgbmVzdGVkLiBcblx0ICogIFwidHJ1ZVwiIGluZGljYXRlcyB0aGF0IHRoZSBuZXh0IHBhY2tldCBpcyBhbm90aGVyIE9uZS1QYXNzIFNpZ25hdHVyZSBwYWNrZXRcblx0ICogICB0aGF0IGRlc2NyaWJlcyBhbm90aGVyIHNpZ25hdHVyZSB0byBiZSBhcHBsaWVkIHRvIHRoZSBzYW1lIG1lc3NhZ2UgZGF0YS4gXG5cdCAqIEByZXR1cm4ge1N0cmluZ30gYSBzdHJpbmcgcmVwcmVzZW50YXRpb24gb2YgYSBvbmUtcGFzcyBzaWduYXR1cmUgcGFja2V0XG5cdCAqL1xuXHR0aGlzLndyaXRlID0gZnVuY3Rpb24odHlwZSwgaGFzaGFsZ29yaXRobSwgcHJpdmF0ZWtleSwgbGVuZ3RoLCBuZXN0ZWQpIHtcblx0XHR2YXIgcmVzdWx0ID1cIlwiOyBcblx0XHRcblx0XHRyZXN1bHQgKz0gU3RyaW5nLmZyb21DaGFyQ29kZSgzKTtcblx0XHRyZXN1bHQgKz0gU3RyaW5nLmZyb21DaGFyQ29kZShlbnVtcy53cml0ZShlbnVtcy5zaWduYXR1cmUsIHR5cGUpKTtcblx0XHRyZXN1bHQgKz0gU3RyaW5nLmZyb21DaGFyQ29kZShlbnVtcy53cml0ZShlbnVtcy5oYXNoLCB0aGlzLmhhc2hBbGdvcml0aG0pKTtcblx0XHRyZXN1bHQgKz0gU3RyaW5nLmZyb21DaGFyQ29kZShlbnVtcy53cml0ZShlbnVtcy5wdWJsaWNLZXksIHByaXZhdGVrZXkuYWxnb3JpdGhtKSk7XG5cdFx0cmVzdWx0ICs9IHByaXZhdGVrZXkuZ2V0S2V5SWQoKTtcblx0XHRpZiAobmVzdGVkKVxuXHRcdFx0cmVzdWx0ICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoMCk7XG5cdFx0ZWxzZVxuXHRcdFx0cmVzdWx0ICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoMSk7XG5cdFx0XG5cdFx0cmV0dXJuIHJlc3VsdDtcblx0fVxufTtcbiIsIi8vIEdQRzRCcm93c2VycyAtIEFuIE9wZW5QR1AgaW1wbGVtZW50YXRpb24gaW4gamF2YXNjcmlwdFxuLy8gQ29weXJpZ2h0IChDKSAyMDExIFJlY3VyaXR5IExhYnMgR21iSFxuLy8gXG4vLyBUaGlzIGxpYnJhcnkgaXMgZnJlZSBzb2Z0d2FyZTsgeW91IGNhbiByZWRpc3RyaWJ1dGUgaXQgYW5kL29yXG4vLyBtb2RpZnkgaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgTGVzc2VyIEdlbmVyYWwgUHVibGljXG4vLyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieSB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uOyBlaXRoZXJcbi8vIHZlcnNpb24gMi4xIG9mIHRoZSBMaWNlbnNlLCBvciAoYXQgeW91ciBvcHRpb24pIGFueSBsYXRlciB2ZXJzaW9uLlxuLy8gXG4vLyBUaGlzIGxpYnJhcnkgaXMgZGlzdHJpYnV0ZWQgaW4gdGhlIGhvcGUgdGhhdCBpdCB3aWxsIGJlIHVzZWZ1bCxcbi8vIGJ1dCBXSVRIT1VUIEFOWSBXQVJSQU5UWTsgd2l0aG91dCBldmVuIHRoZSBpbXBsaWVkIHdhcnJhbnR5IG9mXG4vLyBNRVJDSEFOVEFCSUxJVFkgb3IgRklUTkVTUyBGT1IgQSBQQVJUSUNVTEFSIFBVUlBPU0UuICBTZWUgdGhlIEdOVVxuLy8gTGVzc2VyIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgZm9yIG1vcmUgZGV0YWlscy5cbi8vIFxuLy8gWW91IHNob3VsZCBoYXZlIHJlY2VpdmVkIGEgY29weSBvZiB0aGUgR05VIExlc3NlciBHZW5lcmFsIFB1YmxpY1xuLy8gTGljZW5zZSBhbG9uZyB3aXRoIHRoaXMgbGlicmFyeTsgaWYgbm90LCB3cml0ZSB0byB0aGUgRnJlZSBTb2Z0d2FyZVxuLy8gRm91bmRhdGlvbiwgSW5jLiwgNTEgRnJhbmtsaW4gU3RyZWV0LCBGaWZ0aCBGbG9vciwgQm9zdG9uLCBNQSAgMDIxMTAtMTMwMSAgVVNBXG5cbnZhciBzZWNyZXRfa2V5ID0gcmVxdWlyZSgnLi9zZWNyZXRfa2V5LmpzJyk7XG5cbm1vZHVsZS5leHBvcnRzID0gZnVuY3Rpb24gc2VjcmV0X3N1YmtleSgpIHtcblx0c2VjcmV0X2tleS5jYWxsKHRoaXMpO1xufVxuIiwiLyogQSBKYXZhU2NyaXB0IGltcGxlbWVudGF0aW9uIG9mIHRoZSBTSEEgZmFtaWx5IG9mIGhhc2hlcywgYXMgZGVmaW5lZCBpbiBGSVBTIFxuICogUFVCIDE4MC0yIGFzIHdlbGwgYXMgdGhlIGNvcnJlc3BvbmRpbmcgSE1BQyBpbXBsZW1lbnRhdGlvbiBhcyBkZWZpbmVkIGluXG4gKiBGSVBTIFBVQiAxOThhXG4gKlxuICogVmVyc2lvbiAxLjMgQ29weXJpZ2h0IEJyaWFuIFR1cmVrIDIwMDgtMjAxMFxuICogRGlzdHJpYnV0ZWQgdW5kZXIgdGhlIEJTRCBMaWNlbnNlXG4gKiBTZWUgaHR0cDovL2pzc2hhLnNvdXJjZWZvcmdlLm5ldC8gZm9yIG1vcmUgaW5mb3JtYXRpb25cbiAqXG4gKiBTZXZlcmFsIGZ1bmN0aW9ucyB0YWtlbiBmcm9tIFBhdWwgSm9obnNvblxuICovXG5cbi8qIE1vZGlmaWVkIGJ5IFJlY3VyaXR5IExhYnMgR21iSFxuICogXG4gKiBUaGlzIGNvZGUgaGFzIGJlZW4gc2xpZ2h0bHkgbW9kaWZpZWQgZGlyZWN0IHN0cmluZyBvdXRwdXQ6XG4gKiAtIGJpbjJic3RyIGhhcyBiZWVuIGFkZGVkXG4gKiAtIGZvbGxvd2luZyB3cmFwcGVycyBvZiB0aGlzIGxpYnJhcnkgaGF2ZSBiZWVuIGFkZGVkOlxuICogICAtIHN0cl9zaGExXG4gKiAgIC0gc3RyX3NoYTI1NlxuICogICAtIHN0cl9zaGEyMjRcbiAqICAgLSBzdHJfc2hhMzg0XG4gKiAgIC0gc3RyX3NoYTUxMlxuICovXG5cbnZhciBqc1NIQSA9IChmdW5jdGlvbiAoKSB7XG5cdFxuXHQvKlxuXHQgKiBDb25maWd1cmFibGUgdmFyaWFibGVzLiBEZWZhdWx0cyB0eXBpY2FsbHkgd29ya1xuXHQgKi9cblx0LyogTnVtYmVyIG9mIEJpdHMgUGVyIGNoYXJhY3RlciAoOCBmb3IgQVNDSUksIDE2IGZvciBVbmljb2RlKSAqL1xuXHR2YXIgY2hhclNpemUgPSA4LCBcblx0LyogYmFzZS02NCBwYWQgY2hhcmFjdGVyLiBcIj1cIiBmb3Igc3RyaWN0IFJGQyBjb21wbGlhbmNlICovXG5cdGI2NHBhZCA9IFwiXCIsIFxuXHQvKiBoZXggb3V0cHV0IGZvcm1hdC4gMCAtIGxvd2VyY2FzZTsgMSAtIHVwcGVyY2FzZSAqL1xuXHRoZXhDYXNlID0gMCwgXG5cblx0Lypcblx0ICogSW50XzY0IGlzIGEgb2JqZWN0IGZvciAyIDMyLWJpdCBudW1iZXJzIGVtdWxhdGluZyBhIDY0LWJpdCBudW1iZXJcblx0ICpcblx0ICogQGNvbnN0cnVjdG9yXG5cdCAqIEBwYXJhbSB7TnVtYmVyfSBtc2ludF8zMiBUaGUgbW9zdCBzaWduaWZpY2FudCAzMi1iaXRzIG9mIGEgNjQtYml0IG51bWJlclxuXHQgKiBAcGFyYW0ge051bWJlcn0gbHNpbnRfMzIgVGhlIGxlYXN0IHNpZ25pZmljYW50IDMyLWJpdHMgb2YgYSA2NC1iaXQgbnVtYmVyXG5cdCAqL1xuXHRJbnRfNjQgPSBmdW5jdGlvbiAobXNpbnRfMzIsIGxzaW50XzMyKVxuXHR7XG5cdFx0dGhpcy5oaWdoT3JkZXIgPSBtc2ludF8zMjtcblx0XHR0aGlzLmxvd09yZGVyID0gbHNpbnRfMzI7XG5cdH0sXG5cblx0Lypcblx0ICogQ29udmVydCBhIHN0cmluZyB0byBhbiBhcnJheSBvZiBiaWctZW5kaWFuIHdvcmRzXG5cdCAqIElmIGNoYXJTaXplIGlzIEFTQ0lJLCBjaGFyYWN0ZXJzID4yNTUgaGF2ZSB0aGVpciBoaS1ieXRlIHNpbGVudGx5XG5cdCAqIGlnbm9yZWQuXG5cdCAqXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBzdHIgU3RyaW5nIHRvIGJlIGNvbnZlcnRlZCB0byBiaW5hcnkgcmVwcmVzZW50YXRpb25cblx0ICogQHJldHVybiBJbnRlZ2VyIGFycmF5IHJlcHJlc2VudGF0aW9uIG9mIHRoZSBwYXJhbWV0ZXJcblx0ICovXG5cdHN0cjJiaW5iID0gZnVuY3Rpb24gKHN0cilcblx0e1xuXHRcdHZhciBiaW4gPSBbXSwgbWFzayA9ICgxIDw8IGNoYXJTaXplKSAtIDEsXG5cdFx0XHRsZW5ndGggPSBzdHIubGVuZ3RoICogY2hhclNpemUsIGk7XG5cblx0XHRmb3IgKGkgPSAwOyBpIDwgbGVuZ3RoOyBpICs9IGNoYXJTaXplKVxuXHRcdHtcblx0XHRcdGJpbltpID4+IDVdIHw9IChzdHIuY2hhckNvZGVBdChpIC8gY2hhclNpemUpICYgbWFzaykgPDxcblx0XHRcdFx0KDMyIC0gY2hhclNpemUgLSAoaSAlIDMyKSk7XG5cdFx0fVxuXG5cdFx0cmV0dXJuIGJpbjtcblx0fSxcblxuXHQvKlxuXHQgKiBDb252ZXJ0IGEgaGV4IHN0cmluZyB0byBhbiBhcnJheSBvZiBiaWctZW5kaWFuIHdvcmRzXG5cdCAqXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBzdHIgU3RyaW5nIHRvIGJlIGNvbnZlcnRlZCB0byBiaW5hcnkgcmVwcmVzZW50YXRpb25cblx0ICogQHJldHVybiBJbnRlZ2VyIGFycmF5IHJlcHJlc2VudGF0aW9uIG9mIHRoZSBwYXJhbWV0ZXJcblx0ICovXG5cdGhleDJiaW5iID0gZnVuY3Rpb24gKHN0cilcblx0e1xuXHRcdHZhciBiaW4gPSBbXSwgbGVuZ3RoID0gc3RyLmxlbmd0aCwgaSwgbnVtO1xuXG5cdFx0Zm9yIChpID0gMDsgaSA8IGxlbmd0aDsgaSArPSAyKVxuXHRcdHtcblx0XHRcdG51bSA9IHBhcnNlSW50KHN0ci5zdWJzdHIoaSwgMiksIDE2KTtcblx0XHRcdGlmICghaXNOYU4obnVtKSlcblx0XHRcdHtcblx0XHRcdFx0YmluW2kgPj4gM10gfD0gbnVtIDw8ICgyNCAtICg0ICogKGkgJSA4KSkpO1xuXHRcdFx0fVxuXHRcdFx0ZWxzZVxuXHRcdFx0e1xuXHRcdFx0XHRyZXR1cm4gXCJJTlZBTElEIEhFWCBTVFJJTkdcIjtcblx0XHRcdH1cblx0XHR9XG5cblx0XHRyZXR1cm4gYmluO1xuXHR9LFxuXG5cdC8qXG5cdCAqIENvbnZlcnQgYW4gYXJyYXkgb2YgYmlnLWVuZGlhbiB3b3JkcyB0byBhIGhleCBzdHJpbmcuXG5cdCAqXG5cdCAqIEBwcml2YXRlXG5cdCAqIEBwYXJhbSB7QXJyYXl9IGJpbmFycmF5IEFycmF5IG9mIGludGVnZXJzIHRvIGJlIGNvbnZlcnRlZCB0byBoZXhpZGVjaW1hbFxuXHQgKlx0IHJlcHJlc2VudGF0aW9uXG5cdCAqIEByZXR1cm4gSGV4aWRlY2ltYWwgcmVwcmVzZW50YXRpb24gb2YgdGhlIHBhcmFtZXRlciBpbiBTdHJpbmcgZm9ybVxuXHQgKi9cblx0YmluYjJoZXggPSBmdW5jdGlvbiAoYmluYXJyYXkpXG5cdHtcblx0XHR2YXIgaGV4X3RhYiA9IChoZXhDYXNlKSA/IFwiMDEyMzQ1Njc4OUFCQ0RFRlwiIDogXCIwMTIzNDU2Nzg5YWJjZGVmXCIsXG5cdFx0XHRzdHIgPSBcIlwiLCBsZW5ndGggPSBiaW5hcnJheS5sZW5ndGggKiA0LCBpLCBzcmNCeXRlO1xuXG5cdFx0Zm9yIChpID0gMDsgaSA8IGxlbmd0aDsgaSArPSAxKVxuXHRcdHtcblx0XHRcdHNyY0J5dGUgPSBiaW5hcnJheVtpID4+IDJdID4+ICgoMyAtIChpICUgNCkpICogOCk7XG5cdFx0XHRzdHIgKz0gaGV4X3RhYi5jaGFyQXQoKHNyY0J5dGUgPj4gNCkgJiAweEYpICtcblx0XHRcdFx0aGV4X3RhYi5jaGFyQXQoc3JjQnl0ZSAmIDB4Rik7XG5cdFx0fVxuXG5cdFx0cmV0dXJuIHN0cjtcblx0fSxcblxuXHQvKlxuXHQgKiBDb252ZXJ0IGFuIGFycmF5IG9mIGJpZy1lbmRpYW4gd29yZHMgdG8gYSBiYXNlLTY0IHN0cmluZ1xuXHQgKlxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge0FycmF5fSBiaW5hcnJheSBBcnJheSBvZiBpbnRlZ2VycyB0byBiZSBjb252ZXJ0ZWQgdG8gYmFzZS02NFxuXHQgKlx0IHJlcHJlc2VudGF0aW9uXG5cdCAqIEByZXR1cm4gQmFzZS02NCBlbmNvZGVkIHJlcHJlc2VudGF0aW9uIG9mIHRoZSBwYXJhbWV0ZXIgaW4gU3RyaW5nIGZvcm1cblx0ICovXG5cdGJpbmIyYjY0ID0gZnVuY3Rpb24gKGJpbmFycmF5KVxuXHR7XG5cdFx0dmFyIHRhYiA9IFwiQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5elwiICtcblx0XHRcdFwiMDEyMzQ1Njc4OSsvXCIsIHN0ciA9IFwiXCIsIGxlbmd0aCA9IGJpbmFycmF5Lmxlbmd0aCAqIDQsIGksIGosXG5cdFx0XHR0cmlwbGV0O1xuXG5cdFx0Zm9yIChpID0gMDsgaSA8IGxlbmd0aDsgaSArPSAzKVxuXHRcdHtcblx0XHRcdHRyaXBsZXQgPSAoKChiaW5hcnJheVtpID4+IDJdID4+IDggKiAoMyAtIGkgJSA0KSkgJiAweEZGKSA8PCAxNikgfFxuXHRcdFx0XHQoKChiaW5hcnJheVtpICsgMSA+PiAyXSA+PiA4ICogKDMgLSAoaSArIDEpICUgNCkpICYgMHhGRikgPDwgOCkgfFxuXHRcdFx0XHQoKGJpbmFycmF5W2kgKyAyID4+IDJdID4+IDggKiAoMyAtIChpICsgMikgJSA0KSkgJiAweEZGKTtcblx0XHRcdGZvciAoaiA9IDA7IGogPCA0OyBqICs9IDEpXG5cdFx0XHR7XG5cdFx0XHRcdGlmIChpICogOCArIGogKiA2IDw9IGJpbmFycmF5Lmxlbmd0aCAqIDMyKVxuXHRcdFx0XHR7XG5cdFx0XHRcdFx0c3RyICs9IHRhYi5jaGFyQXQoKHRyaXBsZXQgPj4gNiAqICgzIC0gaikpICYgMHgzRik7XG5cdFx0XHRcdH1cblx0XHRcdFx0ZWxzZVxuXHRcdFx0XHR7XG5cdFx0XHRcdFx0c3RyICs9IGI2NHBhZDtcblx0XHRcdFx0fVxuXHRcdFx0fVxuXHRcdH1cblx0XHRyZXR1cm4gc3RyO1xuXHR9LFxuXG5cdC8qXG5cdCAqIENvbnZlcnQgYW4gYXJyYXkgb2YgYmlnLWVuZGlhbiB3b3JkcyB0byBhIHN0cmluZ1xuXHQgKi9cblx0YmluYjJzdHIgPSBmdW5jdGlvbiAoYmluKVxuXHR7XG5cdCAgdmFyIHN0ciA9IFwiXCI7XG5cdCAgdmFyIG1hc2sgPSAoMSA8PCA4KSAtIDE7XG5cdCAgZm9yKHZhciBpID0gMDsgaSA8IGJpbi5sZW5ndGggKiAzMjsgaSArPSA4KVxuXHQgICAgc3RyICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoKGJpbltpPj41XSA+Pj4gKDI0IC0gaSUzMikpICYgbWFzayk7XG5cdCAgcmV0dXJuIHN0cjtcblx0fSxcblx0Lypcblx0ICogVGhlIDMyLWJpdCBpbXBsZW1lbnRhdGlvbiBvZiBjaXJjdWxhciByb3RhdGUgbGVmdFxuXHQgKlxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge051bWJlcn0geCBUaGUgMzItYml0IGludGVnZXIgYXJndW1lbnRcblx0ICogQHBhcmFtIHtOdW1iZXJ9IG4gVGhlIG51bWJlciBvZiBiaXRzIHRvIHNoaWZ0XG5cdCAqIEByZXR1cm4gVGhlIHggc2hpZnRlZCBjaXJjdWxhcmx5IGJ5IG4gYml0c1xuXHQgKi9cblx0cm90bF8zMiA9IGZ1bmN0aW9uICh4LCBuKVxuXHR7XG5cdFx0cmV0dXJuICh4IDw8IG4pIHwgKHggPj4+ICgzMiAtIG4pKTtcblx0fSxcblxuXHQvKlxuXHQgKiBUaGUgMzItYml0IGltcGxlbWVudGF0aW9uIG9mIGNpcmN1bGFyIHJvdGF0ZSByaWdodFxuXHQgKlxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge051bWJlcn0geCBUaGUgMzItYml0IGludGVnZXIgYXJndW1lbnRcblx0ICogQHBhcmFtIHtOdW1iZXJ9IG4gVGhlIG51bWJlciBvZiBiaXRzIHRvIHNoaWZ0XG5cdCAqIEByZXR1cm4gVGhlIHggc2hpZnRlZCBjaXJjdWxhcmx5IGJ5IG4gYml0c1xuXHQgKi9cblx0cm90cl8zMiA9IGZ1bmN0aW9uICh4LCBuKVxuXHR7XG5cdFx0cmV0dXJuICh4ID4+PiBuKSB8ICh4IDw8ICgzMiAtIG4pKTtcblx0fSxcblxuXHQvKlxuXHQgKiBUaGUgNjQtYml0IGltcGxlbWVudGF0aW9uIG9mIGNpcmN1bGFyIHJvdGF0ZSByaWdodFxuXHQgKlxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge0ludF82NH0geCBUaGUgNjQtYml0IGludGVnZXIgYXJndW1lbnRcblx0ICogQHBhcmFtIHtOdW1iZXJ9IG4gVGhlIG51bWJlciBvZiBiaXRzIHRvIHNoaWZ0XG5cdCAqIEByZXR1cm4gVGhlIHggc2hpZnRlZCBjaXJjdWxhcmx5IGJ5IG4gYml0c1xuXHQgKi9cblx0cm90cl82NCA9IGZ1bmN0aW9uICh4LCBuKVxuXHR7XG5cdFx0aWYgKG4gPD0gMzIpXG5cdFx0e1xuXHRcdFx0cmV0dXJuIG5ldyBJbnRfNjQoXG5cdFx0XHRcdFx0KHguaGlnaE9yZGVyID4+PiBuKSB8ICh4Lmxvd09yZGVyIDw8ICgzMiAtIG4pKSxcblx0XHRcdFx0XHQoeC5sb3dPcmRlciA+Pj4gbikgfCAoeC5oaWdoT3JkZXIgPDwgKDMyIC0gbikpXG5cdFx0XHRcdCk7XG5cdFx0fVxuXHRcdGVsc2Vcblx0XHR7XG5cdFx0XHRyZXR1cm4gbmV3IEludF82NChcblx0XHRcdFx0XHQoeC5sb3dPcmRlciA+Pj4gbikgfCAoeC5oaWdoT3JkZXIgPDwgKDMyIC0gbikpLFxuXHRcdFx0XHRcdCh4LmhpZ2hPcmRlciA+Pj4gbikgfCAoeC5sb3dPcmRlciA8PCAoMzIgLSBuKSlcblx0XHRcdFx0KTtcblx0XHR9XG5cdH0sXG5cblx0Lypcblx0ICogVGhlIDMyLWJpdCBpbXBsZW1lbnRhdGlvbiBvZiBzaGlmdCByaWdodFxuXHQgKlxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge051bWJlcn0geCBUaGUgMzItYml0IGludGVnZXIgYXJndW1lbnRcblx0ICogQHBhcmFtIHtOdW1iZXJ9IG4gVGhlIG51bWJlciBvZiBiaXRzIHRvIHNoaWZ0XG5cdCAqIEByZXR1cm4gVGhlIHggc2hpZnRlZCBieSBuIGJpdHNcblx0ICovXG5cdHNocl8zMiA9IGZ1bmN0aW9uICh4LCBuKVxuXHR7XG5cdFx0cmV0dXJuIHggPj4+IG47XG5cdH0sXG5cblx0Lypcblx0ICogVGhlIDY0LWJpdCBpbXBsZW1lbnRhdGlvbiBvZiBzaGlmdCByaWdodFxuXHQgKlxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge0ludF82NH0geCBUaGUgNjQtYml0IGludGVnZXIgYXJndW1lbnRcblx0ICogQHBhcmFtIHtOdW1iZXJ9IG4gVGhlIG51bWJlciBvZiBiaXRzIHRvIHNoaWZ0XG5cdCAqIEByZXR1cm4gVGhlIHggc2hpZnRlZCBieSBuIGJpdHNcblx0ICovXG5cdHNocl82NCA9IGZ1bmN0aW9uICh4LCBuKVxuXHR7XG5cdFx0aWYgKG4gPD0gMzIpXG5cdFx0e1xuXHRcdFx0cmV0dXJuIG5ldyBJbnRfNjQoXG5cdFx0XHRcdFx0eC5oaWdoT3JkZXIgPj4+IG4sXG5cdFx0XHRcdFx0eC5sb3dPcmRlciA+Pj4gbiB8ICh4LmhpZ2hPcmRlciA8PCAoMzIgLSBuKSlcblx0XHRcdFx0KTtcblx0XHR9XG5cdFx0ZWxzZVxuXHRcdHtcblx0XHRcdHJldHVybiBuZXcgSW50XzY0KFxuXHRcdFx0XHRcdDAsXG5cdFx0XHRcdFx0eC5oaWdoT3JkZXIgPDwgKDMyIC0gbilcblx0XHRcdFx0KTtcblx0XHR9XG5cdH0sXG5cblx0Lypcblx0ICogVGhlIDMyLWJpdCBpbXBsZW1lbnRhdGlvbiBvZiB0aGUgTklTVCBzcGVjaWZpZWQgUGFyaXR5IGZ1bmN0aW9uXG5cdCAqXG5cdCAqIEBwcml2YXRlXG5cdCAqIEBwYXJhbSB7TnVtYmVyfSB4IFRoZSBmaXJzdCAzMi1iaXQgaW50ZWdlciBhcmd1bWVudFxuXHQgKiBAcGFyYW0ge051bWJlcn0geSBUaGUgc2Vjb25kIDMyLWJpdCBpbnRlZ2VyIGFyZ3VtZW50XG5cdCAqIEBwYXJhbSB7TnVtYmVyfSB6IFRoZSB0aGlyZCAzMi1iaXQgaW50ZWdlciBhcmd1bWVudFxuXHQgKiBAcmV0dXJuIFRoZSBOSVNUIHNwZWNpZmllZCBvdXRwdXQgb2YgdGhlIGZ1bmN0aW9uXG5cdCAqL1xuXHRwYXJpdHlfMzIgPSBmdW5jdGlvbiAoeCwgeSwgeilcblx0e1xuXHRcdHJldHVybiB4IF4geSBeIHo7XG5cdH0sXG5cblx0Lypcblx0ICogVGhlIDMyLWJpdCBpbXBsZW1lbnRhdGlvbiBvZiB0aGUgTklTVCBzcGVjaWZpZWQgQ2ggZnVuY3Rpb25cblx0ICpcblx0ICogQHByaXZhdGVcblx0ICogQHBhcmFtIHtOdW1iZXJ9IHggVGhlIGZpcnN0IDMyLWJpdCBpbnRlZ2VyIGFyZ3VtZW50XG5cdCAqIEBwYXJhbSB7TnVtYmVyfSB5IFRoZSBzZWNvbmQgMzItYml0IGludGVnZXIgYXJndW1lbnRcblx0ICogQHBhcmFtIHtOdW1iZXJ9IHogVGhlIHRoaXJkIDMyLWJpdCBpbnRlZ2VyIGFyZ3VtZW50XG5cdCAqIEByZXR1cm4gVGhlIE5JU1Qgc3BlY2lmaWVkIG91dHB1dCBvZiB0aGUgZnVuY3Rpb25cblx0ICovXG5cdGNoXzMyID0gZnVuY3Rpb24gKHgsIHksIHopXG5cdHtcblx0XHRyZXR1cm4gKHggJiB5KSBeICh+eCAmIHopO1xuXHR9LFxuXG5cdC8qXG5cdCAqIFRoZSA2NC1iaXQgaW1wbGVtZW50YXRpb24gb2YgdGhlIE5JU1Qgc3BlY2lmaWVkIENoIGZ1bmN0aW9uXG5cdCAqXG5cdCAqIEBwcml2YXRlXG5cdCAqIEBwYXJhbSB7SW50XzY0fSB4IFRoZSBmaXJzdCA2NC1iaXQgaW50ZWdlciBhcmd1bWVudFxuXHQgKiBAcGFyYW0ge0ludF82NH0geSBUaGUgc2Vjb25kIDY0LWJpdCBpbnRlZ2VyIGFyZ3VtZW50XG5cdCAqIEBwYXJhbSB7SW50XzY0fSB6IFRoZSB0aGlyZCA2NC1iaXQgaW50ZWdlciBhcmd1bWVudFxuXHQgKiBAcmV0dXJuIFRoZSBOSVNUIHNwZWNpZmllZCBvdXRwdXQgb2YgdGhlIGZ1bmN0aW9uXG5cdCAqL1xuXHRjaF82NCA9IGZ1bmN0aW9uICh4LCB5LCB6KVxuXHR7XG5cdFx0cmV0dXJuIG5ldyBJbnRfNjQoXG5cdFx0XHRcdCh4LmhpZ2hPcmRlciAmIHkuaGlnaE9yZGVyKSBeICh+eC5oaWdoT3JkZXIgJiB6LmhpZ2hPcmRlciksXG5cdFx0XHRcdCh4Lmxvd09yZGVyICYgeS5sb3dPcmRlcikgXiAofngubG93T3JkZXIgJiB6Lmxvd09yZGVyKVxuXHRcdFx0KTtcblx0fSxcblxuXHQvKlxuXHQgKiBUaGUgMzItYml0IGltcGxlbWVudGF0aW9uIG9mIHRoZSBOSVNUIHNwZWNpZmllZCBNYWogZnVuY3Rpb25cblx0ICpcblx0ICogQHByaXZhdGVcblx0ICogQHBhcmFtIHtOdW1iZXJ9IHggVGhlIGZpcnN0IDMyLWJpdCBpbnRlZ2VyIGFyZ3VtZW50XG5cdCAqIEBwYXJhbSB7TnVtYmVyfSB5IFRoZSBzZWNvbmQgMzItYml0IGludGVnZXIgYXJndW1lbnRcblx0ICogQHBhcmFtIHtOdW1iZXJ9IHogVGhlIHRoaXJkIDMyLWJpdCBpbnRlZ2VyIGFyZ3VtZW50XG5cdCAqIEByZXR1cm4gVGhlIE5JU1Qgc3BlY2lmaWVkIG91dHB1dCBvZiB0aGUgZnVuY3Rpb25cblx0ICovXG5cdG1hal8zMiA9IGZ1bmN0aW9uICh4LCB5LCB6KVxuXHR7XG5cdFx0cmV0dXJuICh4ICYgeSkgXiAoeCAmIHopIF4gKHkgJiB6KTtcblx0fSxcblxuXHQvKlxuXHQgKiBUaGUgNjQtYml0IGltcGxlbWVudGF0aW9uIG9mIHRoZSBOSVNUIHNwZWNpZmllZCBNYWogZnVuY3Rpb25cblx0ICpcblx0ICogQHByaXZhdGVcblx0ICogQHBhcmFtIHtJbnRfNjR9IHggVGhlIGZpcnN0IDY0LWJpdCBpbnRlZ2VyIGFyZ3VtZW50XG5cdCAqIEBwYXJhbSB7SW50XzY0fSB5IFRoZSBzZWNvbmQgNjQtYml0IGludGVnZXIgYXJndW1lbnRcblx0ICogQHBhcmFtIHtJbnRfNjR9IHogVGhlIHRoaXJkIDY0LWJpdCBpbnRlZ2VyIGFyZ3VtZW50XG5cdCAqIEByZXR1cm4gVGhlIE5JU1Qgc3BlY2lmaWVkIG91dHB1dCBvZiB0aGUgZnVuY3Rpb25cblx0ICovXG5cdG1hal82NCA9IGZ1bmN0aW9uICh4LCB5LCB6KVxuXHR7XG5cdFx0cmV0dXJuIG5ldyBJbnRfNjQoXG5cdFx0XHRcdCh4LmhpZ2hPcmRlciAmIHkuaGlnaE9yZGVyKSBeXG5cdFx0XHRcdCh4LmhpZ2hPcmRlciAmIHouaGlnaE9yZGVyKSBeXG5cdFx0XHRcdCh5LmhpZ2hPcmRlciAmIHouaGlnaE9yZGVyKSxcblx0XHRcdFx0KHgubG93T3JkZXIgJiB5Lmxvd09yZGVyKSBeXG5cdFx0XHRcdCh4Lmxvd09yZGVyICYgei5sb3dPcmRlcikgXlxuXHRcdFx0XHQoeS5sb3dPcmRlciAmIHoubG93T3JkZXIpXG5cdFx0XHQpO1xuXHR9LFxuXG5cdC8qXG5cdCAqIFRoZSAzMi1iaXQgaW1wbGVtZW50YXRpb24gb2YgdGhlIE5JU1Qgc3BlY2lmaWVkIFNpZ21hMCBmdW5jdGlvblxuXHQgKlxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge051bWJlcn0geCBUaGUgMzItYml0IGludGVnZXIgYXJndW1lbnRcblx0ICogQHJldHVybiBUaGUgTklTVCBzcGVjaWZpZWQgb3V0cHV0IG9mIHRoZSBmdW5jdGlvblxuXHQgKi9cblx0c2lnbWEwXzMyID0gZnVuY3Rpb24gKHgpXG5cdHtcblx0XHRyZXR1cm4gcm90cl8zMih4LCAyKSBeIHJvdHJfMzIoeCwgMTMpIF4gcm90cl8zMih4LCAyMik7XG5cdH0sXG5cblx0Lypcblx0ICogVGhlIDY0LWJpdCBpbXBsZW1lbnRhdGlvbiBvZiB0aGUgTklTVCBzcGVjaWZpZWQgU2lnbWEwIGZ1bmN0aW9uXG5cdCAqXG5cdCAqIEBwcml2YXRlXG5cdCAqIEBwYXJhbSB7SW50XzY0fSB4IFRoZSA2NC1iaXQgaW50ZWdlciBhcmd1bWVudFxuXHQgKiBAcmV0dXJuIFRoZSBOSVNUIHNwZWNpZmllZCBvdXRwdXQgb2YgdGhlIGZ1bmN0aW9uXG5cdCAqL1xuXHRzaWdtYTBfNjQgPSBmdW5jdGlvbiAoeClcblx0e1xuXHRcdHZhciByb3RyMjggPSByb3RyXzY0KHgsIDI4KSwgcm90cjM0ID0gcm90cl82NCh4LCAzNCksXG5cdFx0XHRyb3RyMzkgPSByb3RyXzY0KHgsIDM5KTtcblxuXHRcdHJldHVybiBuZXcgSW50XzY0KFxuXHRcdFx0XHRyb3RyMjguaGlnaE9yZGVyIF4gcm90cjM0LmhpZ2hPcmRlciBeIHJvdHIzOS5oaWdoT3JkZXIsXG5cdFx0XHRcdHJvdHIyOC5sb3dPcmRlciBeIHJvdHIzNC5sb3dPcmRlciBeIHJvdHIzOS5sb3dPcmRlcik7XG5cdH0sXG5cblx0Lypcblx0ICogVGhlIDMyLWJpdCBpbXBsZW1lbnRhdGlvbiBvZiB0aGUgTklTVCBzcGVjaWZpZWQgU2lnbWExIGZ1bmN0aW9uXG5cdCAqXG5cdCAqIEBwcml2YXRlXG5cdCAqIEBwYXJhbSB7TnVtYmVyfSB4IFRoZSAzMi1iaXQgaW50ZWdlciBhcmd1bWVudFxuXHQgKiBAcmV0dXJuIFRoZSBOSVNUIHNwZWNpZmllZCBvdXRwdXQgb2YgdGhlIGZ1bmN0aW9uXG5cdCAqL1xuXHRzaWdtYTFfMzIgPSBmdW5jdGlvbiAoeClcblx0e1xuXHRcdHJldHVybiByb3RyXzMyKHgsIDYpIF4gcm90cl8zMih4LCAxMSkgXiByb3RyXzMyKHgsIDI1KTtcblx0fSxcblxuXHQvKlxuXHQgKiBUaGUgNjQtYml0IGltcGxlbWVudGF0aW9uIG9mIHRoZSBOSVNUIHNwZWNpZmllZCBTaWdtYTEgZnVuY3Rpb25cblx0ICpcblx0ICogQHByaXZhdGVcblx0ICogQHBhcmFtIHtJbnRfNjR9IHggVGhlIDY0LWJpdCBpbnRlZ2VyIGFyZ3VtZW50XG5cdCAqIEByZXR1cm4gVGhlIE5JU1Qgc3BlY2lmaWVkIG91dHB1dCBvZiB0aGUgZnVuY3Rpb25cblx0ICovXG5cdHNpZ21hMV82NCA9IGZ1bmN0aW9uICh4KVxuXHR7XG5cdFx0dmFyIHJvdHIxNCA9IHJvdHJfNjQoeCwgMTQpLCByb3RyMTggPSByb3RyXzY0KHgsIDE4KSxcblx0XHRcdHJvdHI0MSA9IHJvdHJfNjQoeCwgNDEpO1xuXG5cdFx0cmV0dXJuIG5ldyBJbnRfNjQoXG5cdFx0XHRcdHJvdHIxNC5oaWdoT3JkZXIgXiByb3RyMTguaGlnaE9yZGVyIF4gcm90cjQxLmhpZ2hPcmRlcixcblx0XHRcdFx0cm90cjE0Lmxvd09yZGVyIF4gcm90cjE4Lmxvd09yZGVyIF4gcm90cjQxLmxvd09yZGVyKTtcblx0fSxcblxuXHQvKlxuXHQgKiBUaGUgMzItYml0IGltcGxlbWVudGF0aW9uIG9mIHRoZSBOSVNUIHNwZWNpZmllZCBHYW1tYTAgZnVuY3Rpb25cblx0ICpcblx0ICogQHByaXZhdGVcblx0ICogQHBhcmFtIHtOdW1iZXJ9IHggVGhlIDMyLWJpdCBpbnRlZ2VyIGFyZ3VtZW50XG5cdCAqIEByZXR1cm4gVGhlIE5JU1Qgc3BlY2lmaWVkIG91dHB1dCBvZiB0aGUgZnVuY3Rpb25cblx0ICovXG5cdGdhbW1hMF8zMiA9IGZ1bmN0aW9uICh4KVxuXHR7XG5cdFx0cmV0dXJuIHJvdHJfMzIoeCwgNykgXiByb3RyXzMyKHgsIDE4KSBeIHNocl8zMih4LCAzKTtcblx0fSxcblxuXHQvKlxuXHQgKiBUaGUgNjQtYml0IGltcGxlbWVudGF0aW9uIG9mIHRoZSBOSVNUIHNwZWNpZmllZCBHYW1tYTAgZnVuY3Rpb25cblx0ICpcblx0ICogQHByaXZhdGVcblx0ICogQHBhcmFtIHtJbnRfNjR9IHggVGhlIDY0LWJpdCBpbnRlZ2VyIGFyZ3VtZW50XG5cdCAqIEByZXR1cm4gVGhlIE5JU1Qgc3BlY2lmaWVkIG91dHB1dCBvZiB0aGUgZnVuY3Rpb25cblx0ICovXG5cdGdhbW1hMF82NCA9IGZ1bmN0aW9uICh4KVxuXHR7XG5cdFx0dmFyIHJvdHIxID0gcm90cl82NCh4LCAxKSwgcm90cjggPSByb3RyXzY0KHgsIDgpLCBzaHI3ID0gc2hyXzY0KHgsIDcpO1xuXG5cdFx0cmV0dXJuIG5ldyBJbnRfNjQoXG5cdFx0XHRcdHJvdHIxLmhpZ2hPcmRlciBeIHJvdHI4LmhpZ2hPcmRlciBeIHNocjcuaGlnaE9yZGVyLFxuXHRcdFx0XHRyb3RyMS5sb3dPcmRlciBeIHJvdHI4Lmxvd09yZGVyIF4gc2hyNy5sb3dPcmRlclxuXHRcdFx0KTtcblx0fSxcblxuXHQvKlxuXHQgKiBUaGUgMzItYml0IGltcGxlbWVudGF0aW9uIG9mIHRoZSBOSVNUIHNwZWNpZmllZCBHYW1tYTEgZnVuY3Rpb25cblx0ICpcblx0ICogQHByaXZhdGVcblx0ICogQHBhcmFtIHtOdW1iZXJ9IHggVGhlIDMyLWJpdCBpbnRlZ2VyIGFyZ3VtZW50XG5cdCAqIEByZXR1cm4gVGhlIE5JU1Qgc3BlY2lmaWVkIG91dHB1dCBvZiB0aGUgZnVuY3Rpb25cblx0ICovXG5cdGdhbW1hMV8zMiA9IGZ1bmN0aW9uICh4KVxuXHR7XG5cdFx0cmV0dXJuIHJvdHJfMzIoeCwgMTcpIF4gcm90cl8zMih4LCAxOSkgXiBzaHJfMzIoeCwgMTApO1xuXHR9LFxuXG5cdC8qXG5cdCAqIFRoZSA2NC1iaXQgaW1wbGVtZW50YXRpb24gb2YgdGhlIE5JU1Qgc3BlY2lmaWVkIEdhbW1hMSBmdW5jdGlvblxuXHQgKlxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge0ludF82NH0geCBUaGUgNjQtYml0IGludGVnZXIgYXJndW1lbnRcblx0ICogQHJldHVybiBUaGUgTklTVCBzcGVjaWZpZWQgb3V0cHV0IG9mIHRoZSBmdW5jdGlvblxuXHQgKi9cblx0Z2FtbWExXzY0ID0gZnVuY3Rpb24gKHgpXG5cdHtcblx0XHR2YXIgcm90cjE5ID0gcm90cl82NCh4LCAxOSksIHJvdHI2MSA9IHJvdHJfNjQoeCwgNjEpLFxuXHRcdFx0c2hyNiA9IHNocl82NCh4LCA2KTtcblxuXHRcdHJldHVybiBuZXcgSW50XzY0KFxuXHRcdFx0XHRyb3RyMTkuaGlnaE9yZGVyIF4gcm90cjYxLmhpZ2hPcmRlciBeIHNocjYuaGlnaE9yZGVyLFxuXHRcdFx0XHRyb3RyMTkubG93T3JkZXIgXiByb3RyNjEubG93T3JkZXIgXiBzaHI2Lmxvd09yZGVyXG5cdFx0XHQpO1xuXHR9LFxuXG5cdC8qXG5cdCAqIEFkZCB0d28gMzItYml0IGludGVnZXJzLCB3cmFwcGluZyBhdCAyXjMyLiBUaGlzIHVzZXMgMTYtYml0IG9wZXJhdGlvbnNcblx0ICogaW50ZXJuYWxseSB0byB3b3JrIGFyb3VuZCBidWdzIGluIHNvbWUgSlMgaW50ZXJwcmV0ZXJzLlxuXHQgKlxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge051bWJlcn0geCBUaGUgZmlyc3QgMzItYml0IGludGVnZXIgYXJndW1lbnQgdG8gYmUgYWRkZWRcblx0ICogQHBhcmFtIHtOdW1iZXJ9IHkgVGhlIHNlY29uZCAzMi1iaXQgaW50ZWdlciBhcmd1bWVudCB0byBiZSBhZGRlZFxuXHQgKiBAcmV0dXJuIFRoZSBzdW0gb2YgeCArIHlcblx0ICovXG5cdHNhZmVBZGRfMzJfMiA9IGZ1bmN0aW9uICh4LCB5KVxuXHR7XG5cdFx0dmFyIGxzdyA9ICh4ICYgMHhGRkZGKSArICh5ICYgMHhGRkZGKSxcblx0XHRcdG1zdyA9ICh4ID4+PiAxNikgKyAoeSA+Pj4gMTYpICsgKGxzdyA+Pj4gMTYpO1xuXG5cdFx0cmV0dXJuICgobXN3ICYgMHhGRkZGKSA8PCAxNikgfCAobHN3ICYgMHhGRkZGKTtcblx0fSxcblxuXHQvKlxuXHQgKiBBZGQgZm91ciAzMi1iaXQgaW50ZWdlcnMsIHdyYXBwaW5nIGF0IDJeMzIuIFRoaXMgdXNlcyAxNi1iaXQgb3BlcmF0aW9uc1xuXHQgKiBpbnRlcm5hbGx5IHRvIHdvcmsgYXJvdW5kIGJ1Z3MgaW4gc29tZSBKUyBpbnRlcnByZXRlcnMuXG5cdCAqXG5cdCAqIEBwcml2YXRlXG5cdCAqIEBwYXJhbSB7TnVtYmVyfSBhIFRoZSBmaXJzdCAzMi1iaXQgaW50ZWdlciBhcmd1bWVudCB0byBiZSBhZGRlZFxuXHQgKiBAcGFyYW0ge051bWJlcn0gYiBUaGUgc2Vjb25kIDMyLWJpdCBpbnRlZ2VyIGFyZ3VtZW50IHRvIGJlIGFkZGVkXG5cdCAqIEBwYXJhbSB7TnVtYmVyfSBjIFRoZSB0aGlyZCAzMi1iaXQgaW50ZWdlciBhcmd1bWVudCB0byBiZSBhZGRlZFxuXHQgKiBAcGFyYW0ge051bWJlcn0gZCBUaGUgZm91cnRoIDMyLWJpdCBpbnRlZ2VyIGFyZ3VtZW50IHRvIGJlIGFkZGVkXG5cdCAqIEByZXR1cm4gVGhlIHN1bSBvZiBhICsgYiArIGMgKyBkXG5cdCAqL1xuXHRzYWZlQWRkXzMyXzQgPSBmdW5jdGlvbiAoYSwgYiwgYywgZClcblx0e1xuXHRcdHZhciBsc3cgPSAoYSAmIDB4RkZGRikgKyAoYiAmIDB4RkZGRikgKyAoYyAmIDB4RkZGRikgKyAoZCAmIDB4RkZGRiksXG5cdFx0XHRtc3cgPSAoYSA+Pj4gMTYpICsgKGIgPj4+IDE2KSArIChjID4+PiAxNikgKyAoZCA+Pj4gMTYpICtcblx0XHRcdFx0KGxzdyA+Pj4gMTYpO1xuXG5cdFx0cmV0dXJuICgobXN3ICYgMHhGRkZGKSA8PCAxNikgfCAobHN3ICYgMHhGRkZGKTtcblx0fSxcblxuXHQvKlxuXHQgKiBBZGQgZml2ZSAzMi1iaXQgaW50ZWdlcnMsIHdyYXBwaW5nIGF0IDJeMzIuIFRoaXMgdXNlcyAxNi1iaXQgb3BlcmF0aW9uc1xuXHQgKiBpbnRlcm5hbGx5IHRvIHdvcmsgYXJvdW5kIGJ1Z3MgaW4gc29tZSBKUyBpbnRlcnByZXRlcnMuXG5cdCAqXG5cdCAqIEBwcml2YXRlXG5cdCAqIEBwYXJhbSB7TnVtYmVyfSBhIFRoZSBmaXJzdCAzMi1iaXQgaW50ZWdlciBhcmd1bWVudCB0byBiZSBhZGRlZFxuXHQgKiBAcGFyYW0ge051bWJlcn0gYiBUaGUgc2Vjb25kIDMyLWJpdCBpbnRlZ2VyIGFyZ3VtZW50IHRvIGJlIGFkZGVkXG5cdCAqIEBwYXJhbSB7TnVtYmVyfSBjIFRoZSB0aGlyZCAzMi1iaXQgaW50ZWdlciBhcmd1bWVudCB0byBiZSBhZGRlZFxuXHQgKiBAcGFyYW0ge051bWJlcn0gZCBUaGUgZm91cnRoIDMyLWJpdCBpbnRlZ2VyIGFyZ3VtZW50IHRvIGJlIGFkZGVkXG5cdCAqIEBwYXJhbSB7TnVtYmVyfSBlIFRoZSBmaWZ0aCAzMi1iaXQgaW50ZWdlciBhcmd1bWVudCB0byBiZSBhZGRlZFxuXHQgKiBAcmV0dXJuIFRoZSBzdW0gb2YgYSArIGIgKyBjICsgZCArIGVcblx0ICovXG5cdHNhZmVBZGRfMzJfNSA9IGZ1bmN0aW9uIChhLCBiLCBjLCBkLCBlKVxuXHR7XG5cdFx0dmFyIGxzdyA9IChhICYgMHhGRkZGKSArIChiICYgMHhGRkZGKSArIChjICYgMHhGRkZGKSArIChkICYgMHhGRkZGKSArXG5cdFx0XHRcdChlICYgMHhGRkZGKSxcblx0XHRcdG1zdyA9IChhID4+PiAxNikgKyAoYiA+Pj4gMTYpICsgKGMgPj4+IDE2KSArIChkID4+PiAxNikgK1xuXHRcdFx0XHQoZSA+Pj4gMTYpICsgKGxzdyA+Pj4gMTYpO1xuXG5cdFx0cmV0dXJuICgobXN3ICYgMHhGRkZGKSA8PCAxNikgfCAobHN3ICYgMHhGRkZGKTtcblx0fSxcblxuXHQvKlxuXHQgKiBBZGQgdHdvIDY0LWJpdCBpbnRlZ2Vycywgd3JhcHBpbmcgYXQgMl42NC4gVGhpcyB1c2VzIDE2LWJpdCBvcGVyYXRpb25zXG5cdCAqIGludGVybmFsbHkgdG8gd29yayBhcm91bmQgYnVncyBpbiBzb21lIEpTIGludGVycHJldGVycy5cblx0ICpcblx0ICogQHByaXZhdGVcblx0ICogQHBhcmFtIHtJbnRfNjR9IHggVGhlIGZpcnN0IDY0LWJpdCBpbnRlZ2VyIGFyZ3VtZW50IHRvIGJlIGFkZGVkXG5cdCAqIEBwYXJhbSB7SW50XzY0fSB5IFRoZSBzZWNvbmQgNjQtYml0IGludGVnZXIgYXJndW1lbnQgdG8gYmUgYWRkZWRcblx0ICogQHJldHVybiBUaGUgc3VtIG9mIHggKyB5XG5cdCAqL1xuXHRzYWZlQWRkXzY0XzIgPSBmdW5jdGlvbiAoeCwgeSlcblx0e1xuXHRcdHZhciBsc3csIG1zdywgbG93T3JkZXIsIGhpZ2hPcmRlcjtcblxuXHRcdGxzdyA9ICh4Lmxvd09yZGVyICYgMHhGRkZGKSArICh5Lmxvd09yZGVyICYgMHhGRkZGKTtcblx0XHRtc3cgPSAoeC5sb3dPcmRlciA+Pj4gMTYpICsgKHkubG93T3JkZXIgPj4+IDE2KSArIChsc3cgPj4+IDE2KTtcblx0XHRsb3dPcmRlciA9ICgobXN3ICYgMHhGRkZGKSA8PCAxNikgfCAobHN3ICYgMHhGRkZGKTtcblxuXHRcdGxzdyA9ICh4LmhpZ2hPcmRlciAmIDB4RkZGRikgKyAoeS5oaWdoT3JkZXIgJiAweEZGRkYpICsgKG1zdyA+Pj4gMTYpO1xuXHRcdG1zdyA9ICh4LmhpZ2hPcmRlciA+Pj4gMTYpICsgKHkuaGlnaE9yZGVyID4+PiAxNikgKyAobHN3ID4+PiAxNik7XG5cdFx0aGlnaE9yZGVyID0gKChtc3cgJiAweEZGRkYpIDw8IDE2KSB8IChsc3cgJiAweEZGRkYpO1xuXG5cdFx0cmV0dXJuIG5ldyBJbnRfNjQoaGlnaE9yZGVyLCBsb3dPcmRlcik7XG5cdH0sXG5cblx0Lypcblx0ICogQWRkIGZvdXIgNjQtYml0IGludGVnZXJzLCB3cmFwcGluZyBhdCAyXjY0LiBUaGlzIHVzZXMgMTYtYml0IG9wZXJhdGlvbnNcblx0ICogaW50ZXJuYWxseSB0byB3b3JrIGFyb3VuZCBidWdzIGluIHNvbWUgSlMgaW50ZXJwcmV0ZXJzLlxuXHQgKlxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge0ludF82NH0gYSBUaGUgZmlyc3QgNjQtYml0IGludGVnZXIgYXJndW1lbnQgdG8gYmUgYWRkZWRcblx0ICogQHBhcmFtIHtJbnRfNjR9IGIgVGhlIHNlY29uZCA2NC1iaXQgaW50ZWdlciBhcmd1bWVudCB0byBiZSBhZGRlZFxuXHQgKiBAcGFyYW0ge0ludF82NH0gYyBUaGUgdGhpcmQgNjQtYml0IGludGVnZXIgYXJndW1lbnQgdG8gYmUgYWRkZWRcblx0ICogQHBhcmFtIHtJbnRfNjR9IGQgVGhlIGZvdXRoIDY0LWJpdCBpbnRlZ2VyIGFyZ3VtZW50IHRvIGJlIGFkZGVkXG5cdCAqIEByZXR1cm4gVGhlIHN1bSBvZiBhICsgYiArIGMgKyBkXG5cdCAqL1xuXHRzYWZlQWRkXzY0XzQgPSBmdW5jdGlvbiAoYSwgYiwgYywgZClcblx0e1xuXHRcdHZhciBsc3csIG1zdywgbG93T3JkZXIsIGhpZ2hPcmRlcjtcblxuXHRcdGxzdyA9IChhLmxvd09yZGVyICYgMHhGRkZGKSArIChiLmxvd09yZGVyICYgMHhGRkZGKSArXG5cdFx0XHQoYy5sb3dPcmRlciAmIDB4RkZGRikgKyAoZC5sb3dPcmRlciAmIDB4RkZGRik7XG5cdFx0bXN3ID0gKGEubG93T3JkZXIgPj4+IDE2KSArIChiLmxvd09yZGVyID4+PiAxNikgK1xuXHRcdFx0KGMubG93T3JkZXIgPj4+IDE2KSArIChkLmxvd09yZGVyID4+PiAxNikgKyAobHN3ID4+PiAxNik7XG5cdFx0bG93T3JkZXIgPSAoKG1zdyAmIDB4RkZGRikgPDwgMTYpIHwgKGxzdyAmIDB4RkZGRik7XG5cblx0XHRsc3cgPSAoYS5oaWdoT3JkZXIgJiAweEZGRkYpICsgKGIuaGlnaE9yZGVyICYgMHhGRkZGKSArXG5cdFx0XHQoYy5oaWdoT3JkZXIgJiAweEZGRkYpICsgKGQuaGlnaE9yZGVyICYgMHhGRkZGKSArIChtc3cgPj4+IDE2KTtcblx0XHRtc3cgPSAoYS5oaWdoT3JkZXIgPj4+IDE2KSArIChiLmhpZ2hPcmRlciA+Pj4gMTYpICtcblx0XHRcdChjLmhpZ2hPcmRlciA+Pj4gMTYpICsgKGQuaGlnaE9yZGVyID4+PiAxNikgKyAobHN3ID4+PiAxNik7XG5cdFx0aGlnaE9yZGVyID0gKChtc3cgJiAweEZGRkYpIDw8IDE2KSB8IChsc3cgJiAweEZGRkYpO1xuXG5cdFx0cmV0dXJuIG5ldyBJbnRfNjQoaGlnaE9yZGVyLCBsb3dPcmRlcik7XG5cdH0sXG5cblx0Lypcblx0ICogQWRkIGZpdmUgNjQtYml0IGludGVnZXJzLCB3cmFwcGluZyBhdCAyXjY0LiBUaGlzIHVzZXMgMTYtYml0IG9wZXJhdGlvbnNcblx0ICogaW50ZXJuYWxseSB0byB3b3JrIGFyb3VuZCBidWdzIGluIHNvbWUgSlMgaW50ZXJwcmV0ZXJzLlxuXHQgKlxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge0ludF82NH0gYSBUaGUgZmlyc3QgNjQtYml0IGludGVnZXIgYXJndW1lbnQgdG8gYmUgYWRkZWRcblx0ICogQHBhcmFtIHtJbnRfNjR9IGIgVGhlIHNlY29uZCA2NC1iaXQgaW50ZWdlciBhcmd1bWVudCB0byBiZSBhZGRlZFxuXHQgKiBAcGFyYW0ge0ludF82NH0gYyBUaGUgdGhpcmQgNjQtYml0IGludGVnZXIgYXJndW1lbnQgdG8gYmUgYWRkZWRcblx0ICogQHBhcmFtIHtJbnRfNjR9IGQgVGhlIGZvdXRoIDY0LWJpdCBpbnRlZ2VyIGFyZ3VtZW50IHRvIGJlIGFkZGVkXG5cdCAqIEBwYXJhbSB7SW50XzY0fSBlIFRoZSBmb3V0aCA2NC1iaXQgaW50ZWdlciBhcmd1bWVudCB0byBiZSBhZGRlZFxuXHQgKiBAcmV0dXJuIFRoZSBzdW0gb2YgYSArIGIgKyBjICsgZCArIGVcblx0ICovXG5cdHNhZmVBZGRfNjRfNSA9IGZ1bmN0aW9uIChhLCBiLCBjLCBkLCBlKVxuXHR7XG5cdFx0dmFyIGxzdywgbXN3LCBsb3dPcmRlciwgaGlnaE9yZGVyO1xuXG5cdFx0bHN3ID0gKGEubG93T3JkZXIgJiAweEZGRkYpICsgKGIubG93T3JkZXIgJiAweEZGRkYpICtcblx0XHRcdChjLmxvd09yZGVyICYgMHhGRkZGKSArIChkLmxvd09yZGVyICYgMHhGRkZGKSArXG5cdFx0XHQoZS5sb3dPcmRlciAmIDB4RkZGRik7XG5cdFx0bXN3ID0gKGEubG93T3JkZXIgPj4+IDE2KSArIChiLmxvd09yZGVyID4+PiAxNikgK1xuXHRcdFx0KGMubG93T3JkZXIgPj4+IDE2KSArIChkLmxvd09yZGVyID4+PiAxNikgKyAoZS5sb3dPcmRlciA+Pj4gMTYpICtcblx0XHRcdChsc3cgPj4+IDE2KTtcblx0XHRsb3dPcmRlciA9ICgobXN3ICYgMHhGRkZGKSA8PCAxNikgfCAobHN3ICYgMHhGRkZGKTtcblxuXHRcdGxzdyA9IChhLmhpZ2hPcmRlciAmIDB4RkZGRikgKyAoYi5oaWdoT3JkZXIgJiAweEZGRkYpICtcblx0XHRcdChjLmhpZ2hPcmRlciAmIDB4RkZGRikgKyAoZC5oaWdoT3JkZXIgJiAweEZGRkYpICtcblx0XHRcdChlLmhpZ2hPcmRlciAmIDB4RkZGRikgKyAobXN3ID4+PiAxNik7XG5cdFx0bXN3ID0gKGEuaGlnaE9yZGVyID4+PiAxNikgKyAoYi5oaWdoT3JkZXIgPj4+IDE2KSArXG5cdFx0XHQoYy5oaWdoT3JkZXIgPj4+IDE2KSArIChkLmhpZ2hPcmRlciA+Pj4gMTYpICtcblx0XHRcdChlLmhpZ2hPcmRlciA+Pj4gMTYpICsgKGxzdyA+Pj4gMTYpO1xuXHRcdGhpZ2hPcmRlciA9ICgobXN3ICYgMHhGRkZGKSA8PCAxNikgfCAobHN3ICYgMHhGRkZGKTtcblxuXHRcdHJldHVybiBuZXcgSW50XzY0KGhpZ2hPcmRlciwgbG93T3JkZXIpO1xuXHR9LFxuXG5cdC8qXG5cdCAqIENhbGN1bGF0ZXMgdGhlIFNIQS0xIGhhc2ggb2YgdGhlIHN0cmluZyBzZXQgYXQgaW5zdGFudGlhdGlvblxuXHQgKlxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge0FycmF5fSBtZXNzYWdlIFRoZSBiaW5hcnkgYXJyYXkgcmVwcmVzZW50YXRpb24gb2YgdGhlIHN0cmluZyB0b1xuXHQgKlx0IGhhc2hcblx0ICogQHBhcmFtIHtOdW1iZXJ9IG1lc3NhZ2VMZW4gVGhlIG51bWJlciBvZiBiaXRzIGluIHRoZSBtZXNzYWdlXG5cdCAqIEByZXR1cm4gVGhlIGFycmF5IG9mIGludGVnZXJzIHJlcHJlc2VudGluZyB0aGUgU0hBLTEgaGFzaCBvZiBtZXNzYWdlXG5cdCAqL1xuXHRjb3JlU0hBMSA9IGZ1bmN0aW9uIChtZXNzYWdlLCBtZXNzYWdlTGVuKVxuXHR7XG5cdFx0dmFyIFcgPSBbXSwgYSwgYiwgYywgZCwgZSwgVCwgY2ggPSBjaF8zMiwgcGFyaXR5ID0gcGFyaXR5XzMyLFxuXHRcdFx0bWFqID0gbWFqXzMyLCByb3RsID0gcm90bF8zMiwgc2FmZUFkZF8yID0gc2FmZUFkZF8zMl8yLCBpLCB0LFxuXHRcdFx0c2FmZUFkZF81ID0gc2FmZUFkZF8zMl81LCBhcHBlbmRlZE1lc3NhZ2VMZW5ndGgsXG5cdFx0XHRIID0gW1xuXHRcdFx0XHQweDY3NDUyMzAxLCAweGVmY2RhYjg5LCAweDk4YmFkY2ZlLCAweDEwMzI1NDc2LCAweGMzZDJlMWYwXG5cdFx0XHRdLFxuXHRcdFx0SyA9IFtcblx0XHRcdFx0MHg1YTgyNzk5OSwgMHg1YTgyNzk5OSwgMHg1YTgyNzk5OSwgMHg1YTgyNzk5OSxcblx0XHRcdFx0MHg1YTgyNzk5OSwgMHg1YTgyNzk5OSwgMHg1YTgyNzk5OSwgMHg1YTgyNzk5OSxcblx0XHRcdFx0MHg1YTgyNzk5OSwgMHg1YTgyNzk5OSwgMHg1YTgyNzk5OSwgMHg1YTgyNzk5OSxcblx0XHRcdFx0MHg1YTgyNzk5OSwgMHg1YTgyNzk5OSwgMHg1YTgyNzk5OSwgMHg1YTgyNzk5OSxcblx0XHRcdFx0MHg1YTgyNzk5OSwgMHg1YTgyNzk5OSwgMHg1YTgyNzk5OSwgMHg1YTgyNzk5OSxcblx0XHRcdFx0MHg2ZWQ5ZWJhMSwgMHg2ZWQ5ZWJhMSwgMHg2ZWQ5ZWJhMSwgMHg2ZWQ5ZWJhMSxcblx0XHRcdFx0MHg2ZWQ5ZWJhMSwgMHg2ZWQ5ZWJhMSwgMHg2ZWQ5ZWJhMSwgMHg2ZWQ5ZWJhMSxcblx0XHRcdFx0MHg2ZWQ5ZWJhMSwgMHg2ZWQ5ZWJhMSwgMHg2ZWQ5ZWJhMSwgMHg2ZWQ5ZWJhMSxcblx0XHRcdFx0MHg2ZWQ5ZWJhMSwgMHg2ZWQ5ZWJhMSwgMHg2ZWQ5ZWJhMSwgMHg2ZWQ5ZWJhMSxcblx0XHRcdFx0MHg2ZWQ5ZWJhMSwgMHg2ZWQ5ZWJhMSwgMHg2ZWQ5ZWJhMSwgMHg2ZWQ5ZWJhMSxcblx0XHRcdFx0MHg4ZjFiYmNkYywgMHg4ZjFiYmNkYywgMHg4ZjFiYmNkYywgMHg4ZjFiYmNkYyxcblx0XHRcdFx0MHg4ZjFiYmNkYywgMHg4ZjFiYmNkYywgMHg4ZjFiYmNkYywgMHg4ZjFiYmNkYyxcblx0XHRcdFx0MHg4ZjFiYmNkYywgMHg4ZjFiYmNkYywgMHg4ZjFiYmNkYywgMHg4ZjFiYmNkYyxcblx0XHRcdFx0MHg4ZjFiYmNkYywgMHg4ZjFiYmNkYywgMHg4ZjFiYmNkYywgMHg4ZjFiYmNkYyxcblx0XHRcdFx0MHg4ZjFiYmNkYywgMHg4ZjFiYmNkYywgMHg4ZjFiYmNkYywgMHg4ZjFiYmNkYyxcblx0XHRcdFx0MHhjYTYyYzFkNiwgMHhjYTYyYzFkNiwgMHhjYTYyYzFkNiwgMHhjYTYyYzFkNixcblx0XHRcdFx0MHhjYTYyYzFkNiwgMHhjYTYyYzFkNiwgMHhjYTYyYzFkNiwgMHhjYTYyYzFkNixcblx0XHRcdFx0MHhjYTYyYzFkNiwgMHhjYTYyYzFkNiwgMHhjYTYyYzFkNiwgMHhjYTYyYzFkNixcblx0XHRcdFx0MHhjYTYyYzFkNiwgMHhjYTYyYzFkNiwgMHhjYTYyYzFkNiwgMHhjYTYyYzFkNixcblx0XHRcdFx0MHhjYTYyYzFkNiwgMHhjYTYyYzFkNiwgMHhjYTYyYzFkNiwgMHhjYTYyYzFkNlxuXHRcdFx0XTtcblxuXHRcdC8qIEFwcGVuZCAnMScgYXQgdGhlIGVuZCBvZiB0aGUgYmluYXJ5IHN0cmluZyAqL1xuXHRcdG1lc3NhZ2VbbWVzc2FnZUxlbiA+PiA1XSB8PSAweDgwIDw8ICgyNCAtIChtZXNzYWdlTGVuICUgMzIpKTtcblx0XHQvKiBBcHBlbmQgbGVuZ3RoIG9mIGJpbmFyeSBzdHJpbmcgaW4gdGhlIHBvc2l0aW9uIHN1Y2ggdGhhdCB0aGUgbmV3XG5cdFx0bGVuZ3RoIGlzIGEgbXVsdGlwbGUgb2YgNTEyLiAgTG9naWMgZG9lcyBub3Qgd29yayBmb3IgZXZlbiBtdWx0aXBsZXNcblx0XHRvZiA1MTIgYnV0IHRoZXJlIGNhbiBuZXZlciBiZSBldmVuIG11bHRpcGxlcyBvZiA1MTIgKi9cblx0XHRtZXNzYWdlWygoKG1lc3NhZ2VMZW4gKyA2NSkgPj4gOSkgPDwgNCkgKyAxNV0gPSBtZXNzYWdlTGVuO1xuXG5cdFx0YXBwZW5kZWRNZXNzYWdlTGVuZ3RoID0gbWVzc2FnZS5sZW5ndGg7XG5cblx0XHRmb3IgKGkgPSAwOyBpIDwgYXBwZW5kZWRNZXNzYWdlTGVuZ3RoOyBpICs9IDE2KVxuXHRcdHtcblx0XHRcdGEgPSBIWzBdO1xuXHRcdFx0YiA9IEhbMV07XG5cdFx0XHRjID0gSFsyXTtcblx0XHRcdGQgPSBIWzNdO1xuXHRcdFx0ZSA9IEhbNF07XG5cblx0XHRcdGZvciAodCA9IDA7IHQgPCA4MDsgdCArPSAxKVxuXHRcdFx0e1xuXHRcdFx0XHRpZiAodCA8IDE2KVxuXHRcdFx0XHR7XG5cdFx0XHRcdFx0V1t0XSA9IG1lc3NhZ2VbdCArIGldO1xuXHRcdFx0XHR9XG5cdFx0XHRcdGVsc2Vcblx0XHRcdFx0e1xuXHRcdFx0XHRcdFdbdF0gPSByb3RsKFdbdCAtIDNdIF4gV1t0IC0gOF0gXiBXW3QgLSAxNF0gXiBXW3QgLSAxNl0sIDEpO1xuXHRcdFx0XHR9XG5cblx0XHRcdFx0aWYgKHQgPCAyMClcblx0XHRcdFx0e1xuXHRcdFx0XHRcdFQgPSBzYWZlQWRkXzUocm90bChhLCA1KSwgY2goYiwgYywgZCksIGUsIEtbdF0sIFdbdF0pO1xuXHRcdFx0XHR9XG5cdFx0XHRcdGVsc2UgaWYgKHQgPCA0MClcblx0XHRcdFx0e1xuXHRcdFx0XHRcdFQgPSBzYWZlQWRkXzUocm90bChhLCA1KSwgcGFyaXR5KGIsIGMsIGQpLCBlLCBLW3RdLCBXW3RdKTtcblx0XHRcdFx0fVxuXHRcdFx0XHRlbHNlIGlmICh0IDwgNjApXG5cdFx0XHRcdHtcblx0XHRcdFx0XHRUID0gc2FmZUFkZF81KHJvdGwoYSwgNSksIG1haihiLCBjLCBkKSwgZSwgS1t0XSwgV1t0XSk7XG5cdFx0XHRcdH0gZWxzZSB7XG5cdFx0XHRcdFx0VCA9IHNhZmVBZGRfNShyb3RsKGEsIDUpLCBwYXJpdHkoYiwgYywgZCksIGUsIEtbdF0sIFdbdF0pO1xuXHRcdFx0XHR9XG5cblx0XHRcdFx0ZSA9IGQ7XG5cdFx0XHRcdGQgPSBjO1xuXHRcdFx0XHRjID0gcm90bChiLCAzMCk7XG5cdFx0XHRcdGIgPSBhO1xuXHRcdFx0XHRhID0gVDtcblx0XHRcdH1cblxuXHRcdFx0SFswXSA9IHNhZmVBZGRfMihhLCBIWzBdKTtcblx0XHRcdEhbMV0gPSBzYWZlQWRkXzIoYiwgSFsxXSk7XG5cdFx0XHRIWzJdID0gc2FmZUFkZF8yKGMsIEhbMl0pO1xuXHRcdFx0SFszXSA9IHNhZmVBZGRfMihkLCBIWzNdKTtcblx0XHRcdEhbNF0gPSBzYWZlQWRkXzIoZSwgSFs0XSk7XG5cdFx0fVxuXG5cdFx0cmV0dXJuIEg7XG5cdH0sXG5cblx0Lypcblx0ICogQ2FsY3VsYXRlcyB0aGUgZGVzaXJlZCBTSEEtMiBoYXNoIG9mIHRoZSBzdHJpbmcgc2V0IGF0IGluc3RhbnRpYXRpb25cblx0ICpcblx0ICogQHByaXZhdGVcblx0ICogQHBhcmFtIHtBcnJheX0gVGhlIGJpbmFyeSBhcnJheSByZXByZXNlbnRhdGlvbiBvZiB0aGUgc3RyaW5nIHRvIGhhc2hcblx0ICogQHBhcmFtIHtOdW1iZXJ9IFRoZSBudW1iZXIgb2YgYml0cyBpbiBtZXNzYWdlXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSB2YXJpYW50IFRoZSBkZXNpcmVkIFNIQS0yIHZhcmlhbnRcblx0ICogQHJldHVybiBUaGUgYXJyYXkgb2YgaW50ZWdlcnMgcmVwcmVzZW50aW5nIHRoZSBTSEEtMiBoYXNoIG9mIG1lc3NhZ2Vcblx0ICovXG5cdGNvcmVTSEEyID0gZnVuY3Rpb24gKG1lc3NhZ2UsIG1lc3NhZ2VMZW4sIHZhcmlhbnQpXG5cdHtcblx0XHR2YXIgYSwgYiwgYywgZCwgZSwgZiwgZywgaCwgVDEsIFQyLCBILCBudW1Sb3VuZHMsIGxlbmd0aFBvc2l0aW9uLCBpLCB0LFxuXHRcdFx0YmluYXJ5U3RyaW5nSW5jLCBiaW5hcnlTdHJpbmdNdWx0LCBzYWZlQWRkXzIsIHNhZmVBZGRfNCwgc2FmZUFkZF81LFxuXHRcdFx0Z2FtbWEwLCBnYW1tYTEsIHNpZ21hMCwgc2lnbWExLCBjaCwgbWFqLCBJbnQsIEssIFcgPSBbXSxcblx0XHRcdGFwcGVuZGVkTWVzc2FnZUxlbmd0aDtcblxuXHRcdC8qIFNldCB1cCB0aGUgdmFyaW91cyBmdW5jdGlvbiBoYW5kbGVzIGFuZCB2YXJpYWJsZSBmb3IgdGhlIHNwZWNpZmljIFxuXHRcdCAqIHZhcmlhbnQgKi9cblx0XHRpZiAodmFyaWFudCA9PT0gXCJTSEEtMjI0XCIgfHwgdmFyaWFudCA9PT0gXCJTSEEtMjU2XCIpXG5cdFx0e1xuXHRcdFx0LyogMzItYml0IHZhcmlhbnQgKi9cblx0XHRcdG51bVJvdW5kcyA9IDY0O1xuXHRcdFx0bGVuZ3RoUG9zaXRpb24gPSAoKChtZXNzYWdlTGVuICsgNjUpID4+IDkpIDw8IDQpICsgMTU7XG5cdFx0XHRiaW5hcnlTdHJpbmdJbmMgPSAxNjtcblx0XHRcdGJpbmFyeVN0cmluZ011bHQgPSAxO1xuXHRcdFx0SW50ID0gTnVtYmVyO1xuXHRcdFx0c2FmZUFkZF8yID0gc2FmZUFkZF8zMl8yO1xuXHRcdFx0c2FmZUFkZF80ID0gc2FmZUFkZF8zMl80O1xuXHRcdFx0c2FmZUFkZF81ID0gc2FmZUFkZF8zMl81O1xuXHRcdFx0Z2FtbWEwID0gZ2FtbWEwXzMyO1xuXHRcdFx0Z2FtbWExID0gZ2FtbWExXzMyO1xuXHRcdFx0c2lnbWEwID0gc2lnbWEwXzMyO1xuXHRcdFx0c2lnbWExID0gc2lnbWExXzMyO1xuXHRcdFx0bWFqID0gbWFqXzMyO1xuXHRcdFx0Y2ggPSBjaF8zMjtcblx0XHRcdEsgPSBbXG5cdFx0XHRcdFx0MHg0MjhBMkY5OCwgMHg3MTM3NDQ5MSwgMHhCNUMwRkJDRiwgMHhFOUI1REJBNSxcblx0XHRcdFx0XHQweDM5NTZDMjVCLCAweDU5RjExMUYxLCAweDkyM0Y4MkE0LCAweEFCMUM1RUQ1LFxuXHRcdFx0XHRcdDB4RDgwN0FBOTgsIDB4MTI4MzVCMDEsIDB4MjQzMTg1QkUsIDB4NTUwQzdEQzMsXG5cdFx0XHRcdFx0MHg3MkJFNUQ3NCwgMHg4MERFQjFGRSwgMHg5QkRDMDZBNywgMHhDMTlCRjE3NCxcblx0XHRcdFx0XHQweEU0OUI2OUMxLCAweEVGQkU0Nzg2LCAweDBGQzE5REM2LCAweDI0MENBMUNDLFxuXHRcdFx0XHRcdDB4MkRFOTJDNkYsIDB4NEE3NDg0QUEsIDB4NUNCMEE5REMsIDB4NzZGOTg4REEsXG5cdFx0XHRcdFx0MHg5ODNFNTE1MiwgMHhBODMxQzY2RCwgMHhCMDAzMjdDOCwgMHhCRjU5N0ZDNyxcblx0XHRcdFx0XHQweEM2RTAwQkYzLCAweEQ1QTc5MTQ3LCAweDA2Q0E2MzUxLCAweDE0MjkyOTY3LFxuXHRcdFx0XHRcdDB4MjdCNzBBODUsIDB4MkUxQjIxMzgsIDB4NEQyQzZERkMsIDB4NTMzODBEMTMsXG5cdFx0XHRcdFx0MHg2NTBBNzM1NCwgMHg3NjZBMEFCQiwgMHg4MUMyQzkyRSwgMHg5MjcyMkM4NSxcblx0XHRcdFx0XHQweEEyQkZFOEExLCAweEE4MUE2NjRCLCAweEMyNEI4QjcwLCAweEM3NkM1MUEzLFxuXHRcdFx0XHRcdDB4RDE5MkU4MTksIDB4RDY5OTA2MjQsIDB4RjQwRTM1ODUsIDB4MTA2QUEwNzAsXG5cdFx0XHRcdFx0MHgxOUE0QzExNiwgMHgxRTM3NkMwOCwgMHgyNzQ4Nzc0QywgMHgzNEIwQkNCNSxcblx0XHRcdFx0XHQweDM5MUMwQ0IzLCAweDRFRDhBQTRBLCAweDVCOUNDQTRGLCAweDY4MkU2RkYzLFxuXHRcdFx0XHRcdDB4NzQ4RjgyRUUsIDB4NzhBNTYzNkYsIDB4ODRDODc4MTQsIDB4OENDNzAyMDgsXG5cdFx0XHRcdFx0MHg5MEJFRkZGQSwgMHhBNDUwNkNFQiwgMHhCRUY5QTNGNywgMHhDNjcxNzhGMlxuXHRcdFx0XHRdO1xuXG5cdFx0XHRpZiAodmFyaWFudCA9PT0gXCJTSEEtMjI0XCIpXG5cdFx0XHR7XG5cdFx0XHRcdEggPSBbXG5cdFx0XHRcdFx0XHQweGMxMDU5ZWQ4LCAweDM2N2NkNTA3LCAweDMwNzBkZDE3LCAweGY3MGU1OTM5LFxuXHRcdFx0XHRcdFx0MHhmZmMwMGIzMSwgMHg2ODU4MTUxMSwgMHg2NGY5OGZhNywgMHhiZWZhNGZhNFxuXHRcdFx0XHRcdF07XG5cdFx0XHR9XG5cdFx0XHRlbHNlXG5cdFx0XHR7XG5cdFx0XHRcdEggPSBbXG5cdFx0XHRcdFx0XHQweDZBMDlFNjY3LCAweEJCNjdBRTg1LCAweDNDNkVGMzcyLCAweEE1NEZGNTNBLFxuXHRcdFx0XHRcdFx0MHg1MTBFNTI3RiwgMHg5QjA1Njg4QywgMHgxRjgzRDlBQiwgMHg1QkUwQ0QxOVxuXHRcdFx0XHRcdF07XG5cdFx0XHR9XG5cdFx0fVxuXHRcdGVsc2UgaWYgKHZhcmlhbnQgPT09IFwiU0hBLTM4NFwiIHx8IHZhcmlhbnQgPT09IFwiU0hBLTUxMlwiKVxuXHRcdHtcblx0XHRcdC8qIDY0LWJpdCB2YXJpYW50ICovXG5cdFx0XHRudW1Sb3VuZHMgPSA4MDtcblx0XHRcdGxlbmd0aFBvc2l0aW9uID0gKCgobWVzc2FnZUxlbiArIDEyOCkgPj4gMTApIDw8IDUpICsgMzE7XG5cdFx0XHRiaW5hcnlTdHJpbmdJbmMgPSAzMjtcblx0XHRcdGJpbmFyeVN0cmluZ011bHQgPSAyO1xuXHRcdFx0SW50ID0gSW50XzY0O1xuXHRcdFx0c2FmZUFkZF8yID0gc2FmZUFkZF82NF8yO1xuXHRcdFx0c2FmZUFkZF80ID0gc2FmZUFkZF82NF80O1xuXHRcdFx0c2FmZUFkZF81ID0gc2FmZUFkZF82NF81O1xuXHRcdFx0Z2FtbWEwID0gZ2FtbWEwXzY0O1xuXHRcdFx0Z2FtbWExID0gZ2FtbWExXzY0O1xuXHRcdFx0c2lnbWEwID0gc2lnbWEwXzY0O1xuXHRcdFx0c2lnbWExID0gc2lnbWExXzY0O1xuXHRcdFx0bWFqID0gbWFqXzY0O1xuXHRcdFx0Y2ggPSBjaF82NDtcblxuXHRcdFx0SyA9IFtcblx0XHRcdFx0bmV3IEludCgweDQyOGEyZjk4LCAweGQ3MjhhZTIyKSwgbmV3IEludCgweDcxMzc0NDkxLCAweDIzZWY2NWNkKSxcblx0XHRcdFx0bmV3IEludCgweGI1YzBmYmNmLCAweGVjNGQzYjJmKSwgbmV3IEludCgweGU5YjVkYmE1LCAweDgxODlkYmJjKSxcblx0XHRcdFx0bmV3IEludCgweDM5NTZjMjViLCAweGYzNDhiNTM4KSwgbmV3IEludCgweDU5ZjExMWYxLCAweGI2MDVkMDE5KSxcblx0XHRcdFx0bmV3IEludCgweDkyM2Y4MmE0LCAweGFmMTk0ZjliKSwgbmV3IEludCgweGFiMWM1ZWQ1LCAweGRhNmQ4MTE4KSxcblx0XHRcdFx0bmV3IEludCgweGQ4MDdhYTk4LCAweGEzMDMwMjQyKSwgbmV3IEludCgweDEyODM1YjAxLCAweDQ1NzA2ZmJlKSxcblx0XHRcdFx0bmV3IEludCgweDI0MzE4NWJlLCAweDRlZTRiMjhjKSwgbmV3IEludCgweDU1MGM3ZGMzLCAweGQ1ZmZiNGUyKSxcblx0XHRcdFx0bmV3IEludCgweDcyYmU1ZDc0LCAweGYyN2I4OTZmKSwgbmV3IEludCgweDgwZGViMWZlLCAweDNiMTY5NmIxKSxcblx0XHRcdFx0bmV3IEludCgweDliZGMwNmE3LCAweDI1YzcxMjM1KSwgbmV3IEludCgweGMxOWJmMTc0LCAweGNmNjkyNjk0KSxcblx0XHRcdFx0bmV3IEludCgweGU0OWI2OWMxLCAweDllZjE0YWQyKSwgbmV3IEludCgweGVmYmU0Nzg2LCAweDM4NGYyNWUzKSxcblx0XHRcdFx0bmV3IEludCgweDBmYzE5ZGM2LCAweDhiOGNkNWI1KSwgbmV3IEludCgweDI0MGNhMWNjLCAweDc3YWM5YzY1KSxcblx0XHRcdFx0bmV3IEludCgweDJkZTkyYzZmLCAweDU5MmIwMjc1KSwgbmV3IEludCgweDRhNzQ4NGFhLCAweDZlYTZlNDgzKSxcblx0XHRcdFx0bmV3IEludCgweDVjYjBhOWRjLCAweGJkNDFmYmQ0KSwgbmV3IEludCgweDc2Zjk4OGRhLCAweDgzMTE1M2I1KSxcblx0XHRcdFx0bmV3IEludCgweDk4M2U1MTUyLCAweGVlNjZkZmFiKSwgbmV3IEludCgweGE4MzFjNjZkLCAweDJkYjQzMjEwKSxcblx0XHRcdFx0bmV3IEludCgweGIwMDMyN2M4LCAweDk4ZmIyMTNmKSwgbmV3IEludCgweGJmNTk3ZmM3LCAweGJlZWYwZWU0KSxcblx0XHRcdFx0bmV3IEludCgweGM2ZTAwYmYzLCAweDNkYTg4ZmMyKSwgbmV3IEludCgweGQ1YTc5MTQ3LCAweDkzMGFhNzI1KSxcblx0XHRcdFx0bmV3IEludCgweDA2Y2E2MzUxLCAweGUwMDM4MjZmKSwgbmV3IEludCgweDE0MjkyOTY3LCAweDBhMGU2ZTcwKSxcblx0XHRcdFx0bmV3IEludCgweDI3YjcwYTg1LCAweDQ2ZDIyZmZjKSwgbmV3IEludCgweDJlMWIyMTM4LCAweDVjMjZjOTI2KSxcblx0XHRcdFx0bmV3IEludCgweDRkMmM2ZGZjLCAweDVhYzQyYWVkKSwgbmV3IEludCgweDUzMzgwZDEzLCAweDlkOTViM2RmKSxcblx0XHRcdFx0bmV3IEludCgweDY1MGE3MzU0LCAweDhiYWY2M2RlKSwgbmV3IEludCgweDc2NmEwYWJiLCAweDNjNzdiMmE4KSxcblx0XHRcdFx0bmV3IEludCgweDgxYzJjOTJlLCAweDQ3ZWRhZWU2KSwgbmV3IEludCgweDkyNzIyYzg1LCAweDE0ODIzNTNiKSxcblx0XHRcdFx0bmV3IEludCgweGEyYmZlOGExLCAweDRjZjEwMzY0KSwgbmV3IEludCgweGE4MWE2NjRiLCAweGJjNDIzMDAxKSxcblx0XHRcdFx0bmV3IEludCgweGMyNGI4YjcwLCAweGQwZjg5NzkxKSwgbmV3IEludCgweGM3NmM1MWEzLCAweDA2NTRiZTMwKSxcblx0XHRcdFx0bmV3IEludCgweGQxOTJlODE5LCAweGQ2ZWY1MjE4KSwgbmV3IEludCgweGQ2OTkwNjI0LCAweDU1NjVhOTEwKSxcblx0XHRcdFx0bmV3IEludCgweGY0MGUzNTg1LCAweDU3NzEyMDJhKSwgbmV3IEludCgweDEwNmFhMDcwLCAweDMyYmJkMWI4KSxcblx0XHRcdFx0bmV3IEludCgweDE5YTRjMTE2LCAweGI4ZDJkMGM4KSwgbmV3IEludCgweDFlMzc2YzA4LCAweDUxNDFhYjUzKSxcblx0XHRcdFx0bmV3IEludCgweDI3NDg3NzRjLCAweGRmOGVlYjk5KSwgbmV3IEludCgweDM0YjBiY2I1LCAweGUxOWI0OGE4KSxcblx0XHRcdFx0bmV3IEludCgweDM5MWMwY2IzLCAweGM1Yzk1YTYzKSwgbmV3IEludCgweDRlZDhhYTRhLCAweGUzNDE4YWNiKSxcblx0XHRcdFx0bmV3IEludCgweDViOWNjYTRmLCAweDc3NjNlMzczKSwgbmV3IEludCgweDY4MmU2ZmYzLCAweGQ2YjJiOGEzKSxcblx0XHRcdFx0bmV3IEludCgweDc0OGY4MmVlLCAweDVkZWZiMmZjKSwgbmV3IEludCgweDc4YTU2MzZmLCAweDQzMTcyZjYwKSxcblx0XHRcdFx0bmV3IEludCgweDg0Yzg3ODE0LCAweGExZjBhYjcyKSwgbmV3IEludCgweDhjYzcwMjA4LCAweDFhNjQzOWVjKSxcblx0XHRcdFx0bmV3IEludCgweDkwYmVmZmZhLCAweDIzNjMxZTI4KSwgbmV3IEludCgweGE0NTA2Y2ViLCAweGRlODJiZGU5KSxcblx0XHRcdFx0bmV3IEludCgweGJlZjlhM2Y3LCAweGIyYzY3OTE1KSwgbmV3IEludCgweGM2NzE3OGYyLCAweGUzNzI1MzJiKSxcblx0XHRcdFx0bmV3IEludCgweGNhMjczZWNlLCAweGVhMjY2MTljKSwgbmV3IEludCgweGQxODZiOGM3LCAweDIxYzBjMjA3KSxcblx0XHRcdFx0bmV3IEludCgweGVhZGE3ZGQ2LCAweGNkZTBlYjFlKSwgbmV3IEludCgweGY1N2Q0ZjdmLCAweGVlNmVkMTc4KSxcblx0XHRcdFx0bmV3IEludCgweDA2ZjA2N2FhLCAweDcyMTc2ZmJhKSwgbmV3IEludCgweDBhNjM3ZGM1LCAweGEyYzg5OGE2KSxcblx0XHRcdFx0bmV3IEludCgweDExM2Y5ODA0LCAweGJlZjkwZGFlKSwgbmV3IEludCgweDFiNzEwYjM1LCAweDEzMWM0NzFiKSxcblx0XHRcdFx0bmV3IEludCgweDI4ZGI3N2Y1LCAweDIzMDQ3ZDg0KSwgbmV3IEludCgweDMyY2FhYjdiLCAweDQwYzcyNDkzKSxcblx0XHRcdFx0bmV3IEludCgweDNjOWViZTBhLCAweDE1YzliZWJjKSwgbmV3IEludCgweDQzMWQ2N2M0LCAweDljMTAwZDRjKSxcblx0XHRcdFx0bmV3IEludCgweDRjYzVkNGJlLCAweGNiM2U0MmI2KSwgbmV3IEludCgweDU5N2YyOTljLCAweGZjNjU3ZTJhKSxcblx0XHRcdFx0bmV3IEludCgweDVmY2I2ZmFiLCAweDNhZDZmYWVjKSwgbmV3IEludCgweDZjNDQxOThjLCAweDRhNDc1ODE3KVxuXHRcdFx0XTtcblxuXHRcdFx0aWYgKHZhcmlhbnQgPT09IFwiU0hBLTM4NFwiKVxuXHRcdFx0e1xuXHRcdFx0XHRIID0gW1xuXHRcdFx0XHRcdG5ldyBJbnQoMHhjYmJiOWQ1ZCwgMHhjMTA1OWVkOCksIG5ldyBJbnQoMHgwNjI5YTI5MmEsIDB4MzY3Y2Q1MDcpLFxuXHRcdFx0XHRcdG5ldyBJbnQoMHg5MTU5MDE1YSwgMHgzMDcwZGQxNyksIG5ldyBJbnQoMHgwMTUyZmVjZDgsIDB4ZjcwZTU5MzkpLFxuXHRcdFx0XHRcdG5ldyBJbnQoMHg2NzMzMjY2NywgMHhmZmMwMGIzMSksIG5ldyBJbnQoMHg5OGViNDRhODcsIDB4Njg1ODE1MTEpLFxuXHRcdFx0XHRcdG5ldyBJbnQoMHhkYjBjMmUwZCwgMHg2NGY5OGZhNyksIG5ldyBJbnQoMHgwNDdiNTQ4MWQsIDB4YmVmYTRmYTQpXG5cdFx0XHRcdF07XG5cdFx0XHR9XG5cdFx0XHRlbHNlXG5cdFx0XHR7XG5cdFx0XHRcdEggPSBbXG5cdFx0XHRcdFx0bmV3IEludCgweDZhMDllNjY3LCAweGYzYmNjOTA4KSwgbmV3IEludCgweGJiNjdhZTg1LCAweDg0Y2FhNzNiKSxcblx0XHRcdFx0XHRuZXcgSW50KDB4M2M2ZWYzNzIsIDB4ZmU5NGY4MmIpLCBuZXcgSW50KDB4YTU0ZmY1M2EsIDB4NWYxZDM2ZjEpLFxuXHRcdFx0XHRcdG5ldyBJbnQoMHg1MTBlNTI3ZiwgMHhhZGU2ODJkMSksIG5ldyBJbnQoMHg5YjA1Njg4YywgMHgyYjNlNmMxZiksXG5cdFx0XHRcdFx0bmV3IEludCgweDFmODNkOWFiLCAweGZiNDFiZDZiKSwgbmV3IEludCgweDViZTBjZDE5LCAweDEzN2UyMTc5KVxuXHRcdFx0XHRdO1xuXHRcdFx0fVxuXHRcdH1cblxuXHRcdC8qIEFwcGVuZCAnMScgYXQgdGhlIGVuZCBvZiB0aGUgYmluYXJ5IHN0cmluZyAqL1xuXHRcdG1lc3NhZ2VbbWVzc2FnZUxlbiA+PiA1XSB8PSAweDgwIDw8ICgyNCAtIG1lc3NhZ2VMZW4gJSAzMik7XG5cdFx0LyogQXBwZW5kIGxlbmd0aCBvZiBiaW5hcnkgc3RyaW5nIGluIHRoZSBwb3NpdGlvbiBzdWNoIHRoYXQgdGhlIG5ld1xuXHRcdCAqIGxlbmd0aCBpcyBjb3JyZWN0ICovXG5cdFx0bWVzc2FnZVtsZW5ndGhQb3NpdGlvbl0gPSBtZXNzYWdlTGVuO1xuXG5cdFx0YXBwZW5kZWRNZXNzYWdlTGVuZ3RoID0gbWVzc2FnZS5sZW5ndGg7XG5cblx0XHRmb3IgKGkgPSAwOyBpIDwgYXBwZW5kZWRNZXNzYWdlTGVuZ3RoOyBpICs9IGJpbmFyeVN0cmluZ0luYylcblx0XHR7XG5cdFx0XHRhID0gSFswXTtcblx0XHRcdGIgPSBIWzFdO1xuXHRcdFx0YyA9IEhbMl07XG5cdFx0XHRkID0gSFszXTtcblx0XHRcdGUgPSBIWzRdO1xuXHRcdFx0ZiA9IEhbNV07XG5cdFx0XHRnID0gSFs2XTtcblx0XHRcdGggPSBIWzddO1xuXG5cdFx0XHRmb3IgKHQgPSAwOyB0IDwgbnVtUm91bmRzOyB0ICs9IDEpXG5cdFx0XHR7XG5cdFx0XHRcdGlmICh0IDwgMTYpXG5cdFx0XHRcdHtcblx0XHRcdFx0XHQvKiBCaXQgb2YgYSBoYWNrIC0gZm9yIDMyLWJpdCwgdGhlIHNlY29uZCB0ZXJtIGlzIGlnbm9yZWQgKi9cblx0XHRcdFx0XHRXW3RdID0gbmV3IEludChtZXNzYWdlW3QgKiBiaW5hcnlTdHJpbmdNdWx0ICsgaV0sXG5cdFx0XHRcdFx0XHRcdG1lc3NhZ2VbdCAqIGJpbmFyeVN0cmluZ011bHQgKyBpICsgMV0pO1xuXHRcdFx0XHR9XG5cdFx0XHRcdGVsc2Vcblx0XHRcdFx0e1xuXHRcdFx0XHRcdFdbdF0gPSBzYWZlQWRkXzQoXG5cdFx0XHRcdFx0XHRcdGdhbW1hMShXW3QgLSAyXSksIFdbdCAtIDddLFxuXHRcdFx0XHRcdFx0XHRnYW1tYTAoV1t0IC0gMTVdKSwgV1t0IC0gMTZdXG5cdFx0XHRcdFx0XHQpO1xuXHRcdFx0XHR9XG5cblx0XHRcdFx0VDEgPSBzYWZlQWRkXzUoaCwgc2lnbWExKGUpLCBjaChlLCBmLCBnKSwgS1t0XSwgV1t0XSk7XG5cdFx0XHRcdFQyID0gc2FmZUFkZF8yKHNpZ21hMChhKSwgbWFqKGEsIGIsIGMpKTtcblx0XHRcdFx0aCA9IGc7XG5cdFx0XHRcdGcgPSBmO1xuXHRcdFx0XHRmID0gZTtcblx0XHRcdFx0ZSA9IHNhZmVBZGRfMihkLCBUMSk7XG5cdFx0XHRcdGQgPSBjO1xuXHRcdFx0XHRjID0gYjtcblx0XHRcdFx0YiA9IGE7XG5cdFx0XHRcdGEgPSBzYWZlQWRkXzIoVDEsIFQyKTtcblx0XHRcdH1cblxuXHRcdFx0SFswXSA9IHNhZmVBZGRfMihhLCBIWzBdKTtcblx0XHRcdEhbMV0gPSBzYWZlQWRkXzIoYiwgSFsxXSk7XG5cdFx0XHRIWzJdID0gc2FmZUFkZF8yKGMsIEhbMl0pO1xuXHRcdFx0SFszXSA9IHNhZmVBZGRfMihkLCBIWzNdKTtcblx0XHRcdEhbNF0gPSBzYWZlQWRkXzIoZSwgSFs0XSk7XG5cdFx0XHRIWzVdID0gc2FmZUFkZF8yKGYsIEhbNV0pO1xuXHRcdFx0SFs2XSA9IHNhZmVBZGRfMihnLCBIWzZdKTtcblx0XHRcdEhbN10gPSBzYWZlQWRkXzIoaCwgSFs3XSk7XG5cdFx0fVxuXG5cdFx0c3dpdGNoICh2YXJpYW50KVxuXHRcdHtcblx0XHRjYXNlIFwiU0hBLTIyNFwiOlxuXHRcdFx0cmV0dXJuXHRbXG5cdFx0XHRcdEhbMF0sIEhbMV0sIEhbMl0sIEhbM10sXG5cdFx0XHRcdEhbNF0sIEhbNV0sIEhbNl1cblx0XHRcdF07XG5cdFx0Y2FzZSBcIlNIQS0yNTZcIjpcblx0XHRcdHJldHVybiBIO1xuXHRcdGNhc2UgXCJTSEEtMzg0XCI6XG5cdFx0XHRyZXR1cm4gW1xuXHRcdFx0XHRIWzBdLmhpZ2hPcmRlciwgSFswXS5sb3dPcmRlcixcblx0XHRcdFx0SFsxXS5oaWdoT3JkZXIsIEhbMV0ubG93T3JkZXIsXG5cdFx0XHRcdEhbMl0uaGlnaE9yZGVyLCBIWzJdLmxvd09yZGVyLFxuXHRcdFx0XHRIWzNdLmhpZ2hPcmRlciwgSFszXS5sb3dPcmRlcixcblx0XHRcdFx0SFs0XS5oaWdoT3JkZXIsIEhbNF0ubG93T3JkZXIsXG5cdFx0XHRcdEhbNV0uaGlnaE9yZGVyLCBIWzVdLmxvd09yZGVyXG5cdFx0XHRdO1xuXHRcdGNhc2UgXCJTSEEtNTEyXCI6XG5cdFx0XHRyZXR1cm4gW1xuXHRcdFx0XHRIWzBdLmhpZ2hPcmRlciwgSFswXS5sb3dPcmRlcixcblx0XHRcdFx0SFsxXS5oaWdoT3JkZXIsIEhbMV0ubG93T3JkZXIsXG5cdFx0XHRcdEhbMl0uaGlnaE9yZGVyLCBIWzJdLmxvd09yZGVyLFxuXHRcdFx0XHRIWzNdLmhpZ2hPcmRlciwgSFszXS5sb3dPcmRlcixcblx0XHRcdFx0SFs0XS5oaWdoT3JkZXIsIEhbNF0ubG93T3JkZXIsXG5cdFx0XHRcdEhbNV0uaGlnaE9yZGVyLCBIWzVdLmxvd09yZGVyLFxuXHRcdFx0XHRIWzZdLmhpZ2hPcmRlciwgSFs2XS5sb3dPcmRlcixcblx0XHRcdFx0SFs3XS5oaWdoT3JkZXIsIEhbN10ubG93T3JkZXJcblx0XHRcdF07XG5cdFx0ZGVmYXVsdDpcblx0XHRcdC8qIFRoaXMgc2hvdWxkIG5ldmVyIGJlIHJlYWNoZWQgKi9cblx0XHRcdHJldHVybiBbXTsgXG5cdFx0fVxuXHR9LFxuXG5cdC8qXG5cdCAqIGpzU0hBIGlzIHRoZSB3b3JraG9yc2Ugb2YgdGhlIGxpYnJhcnkuICBJbnN0YW50aWF0ZSBpdCB3aXRoIHRoZSBzdHJpbmcgdG9cblx0ICogYmUgaGFzaGVkIGFzIHRoZSBwYXJhbWV0ZXJcblx0ICpcblx0ICogQGNvbnN0cnVjdG9yXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBzcmNTdHJpbmcgVGhlIHN0cmluZyB0byBiZSBoYXNoZWRcblx0ICogQHBhcmFtIHtTdHJpbmd9IGlucHV0Rm9ybWF0IFRoZSBmb3JtYXQgb2Ygc3JjU3RyaW5nLCBBU0NJSSBvciBIRVhcblx0ICovXG5cdGpzU0hBID0gZnVuY3Rpb24gKHNyY1N0cmluZywgaW5wdXRGb3JtYXQpXG5cdHtcblxuXHRcdHRoaXMuc2hhMSA9IG51bGw7XG5cdFx0dGhpcy5zaGEyMjQgPSBudWxsO1xuXHRcdHRoaXMuc2hhMjU2ID0gbnVsbDtcblx0XHR0aGlzLnNoYTM4NCA9IG51bGw7XG5cdFx0dGhpcy5zaGE1MTIgPSBudWxsO1xuXG5cdFx0dGhpcy5zdHJCaW5MZW4gPSBudWxsO1xuXHRcdHRoaXMuc3RyVG9IYXNoID0gbnVsbDtcblxuXHRcdC8qIENvbnZlcnQgdGhlIGlucHV0IHN0cmluZyBpbnRvIHRoZSBjb3JyZWN0IHR5cGUgKi9cblx0XHRpZiAoXCJIRVhcIiA9PT0gaW5wdXRGb3JtYXQpXG5cdFx0e1xuXHRcdFx0aWYgKDAgIT09IChzcmNTdHJpbmcubGVuZ3RoICUgMikpXG5cdFx0XHR7XG5cdFx0XHRcdHJldHVybiBcIlRFWFQgTVVTVCBCRSBJTiBCWVRFIElOQ1JFTUVOVFNcIjtcblx0XHRcdH1cblx0XHRcdHRoaXMuc3RyQmluTGVuID0gc3JjU3RyaW5nLmxlbmd0aCAqIDQ7XG5cdFx0XHR0aGlzLnN0clRvSGFzaCA9IGhleDJiaW5iKHNyY1N0cmluZyk7XG5cdFx0fVxuXHRcdGVsc2UgaWYgKChcIkFTQ0lJXCIgPT09IGlucHV0Rm9ybWF0KSB8fFxuXHRcdFx0ICgndW5kZWZpbmVkJyA9PT0gdHlwZW9mKGlucHV0Rm9ybWF0KSkpXG5cdFx0e1xuXHRcdFx0dGhpcy5zdHJCaW5MZW4gPSBzcmNTdHJpbmcubGVuZ3RoICogY2hhclNpemU7XG5cdFx0XHR0aGlzLnN0clRvSGFzaCA9IHN0cjJiaW5iKHNyY1N0cmluZyk7XG5cdFx0fVxuXHRcdGVsc2Vcblx0XHR7XG5cdFx0XHRyZXR1cm4gXCJVTktOT1dOIFRFWFQgSU5QVVQgVFlQRVwiO1xuXHRcdH1cblx0fTtcblxuXHRqc1NIQS5wcm90b3R5cGUgPSB7XG5cdFx0Lypcblx0XHQgKiBSZXR1cm5zIHRoZSBkZXNpcmVkIFNIQSBoYXNoIG9mIHRoZSBzdHJpbmcgc3BlY2lmaWVkIGF0IGluc3RhbnRpYXRpb25cblx0XHQgKiB1c2luZyB0aGUgc3BlY2lmaWVkIHBhcmFtZXRlcnNcblx0XHQgKlxuXHRcdCAqIEBwYXJhbSB7U3RyaW5nfSB2YXJpYW50IFRoZSBkZXNpcmVkIFNIQSB2YXJpYW50IChTSEEtMSwgU0hBLTIyNCxcblx0XHQgKlx0IFNIQS0yNTYsIFNIQS0zODQsIG9yIFNIQS01MTIpXG5cdFx0ICogQHBhcmFtIHtTdHJpbmd9IGZvcm1hdCBUaGUgZGVzaXJlZCBvdXRwdXQgZm9ybWF0dGluZyAoQjY0IG9yIEhFWClcblx0XHQgKiBAcmV0dXJuIFRoZSBzdHJpbmcgcmVwcmVzZW50YXRpb24gb2YgdGhlIGhhc2ggaW4gdGhlIGZvcm1hdCBzcGVjaWZpZWRcblx0XHQgKi9cblx0XHRnZXRIYXNoIDogZnVuY3Rpb24gKHZhcmlhbnQsIGZvcm1hdClcblx0XHR7XG5cdFx0XHR2YXIgZm9ybWF0RnVuYyA9IG51bGwsIG1lc3NhZ2UgPSB0aGlzLnN0clRvSGFzaC5zbGljZSgpO1xuXG5cdFx0XHRzd2l0Y2ggKGZvcm1hdClcblx0XHRcdHtcblx0XHRcdGNhc2UgXCJIRVhcIjpcblx0XHRcdFx0Zm9ybWF0RnVuYyA9IGJpbmIyaGV4O1xuXHRcdFx0XHRicmVhaztcblx0XHRcdGNhc2UgXCJCNjRcIjpcblx0XHRcdFx0Zm9ybWF0RnVuYyA9IGJpbmIyYjY0O1xuXHRcdFx0XHRicmVhaztcblx0XHRcdGNhc2UgXCJBU0NJSVwiOlxuXHRcdFx0XHRmb3JtYXRGdW5jID0gYmluYjJzdHI7XG5cdFx0XHRcdGJyZWFrO1xuXHRcdFx0ZGVmYXVsdDpcblx0XHRcdFx0cmV0dXJuIFwiRk9STUFUIE5PVCBSRUNPR05JWkVEXCI7XG5cdFx0XHR9XG5cblx0XHRcdHN3aXRjaCAodmFyaWFudClcblx0XHRcdHtcblx0XHRcdGNhc2UgXCJTSEEtMVwiOlxuXHRcdFx0XHRpZiAobnVsbCA9PT0gdGhpcy5zaGExKVxuXHRcdFx0XHR7XG5cdFx0XHRcdFx0dGhpcy5zaGExID0gY29yZVNIQTEobWVzc2FnZSwgdGhpcy5zdHJCaW5MZW4pO1xuXHRcdFx0XHR9XG5cdFx0XHRcdHJldHVybiBmb3JtYXRGdW5jKHRoaXMuc2hhMSk7XG5cdFx0XHRjYXNlIFwiU0hBLTIyNFwiOlxuXHRcdFx0XHRpZiAobnVsbCA9PT0gdGhpcy5zaGEyMjQpXG5cdFx0XHRcdHtcblx0XHRcdFx0XHR0aGlzLnNoYTIyNCA9IGNvcmVTSEEyKG1lc3NhZ2UsIHRoaXMuc3RyQmluTGVuLCB2YXJpYW50KTtcblx0XHRcdFx0fVxuXHRcdFx0XHRyZXR1cm4gZm9ybWF0RnVuYyh0aGlzLnNoYTIyNCk7XG5cdFx0XHRjYXNlIFwiU0hBLTI1NlwiOlxuXHRcdFx0XHRpZiAobnVsbCA9PT0gdGhpcy5zaGEyNTYpXG5cdFx0XHRcdHtcblx0XHRcdFx0XHR0aGlzLnNoYTI1NiA9IGNvcmVTSEEyKG1lc3NhZ2UsIHRoaXMuc3RyQmluTGVuLCB2YXJpYW50KTtcblx0XHRcdFx0fVxuXHRcdFx0XHRyZXR1cm4gZm9ybWF0RnVuYyh0aGlzLnNoYTI1Nik7XG5cdFx0XHRjYXNlIFwiU0hBLTM4NFwiOlxuXHRcdFx0XHRpZiAobnVsbCA9PT0gdGhpcy5zaGEzODQpXG5cdFx0XHRcdHtcblx0XHRcdFx0XHR0aGlzLnNoYTM4NCA9IGNvcmVTSEEyKG1lc3NhZ2UsIHRoaXMuc3RyQmluTGVuLCB2YXJpYW50KTtcblx0XHRcdFx0fVxuXHRcdFx0XHRyZXR1cm4gZm9ybWF0RnVuYyh0aGlzLnNoYTM4NCk7XG5cdFx0XHRjYXNlIFwiU0hBLTUxMlwiOlxuXHRcdFx0XHRpZiAobnVsbCA9PT0gdGhpcy5zaGE1MTIpXG5cdFx0XHRcdHtcblx0XHRcdFx0XHR0aGlzLnNoYTUxMiA9IGNvcmVTSEEyKG1lc3NhZ2UsIHRoaXMuc3RyQmluTGVuLCB2YXJpYW50KTtcblx0XHRcdFx0fVxuXHRcdFx0XHRyZXR1cm4gZm9ybWF0RnVuYyh0aGlzLnNoYTUxMik7XG5cdFx0XHRkZWZhdWx0OlxuXHRcdFx0XHRyZXR1cm4gXCJIQVNIIE5PVCBSRUNPR05JWkVEXCI7XG5cdFx0XHR9XG5cdFx0fSxcblxuXHRcdC8qXG5cdFx0ICogUmV0dXJucyB0aGUgZGVzaXJlZCBITUFDIG9mIHRoZSBzdHJpbmcgc3BlY2lmaWVkIGF0IGluc3RhbnRpYXRpb25cblx0XHQgKiB1c2luZyB0aGUga2V5IGFuZCB2YXJpYW50IHBhcmFtLlxuXHRcdCAqXG5cdFx0ICogQHBhcmFtIHtTdHJpbmd9IGtleSBUaGUga2V5IHVzZWQgdG8gY2FsY3VsYXRlIHRoZSBITUFDXG5cdFx0ICogQHBhcmFtIHtTdHJpbmd9IGlucHV0Rm9ybWF0IFRoZSBmb3JtYXQgb2Yga2V5LCBBU0NJSSBvciBIRVhcblx0XHQgKiBAcGFyYW0ge1N0cmluZ30gdmFyaWFudCBUaGUgZGVzaXJlZCBTSEEgdmFyaWFudCAoU0hBLTEsIFNIQS0yMjQsXG5cdFx0ICpcdCBTSEEtMjU2LCBTSEEtMzg0LCBvciBTSEEtNTEyKVxuXHRcdCAqIEBwYXJhbSB7U3RyaW5nfSBvdXRwdXRGb3JtYXQgVGhlIGRlc2lyZWQgb3V0cHV0IGZvcm1hdHRpbmdcblx0XHQgKlx0IChCNjQgb3IgSEVYKVxuXHRcdCAqIEByZXR1cm4gVGhlIHN0cmluZyByZXByZXNlbnRhdGlvbiBvZiB0aGUgaGFzaCBpbiB0aGUgZm9ybWF0IHNwZWNpZmllZFxuXHRcdCAqL1xuXHRcdGdldEhNQUMgOiBmdW5jdGlvbiAoa2V5LCBpbnB1dEZvcm1hdCwgdmFyaWFudCwgb3V0cHV0Rm9ybWF0KVxuXHRcdHtcblx0XHRcdHZhciBmb3JtYXRGdW5jLCBrZXlUb1VzZSwgYmxvY2tCeXRlU2l6ZSwgYmxvY2tCaXRTaXplLCBpLFxuXHRcdFx0XHRyZXRWYWwsIGxhc3RBcnJheUluZGV4LCBrZXlCaW5MZW4sIGhhc2hCaXRTaXplLFxuXHRcdFx0XHRrZXlXaXRoSVBhZCA9IFtdLCBrZXlXaXRoT1BhZCA9IFtdO1xuXG5cdFx0XHQvKiBWYWxpZGF0ZSB0aGUgb3V0cHV0IGZvcm1hdCBzZWxlY3Rpb24gKi9cblx0XHRcdHN3aXRjaCAob3V0cHV0Rm9ybWF0KVxuXHRcdFx0e1xuXHRcdFx0Y2FzZSBcIkhFWFwiOlxuXHRcdFx0XHRmb3JtYXRGdW5jID0gYmluYjJoZXg7XG5cdFx0XHRcdGJyZWFrO1xuXHRcdFx0Y2FzZSBcIkI2NFwiOlxuXHRcdFx0XHRmb3JtYXRGdW5jID0gYmluYjJiNjQ7XG5cdFx0XHRcdGJyZWFrO1xuXHRcdFx0Y2FzZSBcIkFTQ0lJXCI6XG5cdFx0XHRcdGZvcm1hdEZ1bmMgPSBiaW5iMnN0cjtcblx0XHRcdFx0YnJlYWs7XG5cdFx0XHRkZWZhdWx0OlxuXHRcdFx0XHRyZXR1cm4gXCJGT1JNQVQgTk9UIFJFQ09HTklaRURcIjtcblx0XHRcdH1cblxuXHRcdFx0LyogVmFsaWRhdGUgdGhlIGhhc2ggdmFyaWFudCBzZWxlY3Rpb24gYW5kIHNldCBuZWVkZWQgdmFyaWFibGVzICovXG5cdFx0XHRzd2l0Y2ggKHZhcmlhbnQpXG5cdFx0XHR7XG5cdFx0XHRjYXNlIFwiU0hBLTFcIjpcblx0XHRcdFx0YmxvY2tCeXRlU2l6ZSA9IDY0O1xuXHRcdFx0XHRoYXNoQml0U2l6ZSA9IDE2MDtcblx0XHRcdFx0YnJlYWs7XG5cdFx0XHRjYXNlIFwiU0hBLTIyNFwiOlxuXHRcdFx0XHRibG9ja0J5dGVTaXplID0gNjQ7XG5cdFx0XHRcdGhhc2hCaXRTaXplID0gMjI0O1xuXHRcdFx0XHRicmVhaztcblx0XHRcdGNhc2UgXCJTSEEtMjU2XCI6XG5cdFx0XHRcdGJsb2NrQnl0ZVNpemUgPSA2NDtcblx0XHRcdFx0aGFzaEJpdFNpemUgPSAyNTY7XG5cdFx0XHRcdGJyZWFrO1xuXHRcdFx0Y2FzZSBcIlNIQS0zODRcIjpcblx0XHRcdFx0YmxvY2tCeXRlU2l6ZSA9IDEyODtcblx0XHRcdFx0aGFzaEJpdFNpemUgPSAzODQ7XG5cdFx0XHRcdGJyZWFrO1xuXHRcdFx0Y2FzZSBcIlNIQS01MTJcIjpcblx0XHRcdFx0YmxvY2tCeXRlU2l6ZSA9IDEyODtcblx0XHRcdFx0aGFzaEJpdFNpemUgPSA1MTI7XG5cdFx0XHRcdGJyZWFrO1xuXHRcdFx0ZGVmYXVsdDpcblx0XHRcdFx0cmV0dXJuIFwiSEFTSCBOT1QgUkVDT0dOSVpFRFwiO1xuXHRcdFx0fVxuXG5cdFx0XHQvKiBWYWxpZGF0ZSBpbnB1dCBmb3JtYXQgc2VsZWN0aW9uICovXG5cdFx0XHRpZiAoXCJIRVhcIiA9PT0gaW5wdXRGb3JtYXQpXG5cdFx0XHR7XG5cdFx0XHRcdC8qIE5pYmJsZXMgbXVzdCBjb21lIGluIHBhaXJzICovXG5cdFx0XHRcdGlmICgwICE9PSAoa2V5Lmxlbmd0aCAlIDIpKVxuXHRcdFx0XHR7XG5cdFx0XHRcdFx0cmV0dXJuIFwiS0VZIE1VU1QgQkUgSU4gQllURSBJTkNSRU1FTlRTXCI7XG5cdFx0XHRcdH1cblx0XHRcdFx0a2V5VG9Vc2UgPSBoZXgyYmluYihrZXkpO1xuXHRcdFx0XHRrZXlCaW5MZW4gPSBrZXkubGVuZ3RoICogNDtcblx0XHRcdH1cblx0XHRcdGVsc2UgaWYgKFwiQVNDSUlcIiA9PT0gaW5wdXRGb3JtYXQpXG5cdFx0XHR7XG5cdFx0XHRcdGtleVRvVXNlID0gc3RyMmJpbmIoa2V5KTtcblx0XHRcdFx0a2V5QmluTGVuID0ga2V5Lmxlbmd0aCAqIGNoYXJTaXplO1xuXHRcdFx0fVxuXHRcdFx0ZWxzZVxuXHRcdFx0e1xuXHRcdFx0XHRyZXR1cm4gXCJVTktOT1dOIEtFWSBJTlBVVCBUWVBFXCI7XG5cdFx0XHR9XG5cblx0XHRcdC8qIFRoZXNlIGFyZSB1c2VkIG11bHRpcGxlIHRpbWVzLCBjYWxjdWxhdGUgYW5kIHN0b3JlIHRoZW0gKi9cblx0XHRcdGJsb2NrQml0U2l6ZSA9IGJsb2NrQnl0ZVNpemUgKiA4O1xuXHRcdFx0bGFzdEFycmF5SW5kZXggPSAoYmxvY2tCeXRlU2l6ZSAvIDQpIC0gMTtcblxuXHRcdFx0LyogRmlndXJlIG91dCB3aGF0IHRvIGRvIHdpdGggdGhlIGtleSBiYXNlZCBvbiBpdHMgc2l6ZSByZWxhdGl2ZSB0b1xuXHRcdFx0ICogdGhlIGhhc2gncyBibG9jayBzaXplICovXG5cdFx0XHRpZiAoYmxvY2tCeXRlU2l6ZSA8IChrZXlCaW5MZW4gLyA4KSlcblx0XHRcdHtcblx0XHRcdFx0aWYgKFwiU0hBLTFcIiA9PT0gdmFyaWFudClcblx0XHRcdFx0e1xuXHRcdFx0XHRcdGtleVRvVXNlID0gY29yZVNIQTEoa2V5VG9Vc2UsIGtleUJpbkxlbik7XG5cdFx0XHRcdH1cblx0XHRcdFx0ZWxzZVxuXHRcdFx0XHR7XG5cdFx0XHRcdFx0a2V5VG9Vc2UgPSBjb3JlU0hBMihrZXlUb1VzZSwga2V5QmluTGVuLCB2YXJpYW50KTtcblx0XHRcdFx0fVxuXHRcdFx0XHQvKiBGb3IgYWxsIHZhcmlhbnRzLCB0aGUgYmxvY2sgc2l6ZSBpcyBiaWdnZXIgdGhhbiB0aGUgb3V0cHV0XG5cdFx0XHRcdCAqIHNpemUgc28gdGhlcmUgd2lsbCBuZXZlciBiZSBhIHVzZWZ1bCBieXRlIGF0IHRoZSBlbmQgb2YgdGhlXG5cdFx0XHRcdCAqIHN0cmluZyAqL1xuXHRcdFx0XHRrZXlUb1VzZVtsYXN0QXJyYXlJbmRleF0gJj0gMHhGRkZGRkYwMDtcblx0XHRcdH1cblx0XHRcdGVsc2UgaWYgKGJsb2NrQnl0ZVNpemUgPiAoa2V5QmluTGVuIC8gOCkpXG5cdFx0XHR7XG5cdFx0XHRcdC8qIElmIHRoZSBibG9ja0J5dGVTaXplIGlzIGdyZWF0ZXIgdGhhbiB0aGUga2V5IGxlbmd0aCwgdGhlcmVcblx0XHRcdFx0ICogd2lsbCBhbHdheXMgYmUgYXQgTEVBU1Qgb25lIFwidXNlbGVzc1wiIGJ5dGUgYXQgdGhlIGVuZCBvZiB0aGVcblx0XHRcdFx0ICogc3RyaW5nICovXG5cdFx0XHRcdGtleVRvVXNlW2xhc3RBcnJheUluZGV4XSAmPSAweEZGRkZGRjAwO1xuXHRcdFx0fVxuXG5cdFx0XHQvKiBDcmVhdGUgaXBhZCBhbmQgb3BhZCAqL1xuXHRcdFx0Zm9yIChpID0gMDsgaSA8PSBsYXN0QXJyYXlJbmRleDsgaSArPSAxKVxuXHRcdFx0e1xuXHRcdFx0XHRrZXlXaXRoSVBhZFtpXSA9IGtleVRvVXNlW2ldIF4gMHgzNjM2MzYzNjtcblx0XHRcdFx0a2V5V2l0aE9QYWRbaV0gPSBrZXlUb1VzZVtpXSBeIDB4NUM1QzVDNUM7XG5cdFx0XHR9XG5cblx0XHRcdC8qIENhbGN1bGF0ZSB0aGUgSE1BQyAqL1xuXHRcdFx0aWYgKFwiU0hBLTFcIiA9PT0gdmFyaWFudClcblx0XHRcdHtcblx0XHRcdFx0cmV0VmFsID0gY29yZVNIQTEoXG5cdFx0XHRcdFx0XHRcdGtleVdpdGhJUGFkLmNvbmNhdCh0aGlzLnN0clRvSGFzaCksXG5cdFx0XHRcdFx0XHRcdGJsb2NrQml0U2l6ZSArIHRoaXMuc3RyQmluTGVuKTtcblx0XHRcdFx0cmV0VmFsID0gY29yZVNIQTEoXG5cdFx0XHRcdFx0XHRcdGtleVdpdGhPUGFkLmNvbmNhdChyZXRWYWwpLFxuXHRcdFx0XHRcdFx0XHRibG9ja0JpdFNpemUgKyBoYXNoQml0U2l6ZSk7XG5cdFx0XHR9XG5cdFx0XHRlbHNlXG5cdFx0XHR7XG5cdFx0XHRcdHJldFZhbCA9IGNvcmVTSEEyKFxuXHRcdFx0XHRcdFx0XHRrZXlXaXRoSVBhZC5jb25jYXQodGhpcy5zdHJUb0hhc2gpLFxuXHRcdFx0XHRcdFx0XHRibG9ja0JpdFNpemUgKyB0aGlzLnN0ckJpbkxlbiwgdmFyaWFudCk7XG5cdFx0XHRcdHJldFZhbCA9IGNvcmVTSEEyKFxuXHRcdFx0XHRcdFx0XHRrZXlXaXRoT1BhZC5jb25jYXQocmV0VmFsKSxcblx0XHRcdFx0XHRcdFx0YmxvY2tCaXRTaXplICsgaGFzaEJpdFNpemUsIHZhcmlhbnQpO1xuXHRcdFx0fVxuXG5cdFx0XHRyZXR1cm4gKGZvcm1hdEZ1bmMocmV0VmFsKSk7XG5cdFx0fVxuXHR9O1xuXG5cdHJldHVybiBqc1NIQTtcbn0oKSk7XG5cbm1vZHVsZS5leHBvcnRzID0ge1xuXHRzaGExOiBmdW5jdGlvbihzdHIpIHtcblx0XHR2YXIgc2hhT2JqID0gbmV3IGpzU0hBKHN0ciwgXCJBU0NJSVwiKTtcblx0XHRyZXR1cm4gc2hhT2JqLmdldEhhc2goXCJTSEEtMVwiLCBcIkFTQ0lJXCIpO1xuXHR9LFxuXHRzaGEyMjQ6IGZ1bmN0aW9uKHN0cikge1xuXHRcdHZhciBzaGFPYmogPSBuZXcganNTSEEoc3RyLCBcIkFTQ0lJXCIpO1xuXHRcdHJldHVybiBzaGFPYmouZ2V0SGFzaChcIlNIQS0yMjRcIiwgXCJBU0NJSVwiKTtcblx0fSxcblx0c2hhMjU2OiBmdW5jdGlvbihzdHIpIHtcblx0XHR2YXIgc2hhT2JqID0gbmV3IGpzU0hBKHN0ciwgXCJBU0NJSVwiKTtcblx0XHRyZXR1cm4gc2hhT2JqLmdldEhhc2goXCJTSEEtMjU2XCIsIFwiQVNDSUlcIik7XG5cdH0sXG5cdHNoYTM4NDogZnVuY3Rpb24oc3RyKSB7XG5cdFx0dmFyIHNoYU9iaiA9IG5ldyBqc1NIQShzdHIsIFwiQVNDSUlcIik7XG5cdFx0cmV0dXJuIHNoYU9iai5nZXRIYXNoKFwiU0hBLTM4NFwiLCBcIkFTQ0lJXCIpO1xuXG5cdH0sXG5cdHNoYTUxMjogZnVuY3Rpb24oc3RyKSB7XG5cdFx0dmFyIHNoYU9iaiA9IG5ldyBqc1NIQShzdHIsIFwiQVNDSUlcIik7XG5cdFx0cmV0dXJuIHNoYU9iai5nZXRIYXNoKFwiU0hBLTUxMlwiLCBcIkFTQ0lJXCIpO1xuXHR9XG59XG4iLCIvKlxuICogQ3J5cHRvTVggVG9vbHNcbiAqIENvcHlyaWdodCAoQykgMjAwNCAtIDIwMDYgRGVyZWsgQnVpdGVuaHVpc1xuICpcbiAqIFRoaXMgcHJvZ3JhbSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3JcbiAqIG1vZGlmeSBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlXG4gKiBhcyBwdWJsaXNoZWQgYnkgdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyIHZlcnNpb24gMlxuICogb2YgdGhlIExpY2Vuc2UsIG9yIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4gKlxuICogVGhpcyBwcm9ncmFtIGlzIGRpc3RyaWJ1dGVkIGluIHRoZSBob3BlIHRoYXQgaXQgd2lsbCBiZSB1c2VmdWwsXG4gKiBidXQgV0lUSE9VVCBBTlkgV0FSUkFOVFk7IHdpdGhvdXQgZXZlbiB0aGUgaW1wbGllZCB3YXJyYW50eSBvZlxuICogTUVSQ0hBTlRBQklMSVRZIG9yIEZJVE5FU1MgRk9SIEEgUEFSVElDVUxBUiBQVVJQT1NFLiAgU2VlIHRoZVxuICogR05VIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgZm9yIG1vcmUgZGV0YWlscy5cbiAqXG4gKiBZb3Ugc2hvdWxkIGhhdmUgcmVjZWl2ZWQgYSBjb3B5IG9mIHRoZSBHTlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZVxuICogYWxvbmcgd2l0aCB0aGlzIHByb2dyYW07IGlmIG5vdCwgd3JpdGUgdG8gdGhlIEZyZWUgU29mdHdhcmVcbiAqIEZvdW5kYXRpb24sIEluYy4sIDU5IFRlbXBsZSBQbGFjZSAtIFN1aXRlIDMzMCwgQm9zdG9uLCBNQSAgMDIxMTEtMTMwNywgVVNBLlxuICovXG5cbi8qIE1vZGlmaWVkIGJ5IFJlY3VyaXR5IExhYnMgR21iSFxuICovXG5cbnZhciBSTURzaXplICAgPSAxNjA7XG52YXIgWCA9IG5ldyBBcnJheSgpO1xuXG5mdW5jdGlvbiBST0woeCwgbilcbntcbiAgcmV0dXJuIG5ldyBOdW1iZXIgKCh4IDw8IG4pIHwgKCB4ID4+PiAoMzIgLSBuKSkpO1xufVxuXG5mdW5jdGlvbiBGKHgsIHksIHopXG57XG4gIHJldHVybiBuZXcgTnVtYmVyKHggXiB5IF4geik7XG59XG5cbmZ1bmN0aW9uIEcoeCwgeSwgeilcbntcbiAgcmV0dXJuIG5ldyBOdW1iZXIoKHggJiB5KSB8ICh+eCAmIHopKTtcbn1cblxuZnVuY3Rpb24gSCh4LCB5LCB6KVxue1xuICByZXR1cm4gbmV3IE51bWJlcigoeCB8IH55KSBeIHopO1xufVxuXG5mdW5jdGlvbiBJKHgsIHksIHopXG57XG4gIHJldHVybiBuZXcgTnVtYmVyKCh4ICYgeikgfCAoeSAmIH56KSk7XG59XG5cbmZ1bmN0aW9uIEooeCwgeSwgeilcbntcbiAgcmV0dXJuIG5ldyBOdW1iZXIoeCBeICh5IHwgfnopKTtcbn1cblxuZnVuY3Rpb24gbWl4T25lUm91bmQoYSwgYiwgYywgZCwgZSwgeCwgcywgcm91bmROdW1iZXIpXG57XG4gIHN3aXRjaCAocm91bmROdW1iZXIpXG4gIHtcbiAgICBjYXNlIDAgOiBhICs9IEYoYiwgYywgZCkgKyB4ICsgMHgwMDAwMDAwMDsgYnJlYWs7XG4gICAgY2FzZSAxIDogYSArPSBHKGIsIGMsIGQpICsgeCArIDB4NWE4Mjc5OTk7IGJyZWFrO1xuICAgIGNhc2UgMiA6IGEgKz0gSChiLCBjLCBkKSArIHggKyAweDZlZDllYmExOyBicmVhaztcbiAgICBjYXNlIDMgOiBhICs9IEkoYiwgYywgZCkgKyB4ICsgMHg4ZjFiYmNkYzsgYnJlYWs7XG4gICAgY2FzZSA0IDogYSArPSBKKGIsIGMsIGQpICsgeCArIDB4YTk1M2ZkNGU7IGJyZWFrO1xuICAgIGNhc2UgNSA6IGEgKz0gSihiLCBjLCBkKSArIHggKyAweDUwYTI4YmU2OyBicmVhaztcbiAgICBjYXNlIDYgOiBhICs9IEkoYiwgYywgZCkgKyB4ICsgMHg1YzRkZDEyNDsgYnJlYWs7XG4gICAgY2FzZSA3IDogYSArPSBIKGIsIGMsIGQpICsgeCArIDB4NmQ3MDNlZjM7IGJyZWFrO1xuICAgIGNhc2UgOCA6IGEgKz0gRyhiLCBjLCBkKSArIHggKyAweDdhNmQ3NmU5OyBicmVhaztcbiAgICBjYXNlIDkgOiBhICs9IEYoYiwgYywgZCkgKyB4ICsgMHgwMDAwMDAwMDsgYnJlYWs7XG4gICAgXG4gICAgZGVmYXVsdCA6IGRvY3VtZW50LndyaXRlKFwiQm9ndXMgcm91bmQgbnVtYmVyXCIpOyBicmVhaztcbiAgfSAgXG4gIFxuICBhID0gUk9MKGEsIHMpICsgZTtcbiAgYyA9IFJPTChjLCAxMCk7XG5cbiAgYSAmPSAweGZmZmZmZmZmO1xuICBiICY9IDB4ZmZmZmZmZmY7XG4gIGMgJj0gMHhmZmZmZmZmZjtcbiAgZCAmPSAweGZmZmZmZmZmO1xuICBlICY9IDB4ZmZmZmZmZmY7XG5cbiAgdmFyIHJldEJsb2NrID0gbmV3IEFycmF5KCk7XG4gIHJldEJsb2NrWzBdID0gYTtcbiAgcmV0QmxvY2tbMV0gPSBiO1xuICByZXRCbG9ja1syXSA9IGM7XG4gIHJldEJsb2NrWzNdID0gZDtcbiAgcmV0QmxvY2tbNF0gPSBlO1xuICByZXRCbG9ja1s1XSA9IHg7XG4gIHJldEJsb2NrWzZdID0gcztcblxuICByZXR1cm4gcmV0QmxvY2s7XG59XG5cbmZ1bmN0aW9uIE1EaW5pdCAoTURidWYpXG57XG4gIE1EYnVmWzBdID0gMHg2NzQ1MjMwMTtcbiAgTURidWZbMV0gPSAweGVmY2RhYjg5O1xuICBNRGJ1ZlsyXSA9IDB4OThiYWRjZmU7XG4gIE1EYnVmWzNdID0gMHgxMDMyNTQ3NjtcbiAgTURidWZbNF0gPSAweGMzZDJlMWYwO1xufVxuXG52YXIgUk9McyA9IFtcbiAgWzExLCAxNCwgMTUsIDEyLCAgNSwgIDgsICA3LCAgOSwgMTEsIDEzLCAxNCwgMTUsICA2LCAgNywgIDksICA4XSxcbiAgWyA3LCAgNiwgIDgsIDEzLCAxMSwgIDksICA3LCAxNSwgIDcsIDEyLCAxNSwgIDksIDExLCAgNywgMTMsIDEyXSxcbiAgWzExLCAxMywgIDYsICA3LCAxNCwgIDksIDEzLCAxNSwgMTQsICA4LCAxMywgIDYsICA1LCAxMiwgIDcsICA1XSxcbiAgWzExLCAxMiwgMTQsIDE1LCAxNCwgMTUsICA5LCAgOCwgIDksIDE0LCAgNSwgIDYsICA4LCAgNiwgIDUsIDEyXSxcbiAgWyA5LCAxNSwgIDUsIDExLCAgNiwgIDgsIDEzLCAxMiwgIDUsIDEyLCAxMywgMTQsIDExLCAgOCwgIDUsICA2XSxcbiAgWyA4LCAgOSwgIDksIDExLCAxMywgMTUsIDE1LCAgNSwgIDcsICA3LCAgOCwgMTEsIDE0LCAxNCwgMTIsICA2XSxcbiAgWyA5LCAxMywgMTUsICA3LCAxMiwgIDgsICA5LCAxMSwgIDcsICA3LCAxMiwgIDcsICA2LCAxNSwgMTMsIDExXSxcbiAgWyA5LCAgNywgMTUsIDExLCAgOCwgIDYsICA2LCAxNCwgMTIsIDEzLCAgNSwgMTQsIDEzLCAxMywgIDcsICA1XSxcbiAgWzE1LCAgNSwgIDgsIDExLCAxNCwgMTQsICA2LCAxNCwgIDYsICA5LCAxMiwgIDksIDEyLCAgNSwgMTUsICA4XSxcbiAgWyA4LCAgNSwgMTIsICA5LCAxMiwgIDUsIDE0LCAgNiwgIDgsIDEzLCAgNiwgIDUsIDE1LCAxMywgMTEsIDExXVxuXTtcblxudmFyIGluZGV4ZXMgPSBbXG4gIFsgMCwgIDEsICAyLCAgMywgIDQsICA1LCAgNiwgIDcsICA4LCAgOSwgMTAsIDExLCAxMiwgMTMsIDE0LCAxNV0sXG4gIFsgNywgIDQsIDEzLCAgMSwgMTAsICA2LCAxNSwgIDMsIDEyLCAgMCwgIDksICA1LCAgMiwgMTQsIDExLCAgOF0sXG4gIFsgMywgMTAsIDE0LCAgNCwgIDksIDE1LCAgOCwgIDEsICAyLCAgNywgIDAsICA2LCAxMywgMTEsICA1LCAxMl0sXG4gIFsgMSwgIDksIDExLCAxMCwgIDAsICA4LCAxMiwgIDQsIDEzLCAgMywgIDcsIDE1LCAxNCwgIDUsICA2LCAgMl0sXG4gIFsgNCwgIDAsICA1LCAgOSwgIDcsIDEyLCAgMiwgMTAsIDE0LCAgMSwgIDMsICA4LCAxMSwgIDYsIDE1LCAxM10sXG4gIFsgNSwgMTQsICA3LCAgMCwgIDksICAyLCAxMSwgIDQsIDEzLCAgNiwgMTUsICA4LCAgMSwgMTAsICAzLCAxMl0sXG4gIFsgNiwgMTEsICAzLCAgNywgIDAsIDEzLCAgNSwgMTAsIDE0LCAxNSwgIDgsIDEyLCAgNCwgIDksICAxLCAgMl0sXG4gIFsxNSwgIDUsICAxLCAgMywgIDcsIDE0LCAgNiwgIDksIDExLCAgOCwgMTIsICAyLCAxMCwgIDAsICA0LCAxM10sXG4gIFsgOCwgIDYsICA0LCAgMSwgIDMsIDExLCAxNSwgIDAsICA1LCAxMiwgIDIsIDEzLCAgOSwgIDcsIDEwLCAxNF0sXG4gIFsxMiwgMTUsIDEwLCAgNCwgIDEsICA1LCAgOCwgIDcsICA2LCAgMiwgMTMsIDE0LCAgMCwgIDMsICA5LCAxMV1cbl07XG5cbmZ1bmN0aW9uIGNvbXByZXNzIChNRGJ1ZiwgWClcbntcbiAgYmxvY2tBID0gbmV3IEFycmF5KCk7XG4gIGJsb2NrQiA9IG5ldyBBcnJheSgpO1xuXG4gIHZhciByZXRCbG9jaztcblxuICBmb3IgKHZhciBpPTA7IGkgPCA1OyBpKyspXG4gIHtcbiAgICBibG9ja0FbaV0gPSBuZXcgTnVtYmVyKE1EYnVmW2ldKTtcbiAgICBibG9ja0JbaV0gPSBuZXcgTnVtYmVyKE1EYnVmW2ldKTtcbiAgfVxuXG4gIHZhciBzdGVwID0gMDtcbiAgZm9yICh2YXIgaiA9IDA7IGogPCA1OyBqKyspXG4gIHtcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IDE2OyBpKyspXG4gICAge1xuICAgICAgcmV0QmxvY2sgPSBtaXhPbmVSb3VuZChcbiAgICAgICAgYmxvY2tBWyhzdGVwKzApICUgNV0sXG4gICAgICAgIGJsb2NrQVsoc3RlcCsxKSAlIDVdLCAgIFxuICAgICAgICBibG9ja0FbKHN0ZXArMikgJSA1XSwgICBcbiAgICAgICAgYmxvY2tBWyhzdGVwKzMpICUgNV0sICAgXG4gICAgICAgIGJsb2NrQVsoc3RlcCs0KSAlIDVdLCAgXG4gICAgICAgIFhbaW5kZXhlc1tqXVtpXV0sIFxuICAgICAgICBST0xzW2pdW2ldLFxuICAgICAgICBqXG4gICAgICApO1xuXG4gICAgICBibG9ja0FbKHN0ZXArMCkgJSA1XSA9IHJldEJsb2NrWzBdO1xuICAgICAgYmxvY2tBWyhzdGVwKzEpICUgNV0gPSByZXRCbG9ja1sxXTtcbiAgICAgIGJsb2NrQVsoc3RlcCsyKSAlIDVdID0gcmV0QmxvY2tbMl07XG4gICAgICBibG9ja0FbKHN0ZXArMykgJSA1XSA9IHJldEJsb2NrWzNdO1xuICAgICAgYmxvY2tBWyhzdGVwKzQpICUgNV0gPSByZXRCbG9ja1s0XTtcblxuICAgICAgc3RlcCArPSA0O1xuICAgIH1cbiAgfVxuXG4gIHN0ZXAgPSAwO1xuICBmb3IgKHZhciBqID0gNTsgaiA8IDEwOyBqKyspXG4gIHtcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IDE2OyBpKyspXG4gICAgeyAgXG4gICAgICByZXRCbG9jayA9IG1peE9uZVJvdW5kKFxuICAgICAgICBibG9ja0JbKHN0ZXArMCkgJSA1XSwgXG4gICAgICAgIGJsb2NrQlsoc3RlcCsxKSAlIDVdLCBcbiAgICAgICAgYmxvY2tCWyhzdGVwKzIpICUgNV0sIFxuICAgICAgICBibG9ja0JbKHN0ZXArMykgJSA1XSwgXG4gICAgICAgIGJsb2NrQlsoc3RlcCs0KSAlIDVdLCAgXG4gICAgICAgIFhbaW5kZXhlc1tqXVtpXV0sIFxuICAgICAgICBST0xzW2pdW2ldLFxuICAgICAgICBqXG4gICAgICApO1xuXG4gICAgICBibG9ja0JbKHN0ZXArMCkgJSA1XSA9IHJldEJsb2NrWzBdO1xuICAgICAgYmxvY2tCWyhzdGVwKzEpICUgNV0gPSByZXRCbG9ja1sxXTtcbiAgICAgIGJsb2NrQlsoc3RlcCsyKSAlIDVdID0gcmV0QmxvY2tbMl07XG4gICAgICBibG9ja0JbKHN0ZXArMykgJSA1XSA9IHJldEJsb2NrWzNdO1xuICAgICAgYmxvY2tCWyhzdGVwKzQpICUgNV0gPSByZXRCbG9ja1s0XTtcblxuICAgICAgc3RlcCArPSA0O1xuICAgIH1cbiAgfVxuXG4gIGJsb2NrQlszXSArPSBibG9ja0FbMl0gKyBNRGJ1ZlsxXTtcbiAgTURidWZbMV0gID0gTURidWZbMl0gKyBibG9ja0FbM10gKyBibG9ja0JbNF07XG4gIE1EYnVmWzJdICA9IE1EYnVmWzNdICsgYmxvY2tBWzRdICsgYmxvY2tCWzBdO1xuICBNRGJ1ZlszXSAgPSBNRGJ1Zls0XSArIGJsb2NrQVswXSArIGJsb2NrQlsxXTtcbiAgTURidWZbNF0gID0gTURidWZbMF0gKyBibG9ja0FbMV0gKyBibG9ja0JbMl07XG4gIE1EYnVmWzBdICA9IGJsb2NrQlszXTtcbn1cblxuZnVuY3Rpb24gemVyb1goWClcbntcbiAgZm9yICh2YXIgaSA9IDA7IGkgPCAxNjsgaSsrKSB7IFhbaV0gPSAwOyB9XG59XG5cbmZ1bmN0aW9uIE1EZmluaXNoIChNRGJ1Ziwgc3RycHRyLCBsc3dsZW4sIG1zd2xlbilcbntcbiAgdmFyIFggPSBuZXcgQXJyYXkoMTYpO1xuICB6ZXJvWChYKTtcblxuICB2YXIgaiA9IDA7XG4gIGZvciAodmFyIGk9MDsgaSA8IChsc3dsZW4gJiA2Myk7IGkrKylcbiAge1xuICAgIFhbaSA+Pj4gMl0gXj0gKHN0cnB0ci5jaGFyQ29kZUF0KGorKykgJiAyNTUpIDw8ICg4ICogKGkgJiAzKSk7XG4gIH1cblxuICBYWyhsc3dsZW4gPj4+IDIpICYgMTVdIF49IDEgPDwgKDggKiAobHN3bGVuICYgMykgKyA3KTtcblxuICBpZiAoKGxzd2xlbiAmIDYzKSA+IDU1KVxuICB7XG4gICAgY29tcHJlc3MoTURidWYsIFgpO1xuICAgIHZhciBYID0gbmV3IEFycmF5KDE2KTtcbiAgICB6ZXJvWChYKTtcbiAgfVxuXG4gIFhbMTRdID0gbHN3bGVuIDw8IDM7XG4gIFhbMTVdID0gKGxzd2xlbiA+Pj4gMjkpIHwgKG1zd2xlbiA8PCAzKTtcblxuICBjb21wcmVzcyhNRGJ1ZiwgWCk7XG59XG5cbmZ1bmN0aW9uIEJZVEVTX1RPX0RXT1JEKGZvdXJDaGFycylcbntcbiAgdmFyIHRtcCAgPSAoZm91ckNoYXJzLmNoYXJDb2RlQXQoMykgJiAyNTUpIDw8IDI0O1xuICB0bXAgICB8PSAoZm91ckNoYXJzLmNoYXJDb2RlQXQoMikgJiAyNTUpIDw8IDE2O1xuICB0bXAgICB8PSAoZm91ckNoYXJzLmNoYXJDb2RlQXQoMSkgJiAyNTUpIDw8IDg7XG4gIHRtcCAgIHw9IChmb3VyQ2hhcnMuY2hhckNvZGVBdCgwKSAmIDI1NSk7ICBcblxuICByZXR1cm4gdG1wO1xufVxuXG5mdW5jdGlvbiBSTUQobWVzc2FnZSlcbntcbiAgdmFyIE1EYnVmICAgPSBuZXcgQXJyYXkoUk1Ec2l6ZSAvIDMyKTtcbiAgdmFyIGhhc2hjb2RlICAgPSBuZXcgQXJyYXkoUk1Ec2l6ZSAvIDgpO1xuICB2YXIgbGVuZ3RoOyAgXG4gIHZhciBuYnl0ZXM7XG5cbiAgTURpbml0KE1EYnVmKTtcbiAgbGVuZ3RoID0gbWVzc2FnZS5sZW5ndGg7XG5cbiAgdmFyIFggPSBuZXcgQXJyYXkoMTYpO1xuICB6ZXJvWChYKTtcblxuICB2YXIgaj0wO1xuICBmb3IgKHZhciBuYnl0ZXM9bGVuZ3RoOyBuYnl0ZXMgPiA2MzsgbmJ5dGVzIC09IDY0KVxuICB7XG4gICAgZm9yICh2YXIgaT0wOyBpIDwgMTY7IGkrKylcbiAgICB7XG4gICAgICBYW2ldID0gQllURVNfVE9fRFdPUkQobWVzc2FnZS5zdWJzdHIoaiwgNCkpO1xuICAgICAgaiArPSA0O1xuICAgIH1cbiAgICBjb21wcmVzcyhNRGJ1ZiwgWCk7XG4gIH1cblxuICBNRGZpbmlzaChNRGJ1ZiwgbWVzc2FnZS5zdWJzdHIoaiksIGxlbmd0aCwgMCk7XG5cbiAgZm9yICh2YXIgaT0wOyBpIDwgUk1Ec2l6ZSAvIDg7IGkgKz0gNClcbiAge1xuICAgIGhhc2hjb2RlW2ldICAgPSAgTURidWZbaSA+Pj4gMl0gICAmIDI1NTtcbiAgICBoYXNoY29kZVtpKzFdID0gKE1EYnVmW2kgPj4+IDJdID4+PiA4KSAgICYgMjU1O1xuICAgIGhhc2hjb2RlW2krMl0gPSAoTURidWZbaSA+Pj4gMl0gPj4+IDE2KSAmIDI1NTtcbiAgICBoYXNoY29kZVtpKzNdID0gKE1EYnVmW2kgPj4+IDJdID4+PiAyNCkgJiAyNTU7XG4gIH1cblxuICByZXR1cm4gaGFzaGNvZGU7XG59XG5cblxuZnVuY3Rpb24gUk1Ec3RyaW5nKG1lc3NhZ2UpXG57XG4gIHZhciBoYXNoY29kZSA9IFJNRChtZXNzYWdlKTtcbiAgdmFyIHJldFN0cmluZyA9IFwiXCI7XG5cbiAgZm9yICh2YXIgaT0wOyBpIDwgUk1Ec2l6ZS84OyBpKyspXG4gIHtcbiAgICByZXRTdHJpbmcgKz0gU3RyaW5nLmZyb21DaGFyQ29kZShoYXNoY29kZVtpXSk7XG4gIH0gIFxuXG4gIHJldHVybiByZXRTdHJpbmc7ICBcbn1cblxubW9kdWxlLmV4cG9ydHMgPSBSTURzdHJpbmc7XG4iLCIvLyBHUEc0QnJvd3NlcnMgLSBBbiBPcGVuUEdQIGltcGxlbWVudGF0aW9uIGluIGphdmFzY3JpcHRcbi8vIENvcHlyaWdodCAoQykgMjAxMSBSZWN1cml0eSBMYWJzIEdtYkhcbi8vIFxuLy8gVGhpcyBsaWJyYXJ5IGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vclxuLy8gbW9kaWZ5IGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIExlc3NlciBHZW5lcmFsIFB1YmxpY1xuLy8gTGljZW5zZSBhcyBwdWJsaXNoZWQgYnkgdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyXG4vLyB2ZXJzaW9uIDIuMSBvZiB0aGUgTGljZW5zZSwgb3IgKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbi8vIFxuLy8gVGhpcyBsaWJyYXJ5IGlzIGRpc3RyaWJ1dGVkIGluIHRoZSBob3BlIHRoYXQgaXQgd2lsbCBiZSB1c2VmdWwsXG4vLyBidXQgV0lUSE9VVCBBTlkgV0FSUkFOVFk7IHdpdGhvdXQgZXZlbiB0aGUgaW1wbGllZCB3YXJyYW50eSBvZlxuLy8gTUVSQ0hBTlRBQklMSVRZIG9yIEZJVE5FU1MgRk9SIEEgUEFSVElDVUxBUiBQVVJQT1NFLiAgU2VlIHRoZSBHTlVcbi8vIExlc3NlciBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGZvciBtb3JlIGRldGFpbHMuXG4vLyBcbi8vIFlvdSBzaG91bGQgaGF2ZSByZWNlaXZlZCBhIGNvcHkgb2YgdGhlIEdOVSBMZXNzZXIgR2VuZXJhbCBQdWJsaWNcbi8vIExpY2Vuc2UgYWxvbmcgd2l0aCB0aGlzIGxpYnJhcnk7IGlmIG5vdCwgd3JpdGUgdG8gdGhlIEZyZWUgU29mdHdhcmVcbi8vIEZvdW5kYXRpb24sIEluYy4sIDUxIEZyYW5rbGluIFN0cmVldCwgRmlmdGggRmxvb3IsIEJvc3RvbiwgTUEgIDAyMTEwLTEzMDEgIFVTQVxuLy9cbi8vIEEgRGlnaXRhbCBzaWduYXR1cmUgYWxnb3JpdGhtIGltcGxlbWVudGF0aW9uXG5cbmZ1bmN0aW9uIERTQSgpIHtcblx0Ly8gczEgPSAoKGcqKnMpIG1vZCBwKSBtb2QgcVxuXHQvLyBzMSA9ICgocyoqLTEpKihzaGEtMShtKSsoczEqeCkgbW9kIHEpXG5cdGZ1bmN0aW9uIHNpZ24oaGFzaGFsZ28sIG0sIGcsIHAsIHEsIHgpIHtcblx0XHQvLyBJZiB0aGUgb3V0cHV0IHNpemUgb2YgdGhlIGNob3NlbiBoYXNoIGlzIGxhcmdlciB0aGFuIHRoZSBudW1iZXIgb2Zcblx0XHQvLyBiaXRzIG9mIHEsIHRoZSBoYXNoIHJlc3VsdCBpcyB0cnVuY2F0ZWQgdG8gZml0IGJ5IHRha2luZyB0aGUgbnVtYmVyXG5cdFx0Ly8gb2YgbGVmdG1vc3QgYml0cyBlcXVhbCB0byB0aGUgbnVtYmVyIG9mIGJpdHMgb2YgcS4gIFRoaXMgKHBvc3NpYmx5XG5cdFx0Ly8gdHJ1bmNhdGVkKSBoYXNoIGZ1bmN0aW9uIHJlc3VsdCBpcyB0cmVhdGVkIGFzIGEgbnVtYmVyIGFuZCB1c2VkXG5cdFx0Ly8gZGlyZWN0bHkgaW4gdGhlIERTQSBzaWduYXR1cmUgYWxnb3JpdGhtLlxuXHRcdHZhciBoYXNoZWRfZGF0YSA9IHV0aWwuZ2V0TGVmdE5CaXRzKG9wZW5wZ3BfY3J5cHRvX2hhc2hEYXRhKGhhc2hhbGdvLG0pLHEuYml0TGVuZ3RoKCkpO1xuXHRcdHZhciBoYXNoID0gbmV3IEJpZ0ludGVnZXIodXRpbC5oZXhzdHJkdW1wKGhhc2hlZF9kYXRhKSwgMTYpO1xuXHRcdHZhciBrID0gb3BlbnBncF9jcnlwdG9fZ2V0UmFuZG9tQmlnSW50ZWdlckluUmFuZ2UoQmlnSW50ZWdlci5PTkUuYWRkKEJpZ0ludGVnZXIuT05FKSwgcS5zdWJ0cmFjdChCaWdJbnRlZ2VyLk9ORSkpO1xuXHRcdHZhciBzMSA9IChnLm1vZFBvdyhrLHApKS5tb2QocSk7IFxuXHRcdHZhciBzMiA9IChrLm1vZEludmVyc2UocSkubXVsdGlwbHkoaGFzaC5hZGQoeC5tdWx0aXBseShzMSkpKSkubW9kKHEpO1xuXHRcdHZhciByZXN1bHQgPSBuZXcgQXJyYXkoKTtcblx0XHRyZXN1bHRbMF0gPSBzMS50b01QSSgpO1xuXHRcdHJlc3VsdFsxXSA9IHMyLnRvTVBJKCk7XG5cdFx0cmV0dXJuIHJlc3VsdDtcblx0fVxuXHRmdW5jdGlvbiBzZWxlY3RfaGFzaF9hbGdvcml0aG0ocSkge1xuXHRcdHZhciB1c2Vyc2V0dGluZyA9IG9wZW5wZ3AuY29uZmlnLmNvbmZpZy5wcmVmZXJfaGFzaF9hbGdvcml0aG07XG5cdFx0Lypcblx0XHQgKiAxMDI0LWJpdCBrZXksIDE2MC1iaXQgcSwgU0hBLTEsIFNIQS0yMjQsIFNIQS0yNTYsIFNIQS0zODQsIG9yIFNIQS01MTIgaGFzaFxuXHRcdCAqIDIwNDgtYml0IGtleSwgMjI0LWJpdCBxLCBTSEEtMjI0LCBTSEEtMjU2LCBTSEEtMzg0LCBvciBTSEEtNTEyIGhhc2hcblx0XHQgKiAyMDQ4LWJpdCBrZXksIDI1Ni1iaXQgcSwgU0hBLTI1NiwgU0hBLTM4NCwgb3IgU0hBLTUxMiBoYXNoXG5cdFx0ICogMzA3Mi1iaXQga2V5LCAyNTYtYml0IHEsIFNIQS0yNTYsIFNIQS0zODQsIG9yIFNIQS01MTIgaGFzaFxuXHRcdCAqL1xuXHRcdHN3aXRjaCAoTWF0aC5yb3VuZChxLmJpdExlbmd0aCgpIC8gOCkpIHtcblx0XHRjYXNlIDIwOiAvLyAxMDI0IGJpdFxuXHRcdFx0aWYgKHVzZXJzZXR0aW5nICE9IDIgJiZcblx0XHRcdFx0dXNlcnNldHRpbmcgPiAxMSAmJlxuXHRcdFx0XHR1c2Vyc2V0dGluZyAhPSAxMCAmJlxuXHRcdFx0XHR1c2Vyc2V0dGluZyA8IDgpXG5cdFx0XHRcdHJldHVybiAyOyAvLyBwcmVmZXIgc2hhMVxuXHRcdFx0cmV0dXJuIHVzZXJzZXR0aW5nO1xuXHRcdGNhc2UgMjg6IC8vIDIwNDggYml0XG5cdFx0XHRpZiAodXNlcnNldHRpbmcgPiAxMSAmJlxuXHRcdFx0XHRcdHVzZXJzZXR0aW5nIDwgOClcblx0XHRcdFx0XHRyZXR1cm4gMTE7XG5cdFx0XHRyZXR1cm4gdXNlcnNldHRpbmc7XG5cdFx0Y2FzZSAzMjogLy8gNDA5NiBiaXQgLy8gcHJlZmVyIHNoYTIyNFxuXHRcdFx0aWYgKHVzZXJzZXR0aW5nID4gMTAgJiZcblx0XHRcdFx0XHR1c2Vyc2V0dGluZyA8IDgpXG5cdFx0XHRcdFx0cmV0dXJuIDg7IC8vIHByZWZlciBzaGEyNTZcblx0XHRcdHJldHVybiB1c2Vyc2V0dGluZztcblx0XHRkZWZhdWx0OlxuXHRcdFx0dXRpbC5wcmludF9kZWJ1ZyhcIkRTQSBzZWxlY3QgaGFzaCBhbGdvcml0aG06IHJldHVybmluZyBudWxsIGZvciBhbiB1bmtub3duIGxlbmd0aCBvZiBxXCIpO1xuXHRcdFx0cmV0dXJuIG51bGw7XG5cdFx0XHRcblx0XHR9XG5cdH1cblx0dGhpcy5zZWxlY3RfaGFzaF9hbGdvcml0aG0gPSBzZWxlY3RfaGFzaF9hbGdvcml0aG07XG5cdFxuXHRmdW5jdGlvbiB2ZXJpZnkoaGFzaGFsZ28sIHMxLHMyLG0scCxxLGcseSkge1xuXHRcdHZhciBoYXNoZWRfZGF0YSA9IHV0aWwuZ2V0TGVmdE5CaXRzKG9wZW5wZ3BfY3J5cHRvX2hhc2hEYXRhKGhhc2hhbGdvLG0pLHEuYml0TGVuZ3RoKCkpO1xuXHRcdHZhciBoYXNoID0gbmV3IEJpZ0ludGVnZXIodXRpbC5oZXhzdHJkdW1wKGhhc2hlZF9kYXRhKSwgMTYpOyBcblx0XHRpZiAoQmlnSW50ZWdlci5aRVJPLmNvbXBhcmVUbyhzMSkgPiAwIHx8XG5cdFx0XHRcdHMxLmNvbXBhcmVUbyhxKSA+IDAgfHxcblx0XHRcdFx0QmlnSW50ZWdlci5aRVJPLmNvbXBhcmVUbyhzMikgPiAwIHx8XG5cdFx0XHRcdHMyLmNvbXBhcmVUbyhxKSA+IDApIHtcblx0XHRcdHV0aWwucHJpbnRfZXJyb3IoXCJpbnZhbGlkIERTQSBTaWduYXR1cmVcIik7XG5cdFx0XHRyZXR1cm4gbnVsbDtcblx0XHR9XG5cdFx0dmFyIHcgPSBzMi5tb2RJbnZlcnNlKHEpO1xuXHRcdHZhciB1MSA9IGhhc2gubXVsdGlwbHkodykubW9kKHEpO1xuXHRcdHZhciB1MiA9IHMxLm11bHRpcGx5KHcpLm1vZChxKTtcblx0XHRyZXR1cm4gZy5tb2RQb3codTEscCkubXVsdGlwbHkoeS5tb2RQb3codTIscCkpLm1vZChwKS5tb2QocSk7XG5cdH1cblx0XG5cdC8qXG5cdCAqIHVudXNlZCBjb2RlLiBUaGlzIGNhbiBiZSB1c2VkIGFzIGEgc3RhcnQgdG8gd3JpdGUgYSBrZXkgZ2VuZXJhdG9yXG5cdCAqIGZ1bmN0aW9uLlxuXHRcblx0ZnVuY3Rpb24gZ2VuZXJhdGVLZXkoYml0Y291bnQpIHtcblx0ICAgIHZhciBxaSA9IG5ldyBCaWdJbnRlZ2VyKGJpdGNvdW50LCBwcmltZUNlbnRlcmllKTtcblx0ICAgIHZhciBwaSA9IGdlbmVyYXRlUChxLCA1MTIpO1xuXHQgICAgdmFyIGdpID0gZ2VuZXJhdGVHKHAsIHEsIGJpdGNvdW50KTtcblx0ICAgIHZhciB4aTtcblx0ICAgIGRvIHtcblx0ICAgICAgICB4aSA9IG5ldyBCaWdJbnRlZ2VyKHEuYml0Q291bnQoKSwgcmFuZCk7XG5cdCAgICB9IHdoaWxlICh4LmNvbXBhcmVUbyhCaWdJbnRlZ2VyLlpFUk8pICE9IDEgJiYgeC5jb21wYXJlVG8ocSkgIT0gLTEpO1xuXHQgICAgdmFyIHlpID0gZy5tb2RQb3coeCwgcCk7XG5cdCAgICByZXR1cm4ge3g6IHhpLCBxOiBxaSwgcDogcGksIGc6IGdpLCB5OiB5aX07XG5cdH1cblxuXHRmdW5jdGlvbiBnZW5lcmF0ZVAocSwgYml0bGVuZ3RoLCByYW5kb21mbikge1xuXHQgICAgaWYgKGJpdGxlbmd0aCAlIDY0ICE9IDApIHtcblx0ICAgIFx0cmV0dXJuIGZhbHNlO1xuXHQgICAgfVxuXHQgICAgdmFyIHBUZW1wO1xuXHQgICAgdmFyIHBUZW1wMjtcblx0ICAgIGRvIHtcblx0ICAgICAgICBwVGVtcCA9IHJhbmRvbWZuKGJpdGNvdW50LCB0cnVlKTtcblx0ICAgICAgICBwVGVtcDIgPSBwVGVtcC5zdWJ0cmFjdChCaWdJbnRlZ2VyLk9ORSk7XG5cdCAgICAgICAgcFRlbXAgPSBwVGVtcC5zdWJ0cmFjdChwVGVtcDIucmVtYWluZGVyKHEpKTtcblx0ICAgIH0gd2hpbGUgKCFwVGVtcC5pc1Byb2JhYmxlUHJpbWUocHJpbWVDZW50ZXJpZSkgfHwgcFRlbXAuYml0TGVuZ3RoKCkgIT0gbCk7XG5cdCAgICByZXR1cm4gcFRlbXA7XG5cdH1cblx0XG5cdGZ1bmN0aW9uIGdlbmVyYXRlRyhwLCBxLCBiaXRsZW5ndGgsIHJhbmRvbWZuKSB7XG5cdCAgICB2YXIgYXV4ID0gcC5zdWJ0cmFjdChCaWdJbnRlZ2VyLk9ORSk7XG5cdCAgICB2YXIgcG93ID0gYXV4LmRpdmlkZShxKTtcblx0ICAgIHZhciBnVGVtcDtcblx0ICAgIGRvIHtcblx0ICAgICAgICBnVGVtcCA9IHJhbmRvbWZuKGJpdGxlbmd0aCk7XG5cdCAgICB9IHdoaWxlIChnVGVtcC5jb21wYXJlVG8oYXV4KSAhPSAtMSAmJiBnVGVtcC5jb21wYXJlVG8oQmlnSW50ZWdlci5PTkUpICE9IDEpO1xuXHQgICAgcmV0dXJuIGdUZW1wLm1vZFBvdyhwb3csIHApO1xuXHR9XG5cblx0ZnVuY3Rpb24gZ2VuZXJhdGVLKHEsIGJpdGxlbmd0aCwgcmFuZG9tZm4pIHtcblx0ICAgIHZhciB0ZW1wSztcblx0ICAgIGRvIHtcblx0ICAgICAgICB0ZW1wSyA9IHJhbmRvbWZuKGJpdGxlbmd0aCwgZmFsc2UpO1xuXHQgICAgfSB3aGlsZSAodGVtcEsuY29tcGFyZVRvKHEpICE9IC0xICYmIHRlbXBLLmNvbXBhcmVUbyhCaWdJbnRlZ2VyLlpFUk8pICE9IDEpO1xuXHQgICAgcmV0dXJuIHRlbXBLO1xuXHR9XG5cblx0ZnVuY3Rpb24gZ2VuZXJhdGVSKHEscCkge1xuXHQgICAgayA9IGdlbmVyYXRlSyhxKTtcblx0ICAgIHZhciByID0gZy5tb2RQb3coaywgcCkubW9kKHEpO1xuXHQgICAgcmV0dXJuIHI7XG5cdH1cblxuXHRmdW5jdGlvbiBnZW5lcmF0ZVMoaGFzaGZuLGsscixtLHEseCkge1xuICAgICAgICB2YXIgaGFzaCA9IGhhc2hmbihtKTtcbiAgICAgICAgcyA9IChrLm1vZEludmVyc2UocSkubXVsdGlwbHkoaGFzaC5hZGQoeC5tdWx0aXBseShyKSkpKS5tb2QocSk7XG5cdCAgICByZXR1cm4gcztcblx0fSAqL1xuXHR0aGlzLnNpZ24gPSBzaWduO1xuXHR0aGlzLnZlcmlmeSA9IHZlcmlmeTtcblx0Ly8gdGhpcy5nZW5lcmF0ZSA9IGdlbmVyYXRlS2V5O1xufVxuXG5tb2R1bGUuZXhwb3J0cyA9IERTQTtcbiIsIihmdW5jdGlvbigpey8qKlxuICogQSBmYXN0IE1ENSBKYXZhU2NyaXB0IGltcGxlbWVudGF0aW9uXG4gKiBDb3B5cmlnaHQgKGMpIDIwMTIgSm9zZXBoIE15ZXJzXG4gKiBodHRwOi8vd3d3Lm15ZXJzZGFpbHkub3JnL2pvc2VwaC9qYXZhc2NyaXB0L21kNS10ZXh0Lmh0bWxcbiAqXG4gKiBQZXJtaXNzaW9uIHRvIHVzZSwgY29weSwgbW9kaWZ5LCBhbmQgZGlzdHJpYnV0ZSB0aGlzIHNvZnR3YXJlXG4gKiBhbmQgaXRzIGRvY3VtZW50YXRpb24gZm9yIGFueSBwdXJwb3NlcyBhbmQgd2l0aG91dFxuICogZmVlIGlzIGhlcmVieSBncmFudGVkIHByb3ZpZGVkIHRoYXQgdGhpcyBjb3B5cmlnaHQgbm90aWNlXG4gKiBhcHBlYXJzIGluIGFsbCBjb3BpZXMuXG4gKlxuICogT2YgY291cnNlLCB0aGlzIHNvZnQgaXMgcHJvdmlkZWQgXCJhcyBpc1wiIHdpdGhvdXQgZXhwcmVzcyBvciBpbXBsaWVkXG4gKiB3YXJyYW50eSBvZiBhbnkga2luZC5cbiAqL1xuXG52YXIgdXRpbCA9IHJlcXVpcmUoJy4uLy4uL3V0aWwvdXRpbC5qcycpO1xuXG5mdW5jdGlvbiBNRDUoZW50cmVlKSB7XG5cdHZhciBoZXggPSBtZDUoZW50cmVlKTtcblx0dmFyIGJpbiA9IHV0aWwuaGV4MmJpbihoZXgpO1xuXHRyZXR1cm4gYmluO1xufVxuXG5mdW5jdGlvbiBtZDVjeWNsZSh4LCBrKSB7XG52YXIgYSA9IHhbMF0sIGIgPSB4WzFdLCBjID0geFsyXSwgZCA9IHhbM107XG5cbmEgPSBmZihhLCBiLCBjLCBkLCBrWzBdLCA3LCAtNjgwODc2OTM2KTtcbmQgPSBmZihkLCBhLCBiLCBjLCBrWzFdLCAxMiwgLTM4OTU2NDU4Nik7XG5jID0gZmYoYywgZCwgYSwgYiwga1syXSwgMTcsICA2MDYxMDU4MTkpO1xuYiA9IGZmKGIsIGMsIGQsIGEsIGtbM10sIDIyLCAtMTA0NDUyNTMzMCk7XG5hID0gZmYoYSwgYiwgYywgZCwga1s0XSwgNywgLTE3NjQxODg5Nyk7XG5kID0gZmYoZCwgYSwgYiwgYywga1s1XSwgMTIsICAxMjAwMDgwNDI2KTtcbmMgPSBmZihjLCBkLCBhLCBiLCBrWzZdLCAxNywgLTE0NzMyMzEzNDEpO1xuYiA9IGZmKGIsIGMsIGQsIGEsIGtbN10sIDIyLCAtNDU3MDU5ODMpO1xuYSA9IGZmKGEsIGIsIGMsIGQsIGtbOF0sIDcsICAxNzcwMDM1NDE2KTtcbmQgPSBmZihkLCBhLCBiLCBjLCBrWzldLCAxMiwgLTE5NTg0MTQ0MTcpO1xuYyA9IGZmKGMsIGQsIGEsIGIsIGtbMTBdLCAxNywgLTQyMDYzKTtcbmIgPSBmZihiLCBjLCBkLCBhLCBrWzExXSwgMjIsIC0xOTkwNDA0MTYyKTtcbmEgPSBmZihhLCBiLCBjLCBkLCBrWzEyXSwgNywgIDE4MDQ2MDM2ODIpO1xuZCA9IGZmKGQsIGEsIGIsIGMsIGtbMTNdLCAxMiwgLTQwMzQxMTAxKTtcbmMgPSBmZihjLCBkLCBhLCBiLCBrWzE0XSwgMTcsIC0xNTAyMDAyMjkwKTtcbmIgPSBmZihiLCBjLCBkLCBhLCBrWzE1XSwgMjIsICAxMjM2NTM1MzI5KTtcblxuYSA9IGdnKGEsIGIsIGMsIGQsIGtbMV0sIDUsIC0xNjU3OTY1MTApO1xuZCA9IGdnKGQsIGEsIGIsIGMsIGtbNl0sIDksIC0xMDY5NTAxNjMyKTtcbmMgPSBnZyhjLCBkLCBhLCBiLCBrWzExXSwgMTQsICA2NDM3MTc3MTMpO1xuYiA9IGdnKGIsIGMsIGQsIGEsIGtbMF0sIDIwLCAtMzczODk3MzAyKTtcbmEgPSBnZyhhLCBiLCBjLCBkLCBrWzVdLCA1LCAtNzAxNTU4NjkxKTtcbmQgPSBnZyhkLCBhLCBiLCBjLCBrWzEwXSwgOSwgIDM4MDE2MDgzKTtcbmMgPSBnZyhjLCBkLCBhLCBiLCBrWzE1XSwgMTQsIC02NjA0NzgzMzUpO1xuYiA9IGdnKGIsIGMsIGQsIGEsIGtbNF0sIDIwLCAtNDA1NTM3ODQ4KTtcbmEgPSBnZyhhLCBiLCBjLCBkLCBrWzldLCA1LCAgNTY4NDQ2NDM4KTtcbmQgPSBnZyhkLCBhLCBiLCBjLCBrWzE0XSwgOSwgLTEwMTk4MDM2OTApO1xuYyA9IGdnKGMsIGQsIGEsIGIsIGtbM10sIDE0LCAtMTg3MzYzOTYxKTtcbmIgPSBnZyhiLCBjLCBkLCBhLCBrWzhdLCAyMCwgIDExNjM1MzE1MDEpO1xuYSA9IGdnKGEsIGIsIGMsIGQsIGtbMTNdLCA1LCAtMTQ0NDY4MTQ2Nyk7XG5kID0gZ2coZCwgYSwgYiwgYywga1syXSwgOSwgLTUxNDAzNzg0KTtcbmMgPSBnZyhjLCBkLCBhLCBiLCBrWzddLCAxNCwgIDE3MzUzMjg0NzMpO1xuYiA9IGdnKGIsIGMsIGQsIGEsIGtbMTJdLCAyMCwgLTE5MjY2MDc3MzQpO1xuXG5hID0gaGgoYSwgYiwgYywgZCwga1s1XSwgNCwgLTM3ODU1OCk7XG5kID0gaGgoZCwgYSwgYiwgYywga1s4XSwgMTEsIC0yMDIyNTc0NDYzKTtcbmMgPSBoaChjLCBkLCBhLCBiLCBrWzExXSwgMTYsICAxODM5MDMwNTYyKTtcbmIgPSBoaChiLCBjLCBkLCBhLCBrWzE0XSwgMjMsIC0zNTMwOTU1Nik7XG5hID0gaGgoYSwgYiwgYywgZCwga1sxXSwgNCwgLTE1MzA5OTIwNjApO1xuZCA9IGhoKGQsIGEsIGIsIGMsIGtbNF0sIDExLCAgMTI3Mjg5MzM1Myk7XG5jID0gaGgoYywgZCwgYSwgYiwga1s3XSwgMTYsIC0xNTU0OTc2MzIpO1xuYiA9IGhoKGIsIGMsIGQsIGEsIGtbMTBdLCAyMywgLTEwOTQ3MzA2NDApO1xuYSA9IGhoKGEsIGIsIGMsIGQsIGtbMTNdLCA0LCAgNjgxMjc5MTc0KTtcbmQgPSBoaChkLCBhLCBiLCBjLCBrWzBdLCAxMSwgLTM1ODUzNzIyMik7XG5jID0gaGgoYywgZCwgYSwgYiwga1szXSwgMTYsIC03MjI1MjE5NzkpO1xuYiA9IGhoKGIsIGMsIGQsIGEsIGtbNl0sIDIzLCAgNzYwMjkxODkpO1xuYSA9IGhoKGEsIGIsIGMsIGQsIGtbOV0sIDQsIC02NDAzNjQ0ODcpO1xuZCA9IGhoKGQsIGEsIGIsIGMsIGtbMTJdLCAxMSwgLTQyMTgxNTgzNSk7XG5jID0gaGgoYywgZCwgYSwgYiwga1sxNV0sIDE2LCAgNTMwNzQyNTIwKTtcbmIgPSBoaChiLCBjLCBkLCBhLCBrWzJdLCAyMywgLTk5NTMzODY1MSk7XG5cbmEgPSBpaShhLCBiLCBjLCBkLCBrWzBdLCA2LCAtMTk4NjMwODQ0KTtcbmQgPSBpaShkLCBhLCBiLCBjLCBrWzddLCAxMCwgIDExMjY4OTE0MTUpO1xuYyA9IGlpKGMsIGQsIGEsIGIsIGtbMTRdLCAxNSwgLTE0MTYzNTQ5MDUpO1xuYiA9IGlpKGIsIGMsIGQsIGEsIGtbNV0sIDIxLCAtNTc0MzQwNTUpO1xuYSA9IGlpKGEsIGIsIGMsIGQsIGtbMTJdLCA2LCAgMTcwMDQ4NTU3MSk7XG5kID0gaWkoZCwgYSwgYiwgYywga1szXSwgMTAsIC0xODk0OTg2NjA2KTtcbmMgPSBpaShjLCBkLCBhLCBiLCBrWzEwXSwgMTUsIC0xMDUxNTIzKTtcbmIgPSBpaShiLCBjLCBkLCBhLCBrWzFdLCAyMSwgLTIwNTQ5MjI3OTkpO1xuYSA9IGlpKGEsIGIsIGMsIGQsIGtbOF0sIDYsICAxODczMzEzMzU5KTtcbmQgPSBpaShkLCBhLCBiLCBjLCBrWzE1XSwgMTAsIC0zMDYxMTc0NCk7XG5jID0gaWkoYywgZCwgYSwgYiwga1s2XSwgMTUsIC0xNTYwMTk4MzgwKTtcbmIgPSBpaShiLCBjLCBkLCBhLCBrWzEzXSwgMjEsICAxMzA5MTUxNjQ5KTtcbmEgPSBpaShhLCBiLCBjLCBkLCBrWzRdLCA2LCAtMTQ1NTIzMDcwKTtcbmQgPSBpaShkLCBhLCBiLCBjLCBrWzExXSwgMTAsIC0xMTIwMjEwMzc5KTtcbmMgPSBpaShjLCBkLCBhLCBiLCBrWzJdLCAxNSwgIDcxODc4NzI1OSk7XG5iID0gaWkoYiwgYywgZCwgYSwga1s5XSwgMjEsIC0zNDM0ODU1NTEpO1xuXG54WzBdID0gYWRkMzIoYSwgeFswXSk7XG54WzFdID0gYWRkMzIoYiwgeFsxXSk7XG54WzJdID0gYWRkMzIoYywgeFsyXSk7XG54WzNdID0gYWRkMzIoZCwgeFszXSk7XG5cbn1cblxuZnVuY3Rpb24gY21uKHEsIGEsIGIsIHgsIHMsIHQpIHtcbmEgPSBhZGQzMihhZGQzMihhLCBxKSwgYWRkMzIoeCwgdCkpO1xucmV0dXJuIGFkZDMyKChhIDw8IHMpIHwgKGEgPj4+ICgzMiAtIHMpKSwgYik7XG59XG5cbmZ1bmN0aW9uIGZmKGEsIGIsIGMsIGQsIHgsIHMsIHQpIHtcbnJldHVybiBjbW4oKGIgJiBjKSB8ICgofmIpICYgZCksIGEsIGIsIHgsIHMsIHQpO1xufVxuXG5mdW5jdGlvbiBnZyhhLCBiLCBjLCBkLCB4LCBzLCB0KSB7XG5yZXR1cm4gY21uKChiICYgZCkgfCAoYyAmICh+ZCkpLCBhLCBiLCB4LCBzLCB0KTtcbn1cblxuZnVuY3Rpb24gaGgoYSwgYiwgYywgZCwgeCwgcywgdCkge1xucmV0dXJuIGNtbihiIF4gYyBeIGQsIGEsIGIsIHgsIHMsIHQpO1xufVxuXG5mdW5jdGlvbiBpaShhLCBiLCBjLCBkLCB4LCBzLCB0KSB7XG5yZXR1cm4gY21uKGMgXiAoYiB8ICh+ZCkpLCBhLCBiLCB4LCBzLCB0KTtcbn1cblxuZnVuY3Rpb24gbWQ1MShzKSB7XG50eHQgPSAnJztcbnZhciBuID0gcy5sZW5ndGgsXG5zdGF0ZSA9IFsxNzMyNTg0MTkzLCAtMjcxNzMzODc5LCAtMTczMjU4NDE5NCwgMjcxNzMzODc4XSwgaTtcbmZvciAoaT02NDsgaTw9cy5sZW5ndGg7IGkrPTY0KSB7XG5tZDVjeWNsZShzdGF0ZSwgbWQ1YmxrKHMuc3Vic3RyaW5nKGktNjQsIGkpKSk7XG59XG5zID0gcy5zdWJzdHJpbmcoaS02NCk7XG52YXIgdGFpbCA9IFswLDAsMCwwLCAwLDAsMCwwLCAwLDAsMCwwLCAwLDAsMCwwXTtcbmZvciAoaT0wOyBpPHMubGVuZ3RoOyBpKyspXG50YWlsW2k+PjJdIHw9IHMuY2hhckNvZGVBdChpKSA8PCAoKGklNCkgPDwgMyk7XG50YWlsW2k+PjJdIHw9IDB4ODAgPDwgKChpJTQpIDw8IDMpO1xuaWYgKGkgPiA1NSkge1xubWQ1Y3ljbGUoc3RhdGUsIHRhaWwpO1xuZm9yIChpPTA7IGk8MTY7IGkrKykgdGFpbFtpXSA9IDA7XG59XG50YWlsWzE0XSA9IG4qODtcbm1kNWN5Y2xlKHN0YXRlLCB0YWlsKTtcbnJldHVybiBzdGF0ZTtcbn1cblxuLyogdGhlcmUgbmVlZHMgdG8gYmUgc3VwcG9ydCBmb3IgVW5pY29kZSBoZXJlLFxuICogdW5sZXNzIHdlIHByZXRlbmQgdGhhdCB3ZSBjYW4gcmVkZWZpbmUgdGhlIE1ELTVcbiAqIGFsZ29yaXRobSBmb3IgbXVsdGktYnl0ZSBjaGFyYWN0ZXJzIChwZXJoYXBzXG4gKiBieSBhZGRpbmcgZXZlcnkgZm91ciAxNi1iaXQgY2hhcmFjdGVycyBhbmRcbiAqIHNob3J0ZW5pbmcgdGhlIHN1bSB0byAzMiBiaXRzKS4gT3RoZXJ3aXNlXG4gKiBJIHN1Z2dlc3QgcGVyZm9ybWluZyBNRC01IGFzIGlmIGV2ZXJ5IGNoYXJhY3RlclxuICogd2FzIHR3byBieXRlcy0tZS5nLiwgMDA0MCAwMDI1ID0gQCUtLWJ1dCB0aGVuXG4gKiBob3cgd2lsbCBhbiBvcmRpbmFyeSBNRC01IHN1bSBiZSBtYXRjaGVkP1xuICogVGhlcmUgaXMgbm8gd2F5IHRvIHN0YW5kYXJkaXplIHRleHQgdG8gc29tZXRoaW5nXG4gKiBsaWtlIFVURi04IGJlZm9yZSB0cmFuc2Zvcm1hdGlvbjsgc3BlZWQgY29zdCBpc1xuICogdXR0ZXJseSBwcm9oaWJpdGl2ZS4gVGhlIEphdmFTY3JpcHQgc3RhbmRhcmRcbiAqIGl0c2VsZiBuZWVkcyB0byBsb29rIGF0IHRoaXM6IGl0IHNob3VsZCBzdGFydFxuICogcHJvdmlkaW5nIGFjY2VzcyB0byBzdHJpbmdzIGFzIHByZWZvcm1lZCBVVEYtOFxuICogOC1iaXQgdW5zaWduZWQgdmFsdWUgYXJyYXlzLlxuICovXG5mdW5jdGlvbiBtZDVibGsocykgeyAvKiBJIGZpZ3VyZWQgZ2xvYmFsIHdhcyBmYXN0ZXIuICAgKi9cbnZhciBtZDVibGtzID0gW10sIGk7IC8qIEFuZHkgS2luZyBzYWlkIGRvIGl0IHRoaXMgd2F5LiAqL1xuZm9yIChpPTA7IGk8NjQ7IGkrPTQpIHtcbm1kNWJsa3NbaT4+Ml0gPSBzLmNoYXJDb2RlQXQoaSlcbisgKHMuY2hhckNvZGVBdChpKzEpIDw8IDgpXG4rIChzLmNoYXJDb2RlQXQoaSsyKSA8PCAxNilcbisgKHMuY2hhckNvZGVBdChpKzMpIDw8IDI0KTtcbn1cbnJldHVybiBtZDVibGtzO1xufVxuXG52YXIgaGV4X2NociA9ICcwMTIzNDU2Nzg5YWJjZGVmJy5zcGxpdCgnJyk7XG5cbmZ1bmN0aW9uIHJoZXgobilcbntcbnZhciBzPScnLCBqPTA7XG5mb3IoOyBqPDQ7IGorKylcbnMgKz0gaGV4X2NoclsobiA+PiAoaiAqIDggKyA0KSkgJiAweDBGXVxuKyBoZXhfY2hyWyhuID4+IChqICogOCkpICYgMHgwRl07XG5yZXR1cm4gcztcbn1cblxuZnVuY3Rpb24gaGV4KHgpIHtcbmZvciAodmFyIGk9MDsgaTx4Lmxlbmd0aDsgaSsrKVxueFtpXSA9IHJoZXgoeFtpXSk7XG5yZXR1cm4geC5qb2luKCcnKTtcbn1cblxuZnVuY3Rpb24gbWQ1KHMpIHtcbnJldHVybiBoZXgobWQ1MShzKSk7XG59XG5cbi8qIHRoaXMgZnVuY3Rpb24gaXMgbXVjaCBmYXN0ZXIsXG5zbyBpZiBwb3NzaWJsZSB3ZSB1c2UgaXQuIFNvbWUgSUVzXG5hcmUgdGhlIG9ubHkgb25lcyBJIGtub3cgb2YgdGhhdFxubmVlZCB0aGUgaWRpb3RpYyBzZWNvbmQgZnVuY3Rpb24sXG5nZW5lcmF0ZWQgYnkgYW4gaWYgY2xhdXNlLiAgKi9cblxuZnVuY3Rpb24gYWRkMzIoYSwgYikge1xucmV0dXJuIChhICsgYikgJiAweEZGRkZGRkZGO1xufVxuXG5pZiAobWQ1KCdoZWxsbycpICE9ICc1ZDQxNDAyYWJjNGIyYTc2Yjk3MTlkOTExMDE3YzU5MicpIHtcbmZ1bmN0aW9uIGFkZDMyKHgsIHkpIHtcbnZhciBsc3cgPSAoeCAmIDB4RkZGRikgKyAoeSAmIDB4RkZGRiksXG5tc3cgPSAoeCA+PiAxNikgKyAoeSA+PiAxNikgKyAobHN3ID4+IDE2KTtcbnJldHVybiAobXN3IDw8IDE2KSB8IChsc3cgJiAweEZGRkYpO1xufVxufVxuXG5tb2R1bGUuZXhwb3J0cyA9IE1ENVxuXG59KSgpIiwiLy8gR1BHNEJyb3dzZXJzIC0gQW4gT3BlblBHUCBpbXBsZW1lbnRhdGlvbiBpbiBqYXZhc2NyaXB0XG4vLyBDb3B5cmlnaHQgKEMpIDIwMTEgUmVjdXJpdHkgTGFicyBHbWJIXG4vLyBcbi8vIFRoaXMgbGlicmFyeSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3Jcbi8vIG1vZGlmeSBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBMZXNzZXIgR2VuZXJhbCBQdWJsaWNcbi8vIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5IHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlclxuLy8gdmVyc2lvbiAyLjEgb2YgdGhlIExpY2Vuc2UsIG9yIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4vLyBcbi8vIFRoaXMgbGlicmFyeSBpcyBkaXN0cmlidXRlZCBpbiB0aGUgaG9wZSB0aGF0IGl0IHdpbGwgYmUgdXNlZnVsLFxuLy8gYnV0IFdJVEhPVVQgQU5ZIFdBUlJBTlRZOyB3aXRob3V0IGV2ZW4gdGhlIGltcGxpZWQgd2FycmFudHkgb2Zcbi8vIE1FUkNIQU5UQUJJTElUWSBvciBGSVRORVNTIEZPUiBBIFBBUlRJQ1VMQVIgUFVSUE9TRS4gIFNlZSB0aGUgR05VXG4vLyBMZXNzZXIgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBmb3IgbW9yZSBkZXRhaWxzLlxuLy8gXG4vLyBZb3Ugc2hvdWxkIGhhdmUgcmVjZWl2ZWQgYSBjb3B5IG9mIHRoZSBHTlUgTGVzc2VyIEdlbmVyYWwgUHVibGljXG4vLyBMaWNlbnNlIGFsb25nIHdpdGggdGhpcyBsaWJyYXJ5OyBpZiBub3QsIHdyaXRlIHRvIHRoZSBGcmVlIFNvZnR3YXJlXG4vLyBGb3VuZGF0aW9uLCBJbmMuLCA1MSBGcmFua2xpbiBTdHJlZXQsIEZpZnRoIEZsb29yLCBCb3N0b24sIE1BICAwMjExMC0xMzAxICBVU0Fcbi8vXG4vLyBSU0EgaW1wbGVtZW50YXRpb25cblxudmFyIEJpZ0ludGVnZXIgPSByZXF1aXJlKCcuL2pzYm4uanMnKSxcblx0cmFuZG9tID0gcmVxdWlyZSgnLi4vcmFuZG9tLmpzJyk7XG5cbmZ1bmN0aW9uIFNlY3VyZVJhbmRvbSgpe1xuICAgIGZ1bmN0aW9uIG5leHRCeXRlcyhieXRlQXJyYXkpe1xuICAgICAgICBmb3IodmFyIG4gPSAwOyBuIDwgYnl0ZUFycmF5Lmxlbmd0aDtuKyspe1xuICAgICAgICAgICAgYnl0ZUFycmF5W25dID0gcmFuZG9tLmdldFNlY3VyZVJhbmRvbU9jdGV0KCk7XG4gICAgICAgIH1cbiAgICB9XG4gICAgdGhpcy5uZXh0Qnl0ZXMgPSBuZXh0Qnl0ZXM7XG59XG5cbmZ1bmN0aW9uIFJTQSgpIHtcblx0LyoqXG5cdCAqIFRoaXMgZnVuY3Rpb24gdXNlcyBqc2JuIEJpZyBOdW0gbGlicmFyeSB0byBkZWNyeXB0IFJTQVxuXHQgKiBAcGFyYW0gbVxuXHQgKiAgICAgICAgICAgIG1lc3NhZ2Vcblx0ICogQHBhcmFtIGRcblx0ICogICAgICAgICAgICBSU0EgZCBhcyBCaWdJbnRlZ2VyXG5cdCAqIEBwYXJhbSBwXG5cdCAqICAgICAgICAgICAgUlNBIHAgYXMgQmlnSW50ZWdlclxuXHQgKiBAcGFyYW0gcVxuXHQgKiAgICAgICAgICAgIFJTQSBxIGFzIEJpZ0ludGVnZXJcblx0ICogQHBhcmFtIHVcblx0ICogICAgICAgICAgICBSU0EgdSBhcyBCaWdJbnRlZ2VyXG5cdCAqIEByZXR1cm4ge0JpZ0ludGVnZXJ9IFRoZSBkZWNyeXB0ZWQgdmFsdWUgb2YgdGhlIG1lc3NhZ2Vcblx0ICovXG5cdGZ1bmN0aW9uIGRlY3J5cHQobSwgZCwgcCwgcSwgdSkge1xuXHRcdHZhciB4cCA9IG0ubW9kKHApLm1vZFBvdyhkLm1vZChwLnN1YnRyYWN0KEJpZ0ludGVnZXIuT05FKSksIHApO1xuXHRcdHZhciB4cSA9IG0ubW9kKHEpLm1vZFBvdyhkLm1vZChxLnN1YnRyYWN0KEJpZ0ludGVnZXIuT05FKSksIHEpO1xuXHRcdHV0aWwucHJpbnRfZGVidWcoXCJyc2EuanMgZGVjcnlwdFxcbnhwbjpcIit1dGlsLmhleHN0cmR1bXAoeHAudG9NUEkoKSkrXCJcXG54cW46XCIrdXRpbC5oZXhzdHJkdW1wKHhxLnRvTVBJKCkpKTtcblxuXHRcdHZhciB0ID0geHEuc3VidHJhY3QoeHApO1xuXHRcdGlmICh0WzBdID09IDApIHtcblx0XHRcdHQgPSB4cC5zdWJ0cmFjdCh4cSk7XG5cdFx0XHR0ID0gdC5tdWx0aXBseSh1KS5tb2QocSk7XG5cdFx0XHR0ID0gcS5zdWJ0cmFjdCh0KTtcblx0XHR9IGVsc2Uge1xuXHRcdFx0dCA9IHQubXVsdGlwbHkodSkubW9kKHEpO1xuXHRcdH1cblx0XHRyZXR1cm4gdC5tdWx0aXBseShwKS5hZGQoeHApO1xuXHR9XG5cdFxuXHQvKipcblx0ICogZW5jcnlwdCBtZXNzYWdlXG5cdCAqIEBwYXJhbSBtIG1lc3NhZ2UgYXMgQmlnSW50ZWdlclxuXHQgKiBAcGFyYW0gZSBwdWJsaWMgTVBJIHBhcnQgYXMgQmlnSW50ZWdlclxuXHQgKiBAcGFyYW0gbiBwdWJsaWMgTVBJIHBhcnQgYXMgQmlnSW50ZWdlclxuXHQgKiBAcmV0dXJuIEJpZ0ludGVnZXJcblx0ICovXG5cdGZ1bmN0aW9uIGVuY3J5cHQobSxlLG4pIHtcblx0XHRyZXR1cm4gbS5tb2RQb3dJbnQoZSwgbik7XG5cdH1cblx0XG5cdC8qIFNpZ24gYW5kIFZlcmlmeSAqL1xuXHRmdW5jdGlvbiBzaWduKG0sZCxuKSB7XG5cdFx0cmV0dXJuIG0ubW9kUG93KGQsIG4pO1xuXHR9XG5cdFx0XG5cdGZ1bmN0aW9uIHZlcmlmeSh4LGUsbikge1xuXHRcdHJldHVybiB4Lm1vZFBvd0ludChlLCBuKTtcblx0fVxuXHRcblx0Ly8gXCJlbXB0eVwiIFJTQSBrZXkgY29uc3RydWN0b3JcbiAgICBmdW5jdGlvbiBrZXlPYmplY3QoKSB7XG4gICAgICAgIHRoaXMubiA9IG51bGw7XG4gICAgICAgIHRoaXMuZSA9IDA7XG4gICAgICAgIHRoaXMuZWUgPSBudWxsO1xuICAgICAgICB0aGlzLmQgPSBudWxsO1xuICAgICAgICB0aGlzLnAgPSBudWxsO1xuICAgICAgICB0aGlzLnEgPSBudWxsO1xuICAgICAgICB0aGlzLmRtcDEgPSBudWxsO1xuICAgICAgICB0aGlzLmRtcTEgPSBudWxsO1xuICAgICAgICB0aGlzLnUgPSBudWxsO1xuICAgIH1cblx0XG5cdC8vIEdlbmVyYXRlIGEgbmV3IHJhbmRvbSBwcml2YXRlIGtleSBCIGJpdHMgbG9uZywgdXNpbmcgcHVibGljIGV4cHQgRVxuICAgIGZ1bmN0aW9uIGdlbmVyYXRlKEIsRSkge1xuICAgICAgICB2YXIga2V5ID0gbmV3IGtleU9iamVjdCgpO1xuICAgICAgICB2YXIgcm5nID0gbmV3IFNlY3VyZVJhbmRvbSgpO1xuICAgICAgICB2YXIgcXMgPSBCPj4xO1xuICAgICAgICBrZXkuZSA9IHBhcnNlSW50KEUsMTYpO1xuICAgICAgICBrZXkuZWUgPSBuZXcgQmlnSW50ZWdlcihFLDE2KTtcbiAgICAgICAgZm9yKDs7KSB7XG4gICAgICAgICAgICBmb3IoOzspIHtcbiAgICAgICAgICAgICAgICBrZXkucCA9IG5ldyBCaWdJbnRlZ2VyKEItcXMsMSxybmcpO1xuICAgICAgICAgICAgICAgIGlmKGtleS5wLnN1YnRyYWN0KEJpZ0ludGVnZXIuT05FKS5nY2Qoa2V5LmVlKS5jb21wYXJlVG8oQmlnSW50ZWdlci5PTkUpID09IDAgJiYga2V5LnAuaXNQcm9iYWJsZVByaW1lKDEwKSkgYnJlYWs7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBmb3IoOzspIHtcbiAgICAgICAgICAgICAgICBrZXkucSA9IG5ldyBCaWdJbnRlZ2VyKHFzLDEscm5nKTtcbiAgICAgICAgICAgICAgICBpZihrZXkucS5zdWJ0cmFjdChCaWdJbnRlZ2VyLk9ORSkuZ2NkKGtleS5lZSkuY29tcGFyZVRvKEJpZ0ludGVnZXIuT05FKSA9PSAwICYmIGtleS5xLmlzUHJvYmFibGVQcmltZSgxMCkpIGJyZWFrO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgaWYoa2V5LnAuY29tcGFyZVRvKGtleS5xKSA8PSAwKSB7XG4gICAgICAgICAgICAgICAgdmFyIHQgPSBrZXkucDtcbiAgICAgICAgICAgICAgICBrZXkucCA9IGtleS5xO1xuICAgICAgICAgICAgICAgIGtleS5xID0gdDtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHZhciBwMSA9IGtleS5wLnN1YnRyYWN0KEJpZ0ludGVnZXIuT05FKTtcbiAgICAgICAgICAgIHZhciBxMSA9IGtleS5xLnN1YnRyYWN0KEJpZ0ludGVnZXIuT05FKTtcbiAgICAgICAgICAgIHZhciBwaGkgPSBwMS5tdWx0aXBseShxMSk7XG4gICAgICAgICAgICBpZihwaGkuZ2NkKGtleS5lZSkuY29tcGFyZVRvKEJpZ0ludGVnZXIuT05FKSA9PSAwKSB7XG4gICAgICAgICAgICAgICAga2V5Lm4gPSBrZXkucC5tdWx0aXBseShrZXkucSk7XG4gICAgICAgICAgICAgICAga2V5LmQgPSBrZXkuZWUubW9kSW52ZXJzZShwaGkpO1xuICAgICAgICAgICAgICAgIGtleS5kbXAxID0ga2V5LmQubW9kKHAxKTtcbiAgICAgICAgICAgICAgICBrZXkuZG1xMSA9IGtleS5kLm1vZChxMSk7XG4gICAgICAgICAgICAgICAga2V5LnUgPSBrZXkucC5tb2RJbnZlcnNlKGtleS5xKTtcbiAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICByZXR1cm4ga2V5O1xuICAgIH1cblx0XHRcblx0dGhpcy5lbmNyeXB0ID0gZW5jcnlwdDtcblx0dGhpcy5kZWNyeXB0ID0gZGVjcnlwdDtcblx0dGhpcy52ZXJpZnkgPSB2ZXJpZnk7XG5cdHRoaXMuc2lnbiA9IHNpZ247XG5cdHRoaXMuZ2VuZXJhdGUgPSBnZW5lcmF0ZTtcblx0dGhpcy5rZXlPYmplY3QgPSBrZXlPYmplY3Q7XG59XG5cbm1vZHVsZS5leHBvcnRzID0gUlNBO1xuIiwiLy8gR1BHNEJyb3dzZXJzIC0gQW4gT3BlblBHUCBpbXBsZW1lbnRhdGlvbiBpbiBqYXZhc2NyaXB0XG4vLyBDb3B5cmlnaHQgKEMpIDIwMTEgUmVjdXJpdHkgTGFicyBHbWJIXG4vLyBcbi8vIFRoaXMgbGlicmFyeSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3Jcbi8vIG1vZGlmeSBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBMZXNzZXIgR2VuZXJhbCBQdWJsaWNcbi8vIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5IHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlclxuLy8gdmVyc2lvbiAyLjEgb2YgdGhlIExpY2Vuc2UsIG9yIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4vLyBcbi8vIFRoaXMgbGlicmFyeSBpcyBkaXN0cmlidXRlZCBpbiB0aGUgaG9wZSB0aGF0IGl0IHdpbGwgYmUgdXNlZnVsLFxuLy8gYnV0IFdJVEhPVVQgQU5ZIFdBUlJBTlRZOyB3aXRob3V0IGV2ZW4gdGhlIGltcGxpZWQgd2FycmFudHkgb2Zcbi8vIE1FUkNIQU5UQUJJTElUWSBvciBGSVRORVNTIEZPUiBBIFBBUlRJQ1VMQVIgUFVSUE9TRS4gIFNlZSB0aGUgR05VXG4vLyBMZXNzZXIgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBmb3IgbW9yZSBkZXRhaWxzLlxuLy8gXG4vLyBZb3Ugc2hvdWxkIGhhdmUgcmVjZWl2ZWQgYSBjb3B5IG9mIHRoZSBHTlUgTGVzc2VyIEdlbmVyYWwgUHVibGljXG4vLyBMaWNlbnNlIGFsb25nIHdpdGggdGhpcyBsaWJyYXJ5OyBpZiBub3QsIHdyaXRlIHRvIHRoZSBGcmVlIFNvZnR3YXJlXG4vLyBGb3VuZGF0aW9uLCBJbmMuLCA1MSBGcmFua2xpbiBTdHJlZXQsIEZpZnRoIEZsb29yLCBCb3N0b24sIE1BICAwMjExMC0xMzAxICBVU0FcblxuLyoqXG4gKiBBU04xIG9iamVjdCBpZGVudGlmaWVycyBmb3IgaGFzaGVzIChTZWUgUkZDNDg4MCA1LjIuMilcbiAqL1xuaGFzaF9oZWFkZXJzID0gbmV3IEFycmF5KCk7XG5oYXNoX2hlYWRlcnNbMV0gID0gWzB4MzAsMHgyMCwweDMwLDB4MGMsMHgwNiwweDA4LDB4MmEsMHg4NiwweDQ4LDB4ODYsMHhmNywweDBkLDB4MDIsMHgwNSwweDA1LDB4MDAsMHgwNCwweDEwXTtcbmhhc2hfaGVhZGVyc1szXSAgPSBbMHgzMCwweDIxLDB4MzAsMHgwOSwweDA2LDB4MDUsMHgyQiwweDI0LDB4MDMsMHgwMiwweDAxLDB4MDUsMHgwMCwweDA0LDB4MTRdO1xuaGFzaF9oZWFkZXJzWzJdICA9IFsweDMwLDB4MjEsMHgzMCwweDA5LDB4MDYsMHgwNSwweDJiLDB4MGUsMHgwMywweDAyLDB4MWEsMHgwNSwweDAwLDB4MDQsMHgxNF07XG5oYXNoX2hlYWRlcnNbOF0gID0gWzB4MzAsMHgzMSwweDMwLDB4MGQsMHgwNiwweDA5LDB4NjAsMHg4NiwweDQ4LDB4MDEsMHg2NSwweDAzLDB4MDQsMHgwMiwweDAxLDB4MDUsMHgwMCwweDA0LDB4MjBdO1xuaGFzaF9oZWFkZXJzWzldICA9IFsweDMwLDB4NDEsMHgzMCwweDBkLDB4MDYsMHgwOSwweDYwLDB4ODYsMHg0OCwweDAxLDB4NjUsMHgwMywweDA0LDB4MDIsMHgwMiwweDA1LDB4MDAsMHgwNCwweDMwXTtcbmhhc2hfaGVhZGVyc1sxMF0gPSBbMHgzMCwweDUxLDB4MzAsMHgwZCwweDA2LDB4MDksMHg2MCwweDg2LDB4NDgsMHgwMSwweDY1LDB4MDMsMHgwNCwweDAyLDB4MDMsMHgwNSwweDAwLDB4MDQsMHg0MF07XG5oYXNoX2hlYWRlcnNbMTFdID0gWzB4MzAsMHgzMSwweDMwLDB4MGQsMHgwNiwweDA5LDB4NjAsMHg4NiwweDQ4LDB4MDEsMHg2NSwweDAzLDB4MDQsMHgwMiwweDA0LDB4MDUsMHgwMCwweDA0LDB4MUNdO1xuXG5cbnZhciBjcnlwdG8gPSByZXF1aXJlKCcuL2NyeXB0by5qcycpLFxuXHRyYW5kb20gPSByZXF1aXJlKCcuL3JhbmRvbS5qcycpLFxuXHR1dGlsID0gcmVxdWlyZSgnLi4vdXRpbCcpLFxuXHRCaWdJbnRlZ2VyID0gcmVxdWlyZSgnLi9wdWJsaWNfa2V5L2pzYm4uanMnKSxcblx0aGFzaCA9IHJlcXVpcmUoJy4vaGFzaCcpO1xuXHRcbm1vZHVsZS5leHBvcnRzID0ge1xuXHRlbWU6IHtcblx0LyoqXG5cdCAqIGNyZWF0ZSBhIEVNRS1QS0NTMS12MV81IHBhZGRpbmcgKFNlZSBSRkM0ODgwIDEzLjEuMSlcblx0ICogQHBhcmFtIHtTdHJpbmd9IG1lc3NhZ2UgbWVzc2FnZSB0byBiZSBwYWRkZWRcblx0ICogQHBhcmFtIHtJbnRlZ2VyfSBsZW5ndGggTGVuZ3RoIHRvIHRoZSByZXN1bHRpbmcgbWVzc2FnZVxuXHQgKiBAcmV0dXJuIHtTdHJpbmd9IEVNRS1QS0NTMSBwYWRkZWQgbWVzc2FnZVxuXHQgKi9cblx0ZW5jb2RlOiBmdW5jdGlvbihtZXNzYWdlLCBsZW5ndGgpIHtcblx0XHRpZiAobWVzc2FnZS5sZW5ndGggPiBsZW5ndGgtMTEpXG5cdFx0XHRyZXR1cm4gLTE7XG5cdFx0dmFyIHJlc3VsdCA9IFwiXCI7XG5cdFx0cmVzdWx0ICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoMCk7XG5cdFx0cmVzdWx0ICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoMik7XG5cdFx0Zm9yICh2YXIgaSA9IDA7IGkgPCBsZW5ndGggLSBtZXNzYWdlLmxlbmd0aCAtIDM7IGkrKykge1xuXHRcdFx0cmVzdWx0ICs9IFN0cmluZy5mcm9tQ2hhckNvZGUocmFuZG9tLmdldFBzZXVkb1JhbmRvbSgxLDI1NSkpO1xuXHRcdH1cblx0XHRyZXN1bHQgKz0gU3RyaW5nLmZyb21DaGFyQ29kZSgwKTtcblx0XHRyZXN1bHQgKz0gbWVzc2FnZTtcblx0XHRyZXR1cm4gcmVzdWx0O1xuXHR9LFxuXG5cdC8qKlxuXHQgKiBkZWNvZGVzIGEgRU1FLVBLQ1MxLXYxXzUgcGFkZGluZyAoU2VlIFJGQzQ4ODAgMTMuMS4yKVxuXHQgKiBAcGFyYW0ge1N0cmluZ30gbWVzc2FnZSBFTUUtUEtDUzEgcGFkZGVkIG1lc3NhZ2Vcblx0ICogQHJldHVybiB7U3RyaW5nfSBkZWNvZGVkIG1lc3NhZ2UgXG5cdCAqL1xuXHQgZGVjb2RlOiBmdW5jdGlvbihtZXNzYWdlLCBsZW4pIHtcblx0XHRpZiAobWVzc2FnZS5sZW5ndGggPCBsZW4pXG5cdFx0XHRtZXNzYWdlID0gU3RyaW5nLmZyb21DaGFyQ29kZSgwKSttZXNzYWdlO1xuXHRcdGlmIChtZXNzYWdlLmxlbmd0aCA8IDEyIHx8IG1lc3NhZ2UuY2hhckNvZGVBdCgwKSAhPSAwIHx8IG1lc3NhZ2UuY2hhckNvZGVBdCgxKSAhPSAyKVxuXHRcdFx0cmV0dXJuIC0xO1xuXHRcdHZhciBpID0gMjtcblx0XHR3aGlsZSAobWVzc2FnZS5jaGFyQ29kZUF0KGkpICE9IDAgJiYgbWVzc2FnZS5sZW5ndGggPiBpKVxuXHRcdFx0aSsrO1xuXHRcdHJldHVybiBtZXNzYWdlLnN1YnN0cmluZyhpKzEsIG1lc3NhZ2UubGVuZ3RoKTtcblx0fSxcblx0fSxcblxuXHRlbXNhOiB7XG5cblx0LyoqXG5cdCAqIGNyZWF0ZSBhIEVNU0EtUEtDUzEtdjFfNSBwYWRkaW5nIChTZWUgUkZDNDg4MCAxMy4xLjMpXG5cdCAqIEBwYXJhbSB7SW50ZWdlcn0gYWxnbyBIYXNoIGFsZ29yaXRobSB0eXBlIHVzZWRcblx0ICogQHBhcmFtIHtTdHJpbmd9IGRhdGEgRGF0YSB0byBiZSBoYXNoZWRcblx0ICogQHBhcmFtIHtJbnRlZ2VyfSBrZXlsZW5ndGggS2V5IHNpemUgb2YgdGhlIHB1YmxpYyBtcGkgaW4gYnl0ZXNcblx0ICogQHJldHVybnMge1N0cmluZ30gSGFzaGNvZGUgd2l0aCBwa2NzMXBhZGRpbmcgYXMgc3RyaW5nXG5cdCAqL1xuXHRlbmNvZGU6IGZ1bmN0aW9uKGFsZ28sIGRhdGEsIGtleWxlbmd0aCkge1xuXHRcdHZhciBkYXRhMiA9IFwiXCI7XG5cdFx0ZGF0YTIgKz0gU3RyaW5nLmZyb21DaGFyQ29kZSgweDAwKTtcblx0XHRkYXRhMiArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKDB4MDEpO1xuXHRcdGZvciAodmFyIGkgPSAwOyBpIDwgKGtleWxlbmd0aCAtIGhhc2hfaGVhZGVyc1thbGdvXS5sZW5ndGggLSAzIC0gXG5cdFx0XHRoYXNoLmdldEhhc2hCeXRlTGVuZ3RoKGFsZ28pKTsgaSsrKVxuXG5cdFx0XHRkYXRhMiArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKDB4ZmYpO1xuXG5cdFx0ZGF0YTIgKz0gU3RyaW5nLmZyb21DaGFyQ29kZSgweDAwKTtcblx0XHRcblx0XHRmb3IgKHZhciBpID0gMDsgaSA8IGhhc2hfaGVhZGVyc1thbGdvXS5sZW5ndGg7IGkrKylcblx0XHRcdGRhdGEyICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoaGFzaF9oZWFkZXJzW2FsZ29dW2ldKTtcblx0XHRcblx0XHRkYXRhMiArPSBoYXNoLmRpZ2VzdChhbGdvLCBkYXRhKTtcblx0XHRyZXR1cm4gbmV3IEJpZ0ludGVnZXIodXRpbC5oZXhzdHJkdW1wKGRhdGEyKSwxNik7XG5cdH0sXG5cblx0LyoqXG5cdCAqIGV4dHJhY3QgdGhlIGhhc2ggb3V0IG9mIGFuIEVNU0EtUEtDUzEtdjEuNSBwYWRkaW5nIChTZWUgUkZDNDg4MCAxMy4xLjMpIFxuXHQgKiBAcGFyYW0ge1N0cmluZ30gZGF0YSBIYXNoIGluIHBrY3MxIGVuY29kaW5nXG5cdCAqIEByZXR1cm5zIHtTdHJpbmd9IFRoZSBoYXNoIGFzIHN0cmluZ1xuXHQgKi9cblx0ZGVjb2RlOiBmdW5jdGlvbihhbGdvLCBkYXRhKSB7IFxuXHRcdHZhciBpID0gMDtcblx0XHRpZiAoZGF0YS5jaGFyQ29kZUF0KDApID09IDApIGkrKztcblx0XHRlbHNlIGlmIChkYXRhLmNoYXJDb2RlQXQoMCkgIT0gMSkgcmV0dXJuIC0xO1xuXHRcdGVsc2UgaSsrO1xuXG5cdFx0d2hpbGUgKGRhdGEuY2hhckNvZGVBdChpKSA9PSAweEZGKSBpKys7XG5cdFx0aWYgKGRhdGEuY2hhckNvZGVBdChpKyspICE9IDApIHJldHVybiAtMTtcblx0XHR2YXIgaiA9IDA7XG5cdFx0Zm9yIChqID0gMDsgaiA8IGhhc2hfaGVhZGVyc1thbGdvXS5sZW5ndGggJiYgaitpIDwgZGF0YS5sZW5ndGg7IGorKykge1xuXHRcdFx0aWYgKGRhdGEuY2hhckNvZGVBdChqK2kpICE9IGhhc2hfaGVhZGVyc1thbGdvXVtqXSkgcmV0dXJuIC0xO1xuXHRcdH1cblx0XHRpKz0gajtcdFxuXHRcdGlmIChkYXRhLnN1YnN0cmluZyhpKS5sZW5ndGggPCBoYXNoLmdldEhhc2hCeXRlTGVuZ3RoKGFsZ28pKSByZXR1cm4gLTE7XG5cdFx0cmV0dXJuIGRhdGEuc3Vic3RyaW5nKGkpO1xuXHR9XG5cdH1cbn1cbiIsIi8vIEdQRzRCcm93c2VycyAtIEFuIE9wZW5QR1AgaW1wbGVtZW50YXRpb24gaW4gamF2YXNjcmlwdFxuLy8gQ29weXJpZ2h0IChDKSAyMDExIFJlY3VyaXR5IExhYnMgR21iSFxuLy8gXG4vLyBUaGlzIGxpYnJhcnkgaXMgZnJlZSBzb2Z0d2FyZTsgeW91IGNhbiByZWRpc3RyaWJ1dGUgaXQgYW5kL29yXG4vLyBtb2RpZnkgaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgTGVzc2VyIEdlbmVyYWwgUHVibGljXG4vLyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieSB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uOyBlaXRoZXJcbi8vIHZlcnNpb24gMi4xIG9mIHRoZSBMaWNlbnNlLCBvciAoYXQgeW91ciBvcHRpb24pIGFueSBsYXRlciB2ZXJzaW9uLlxuLy8gXG4vLyBUaGlzIGxpYnJhcnkgaXMgZGlzdHJpYnV0ZWQgaW4gdGhlIGhvcGUgdGhhdCBpdCB3aWxsIGJlIHVzZWZ1bCxcbi8vIGJ1dCBXSVRIT1VUIEFOWSBXQVJSQU5UWTsgd2l0aG91dCBldmVuIHRoZSBpbXBsaWVkIHdhcnJhbnR5IG9mXG4vLyBNRVJDSEFOVEFCSUxJVFkgb3IgRklUTkVTUyBGT1IgQSBQQVJUSUNVTEFSIFBVUlBPU0UuICBTZWUgdGhlIEdOVVxuLy8gTGVzc2VyIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgZm9yIG1vcmUgZGV0YWlscy5cbi8vIFxuLy8gWW91IHNob3VsZCBoYXZlIHJlY2VpdmVkIGEgY29weSBvZiB0aGUgR05VIExlc3NlciBHZW5lcmFsIFB1YmxpY1xuLy8gTGljZW5zZSBhbG9uZyB3aXRoIHRoaXMgbGlicmFyeTsgaWYgbm90LCB3cml0ZSB0byB0aGUgRnJlZSBTb2Z0d2FyZVxuLy8gRm91bmRhdGlvbiwgSW5jLiwgNTEgRnJhbmtsaW4gU3RyZWV0LCBGaWZ0aCBGbG9vciwgQm9zdG9uLCBNQSAgMDIxMTAtMTMwMSAgVVNBXG5cbnZhciBlbnVtcyA9IHJlcXVpcmUoJy4uL2VudW1zLmpzJyksXG5cdHV0aWwgPSByZXF1aXJlKCcuLi91dGlsJyk7XG5cblxubW9kdWxlLmV4cG9ydHMgPSB7XG5cdHJlYWRTaW1wbGVMZW5ndGg6IGZ1bmN0aW9uKGJ5dGVzKSB7XG5cdFx0dmFyIGxlbiA9IDAsXG5cdFx0XHRvZmZzZXQsXG5cdFx0XHR0eXBlID0gYnl0ZXNbMF0uY2hhckNvZGVBdCgpO1xuXG5cblx0XHRpZiAodHlwZSA8IDE5Mikge1xuXHRcdFx0bGVuID0gYnl0ZXNbMF0uY2hhckNvZGVBdCgpO1xuXHRcdFx0b2Zmc2V0ID0gMTtcblx0XHR9IGVsc2UgaWYgKHR5cGUgPCAyNTUpIHtcblx0XHRcdGxlbiA9ICgoYnl0ZXNbMF0uY2hhckNvZGVBdCgpIC0gMTkyKSA8PCA4KSArIChieXRlc1sxXS5jaGFyQ29kZUF0KCkpICsgMTkyO1xuXHRcdFx0b2Zmc2V0ID0gMjtcblx0XHR9IGVsc2UgaWYgKHR5cGUgPT0gMjU1KSB7XG5cdFx0XHRsZW4gPSB1dGlsLnJlYWROdW1iZXIoYnl0ZXMuc3Vic3RyKDEsIDQpKTtcblx0XHRcdG9mZnNldCA9IDU7XG5cdFx0fVxuXG5cdFx0cmV0dXJuIHsgbGVuOiBsZW4sIG9mZnNldDogb2Zmc2V0IH07XG5cdH0sXG5cblx0LyoqXG5cdCAqIEVuY29kZXMgYSBnaXZlbiBpbnRlZ2VyIG9mIGxlbmd0aCB0byB0aGUgb3BlbnBncCBsZW5ndGggc3BlY2lmaWVyIHRvIGFcblx0ICogc3RyaW5nXG5cdCAqIFxuXHQgKiBAcGFyYW0ge0ludGVnZXJ9IGxlbmd0aCBUaGUgbGVuZ3RoIHRvIGVuY29kZVxuXHQgKiBAcmV0dXJuIHtTdHJpbmd9IFN0cmluZyB3aXRoIG9wZW5wZ3AgbGVuZ3RoIHJlcHJlc2VudGF0aW9uXG5cdCAqL1xuXHR3cml0ZVNpbXBsZUxlbmd0aDogZnVuY3Rpb24obGVuZ3RoKSB7XG5cdFx0dmFyIHJlc3VsdCA9IFwiXCI7XG5cdFx0aWYgKGxlbmd0aCA8IDE5Mikge1xuXHRcdFx0cmVzdWx0ICs9IFN0cmluZy5mcm9tQ2hhckNvZGUobGVuZ3RoKTtcblx0XHR9IGVsc2UgaWYgKGxlbmd0aCA+IDE5MSAmJiBsZW5ndGggPCA4Mzg0KSB7XG5cdFx0XHQvKlxuXHRcdFx0ICogbGV0IGEgPSAodG90YWwgZGF0YSBwYWNrZXQgbGVuZ3RoKSAtIDE5MiBsZXQgYmMgPSB0d28gb2N0ZXRcblx0XHRcdCAqIHJlcHJlc2VudGF0aW9uIG9mIGEgbGV0IGQgPSBiICsgMTkyXG5cdFx0XHQgKi9cblx0XHRcdHJlc3VsdCArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKCgobGVuZ3RoIC0gMTkyKSA+PiA4KSArIDE5Mik7XG5cdFx0XHRyZXN1bHQgKz0gU3RyaW5nLmZyb21DaGFyQ29kZSgobGVuZ3RoIC0gMTkyKSAmIDB4RkYpO1xuXHRcdH0gZWxzZSB7XG5cdFx0XHRyZXN1bHQgKz0gU3RyaW5nLmZyb21DaGFyQ29kZSgyNTUpO1xuXHRcdFx0cmVzdWx0ICs9IHV0aWwud3JpdGVOdW1iZXIobGVuZ3RoLCA0KTtcblx0XHR9XG5cdFx0cmV0dXJuIHJlc3VsdDtcblx0fSxcblxuXHQvKipcblx0ICogV3JpdGVzIGEgcGFja2V0IGhlYWRlciB2ZXJzaW9uIDQgd2l0aCB0aGUgZ2l2ZW4gdGFnX3R5cGUgYW5kIGxlbmd0aCB0byBhXG5cdCAqIHN0cmluZ1xuXHQgKiBcblx0ICogQHBhcmFtIHtJbnRlZ2VyfSB0YWdfdHlwZSBUYWcgdHlwZVxuXHQgKiBAcGFyYW0ge0ludGVnZXJ9IGxlbmd0aCBMZW5ndGggb2YgdGhlIHBheWxvYWRcblx0ICogQHJldHVybiB7U3RyaW5nfSBTdHJpbmcgb2YgdGhlIGhlYWRlclxuXHQgKi9cblx0d3JpdGVIZWFkZXI6IGZ1bmN0aW9uKHRhZ190eXBlLCBsZW5ndGgpIHtcblx0XHQvKiB3ZSdyZSBvbmx5IGdlbmVyYXRpbmcgdjQgcGFja2V0IGhlYWRlcnMgaGVyZSAqL1xuXHRcdHZhciByZXN1bHQgPSBcIlwiO1xuXHRcdHJlc3VsdCArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKDB4QzAgfCB0YWdfdHlwZSk7XG5cdFx0cmVzdWx0ICs9IHRoaXMud3JpdGVTaW1wbGVMZW5ndGgobGVuZ3RoKTtcblx0XHRyZXR1cm4gcmVzdWx0O1xuXHR9LFxuXG5cdC8qKlxuXHQgKiBXcml0ZXMgYSBwYWNrZXQgaGVhZGVyIFZlcnNpb24gMyB3aXRoIHRoZSBnaXZlbiB0YWdfdHlwZSBhbmQgbGVuZ3RoIHRvIGFcblx0ICogc3RyaW5nXG5cdCAqIFxuXHQgKiBAcGFyYW0ge0ludGVnZXJ9IHRhZ190eXBlIFRhZyB0eXBlXG5cdCAqIEBwYXJhbSB7SW50ZWdlcn0gbGVuZ3RoIExlbmd0aCBvZiB0aGUgcGF5bG9hZFxuXHQgKiBAcmV0dXJuIHtTdHJpbmd9IFN0cmluZyBvZiB0aGUgaGVhZGVyXG5cdCAqL1xuXHR3cml0ZU9sZEhlYWRlcjogZnVuY3Rpb24odGFnX3R5cGUsIGxlbmd0aCkge1xuXHRcdHZhciByZXN1bHQgPSBcIlwiO1xuXHRcdGlmIChsZW5ndGggPCAyNTYpIHtcblx0XHRcdHJlc3VsdCArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKDB4ODAgfCAodGFnX3R5cGUgPDwgMikpO1xuXHRcdFx0cmVzdWx0ICs9IFN0cmluZy5mcm9tQ2hhckNvZGUobGVuZ3RoKTtcblx0XHR9IGVsc2UgaWYgKGxlbmd0aCA8IDY1NTM2KSB7XG5cdFx0XHRyZXN1bHQgKz0gU3RyaW5nLmZyb21DaGFyQ29kZSgweDgwIHwgKHRhZ190eXBlIDw8IDIpIHwgMSk7XG5cdFx0XHRyZXN1bHQgKz0gdXRpbC53cml0ZU51bWJlcihsZW5ndGgsIDIpO1xuXHRcdH0gZWxzZSB7XG5cdFx0XHRyZXN1bHQgKz0gU3RyaW5nLmZyb21DaGFyQ29kZSgweDgwIHwgKHRhZ190eXBlIDw8IDIpIHwgMik7XG5cdFx0XHRyZXN1bHQgKz0gdXRpbC53cml0ZU51bWJlcihsZW5ndGgsIDQpO1xuXHRcdH1cblx0XHRyZXR1cm4gcmVzdWx0O1xuXHR9LFxuXG5cdC8qKlxuXHQgKiBHZW5lcmljIHN0YXRpYyBQYWNrZXQgUGFyc2VyIGZ1bmN0aW9uXG5cdCAqIFxuXHQgKiBAcGFyYW0ge1N0cmluZ30gaW5wdXQgSW5wdXQgc3RyZWFtIGFzIHN0cmluZ1xuXHQgKiBAcGFyYW0ge2ludGVnZXJ9IHBvc2l0aW9uIFBvc2l0aW9uIHRvIHN0YXJ0IHBhcnNpbmdcblx0ICogQHBhcmFtIHtpbnRlZ2VyfSBsZW4gTGVuZ3RoIG9mIHRoZSBpbnB1dCBmcm9tIHBvc2l0aW9uIG9uXG5cdCAqIEByZXR1cm4ge09iamVjdH0gUmV0dXJucyBhIHBhcnNlZCBvcGVucGdwX3BhY2tldFxuXHQgKi9cblx0cmVhZDogZnVuY3Rpb24oaW5wdXQsIHBvc2l0aW9uLCBsZW4pIHtcblx0XHQvLyBzb21lIHNhbml0eSBjaGVja3Ncblx0XHRpZiAoaW5wdXQgPT0gbnVsbCB8fCBpbnB1dC5sZW5ndGggPD0gcG9zaXRpb25cblx0XHRcdFx0fHwgaW5wdXQuc3Vic3RyaW5nKHBvc2l0aW9uKS5sZW5ndGggPCAyXG5cdFx0XHRcdHx8IChpbnB1dFtwb3NpdGlvbl0uY2hhckNvZGVBdCgpICYgMHg4MCkgPT0gMCkge1xuXHRcdFx0dXRpbFxuXHRcdFx0XHRcdC5wcmludF9lcnJvcihcIkVycm9yIGR1cmluZyBwYXJzaW5nLiBUaGlzIG1lc3NhZ2UgLyBrZXkgaXMgcHJvYmFibHkgbm90IGNvbnRhaW5pbmcgYSB2YWxpZCBPcGVuUEdQIGZvcm1hdC5cIik7XG5cdFx0XHRyZXR1cm4gbnVsbDtcblx0XHR9XG5cdFx0dmFyIG15cG9zID0gcG9zaXRpb247XG5cdFx0dmFyIHRhZyA9IC0xO1xuXHRcdHZhciBmb3JtYXQgPSAtMTtcblx0XHR2YXIgcGFja2V0X2xlbmd0aDtcblxuXHRcdGZvcm1hdCA9IDA7IC8vIDAgPSBvbGQgZm9ybWF0OyAxID0gbmV3IGZvcm1hdFxuXHRcdGlmICgoaW5wdXRbbXlwb3NdLmNoYXJDb2RlQXQoKSAmIDB4NDApICE9IDApIHtcblx0XHRcdGZvcm1hdCA9IDE7XG5cdFx0fVxuXG5cdFx0dmFyIHBhY2tldF9sZW5ndGhfdHlwZTtcblx0XHRpZiAoZm9ybWF0KSB7XG5cdFx0XHQvLyBuZXcgZm9ybWF0IGhlYWRlclxuXHRcdFx0dGFnID0gaW5wdXRbbXlwb3NdLmNoYXJDb2RlQXQoKSAmIDB4M0Y7IC8vIGJpdCA1LTBcblx0XHR9IGVsc2Uge1xuXHRcdFx0Ly8gb2xkIGZvcm1hdCBoZWFkZXJcblx0XHRcdHRhZyA9IChpbnB1dFtteXBvc10uY2hhckNvZGVBdCgpICYgMHgzRikgPj4gMjsgLy8gYml0IDUtMlxuXHRcdFx0cGFja2V0X2xlbmd0aF90eXBlID0gaW5wdXRbbXlwb3NdLmNoYXJDb2RlQXQoKSAmIDB4MDM7IC8vIGJpdCAxLTBcblx0XHR9XG5cblx0XHQvLyBoZWFkZXIgb2N0ZXQgcGFyc2luZyBkb25lXG5cdFx0bXlwb3MrKztcblxuXHRcdC8vIHBhcnNlZCBsZW5ndGggZnJvbSBsZW5ndGggZmllbGRcblx0XHR2YXIgYm9keWRhdGEgPSBudWxsO1xuXG5cdFx0Ly8gdXNlZCBmb3IgcGFydGlhbCBib2R5IGxlbmd0aHNcblx0XHR2YXIgcmVhbF9wYWNrZXRfbGVuZ3RoID0gLTE7XG5cdFx0aWYgKCFmb3JtYXQpIHtcblx0XHRcdC8vIDQuMi4xLiBPbGQgRm9ybWF0IFBhY2tldCBMZW5ndGhzXG5cdFx0XHRzd2l0Y2ggKHBhY2tldF9sZW5ndGhfdHlwZSkge1xuXHRcdFx0Y2FzZSAwOiAvLyBUaGUgcGFja2V0IGhhcyBhIG9uZS1vY3RldCBsZW5ndGguIFRoZSBoZWFkZXIgaXMgMiBvY3RldHNcblx0XHRcdFx0Ly8gbG9uZy5cblx0XHRcdFx0cGFja2V0X2xlbmd0aCA9IGlucHV0W215cG9zKytdLmNoYXJDb2RlQXQoKTtcblx0XHRcdFx0YnJlYWs7XG5cdFx0XHRjYXNlIDE6IC8vIFRoZSBwYWNrZXQgaGFzIGEgdHdvLW9jdGV0IGxlbmd0aC4gVGhlIGhlYWRlciBpcyAzIG9jdGV0c1xuXHRcdFx0XHQvLyBsb25nLlxuXHRcdFx0XHRwYWNrZXRfbGVuZ3RoID0gKGlucHV0W215cG9zKytdLmNoYXJDb2RlQXQoKSA8PCA4KVxuXHRcdFx0XHRcdFx0fCBpbnB1dFtteXBvcysrXS5jaGFyQ29kZUF0KCk7XG5cdFx0XHRcdGJyZWFrO1xuXHRcdFx0Y2FzZSAyOiAvLyBUaGUgcGFja2V0IGhhcyBhIGZvdXItb2N0ZXQgbGVuZ3RoLiBUaGUgaGVhZGVyIGlzIDVcblx0XHRcdFx0Ly8gb2N0ZXRzIGxvbmcuXG5cdFx0XHRcdHBhY2tldF9sZW5ndGggPSAoaW5wdXRbbXlwb3MrK10uY2hhckNvZGVBdCgpIDw8IDI0KVxuXHRcdFx0XHRcdFx0fCAoaW5wdXRbbXlwb3MrK10uY2hhckNvZGVBdCgpIDw8IDE2KVxuXHRcdFx0XHRcdFx0fCAoaW5wdXRbbXlwb3MrK10uY2hhckNvZGVBdCgpIDw8IDgpXG5cdFx0XHRcdFx0XHR8IGlucHV0W215cG9zKytdLmNoYXJDb2RlQXQoKTtcblx0XHRcdFx0YnJlYWs7XG5cdFx0XHRkZWZhdWx0OlxuXHRcdFx0XHQvLyAzIC0gVGhlIHBhY2tldCBpcyBvZiBpbmRldGVybWluYXRlIGxlbmd0aC4gVGhlIGhlYWRlciBpcyAxXG5cdFx0XHRcdC8vIG9jdGV0IGxvbmcsIGFuZCB0aGUgaW1wbGVtZW50YXRpb24gbXVzdCBkZXRlcm1pbmUgaG93IGxvbmdcblx0XHRcdFx0Ly8gdGhlIHBhY2tldCBpcy4gSWYgdGhlIHBhY2tldCBpcyBpbiBhIGZpbGUsIHRoaXMgbWVhbnMgdGhhdFxuXHRcdFx0XHQvLyB0aGUgcGFja2V0IGV4dGVuZHMgdW50aWwgdGhlIGVuZCBvZiB0aGUgZmlsZS4gSW4gZ2VuZXJhbCwgXG5cdFx0XHRcdC8vIGFuIGltcGxlbWVudGF0aW9uIFNIT1VMRCBOT1QgdXNlIGluZGV0ZXJtaW5hdGUtbGVuZ3RoIFxuXHRcdFx0XHQvLyBwYWNrZXRzIGV4Y2VwdCB3aGVyZSB0aGUgZW5kIG9mIHRoZSBkYXRhIHdpbGwgYmUgY2xlYXIgXG5cdFx0XHRcdC8vIGZyb20gdGhlIGNvbnRleHQsIGFuZCBldmVuIHRoZW4gaXQgaXMgYmV0dGVyIHRvIHVzZSBhIFxuXHRcdFx0XHQvLyBkZWZpbml0ZSBsZW5ndGgsIG9yIGEgbmV3IGZvcm1hdCBoZWFkZXIuIFRoZSBuZXcgZm9ybWF0IFxuXHRcdFx0XHQvLyBoZWFkZXJzIGRlc2NyaWJlZCBiZWxvdyBoYXZlIGEgbWVjaGFuaXNtIGZvciBwcmVjaXNlbHlcblx0XHRcdFx0Ly8gZW5jb2RpbmcgZGF0YSBvZiBpbmRldGVybWluYXRlIGxlbmd0aC5cblx0XHRcdFx0cGFja2V0X2xlbmd0aCA9IGxlbjtcblx0XHRcdFx0YnJlYWs7XG5cdFx0XHR9XG5cblx0XHR9IGVsc2UgLy8gNC4yLjIuIE5ldyBGb3JtYXQgUGFja2V0IExlbmd0aHNcblx0XHR7XG5cblx0XHRcdC8vIDQuMi4yLjEuIE9uZS1PY3RldCBMZW5ndGhzXG5cdFx0XHRpZiAoaW5wdXRbbXlwb3NdLmNoYXJDb2RlQXQoKSA8IDE5Mikge1xuXHRcdFx0XHRwYWNrZXRfbGVuZ3RoID0gaW5wdXRbbXlwb3MrK10uY2hhckNvZGVBdCgpO1xuXHRcdFx0XHR1dGlsLnByaW50X2RlYnVnKFwiMSBieXRlIGxlbmd0aDpcIiArIHBhY2tldF9sZW5ndGgpO1xuXHRcdFx0XHQvLyA0LjIuMi4yLiBUd28tT2N0ZXQgTGVuZ3Roc1xuXHRcdFx0fSBlbHNlIGlmIChpbnB1dFtteXBvc10uY2hhckNvZGVBdCgpID49IDE5MlxuXHRcdFx0XHRcdCYmIGlucHV0W215cG9zXS5jaGFyQ29kZUF0KCkgPCAyMjQpIHtcblx0XHRcdFx0cGFja2V0X2xlbmd0aCA9ICgoaW5wdXRbbXlwb3MrK10uY2hhckNvZGVBdCgpIC0gMTkyKSA8PCA4KVxuXHRcdFx0XHRcdFx0KyAoaW5wdXRbbXlwb3MrK10uY2hhckNvZGVBdCgpKSArIDE5Mjtcblx0XHRcdFx0dXRpbC5wcmludF9kZWJ1ZyhcIjIgYnl0ZSBsZW5ndGg6XCIgKyBwYWNrZXRfbGVuZ3RoKTtcblx0XHRcdFx0Ly8gNC4yLjIuNC4gUGFydGlhbCBCb2R5IExlbmd0aHNcblx0XHRcdH0gZWxzZSBpZiAoaW5wdXRbbXlwb3NdLmNoYXJDb2RlQXQoKSA+IDIyM1xuXHRcdFx0XHRcdCYmIGlucHV0W215cG9zXS5jaGFyQ29kZUF0KCkgPCAyNTUpIHtcblx0XHRcdFx0cGFja2V0X2xlbmd0aCA9IDEgPDwgKGlucHV0W215cG9zKytdLmNoYXJDb2RlQXQoKSAmIDB4MUYpO1xuXHRcdFx0XHR1dGlsLnByaW50X2RlYnVnKFwiNCBieXRlIGxlbmd0aDpcIiArIHBhY2tldF9sZW5ndGgpO1xuXHRcdFx0XHQvLyBFRUVLLCB3ZSdyZSByZWFkaW5nIHRoZSBmdWxsIGRhdGEgaGVyZS4uLlxuXHRcdFx0XHR2YXIgbXlwb3MyID0gbXlwb3MgKyBwYWNrZXRfbGVuZ3RoO1xuXHRcdFx0XHRib2R5ZGF0YSA9IGlucHV0LnN1YnN0cmluZyhteXBvcywgbXlwb3MgKyBwYWNrZXRfbGVuZ3RoKTtcblx0XHRcdFx0d2hpbGUgKHRydWUpIHtcblx0XHRcdFx0XHRpZiAoaW5wdXRbbXlwb3MyXS5jaGFyQ29kZUF0KCkgPCAxOTIpIHtcblx0XHRcdFx0XHRcdHZhciB0bXBsZW4gPSBpbnB1dFtteXBvczIrK10uY2hhckNvZGVBdCgpO1xuXHRcdFx0XHRcdFx0cGFja2V0X2xlbmd0aCArPSB0bXBsZW47XG5cdFx0XHRcdFx0XHRib2R5ZGF0YSArPSBpbnB1dC5zdWJzdHJpbmcobXlwb3MyLCBteXBvczIgKyB0bXBsZW4pO1xuXHRcdFx0XHRcdFx0bXlwb3MyICs9IHRtcGxlbjtcblx0XHRcdFx0XHRcdGJyZWFrO1xuXHRcdFx0XHRcdH0gZWxzZSBpZiAoaW5wdXRbbXlwb3MyXS5jaGFyQ29kZUF0KCkgPj0gMTkyXG5cdFx0XHRcdFx0XHRcdCYmIGlucHV0W215cG9zMl0uY2hhckNvZGVBdCgpIDwgMjI0KSB7XG5cdFx0XHRcdFx0XHR2YXIgdG1wbGVuID0gKChpbnB1dFtteXBvczIrK10uY2hhckNvZGVBdCgpIC0gMTkyKSA8PCA4KVxuXHRcdFx0XHRcdFx0XHRcdCsgKGlucHV0W215cG9zMisrXS5jaGFyQ29kZUF0KCkpICsgMTkyO1xuXHRcdFx0XHRcdFx0cGFja2V0X2xlbmd0aCArPSB0bXBsZW47XG5cdFx0XHRcdFx0XHRib2R5ZGF0YSArPSBpbnB1dC5zdWJzdHJpbmcobXlwb3MyLCBteXBvczIgKyB0bXBsZW4pO1xuXHRcdFx0XHRcdFx0bXlwb3MyICs9IHRtcGxlbjtcblx0XHRcdFx0XHRcdGJyZWFrO1xuXHRcdFx0XHRcdH0gZWxzZSBpZiAoaW5wdXRbbXlwb3MyXS5jaGFyQ29kZUF0KCkgPiAyMjNcblx0XHRcdFx0XHRcdFx0JiYgaW5wdXRbbXlwb3MyXS5jaGFyQ29kZUF0KCkgPCAyNTUpIHtcblx0XHRcdFx0XHRcdHZhciB0bXBsZW4gPSAxIDw8IChpbnB1dFtteXBvczIrK10uY2hhckNvZGVBdCgpICYgMHgxRik7XG5cdFx0XHRcdFx0XHRwYWNrZXRfbGVuZ3RoICs9IHRtcGxlbjtcblx0XHRcdFx0XHRcdGJvZHlkYXRhICs9IGlucHV0LnN1YnN0cmluZyhteXBvczIsIG15cG9zMiArIHRtcGxlbik7XG5cdFx0XHRcdFx0XHRteXBvczIgKz0gdG1wbGVuO1xuXHRcdFx0XHRcdH0gZWxzZSB7XG5cdFx0XHRcdFx0XHRteXBvczIrKztcblx0XHRcdFx0XHRcdHZhciB0bXBsZW4gPSAoaW5wdXRbbXlwb3MyKytdLmNoYXJDb2RlQXQoKSA8PCAyNClcblx0XHRcdFx0XHRcdFx0XHR8IChpbnB1dFtteXBvczIrK10uY2hhckNvZGVBdCgpIDw8IDE2KVxuXHRcdFx0XHRcdFx0XHRcdHwgKGlucHV0W215cG9zMisrXS5jaGFyQ29kZUF0KCkgPDwgOClcblx0XHRcdFx0XHRcdFx0XHR8IGlucHV0W215cG9zMisrXS5jaGFyQ29kZUF0KCk7XG5cdFx0XHRcdFx0XHRib2R5ZGF0YSArPSBpbnB1dC5zdWJzdHJpbmcobXlwb3MyLCBteXBvczIgKyB0bXBsZW4pO1xuXHRcdFx0XHRcdFx0cGFja2V0X2xlbmd0aCArPSB0bXBsZW47XG5cdFx0XHRcdFx0XHRteXBvczIgKz0gdG1wbGVuO1xuXHRcdFx0XHRcdFx0YnJlYWs7XG5cdFx0XHRcdFx0fVxuXHRcdFx0XHR9XG5cdFx0XHRcdHJlYWxfcGFja2V0X2xlbmd0aCA9IG15cG9zMjtcblx0XHRcdFx0Ly8gNC4yLjIuMy4gRml2ZS1PY3RldCBMZW5ndGhzXG5cdFx0XHR9IGVsc2Uge1xuXHRcdFx0XHRteXBvcysrO1xuXHRcdFx0XHRwYWNrZXRfbGVuZ3RoID0gKGlucHV0W215cG9zKytdLmNoYXJDb2RlQXQoKSA8PCAyNClcblx0XHRcdFx0XHRcdHwgKGlucHV0W215cG9zKytdLmNoYXJDb2RlQXQoKSA8PCAxNilcblx0XHRcdFx0XHRcdHwgKGlucHV0W215cG9zKytdLmNoYXJDb2RlQXQoKSA8PCA4KVxuXHRcdFx0XHRcdFx0fCBpbnB1dFtteXBvcysrXS5jaGFyQ29kZUF0KCk7XG5cdFx0XHR9XG5cdFx0fVxuXG5cdFx0Ly8gaWYgdGhlcmUgd2FzJ250IGEgcGFydGlhbCBib2R5IGxlbmd0aDogdXNlIHRoZSBzcGVjaWZpZWRcblx0XHQvLyBwYWNrZXRfbGVuZ3RoXG5cdFx0aWYgKHJlYWxfcGFja2V0X2xlbmd0aCA9PSAtMSkge1xuXHRcdFx0cmVhbF9wYWNrZXRfbGVuZ3RoID0gcGFja2V0X2xlbmd0aDtcblx0XHR9XG5cblx0XHRpZiAoYm9keWRhdGEgPT0gbnVsbCkge1xuXHRcdFx0Ym9keWRhdGEgPSBpbnB1dC5zdWJzdHJpbmcobXlwb3MsIG15cG9zICsgcmVhbF9wYWNrZXRfbGVuZ3RoKTtcblx0XHR9XG5cblx0XHRyZXR1cm4geyBcblx0XHRcdHRhZzogdGFnLFxuXHRcdFx0cGFja2V0OiBib2R5ZGF0YSxcblx0XHRcdG9mZnNldDogbXlwb3MgKyByZWFsX3BhY2tldF9sZW5ndGhcblx0XHR9O1xuXHR9XG59XG5cbiIsIi8vIEdQRzRCcm93c2VycyAtIEFuIE9wZW5QR1AgaW1wbGVtZW50YXRpb24gaW4gamF2YXNjcmlwdFxuLy8gQ29weXJpZ2h0IChDKSAyMDExIFJlY3VyaXR5IExhYnMgR21iSFxuLy8gXG4vLyBUaGlzIGxpYnJhcnkgaXMgZnJlZSBzb2Z0d2FyZTsgeW91IGNhbiByZWRpc3RyaWJ1dGUgaXQgYW5kL29yXG4vLyBtb2RpZnkgaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgTGVzc2VyIEdlbmVyYWwgUHVibGljXG4vLyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieSB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uOyBlaXRoZXJcbi8vIHZlcnNpb24gMi4xIG9mIHRoZSBMaWNlbnNlLCBvciAoYXQgeW91ciBvcHRpb24pIGFueSBsYXRlciB2ZXJzaW9uLlxuLy8gXG4vLyBUaGlzIGxpYnJhcnkgaXMgZGlzdHJpYnV0ZWQgaW4gdGhlIGhvcGUgdGhhdCBpdCB3aWxsIGJlIHVzZWZ1bCxcbi8vIGJ1dCBXSVRIT1VUIEFOWSBXQVJSQU5UWTsgd2l0aG91dCBldmVuIHRoZSBpbXBsaWVkIHdhcnJhbnR5IG9mXG4vLyBNRVJDSEFOVEFCSUxJVFkgb3IgRklUTkVTUyBGT1IgQSBQQVJUSUNVTEFSIFBVUlBPU0UuICBTZWUgdGhlIEdOVVxuLy8gTGVzc2VyIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgZm9yIG1vcmUgZGV0YWlscy5cbi8vIFxuLy8gWW91IHNob3VsZCBoYXZlIHJlY2VpdmVkIGEgY29weSBvZiB0aGUgR05VIExlc3NlciBHZW5lcmFsIFB1YmxpY1xuLy8gTGljZW5zZSBhbG9uZyB3aXRoIHRoaXMgbGlicmFyeTsgaWYgbm90LCB3cml0ZSB0byB0aGUgRnJlZSBTb2Z0d2FyZVxuLy8gRm91bmRhdGlvbiwgSW5jLiwgNTEgRnJhbmtsaW4gU3RyZWV0LCBGaWZ0aCBGbG9vciwgQm9zdG9uLCBNQSAgMDIxMTAtMTMwMSAgVVNBXG5cbnZhciB1dGlsID0gcmVxdWlyZSgnLi4vdXRpbCcpLFxuXHRlbnVtcyA9IHJlcXVpcmUoJy4uL2VudW1zLmpzJyk7XG5cbi8qKlxuICogQGNsYXNzXG4gKiBAY2xhc3NkZXNjIEltcGxlbWVudGF0aW9uIG9mIHRoZSBMaXRlcmFsIERhdGEgUGFja2V0IChUYWcgMTEpXG4gKiBcbiAqIFJGQzQ4ODAgNS45OiBBIExpdGVyYWwgRGF0YSBwYWNrZXQgY29udGFpbnMgdGhlIGJvZHkgb2YgYSBtZXNzYWdlOyBkYXRhIHRoYXRcbiAqIGlzIG5vdCB0byBiZSBmdXJ0aGVyIGludGVycHJldGVkLlxuICovXG5tb2R1bGUuZXhwb3J0cyA9IGZ1bmN0aW9uIHBhY2tldF9saXRlcmFsKCkge1xuXHR0aGlzLmZvcm1hdCA9ICd1dGY4Jztcblx0dGhpcy5kYXRhID0gJyc7XG5cdHRoaXMuZGF0ZSA9IG5ldyBEYXRlKCk7XG5cblx0XG5cdC8qKlxuXHQgKiBTZXQgdGhlIHBhY2tldCBkYXRhIHRvIGEgamF2YXNjcmlwdCBuYXRpdmUgc3RyaW5nIG9yIGEgc3F1ZW5jZSBvZiBcblx0ICogYnl0ZXMuIENvbnZlcnNpb24gdG8gYSBwcm9wZXIgdXRmOCBlbmNvZGluZyB0YWtlcyBwbGFjZSB3aGVuIHRoZSBcblx0ICogcGFja2V0IGlzIHdyaXR0ZW4uXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBzdHIgQW55IG5hdGl2ZSBqYXZhc2NyaXB0IHN0cmluZ1xuXHQgKiBAcGFyYW0ge29wZW5wZ3BfcGFja2V0X2xpdGVyYWxkYXRhLmZvcm1hdH0gZm9ybWF0IFxuXHQgKi9cblx0dGhpcy5zZXQgPSBmdW5jdGlvbihzdHIsIGZvcm1hdCkge1xuXHRcdHRoaXMuZm9ybWF0ID0gZm9ybWF0O1xuXHRcdHRoaXMuZGF0YSA9IHN0cjtcblx0fVxuXG5cdC8qKlxuXHQgKiBTZXQgdGhlIHBhY2tldCBkYXRhIHRvIHZhbHVlIHJlcHJlc2VudGVkIGJ5IHRoZSBwcm92aWRlZCBzdHJpbmdcblx0ICogb2YgYnl0ZXMgdG9nZXRoZXIgd2l0aCB0aGUgYXBwcm9wcmlhdGUgY29udmVyc2lvbiBmb3JtYXQuXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBieXRlcyBUaGUgc3RyaW5nIG9mIGJ5dGVzXG5cdCAqIEBwYXJhbSB7b3BlbnBncF9wYWNrZXRfbGl0ZXJhbGRhdGEuZm9ybWF0fSBmb3JtYXRcblx0ICovXG5cdHRoaXMuc2V0Qnl0ZXMgPSBmdW5jdGlvbihieXRlcywgZm9ybWF0KSB7XG5cdFx0dGhpcy5mb3JtYXQgPSBmb3JtYXQ7XG5cblx0XHRpZihmb3JtYXQgPT0gJ3V0ZjgnKVxuXHRcdFx0Ynl0ZXMgPSB1dGlsLmRlY29kZV91dGY4KGJ5dGVzKTtcblxuXHRcdHRoaXMuZGF0YSA9IGJ5dGVzO1xuXHR9XG5cblx0LyoqXG5cdCAqIEdldCB0aGUgYnl0ZSBzZXF1ZW5jZSByZXByZXNlbnRpbmcgdGhlIGxpdGVyYWwgcGFja2V0IGRhdGFcblx0ICogQHJldHVybnMge1N0cmluZ30gQSBzZXF1ZW5jZSBvZiBieXRlc1xuXHQgKi9cblx0dGhpcy5nZXRCeXRlcyA9IGZ1bmN0aW9uKCkge1xuXHRcdGlmKHRoaXMuZm9ybWF0ID09ICd1dGY4Jylcblx0XHRcdHJldHVybiB1dGlsLmVuY29kZV91dGY4KHRoaXMuZGF0YSk7XG5cdFx0ZWxzZVxuXHRcdFx0cmV0dXJuIHRoaXMuZGF0YTtcblx0fVxuXHRcblx0XG5cblx0LyoqXG5cdCAqIFBhcnNpbmcgZnVuY3Rpb24gZm9yIGEgbGl0ZXJhbCBkYXRhIHBhY2tldCAodGFnIDExKS5cblx0ICogXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBpbnB1dCBQYXlsb2FkIG9mIGEgdGFnIDExIHBhY2tldFxuXHQgKiBAcGFyYW0ge0ludGVnZXJ9IHBvc2l0aW9uXG5cdCAqICAgICAgICAgICAgUG9zaXRpb24gdG8gc3RhcnQgcmVhZGluZyBmcm9tIHRoZSBpbnB1dCBzdHJpbmdcblx0ICogQHBhcmFtIHtJbnRlZ2VyfSBsZW5cblx0ICogICAgICAgICAgICBMZW5ndGggb2YgdGhlIHBhY2tldCBvciB0aGUgcmVtYWluaW5nIGxlbmd0aCBvZlxuXHQgKiAgICAgICAgICAgIGlucHV0IGF0IHBvc2l0aW9uXG5cdCAqIEByZXR1cm4ge29wZW5wZ3BfcGFja2V0X2VuY3J5cHRlZGRhdGF9IG9iamVjdCByZXByZXNlbnRhdGlvblxuXHQgKi9cblx0dGhpcy5yZWFkID0gZnVuY3Rpb24oYnl0ZXMpIHtcblx0XHQvLyAtIEEgb25lLW9jdGV0IGZpZWxkIHRoYXQgZGVzY3JpYmVzIGhvdyB0aGUgZGF0YSBpcyBmb3JtYXR0ZWQuXG5cblx0XHR2YXIgZm9ybWF0ID0gZW51bXMucmVhZChlbnVtcy5saXRlcmFsLCBieXRlc1swXS5jaGFyQ29kZUF0KCkpO1xuXG5cdFx0dmFyIGZpbGVuYW1lX2xlbiA9IGJ5dGVzLmNoYXJDb2RlQXQoMSk7XG5cdFx0dGhpcy5maWxlbmFtZSA9IHV0aWwuZGVjb2RlX3V0ZjgoYnl0ZXMuc3Vic3RyKDIsIGZpbGVuYW1lX2xlbikpO1xuXG5cdFx0dGhpcy5kYXRlID0gdXRpbC5yZWFkRGF0ZShieXRlcy5zdWJzdHIoMlxuXHRcdFx0XHQrIGZpbGVuYW1lX2xlbiwgNCkpO1xuXG5cdFx0dmFyIGRhdGEgPSBieXRlcy5zdWJzdHJpbmcoNiArIGZpbGVuYW1lX2xlbik7XG5cdFxuXHRcdHRoaXMuc2V0Qnl0ZXMoZGF0YSwgZm9ybWF0KTtcblx0fVxuXG5cdC8qKlxuXHQgKiBDcmVhdGVzIGEgc3RyaW5nIHJlcHJlc2VudGF0aW9uIG9mIHRoZSBwYWNrZXRcblx0ICogXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBkYXRhIFRoZSBkYXRhIHRvIGJlIGluc2VydGVkIGFzIGJvZHlcblx0ICogQHJldHVybiB7U3RyaW5nfSBzdHJpbmctcmVwcmVzZW50YXRpb24gb2YgdGhlIHBhY2tldFxuXHQgKi9cblx0dGhpcy53cml0ZSA9IGZ1bmN0aW9uKCkge1xuXHRcdHZhciBmaWxlbmFtZSA9IHV0aWwuZW5jb2RlX3V0ZjgoXCJtc2cudHh0XCIpO1xuXG5cdFx0dmFyIGRhdGEgPSB0aGlzLmdldEJ5dGVzKCk7XG5cblx0XHR2YXIgcmVzdWx0ID0gJyc7XG5cdFx0cmVzdWx0ICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoZW51bXMud3JpdGUoZW51bXMubGl0ZXJhbCwgdGhpcy5mb3JtYXQpKTtcblx0XHRyZXN1bHQgKz0gU3RyaW5nLmZyb21DaGFyQ29kZShmaWxlbmFtZS5sZW5ndGgpO1xuXHRcdHJlc3VsdCArPSBmaWxlbmFtZTtcblx0XHRyZXN1bHQgKz0gdXRpbC53cml0ZURhdGUodGhpcy5kYXRlKTtcblx0XHRyZXN1bHQgKz0gZGF0YTtcblx0XHRyZXR1cm4gcmVzdWx0O1xuXHR9XG59XG4iLCIvLyBHUEc0QnJvd3NlcnMgLSBBbiBPcGVuUEdQIGltcGxlbWVudGF0aW9uIGluIGphdmFzY3JpcHRcbi8vIENvcHlyaWdodCAoQykgMjAxMSBSZWN1cml0eSBMYWJzIEdtYkhcbi8vIFxuLy8gVGhpcyBsaWJyYXJ5IGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vclxuLy8gbW9kaWZ5IGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIExlc3NlciBHZW5lcmFsIFB1YmxpY1xuLy8gTGljZW5zZSBhcyBwdWJsaXNoZWQgYnkgdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyXG4vLyB2ZXJzaW9uIDIuMSBvZiB0aGUgTGljZW5zZSwgb3IgKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbi8vIFxuLy8gVGhpcyBsaWJyYXJ5IGlzIGRpc3RyaWJ1dGVkIGluIHRoZSBob3BlIHRoYXQgaXQgd2lsbCBiZSB1c2VmdWwsXG4vLyBidXQgV0lUSE9VVCBBTlkgV0FSUkFOVFk7IHdpdGhvdXQgZXZlbiB0aGUgaW1wbGllZCB3YXJyYW50eSBvZlxuLy8gTUVSQ0hBTlRBQklMSVRZIG9yIEZJVE5FU1MgRk9SIEEgUEFSVElDVUxBUiBQVVJQT1NFLiAgU2VlIHRoZSBHTlVcbi8vIExlc3NlciBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGZvciBtb3JlIGRldGFpbHMuXG4vLyBcbi8vIFlvdSBzaG91bGQgaGF2ZSByZWNlaXZlZCBhIGNvcHkgb2YgdGhlIEdOVSBMZXNzZXIgR2VuZXJhbCBQdWJsaWNcbi8vIExpY2Vuc2UgYWxvbmcgd2l0aCB0aGlzIGxpYnJhcnk7IGlmIG5vdCwgd3JpdGUgdG8gdGhlIEZyZWUgU29mdHdhcmVcbi8vIEZvdW5kYXRpb24sIEluYy4sIDUxIEZyYW5rbGluIFN0cmVldCwgRmlmdGggRmxvb3IsIEJvc3RvbiwgTUEgIDAyMTEwLTEzMDEgIFVTQVxuXG52YXIgcHVibGljS2V5ID0gcmVxdWlyZSgnLi9wdWJsaWNfa2V5LmpzJyksXG5cdHV0aWwgPSByZXF1aXJlKCcuLi91dGlsJyksXG5cdGNyeXB0byA9IHJlcXVpcmUoJy4uL2NyeXB0bycpO1xuXG4vKipcbiAqIEBjbGFzc1xuICogQGNsYXNzZGVzYyBJbXBsZW1lbnRhdGlvbiBvZiB0aGUgS2V5IE1hdGVyaWFsIFBhY2tldCAoVGFnIDUsNiw3LDE0KVxuICogICBcbiAqIFJGQzQ0ODAgNS41OlxuICogQSBrZXkgbWF0ZXJpYWwgcGFja2V0IGNvbnRhaW5zIGFsbCB0aGUgaW5mb3JtYXRpb24gYWJvdXQgYSBwdWJsaWMgb3JcbiAqIHByaXZhdGUga2V5LiAgVGhlcmUgYXJlIGZvdXIgdmFyaWFudHMgb2YgdGhpcyBwYWNrZXQgdHlwZSwgYW5kIHR3b1xuICogbWFqb3IgdmVyc2lvbnMuICBDb25zZXF1ZW50bHksIHRoaXMgc2VjdGlvbiBpcyBjb21wbGV4LlxuICovXG5mdW5jdGlvbiBwYWNrZXRfc2VjcmV0X2tleSgpIHtcblx0cHVibGljS2V5LmNhbGwodGhpcyk7XG5cblx0dGhpcy5lbmNyeXB0ZWQgPSBudWxsO1xuXG5cblx0ZnVuY3Rpb24gZ2V0X2hhc2hfbGVuKGhhc2gpIHtcblx0XHRpZihoYXNoID09IG9wZW5wZ3AuaGFzaC5zaGExKVxuXHRcdFx0cmV0dXJuIDIwO1xuXHRcdGVsc2Vcblx0XHRcdHJldHVybiAyO1xuXHR9XG5cblx0ZnVuY3Rpb24gZ2V0X2hhc2hfZm4oaGFzaCkge1xuXHRcdGlmKGhhc2ggPT0gb3BlbnBncC5oYXNoLnNoYTEpXG5cdFx0XHRyZXR1cm4gc3RyX3NoYTE7XG5cdFx0ZWxzZVxuXHRcdFx0cmV0dXJuIGZ1bmN0aW9uKGMpIHtcblx0XHRcdFx0XHRyZXR1cm4gdXRpbC53cml0ZU51bWJlcih1dGlsLmNhbGNfY2hlY2tzdW0oYyksIDIpO1xuXHRcdFx0XHR9XG5cdH1cblxuXHQvLyBIZWxwZXIgZnVuY3Rpb25cblx0ZnVuY3Rpb24gcGFyc2VfY2xlYXJ0ZXh0X21waShoYXNoX2FsZ29yaXRobSwgY2xlYXJ0ZXh0LCBhbGdvcml0aG0pIHtcblx0XHR2YXIgaGFzaGxlbiA9IGdldF9oYXNoX2xlbihoYXNoX2FsZ29yaXRobSksXG5cdFx0XHRoYXNoZm4gPSBnZXRfaGFzaF9mbihoYXNoX2FsZ29yaXRobSk7XG5cblx0XHR2YXIgaGFzaHRleHQgPSBjbGVhcnRleHQuc3Vic3RyKGNsZWFydGV4dC5sZW5ndGggLSBoYXNobGVuKTtcblx0XHRjbGVhcnRleHQgPSBjbGVhcnRleHQuc3Vic3RyKDAsIGNsZWFydGV4dC5sZW5ndGggLSBoYXNobGVuKTtcblxuXHRcdHZhciBoYXNoID0gaGFzaGZuKGNsZWFydGV4dCk7XG5cblx0XHRpZihoYXNoICE9IGhhc2h0ZXh0KVxuXHRcdFx0dGhyb3cgbmV3IEVycm9yKFwiSGFzaCBtaXNtYXRjaC5cIik7XG5cblx0XHR2YXIgbXBpcyA9IGNyeXB0by5nZXRQcml2YXRlTXBpQ291bnQoYWxnb3JpdGhtKTtcblxuXHRcdHZhciBqID0gMDtcblx0XHR2YXIgbXBpID0gW107XG5cdFx0Zm9yKHZhciBpID0gMDsgaSA8IG1waXMgJiYgaiA8IGNsZWFydGV4dC5sZW5ndGg7IGkrKykge1xuXHRcdFx0bXBpW2ldID0gbmV3IG9wZW5wZ3BfdHlwZV9tcGkoKTtcblx0XHRcdGogKz0gbXBpW2ldLnJlYWQoY2xlYXJ0ZXh0LnN1YnN0cihqKSk7XG5cdFx0fVxuXG5cdFx0cmV0dXJuIG1waTtcblx0fVxuXG5cdGZ1bmN0aW9uIHdyaXRlX2NsZWFydGV4dF9tcGkoaGFzaF9hbGdvcml0aG0sIG1waSkge1xuXHRcdHZhciBieXRlcz0gJyc7XG5cdFx0dmFyIGRpc2NhcmQgPSBjcnlwdG8uZ2V0UHVibGljTXBpQ291bnQodGhpcy5hbGdvcml0aG0pO1xuXG5cdFx0Zm9yKHZhciBpID0gZGlzY2FyZDsgaSA8IG1waS5sZW5ndGg7IGkrKykge1xuXHRcdFx0Ynl0ZXMgKz0gbXBpW2ldLndyaXRlKCk7XG5cdFx0fVxuXG5cblx0XHRieXRlcyArPSBnZXRfaGFzaF9mbihoYXNoX2FsZ29yaXRobSkoYnl0ZXMpO1xuXHRcdFxuXHRcdHJldHVybiBieXRlcztcblx0fVxuXHRcdFxuXG5cdC8vIDUuNS4zLiAgU2VjcmV0LUtleSBQYWNrZXQgRm9ybWF0c1xuXHRcblx0LyoqXG5cdCAqIEludGVybmFsIHBhcnNlciBmb3IgcHJpdmF0ZSBrZXlzIGFzIHNwZWNpZmllZCBpbiBSRkMgNDg4MCBzZWN0aW9uIDUuNS4zXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBieXRlcyBJbnB1dCBzdHJpbmcgdG8gcmVhZCB0aGUgcGFja2V0IGZyb21cblx0ICogQHBhcmFtIHtJbnRlZ2VyfSBwb3NpdGlvbiBTdGFydCBwb3NpdGlvbiBmb3IgdGhlIHBhcnNlclxuXHQgKiBAcGFyYW0ge0ludGVnZXJ9IGxlbiBMZW5ndGggb2YgdGhlIHBhY2tldCBvciByZW1haW5pbmcgbGVuZ3RoIG9mIGJ5dGVzXG5cdCAqIEByZXR1cm4ge09iamVjdH0gVGhpcyBvYmplY3Qgd2l0aCBhdHRyaWJ1dGVzIHNldCBieSB0aGUgcGFyc2VyXG5cdCAqL1xuXHR0aGlzLnJlYWQgPSBmdW5jdGlvbihieXRlcykge1xuXHQgICAgLy8gLSBBIFB1YmxpYy1LZXkgb3IgUHVibGljLVN1YmtleSBwYWNrZXQsIGFzIGRlc2NyaWJlZCBhYm92ZS5cblx0XHR2YXIgbGVuID0gdGhpcy5yZWFkUHVibGljS2V5KGJ5dGVzKTtcblxuXHQgICAgYnl0ZXMgPSBieXRlcy5zdWJzdHIobGVuKTtcblxuXHRcdFxuXHQgICAgLy8gLSBPbmUgb2N0ZXQgaW5kaWNhdGluZyBzdHJpbmctdG8ta2V5IHVzYWdlIGNvbnZlbnRpb25zLiAgWmVyb1xuXHQgICAgLy8gICBpbmRpY2F0ZXMgdGhhdCB0aGUgc2VjcmV0LWtleSBkYXRhIGlzIG5vdCBlbmNyeXB0ZWQuICAyNTUgb3IgMjU0XG5cdCAgICAvLyAgIGluZGljYXRlcyB0aGF0IGEgc3RyaW5nLXRvLWtleSBzcGVjaWZpZXIgaXMgYmVpbmcgZ2l2ZW4uICBBbnlcblx0ICAgIC8vICAgb3RoZXIgdmFsdWUgaXMgYSBzeW1tZXRyaWMta2V5IGVuY3J5cHRpb24gYWxnb3JpdGhtIGlkZW50aWZpZXIuXG5cdCAgICB2YXIgaXNFbmNyeXB0ZWQgPSBieXRlc1swXS5jaGFyQ29kZUF0KCk7XG5cblx0XHRpZihpc0VuY3J5cHRlZCkge1xuXHRcdFx0dGhpcy5lbmNyeXB0ZWQgPSBieXRlcztcblx0XHR9IGVsc2Uge1xuXHRcblx0XHRcdC8vIC0gUGxhaW4gb3IgZW5jcnlwdGVkIG11bHRpcHJlY2lzaW9uIGludGVnZXJzIGNvbXByaXNpbmcgdGhlIHNlY3JldFxuXHRcdFx0Ly8gICBrZXkgZGF0YS4gIFRoZXNlIGFsZ29yaXRobS1zcGVjaWZpYyBmaWVsZHMgYXJlIGFzIGRlc2NyaWJlZFxuXHRcdFx0Ly8gICBiZWxvdy5cblxuXHRcdFx0dGhpcy5tcGkgPSB0aGlzLm1waS5jb25jYXQocGFyc2VfY2xlYXJ0ZXh0X21waSgnbW9kJywgYnl0ZXMuc3Vic3RyKDEpLFxuXHRcdFx0XHR0aGlzLmFsZ29yaXRobSkpO1xuXHRcdH0gICAgXG5cblx0fVxuXHRcblx0LypcbiAgICAgKiBDcmVhdGVzIGFuIE9wZW5QR1Aga2V5IHBhY2tldCBmb3IgdGhlIGdpdmVuIGtleS4gbXVjaCBcblx0ICogVE9ETyBpbiByZWdhcmRzIHRvIHMyaywgc3Via2V5cy5cbiAgICAgKiBAcGFyYW0ge0ludGVnZXJ9IGtleVR5cGUgRm9sbG93cyB0aGUgT3BlblBHUCBhbGdvcml0aG0gc3RhbmRhcmQsIFxuXHQgKiBJRSAxIGNvcnJlc3BvbmRzIHRvIFJTQS5cbiAgICAgKiBAcGFyYW0ge1JTQS5rZXlPYmplY3R9IGtleVxuICAgICAqIEBwYXJhbSBwYXNzcGhyYXNlXG4gICAgICogQHBhcmFtIHMya0hhc2hcbiAgICAgKiBAcGFyYW0gc3ltbWV0cmljRW5jcnlwdGlvbkFsZ29yaXRobVxuICAgICAqIEBwYXJhbSB0aW1lUGFja2V0XG4gICAgICogQHJldHVybiB7T2JqZWN0fSB7Ym9keTogW3N0cmluZ11PcGVuUEdQIHBhY2tldCBib2R5IGNvbnRlbnRzLCBcblx0XHRoZWFkZXI6IFtzdHJpbmddIE9wZW5QR1AgcGFja2V0IGhlYWRlciwgc3RyaW5nOiBbc3RyaW5nXSBoZWFkZXIrYm9keX1cbiAgICAgKi9cbiAgICB0aGlzLndyaXRlID0gZnVuY3Rpb24oKSB7XG5cdFx0dmFyIGJ5dGVzID0gdGhpcy53cml0ZVB1YmxpY0tleSgpO1xuXG5cdFx0aWYoIXRoaXMuZW5jcnlwdGVkKSB7XG5cdFx0XHRieXRlcyArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKDApO1xuXHRcdFx0XG5cdFx0XHRieXRlcyArPSB3cml0ZV9jbGVhcnRleHRfbXBpKCdtb2QnLCB0aGlzLm1waSk7XG5cdFx0fSBlbHNlIHtcblx0XHRcdGJ5dGVzICs9IHRoaXMuZW5jcnlwdGVkO1xuXHRcdH1cblxuXHRcdHJldHVybiBieXRlcztcblx0fVxuXHRcdFx0XG5cblxuXG5cdC8qKiBFbmNyeXB0IHRoZSBwYXlsb2FkLiBCeSBkZWZhdWx0LCB3ZSB1c2UgYWVzMjU2IGFuZCBpdGVyYXRlZCwgc2FsdGVkIHN0cmluZ1xuXHQgKiB0byBrZXkgc3BlY2lmaWVyXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBwYXNzcGhyYXNlXG5cdCAqL1xuICAgIHRoaXMuZW5jcnlwdCA9IGZ1bmN0aW9uKHBhc3NwaHJhc2UpIHtcblxuXHRcdHZhciBzMmsgPSBuZXcgb3BlbnBncF90eXBlX3MyaygpLFxuXHRcdFx0c3ltbWV0cmljID0gb3BlbnBncC5zeW1tZXRyaWMuYWVzMjU2LFxuXHRcdFx0Y2xlYXJ0ZXh0ID0gd3JpdGVfY2xlYXJ0ZXh0X21waShvcGVucGdwLmhhc2guc2hhMSwgdGhpcy5tcGkpLFxuXHRcdFx0a2V5ID0gcHJvZHVjZUVuY3J5cHRpb25LZXkoczJrLCBwYXNzcGhyYXNlLCBzeW1tZXRyaWMpLFxuXHRcdFx0YmxvY2tMZW4gPSBvcGVucGdwX2NyeXB0b19nZXRCbG9ja0xlbmd0aChzeW1tZXRyaWMpLFxuXHRcdFx0aXYgPSBvcGVucGdwX2NyeXB0b19nZXRSYW5kb21CeXRlcyhibG9ja0xlbik7XG5cblxuXHRcdHRoaXMuZW5jcnlwdGVkID0gJyc7XG5cdFx0dGhpcy5lbmNyeXB0ZWQgKz0gU3RyaW5nLmZyb21DaGFyQ29kZSgyNTQpO1xuXHRcdHRoaXMuZW5jcnlwdGVkICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoc3ltbWV0cmljKTtcblx0XHR0aGlzLmVuY3J5cHRlZCArPSBzMmsud3JpdGUoKTtcblx0XHR0aGlzLmVuY3J5cHRlZCArPSBpdjtcblxuXHRcdGNvbnNvbGUubG9nKGNsZWFydGV4dCk7XG5cblx0XHRzd2l0Y2goc3ltbWV0cmljKSB7XG5cdFx0Y2FzZSAzOlxuXHRcdFx0dGhpcy5lbmNyeXB0ZWQgKz0gbm9ybWFsX2NmYl9lbmNyeXB0KGZ1bmN0aW9uKGJsb2NrLCBrZXkpIHtcblx0XHRcdFx0dmFyIGNhc3Q1ID0gbmV3IG9wZW5wZ3Bfc3ltZW5jX2Nhc3Q1KCk7XG5cdFx0XHRcdGNhc3Q1LnNldEtleShrZXkpO1xuXHRcdFx0XHRyZXR1cm4gY2FzdDUuZW5jcnlwdCh1dGlsLnN0cjJiaW4oYmxvY2spKTsgXG5cdFx0XHR9LCBpdi5sZW5ndGgsIGtleSwgY2xlYXJ0ZXh0LCBpdik7XG5cdFx0XHRicmVhaztcblx0XHRjYXNlIDc6XG5cdFx0Y2FzZSA4OlxuXHRcdGNhc2UgOTpcbiAgICBcdFx0dmFyIGZuID0gZnVuY3Rpb24oYmxvY2ssa2V5KSB7XG4gICAgXHRcdCAgICBcdHJldHVybiBBRVNlbmNyeXB0KHV0aWwuc3RyMmJpbihibG9jayksa2V5KTtcbiAgICBcdFx0XHR9XG5cdFx0XHR0aGlzLmVuY3J5cHRlZCArPSBub3JtYWxfY2ZiX2VuY3J5cHQoZm4sXG5cdFx0XHRcdFx0aXYubGVuZ3RoLCBuZXcga2V5RXhwYW5zaW9uKGtleSksIGNsZWFydGV4dCwgaXYpO1xuXHRcdFx0YnJlYWs7XG5cdFx0ZGVmYXVsdDpcblx0XHRcdHRocm93IG5ldyBFcnJvcihcIlVuc3VwcG9ydGVkIHN5bW1ldHJpYyBlbmNyeXB0aW9uIGFsZ29yaXRobS5cIik7XG5cdFx0fVxuICAgIH1cblxuXHRmdW5jdGlvbiBwcm9kdWNlRW5jcnlwdGlvbktleShzMmssIHBhc3NwaHJhc2UsIGFsZ29yaXRobSkge1xuXHRcdHJldHVybiBzMmsucHJvZHVjZV9rZXkocGFzc3BocmFzZSxcblx0XHRcdG9wZW5wZ3BfY3J5cHRvX2dldEtleUxlbmd0aChhbGdvcml0aG0pKTtcblx0fVxuXG5cdC8qKlxuXHQgKiBEZWNyeXB0cyB0aGUgcHJpdmF0ZSBrZXkgTVBJcyB3aGljaCBhcmUgbmVlZGVkIHRvIHVzZSB0aGUga2V5LlxuXHQgKiBvcGVucGdwX3BhY2tldF9rZXltYXRlcmlhbC5oYXNVbmVuY3J5cHRlZFNlY3JldEtleURhdGEgc2hvdWxkIGJlIFxuXHQgKiBmYWxzZSBvdGhlcndpc2Vcblx0ICogYSBjYWxsIHRvIHRoaXMgZnVuY3Rpb24gaXMgbm90IG5lZWRlZFxuXHQgKiBcblx0ICogQHBhcmFtIHtTdHJpbmd9IHN0cl9wYXNzcGhyYXNlIFRoZSBwYXNzcGhyYXNlIGZvciB0aGlzIHByaXZhdGUga2V5IFxuXHQgKiBhcyBzdHJpbmdcblx0ICogQHJldHVybiB7Qm9vbGVhbn0gVHJ1ZSBpZiB0aGUgcGFzc3BocmFzZSB3YXMgY29ycmVjdDsgZmFsc2UgaWYgbm90XG5cdCAqL1xuXHR0aGlzLmRlY3J5cHQgPSBmdW5jdGlvbihwYXNzcGhyYXNlKSB7XG5cdFx0aWYgKCF0aGlzLmVuY3J5cHRlZClcblx0XHRcdHJldHVybjtcblxuXHRcdHZhciBpID0gMCxcblx0XHRcdHN5bW1ldHJpYyxcblx0XHRcdGtleTtcblxuXHRcdHZhciBzMmtfdXNhZ2UgPSB0aGlzLmVuY3J5cHRlZFtpKytdLmNoYXJDb2RlQXQoKTtcblxuXHQgICAgLy8gLSBbT3B0aW9uYWxdIElmIHN0cmluZy10by1rZXkgdXNhZ2Ugb2N0ZXQgd2FzIDI1NSBvciAyNTQsIGEgb25lLVxuXHQgICAgLy8gICBvY3RldCBzeW1tZXRyaWMgZW5jcnlwdGlvbiBhbGdvcml0aG0uXG5cdCAgICBpZiAoczJrX3VzYWdlID09IDI1NSB8fCBzMmtfdXNhZ2UgPT0gMjU0KSB7XG5cdCAgICBcdHN5bW1ldHJpYyA9IHRoaXMuZW5jcnlwdGVkW2krK10uY2hhckNvZGVBdCgpO1xuXHQgICAgIFxuXHRcdFx0Ly8gLSBbT3B0aW9uYWxdIElmIHN0cmluZy10by1rZXkgdXNhZ2Ugb2N0ZXQgd2FzIDI1NSBvciAyNTQsIGFcblx0XHRcdC8vICAgc3RyaW5nLXRvLWtleSBzcGVjaWZpZXIuICBUaGUgbGVuZ3RoIG9mIHRoZSBzdHJpbmctdG8ta2V5XG5cdFx0XHQvLyAgIHNwZWNpZmllciBpcyBpbXBsaWVkIGJ5IGl0cyB0eXBlLCBhcyBkZXNjcmliZWQgYWJvdmUuXG5cdCAgICBcdHZhciBzMmsgPSBuZXcgb3BlbnBncF90eXBlX3MyaygpO1xuXHQgICAgXHRpICs9IHMyay5yZWFkKHRoaXMuZW5jcnlwdGVkLnN1YnN0cihpKSk7XG5cblx0XHRcdGtleSA9IHByb2R1Y2VFbmNyeXB0aW9uS2V5KHMyaywgcGFzc3BocmFzZSwgc3ltbWV0cmljKTtcblx0ICAgIH0gZWxzZSB7XG5cdFx0XHRzeW1tZXRyaWMgPSBzMmtfdXNhZ2U7XG5cdFx0XHRrZXkgPSBNRDUocGFzc3BocmFzZSk7XG5cdFx0fVxuXHQgICAgXG5cdCAgICAvLyAtIFtPcHRpb25hbF0gSWYgc2VjcmV0IGRhdGEgaXMgZW5jcnlwdGVkIChzdHJpbmctdG8ta2V5IHVzYWdlIG9jdGV0XG5cdCAgICAvLyAgIG5vdCB6ZXJvKSwgYW4gSW5pdGlhbCBWZWN0b3IgKElWKSBvZiB0aGUgc2FtZSBsZW5ndGggYXMgdGhlXG5cdCAgICAvLyAgIGNpcGhlcidzIGJsb2NrIHNpemUuXG5cdFx0dmFyIGl2ID0gdGhpcy5lbmNyeXB0ZWQuc3Vic3RyKGksIFxuXHRcdFx0b3BlbnBncF9jcnlwdG9fZ2V0QmxvY2tMZW5ndGgoc3ltbWV0cmljKSk7XG5cblx0XHRpICs9IGl2Lmxlbmd0aDtcblxuXHRcdHZhciBjbGVhcnRleHQsXG5cdFx0XHRjaXBoZXJ0ZXh0ID0gdGhpcy5lbmNyeXB0ZWQuc3Vic3RyKGkpO1xuXG5cbiAgICBcdHN3aXRjaCAoc3ltbWV0cmljKSB7XG5cdCAgICBjYXNlICAxOiAvLyAtIElERUEgW0lERUFdXG5cdFx0XHR0aHJvdyBuZXcgRXJyb3IoXCJJREVBIGlzIG5vdCBpbXBsZW1lbnRlZC5cIik7XG5cdCAgICBcdHJldHVybiBmYWxzZTtcbiAgICBcdGNhc2UgIDI6IC8vIC0gVHJpcGxlREVTIChERVMtRURFLCBbU0NITkVJRVJdIFtIQUNdIC0gMTY4IGJpdCBrZXkgZGVyaXZlZCBmcm9tIDE5MilcbiAgICBcdFx0Y2xlYXJ0ZXh0ID0gbm9ybWFsX2NmYl9kZWNyeXB0KGZ1bmN0aW9uKGJsb2NrLCBrZXkpIHtcbiAgICBcdFx0XHRyZXR1cm4gZGVzKGtleSwgYmxvY2ssMSxudWxsLDApO1xuICAgIFx0XHR9LCBpdi5sZW5ndGgsIGtleSwgY2lwaGVydGV4dCwgaXYpO1xuICAgIFx0XHRicmVhaztcbiAgICBcdGNhc2UgIDM6IC8vIC0gQ0FTVDUgKDEyOCBiaXQga2V5LCBhcyBwZXIgW1JGQzIxNDRdKVxuICAgIFx0XHRjbGVhcnRleHQgPSBub3JtYWxfY2ZiX2RlY3J5cHQoZnVuY3Rpb24oYmxvY2ssIGtleSkge1xuICAgICAgICBcdFx0dmFyIGNhc3Q1ID0gbmV3IG9wZW5wZ3Bfc3ltZW5jX2Nhc3Q1KCk7XG4gICAgICAgIFx0XHRjYXN0NS5zZXRLZXkoa2V5KTtcbiAgICAgICAgXHRcdHJldHVybiBjYXN0NS5lbmNyeXB0KHV0aWwuc3RyMmJpbihibG9jaykpOyBcbiAgICBcdFx0fSwgaXYubGVuZ3RoLCB1dGlsLnN0cjJiaW4oa2V5LnN1YnN0cmluZygwLDE2KSksIGNpcGhlcnRleHQsIGl2KTtcbiAgICBcdFx0YnJlYWs7XG5cdCAgICBjYXNlICA0OiAvLyAtIEJsb3dmaXNoICgxMjggYml0IGtleSwgMTYgcm91bmRzKSBbQkxPV0ZJU0hdXG5cdCAgICBcdGNsZWFydGV4dCA9IG5vcm1hbF9jZmJfZGVjcnlwdChmdW5jdGlvbihibG9jaywga2V5KSB7XG4gICAgXHRcdFx0dmFyIGJsb3dmaXNoID0gbmV3IEJsb3dmaXNoKGtleSk7XG4gICAgICAgIFx0XHRyZXR1cm4gYmxvd2Zpc2guZW5jcnlwdChibG9jayk7IFxuICAgIFx0XHR9LCBpdi5sZW5ndGgsIGtleSwgY2lwaGVydGV4dCwgaXYpO1xuICAgIFx0XHRicmVhaztcblx0ICAgIGNhc2UgIDc6IC8vIC0gQUVTIHdpdGggMTI4LWJpdCBrZXkgW0FFU11cbiAgICBcdGNhc2UgIDg6IC8vIC0gQUVTIHdpdGggMTkyLWJpdCBrZXlcbiAgICBcdGNhc2UgIDk6IC8vIC0gQUVTIHdpdGggMjU2LWJpdCBrZXlcbiAgICBcdFx0Y2xlYXJ0ZXh0ID0gbm9ybWFsX2NmYl9kZWNyeXB0KGZ1bmN0aW9uKGJsb2NrLGtleSl7XG4gICAgXHRcdCAgICBcdHJldHVybiBBRVNlbmNyeXB0KHV0aWwuc3RyMmJpbihibG9jayksa2V5KTtcbiAgICBcdFx0XHR9LFxuICAgIFx0XHRcdGl2Lmxlbmd0aCwgbmV3IGtleUV4cGFuc2lvbihrZXkpLCBcblx0XHRcdFx0XHRjaXBoZXJ0ZXh0LCBpdik7XG5cdCAgICBcdGJyZWFrO1xuICAgIFx0Y2FzZSAxMDogLy8gLSBUd29maXNoIHdpdGggMjU2LWJpdCBrZXkgW1RXT0ZJU0hdXG5cdFx0XHR0aHJvdyBuZXcgRXJyb3IoXCJUd29maXNoIGlzIG5vdCBpbXBsZW1lbnRlZC5cIik7XG5cdCAgICBcdHJldHVybiBmYWxzZTtcbiAgICBcdGNhc2UgIDU6IC8vIC0gUmVzZXJ2ZWRcbiAgICBcdGNhc2UgIDY6IC8vIC0gUmVzZXJ2ZWRcbiAgICBcdGRlZmF1bHQ6XG5cdFx0XHR0aHJvdyBuZXcgRXJyb3IoXCJVbmtub3duIHN5bW1ldHJpYyBhbGdvcml0aG0uXCIpO1xuICAgIFx0XHRyZXR1cm4gZmFsc2U7XG4gICAgXHR9XG4gXG5cdFx0dmFyIGhhc2g7XG5cdFx0aWYoczJrX3VzYWdlID09IDI1NClcblx0XHRcdGhhc2ggPSBvcGVucGdwLmhhc2guc2hhMTtcblx0XHRlbHNlXG5cdFx0XHRoYXNoID0gJ21vZCc7XG5cbiAgIFx0XG5cdFx0dGhpcy5tcGkgPSB0aGlzLm1waS5jb25jYXQocGFyc2VfY2xlYXJ0ZXh0X21waShoYXNoLCBjbGVhcnRleHQsXG5cdFx0XHR0aGlzLmFsZ29yaXRobSkpO1xuXHR9XG5cdFxufVxuXG5wYWNrZXRfc2VjcmV0X2tleS5wcm90b3R5cGUgPSBuZXcgcHVibGljS2V5O1xuXG5tb2R1bGUuZXhwb3J0cyA9IHBhY2tldF9zZWNyZXRfa2V5O1xuIiwiLy8gR1BHNEJyb3dzZXJzIC0gQW4gT3BlblBHUCBpbXBsZW1lbnRhdGlvbiBpbiBqYXZhc2NyaXB0XG4vLyBDb3B5cmlnaHQgKEMpIDIwMTEgUmVjdXJpdHkgTGFicyBHbWJIXG4vLyBcbi8vIFRoaXMgbGlicmFyeSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3Jcbi8vIG1vZGlmeSBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBMZXNzZXIgR2VuZXJhbCBQdWJsaWNcbi8vIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5IHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlclxuLy8gdmVyc2lvbiAyLjEgb2YgdGhlIExpY2Vuc2UsIG9yIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4vLyBcbi8vIFRoaXMgbGlicmFyeSBpcyBkaXN0cmlidXRlZCBpbiB0aGUgaG9wZSB0aGF0IGl0IHdpbGwgYmUgdXNlZnVsLFxuLy8gYnV0IFdJVEhPVVQgQU5ZIFdBUlJBTlRZOyB3aXRob3V0IGV2ZW4gdGhlIGltcGxpZWQgd2FycmFudHkgb2Zcbi8vIE1FUkNIQU5UQUJJTElUWSBvciBGSVRORVNTIEZPUiBBIFBBUlRJQ1VMQVIgUFVSUE9TRS4gIFNlZSB0aGUgR05VXG4vLyBMZXNzZXIgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBmb3IgbW9yZSBkZXRhaWxzLlxuLy8gXG4vLyBZb3Ugc2hvdWxkIGhhdmUgcmVjZWl2ZWQgYSBjb3B5IG9mIHRoZSBHTlUgTGVzc2VyIEdlbmVyYWwgUHVibGljXG4vLyBMaWNlbnNlIGFsb25nIHdpdGggdGhpcyBsaWJyYXJ5OyBpZiBub3QsIHdyaXRlIHRvIHRoZSBGcmVlIFNvZnR3YXJlXG4vLyBGb3VuZGF0aW9uLCBJbmMuLCA1MSBGcmFua2xpbiBTdHJlZXQsIEZpZnRoIEZsb29yLCBCb3N0b24sIE1BICAwMjExMC0xMzAxICBVU0FcblxudmFyIHV0aWwgPSByZXF1aXJlKCcuLi91dGlsJyk7XG5cbi8qKlxuICogQGNsYXNzXG4gKiBAY2xhc3NkZXNjIEltcGxlbWVudGF0aW9uIG9mIHRoZSBVc2VyIElEIFBhY2tldCAoVGFnIDEzKVxuICogQSBVc2VyIElEIHBhY2tldCBjb25zaXN0cyBvZiBVVEYtOCB0ZXh0IHRoYXQgaXMgaW50ZW5kZWQgdG8gcmVwcmVzZW50XG4gKiB0aGUgbmFtZSBhbmQgZW1haWwgYWRkcmVzcyBvZiB0aGUga2V5IGhvbGRlci4gIEJ5IGNvbnZlbnRpb24sIGl0XG4gKiBpbmNsdWRlcyBhbiBSRkMgMjgyMiBbUkZDMjgyMl0gbWFpbCBuYW1lLWFkZHIsIGJ1dCB0aGVyZSBhcmUgbm9cbiAqIHJlc3RyaWN0aW9ucyBvbiBpdHMgY29udGVudC4gIFRoZSBwYWNrZXQgbGVuZ3RoIGluIHRoZSBoZWFkZXJcbiAqIHNwZWNpZmllcyB0aGUgbGVuZ3RoIG9mIHRoZSBVc2VyIElELiBcbiAqL1xubW9kdWxlLmV4cG9ydHMgPSBmdW5jdGlvbiBwYWNrZXRfdXNlcmlkKCkge1xuXHQvKiogQHR5cGUge1N0cmluZ30gQSBzdHJpbmcgY29udGFpbmluZyB0aGUgdXNlciBpZC4gVXN1YWxseSBpbiB0aGUgZm9ybVxuXHQgKiBKb2huIERvZSA8am9obkBleGFtcGxlLmNvbT4gXG5cdCAqL1xuXHR0aGlzLnVzZXJpZCA9ICcnO1xuXHRcblx0XG5cdC8qKlxuXHQgKiBQYXJzaW5nIGZ1bmN0aW9uIGZvciBhIHVzZXIgaWQgcGFja2V0ICh0YWcgMTMpLlxuXHQgKiBAcGFyYW0ge1N0cmluZ30gaW5wdXQgcGF5bG9hZCBvZiBhIHRhZyAxMyBwYWNrZXRcblx0ICogQHBhcmFtIHtJbnRlZ2VyfSBwb3NpdGlvbiBwb3NpdGlvbiB0byBzdGFydCByZWFkaW5nIGZyb20gdGhlIGlucHV0IHN0cmluZ1xuXHQgKiBAcGFyYW0ge0ludGVnZXJ9IGxlbiBsZW5ndGggb2YgdGhlIHBhY2tldCBvciB0aGUgcmVtYWluaW5nIGxlbmd0aCBvZiBpbnB1dCBcblx0ICogYXQgcG9zaXRpb25cblx0ICogQHJldHVybiB7b3BlbnBncF9wYWNrZXRfZW5jcnlwdGVkZGF0YX0gb2JqZWN0IHJlcHJlc2VudGF0aW9uXG5cdCAqL1xuXHR0aGlzLnJlYWQgPSBmdW5jdGlvbihieXRlcykge1xuXHRcdHRoaXMudXNlcmlkID0gdXRpbC5kZWNvZGVfdXRmOChieXRlcyk7XG5cdH1cblxuXHQvKipcblx0ICogQ3JlYXRlcyBhIHN0cmluZyByZXByZXNlbnRhdGlvbiBvZiB0aGUgdXNlciBpZCBwYWNrZXRcblx0ICogQHBhcmFtIHtTdHJpbmd9IHVzZXJfaWQgdGhlIHVzZXIgaWQgYXMgc3RyaW5nIChcIkpvaG4gRG9lIDxqb2huLmRvZUBtYWlsLnVzXCIpXG5cdCAqIEByZXR1cm4ge1N0cmluZ30gc3RyaW5nIHJlcHJlc2VudGF0aW9uXG5cdCAqL1xuXHR0aGlzLndyaXRlID0gZnVuY3Rpb24oKSB7XG5cdFx0cmV0dXJuIHV0aWwuZW5jb2RlX3V0ZjgodGhpcy51c2VyaWQpO1xuXHR9XG59XG4iLCIvLyBHUEc0QnJvd3NlcnMgLSBBbiBPcGVuUEdQIGltcGxlbWVudGF0aW9uIGluIGphdmFzY3JpcHRcbi8vIENvcHlyaWdodCAoQykgMjAxMSBSZWN1cml0eSBMYWJzIEdtYkhcbi8vIFxuLy8gVGhpcyBsaWJyYXJ5IGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vclxuLy8gbW9kaWZ5IGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIExlc3NlciBHZW5lcmFsIFB1YmxpY1xuLy8gTGljZW5zZSBhcyBwdWJsaXNoZWQgYnkgdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyXG4vLyB2ZXJzaW9uIDIuMSBvZiB0aGUgTGljZW5zZSwgb3IgKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbi8vIFxuLy8gVGhpcyBsaWJyYXJ5IGlzIGRpc3RyaWJ1dGVkIGluIHRoZSBob3BlIHRoYXQgaXQgd2lsbCBiZSB1c2VmdWwsXG4vLyBidXQgV0lUSE9VVCBBTlkgV0FSUkFOVFk7IHdpdGhvdXQgZXZlbiB0aGUgaW1wbGllZCB3YXJyYW50eSBvZlxuLy8gTUVSQ0hBTlRBQklMSVRZIG9yIEZJVE5FU1MgRk9SIEEgUEFSVElDVUxBUiBQVVJQT1NFLiAgU2VlIHRoZSBHTlVcbi8vIExlc3NlciBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGZvciBtb3JlIGRldGFpbHMuXG4vLyBcbi8vIFlvdSBzaG91bGQgaGF2ZSByZWNlaXZlZCBhIGNvcHkgb2YgdGhlIEdOVSBMZXNzZXIgR2VuZXJhbCBQdWJsaWNcbi8vIExpY2Vuc2UgYWxvbmcgd2l0aCB0aGlzIGxpYnJhcnk7IGlmIG5vdCwgd3JpdGUgdG8gdGhlIEZyZWUgU29mdHdhcmVcbi8vIEZvdW5kYXRpb24sIEluYy4sIDUxIEZyYW5rbGluIFN0cmVldCwgRmlmdGggRmxvb3IsIEJvc3RvbiwgTUEgIDAyMTEwLTEzMDEgIFVTQVxuXG52YXIgdXRpbCA9IHJlcXVpcmUoJy4uL3V0aWwnKSxcblx0cGFja2V0ID0gcmVxdWlyZSgnLi9wYWNrZXQuanMnKSxcblx0ZW51bXMgPSByZXF1aXJlKCcuLi9lbnVtcy5qcycpLFxuXHRjcnlwdG8gPSByZXF1aXJlKCcuLi9jcnlwdG8nKSxcblx0dHlwZV9tcGkgPSByZXF1aXJlKCcuLi90eXBlL21waS5qcycpO1xuXG4vKipcbiAqIEBjbGFzc1xuICogQGNsYXNzZGVzYyBJbXBsZW1lbnRhdGlvbiBvZiB0aGUgU2lnbmF0dXJlIFBhY2tldCAoVGFnIDIpXG4gKiBcbiAqIFJGQzQ0ODAgNS4yOlxuICogQSBTaWduYXR1cmUgcGFja2V0IGRlc2NyaWJlcyBhIGJpbmRpbmcgYmV0d2VlbiBzb21lIHB1YmxpYyBrZXkgYW5kXG4gKiBzb21lIGRhdGEuICBUaGUgbW9zdCBjb21tb24gc2lnbmF0dXJlcyBhcmUgYSBzaWduYXR1cmUgb2YgYSBmaWxlIG9yIGFcbiAqIGJsb2NrIG9mIHRleHQsIGFuZCBhIHNpZ25hdHVyZSB0aGF0IGlzIGEgY2VydGlmaWNhdGlvbiBvZiBhIFVzZXIgSUQuXG4gKi9cbm1vZHVsZS5leHBvcnRzID0gZnVuY3Rpb24gcGFja2V0X3NpZ25hdHVyZSgpIHtcblxuXHR0aGlzLnNpZ25hdHVyZVR5cGUgPSBudWxsO1xuXHR0aGlzLmhhc2hBbGdvcml0aG0gPSBudWxsO1xuXHR0aGlzLnB1YmxpY0tleUFsZ29yaXRobSA9IG51bGw7IFxuXG5cdHRoaXMuc2lnbmF0dXJlRGF0YSA9IG51bGw7XG5cdHRoaXMuc2lnbmVkSGFzaFZhbHVlID0gbnVsbDtcblx0dGhpcy5tcGkgPSBudWxsO1xuXG5cdHRoaXMuY3JlYXRlZCA9IG51bGw7XG5cdHRoaXMuc2lnbmF0dXJlRXhwaXJhdGlvblRpbWUgPSBudWxsO1xuXHR0aGlzLnNpZ25hdHVyZU5ldmVyRXhwaXJlcyA9IG51bGw7XG5cdHRoaXMuZXhwb3J0YWJsZSA9IG51bGw7XG5cdHRoaXMudHJ1c3RMZXZlbCA9IG51bGw7XG5cdHRoaXMudHJ1c3RBbW91bnQgPSBudWxsO1xuXHR0aGlzLnJlZ3VsYXJFeHByZXNzaW9uID0gbnVsbDtcblx0dGhpcy5yZXZvY2FibGUgPSBudWxsO1xuXHR0aGlzLmtleUV4cGlyYXRpb25UaW1lID0gbnVsbDtcblx0dGhpcy5rZXlOZXZlckV4cGlyZXMgPSBudWxsO1xuXHR0aGlzLnByZWZlcnJlZFN5bW1ldHJpY0FsZ29yaXRobXMgPSBudWxsO1xuXHR0aGlzLnJldm9jYXRpb25LZXlDbGFzcyA9IG51bGw7XG5cdHRoaXMucmV2b2NhdGlvbktleUFsZ29yaXRobSA9IG51bGw7XG5cdHRoaXMucmV2b2NhdGlvbktleUZpbmdlcnByaW50ID0gbnVsbDtcblx0dGhpcy5pc3N1ZXJLZXlJZCA9IG51bGw7XG5cdHRoaXMubm90YXRpb24gPSB7fTtcblx0dGhpcy5wcmVmZXJyZWRIYXNoQWxnb3JpdGhtcyA9IG51bGw7XG5cdHRoaXMucHJlZmVycmVkQ29tcHJlc3Npb25BbGdvcml0aG1zID0gbnVsbDtcblx0dGhpcy5rZXlTZXJ2ZXJQcmVmZXJlbmNlcyA9IG51bGw7XG5cdHRoaXMucHJlZmVycmVkS2V5U2VydmVyID0gbnVsbDtcblx0dGhpcy5pc1ByaW1hcnlVc2VySUQgPSBudWxsO1xuXHR0aGlzLnBvbGljeVVSSSA9IG51bGw7XG5cdHRoaXMua2V5RmxhZ3MgPSBudWxsO1xuXHR0aGlzLnNpZ25lcnNVc2VySWQgPSBudWxsO1xuXHR0aGlzLnJlYXNvbkZvclJldm9jYXRpb25GbGFnID0gbnVsbDtcblx0dGhpcy5yZWFzb25Gb3JSZXZvY2F0aW9uU3RyaW5nID0gbnVsbDtcblx0dGhpcy5zaWduYXR1cmVUYXJnZXRQdWJsaWNLZXlBbGdvcml0aG0gPSBudWxsO1xuXHR0aGlzLnNpZ25hdHVyZVRhcmdldEhhc2hBbGdvcml0aG0gPSBudWxsO1xuXHR0aGlzLnNpZ25hdHVyZVRhcmdldEhhc2ggPSBudWxsO1xuXHR0aGlzLmVtYmVkZGVkU2lnbmF0dXJlID0gbnVsbDtcblxuXHR0aGlzLnZlcmlmaWVkID0gZmFsc2U7XG5cdFxuXG5cdC8qKlxuXHQgKiBwYXJzaW5nIGZ1bmN0aW9uIGZvciBhIHNpZ25hdHVyZSBwYWNrZXQgKHRhZyAyKS5cblx0ICogQHBhcmFtIHtTdHJpbmd9IGJ5dGVzIHBheWxvYWQgb2YgYSB0YWcgMiBwYWNrZXRcblx0ICogQHBhcmFtIHtJbnRlZ2VyfSBwb3NpdGlvbiBwb3NpdGlvbiB0byBzdGFydCByZWFkaW5nIGZyb20gdGhlIGJ5dGVzIHN0cmluZ1xuXHQgKiBAcGFyYW0ge0ludGVnZXJ9IGxlbiBsZW5ndGggb2YgdGhlIHBhY2tldCBvciB0aGUgcmVtYWluaW5nIGxlbmd0aCBvZiBieXRlcyBhdCBwb3NpdGlvblxuXHQgKiBAcmV0dXJuIHtvcGVucGdwX3BhY2tldF9lbmNyeXB0ZWRkYXRhfSBvYmplY3QgcmVwcmVzZW50YXRpb25cblx0ICovXG5cdHRoaXMucmVhZCA9IGZ1bmN0aW9uKGJ5dGVzKSB7XG5cdFx0dmFyIGkgPSAwO1xuXG5cdFx0dmFyIHZlcnNpb24gPSBieXRlc1tpKytdLmNoYXJDb2RlQXQoKTtcblx0XHQvLyBzd2l0Y2ggb24gdmVyc2lvbiAoMyBhbmQgNClcblx0XHRzd2l0Y2ggKHZlcnNpb24pIHtcblx0XHRjYXNlIDM6XG5cdFx0XHQvLyBPbmUtb2N0ZXQgbGVuZ3RoIG9mIGZvbGxvd2luZyBoYXNoZWQgbWF0ZXJpYWwuIE1VU1QgYmUgNS5cblx0XHRcdGlmIChieXRlc1tpKytdLmNoYXJDb2RlQXQoKSAhPSA1KVxuXHRcdFx0XHR1dGlsLnByaW50X2RlYnVnKFwib3BlbnBncC5wYWNrZXQuc2lnbmF0dXJlLmpzXFxuXCIrXG5cdFx0XHRcdFx0J2ludmFsaWQgT25lLW9jdGV0IGxlbmd0aCBvZiBmb2xsb3dpbmcgaGFzaGVkIG1hdGVyaWFsLicgK1xuXHRcdFx0XHRcdCdNVVNUIGJlIDUuIEA6JysoaS0xKSk7XG5cblx0XHRcdHZhciBzaWdwb3MgPSBpO1xuXHRcdFx0Ly8gT25lLW9jdGV0IHNpZ25hdHVyZSB0eXBlLlxuXHRcdFx0dGhpcy5zaWduYXR1cmVUeXBlID0gYnl0ZXNbaSsrXS5jaGFyQ29kZUF0KCk7XG5cblx0XHRcdC8vIEZvdXItb2N0ZXQgY3JlYXRpb24gdGltZS5cblx0XHRcdHRoaXMuY3JlYXRlZCA9IHV0aWwucmVhZERhdGUoYnl0ZXMuc3Vic3RyKGksIDQpKTtcblx0XHRcdGkgKz0gNDtcblx0XHRcdFxuXHRcdFx0Ly8gc3RvcmluZyBkYXRhIGFwcGVuZGVkIHRvIGRhdGEgd2hpY2ggZ2V0cyB2ZXJpZmllZFxuXHRcdFx0dGhpcy5zaWduYXR1cmVEYXRhID0gYnl0ZXMuc3Vic3RyaW5nKHBvc2l0aW9uLCBpKTtcblx0XHRcdFxuXHRcdFx0Ly8gRWlnaHQtb2N0ZXQgS2V5IElEIG9mIHNpZ25lci5cblx0XHRcdHRoaXMuaXNzdWVyS2V5SWQgPSBieXRlcy5zdWJzdHJpbmcoaSwgaSArOCk7XG5cdFx0XHRpICs9IDg7XG5cblx0XHRcdC8vIE9uZS1vY3RldCBwdWJsaWMta2V5IGFsZ29yaXRobS5cblx0XHRcdHRoaXMucHVibGljS2V5QWxnb3JpdGhtID0gYnl0ZXNbaSsrXS5jaGFyQ29kZUF0KCk7XG5cblx0XHRcdC8vIE9uZS1vY3RldCBoYXNoIGFsZ29yaXRobS5cblx0XHRcdHRoaXMuaGFzaEFsZ29yaXRobSA9IGJ5dGVzW2krK10uY2hhckNvZGVBdCgpO1xuXHRcdGJyZWFrO1xuXHRcdGNhc2UgNDpcblx0XHRcdHRoaXMuc2lnbmF0dXJlVHlwZSA9IGJ5dGVzW2krK10uY2hhckNvZGVBdCgpO1xuXHRcdFx0dGhpcy5wdWJsaWNLZXlBbGdvcml0aG0gPSBieXRlc1tpKytdLmNoYXJDb2RlQXQoKTtcblx0XHRcdHRoaXMuaGFzaEFsZ29yaXRobSA9IGJ5dGVzW2krK10uY2hhckNvZGVBdCgpO1xuXG5cblx0XHRcdGZ1bmN0aW9uIHN1YnBhY2tldHMoYnl0ZXMsIHNpZ25lZCkge1xuXHRcdFx0XHQvLyBUd28tb2N0ZXQgc2NhbGFyIG9jdGV0IGNvdW50IGZvciBmb2xsb3dpbmcgaGFzaGVkIHN1YnBhY2tldFxuXHRcdFx0XHQvLyBkYXRhLlxuXHRcdFx0XHR2YXIgc3VicGFja2V0X2xlbmd0aCA9IHV0aWwucmVhZE51bWJlcihcblx0XHRcdFx0XHRieXRlcy5zdWJzdHIoMCwgMikpO1xuXG5cdFx0XHRcdHZhciBpID0gMjtcblxuXHRcdFx0XHQvLyBIYXNoZWQgc3VicGFja2V0IGRhdGEgc2V0ICh6ZXJvIG9yIG1vcmUgc3VicGFja2V0cylcblx0XHRcdFx0dmFyIHN1YnBhY2tlZF9yZWFkID0gMDtcblx0XHRcdFx0d2hpbGUgKGkgPCAyICsgc3VicGFja2V0X2xlbmd0aCkge1xuXG5cdFx0XHRcdFx0dmFyIGxlbiA9IHBhY2tldC5yZWFkU2ltcGxlTGVuZ3RoKGJ5dGVzLnN1YnN0cihpKSk7XG5cdFx0XHRcdFx0aSArPSBsZW4ub2Zmc2V0O1xuXG5cdFx0XHRcdFx0Ly8gU2luY2UgaXQgaXMgdHJpdmlhbCB0byBhZGQgZGF0YSB0byB0aGUgdW5oYXNoZWQgcG9ydGlvbiBvZiBcblx0XHRcdFx0XHQvLyB0aGUgcGFja2V0IHdlIHNpbXBseSBpZ25vcmUgYWxsIHVuYXV0aGVudGljYXRlZCBkYXRhLlxuXHRcdFx0XHRcdGlmKHNpZ25lZClcblx0XHRcdFx0XHRcdHRoaXMucmVhZF9zdWJfcGFja2V0KGJ5dGVzLnN1YnN0cihpLCBsZW4ubGVuKSk7XG5cblx0XHRcdFx0XHRpICs9IGxlbi5sZW47XG5cdFx0XHRcdH1cblx0XHRcdFx0XG5cdFx0XHRcdHJldHVybiBpO1xuXHRcdFx0fVxuXHRcdFx0XG5cdFx0XHRpICs9IHN1YnBhY2tldHMuY2FsbCh0aGlzLCBieXRlcy5zdWJzdHIoaSksIHRydWUpO1xuXG5cdFx0XHQvLyBBIFY0IHNpZ25hdHVyZSBoYXNoZXMgdGhlIHBhY2tldCBib2R5XG5cdFx0XHQvLyBzdGFydGluZyBmcm9tIGl0cyBmaXJzdCBmaWVsZCwgdGhlIHZlcnNpb24gbnVtYmVyLCB0aHJvdWdoIHRoZSBlbmRcblx0XHRcdC8vIG9mIHRoZSBoYXNoZWQgc3VicGFja2V0IGRhdGEuICBUaHVzLCB0aGUgZmllbGRzIGhhc2hlZCBhcmUgdGhlXG5cdFx0XHQvLyBzaWduYXR1cmUgdmVyc2lvbiwgdGhlIHNpZ25hdHVyZSB0eXBlLCB0aGUgcHVibGljLWtleSBhbGdvcml0aG0sIHRoZVxuXHRcdFx0Ly8gaGFzaCBhbGdvcml0aG0sIHRoZSBoYXNoZWQgc3VicGFja2V0IGxlbmd0aCwgYW5kIHRoZSBoYXNoZWRcblx0XHRcdC8vIHN1YnBhY2tldCBib2R5LlxuXHRcdFx0dGhpcy5zaWduYXR1cmVEYXRhID0gYnl0ZXMuc3Vic3RyKDAsIGkpO1xuXG5cdFx0XHRpICs9IHN1YnBhY2tldHMuY2FsbCh0aGlzLCBieXRlcy5zdWJzdHIoaSksIGZhbHNlKTtcblxuXHRcdFx0YnJlYWs7XG5cdFx0ZGVmYXVsdDpcblx0XHRcdHRocm93IG5ldyBFcnJvcignVmVyc2lvbiAnICsgdmVyc2lvbiArICcgb2YgdGhlIHNpZ25hdHVyZSBpcyB1bnN1cHBvcnRlZC4nKTtcblx0XHRcdGJyZWFrO1xuXHRcdH1cblxuXHRcdC8vIFR3by1vY3RldCBmaWVsZCBob2xkaW5nIGxlZnQgMTYgYml0cyBvZiBzaWduZWQgaGFzaCB2YWx1ZS5cblx0XHR0aGlzLnNpZ25lZEhhc2hWYWx1ZSA9IGJ5dGVzLnN1YnN0cihpLCAyKTtcblx0XHRpICs9IDI7XG5cblx0XHR0aGlzLnNpZ25hdHVyZSA9IGJ5dGVzLnN1YnN0cihpKTtcblx0fVxuXG5cdHRoaXMud3JpdGUgPSBmdW5jdGlvbigpIHtcblx0XHRyZXR1cm4gdGhpcy5zaWduYXR1cmVEYXRhICsgXG5cdFx0XHR1dGlsLndyaXRlTnVtYmVyKDAsIDIpICsgLy8gTnVtYmVyIG9mIHVuc2lnbmVkIHN1YnBhY2tldHMuXG5cdFx0XHR0aGlzLnNpZ25lZEhhc2hWYWx1ZSArXG5cdFx0XHR0aGlzLnNpZ25hdHVyZTtcblx0fVxuXG5cdC8qKlxuXHQgKiBTaWducyBwcm92aWRlZCBkYXRhLiBUaGlzIG5lZWRzIHRvIGJlIGRvbmUgcHJpb3IgdG8gc2VyaWFsaXphdGlvbi5cblx0ICogQHBhcmFtIHtPYmplY3R9IGRhdGEgQ29udGFpbnMgcGFja2V0cyB0byBiZSBzaWduZWQuXG5cdCAqIEBwYXJhbSB7b3BlbnBncF9tc2dfcHJpdmF0ZWtleX0gcHJpdmF0ZWtleSBwcml2YXRlIGtleSB1c2VkIHRvIHNpZ24gdGhlIG1lc3NhZ2UuIFxuXHQgKi9cblx0dGhpcy5zaWduID0gZnVuY3Rpb24oa2V5LCBkYXRhKSB7XG5cdFx0dmFyIHNpZ25hdHVyZVR5cGUgPSBlbnVtcy53cml0ZShlbnVtcy5zaWduYXR1cmUsIHRoaXMuc2lnbmF0dXJlVHlwZSksXG5cdFx0XHRwdWJsaWNLZXlBbGdvcml0aG0gPSBlbnVtcy53cml0ZShlbnVtcy5wdWJsaWNLZXksIHRoaXMucHVibGljS2V5QWxnb3JpdGhtKSxcblx0XHRcdGhhc2hBbGdvcml0aG0gPSBlbnVtcy53cml0ZShlbnVtcy5oYXNoLCB0aGlzLmhhc2hBbGdvcml0aG0pO1xuXG5cdFx0dmFyIHJlc3VsdCA9IFN0cmluZy5mcm9tQ2hhckNvZGUoNCk7IFxuXHRcdHJlc3VsdCArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKHNpZ25hdHVyZVR5cGUpO1xuXHRcdHJlc3VsdCArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKHB1YmxpY0tleUFsZ29yaXRobSk7XG5cdFx0cmVzdWx0ICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoaGFzaEFsZ29yaXRobSk7XG5cblxuXHRcdC8vIEFkZCBzdWJwYWNrZXRzIGhlcmVcblx0XHRyZXN1bHQgKz0gdXRpbC53cml0ZU51bWJlcigwLCAyKTtcblxuXG5cdFx0dGhpcy5zaWduYXR1cmVEYXRhID0gcmVzdWx0O1xuXG5cdFx0dmFyIHRyYWlsZXIgPSB0aGlzLmNhbGN1bGF0ZVRyYWlsZXIoKTtcblx0XHRcblx0XHR2YXIgdG9IYXNoID0gdGhpcy50b1NpZ24oc2lnbmF0dXJlVHlwZSwgZGF0YSkgKyBcblx0XHRcdHRoaXMuc2lnbmF0dXJlRGF0YSArIHRyYWlsZXI7XG5cblx0XHR2YXIgaGFzaCA9IGNyeXB0by5oYXNoLmRpZ2VzdChoYXNoQWxnb3JpdGhtLCB0b0hhc2gpO1xuXHRcdFxuXHRcdHRoaXMuc2lnbmVkSGFzaFZhbHVlID0gaGFzaC5zdWJzdHIoMCwgMik7XG5cblxuXHRcdHRoaXMuc2lnbmF0dXJlID0gY3J5cHRvLnNpZ25hdHVyZS5zaWduKGhhc2hBbGdvcml0aG0sIFxuXHRcdFx0cHVibGljS2V5QWxnb3JpdGhtLCBrZXkubXBpLCB0b0hhc2gpO1xuXHR9XG5cblx0LyoqXG5cdCAqIGNyZWF0ZXMgYSBzdHJpbmcgcmVwcmVzZW50YXRpb24gb2YgYSBzdWIgc2lnbmF0dXJlIHBhY2tldCAoU2VlIFJGQyA0ODgwIDUuMi4zLjEpXG5cdCAqIEBwYXJhbSB7SW50ZWdlcn0gdHlwZSBzdWJwYWNrZXQgc2lnbmF0dXJlIHR5cGUuIFNpZ25hdHVyZSB0eXBlcyBhcyBkZXNjcmliZWQgXG5cdCAqIGluIFJGQzQ4ODAgU2VjdGlvbiA1LjIuMy4yXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBkYXRhIGRhdGEgdG8gYmUgaW5jbHVkZWRcblx0ICogQHJldHVybiB7U3RyaW5nfSBhIHN0cmluZy1yZXByZXNlbnRhdGlvbiBvZiBhIHN1YiBzaWduYXR1cmUgcGFja2V0IChTZWUgUkZDIDQ4ODAgNS4yLjMuMSlcblx0ICovXG5cdGZ1bmN0aW9uIHdyaXRlX3N1Yl9wYWNrZXQodHlwZSwgZGF0YSkge1xuXHRcdHZhciByZXN1bHQgPSBcIlwiO1xuXHRcdHJlc3VsdCArPSBwYWNrZXQud3JpdGVTaW1wbGVMZW5ndGgoZGF0YS5sZW5ndGgrMSk7XG5cdFx0cmVzdWx0ICs9IFN0cmluZy5mcm9tQ2hhckNvZGUodHlwZSk7XG5cdFx0cmVzdWx0ICs9IGRhdGE7XG5cdFx0cmV0dXJuIHJlc3VsdDtcblx0fVxuXHRcblx0Ly8gVjQgc2lnbmF0dXJlIHN1YiBwYWNrZXRzXG5cdFxuXHR0aGlzLnJlYWRfc3ViX3BhY2tldCA9IGZ1bmN0aW9uKGJ5dGVzKSB7XG5cdFx0dmFyIG15cG9zID0gMDtcblxuXHRcdGZ1bmN0aW9uIHJlYWRfYXJyYXkocHJvcCwgYnl0ZXMpIHtcblx0XHRcdHRoaXNbcHJvcF0gPSBbXTtcblxuXHRcdFx0Zm9yICh2YXIgaSA9IDA7IGkgPCBieXRlcy5sZW5ndGg7IGkrKykge1xuXHRcdFx0XHR0aGlzW3Byb3BdLnB1c2goYnl0ZXNbaV0uY2hhckNvZGVBdCgpKTtcblx0XHRcdH1cblx0XHR9XG5cdFx0XG5cdFx0Ly8gVGhlIGxlZnR3b3N0IGJpdCBkZW5vdGVzIGEgXCJjcml0aWNhbFwiIHBhY2tldCwgYnV0IHdlIGlnbm9yZSBpdC5cblx0XHR2YXIgdHlwZSA9IGJ5dGVzW215cG9zKytdLmNoYXJDb2RlQXQoKSAmIDB4N0Y7XG5cblx0XHQvLyBzdWJwYWNrZXQgdHlwZVxuXHRcdHN3aXRjaCAodHlwZSkge1xuXHRcdGNhc2UgMjogLy8gU2lnbmF0dXJlIENyZWF0aW9uIFRpbWVcblx0XHRcdHRoaXMuY3JlYXRlZCA9IHV0aWwucmVhZERhdGUoYnl0ZXMuc3Vic3RyKG15cG9zKSk7XG5cdFx0XHRicmVhaztcblx0XHRjYXNlIDM6IC8vIFNpZ25hdHVyZSBFeHBpcmF0aW9uIFRpbWVcblx0XHRcdHZhciB0aW1lID0gdXRpbC5yZWFkRGF0ZShieXRlcy5zdWJzdHIobXlwb3MpKTtcblxuXHRcdFx0dGhpcy5zaWduYXR1cmVOZXZlckV4cGlyZXMgPSB0aW1lLmdldFRpbWUoKSA9PSAwO1xuXHRcdFx0dGhpcy5zaWduYXR1cmVFeHBpcmF0aW9uVGltZSA9IHRpbWU7XG5cdFx0XHRcblx0XHRcdGJyZWFrO1xuXHRcdGNhc2UgNDogLy8gRXhwb3J0YWJsZSBDZXJ0aWZpY2F0aW9uXG5cdFx0XHR0aGlzLmV4cG9ydGFibGUgPSBieXRlc1tteXBvcysrXS5jaGFyQ29kZUF0KCkgPT0gMTtcblx0XHRcdGJyZWFrO1xuXHRcdGNhc2UgNTogLy8gVHJ1c3QgU2lnbmF0dXJlXG5cdFx0XHR0aGlzLnRydXN0TGV2ZWwgPSBieXRlc1tteXBvcysrXS5jaGFyQ29kZUF0KCk7XG5cdFx0XHR0aGlzLnRydXN0QW1vdW50ID0gYnl0ZXNbbXlwb3MrK10uY2hhckNvZGVBdCgpO1xuXHRcdFx0YnJlYWs7XG5cdFx0Y2FzZSA2OiAvLyBSZWd1bGFyIEV4cHJlc3Npb25cblx0XHRcdHRoaXMucmVndWxhckV4cHJlc3Npb24gPSBieXRlcy5zdWJzdHIobXlwb3MpO1xuXHRcdFx0YnJlYWs7XG5cdFx0Y2FzZSA3OiAvLyBSZXZvY2FibGVcblx0XHRcdHRoaXMucmV2b2NhYmxlID0gYnl0ZXNbbXlwb3MrK10uY2hhckNvZGVBdCgpID09IDE7XG5cdFx0XHRicmVhaztcblx0XHRjYXNlIDk6IC8vIEtleSBFeHBpcmF0aW9uIFRpbWVcblx0XHRcdHZhciB0aW1lID0gdXRpbC5yZWFkRGF0ZShieXRlcy5zdWJzdHIobXlwb3MpKTtcblxuXHRcdFx0dGhpcy5rZXlFeHBpcmF0aW9uVGltZSA9IHRpbWU7XG5cdFx0XHR0aGlzLmtleU5ldmVyRXhwaXJlcyA9IHRpbWUuZ2V0VGltZSgpID09IDA7XG5cblx0XHRcdGJyZWFrO1xuXHRcdGNhc2UgMTE6IC8vIFByZWZlcnJlZCBTeW1tZXRyaWMgQWxnb3JpdGhtc1xuXHRcdFx0dGhpcy5wcmVmZXJyZWRTeW1tZXRyaWNBbGdvcml0aG1zID0gW107XG5cblx0XHRcdHdoaWxlKG15cG9zICE9IGJ5dGVzLmxlbmd0aCkge1xuXHRcdFx0XHR0aGlzLnByZWZlcnJlZFN5bW1ldHJpY0FsZ29yaXRobXMucHVzaChieXRlc1tteXBvcysrXS5jaGFyQ29kZUF0KCkpO1xuXHRcdFx0fVxuXG5cdFx0XHRicmVhaztcblx0XHRjYXNlIDEyOiAvLyBSZXZvY2F0aW9uIEtleVxuXHRcdFx0Ly8gKDEgb2N0ZXQgb2YgY2xhc3MsIDEgb2N0ZXQgb2YgcHVibGljLWtleSBhbGdvcml0aG0gSUQsIDIwXG5cdFx0XHQvLyBvY3RldHMgb2Zcblx0XHRcdC8vIGZpbmdlcnByaW50KVxuXHRcdFx0dGhpcy5yZXZvY2F0aW9uS2V5Q2xhc3MgPSBieXRlc1tteXBvcysrXS5jaGFyQ29kZUF0KCk7XG5cdFx0XHR0aGlzLnJldm9jYXRpb25LZXlBbGdvcml0aG0gPSBieXRlc1tteXBvcysrXS5jaGFyQ29kZUF0KCk7XG5cdFx0XHR0aGlzLnJldm9jYXRpb25LZXlGaW5nZXJwcmludCA9IGJ5dGVzLnN1YnN0cihteXBvcywgMjApO1xuXHRcdFx0YnJlYWs7XG5cblx0XHRjYXNlIDE2OiAvLyBJc3N1ZXJcblx0XHRcdHRoaXMuaXNzdWVyS2V5SWQgPSBieXRlcy5zdWJzdHIobXlwb3MsIDgpO1xuXHRcdFx0YnJlYWs7XG5cblx0XHRjYXNlIDIwOiAvLyBOb3RhdGlvbiBEYXRhXG5cdFx0XHQvLyBXZSBkb24ndCBrbm93IGhvdyB0byBoYW5kbGUgYW55dGhpbmcgYnV0IGEgdGV4dCBmbGFnZ2VkIGRhdGEuXG5cdFx0XHRpZihieXRlc1tteXBvc10uY2hhckNvZGVBdCgpID09IDB4ODApIHtcblxuXHRcdFx0XHQvLyBXZSBleHRyYWN0IGtleS92YWx1ZSB0dXBsZSBmcm9tIHRoZSBieXRlIHN0cmVhbS5cblx0XHRcdFx0bXlwb3MgKz0gNDtcblx0XHRcdFx0dmFyIG0gPSB1dGlsLndyaXRlTnVtYmVyKGJ5dGVzLnN1YnN0cihteXBvcywgMikpO1xuXHRcdFx0XHRteXBvcyArPSAyXG5cdFx0XHRcdHZhciBuID0gdXRpbC53cml0ZU51bWJlcihieXRlcy5zdWJzdHIobXlwb3MsIDIpKTtcblx0XHRcdFx0bXlwb3MgKz0gMlxuXG5cdFx0XHRcdHZhciBuYW1lID0gYnl0ZXMuc3Vic3RyKG15cG9zLCBtKSxcblx0XHRcdFx0XHR2YWx1ZSA9IGJ5dGVzLnN1YnN0cihteXBvcyArIG0sIG4pO1xuXG5cdFx0XHRcdHRoaXMubm90YXRpb25bbmFtZV0gPSB2YWx1ZTtcblx0XHRcdH1cblx0XHRcdGVsc2UgdGhyb3cgbmV3IEVycm9yKFwiVW5zdXBwb3J0ZWQgbm90YXRpb24gZmxhZy5cIik7XG5cdFx0XHRicmVhaztcblx0XHRjYXNlIDIxOiAvLyBQcmVmZXJyZWQgSGFzaCBBbGdvcml0aG1zXG5cdFx0XHRyZWFkX2FycmF5LmNhbGwodGhpcywgJ3ByZWZlcnJlZEhhc2hBbGdvcml0aG1zJywgYnl0ZXMuc3Vic3RyKG15cG9zKSk7XG5cdFx0XHRicmVhaztcblx0XHRjYXNlIDIyOiAvLyBQcmVmZXJyZWQgQ29tcHJlc3Npb24gQWxnb3JpdGhtc1xuXHRcdFx0cmVhZF9hcnJheS5jYWxsKHRoaXMsICdwcmVmZXJyZWRDb21wcmVzc2lvbkFsZ29yaXRobXMgJywgYnl0ZXMuc3Vic3RyKG15cG9zKSk7XG5cdFx0XHRicmVhaztcblx0XHRjYXNlIDIzOiAvLyBLZXkgU2VydmVyIFByZWZlcmVuY2VzXG5cdFx0XHRyZWFkX2FycmF5LmNhbGwodGhpcywgJ2tleVNlcnZlclByZWZlcmVuY2VzcycsIGJ5dGVzLnN1YnN0cihteXBvcykpO1xuXHRcdFx0YnJlYWs7XG5cdFx0Y2FzZSAyNDogLy8gUHJlZmVycmVkIEtleSBTZXJ2ZXJcblx0XHRcdHRoaXMucHJlZmVycmVkS2V5U2VydmVyID0gYnl0ZXMuc3Vic3RyKG15cG9zKTtcblx0XHRcdGJyZWFrO1xuXHRcdGNhc2UgMjU6IC8vIFByaW1hcnkgVXNlciBJRFxuXHRcdFx0dGhpcy5pc1ByaW1hcnlVc2VySUQgPSBieXRlc1tteXBvcysrXSAhPSAwO1xuXHRcdFx0YnJlYWs7XG5cdFx0Y2FzZSAyNjogLy8gUG9saWN5IFVSSVxuXHRcdFx0dGhpcy5wb2xpY3lVUkkgPSBieXRlcy5zdWJzdHIobXlwb3MpO1xuXHRcdFx0YnJlYWs7XG5cdFx0Y2FzZSAyNzogLy8gS2V5IEZsYWdzXG5cdFx0XHRyZWFkX2FycmF5LmNhbGwodGhpcywgJ2tleUZsYWdzJywgYnl0ZXMuc3Vic3RyKG15cG9zKSk7XG5cdFx0XHRicmVhaztcblx0XHRjYXNlIDI4OiAvLyBTaWduZXIncyBVc2VyIElEXG5cdFx0XHR0aGlzLnNpZ25lcnNVc2VySWQgKz0gYnl0ZXMuc3Vic3RyKG15cG9zKTtcblx0XHRcdGJyZWFrO1xuXHRcdGNhc2UgMjk6IC8vIFJlYXNvbiBmb3IgUmV2b2NhdGlvblxuXHRcdFx0dGhpcy5yZWFzb25Gb3JSZXZvY2F0aW9uRmxhZyA9IGJ5dGVzW215cG9zKytdLmNoYXJDb2RlQXQoKTtcblx0XHRcdHRoaXMucmVhc29uRm9yUmV2b2NhdGlvblN0cmluZyA9IGJ5dGVzLnN1YnN0cihteXBvcyk7XG5cdFx0XHRicmVhaztcblx0XHRjYXNlIDMwOiAvLyBGZWF0dXJlc1xuXHRcdFx0cmVhZF9hcnJheS5jYWxsKHRoaXMsICdmZWF0dXJlcycsIGJ5dGVzLnN1YnN0cihteXBvcykpO1xuXHRcdFx0YnJlYWs7XG5cdFx0Y2FzZSAzMTogLy8gU2lnbmF0dXJlIFRhcmdldFxuXHRcdFx0Ly8gKDEgb2N0ZXQgcHVibGljLWtleSBhbGdvcml0aG0sIDEgb2N0ZXQgaGFzaCBhbGdvcml0aG0sIE4gb2N0ZXRzIGhhc2gpXG5cdFx0XHR0aGlzLnNpZ25hdHVyZVRhcmdldFB1YmxpY0tleUFsZ29yaXRobSA9IGJ5dGVzW215cG9zKytdLmNoYXJDb2RlQXQoKTtcblx0XHRcdHRoaXMuc2lnbmF0dXJlVGFyZ2V0SGFzaEFsZ29yaXRobSA9IGJ5dGVzW215cG9zKytdLmNoYXJDb2RlQXQoKTtcblxuXHRcdFx0dmFyIGxlbiA9IGNyeXB0by5nZXRIYXNoQnl0ZUxlbmd0aCh0aGlzLnNpZ25hdHVyZVRhcmdldEhhc2hBbGdvcml0aG0pO1xuXG5cdFx0XHR0aGlzLnNpZ25hdHVyZVRhcmdldEhhc2ggPSBieXRlcy5zdWJzdHIobXlwb3MsIGxlbik7XG5cdFx0XHRicmVhaztcblx0XHRjYXNlIDMyOiAvLyBFbWJlZGRlZCBTaWduYXR1cmVcblx0XHRcdHRoaXMuZW1iZWRkZWRTaWduYXR1cmUgPSBuZXcgcGFja2V0X3NpZ25hdHVyZSgpO1xuXHRcdFx0dGhpcy5lbWJlZGRlZFNpZ25hdHVyZS5yZWFkKGJ5dGVzLnN1YnN0cihteXBvcykpO1xuXHRcdFx0YnJlYWs7XG5cdFx0ZGVmYXVsdDpcblx0XHRcdHV0aWwucHJpbnRfZXJyb3IoXCJvcGVucGdwLnBhY2tldC5zaWduYXR1cmUuanNcXG5cIitcblx0XHRcdFx0J3Vua25vd24gc2lnbmF0dXJlIHN1YnBhY2tldCB0eXBlICcrdHlwZStcIiBAOlwiK215cG9zK1xuXHRcdFx0XHRcIiBzdWJwbGVuOlwiK3N1YnBsZW4rXCIgbGVuOlwiK2xlbik7XG5cdFx0XHRicmVhaztcblx0XHR9XG5cdH07XG5cblx0Ly8gUHJvZHVjZXMgZGF0YSB0byBwcm9kdWNlIHNpZ25hdHVyZSBvblxuXHR0aGlzLnRvU2lnbiA9IGZ1bmN0aW9uKHR5cGUsIGRhdGEpIHtcblx0XHR2YXIgdCA9IGVudW1zLnNpZ25hdHVyZVxuXG5cdFx0c3dpdGNoKHR5cGUpIHtcblx0XHRjYXNlIHQuYmluYXJ5OlxuXHRcdFx0cmV0dXJuIGRhdGEubGl0ZXJhbC5nZXRCeXRlcygpO1xuXG5cdFx0Y2FzZSB0LnRleHQ6XG5cdFx0XHRyZXR1cm4gdGhpcy50b1NpZ24odC5iaW5hcnksIGRhdGEpXG5cdFx0XHRcdC5yZXBsYWNlKC9cXHJcXG4vZywgJ1xcbicpXG5cdFx0XHRcdC5yZXBsYWNlKC9cXG4vZywgJ1xcclxcbicpO1xuXHRcdFx0XHRcblx0XHRjYXNlIHQuc3RhbmRhbG9uZTpcblx0XHRcdHJldHVybiAnJ1xuXG5cdFx0Y2FzZSB0LmNlcnRfZ2VuZXJpYzpcblx0XHRjYXNlIHQuY2VydF9wZXJzb25hOlxuXHRcdGNhc2UgdC5jZXJ0X2Nhc3VhbDpcblx0XHRjYXNlIHQuY2VydF9wb3NpdGl2ZTpcblx0XHRjYXNlIHQuY2VydF9yZXZvY2F0aW9uOlxuXHRcdHtcblx0XHRcdHZhciBwYWNrZXQsIHRhZztcblxuXHRcdFx0aWYoZGF0YS51c2VyaWQgIT0gdW5kZWZpbmVkKSB7XG5cdFx0XHRcdHRhZyA9IDB4QjQ7XG5cdFx0XHRcdHBhY2tldCA9IGRhdGEudXNlcmlkO1xuXHRcdFx0fVxuXHRcdFx0ZWxzZSBpZihkYXRhLnVzZXJhdHRyaWJ1dGUgIT0gdW5kZWZpbmVkKSB7XG5cdFx0XHRcdHRhZyA9IDB4RDFcblx0XHRcdFx0cGFja2V0ID0gZGF0YS51c2VyYXR0cmlidXRlO1xuXHRcdFx0fVxuXHRcdFx0ZWxzZSB0aHJvdyBuZXcgRXJyb3IoJ0VpdGhlciBhIHVzZXJpZCBvciB1c2VyYXR0cmlidXRlIHBhY2tldCBuZWVkcyB0byBiZSAnICtcblx0XHRcdFx0J3N1cHBsaWVkIGZvciBjZXJ0aWZpY2F0aW9uLicpO1xuXG5cblx0XHRcdHZhciBieXRlcyA9IHBhY2tldC53cml0ZSgpO1xuXG5cdFx0XHRcblx0XHRcdHJldHVybiB0aGlzLnRvU2lnbih0LmtleSwgZGF0YSkgK1xuXHRcdFx0XHRTdHJpbmcuZnJvbUNoYXJDb2RlKHRhZykgK1xuXHRcdFx0XHR1dGlsLndyaXRlTnVtYmVyKGJ5dGVzLmxlbmd0aCwgNCkgK1xuXHRcdFx0XHRieXRlcztcblx0XHR9XG5cdFx0Y2FzZSB0LnN1YmtleV9iaW5kaW5nOlxuXHRcdGNhc2UgdC5rZXlfYmluZGluZzpcblx0XHR7XG5cdFx0XHRyZXR1cm4gdGhpcy50b1NpZ24odC5rZXksIGRhdGEpICsgdGhpcy50b1NpZ24odC5rZXksIHsga2V5OiBkYXRhLmJpbmQgfSk7XG5cdFx0fVxuXHRcdGNhc2UgdC5rZXk6XG5cdFx0e1xuXHRcdFx0aWYoZGF0YS5rZXkgPT0gdW5kZWZpbmVkKVxuXHRcdFx0XHR0aHJvdyBuZXcgRXJyb3IoJ0tleSBwYWNrZXQgaXMgcmVxdWlyZWQgZm9yIHRoaXMgc2lndGF0dXJlLicpO1xuXHRcdFx0XG5cdFx0XHRyZXR1cm4gZGF0YS5rZXkud3JpdGVPbGQoKTtcblx0XHR9XG5cdFx0Y2FzZSB0LmtleV9yZXZvY2F0aW9uOlxuXHRcdGNhc2UgdC5zdWJrZXlfcmV2b2NhdGlvbjpcblx0XHRcdHJldHVybiB0aGlzLnRvU2lnbih0LmtleSwgZGF0YSk7XG5cdFx0Y2FzZSB0LnRpbWVzdGFtcDpcblx0XHRcdHJldHVybiAnJztcblx0XHRjYXNlIHQudGhyaWRfcGFydHk6XG5cdFx0XHR0aHJvdyBuZXcgRXJyb3IoJ05vdCBpbXBsZW1lbnRlZCcpO1xuXHRcdFx0YnJlYWs7XG5cdFx0ZGVmYXVsdDpcblx0XHRcdHRocm93IG5ldyBFcnJvcignVW5rbm93biBzaWduYXR1cmUgdHlwZS4nKVxuXHRcdH1cblx0fVxuXG5cdFxuXHR0aGlzLmNhbGN1bGF0ZVRyYWlsZXIgPSBmdW5jdGlvbigpIHtcblx0XHQvLyBjYWxjdWxhdGluZyB0aGUgdHJhaWxlclxuXHRcdHZhciB0cmFpbGVyID0gJyc7XG5cdFx0dHJhaWxlciArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKDQpOyAvLyBWZXJzaW9uXG5cdFx0dHJhaWxlciArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKDB4RkYpO1xuXHRcdHRyYWlsZXIgKz0gdXRpbC53cml0ZU51bWJlcih0aGlzLnNpZ25hdHVyZURhdGEubGVuZ3RoLCA0KTtcblx0XHRyZXR1cm4gdHJhaWxlclxuXHR9XG5cblxuXHQvKipcblx0ICogdmVyaWZ5cyB0aGUgc2lnbmF0dXJlIHBhY2tldC4gTm90ZTogbm90IHNpZ25hdHVyZSB0eXBlcyBhcmUgaW1wbGVtZW50ZWRcblx0ICogQHBhcmFtIHtTdHJpbmd9IGRhdGEgZGF0YSB3aGljaCBvbiB0aGUgc2lnbmF0dXJlIGFwcGxpZXNcblx0ICogQHBhcmFtIHtvcGVucGdwX21zZ19wcml2YXRla2V5fSBrZXkgdGhlIHB1YmxpYyBrZXkgdG8gdmVyaWZ5IHRoZSBzaWduYXR1cmVcblx0ICogQHJldHVybiB7Ym9vbGVhbn0gVHJ1ZSBpZiBtZXNzYWdlIGlzIHZlcmlmaWVkLCBlbHNlIGZhbHNlLlxuXHQgKi9cblx0dGhpcy52ZXJpZnkgPSBmdW5jdGlvbihrZXksIGRhdGEpIHtcblx0XHR2YXIgc2lnbmF0dXJlVHlwZSA9IGVudW1zLndyaXRlKGVudW1zLnNpZ25hdHVyZSwgdGhpcy5zaWduYXR1cmVUeXBlKSxcblx0XHRcdHB1YmxpY0tleUFsZ29yaXRobSA9IGVudW1zLndyaXRlKGVudW1zLnB1YmxpY0tleSwgdGhpcy5wdWJsaWNLZXlBbGdvcml0aG0pLFxuXHRcdFx0aGFzaEFsZ29yaXRobSA9IGVudW1zLndyaXRlKGVudW1zLmhhc2gsIHRoaXMuaGFzaEFsZ29yaXRobSk7XG5cblx0XHR2YXIgYnl0ZXMgPSB0aGlzLnRvU2lnbihzaWduYXR1cmVUeXBlLCBkYXRhKSxcblx0XHRcdHRyYWlsZXIgPSB0aGlzLmNhbGN1bGF0ZVRyYWlsZXIoKTtcblxuXG5cdFx0dmFyIG1waWNvdW50ID0gMDtcblx0XHQvLyBBbGdvcml0aG0tU3BlY2lmaWMgRmllbGRzIGZvciBSU0Egc2lnbmF0dXJlczpcblx0XHQvLyBcdCAgICAtIG11bHRpcHJlY2lzaW9uIG51bWJlciAoTVBJKSBvZiBSU0Egc2lnbmF0dXJlIHZhbHVlIG0qKmQgbW9kIG4uXG5cdFx0aWYgKHB1YmxpY0tleUFsZ29yaXRobSA+IDAgJiYgcHVibGljS2V5QWxnb3JpdGhtIDwgNClcblx0XHRcdG1waWNvdW50ID0gMTtcblx0XHQvLyAgICBBbGdvcml0aG0tU3BlY2lmaWMgRmllbGRzIGZvciBEU0Egc2lnbmF0dXJlczpcblx0XHQvLyAgICAgIC0gTVBJIG9mIERTQSB2YWx1ZSByLlxuXHRcdC8vICAgICAgLSBNUEkgb2YgRFNBIHZhbHVlIHMuXG5cdFx0ZWxzZSBpZiAocHVibGljS2V5QWxnb3JpdGhtID09IDE3KVxuXHRcdFx0bXBpY291bnQgPSAyO1xuXHRcdFxuXHRcdHZhciBtcGkgPSBbXSwgaSA9IDA7XG5cdFx0Zm9yICh2YXIgaiA9IDA7IGogPCBtcGljb3VudDsgaisrKSB7XG5cdFx0XHRtcGlbal0gPSBuZXcgdHlwZV9tcGkoKTtcblx0XHRcdGkgKz0gbXBpW2pdLnJlYWQodGhpcy5zaWduYXR1cmUuc3Vic3RyKGkpKTtcblx0XHR9XG5cblx0XHR0aGlzLnZlcmlmaWVkID0gY3J5cHRvLnNpZ25hdHVyZS52ZXJpZnkocHVibGljS2V5QWxnb3JpdGhtLCBcblx0XHRcdGhhc2hBbGdvcml0aG0sIG1waSwga2V5Lm1waSwgXG5cdFx0XHRieXRlcyArIHRoaXMuc2lnbmF0dXJlRGF0YSArIHRyYWlsZXIpO1xuXG5cdFx0cmV0dXJuIHRoaXMudmVyaWZpZWQ7XG5cdH1cbn1cblxuIiwiXG4vKiBSaWpuZGFlbCAoQUVTKSBFbmNyeXB0aW9uXG4gKiBDb3B5cmlnaHQgMjAwNSBIZXJiZXJ0IEhhbmV3aW5rZWwsIHd3dy5oYW5lV0lOLmRlXG4gKiB2ZXJzaW9uIDEuMSwgY2hlY2sgd3d3LmhhbmVXSU4uZGUgZm9yIHRoZSBsYXRlc3QgdmVyc2lvblxuXG4gKiBUaGlzIHNvZnR3YXJlIGlzIHByb3ZpZGVkIGFzLWlzLCB3aXRob3V0IGV4cHJlc3Mgb3IgaW1wbGllZCB3YXJyYW50eS4gIFxuICogUGVybWlzc2lvbiB0byB1c2UsIGNvcHksIG1vZGlmeSwgZGlzdHJpYnV0ZSBvciBzZWxsIHRoaXMgc29mdHdhcmUsIHdpdGggb3JcbiAqIHdpdGhvdXQgZmVlLCBmb3IgYW55IHB1cnBvc2UgYW5kIGJ5IGFueSBpbmRpdmlkdWFsIG9yIG9yZ2FuaXphdGlvbiwgaXMgaGVyZWJ5XG4gKiBncmFudGVkLCBwcm92aWRlZCB0aGF0IHRoZSBhYm92ZSBjb3B5cmlnaHQgbm90aWNlIGFuZCB0aGlzIHBhcmFncmFwaCBhcHBlYXIgXG4gKiBpbiBhbGwgY29waWVzLiBEaXN0cmlidXRpb24gYXMgYSBwYXJ0IG9mIGFuIGFwcGxpY2F0aW9uIG9yIGJpbmFyeSBtdXN0XG4gKiBpbmNsdWRlIHRoZSBhYm92ZSBjb3B5cmlnaHQgbm90aWNlIGluIHRoZSBkb2N1bWVudGF0aW9uIGFuZC9vciBvdGhlclxuICogbWF0ZXJpYWxzIHByb3ZpZGVkIHdpdGggdGhlIGFwcGxpY2F0aW9uIG9yIGRpc3RyaWJ1dGlvbi5cbiAqL1xuXG52YXIgdXRpbCA9IHJlcXVpcmUoJy4uLy4uL3V0aWwnKTtcblxuLy8gVGhlIHJvdW5kIGNvbnN0YW50cyB1c2VkIGluIHN1YmtleSBleHBhbnNpb25cbnZhciBSY29uID0gWyBcbjB4MDEsIDB4MDIsIDB4MDQsIDB4MDgsIDB4MTAsIDB4MjAsIDB4NDAsIDB4ODAsIDB4MWIsIDB4MzYsIDB4NmMsIDB4ZDgsIFxuMHhhYiwgMHg0ZCwgMHg5YSwgMHgyZiwgMHg1ZSwgMHhiYywgMHg2MywgMHhjNiwgMHg5NywgMHgzNSwgMHg2YSwgMHhkNCwgXG4weGIzLCAweDdkLCAweGZhLCAweGVmLCAweGM1LCAweDkxIF07XG5cbi8vIFByZWNvbXB1dGVkIGxvb2t1cCB0YWJsZSBmb3IgdGhlIFNCb3hcbnZhciBTID0gW1xuIDk5LCAxMjQsIDExOSwgMTIzLCAyNDIsIDEwNywgMTExLCAxOTcsICA0OCwgICAxLCAxMDMsICA0MywgMjU0LCAyMTUsIDE3MSwgXG4xMTgsIDIwMiwgMTMwLCAyMDEsIDEyNSwgMjUwLCAgODksICA3MSwgMjQwLCAxNzMsIDIxMiwgMTYyLCAxNzUsIDE1NiwgMTY0LCBcbjExNCwgMTkyLCAxODMsIDI1MywgMTQ3LCAgMzgsICA1NCwgIDYzLCAyNDcsIDIwNCwgIDUyLCAxNjUsIDIyOSwgMjQxLCAxMTMsIFxuMjE2LCAgNDksICAyMSwgICA0LCAxOTksICAzNSwgMTk1LCAgMjQsIDE1MCwgICA1LCAxNTQsICAgNywgIDE4LCAxMjgsIDIyNiwgXG4yMzUsICAzOSwgMTc4LCAxMTcsICAgOSwgMTMxLCAgNDQsICAyNiwgIDI3LCAxMTAsICA5MCwgMTYwLCAgODIsICA1OSwgMjE0LCBcbjE3OSwgIDQxLCAyMjcsICA0NywgMTMyLCAgODMsIDIwOSwgICAwLCAyMzcsICAzMiwgMjUyLCAxNzcsICA5MSwgMTA2LCAyMDMsIFxuMTkwLCAgNTcsICA3NCwgIDc2LCAgODgsIDIwNywgMjA4LCAyMzksIDE3MCwgMjUxLCAgNjcsICA3NywgIDUxLCAxMzMsICA2OSwgXG4yNDksICAgMiwgMTI3LCAgODAsICA2MCwgMTU5LCAxNjgsICA4MSwgMTYzLCAgNjQsIDE0MywgMTQ2LCAxNTcsICA1NiwgMjQ1LCBcbjE4OCwgMTgyLCAyMTgsICAzMywgIDE2LCAyNTUsIDI0MywgMjEwLCAyMDUsICAxMiwgIDE5LCAyMzYsICA5NSwgMTUxLCAgNjgsICBcbjIzLCAgMTk2LCAxNjcsIDEyNiwgIDYxLCAxMDAsICA5MywgIDI1LCAxMTUsICA5NiwgMTI5LCAgNzksIDIyMCwgIDM0LCAgNDIsIFxuMTQ0LCAxMzYsICA3MCwgMjM4LCAxODQsICAyMCwgMjIyLCAgOTQsICAxMSwgMjE5LCAyMjQsICA1MCwgIDU4LCAgMTAsICA3MyxcbiAgNiwgIDM2LCAgOTIsIDE5NCwgMjExLCAxNzIsICA5OCwgMTQ1LCAxNDksIDIyOCwgMTIxLCAyMzEsIDIwMCwgIDU1LCAxMDksIFxuMTQxLCAyMTMsICA3OCwgMTY5LCAxMDgsICA4NiwgMjQ0LCAyMzQsIDEwMSwgMTIyLCAxNzQsICAgOCwgMTg2LCAxMjAsICAzNywgIFxuIDQ2LCAgMjgsIDE2NiwgMTgwLCAxOTgsIDIzMiwgMjIxLCAxMTYsICAzMSwgIDc1LCAxODksIDEzOSwgMTM4LCAxMTIsICA2MiwgXG4xODEsIDEwMiwgIDcyLCAgIDMsIDI0NiwgIDE0LCAgOTcsICA1MywgIDg3LCAxODUsIDEzNCwgMTkzLCAgMjksIDE1OCwgMjI1LFxuMjQ4LCAxNTIsICAxNywgMTA1LCAyMTcsIDE0MiwgMTQ4LCAxNTUsICAzMCwgMTM1LCAyMzMsIDIwNiwgIDg1LCAgNDAsIDIyMyxcbjE0MCwgMTYxLCAxMzcsICAxMywgMTkxLCAyMzAsICA2NiwgMTA0LCAgNjUsIDE1MywgIDQ1LCAgMTUsIDE3NiwgIDg0LCAxODcsICBcbiAyMiBdO1xuXG52YXIgVDEgPSBbXG4weGE1NjM2M2M2LCAweDg0N2M3Y2Y4LCAweDk5Nzc3N2VlLCAweDhkN2I3YmY2LFxuMHgwZGYyZjJmZiwgMHhiZDZiNmJkNiwgMHhiMTZmNmZkZSwgMHg1NGM1YzU5MSxcbjB4NTAzMDMwNjAsIDB4MDMwMTAxMDIsIDB4YTk2NzY3Y2UsIDB4N2QyYjJiNTYsXG4weDE5ZmVmZWU3LCAweDYyZDdkN2I1LCAweGU2YWJhYjRkLCAweDlhNzY3NmVjLFxuMHg0NWNhY2E4ZiwgMHg5ZDgyODIxZiwgMHg0MGM5Yzk4OSwgMHg4NzdkN2RmYSxcbjB4MTVmYWZhZWYsIDB4ZWI1OTU5YjIsIDB4Yzk0NzQ3OGUsIDB4MGJmMGYwZmIsXG4weGVjYWRhZDQxLCAweDY3ZDRkNGIzLCAweGZkYTJhMjVmLCAweGVhYWZhZjQ1LFxuMHhiZjljOWMyMywgMHhmN2E0YTQ1MywgMHg5NjcyNzJlNCwgMHg1YmMwYzA5YixcbjB4YzJiN2I3NzUsIDB4MWNmZGZkZTEsIDB4YWU5MzkzM2QsIDB4NmEyNjI2NGMsXG4weDVhMzYzNjZjLCAweDQxM2YzZjdlLCAweDAyZjdmN2Y1LCAweDRmY2NjYzgzLFxuMHg1YzM0MzQ2OCwgMHhmNGE1YTU1MSwgMHgzNGU1ZTVkMSwgMHgwOGYxZjFmOSxcbjB4OTM3MTcxZTIsIDB4NzNkOGQ4YWIsIDB4NTMzMTMxNjIsIDB4M2YxNTE1MmEsXG4weDBjMDQwNDA4LCAweDUyYzdjNzk1LCAweDY1MjMyMzQ2LCAweDVlYzNjMzlkLFxuMHgyODE4MTgzMCwgMHhhMTk2OTYzNywgMHgwZjA1MDUwYSwgMHhiNTlhOWEyZixcbjB4MDkwNzA3MGUsIDB4MzYxMjEyMjQsIDB4OWI4MDgwMWIsIDB4M2RlMmUyZGYsXG4weDI2ZWJlYmNkLCAweDY5MjcyNzRlLCAweGNkYjJiMjdmLCAweDlmNzU3NWVhLFxuMHgxYjA5MDkxMiwgMHg5ZTgzODMxZCwgMHg3NDJjMmM1OCwgMHgyZTFhMWEzNCxcbjB4MmQxYjFiMzYsIDB4YjI2ZTZlZGMsIDB4ZWU1YTVhYjQsIDB4ZmJhMGEwNWIsXG4weGY2NTI1MmE0LCAweDRkM2IzYjc2LCAweDYxZDZkNmI3LCAweGNlYjNiMzdkLFxuMHg3YjI5Mjk1MiwgMHgzZWUzZTNkZCwgMHg3MTJmMmY1ZSwgMHg5Nzg0ODQxMyxcbjB4ZjU1MzUzYTYsIDB4NjhkMWQxYjksIDB4MDAwMDAwMDAsIDB4MmNlZGVkYzEsXG4weDYwMjAyMDQwLCAweDFmZmNmY2UzLCAweGM4YjFiMTc5LCAweGVkNWI1YmI2LFxuMHhiZTZhNmFkNCwgMHg0NmNiY2I4ZCwgMHhkOWJlYmU2NywgMHg0YjM5Mzk3MixcbjB4ZGU0YTRhOTQsIDB4ZDQ0YzRjOTgsIDB4ZTg1ODU4YjAsIDB4NGFjZmNmODUsXG4weDZiZDBkMGJiLCAweDJhZWZlZmM1LCAweGU1YWFhYTRmLCAweDE2ZmJmYmVkLFxuMHhjNTQzNDM4NiwgMHhkNzRkNGQ5YSwgMHg1NTMzMzM2NiwgMHg5NDg1ODUxMSxcbjB4Y2Y0NTQ1OGEsIDB4MTBmOWY5ZTksIDB4MDYwMjAyMDQsIDB4ODE3ZjdmZmUsXG4weGYwNTA1MGEwLCAweDQ0M2MzYzc4LCAweGJhOWY5ZjI1LCAweGUzYThhODRiLFxuMHhmMzUxNTFhMiwgMHhmZWEzYTM1ZCwgMHhjMDQwNDA4MCwgMHg4YThmOGYwNSxcbjB4YWQ5MjkyM2YsIDB4YmM5ZDlkMjEsIDB4NDgzODM4NzAsIDB4MDRmNWY1ZjEsXG4weGRmYmNiYzYzLCAweGMxYjZiNjc3LCAweDc1ZGFkYWFmLCAweDYzMjEyMTQyLFxuMHgzMDEwMTAyMCwgMHgxYWZmZmZlNSwgMHgwZWYzZjNmZCwgMHg2ZGQyZDJiZixcbjB4NGNjZGNkODEsIDB4MTQwYzBjMTgsIDB4MzUxMzEzMjYsIDB4MmZlY2VjYzMsXG4weGUxNWY1ZmJlLCAweGEyOTc5NzM1LCAweGNjNDQ0NDg4LCAweDM5MTcxNzJlLFxuMHg1N2M0YzQ5MywgMHhmMmE3YTc1NSwgMHg4MjdlN2VmYywgMHg0NzNkM2Q3YSxcbjB4YWM2NDY0YzgsIDB4ZTc1ZDVkYmEsIDB4MmIxOTE5MzIsIDB4OTU3MzczZTYsXG4weGEwNjA2MGMwLCAweDk4ODE4MTE5LCAweGQxNGY0ZjllLCAweDdmZGNkY2EzLFxuMHg2NjIyMjI0NCwgMHg3ZTJhMmE1NCwgMHhhYjkwOTAzYiwgMHg4Mzg4ODgwYixcbjB4Y2E0NjQ2OGMsIDB4MjllZWVlYzcsIDB4ZDNiOGI4NmIsIDB4M2MxNDE0MjgsXG4weDc5ZGVkZWE3LCAweGUyNWU1ZWJjLCAweDFkMGIwYjE2LCAweDc2ZGJkYmFkLFxuMHgzYmUwZTBkYiwgMHg1NjMyMzI2NCwgMHg0ZTNhM2E3NCwgMHgxZTBhMGExNCxcbjB4ZGI0OTQ5OTIsIDB4MGEwNjA2MGMsIDB4NmMyNDI0NDgsIDB4ZTQ1YzVjYjgsXG4weDVkYzJjMjlmLCAweDZlZDNkM2JkLCAweGVmYWNhYzQzLCAweGE2NjI2MmM0LFxuMHhhODkxOTEzOSwgMHhhNDk1OTUzMSwgMHgzN2U0ZTRkMywgMHg4Yjc5NzlmMixcbjB4MzJlN2U3ZDUsIDB4NDNjOGM4OGIsIDB4NTkzNzM3NmUsIDB4Yjc2ZDZkZGEsXG4weDhjOGQ4ZDAxLCAweDY0ZDVkNWIxLCAweGQyNGU0ZTljLCAweGUwYTlhOTQ5LFxuMHhiNDZjNmNkOCwgMHhmYTU2NTZhYywgMHgwN2Y0ZjRmMywgMHgyNWVhZWFjZixcbjB4YWY2NTY1Y2EsIDB4OGU3YTdhZjQsIDB4ZTlhZWFlNDcsIDB4MTgwODA4MTAsXG4weGQ1YmFiYTZmLCAweDg4Nzg3OGYwLCAweDZmMjUyNTRhLCAweDcyMmUyZTVjLFxuMHgyNDFjMWMzOCwgMHhmMWE2YTY1NywgMHhjN2I0YjQ3MywgMHg1MWM2YzY5NyxcbjB4MjNlOGU4Y2IsIDB4N2NkZGRkYTEsIDB4OWM3NDc0ZTgsIDB4MjExZjFmM2UsXG4weGRkNGI0Yjk2LCAweGRjYmRiZDYxLCAweDg2OGI4YjBkLCAweDg1OGE4YTBmLFxuMHg5MDcwNzBlMCwgMHg0MjNlM2U3YywgMHhjNGI1YjU3MSwgMHhhYTY2NjZjYyxcbjB4ZDg0ODQ4OTAsIDB4MDUwMzAzMDYsIDB4MDFmNmY2ZjcsIDB4MTIwZTBlMWMsXG4weGEzNjE2MWMyLCAweDVmMzUzNTZhLCAweGY5NTc1N2FlLCAweGQwYjliOTY5LFxuMHg5MTg2ODYxNywgMHg1OGMxYzE5OSwgMHgyNzFkMWQzYSwgMHhiOTllOWUyNyxcbjB4MzhlMWUxZDksIDB4MTNmOGY4ZWIsIDB4YjM5ODk4MmIsIDB4MzMxMTExMjIsXG4weGJiNjk2OWQyLCAweDcwZDlkOWE5LCAweDg5OGU4ZTA3LCAweGE3OTQ5NDMzLFxuMHhiNjliOWIyZCwgMHgyMjFlMWUzYywgMHg5Mjg3ODcxNSwgMHgyMGU5ZTljOSxcbjB4NDljZWNlODcsIDB4ZmY1NTU1YWEsIDB4NzgyODI4NTAsIDB4N2FkZmRmYTUsXG4weDhmOGM4YzAzLCAweGY4YTFhMTU5LCAweDgwODk4OTA5LCAweDE3MGQwZDFhLFxuMHhkYWJmYmY2NSwgMHgzMWU2ZTZkNywgMHhjNjQyNDI4NCwgMHhiODY4NjhkMCxcbjB4YzM0MTQxODIsIDB4YjA5OTk5MjksIDB4NzcyZDJkNWEsIDB4MTEwZjBmMWUsXG4weGNiYjBiMDdiLCAweGZjNTQ1NGE4LCAweGQ2YmJiYjZkLCAweDNhMTYxNjJjIF07XG5cbnZhciBUMiA9IFtcbjB4NjM2M2M2YTUsIDB4N2M3Y2Y4ODQsIDB4Nzc3N2VlOTksIDB4N2I3YmY2OGQsXG4weGYyZjJmZjBkLCAweDZiNmJkNmJkLCAweDZmNmZkZWIxLCAweGM1YzU5MTU0LFxuMHgzMDMwNjA1MCwgMHgwMTAxMDIwMywgMHg2NzY3Y2VhOSwgMHgyYjJiNTY3ZCxcbjB4ZmVmZWU3MTksIDB4ZDdkN2I1NjIsIDB4YWJhYjRkZTYsIDB4NzY3NmVjOWEsXG4weGNhY2E4ZjQ1LCAweDgyODIxZjlkLCAweGM5Yzk4OTQwLCAweDdkN2RmYTg3LFxuMHhmYWZhZWYxNSwgMHg1OTU5YjJlYiwgMHg0NzQ3OGVjOSwgMHhmMGYwZmIwYixcbjB4YWRhZDQxZWMsIDB4ZDRkNGIzNjcsIDB4YTJhMjVmZmQsIDB4YWZhZjQ1ZWEsXG4weDljOWMyM2JmLCAweGE0YTQ1M2Y3LCAweDcyNzJlNDk2LCAweGMwYzA5YjViLFxuMHhiN2I3NzVjMiwgMHhmZGZkZTExYywgMHg5MzkzM2RhZSwgMHgyNjI2NGM2YSxcbjB4MzYzNjZjNWEsIDB4M2YzZjdlNDEsIDB4ZjdmN2Y1MDIsIDB4Y2NjYzgzNGYsXG4weDM0MzQ2ODVjLCAweGE1YTU1MWY0LCAweGU1ZTVkMTM0LCAweGYxZjFmOTA4LFxuMHg3MTcxZTI5MywgMHhkOGQ4YWI3MywgMHgzMTMxNjI1MywgMHgxNTE1MmEzZixcbjB4MDQwNDA4MGMsIDB4YzdjNzk1NTIsIDB4MjMyMzQ2NjUsIDB4YzNjMzlkNWUsXG4weDE4MTgzMDI4LCAweDk2OTYzN2ExLCAweDA1MDUwYTBmLCAweDlhOWEyZmI1LFxuMHgwNzA3MGUwOSwgMHgxMjEyMjQzNiwgMHg4MDgwMWI5YiwgMHhlMmUyZGYzZCxcbjB4ZWJlYmNkMjYsIDB4MjcyNzRlNjksIDB4YjJiMjdmY2QsIDB4NzU3NWVhOWYsXG4weDA5MDkxMjFiLCAweDgzODMxZDllLCAweDJjMmM1ODc0LCAweDFhMWEzNDJlLFxuMHgxYjFiMzYyZCwgMHg2ZTZlZGNiMiwgMHg1YTVhYjRlZSwgMHhhMGEwNWJmYixcbjB4NTI1MmE0ZjYsIDB4M2IzYjc2NGQsIDB4ZDZkNmI3NjEsIDB4YjNiMzdkY2UsXG4weDI5Mjk1MjdiLCAweGUzZTNkZDNlLCAweDJmMmY1ZTcxLCAweDg0ODQxMzk3LFxuMHg1MzUzYTZmNSwgMHhkMWQxYjk2OCwgMHgwMDAwMDAwMCwgMHhlZGVkYzEyYyxcbjB4MjAyMDQwNjAsIDB4ZmNmY2UzMWYsIDB4YjFiMTc5YzgsIDB4NWI1YmI2ZWQsXG4weDZhNmFkNGJlLCAweGNiY2I4ZDQ2LCAweGJlYmU2N2Q5LCAweDM5Mzk3MjRiLFxuMHg0YTRhOTRkZSwgMHg0YzRjOThkNCwgMHg1ODU4YjBlOCwgMHhjZmNmODU0YSxcbjB4ZDBkMGJiNmIsIDB4ZWZlZmM1MmEsIDB4YWFhYTRmZTUsIDB4ZmJmYmVkMTYsXG4weDQzNDM4NmM1LCAweDRkNGQ5YWQ3LCAweDMzMzM2NjU1LCAweDg1ODUxMTk0LFxuMHg0NTQ1OGFjZiwgMHhmOWY5ZTkxMCwgMHgwMjAyMDQwNiwgMHg3ZjdmZmU4MSxcbjB4NTA1MGEwZjAsIDB4M2MzYzc4NDQsIDB4OWY5ZjI1YmEsIDB4YThhODRiZTMsXG4weDUxNTFhMmYzLCAweGEzYTM1ZGZlLCAweDQwNDA4MGMwLCAweDhmOGYwNThhLFxuMHg5MjkyM2ZhZCwgMHg5ZDlkMjFiYywgMHgzODM4NzA0OCwgMHhmNWY1ZjEwNCxcbjB4YmNiYzYzZGYsIDB4YjZiNjc3YzEsIDB4ZGFkYWFmNzUsIDB4MjEyMTQyNjMsXG4weDEwMTAyMDMwLCAweGZmZmZlNTFhLCAweGYzZjNmZDBlLCAweGQyZDJiZjZkLFxuMHhjZGNkODE0YywgMHgwYzBjMTgxNCwgMHgxMzEzMjYzNSwgMHhlY2VjYzMyZixcbjB4NWY1ZmJlZTEsIDB4OTc5NzM1YTIsIDB4NDQ0NDg4Y2MsIDB4MTcxNzJlMzksXG4weGM0YzQ5MzU3LCAweGE3YTc1NWYyLCAweDdlN2VmYzgyLCAweDNkM2Q3YTQ3LFxuMHg2NDY0YzhhYywgMHg1ZDVkYmFlNywgMHgxOTE5MzIyYiwgMHg3MzczZTY5NSxcbjB4NjA2MGMwYTAsIDB4ODE4MTE5OTgsIDB4NGY0ZjllZDEsIDB4ZGNkY2EzN2YsXG4weDIyMjI0NDY2LCAweDJhMmE1NDdlLCAweDkwOTAzYmFiLCAweDg4ODgwYjgzLFxuMHg0NjQ2OGNjYSwgMHhlZWVlYzcyOSwgMHhiOGI4NmJkMywgMHgxNDE0MjgzYyxcbjB4ZGVkZWE3NzksIDB4NWU1ZWJjZTIsIDB4MGIwYjE2MWQsIDB4ZGJkYmFkNzYsXG4weGUwZTBkYjNiLCAweDMyMzI2NDU2LCAweDNhM2E3NDRlLCAweDBhMGExNDFlLFxuMHg0OTQ5OTJkYiwgMHgwNjA2MGMwYSwgMHgyNDI0NDg2YywgMHg1YzVjYjhlNCxcbjB4YzJjMjlmNWQsIDB4ZDNkM2JkNmUsIDB4YWNhYzQzZWYsIDB4NjI2MmM0YTYsXG4weDkxOTEzOWE4LCAweDk1OTUzMWE0LCAweGU0ZTRkMzM3LCAweDc5NzlmMjhiLFxuMHhlN2U3ZDUzMiwgMHhjOGM4OGI0MywgMHgzNzM3NmU1OSwgMHg2ZDZkZGFiNyxcbjB4OGQ4ZDAxOGMsIDB4ZDVkNWIxNjQsIDB4NGU0ZTljZDIsIDB4YTlhOTQ5ZTAsXG4weDZjNmNkOGI0LCAweDU2NTZhY2ZhLCAweGY0ZjRmMzA3LCAweGVhZWFjZjI1LFxuMHg2NTY1Y2FhZiwgMHg3YTdhZjQ4ZSwgMHhhZWFlNDdlOSwgMHgwODA4MTAxOCxcbjB4YmFiYTZmZDUsIDB4Nzg3OGYwODgsIDB4MjUyNTRhNmYsIDB4MmUyZTVjNzIsXG4weDFjMWMzODI0LCAweGE2YTY1N2YxLCAweGI0YjQ3M2M3LCAweGM2YzY5NzUxLFxuMHhlOGU4Y2IyMywgMHhkZGRkYTE3YywgMHg3NDc0ZTg5YywgMHgxZjFmM2UyMSxcbjB4NGI0Yjk2ZGQsIDB4YmRiZDYxZGMsIDB4OGI4YjBkODYsIDB4OGE4YTBmODUsXG4weDcwNzBlMDkwLCAweDNlM2U3YzQyLCAweGI1YjU3MWM0LCAweDY2NjZjY2FhLFxuMHg0ODQ4OTBkOCwgMHgwMzAzMDYwNSwgMHhmNmY2ZjcwMSwgMHgwZTBlMWMxMixcbjB4NjE2MWMyYTMsIDB4MzUzNTZhNWYsIDB4NTc1N2FlZjksIDB4YjliOTY5ZDAsXG4weDg2ODYxNzkxLCAweGMxYzE5OTU4LCAweDFkMWQzYTI3LCAweDllOWUyN2I5LFxuMHhlMWUxZDkzOCwgMHhmOGY4ZWIxMywgMHg5ODk4MmJiMywgMHgxMTExMjIzMyxcbjB4Njk2OWQyYmIsIDB4ZDlkOWE5NzAsIDB4OGU4ZTA3ODksIDB4OTQ5NDMzYTcsXG4weDliOWIyZGI2LCAweDFlMWUzYzIyLCAweDg3ODcxNTkyLCAweGU5ZTljOTIwLFxuMHhjZWNlODc0OSwgMHg1NTU1YWFmZiwgMHgyODI4NTA3OCwgMHhkZmRmYTU3YSxcbjB4OGM4YzAzOGYsIDB4YTFhMTU5ZjgsIDB4ODk4OTA5ODAsIDB4MGQwZDFhMTcsXG4weGJmYmY2NWRhLCAweGU2ZTZkNzMxLCAweDQyNDI4NGM2LCAweDY4NjhkMGI4LFxuMHg0MTQxODJjMywgMHg5OTk5MjliMCwgMHgyZDJkNWE3NywgMHgwZjBmMWUxMSxcbjB4YjBiMDdiY2IsIDB4NTQ1NGE4ZmMsIDB4YmJiYjZkZDYsIDB4MTYxNjJjM2EgXTtcblxudmFyIFQzID0gW1xuMHg2M2M2YTU2MywgMHg3Y2Y4ODQ3YywgMHg3N2VlOTk3NywgMHg3YmY2OGQ3YixcbjB4ZjJmZjBkZjIsIDB4NmJkNmJkNmIsIDB4NmZkZWIxNmYsIDB4YzU5MTU0YzUsXG4weDMwNjA1MDMwLCAweDAxMDIwMzAxLCAweDY3Y2VhOTY3LCAweDJiNTY3ZDJiLFxuMHhmZWU3MTlmZSwgMHhkN2I1NjJkNywgMHhhYjRkZTZhYiwgMHg3NmVjOWE3NixcbjB4Y2E4ZjQ1Y2EsIDB4ODIxZjlkODIsIDB4Yzk4OTQwYzksIDB4N2RmYTg3N2QsXG4weGZhZWYxNWZhLCAweDU5YjJlYjU5LCAweDQ3OGVjOTQ3LCAweGYwZmIwYmYwLFxuMHhhZDQxZWNhZCwgMHhkNGIzNjdkNCwgMHhhMjVmZmRhMiwgMHhhZjQ1ZWFhZixcbjB4OWMyM2JmOWMsIDB4YTQ1M2Y3YTQsIDB4NzJlNDk2NzIsIDB4YzA5YjViYzAsXG4weGI3NzVjMmI3LCAweGZkZTExY2ZkLCAweDkzM2RhZTkzLCAweDI2NGM2YTI2LFxuMHgzNjZjNWEzNiwgMHgzZjdlNDEzZiwgMHhmN2Y1MDJmNywgMHhjYzgzNGZjYyxcbjB4MzQ2ODVjMzQsIDB4YTU1MWY0YTUsIDB4ZTVkMTM0ZTUsIDB4ZjFmOTA4ZjEsXG4weDcxZTI5MzcxLCAweGQ4YWI3M2Q4LCAweDMxNjI1MzMxLCAweDE1MmEzZjE1LFxuMHgwNDA4MGMwNCwgMHhjNzk1NTJjNywgMHgyMzQ2NjUyMywgMHhjMzlkNWVjMyxcbjB4MTgzMDI4MTgsIDB4OTYzN2ExOTYsIDB4MDUwYTBmMDUsIDB4OWEyZmI1OWEsXG4weDA3MGUwOTA3LCAweDEyMjQzNjEyLCAweDgwMWI5YjgwLCAweGUyZGYzZGUyLFxuMHhlYmNkMjZlYiwgMHgyNzRlNjkyNywgMHhiMjdmY2RiMiwgMHg3NWVhOWY3NSxcbjB4MDkxMjFiMDksIDB4ODMxZDllODMsIDB4MmM1ODc0MmMsIDB4MWEzNDJlMWEsXG4weDFiMzYyZDFiLCAweDZlZGNiMjZlLCAweDVhYjRlZTVhLCAweGEwNWJmYmEwLFxuMHg1MmE0ZjY1MiwgMHgzYjc2NGQzYiwgMHhkNmI3NjFkNiwgMHhiMzdkY2ViMyxcbjB4Mjk1MjdiMjksIDB4ZTNkZDNlZTMsIDB4MmY1ZTcxMmYsIDB4ODQxMzk3ODQsXG4weDUzYTZmNTUzLCAweGQxYjk2OGQxLCAweDAwMDAwMDAwLCAweGVkYzEyY2VkLFxuMHgyMDQwNjAyMCwgMHhmY2UzMWZmYywgMHhiMTc5YzhiMSwgMHg1YmI2ZWQ1YixcbjB4NmFkNGJlNmEsIDB4Y2I4ZDQ2Y2IsIDB4YmU2N2Q5YmUsIDB4Mzk3MjRiMzksXG4weDRhOTRkZTRhLCAweDRjOThkNDRjLCAweDU4YjBlODU4LCAweGNmODU0YWNmLFxuMHhkMGJiNmJkMCwgMHhlZmM1MmFlZiwgMHhhYTRmZTVhYSwgMHhmYmVkMTZmYixcbjB4NDM4NmM1NDMsIDB4NGQ5YWQ3NGQsIDB4MzM2NjU1MzMsIDB4ODUxMTk0ODUsXG4weDQ1OGFjZjQ1LCAweGY5ZTkxMGY5LCAweDAyMDQwNjAyLCAweDdmZmU4MTdmLFxuMHg1MGEwZjA1MCwgMHgzYzc4NDQzYywgMHg5ZjI1YmE5ZiwgMHhhODRiZTNhOCxcbjB4NTFhMmYzNTEsIDB4YTM1ZGZlYTMsIDB4NDA4MGMwNDAsIDB4OGYwNThhOGYsXG4weDkyM2ZhZDkyLCAweDlkMjFiYzlkLCAweDM4NzA0ODM4LCAweGY1ZjEwNGY1LFxuMHhiYzYzZGZiYywgMHhiNjc3YzFiNiwgMHhkYWFmNzVkYSwgMHgyMTQyNjMyMSxcbjB4MTAyMDMwMTAsIDB4ZmZlNTFhZmYsIDB4ZjNmZDBlZjMsIDB4ZDJiZjZkZDIsXG4weGNkODE0Y2NkLCAweDBjMTgxNDBjLCAweDEzMjYzNTEzLCAweGVjYzMyZmVjLFxuMHg1ZmJlZTE1ZiwgMHg5NzM1YTI5NywgMHg0NDg4Y2M0NCwgMHgxNzJlMzkxNyxcbjB4YzQ5MzU3YzQsIDB4YTc1NWYyYTcsIDB4N2VmYzgyN2UsIDB4M2Q3YTQ3M2QsXG4weDY0YzhhYzY0LCAweDVkYmFlNzVkLCAweDE5MzIyYjE5LCAweDczZTY5NTczLFxuMHg2MGMwYTA2MCwgMHg4MTE5OTg4MSwgMHg0ZjllZDE0ZiwgMHhkY2EzN2ZkYyxcbjB4MjI0NDY2MjIsIDB4MmE1NDdlMmEsIDB4OTAzYmFiOTAsIDB4ODgwYjgzODgsXG4weDQ2OGNjYTQ2LCAweGVlYzcyOWVlLCAweGI4NmJkM2I4LCAweDE0MjgzYzE0LFxuMHhkZWE3NzlkZSwgMHg1ZWJjZTI1ZSwgMHgwYjE2MWQwYiwgMHhkYmFkNzZkYixcbjB4ZTBkYjNiZTAsIDB4MzI2NDU2MzIsIDB4M2E3NDRlM2EsIDB4MGExNDFlMGEsXG4weDQ5OTJkYjQ5LCAweDA2MGMwYTA2LCAweDI0NDg2YzI0LCAweDVjYjhlNDVjLFxuMHhjMjlmNWRjMiwgMHhkM2JkNmVkMywgMHhhYzQzZWZhYywgMHg2MmM0YTY2MixcbjB4OTEzOWE4OTEsIDB4OTUzMWE0OTUsIDB4ZTRkMzM3ZTQsIDB4NzlmMjhiNzksXG4weGU3ZDUzMmU3LCAweGM4OGI0M2M4LCAweDM3NmU1OTM3LCAweDZkZGFiNzZkLFxuMHg4ZDAxOGM4ZCwgMHhkNWIxNjRkNSwgMHg0ZTljZDI0ZSwgMHhhOTQ5ZTBhOSxcbjB4NmNkOGI0NmMsIDB4NTZhY2ZhNTYsIDB4ZjRmMzA3ZjQsIDB4ZWFjZjI1ZWEsXG4weDY1Y2FhZjY1LCAweDdhZjQ4ZTdhLCAweGFlNDdlOWFlLCAweDA4MTAxODA4LFxuMHhiYTZmZDViYSwgMHg3OGYwODg3OCwgMHgyNTRhNmYyNSwgMHgyZTVjNzIyZSxcbjB4MWMzODI0MWMsIDB4YTY1N2YxYTYsIDB4YjQ3M2M3YjQsIDB4YzY5NzUxYzYsXG4weGU4Y2IyM2U4LCAweGRkYTE3Y2RkLCAweDc0ZTg5Yzc0LCAweDFmM2UyMTFmLFxuMHg0Yjk2ZGQ0YiwgMHhiZDYxZGNiZCwgMHg4YjBkODY4YiwgMHg4YTBmODU4YSxcbjB4NzBlMDkwNzAsIDB4M2U3YzQyM2UsIDB4YjU3MWM0YjUsIDB4NjZjY2FhNjYsXG4weDQ4OTBkODQ4LCAweDAzMDYwNTAzLCAweGY2ZjcwMWY2LCAweDBlMWMxMjBlLFxuMHg2MWMyYTM2MSwgMHgzNTZhNWYzNSwgMHg1N2FlZjk1NywgMHhiOTY5ZDBiOSxcbjB4ODYxNzkxODYsIDB4YzE5OTU4YzEsIDB4MWQzYTI3MWQsIDB4OWUyN2I5OWUsXG4weGUxZDkzOGUxLCAweGY4ZWIxM2Y4LCAweDk4MmJiMzk4LCAweDExMjIzMzExLFxuMHg2OWQyYmI2OSwgMHhkOWE5NzBkOSwgMHg4ZTA3ODk4ZSwgMHg5NDMzYTc5NCxcbjB4OWIyZGI2OWIsIDB4MWUzYzIyMWUsIDB4ODcxNTkyODcsIDB4ZTljOTIwZTksXG4weGNlODc0OWNlLCAweDU1YWFmZjU1LCAweDI4NTA3ODI4LCAweGRmYTU3YWRmLFxuMHg4YzAzOGY4YywgMHhhMTU5ZjhhMSwgMHg4OTA5ODA4OSwgMHgwZDFhMTcwZCxcbjB4YmY2NWRhYmYsIDB4ZTZkNzMxZTYsIDB4NDI4NGM2NDIsIDB4NjhkMGI4NjgsXG4weDQxODJjMzQxLCAweDk5MjliMDk5LCAweDJkNWE3NzJkLCAweDBmMWUxMTBmLFxuMHhiMDdiY2JiMCwgMHg1NGE4ZmM1NCwgMHhiYjZkZDZiYiwgMHgxNjJjM2ExNiBdO1xuXG52YXIgVDQgPSBbXG4weGM2YTU2MzYzLCAweGY4ODQ3YzdjLCAweGVlOTk3Nzc3LCAweGY2OGQ3YjdiLFxuMHhmZjBkZjJmMiwgMHhkNmJkNmI2YiwgMHhkZWIxNmY2ZiwgMHg5MTU0YzVjNSxcbjB4NjA1MDMwMzAsIDB4MDIwMzAxMDEsIDB4Y2VhOTY3NjcsIDB4NTY3ZDJiMmIsXG4weGU3MTlmZWZlLCAweGI1NjJkN2Q3LCAweDRkZTZhYmFiLCAweGVjOWE3Njc2LFxuMHg4ZjQ1Y2FjYSwgMHgxZjlkODI4MiwgMHg4OTQwYzljOSwgMHhmYTg3N2Q3ZCxcbjB4ZWYxNWZhZmEsIDB4YjJlYjU5NTksIDB4OGVjOTQ3NDcsIDB4ZmIwYmYwZjAsXG4weDQxZWNhZGFkLCAweGIzNjdkNGQ0LCAweDVmZmRhMmEyLCAweDQ1ZWFhZmFmLFxuMHgyM2JmOWM5YywgMHg1M2Y3YTRhNCwgMHhlNDk2NzI3MiwgMHg5YjViYzBjMCxcbjB4NzVjMmI3YjcsIDB4ZTExY2ZkZmQsIDB4M2RhZTkzOTMsIDB4NGM2YTI2MjYsXG4weDZjNWEzNjM2LCAweDdlNDEzZjNmLCAweGY1MDJmN2Y3LCAweDgzNGZjY2NjLFxuMHg2ODVjMzQzNCwgMHg1MWY0YTVhNSwgMHhkMTM0ZTVlNSwgMHhmOTA4ZjFmMSxcbjB4ZTI5MzcxNzEsIDB4YWI3M2Q4ZDgsIDB4NjI1MzMxMzEsIDB4MmEzZjE1MTUsXG4weDA4MGMwNDA0LCAweDk1NTJjN2M3LCAweDQ2NjUyMzIzLCAweDlkNWVjM2MzLFxuMHgzMDI4MTgxOCwgMHgzN2ExOTY5NiwgMHgwYTBmMDUwNSwgMHgyZmI1OWE5YSxcbjB4MGUwOTA3MDcsIDB4MjQzNjEyMTIsIDB4MWI5YjgwODAsIDB4ZGYzZGUyZTIsXG4weGNkMjZlYmViLCAweDRlNjkyNzI3LCAweDdmY2RiMmIyLCAweGVhOWY3NTc1LFxuMHgxMjFiMDkwOSwgMHgxZDllODM4MywgMHg1ODc0MmMyYywgMHgzNDJlMWExYSxcbjB4MzYyZDFiMWIsIDB4ZGNiMjZlNmUsIDB4YjRlZTVhNWEsIDB4NWJmYmEwYTAsXG4weGE0ZjY1MjUyLCAweDc2NGQzYjNiLCAweGI3NjFkNmQ2LCAweDdkY2ViM2IzLFxuMHg1MjdiMjkyOSwgMHhkZDNlZTNlMywgMHg1ZTcxMmYyZiwgMHgxMzk3ODQ4NCxcbjB4YTZmNTUzNTMsIDB4Yjk2OGQxZDEsIDB4MDAwMDAwMDAsIDB4YzEyY2VkZWQsXG4weDQwNjAyMDIwLCAweGUzMWZmY2ZjLCAweDc5YzhiMWIxLCAweGI2ZWQ1YjViLFxuMHhkNGJlNmE2YSwgMHg4ZDQ2Y2JjYiwgMHg2N2Q5YmViZSwgMHg3MjRiMzkzOSxcbjB4OTRkZTRhNGEsIDB4OThkNDRjNGMsIDB4YjBlODU4NTgsIDB4ODU0YWNmY2YsXG4weGJiNmJkMGQwLCAweGM1MmFlZmVmLCAweDRmZTVhYWFhLCAweGVkMTZmYmZiLFxuMHg4NmM1NDM0MywgMHg5YWQ3NGQ0ZCwgMHg2NjU1MzMzMywgMHgxMTk0ODU4NSxcbjB4OGFjZjQ1NDUsIDB4ZTkxMGY5ZjksIDB4MDQwNjAyMDIsIDB4ZmU4MTdmN2YsXG4weGEwZjA1MDUwLCAweDc4NDQzYzNjLCAweDI1YmE5ZjlmLCAweDRiZTNhOGE4LFxuMHhhMmYzNTE1MSwgMHg1ZGZlYTNhMywgMHg4MGMwNDA0MCwgMHgwNThhOGY4ZixcbjB4M2ZhZDkyOTIsIDB4MjFiYzlkOWQsIDB4NzA0ODM4MzgsIDB4ZjEwNGY1ZjUsXG4weDYzZGZiY2JjLCAweDc3YzFiNmI2LCAweGFmNzVkYWRhLCAweDQyNjMyMTIxLFxuMHgyMDMwMTAxMCwgMHhlNTFhZmZmZiwgMHhmZDBlZjNmMywgMHhiZjZkZDJkMixcbjB4ODE0Y2NkY2QsIDB4MTgxNDBjMGMsIDB4MjYzNTEzMTMsIDB4YzMyZmVjZWMsXG4weGJlZTE1ZjVmLCAweDM1YTI5Nzk3LCAweDg4Y2M0NDQ0LCAweDJlMzkxNzE3LFxuMHg5MzU3YzRjNCwgMHg1NWYyYTdhNywgMHhmYzgyN2U3ZSwgMHg3YTQ3M2QzZCxcbjB4YzhhYzY0NjQsIDB4YmFlNzVkNWQsIDB4MzIyYjE5MTksIDB4ZTY5NTczNzMsXG4weGMwYTA2MDYwLCAweDE5OTg4MTgxLCAweDllZDE0ZjRmLCAweGEzN2ZkY2RjLFxuMHg0NDY2MjIyMiwgMHg1NDdlMmEyYSwgMHgzYmFiOTA5MCwgMHgwYjgzODg4OCxcbjB4OGNjYTQ2NDYsIDB4YzcyOWVlZWUsIDB4NmJkM2I4YjgsIDB4MjgzYzE0MTQsXG4weGE3NzlkZWRlLCAweGJjZTI1ZTVlLCAweDE2MWQwYjBiLCAweGFkNzZkYmRiLFxuMHhkYjNiZTBlMCwgMHg2NDU2MzIzMiwgMHg3NDRlM2EzYSwgMHgxNDFlMGEwYSxcbjB4OTJkYjQ5NDksIDB4MGMwYTA2MDYsIDB4NDg2YzI0MjQsIDB4YjhlNDVjNWMsXG4weDlmNWRjMmMyLCAweGJkNmVkM2QzLCAweDQzZWZhY2FjLCAweGM0YTY2MjYyLFxuMHgzOWE4OTE5MSwgMHgzMWE0OTU5NSwgMHhkMzM3ZTRlNCwgMHhmMjhiNzk3OSxcbjB4ZDUzMmU3ZTcsIDB4OGI0M2M4YzgsIDB4NmU1OTM3MzcsIDB4ZGFiNzZkNmQsXG4weDAxOGM4ZDhkLCAweGIxNjRkNWQ1LCAweDljZDI0ZTRlLCAweDQ5ZTBhOWE5LFxuMHhkOGI0NmM2YywgMHhhY2ZhNTY1NiwgMHhmMzA3ZjRmNCwgMHhjZjI1ZWFlYSxcbjB4Y2FhZjY1NjUsIDB4ZjQ4ZTdhN2EsIDB4NDdlOWFlYWUsIDB4MTAxODA4MDgsXG4weDZmZDViYWJhLCAweGYwODg3ODc4LCAweDRhNmYyNTI1LCAweDVjNzIyZTJlLFxuMHgzODI0MWMxYywgMHg1N2YxYTZhNiwgMHg3M2M3YjRiNCwgMHg5NzUxYzZjNixcbjB4Y2IyM2U4ZTgsIDB4YTE3Y2RkZGQsIDB4ZTg5Yzc0NzQsIDB4M2UyMTFmMWYsXG4weDk2ZGQ0YjRiLCAweDYxZGNiZGJkLCAweDBkODY4YjhiLCAweDBmODU4YThhLFxuMHhlMDkwNzA3MCwgMHg3YzQyM2UzZSwgMHg3MWM0YjViNSwgMHhjY2FhNjY2NixcbjB4OTBkODQ4NDgsIDB4MDYwNTAzMDMsIDB4ZjcwMWY2ZjYsIDB4MWMxMjBlMGUsXG4weGMyYTM2MTYxLCAweDZhNWYzNTM1LCAweGFlZjk1NzU3LCAweDY5ZDBiOWI5LFxuMHgxNzkxODY4NiwgMHg5OTU4YzFjMSwgMHgzYTI3MWQxZCwgMHgyN2I5OWU5ZSxcbjB4ZDkzOGUxZTEsIDB4ZWIxM2Y4ZjgsIDB4MmJiMzk4OTgsIDB4MjIzMzExMTEsXG4weGQyYmI2OTY5LCAweGE5NzBkOWQ5LCAweDA3ODk4ZThlLCAweDMzYTc5NDk0LFxuMHgyZGI2OWI5YiwgMHgzYzIyMWUxZSwgMHgxNTkyODc4NywgMHhjOTIwZTllOSxcbjB4ODc0OWNlY2UsIDB4YWFmZjU1NTUsIDB4NTA3ODI4MjgsIDB4YTU3YWRmZGYsXG4weDAzOGY4YzhjLCAweDU5ZjhhMWExLCAweDA5ODA4OTg5LCAweDFhMTcwZDBkLFxuMHg2NWRhYmZiZiwgMHhkNzMxZTZlNiwgMHg4NGM2NDI0MiwgMHhkMGI4Njg2OCxcbjB4ODJjMzQxNDEsIDB4MjliMDk5OTksIDB4NWE3NzJkMmQsIDB4MWUxMTBmMGYsXG4weDdiY2JiMGIwLCAweGE4ZmM1NDU0LCAweDZkZDZiYmJiLCAweDJjM2ExNjE2IF07XG5cbmZ1bmN0aW9uIEIwKHgpIHsgcmV0dXJuICh4JjI1NSk7IH1cbmZ1bmN0aW9uIEIxKHgpIHsgcmV0dXJuICgoeD4+OCkmMjU1KTsgfVxuZnVuY3Rpb24gQjIoeCkgeyByZXR1cm4gKCh4Pj4xNikmMjU1KTsgfVxuZnVuY3Rpb24gQjMoeCkgeyByZXR1cm4gKCh4Pj4yNCkmMjU1KTsgfVxuXG5mdW5jdGlvbiBGMSh4MCwgeDEsIHgyLCB4MylcbntcbiAgcmV0dXJuIEIxKFQxW3gwJjI1NV0pIHwgKEIxKFQxWyh4MT4+OCkmMjU1XSk8PDgpXG4gICAgICB8IChCMShUMVsoeDI+PjE2KSYyNTVdKTw8MTYpIHwgKEIxKFQxW3gzPj4+MjRdKTw8MjQpO1xufVxuXG5mdW5jdGlvbiBwYWNrQnl0ZXMob2N0ZXRzKVxue1xuICB2YXIgaSwgajtcbiAgdmFyIGxlbj1vY3RldHMubGVuZ3RoO1xuICB2YXIgYj1uZXcgQXJyYXkobGVuLzQpO1xuXG4gIGlmICghb2N0ZXRzIHx8IGxlbiAlIDQpIHJldHVybjtcblxuICBmb3IgKGk9MCwgaj0wOyBqPGxlbjsgais9IDQpXG4gICAgIGJbaSsrXSA9IG9jdGV0c1tqXSB8IChvY3RldHNbaisxXTw8OCkgfCAob2N0ZXRzW2orMl08PDE2KSB8IChvY3RldHNbaiszXTw8MjQpO1xuXG4gIHJldHVybiBiOyAgXG59XG5cbmZ1bmN0aW9uIHVucGFja0J5dGVzKHBhY2tlZClcbntcbiAgdmFyIGo7XG4gIHZhciBpPTAsIGwgPSBwYWNrZWQubGVuZ3RoO1xuICB2YXIgciA9IG5ldyBBcnJheShsKjQpO1xuXG4gIGZvciAoaj0wOyBqPGw7IGorKylcbiAge1xuICAgIHJbaSsrXSA9IEIwKHBhY2tlZFtqXSk7XG4gICAgcltpKytdID0gQjEocGFja2VkW2pdKTtcbiAgICByW2krK10gPSBCMihwYWNrZWRbal0pO1xuICAgIHJbaSsrXSA9IEIzKHBhY2tlZFtqXSk7XG4gIH1cbiAgcmV0dXJuIHI7XG59XG5cbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuXG52YXIgbWF4a2M9ODtcbnZhciBtYXhyaz0xNDtcblxuZnVuY3Rpb24ga2V5RXhwYW5zaW9uKGtleSlcbntcbiAgdmFyIGtjLCBpLCBqLCByLCB0O1xuICB2YXIgcm91bmRzO1xuICB2YXIga2V5U2NoZWQ9bmV3IEFycmF5KG1heHJrKzEpO1xuICB2YXIga2V5bGVuPWtleS5sZW5ndGg7XG4gIHZhciBrPW5ldyBBcnJheShtYXhrYyk7XG4gIHZhciB0az1uZXcgQXJyYXkobWF4a2MpO1xuICB2YXIgcmNvbnBvaW50ZXI9MDtcblxuICBpZihrZXlsZW49PTE2KVxuICB7XG4gICByb3VuZHM9MTA7XG4gICBrYz00O1xuICB9XG4gIGVsc2UgaWYoa2V5bGVuPT0yNClcbiAge1xuICAgcm91bmRzPTEyO1xuICAga2M9NjtcbiAgfVxuICBlbHNlIGlmKGtleWxlbj09MzIpXG4gIHtcbiAgIHJvdW5kcz0xNDtcbiAgIGtjPTg7XG4gIH1cbiAgZWxzZVxuICB7XG5cdHV0aWwucHJpbnRfZXJyb3IoJ2Flcy5qczogSW52YWxpZCBrZXktbGVuZ3RoIGZvciBBRVMga2V5Oicra2V5bGVuKTtcbiAgIHJldHVybjtcbiAgfVxuXG4gIGZvcihpPTA7IGk8bWF4cmsrMTsgaSsrKSBrZXlTY2hlZFtpXT1uZXcgQXJyYXkoNCk7XG5cbiAgZm9yKGk9MCxqPTA7IGo8a2V5bGVuOyBqKyssaSs9NClcbiAgICBrW2pdID0ga2V5LmNoYXJDb2RlQXQoaSkgfCAoa2V5LmNoYXJDb2RlQXQoaSsxKTw8OClcbiAgICAgICAgICAgICAgICAgICAgIHwgKGtleS5jaGFyQ29kZUF0KGkrMik8PDE2KSB8IChrZXkuY2hhckNvZGVBdChpKzMpPDwyNCk7XG5cbiAgZm9yKGo9a2MtMTsgaj49MDsgai0tKSB0a1tqXSA9IGtbal07XG5cbiAgcj0wO1xuICB0PTA7XG4gIGZvcihqPTA7IChqPGtjKSYmKHI8cm91bmRzKzEpOyApXG4gIHtcbiAgICBmb3IoOyAoajxrYykmJih0PDQpOyBqKyssdCsrKVxuICAgIHtcbiAgICAgIGtleVNjaGVkW3JdW3RdPXRrW2pdO1xuICAgIH1cbiAgICBpZih0PT00KVxuICAgIHtcbiAgICAgIHIrKztcbiAgICAgIHQ9MDtcbiAgICB9XG4gIH1cblxuICB3aGlsZShyPHJvdW5kcysxKVxuICB7XG4gICAgdmFyIHRlbXAgPSB0a1trYy0xXTtcblxuICAgIHRrWzBdIF49IFNbQjEodGVtcCldIHwgKFNbQjIodGVtcCldPDw4KSB8IChTW0IzKHRlbXApXTw8MTYpIHwgKFNbQjAodGVtcCldPDwyNCk7XG4gICAgdGtbMF0gXj0gUmNvbltyY29ucG9pbnRlcisrXTtcblxuICAgIGlmKGtjICE9IDgpXG4gICAge1xuICAgICAgZm9yKGo9MTsgajxrYzsgaisrKSB0a1tqXSBePSB0a1tqLTFdO1xuICAgIH1cbiAgICBlbHNlXG4gICAge1xuICAgICAgZm9yKGo9MTsgajxrYy8yOyBqKyspIHRrW2pdIF49IHRrW2otMV07XG4gXG4gICAgICB0ZW1wID0gdGtba2MvMi0xXTtcbiAgICAgIHRrW2tjLzJdIF49IFNbQjAodGVtcCldIHwgKFNbQjEodGVtcCldPDw4KSB8IChTW0IyKHRlbXApXTw8MTYpIHwgKFNbQjModGVtcCldPDwyNCk7XG5cbiAgICAgIGZvcihqPWtjLzIrMTsgajxrYzsgaisrKSB0a1tqXSBePSB0a1tqLTFdO1xuICAgIH1cblxuICAgIGZvcihqPTA7IChqPGtjKSYmKHI8cm91bmRzKzEpOyApXG4gICAge1xuICAgICAgZm9yKDsgKGo8a2MpJiYodDw0KTsgaisrLHQrKylcbiAgICAgIHtcbiAgICAgICAga2V5U2NoZWRbcl1bdF09dGtbal07XG4gICAgICB9XG4gICAgICBpZih0PT00KVxuICAgICAge1xuICAgICAgICByKys7XG4gICAgICAgIHQ9MDtcbiAgICAgIH1cbiAgICB9XG4gIH1cbiAgdGhpcy5yb3VuZHMgPSByb3VuZHM7XG4gIHRoaXMucmsgPSBrZXlTY2hlZDtcbiAgcmV0dXJuIHRoaXM7XG59XG5cbmZ1bmN0aW9uIEFFU2VuY3J5cHQoYmxvY2ssIGN0eClcbntcbiAgdmFyIHI7XG4gIHZhciB0MCx0MSx0Mix0MztcblxuICB2YXIgYiA9IHBhY2tCeXRlcyhibG9jayk7XG4gIHZhciByb3VuZHMgPSBjdHgucm91bmRzO1xuICB2YXIgYjAgPSBiWzBdO1xuICB2YXIgYjEgPSBiWzFdO1xuICB2YXIgYjIgPSBiWzJdO1xuICB2YXIgYjMgPSBiWzNdO1xuXG4gIGZvcihyPTA7IHI8cm91bmRzLTE7IHIrKylcbiAge1xuICAgIHQwID0gYjAgXiBjdHgucmtbcl1bMF07XG4gICAgdDEgPSBiMSBeIGN0eC5ya1tyXVsxXTtcbiAgICB0MiA9IGIyIF4gY3R4LnJrW3JdWzJdO1xuICAgIHQzID0gYjMgXiBjdHgucmtbcl1bM107XG5cbiAgICBiMCA9IFQxW3QwJjI1NV0gXiBUMlsodDE+PjgpJjI1NV0gXiBUM1sodDI+PjE2KSYyNTVdIF4gVDRbdDM+Pj4yNF07XG4gICAgYjEgPSBUMVt0MSYyNTVdIF4gVDJbKHQyPj44KSYyNTVdIF4gVDNbKHQzPj4xNikmMjU1XSBeIFQ0W3QwPj4+MjRdO1xuICAgIGIyID0gVDFbdDImMjU1XSBeIFQyWyh0Mz4+OCkmMjU1XSBeIFQzWyh0MD4+MTYpJjI1NV0gXiBUNFt0MT4+PjI0XTtcbiAgICBiMyA9IFQxW3QzJjI1NV0gXiBUMlsodDA+PjgpJjI1NV0gXiBUM1sodDE+PjE2KSYyNTVdIF4gVDRbdDI+Pj4yNF07XG4gIH1cblxuICAvLyBsYXN0IHJvdW5kIGlzIHNwZWNpYWxcbiAgciA9IHJvdW5kcy0xO1xuXG4gIHQwID0gYjAgXiBjdHgucmtbcl1bMF07XG4gIHQxID0gYjEgXiBjdHgucmtbcl1bMV07XG4gIHQyID0gYjIgXiBjdHgucmtbcl1bMl07XG4gIHQzID0gYjMgXiBjdHgucmtbcl1bM107XG5cbiAgYlswXSA9IEYxKHQwLCB0MSwgdDIsIHQzKSBeIGN0eC5ya1tyb3VuZHNdWzBdO1xuICBiWzFdID0gRjEodDEsIHQyLCB0MywgdDApIF4gY3R4LnJrW3JvdW5kc11bMV07XG4gIGJbMl0gPSBGMSh0MiwgdDMsIHQwLCB0MSkgXiBjdHgucmtbcm91bmRzXVsyXTtcbiAgYlszXSA9IEYxKHQzLCB0MCwgdDEsIHQyKSBeIGN0eC5ya1tyb3VuZHNdWzNdO1xuXG4gIHJldHVybiB1bnBhY2tCeXRlcyhiKTtcbn1cblxubW9kdWxlLmV4cG9ydHMgPSB7XG5cdGVuY3J5cHQ6IEFFU2VuY3J5cHQsXG5cdGtleUV4cGFuc2lvbjoga2V5RXhwYW5zaW9uXG59XG4iLCIvL1BhdWwgVGVybywgSnVseSAyMDAxXG4vL2h0dHA6Ly93d3cudGVyby5jby51ay9kZXMvXG4vL1xuLy9PcHRpbWlzZWQgZm9yIHBlcmZvcm1hbmNlIHdpdGggbGFyZ2UgYmxvY2tzIGJ5IE1pY2hhZWwgSGF5d29ydGgsIE5vdmVtYmVyIDIwMDFcbi8vaHR0cDovL3d3dy5uZXRkZWFsaW5nLmNvbVxuLy9cbi8vIE1vZGlmaWVkIGJ5IFJlY3VyaXR5IExhYnMgR21iSFxuXG4vL1RISVMgU09GVFdBUkUgSVMgUFJPVklERUQgXCJBUyBJU1wiIEFORFxuLy9BTlkgRVhQUkVTUyBPUiBJTVBMSUVEIFdBUlJBTlRJRVMsIElOQ0xVRElORywgQlVUIE5PVCBMSU1JVEVEIFRPLCBUSEVcbi8vSU1QTElFRCBXQVJSQU5USUVTIE9GIE1FUkNIQU5UQUJJTElUWSBBTkQgRklUTkVTUyBGT1IgQSBQQVJUSUNVTEFSIFBVUlBPU0Vcbi8vQVJFIERJU0NMQUlNRUQuICBJTiBOTyBFVkVOVCBTSEFMTCBUSEUgQVVUSE9SIE9SIENPTlRSSUJVVE9SUyBCRSBMSUFCTEVcbi8vRk9SIEFOWSBESVJFQ1QsIElORElSRUNULCBJTkNJREVOVEFMLCBTUEVDSUFMLCBFWEVNUExBUlksIE9SIENPTlNFUVVFTlRJQUxcbi8vREFNQUdFUyAoSU5DTFVESU5HLCBCVVQgTk9UIExJTUlURUQgVE8sIFBST0NVUkVNRU5UIE9GIFNVQlNUSVRVVEUgR09PRFNcbi8vT1IgU0VSVklDRVM7IExPU1MgT0YgVVNFLCBEQVRBLCBPUiBQUk9GSVRTOyBPUiBCVVNJTkVTUyBJTlRFUlJVUFRJT04pXG4vL0hPV0VWRVIgQ0FVU0VEIEFORCBPTiBBTlkgVEhFT1JZIE9GIExJQUJJTElUWSwgV0hFVEhFUiBJTiBDT05UUkFDVCwgU1RSSUNUXG4vL0xJQUJJTElUWSwgT1IgVE9SVCAoSU5DTFVESU5HIE5FR0xJR0VOQ0UgT1IgT1RIRVJXSVNFKSBBUklTSU5HIElOIEFOWSBXQVlcbi8vT1VUIE9GIFRIRSBVU0UgT0YgVEhJUyBTT0ZUV0FSRSwgRVZFTiBJRiBBRFZJU0VEIE9GIFRIRSBQT1NTSUJJTElUWSBPRlxuLy9TVUNIIERBTUFHRS5cblxuLy9kZXNcbi8vdGhpcyB0YWtlcyB0aGUga2V5LCB0aGUgbWVzc2FnZSwgYW5kIHdoZXRoZXIgdG8gZW5jcnlwdCBvciBkZWNyeXB0XG5cbnZhciB1dGlsID0gcmVxdWlyZSgnLi4vLi4vdXRpbCcpO1xuXG4vLyBhZGRlZCBieSBSZWN1cml0eSBMYWJzXG5mdW5jdGlvbiBkZXNlZGUoYmxvY2ssa2V5KSB7XG5cdHZhciBrZXkxID0ga2V5LnN1YnN0cmluZygwLDgpO1xuXHR2YXIga2V5MiA9IGtleS5zdWJzdHJpbmcoOCwxNik7XG5cdHZhciBrZXkzID0ga2V5LnN1YnN0cmluZygxNiwyNCk7XG5cdHJldHVybiB1dGlsLnN0cjJiaW4oZGVzKGRlc19jcmVhdGVLZXlzKGtleTMpLGRlcyhkZXNfY3JlYXRlS2V5cyhrZXkyKSxkZXMoZGVzX2NyZWF0ZUtleXMoa2V5MSksdXRpbC5iaW4yc3RyKGJsb2NrKSwgdHJ1ZSwgMCxudWxsLG51bGwpLCBmYWxzZSwgMCxudWxsLG51bGwpLCB0cnVlLCAwLG51bGwsbnVsbCkpO1xufVxuXG5cbmZ1bmN0aW9uIGRlcyAoa2V5cywgbWVzc2FnZSwgZW5jcnlwdCwgbW9kZSwgaXYsIHBhZGRpbmcpIHtcbiAgLy9kZWNsYXJpbmcgdGhpcyBsb2NhbGx5IHNwZWVkcyB0aGluZ3MgdXAgYSBiaXRcbiAgdmFyIHNwZnVuY3Rpb24xID0gbmV3IEFycmF5ICgweDEwMTA0MDAsMCwweDEwMDAwLDB4MTAxMDQwNCwweDEwMTAwMDQsMHgxMDQwNCwweDQsMHgxMDAwMCwweDQwMCwweDEwMTA0MDAsMHgxMDEwNDA0LDB4NDAwLDB4MTAwMDQwNCwweDEwMTAwMDQsMHgxMDAwMDAwLDB4NCwweDQwNCwweDEwMDA0MDAsMHgxMDAwNDAwLDB4MTA0MDAsMHgxMDQwMCwweDEwMTAwMDAsMHgxMDEwMDAwLDB4MTAwMDQwNCwweDEwMDA0LDB4MTAwMDAwNCwweDEwMDAwMDQsMHgxMDAwNCwwLDB4NDA0LDB4MTA0MDQsMHgxMDAwMDAwLDB4MTAwMDAsMHgxMDEwNDA0LDB4NCwweDEwMTAwMDAsMHgxMDEwNDAwLDB4MTAwMDAwMCwweDEwMDAwMDAsMHg0MDAsMHgxMDEwMDA0LDB4MTAwMDAsMHgxMDQwMCwweDEwMDAwMDQsMHg0MDAsMHg0LDB4MTAwMDQwNCwweDEwNDA0LDB4MTAxMDQwNCwweDEwMDA0LDB4MTAxMDAwMCwweDEwMDA0MDQsMHgxMDAwMDA0LDB4NDA0LDB4MTA0MDQsMHgxMDEwNDAwLDB4NDA0LDB4MTAwMDQwMCwweDEwMDA0MDAsMCwweDEwMDA0LDB4MTA0MDAsMCwweDEwMTAwMDQpO1xuICB2YXIgc3BmdW5jdGlvbjIgPSBuZXcgQXJyYXkgKC0weDdmZWY3ZmUwLC0weDdmZmY4MDAwLDB4ODAwMCwweDEwODAyMCwweDEwMDAwMCwweDIwLC0weDdmZWZmZmUwLC0weDdmZmY3ZmUwLC0weDdmZmZmZmUwLC0weDdmZWY3ZmUwLC0weDdmZWY4MDAwLC0weDgwMDAwMDAwLC0weDdmZmY4MDAwLDB4MTAwMDAwLDB4MjAsLTB4N2ZlZmZmZTAsMHgxMDgwMDAsMHgxMDAwMjAsLTB4N2ZmZjdmZTAsMCwtMHg4MDAwMDAwMCwweDgwMDAsMHgxMDgwMjAsLTB4N2ZmMDAwMDAsMHgxMDAwMjAsLTB4N2ZmZmZmZTAsMCwweDEwODAwMCwweDgwMjAsLTB4N2ZlZjgwMDAsLTB4N2ZmMDAwMDAsMHg4MDIwLDAsMHgxMDgwMjAsLTB4N2ZlZmZmZTAsMHgxMDAwMDAsLTB4N2ZmZjdmZTAsLTB4N2ZmMDAwMDAsLTB4N2ZlZjgwMDAsMHg4MDAwLC0weDdmZjAwMDAwLC0weDdmZmY4MDAwLDB4MjAsLTB4N2ZlZjdmZTAsMHgxMDgwMjAsMHgyMCwweDgwMDAsLTB4ODAwMDAwMDAsMHg4MDIwLC0weDdmZWY4MDAwLDB4MTAwMDAwLC0weDdmZmZmZmUwLDB4MTAwMDIwLC0weDdmZmY3ZmUwLC0weDdmZmZmZmUwLDB4MTAwMDIwLDB4MTA4MDAwLDAsLTB4N2ZmZjgwMDAsMHg4MDIwLC0weDgwMDAwMDAwLC0weDdmZWZmZmUwLC0weDdmZWY3ZmUwLDB4MTA4MDAwKTtcbiAgdmFyIHNwZnVuY3Rpb24zID0gbmV3IEFycmF5ICgweDIwOCwweDgwMjAyMDAsMCwweDgwMjAwMDgsMHg4MDAwMjAwLDAsMHgyMDIwOCwweDgwMDAyMDAsMHgyMDAwOCwweDgwMDAwMDgsMHg4MDAwMDA4LDB4MjAwMDAsMHg4MDIwMjA4LDB4MjAwMDgsMHg4MDIwMDAwLDB4MjA4LDB4ODAwMDAwMCwweDgsMHg4MDIwMjAwLDB4MjAwLDB4MjAyMDAsMHg4MDIwMDAwLDB4ODAyMDAwOCwweDIwMjA4LDB4ODAwMDIwOCwweDIwMjAwLDB4MjAwMDAsMHg4MDAwMjA4LDB4OCwweDgwMjAyMDgsMHgyMDAsMHg4MDAwMDAwLDB4ODAyMDIwMCwweDgwMDAwMDAsMHgyMDAwOCwweDIwOCwweDIwMDAwLDB4ODAyMDIwMCwweDgwMDAyMDAsMCwweDIwMCwweDIwMDA4LDB4ODAyMDIwOCwweDgwMDAyMDAsMHg4MDAwMDA4LDB4MjAwLDAsMHg4MDIwMDA4LDB4ODAwMDIwOCwweDIwMDAwLDB4ODAwMDAwMCwweDgwMjAyMDgsMHg4LDB4MjAyMDgsMHgyMDIwMCwweDgwMDAwMDgsMHg4MDIwMDAwLDB4ODAwMDIwOCwweDIwOCwweDgwMjAwMDAsMHgyMDIwOCwweDgsMHg4MDIwMDA4LDB4MjAyMDApO1xuICB2YXIgc3BmdW5jdGlvbjQgPSBuZXcgQXJyYXkgKDB4ODAyMDAxLDB4MjA4MSwweDIwODEsMHg4MCwweDgwMjA4MCwweDgwMDA4MSwweDgwMDAwMSwweDIwMDEsMCwweDgwMjAwMCwweDgwMjAwMCwweDgwMjA4MSwweDgxLDAsMHg4MDAwODAsMHg4MDAwMDEsMHgxLDB4MjAwMCwweDgwMDAwMCwweDgwMjAwMSwweDgwLDB4ODAwMDAwLDB4MjAwMSwweDIwODAsMHg4MDAwODEsMHgxLDB4MjA4MCwweDgwMDA4MCwweDIwMDAsMHg4MDIwODAsMHg4MDIwODEsMHg4MSwweDgwMDA4MCwweDgwMDAwMSwweDgwMjAwMCwweDgwMjA4MSwweDgxLDAsMCwweDgwMjAwMCwweDIwODAsMHg4MDAwODAsMHg4MDAwODEsMHgxLDB4ODAyMDAxLDB4MjA4MSwweDIwODEsMHg4MCwweDgwMjA4MSwweDgxLDB4MSwweDIwMDAsMHg4MDAwMDEsMHgyMDAxLDB4ODAyMDgwLDB4ODAwMDgxLDB4MjAwMSwweDIwODAsMHg4MDAwMDAsMHg4MDIwMDEsMHg4MCwweDgwMDAwMCwweDIwMDAsMHg4MDIwODApO1xuICB2YXIgc3BmdW5jdGlvbjUgPSBuZXcgQXJyYXkgKDB4MTAwLDB4MjA4MDEwMCwweDIwODAwMDAsMHg0MjAwMDEwMCwweDgwMDAwLDB4MTAwLDB4NDAwMDAwMDAsMHgyMDgwMDAwLDB4NDAwODAxMDAsMHg4MDAwMCwweDIwMDAxMDAsMHg0MDA4MDEwMCwweDQyMDAwMTAwLDB4NDIwODAwMDAsMHg4MDEwMCwweDQwMDAwMDAwLDB4MjAwMDAwMCwweDQwMDgwMDAwLDB4NDAwODAwMDAsMCwweDQwMDAwMTAwLDB4NDIwODAxMDAsMHg0MjA4MDEwMCwweDIwMDAxMDAsMHg0MjA4MDAwMCwweDQwMDAwMTAwLDAsMHg0MjAwMDAwMCwweDIwODAxMDAsMHgyMDAwMDAwLDB4NDIwMDAwMDAsMHg4MDEwMCwweDgwMDAwLDB4NDIwMDAxMDAsMHgxMDAsMHgyMDAwMDAwLDB4NDAwMDAwMDAsMHgyMDgwMDAwLDB4NDIwMDAxMDAsMHg0MDA4MDEwMCwweDIwMDAxMDAsMHg0MDAwMDAwMCwweDQyMDgwMDAwLDB4MjA4MDEwMCwweDQwMDgwMTAwLDB4MTAwLDB4MjAwMDAwMCwweDQyMDgwMDAwLDB4NDIwODAxMDAsMHg4MDEwMCwweDQyMDAwMDAwLDB4NDIwODAxMDAsMHgyMDgwMDAwLDAsMHg0MDA4MDAwMCwweDQyMDAwMDAwLDB4ODAxMDAsMHgyMDAwMTAwLDB4NDAwMDAxMDAsMHg4MDAwMCwwLDB4NDAwODAwMDAsMHgyMDgwMTAwLDB4NDAwMDAxMDApO1xuICB2YXIgc3BmdW5jdGlvbjYgPSBuZXcgQXJyYXkgKDB4MjAwMDAwMTAsMHgyMDQwMDAwMCwweDQwMDAsMHgyMDQwNDAxMCwweDIwNDAwMDAwLDB4MTAsMHgyMDQwNDAxMCwweDQwMDAwMCwweDIwMDA0MDAwLDB4NDA0MDEwLDB4NDAwMDAwLDB4MjAwMDAwMTAsMHg0MDAwMTAsMHgyMDAwNDAwMCwweDIwMDAwMDAwLDB4NDAxMCwwLDB4NDAwMDEwLDB4MjAwMDQwMTAsMHg0MDAwLDB4NDA0MDAwLDB4MjAwMDQwMTAsMHgxMCwweDIwNDAwMDEwLDB4MjA0MDAwMTAsMCwweDQwNDAxMCwweDIwNDA0MDAwLDB4NDAxMCwweDQwNDAwMCwweDIwNDA0MDAwLDB4MjAwMDAwMDAsMHgyMDAwNDAwMCwweDEwLDB4MjA0MDAwMTAsMHg0MDQwMDAsMHgyMDQwNDAxMCwweDQwMDAwMCwweDQwMTAsMHgyMDAwMDAxMCwweDQwMDAwMCwweDIwMDA0MDAwLDB4MjAwMDAwMDAsMHg0MDEwLDB4MjAwMDAwMTAsMHgyMDQwNDAxMCwweDQwNDAwMCwweDIwNDAwMDAwLDB4NDA0MDEwLDB4MjA0MDQwMDAsMCwweDIwNDAwMDEwLDB4MTAsMHg0MDAwLDB4MjA0MDAwMDAsMHg0MDQwMTAsMHg0MDAwLDB4NDAwMDEwLDB4MjAwMDQwMTAsMCwweDIwNDA0MDAwLDB4MjAwMDAwMDAsMHg0MDAwMTAsMHgyMDAwNDAxMCk7XG4gIHZhciBzcGZ1bmN0aW9uNyA9IG5ldyBBcnJheSAoMHgyMDAwMDAsMHg0MjAwMDAyLDB4NDAwMDgwMiwwLDB4ODAwLDB4NDAwMDgwMiwweDIwMDgwMiwweDQyMDA4MDAsMHg0MjAwODAyLDB4MjAwMDAwLDAsMHg0MDAwMDAyLDB4MiwweDQwMDAwMDAsMHg0MjAwMDAyLDB4ODAyLDB4NDAwMDgwMCwweDIwMDgwMiwweDIwMDAwMiwweDQwMDA4MDAsMHg0MDAwMDAyLDB4NDIwMDAwMCwweDQyMDA4MDAsMHgyMDAwMDIsMHg0MjAwMDAwLDB4ODAwLDB4ODAyLDB4NDIwMDgwMiwweDIwMDgwMCwweDIsMHg0MDAwMDAwLDB4MjAwODAwLDB4NDAwMDAwMCwweDIwMDgwMCwweDIwMDAwMCwweDQwMDA4MDIsMHg0MDAwODAyLDB4NDIwMDAwMiwweDQyMDAwMDIsMHgyLDB4MjAwMDAyLDB4NDAwMDAwMCwweDQwMDA4MDAsMHgyMDAwMDAsMHg0MjAwODAwLDB4ODAyLDB4MjAwODAyLDB4NDIwMDgwMCwweDgwMiwweDQwMDAwMDIsMHg0MjAwODAyLDB4NDIwMDAwMCwweDIwMDgwMCwwLDB4MiwweDQyMDA4MDIsMCwweDIwMDgwMiwweDQyMDAwMDAsMHg4MDAsMHg0MDAwMDAyLDB4NDAwMDgwMCwweDgwMCwweDIwMDAwMik7XG4gIHZhciBzcGZ1bmN0aW9uOCA9IG5ldyBBcnJheSAoMHgxMDAwMTA0MCwweDEwMDAsMHg0MDAwMCwweDEwMDQxMDQwLDB4MTAwMDAwMDAsMHgxMDAwMTA0MCwweDQwLDB4MTAwMDAwMDAsMHg0MDA0MCwweDEwMDQwMDAwLDB4MTAwNDEwNDAsMHg0MTAwMCwweDEwMDQxMDAwLDB4NDEwNDAsMHgxMDAwLDB4NDAsMHgxMDA0MDAwMCwweDEwMDAwMDQwLDB4MTAwMDEwMDAsMHgxMDQwLDB4NDEwMDAsMHg0MDA0MCwweDEwMDQwMDQwLDB4MTAwNDEwMDAsMHgxMDQwLDAsMCwweDEwMDQwMDQwLDB4MTAwMDAwNDAsMHgxMDAwMTAwMCwweDQxMDQwLDB4NDAwMDAsMHg0MTA0MCwweDQwMDAwLDB4MTAwNDEwMDAsMHgxMDAwLDB4NDAsMHgxMDA0MDA0MCwweDEwMDAsMHg0MTA0MCwweDEwMDAxMDAwLDB4NDAsMHgxMDAwMDA0MCwweDEwMDQwMDAwLDB4MTAwNDAwNDAsMHgxMDAwMDAwMCwweDQwMDAwLDB4MTAwMDEwNDAsMCwweDEwMDQxMDQwLDB4NDAwNDAsMHgxMDAwMDA0MCwweDEwMDQwMDAwLDB4MTAwMDEwMDAsMHgxMDAwMTA0MCwwLDB4MTAwNDEwNDAsMHg0MTAwMCwweDQxMDAwLDB4MTA0MCwweDEwNDAsMHg0MDA0MCwweDEwMDAwMDAwLDB4MTAwNDEwMDApO1xuXG4gIC8vY3JlYXRlIHRoZSAxNiBvciA0OCBzdWJrZXlzIHdlIHdpbGwgbmVlZFxuICB2YXIgbT0wLCBpLCBqLCB0ZW1wLCB0ZW1wMiwgcmlnaHQxLCByaWdodDIsIGxlZnQsIHJpZ2h0LCBsb29waW5nO1xuICB2YXIgY2JjbGVmdCwgY2JjbGVmdDIsIGNiY3JpZ2h0LCBjYmNyaWdodDJcbiAgdmFyIGVuZGxvb3AsIGxvb3BpbmM7XG4gIHZhciBsZW4gPSBtZXNzYWdlLmxlbmd0aDtcbiAgdmFyIGNodW5rID0gMDtcbiAgLy9zZXQgdXAgdGhlIGxvb3BzIGZvciBzaW5nbGUgYW5kIHRyaXBsZSBkZXNcbiAgdmFyIGl0ZXJhdGlvbnMgPSBrZXlzLmxlbmd0aCA9PSAzMiA/IDMgOiA5OyAvL3NpbmdsZSBvciB0cmlwbGUgZGVzXG4gIGlmIChpdGVyYXRpb25zID09IDMpIHtsb29waW5nID0gZW5jcnlwdCA/IG5ldyBBcnJheSAoMCwgMzIsIDIpIDogbmV3IEFycmF5ICgzMCwgLTIsIC0yKTt9XG4gIGVsc2Uge2xvb3BpbmcgPSBlbmNyeXB0ID8gbmV3IEFycmF5ICgwLCAzMiwgMiwgNjIsIDMwLCAtMiwgNjQsIDk2LCAyKSA6IG5ldyBBcnJheSAoOTQsIDYyLCAtMiwgMzIsIDY0LCAyLCAzMCwgLTIsIC0yKTt9XG5cbiAgLy9wYWQgdGhlIG1lc3NhZ2UgZGVwZW5kaW5nIG9uIHRoZSBwYWRkaW5nIHBhcmFtZXRlclxuICBpZiAocGFkZGluZyA9PSAyKSBtZXNzYWdlICs9IFwiICAgICAgICBcIjsgLy9wYWQgdGhlIG1lc3NhZ2Ugd2l0aCBzcGFjZXNcbiAgZWxzZSBpZiAocGFkZGluZyA9PSAxKSB7dGVtcCA9IDgtKGxlbiU4KTsgbWVzc2FnZSArPSBTdHJpbmcuZnJvbUNoYXJDb2RlICh0ZW1wLHRlbXAsdGVtcCx0ZW1wLHRlbXAsdGVtcCx0ZW1wLHRlbXApOyBpZiAodGVtcD09OCkgbGVuKz04O30gLy9QS0NTNyBwYWRkaW5nXG4gIGVsc2UgaWYgKCFwYWRkaW5nKSBtZXNzYWdlICs9IFwiXFwwXFwwXFwwXFwwXFwwXFwwXFwwXFwwXCI7IC8vcGFkIHRoZSBtZXNzYWdlIG91dCB3aXRoIG51bGwgYnl0ZXNcblxuICAvL3N0b3JlIHRoZSByZXN1bHQgaGVyZVxuICByZXN1bHQgPSBcIlwiO1xuICB0ZW1wcmVzdWx0ID0gXCJcIjtcblxuICBpZiAobW9kZSA9PSAxKSB7IC8vQ0JDIG1vZGVcbiAgICBjYmNsZWZ0ID0gKGl2LmNoYXJDb2RlQXQobSsrKSA8PCAyNCkgfCAoaXYuY2hhckNvZGVBdChtKyspIDw8IDE2KSB8IChpdi5jaGFyQ29kZUF0KG0rKykgPDwgOCkgfCBpdi5jaGFyQ29kZUF0KG0rKyk7XG4gICAgY2JjcmlnaHQgPSAoaXYuY2hhckNvZGVBdChtKyspIDw8IDI0KSB8IChpdi5jaGFyQ29kZUF0KG0rKykgPDwgMTYpIHwgKGl2LmNoYXJDb2RlQXQobSsrKSA8PCA4KSB8IGl2LmNoYXJDb2RlQXQobSsrKTtcbiAgICBtPTA7XG4gIH1cblxuICAvL2xvb3AgdGhyb3VnaCBlYWNoIDY0IGJpdCBjaHVuayBvZiB0aGUgbWVzc2FnZVxuICB3aGlsZSAobSA8IGxlbikge1xuICAgIGxlZnQgPSAobWVzc2FnZS5jaGFyQ29kZUF0KG0rKykgPDwgMjQpIHwgKG1lc3NhZ2UuY2hhckNvZGVBdChtKyspIDw8IDE2KSB8IChtZXNzYWdlLmNoYXJDb2RlQXQobSsrKSA8PCA4KSB8IG1lc3NhZ2UuY2hhckNvZGVBdChtKyspO1xuICAgIHJpZ2h0ID0gKG1lc3NhZ2UuY2hhckNvZGVBdChtKyspIDw8IDI0KSB8IChtZXNzYWdlLmNoYXJDb2RlQXQobSsrKSA8PCAxNikgfCAobWVzc2FnZS5jaGFyQ29kZUF0KG0rKykgPDwgOCkgfCBtZXNzYWdlLmNoYXJDb2RlQXQobSsrKTtcblxuICAgIC8vZm9yIENpcGhlciBCbG9jayBDaGFpbmluZyBtb2RlLCB4b3IgdGhlIG1lc3NhZ2Ugd2l0aCB0aGUgcHJldmlvdXMgcmVzdWx0XG4gICAgaWYgKG1vZGUgPT0gMSkge2lmIChlbmNyeXB0KSB7bGVmdCBePSBjYmNsZWZ0OyByaWdodCBePSBjYmNyaWdodDt9IGVsc2Uge2NiY2xlZnQyID0gY2JjbGVmdDsgY2JjcmlnaHQyID0gY2JjcmlnaHQ7IGNiY2xlZnQgPSBsZWZ0OyBjYmNyaWdodCA9IHJpZ2h0O319XG5cbiAgICAvL2ZpcnN0IGVhY2ggNjQgYnV0IGNodW5rIG9mIHRoZSBtZXNzYWdlIG11c3QgYmUgcGVybXV0ZWQgYWNjb3JkaW5nIHRvIElQXG4gICAgdGVtcCA9ICgobGVmdCA+Pj4gNCkgXiByaWdodCkgJiAweDBmMGYwZjBmOyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDQpO1xuICAgIHRlbXAgPSAoKGxlZnQgPj4+IDE2KSBeIHJpZ2h0KSAmIDB4MDAwMGZmZmY7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgMTYpO1xuICAgIHRlbXAgPSAoKHJpZ2h0ID4+PiAyKSBeIGxlZnQpICYgMHgzMzMzMzMzMzsgbGVmdCBePSB0ZW1wOyByaWdodCBePSAodGVtcCA8PCAyKTtcbiAgICB0ZW1wID0gKChyaWdodCA+Pj4gOCkgXiBsZWZ0KSAmIDB4MDBmZjAwZmY7IGxlZnQgXj0gdGVtcDsgcmlnaHQgXj0gKHRlbXAgPDwgOCk7XG4gICAgdGVtcCA9ICgobGVmdCA+Pj4gMSkgXiByaWdodCkgJiAweDU1NTU1NTU1OyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDEpO1xuXG4gICAgbGVmdCA9ICgobGVmdCA8PCAxKSB8IChsZWZ0ID4+PiAzMSkpOyBcbiAgICByaWdodCA9ICgocmlnaHQgPDwgMSkgfCAocmlnaHQgPj4+IDMxKSk7IFxuXG4gICAgLy9kbyB0aGlzIGVpdGhlciAxIG9yIDMgdGltZXMgZm9yIGVhY2ggY2h1bmsgb2YgdGhlIG1lc3NhZ2VcbiAgICBmb3IgKGo9MDsgajxpdGVyYXRpb25zOyBqKz0zKSB7XG4gICAgICBlbmRsb29wID0gbG9vcGluZ1tqKzFdO1xuICAgICAgbG9vcGluYyA9IGxvb3BpbmdbaisyXTtcbiAgICAgIC8vbm93IGdvIHRocm91Z2ggYW5kIHBlcmZvcm0gdGhlIGVuY3J5cHRpb24gb3IgZGVjcnlwdGlvbiAgXG4gICAgICBmb3IgKGk9bG9vcGluZ1tqXTsgaSE9ZW5kbG9vcDsgaSs9bG9vcGluYykgeyAvL2ZvciBlZmZpY2llbmN5XG4gICAgICAgIHJpZ2h0MSA9IHJpZ2h0IF4ga2V5c1tpXTsgXG4gICAgICAgIHJpZ2h0MiA9ICgocmlnaHQgPj4+IDQpIHwgKHJpZ2h0IDw8IDI4KSkgXiBrZXlzW2krMV07XG4gICAgICAgIC8vdGhlIHJlc3VsdCBpcyBhdHRhaW5lZCBieSBwYXNzaW5nIHRoZXNlIGJ5dGVzIHRocm91Z2ggdGhlIFMgc2VsZWN0aW9uIGZ1bmN0aW9uc1xuICAgICAgICB0ZW1wID0gbGVmdDtcbiAgICAgICAgbGVmdCA9IHJpZ2h0O1xuICAgICAgICByaWdodCA9IHRlbXAgXiAoc3BmdW5jdGlvbjJbKHJpZ2h0MSA+Pj4gMjQpICYgMHgzZl0gfCBzcGZ1bmN0aW9uNFsocmlnaHQxID4+PiAxNikgJiAweDNmXVxuICAgICAgICAgICAgICB8IHNwZnVuY3Rpb242WyhyaWdodDEgPj4+ICA4KSAmIDB4M2ZdIHwgc3BmdW5jdGlvbjhbcmlnaHQxICYgMHgzZl1cbiAgICAgICAgICAgICAgfCBzcGZ1bmN0aW9uMVsocmlnaHQyID4+PiAyNCkgJiAweDNmXSB8IHNwZnVuY3Rpb24zWyhyaWdodDIgPj4+IDE2KSAmIDB4M2ZdXG4gICAgICAgICAgICAgIHwgc3BmdW5jdGlvbjVbKHJpZ2h0MiA+Pj4gIDgpICYgMHgzZl0gfCBzcGZ1bmN0aW9uN1tyaWdodDIgJiAweDNmXSk7XG4gICAgICB9XG4gICAgICB0ZW1wID0gbGVmdDsgbGVmdCA9IHJpZ2h0OyByaWdodCA9IHRlbXA7IC8vdW5yZXZlcnNlIGxlZnQgYW5kIHJpZ2h0XG4gICAgfSAvL2ZvciBlaXRoZXIgMSBvciAzIGl0ZXJhdGlvbnNcblxuICAgIC8vbW92ZSB0aGVuIGVhY2ggb25lIGJpdCB0byB0aGUgcmlnaHRcbiAgICBsZWZ0ID0gKChsZWZ0ID4+PiAxKSB8IChsZWZ0IDw8IDMxKSk7IFxuICAgIHJpZ2h0ID0gKChyaWdodCA+Pj4gMSkgfCAocmlnaHQgPDwgMzEpKTsgXG5cbiAgICAvL25vdyBwZXJmb3JtIElQLTEsIHdoaWNoIGlzIElQIGluIHRoZSBvcHBvc2l0ZSBkaXJlY3Rpb25cbiAgICB0ZW1wID0gKChsZWZ0ID4+PiAxKSBeIHJpZ2h0KSAmIDB4NTU1NTU1NTU7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgMSk7XG4gICAgdGVtcCA9ICgocmlnaHQgPj4+IDgpIF4gbGVmdCkgJiAweDAwZmYwMGZmOyBsZWZ0IF49IHRlbXA7IHJpZ2h0IF49ICh0ZW1wIDw8IDgpO1xuICAgIHRlbXAgPSAoKHJpZ2h0ID4+PiAyKSBeIGxlZnQpICYgMHgzMzMzMzMzMzsgbGVmdCBePSB0ZW1wOyByaWdodCBePSAodGVtcCA8PCAyKTtcbiAgICB0ZW1wID0gKChsZWZ0ID4+PiAxNikgXiByaWdodCkgJiAweDAwMDBmZmZmOyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDE2KTtcbiAgICB0ZW1wID0gKChsZWZ0ID4+PiA0KSBeIHJpZ2h0KSAmIDB4MGYwZjBmMGY7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgNCk7XG5cbiAgICAvL2ZvciBDaXBoZXIgQmxvY2sgQ2hhaW5pbmcgbW9kZSwgeG9yIHRoZSBtZXNzYWdlIHdpdGggdGhlIHByZXZpb3VzIHJlc3VsdFxuICAgIGlmIChtb2RlID09IDEpIHtpZiAoZW5jcnlwdCkge2NiY2xlZnQgPSBsZWZ0OyBjYmNyaWdodCA9IHJpZ2h0O30gZWxzZSB7bGVmdCBePSBjYmNsZWZ0MjsgcmlnaHQgXj0gY2JjcmlnaHQyO319XG4gICAgdGVtcHJlc3VsdCArPSBTdHJpbmcuZnJvbUNoYXJDb2RlICgobGVmdD4+PjI0KSwgKChsZWZ0Pj4+MTYpICYgMHhmZiksICgobGVmdD4+PjgpICYgMHhmZiksIChsZWZ0ICYgMHhmZiksIChyaWdodD4+PjI0KSwgKChyaWdodD4+PjE2KSAmIDB4ZmYpLCAoKHJpZ2h0Pj4+OCkgJiAweGZmKSwgKHJpZ2h0ICYgMHhmZikpO1xuXG4gICAgY2h1bmsgKz0gODtcbiAgICBpZiAoY2h1bmsgPT0gNTEyKSB7cmVzdWx0ICs9IHRlbXByZXN1bHQ7IHRlbXByZXN1bHQgPSBcIlwiOyBjaHVuayA9IDA7fVxuICB9IC8vZm9yIGV2ZXJ5IDggY2hhcmFjdGVycywgb3IgNjQgYml0cyBpbiB0aGUgbWVzc2FnZVxuXG4gIC8vcmV0dXJuIHRoZSByZXN1bHQgYXMgYW4gYXJyYXlcbiAgcmVzdWx0ICs9IHRlbXByZXN1bHQ7XG4gIHJlc3VsdCA9IHJlc3VsdC5yZXBsYWNlKC9cXDAqJC9nLCBcIlwiKTtcbiAgcmV0dXJuIHJlc3VsdDtcbn0gLy9lbmQgb2YgZGVzXG5cblxuXG4vL2Rlc19jcmVhdGVLZXlzXG4vL3RoaXMgdGFrZXMgYXMgaW5wdXQgYSA2NCBiaXQga2V5IChldmVuIHRob3VnaCBvbmx5IDU2IGJpdHMgYXJlIHVzZWQpXG4vL2FzIGFuIGFycmF5IG9mIDIgaW50ZWdlcnMsIGFuZCByZXR1cm5zIDE2IDQ4IGJpdCBrZXlzXG5mdW5jdGlvbiBkZXNfY3JlYXRlS2V5cyAoa2V5KSB7XG4gIC8vZGVjbGFyaW5nIHRoaXMgbG9jYWxseSBzcGVlZHMgdGhpbmdzIHVwIGEgYml0XG4gIHBjMmJ5dGVzMCAgPSBuZXcgQXJyYXkgKDAsMHg0LDB4MjAwMDAwMDAsMHgyMDAwMDAwNCwweDEwMDAwLDB4MTAwMDQsMHgyMDAxMDAwMCwweDIwMDEwMDA0LDB4MjAwLDB4MjA0LDB4MjAwMDAyMDAsMHgyMDAwMDIwNCwweDEwMjAwLDB4MTAyMDQsMHgyMDAxMDIwMCwweDIwMDEwMjA0KTtcbiAgcGMyYnl0ZXMxICA9IG5ldyBBcnJheSAoMCwweDEsMHgxMDAwMDAsMHgxMDAwMDEsMHg0MDAwMDAwLDB4NDAwMDAwMSwweDQxMDAwMDAsMHg0MTAwMDAxLDB4MTAwLDB4MTAxLDB4MTAwMTAwLDB4MTAwMTAxLDB4NDAwMDEwMCwweDQwMDAxMDEsMHg0MTAwMTAwLDB4NDEwMDEwMSk7XG4gIHBjMmJ5dGVzMiAgPSBuZXcgQXJyYXkgKDAsMHg4LDB4ODAwLDB4ODA4LDB4MTAwMDAwMCwweDEwMDAwMDgsMHgxMDAwODAwLDB4MTAwMDgwOCwwLDB4OCwweDgwMCwweDgwOCwweDEwMDAwMDAsMHgxMDAwMDA4LDB4MTAwMDgwMCwweDEwMDA4MDgpO1xuICBwYzJieXRlczMgID0gbmV3IEFycmF5ICgwLDB4MjAwMDAwLDB4ODAwMDAwMCwweDgyMDAwMDAsMHgyMDAwLDB4MjAyMDAwLDB4ODAwMjAwMCwweDgyMDIwMDAsMHgyMDAwMCwweDIyMDAwMCwweDgwMjAwMDAsMHg4MjIwMDAwLDB4MjIwMDAsMHgyMjIwMDAsMHg4MDIyMDAwLDB4ODIyMjAwMCk7XG4gIHBjMmJ5dGVzNCAgPSBuZXcgQXJyYXkgKDAsMHg0MDAwMCwweDEwLDB4NDAwMTAsMCwweDQwMDAwLDB4MTAsMHg0MDAxMCwweDEwMDAsMHg0MTAwMCwweDEwMTAsMHg0MTAxMCwweDEwMDAsMHg0MTAwMCwweDEwMTAsMHg0MTAxMCk7XG4gIHBjMmJ5dGVzNSAgPSBuZXcgQXJyYXkgKDAsMHg0MDAsMHgyMCwweDQyMCwwLDB4NDAwLDB4MjAsMHg0MjAsMHgyMDAwMDAwLDB4MjAwMDQwMCwweDIwMDAwMjAsMHgyMDAwNDIwLDB4MjAwMDAwMCwweDIwMDA0MDAsMHgyMDAwMDIwLDB4MjAwMDQyMCk7XG4gIHBjMmJ5dGVzNiAgPSBuZXcgQXJyYXkgKDAsMHgxMDAwMDAwMCwweDgwMDAwLDB4MTAwODAwMDAsMHgyLDB4MTAwMDAwMDIsMHg4MDAwMiwweDEwMDgwMDAyLDAsMHgxMDAwMDAwMCwweDgwMDAwLDB4MTAwODAwMDAsMHgyLDB4MTAwMDAwMDIsMHg4MDAwMiwweDEwMDgwMDAyKTtcbiAgcGMyYnl0ZXM3ICA9IG5ldyBBcnJheSAoMCwweDEwMDAwLDB4ODAwLDB4MTA4MDAsMHgyMDAwMDAwMCwweDIwMDEwMDAwLDB4MjAwMDA4MDAsMHgyMDAxMDgwMCwweDIwMDAwLDB4MzAwMDAsMHgyMDgwMCwweDMwODAwLDB4MjAwMjAwMDAsMHgyMDAzMDAwMCwweDIwMDIwODAwLDB4MjAwMzA4MDApO1xuICBwYzJieXRlczggID0gbmV3IEFycmF5ICgwLDB4NDAwMDAsMCwweDQwMDAwLDB4MiwweDQwMDAyLDB4MiwweDQwMDAyLDB4MjAwMDAwMCwweDIwNDAwMDAsMHgyMDAwMDAwLDB4MjA0MDAwMCwweDIwMDAwMDIsMHgyMDQwMDAyLDB4MjAwMDAwMiwweDIwNDAwMDIpO1xuICBwYzJieXRlczkgID0gbmV3IEFycmF5ICgwLDB4MTAwMDAwMDAsMHg4LDB4MTAwMDAwMDgsMCwweDEwMDAwMDAwLDB4OCwweDEwMDAwMDA4LDB4NDAwLDB4MTAwMDA0MDAsMHg0MDgsMHgxMDAwMDQwOCwweDQwMCwweDEwMDAwNDAwLDB4NDA4LDB4MTAwMDA0MDgpO1xuICBwYzJieXRlczEwID0gbmV3IEFycmF5ICgwLDB4MjAsMCwweDIwLDB4MTAwMDAwLDB4MTAwMDIwLDB4MTAwMDAwLDB4MTAwMDIwLDB4MjAwMCwweDIwMjAsMHgyMDAwLDB4MjAyMCwweDEwMjAwMCwweDEwMjAyMCwweDEwMjAwMCwweDEwMjAyMCk7XG4gIHBjMmJ5dGVzMTEgPSBuZXcgQXJyYXkgKDAsMHgxMDAwMDAwLDB4MjAwLDB4MTAwMDIwMCwweDIwMDAwMCwweDEyMDAwMDAsMHgyMDAyMDAsMHgxMjAwMjAwLDB4NDAwMDAwMCwweDUwMDAwMDAsMHg0MDAwMjAwLDB4NTAwMDIwMCwweDQyMDAwMDAsMHg1MjAwMDAwLDB4NDIwMDIwMCwweDUyMDAyMDApO1xuICBwYzJieXRlczEyID0gbmV3IEFycmF5ICgwLDB4MTAwMCwweDgwMDAwMDAsMHg4MDAxMDAwLDB4ODAwMDAsMHg4MTAwMCwweDgwODAwMDAsMHg4MDgxMDAwLDB4MTAsMHgxMDEwLDB4ODAwMDAxMCwweDgwMDEwMTAsMHg4MDAxMCwweDgxMDEwLDB4ODA4MDAxMCwweDgwODEwMTApO1xuICBwYzJieXRlczEzID0gbmV3IEFycmF5ICgwLDB4NCwweDEwMCwweDEwNCwwLDB4NCwweDEwMCwweDEwNCwweDEsMHg1LDB4MTAxLDB4MTA1LDB4MSwweDUsMHgxMDEsMHgxMDUpO1xuXG4gIC8vaG93IG1hbnkgaXRlcmF0aW9ucyAoMSBmb3IgZGVzLCAzIGZvciB0cmlwbGUgZGVzKVxuICB2YXIgaXRlcmF0aW9ucyA9IGtleS5sZW5ndGggPiA4ID8gMyA6IDE7IC8vY2hhbmdlZCBieSBQYXVsIDE2LzYvMjAwNyB0byB1c2UgVHJpcGxlIERFUyBmb3IgOSsgYnl0ZSBrZXlzXG4gIC8vc3RvcmVzIHRoZSByZXR1cm4ga2V5c1xuICB2YXIga2V5cyA9IG5ldyBBcnJheSAoMzIgKiBpdGVyYXRpb25zKTtcbiAgLy9ub3cgZGVmaW5lIHRoZSBsZWZ0IHNoaWZ0cyB3aGljaCBuZWVkIHRvIGJlIGRvbmVcbiAgdmFyIHNoaWZ0cyA9IG5ldyBBcnJheSAoMCwgMCwgMSwgMSwgMSwgMSwgMSwgMSwgMCwgMSwgMSwgMSwgMSwgMSwgMSwgMCk7XG4gIC8vb3RoZXIgdmFyaWFibGVzXG4gIHZhciBsZWZ0dGVtcCwgcmlnaHR0ZW1wLCBtPTAsIG49MCwgdGVtcDtcblxuICBmb3IgKHZhciBqPTA7IGo8aXRlcmF0aW9uczsgaisrKSB7IC8vZWl0aGVyIDEgb3IgMyBpdGVyYXRpb25zXG4gICAgbGVmdCA9IChrZXkuY2hhckNvZGVBdChtKyspIDw8IDI0KSB8IChrZXkuY2hhckNvZGVBdChtKyspIDw8IDE2KSB8IChrZXkuY2hhckNvZGVBdChtKyspIDw8IDgpIHwga2V5LmNoYXJDb2RlQXQobSsrKTtcbiAgICByaWdodCA9IChrZXkuY2hhckNvZGVBdChtKyspIDw8IDI0KSB8IChrZXkuY2hhckNvZGVBdChtKyspIDw8IDE2KSB8IChrZXkuY2hhckNvZGVBdChtKyspIDw8IDgpIHwga2V5LmNoYXJDb2RlQXQobSsrKTtcblxuICAgIHRlbXAgPSAoKGxlZnQgPj4+IDQpIF4gcmlnaHQpICYgMHgwZjBmMGYwZjsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCA0KTtcbiAgICB0ZW1wID0gKChyaWdodCA+Pj4gLTE2KSBeIGxlZnQpICYgMHgwMDAwZmZmZjsgbGVmdCBePSB0ZW1wOyByaWdodCBePSAodGVtcCA8PCAtMTYpO1xuICAgIHRlbXAgPSAoKGxlZnQgPj4+IDIpIF4gcmlnaHQpICYgMHgzMzMzMzMzMzsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCAyKTtcbiAgICB0ZW1wID0gKChyaWdodCA+Pj4gLTE2KSBeIGxlZnQpICYgMHgwMDAwZmZmZjsgbGVmdCBePSB0ZW1wOyByaWdodCBePSAodGVtcCA8PCAtMTYpO1xuICAgIHRlbXAgPSAoKGxlZnQgPj4+IDEpIF4gcmlnaHQpICYgMHg1NTU1NTU1NTsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCAxKTtcbiAgICB0ZW1wID0gKChyaWdodCA+Pj4gOCkgXiBsZWZ0KSAmIDB4MDBmZjAwZmY7IGxlZnQgXj0gdGVtcDsgcmlnaHQgXj0gKHRlbXAgPDwgOCk7XG4gICAgdGVtcCA9ICgobGVmdCA+Pj4gMSkgXiByaWdodCkgJiAweDU1NTU1NTU1OyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDEpO1xuXG4gICAgLy90aGUgcmlnaHQgc2lkZSBuZWVkcyB0byBiZSBzaGlmdGVkIGFuZCB0byBnZXQgdGhlIGxhc3QgZm91ciBiaXRzIG9mIHRoZSBsZWZ0IHNpZGVcbiAgICB0ZW1wID0gKGxlZnQgPDwgOCkgfCAoKHJpZ2h0ID4+PiAyMCkgJiAweDAwMDAwMGYwKTtcbiAgICAvL2xlZnQgbmVlZHMgdG8gYmUgcHV0IHVwc2lkZSBkb3duXG4gICAgbGVmdCA9IChyaWdodCA8PCAyNCkgfCAoKHJpZ2h0IDw8IDgpICYgMHhmZjAwMDApIHwgKChyaWdodCA+Pj4gOCkgJiAweGZmMDApIHwgKChyaWdodCA+Pj4gMjQpICYgMHhmMCk7XG4gICAgcmlnaHQgPSB0ZW1wO1xuXG4gICAgLy9ub3cgZ28gdGhyb3VnaCBhbmQgcGVyZm9ybSB0aGVzZSBzaGlmdHMgb24gdGhlIGxlZnQgYW5kIHJpZ2h0IGtleXNcbiAgICBmb3IgKGk9MDsgaSA8IHNoaWZ0cy5sZW5ndGg7IGkrKykge1xuICAgICAgLy9zaGlmdCB0aGUga2V5cyBlaXRoZXIgb25lIG9yIHR3byBiaXRzIHRvIHRoZSBsZWZ0XG4gICAgICBpZiAoc2hpZnRzW2ldKSB7bGVmdCA9IChsZWZ0IDw8IDIpIHwgKGxlZnQgPj4+IDI2KTsgcmlnaHQgPSAocmlnaHQgPDwgMikgfCAocmlnaHQgPj4+IDI2KTt9XG4gICAgICBlbHNlIHtsZWZ0ID0gKGxlZnQgPDwgMSkgfCAobGVmdCA+Pj4gMjcpOyByaWdodCA9IChyaWdodCA8PCAxKSB8IChyaWdodCA+Pj4gMjcpO31cbiAgICAgIGxlZnQgJj0gLTB4ZjsgcmlnaHQgJj0gLTB4ZjtcblxuICAgICAgLy9ub3cgYXBwbHkgUEMtMiwgaW4gc3VjaCBhIHdheSB0aGF0IEUgaXMgZWFzaWVyIHdoZW4gZW5jcnlwdGluZyBvciBkZWNyeXB0aW5nXG4gICAgICAvL3RoaXMgY29udmVyc2lvbiB3aWxsIGxvb2sgbGlrZSBQQy0yIGV4Y2VwdCBvbmx5IHRoZSBsYXN0IDYgYml0cyBvZiBlYWNoIGJ5dGUgYXJlIHVzZWRcbiAgICAgIC8vcmF0aGVyIHRoYW4gNDggY29uc2VjdXRpdmUgYml0cyBhbmQgdGhlIG9yZGVyIG9mIGxpbmVzIHdpbGwgYmUgYWNjb3JkaW5nIHRvIFxuICAgICAgLy9ob3cgdGhlIFMgc2VsZWN0aW9uIGZ1bmN0aW9ucyB3aWxsIGJlIGFwcGxpZWQ6IFMyLCBTNCwgUzYsIFM4LCBTMSwgUzMsIFM1LCBTN1xuICAgICAgbGVmdHRlbXAgPSBwYzJieXRlczBbbGVmdCA+Pj4gMjhdIHwgcGMyYnl0ZXMxWyhsZWZ0ID4+PiAyNCkgJiAweGZdXG4gICAgICAgICAgICAgIHwgcGMyYnl0ZXMyWyhsZWZ0ID4+PiAyMCkgJiAweGZdIHwgcGMyYnl0ZXMzWyhsZWZ0ID4+PiAxNikgJiAweGZdXG4gICAgICAgICAgICAgIHwgcGMyYnl0ZXM0WyhsZWZ0ID4+PiAxMikgJiAweGZdIHwgcGMyYnl0ZXM1WyhsZWZ0ID4+PiA4KSAmIDB4Zl1cbiAgICAgICAgICAgICAgfCBwYzJieXRlczZbKGxlZnQgPj4+IDQpICYgMHhmXTtcbiAgICAgIHJpZ2h0dGVtcCA9IHBjMmJ5dGVzN1tyaWdodCA+Pj4gMjhdIHwgcGMyYnl0ZXM4WyhyaWdodCA+Pj4gMjQpICYgMHhmXVxuICAgICAgICAgICAgICAgIHwgcGMyYnl0ZXM5WyhyaWdodCA+Pj4gMjApICYgMHhmXSB8IHBjMmJ5dGVzMTBbKHJpZ2h0ID4+PiAxNikgJiAweGZdXG4gICAgICAgICAgICAgICAgfCBwYzJieXRlczExWyhyaWdodCA+Pj4gMTIpICYgMHhmXSB8IHBjMmJ5dGVzMTJbKHJpZ2h0ID4+PiA4KSAmIDB4Zl1cbiAgICAgICAgICAgICAgICB8IHBjMmJ5dGVzMTNbKHJpZ2h0ID4+PiA0KSAmIDB4Zl07XG4gICAgICB0ZW1wID0gKChyaWdodHRlbXAgPj4+IDE2KSBeIGxlZnR0ZW1wKSAmIDB4MDAwMGZmZmY7IFxuICAgICAga2V5c1tuKytdID0gbGVmdHRlbXAgXiB0ZW1wOyBrZXlzW24rK10gPSByaWdodHRlbXAgXiAodGVtcCA8PCAxNik7XG4gICAgfVxuICB9IC8vZm9yIGVhY2ggaXRlcmF0aW9uc1xuICAvL3JldHVybiB0aGUga2V5cyB3ZSd2ZSBjcmVhdGVkXG4gIHJldHVybiBrZXlzO1xufSAvL2VuZCBvZiBkZXNfY3JlYXRlS2V5c1xuXG5cbm1vZHVsZS5leHBvcnRzID0gZGVzZWRlO1xuIiwiXHJcbi8vIFVzZSBvZiB0aGlzIHNvdXJjZSBjb2RlIGlzIGdvdmVybmVkIGJ5IGEgQlNELXN0eWxlXHJcbi8vIGxpY2Vuc2UgdGhhdCBjYW4gYmUgZm91bmQgaW4gdGhlIExJQ0VOU0UgZmlsZS5cclxuXHJcbi8vIENvcHlyaWdodCAyMDEwIHBqYWNvYnNAeGVla3IuY29tIC4gQWxsIHJpZ2h0cyByZXNlcnZlZC5cclxuXHJcbi8vIE1vZGlmaWVkIGJ5IFJlY3VyaXR5IExhYnMgR21iSFxyXG5cclxuLy8gZml4ZWQvbW9kaWZpZWQgYnkgSGVyYmVydCBIYW5ld2lua2VsLCB3d3cuaGFuZVdJTi5kZVxyXG4vLyBjaGVjayB3d3cuaGFuZVdJTi5kZSBmb3IgdGhlIGxhdGVzdCB2ZXJzaW9uXHJcblxyXG4vLyBjYXN0NS5qcyBpcyBhIEphdmFzY3JpcHQgaW1wbGVtZW50YXRpb24gb2YgQ0FTVC0xMjgsIGFzIGRlZmluZWQgaW4gUkZDIDIxNDQuXHJcbi8vIENBU1QtMTI4IGlzIGEgY29tbW9uIE9wZW5QR1AgY2lwaGVyLlxyXG5cclxuXHJcbi8vIENBU1Q1IGNvbnN0cnVjdG9yXHJcblxyXG52YXIgdXRpbCA9IHJlcXVpcmUoJy4uLy4uL3V0aWwnKTtcclxuXHJcbmZ1bmN0aW9uIGNhc3Q1X2VuY3J5cHQoYmxvY2ssIGtleSkge1xyXG5cdHZhciBjYXN0NSA9IG5ldyBvcGVucGdwX3N5bWVuY19jYXN0NSgpO1xyXG5cdGNhc3Q1LnNldEtleSh1dGlsLnN0cjJiaW4oa2V5KSk7XHJcblx0cmV0dXJuIGNhc3Q1LmVuY3J5cHQoYmxvY2spO1xyXG59XHJcblxyXG5mdW5jdGlvbiBvcGVucGdwX3N5bWVuY19jYXN0NSgpIHtcclxuXHR0aGlzLkJsb2NrU2l6ZT0gODtcclxuXHR0aGlzLktleVNpemUgPSAxNjtcclxuXHJcblx0dGhpcy5zZXRLZXkgPSBmdW5jdGlvbiAoa2V5KSB7XHJcblx0XHQgdGhpcy5tYXNraW5nID0gbmV3IEFycmF5KDE2KTtcclxuXHRcdCB0aGlzLnJvdGF0ZSA9IG5ldyBBcnJheSgxNik7XHJcblxyXG5cdFx0IHRoaXMucmVzZXQoKTtcclxuXHJcblx0XHQgaWYgKGtleS5sZW5ndGggPT0gdGhpcy5LZXlTaXplKVxyXG5cdFx0IHtcclxuXHRcdCAgIHRoaXMua2V5U2NoZWR1bGUoa2V5KTtcclxuXHRcdCB9XHJcblx0XHQgZWxzZVxyXG5cdFx0IHtcclxuXHRcdCAgIHV0aWwucHJpbnRfZXJyb3IoJ2Nhc3Q1LmpzOiBDQVNULTEyODoga2V5cyBtdXN0IGJlIDE2IGJ5dGVzJyk7XHJcblx0XHQgICByZXR1cm4gZmFsc2U7XHJcblx0XHQgfVxyXG5cdFx0IHJldHVybiB0cnVlO1xyXG5cdH07XHJcblx0XHJcblx0dGhpcy5yZXNldCA9IGZ1bmN0aW9uKCkge1xyXG5cdFx0IGZvciAodmFyIGkgPSAwOyBpIDwgMTY7IGkrKylcclxuXHRcdCB7XHJcblx0XHQgIHRoaXMubWFza2luZ1tpXSA9IDA7XHJcblx0XHQgIHRoaXMucm90YXRlW2ldID0gMDtcclxuXHRcdCB9XHJcblx0fTtcclxuXHJcblx0dGhpcy5nZXRCbG9ja1NpemUgPSBmdW5jdGlvbigpIHtcclxuXHRcdCByZXR1cm4gQmxvY2tTaXplO1xyXG5cdH07XHJcblxyXG5cdHRoaXMuZW5jcnlwdCA9IGZ1bmN0aW9uKHNyYykge1xyXG5cdFx0IHZhciBkc3QgPSBuZXcgQXJyYXkoc3JjLmxlbmd0aCk7XHJcblxyXG5cdFx0IGZvcih2YXIgaSA9IDA7IGkgPCBzcmMubGVuZ3RoOyBpKz04KVxyXG5cdFx0IHtcclxuXHRcdCAgdmFyIGwgPSBzcmNbaV08PDI0IHwgc3JjW2krMV08PDE2IHwgc3JjW2krMl08PDggfCBzcmNbaSszXTtcclxuXHRcdCAgdmFyIHIgPSBzcmNbaSs0XTw8MjQgfCBzcmNbaSs1XTw8MTYgfCBzcmNbaSs2XTw8OCB8IHNyY1tpKzddO1xyXG5cdFx0ICB2YXIgdDtcclxuXHJcblx0XHQgIHQgPSByOyByID0gbF5mMShyLCB0aGlzLm1hc2tpbmdbMF0sIHRoaXMucm90YXRlWzBdKTsgbCA9IHQ7XHJcblx0XHQgIHQgPSByOyByID0gbF5mMihyLCB0aGlzLm1hc2tpbmdbMV0sIHRoaXMucm90YXRlWzFdKTsgbCA9IHQ7XHJcblx0XHQgIHQgPSByOyByID0gbF5mMyhyLCB0aGlzLm1hc2tpbmdbMl0sIHRoaXMucm90YXRlWzJdKTsgbCA9IHQ7XHJcblx0XHQgIHQgPSByOyByID0gbF5mMShyLCB0aGlzLm1hc2tpbmdbM10sIHRoaXMucm90YXRlWzNdKTsgbCA9IHQ7XHJcblxyXG5cdFx0ICB0ID0gcjsgciA9IGxeZjIociwgdGhpcy5tYXNraW5nWzRdLCB0aGlzLnJvdGF0ZVs0XSk7IGwgPSB0O1xyXG5cdFx0ICB0ID0gcjsgciA9IGxeZjMociwgdGhpcy5tYXNraW5nWzVdLCB0aGlzLnJvdGF0ZVs1XSk7IGwgPSB0O1xyXG5cdFx0ICB0ID0gcjsgciA9IGxeZjEociwgdGhpcy5tYXNraW5nWzZdLCB0aGlzLnJvdGF0ZVs2XSk7IGwgPSB0O1xyXG5cdFx0ICB0ID0gcjsgciA9IGxeZjIociwgdGhpcy5tYXNraW5nWzddLCB0aGlzLnJvdGF0ZVs3XSk7IGwgPSB0O1xyXG5cclxuXHRcdCAgdCA9IHI7IHIgPSBsXmYzKHIsIHRoaXMubWFza2luZ1s4XSwgdGhpcy5yb3RhdGVbOF0pOyBsID0gdDtcclxuXHRcdCAgdCA9IHI7IHIgPSBsXmYxKHIsIHRoaXMubWFza2luZ1s5XSwgdGhpcy5yb3RhdGVbOV0pOyBsID0gdDtcclxuXHRcdCAgdCA9IHI7IHIgPSBsXmYyKHIsIHRoaXMubWFza2luZ1sxMF0sIHRoaXMucm90YXRlWzEwXSk7IGwgPSB0O1xyXG5cdFx0ICB0ID0gcjsgciA9IGxeZjMociwgdGhpcy5tYXNraW5nWzExXSwgdGhpcy5yb3RhdGVbMTFdKTsgbCA9IHQ7XHJcblxyXG5cdFx0ICB0ID0gcjsgciA9IGxeZjEociwgdGhpcy5tYXNraW5nWzEyXSwgdGhpcy5yb3RhdGVbMTJdKTsgbCA9IHQ7XHJcblx0XHQgIHQgPSByOyByID0gbF5mMihyLCB0aGlzLm1hc2tpbmdbMTNdLCB0aGlzLnJvdGF0ZVsxM10pOyBsID0gdDtcclxuXHRcdCAgdCA9IHI7IHIgPSBsXmYzKHIsIHRoaXMubWFza2luZ1sxNF0sIHRoaXMucm90YXRlWzE0XSk7IGwgPSB0O1xyXG5cdFx0ICB0ID0gcjsgciA9IGxeZjEociwgdGhpcy5tYXNraW5nWzE1XSwgdGhpcy5yb3RhdGVbMTVdKTsgbCA9IHQ7XHJcblxyXG5cdFx0ICBkc3RbaV0gICA9IChyID4+PiAyNCkmMjU1O1xyXG5cdFx0ICBkc3RbaSsxXSA9IChyID4+PiAxNikmMjU1O1xyXG5cdFx0ICBkc3RbaSsyXSA9IChyID4+PiA4KSYyNTU7XHJcblx0XHQgIGRzdFtpKzNdID0gciYyNTU7XHJcblx0XHQgIGRzdFtpKzRdID0gKGwgPj4+IDI0KSYyNTU7XHJcblx0XHQgIGRzdFtpKzVdID0gKGwgPj4+IDE2KSYyNTU7XHJcblx0XHQgIGRzdFtpKzZdID0gKGwgPj4+IDgpJjI1NTtcclxuXHRcdCAgZHN0W2krN10gPSBsJjI1NTtcclxuXHRcdCB9XHJcblxyXG5cdFx0IHJldHVybiBkc3Q7XHJcblx0fTtcclxuXHRcclxuXHR0aGlzLmRlY3J5cHQgPSBmdW5jdGlvbihzcmMpIHtcclxuXHRcdCB2YXIgZHN0ID0gbmV3IEFycmF5KHNyYy5sZW5ndGgpO1xyXG5cclxuXHRcdCBmb3IodmFyIGkgPSAwOyBpIDwgc3JjLmxlbmd0aDsgaSs9OClcclxuXHRcdCB7XHJcblx0XHQgIHZhciBsID0gc3JjW2ldPDwyNCB8IHNyY1tpKzFdPDwxNiB8IHNyY1tpKzJdPDw4IHwgc3JjW2krM107XHJcblx0XHQgIHZhciByID0gc3JjW2krNF08PDI0IHwgc3JjW2krNV08PDE2IHwgc3JjW2krNl08PDggfCBzcmNbaSs3XTtcclxuXHRcdCAgdmFyIHQ7XHJcblxyXG5cdFx0ICB0ID0gcjsgciA9IGxeZjEociwgdGhpcy5tYXNraW5nWzE1XSwgdGhpcy5yb3RhdGVbMTVdKTsgbCA9IHQ7XHJcblx0XHQgIHQgPSByOyByID0gbF5mMyhyLCB0aGlzLm1hc2tpbmdbMTRdLCB0aGlzLnJvdGF0ZVsxNF0pOyBsID0gdDtcclxuXHRcdCAgdCA9IHI7IHIgPSBsXmYyKHIsIHRoaXMubWFza2luZ1sxM10sIHRoaXMucm90YXRlWzEzXSk7IGwgPSB0O1xyXG5cdFx0ICB0ID0gcjsgciA9IGxeZjEociwgdGhpcy5tYXNraW5nWzEyXSwgdGhpcy5yb3RhdGVbMTJdKTsgbCA9IHQ7XHJcblxyXG5cdFx0ICB0ID0gcjsgciA9IGxeZjMociwgdGhpcy5tYXNraW5nWzExXSwgdGhpcy5yb3RhdGVbMTFdKTsgbCA9IHQ7XHJcblx0XHQgIHQgPSByOyByID0gbF5mMihyLCB0aGlzLm1hc2tpbmdbMTBdLCB0aGlzLnJvdGF0ZVsxMF0pOyBsID0gdDtcclxuXHRcdCAgdCA9IHI7IHIgPSBsXmYxKHIsIHRoaXMubWFza2luZ1s5XSwgdGhpcy5yb3RhdGVbOV0pOyBsID0gdDtcclxuXHRcdCAgdCA9IHI7IHIgPSBsXmYzKHIsIHRoaXMubWFza2luZ1s4XSwgdGhpcy5yb3RhdGVbOF0pOyBsID0gdDtcclxuXHJcblx0XHQgIHQgPSByOyByID0gbF5mMihyLCB0aGlzLm1hc2tpbmdbN10sIHRoaXMucm90YXRlWzddKTsgbCA9IHQ7XHJcblx0XHQgIHQgPSByOyByID0gbF5mMShyLCB0aGlzLm1hc2tpbmdbNl0sIHRoaXMucm90YXRlWzZdKTsgbCA9IHQ7XHJcblx0XHQgIHQgPSByOyByID0gbF5mMyhyLCB0aGlzLm1hc2tpbmdbNV0sIHRoaXMucm90YXRlWzVdKTsgbCA9IHQ7XHJcblx0XHQgIHQgPSByOyByID0gbF5mMihyLCB0aGlzLm1hc2tpbmdbNF0sIHRoaXMucm90YXRlWzRdKTsgbCA9IHQ7XHJcblxyXG5cdFx0ICB0ID0gcjsgciA9IGxeZjEociwgdGhpcy5tYXNraW5nWzNdLCB0aGlzLnJvdGF0ZVszXSk7IGwgPSB0O1xyXG5cdFx0ICB0ID0gcjsgciA9IGxeZjMociwgdGhpcy5tYXNraW5nWzJdLCB0aGlzLnJvdGF0ZVsyXSk7IGwgPSB0O1xyXG5cdFx0ICB0ID0gcjsgciA9IGxeZjIociwgdGhpcy5tYXNraW5nWzFdLCB0aGlzLnJvdGF0ZVsxXSk7IGwgPSB0O1xyXG5cdFx0ICB0ID0gcjsgciA9IGxeZjEociwgdGhpcy5tYXNraW5nWzBdLCB0aGlzLnJvdGF0ZVswXSk7IGwgPSB0O1xyXG5cclxuXHRcdCAgZHN0W2ldICAgPSAociA+Pj4gMjQpJjI1NTtcclxuXHRcdCAgZHN0W2krMV0gPSAociA+Pj4gMTYpJjI1NTtcclxuXHRcdCAgZHN0W2krMl0gPSAociA+Pj4gOCkmMjU1O1xyXG5cdFx0ICBkc3RbaSszXSA9IHImMjU1O1xyXG5cdFx0ICBkc3RbaSs0XSA9IChsID4+PiAyNCkmMjU1O1xyXG5cdFx0ICBkc3RbaSs1XSA9IChsID4+IDE2KSYyNTU7XHJcblx0XHQgIGRzdFtpKzZdID0gKGwgPj4gOCkmMjU1O1xyXG5cdFx0ICBkc3RbaSs3XSA9IGwmMjU1O1xyXG5cdFx0IH1cclxuXHJcblx0XHQgcmV0dXJuIGRzdDtcclxuXHRcdH07XHJcblx0XHR2YXIgc2NoZWR1bGVBID0gbmV3IEFycmF5KDQpO1xyXG5cclxuXHRcdHNjaGVkdWxlQVswXSA9IG5ldyBBcnJheSg0KTtcclxuXHRcdHNjaGVkdWxlQVswXVswXSA9IG5ldyBBcnJheSg0LCAwLCAweGQsIDB4ZiwgMHhjLCAweGUsIDB4OCk7XHJcblx0XHRzY2hlZHVsZUFbMF1bMV0gPSBuZXcgQXJyYXkoNSwgMiwgMTYgKyAwLCAxNiArIDIsIDE2ICsgMSwgMTYgKyAzLCAweGEpO1xyXG5cdFx0c2NoZWR1bGVBWzBdWzJdID0gbmV3IEFycmF5KDYsIDMsIDE2ICsgNywgMTYgKyA2LCAxNiArIDUsIDE2ICsgNCwgOSk7XHJcblx0XHRzY2hlZHVsZUFbMF1bM10gPSBuZXcgQXJyYXkoNywgMSwgMTYgKyAweGEsIDE2ICsgOSwgMTYgKyAweGIsIDE2ICsgOCwgMHhiKTtcclxuXHJcblx0XHRzY2hlZHVsZUFbMV0gPSBuZXcgQXJyYXkoNCk7XHJcblx0XHRzY2hlZHVsZUFbMV1bMF0gPSBuZXcgQXJyYXkoMCwgNiwgMTYgKyA1LCAxNiArIDcsIDE2ICsgNCwgMTYgKyA2LCAxNiArIDApO1xyXG5cdFx0c2NoZWR1bGVBWzFdWzFdID0gbmV3IEFycmF5KDEsIDQsIDAsIDIsIDEsIDMsIDE2ICsgMik7XHJcblx0XHRzY2hlZHVsZUFbMV1bMl0gPSBuZXcgQXJyYXkoMiwgNSwgNywgNiwgNSwgNCwgMTYgKyAxKTtcclxuXHRcdHNjaGVkdWxlQVsxXVszXSA9IG5ldyBBcnJheSgzLCA3LCAweGEsIDksIDB4YiwgOCwgMTYgKyAzKTtcclxuXHJcblx0XHRzY2hlZHVsZUFbMl0gPSBuZXcgQXJyYXkoNCk7XHJcblx0XHRzY2hlZHVsZUFbMl1bMF0gPSBuZXcgQXJyYXkoNCwgMCwgMHhkLCAweGYsIDB4YywgMHhlLCA4KTtcclxuXHRcdHNjaGVkdWxlQVsyXVsxXSA9IG5ldyBBcnJheSg1LCAyLCAxNiArIDAsIDE2ICsgMiwgMTYgKyAxLCAxNiArIDMsIDB4YSk7XHJcblx0XHRzY2hlZHVsZUFbMl1bMl0gPSBuZXcgQXJyYXkoNiwgMywgMTYgKyA3LCAxNiArIDYsIDE2ICsgNSwgMTYgKyA0LCA5KTtcclxuXHRcdHNjaGVkdWxlQVsyXVszXSA9IG5ldyBBcnJheSg3LCAxLCAxNiArIDB4YSwgMTYgKyA5LCAxNiArIDB4YiwgMTYgKyA4LCAweGIpO1xyXG5cclxuXHJcblx0XHRzY2hlZHVsZUFbM10gPSBuZXcgQXJyYXkoNCk7XHJcblx0XHRzY2hlZHVsZUFbM11bMF0gPSBuZXcgQXJyYXkoMCwgNiwgMTYgKyA1LCAxNiArIDcsIDE2ICsgNCwgMTYgKyA2LCAxNiArIDApO1xyXG5cdFx0c2NoZWR1bGVBWzNdWzFdID0gbmV3IEFycmF5KDEsIDQsIDAsIDIsIDEsIDMsIDE2ICsgMik7XHJcblx0XHRzY2hlZHVsZUFbM11bMl0gPSBuZXcgQXJyYXkoMiwgNSwgNywgNiwgNSwgNCwgMTYgKyAxKTtcclxuXHRcdHNjaGVkdWxlQVszXVszXSA9IG5ldyBBcnJheSgzLCA3LCAweGEsIDksIDB4YiwgOCwgMTYgKyAzKTtcclxuXHJcblx0XHR2YXIgc2NoZWR1bGVCID0gbmV3IEFycmF5KDQpO1xyXG5cclxuXHRcdHNjaGVkdWxlQlswXSA9IG5ldyBBcnJheSg0KTtcclxuXHRcdHNjaGVkdWxlQlswXVswXSA9IG5ldyBBcnJheSgxNiArIDgsIDE2ICsgOSwgMTYgKyA3LCAxNiArIDYsIDE2ICsgMik7XHJcblx0XHRzY2hlZHVsZUJbMF1bMV0gPSBuZXcgQXJyYXkoMTYgKyAweGEsIDE2ICsgMHhiLCAxNiArIDUsIDE2ICsgNCwgMTYgKyA2KTtcclxuXHRcdHNjaGVkdWxlQlswXVsyXSA9IG5ldyBBcnJheSgxNiArIDB4YywgMTYgKyAweGQsIDE2ICsgMywgMTYgKyAyLCAxNiArIDkpO1xyXG5cdFx0c2NoZWR1bGVCWzBdWzNdID0gbmV3IEFycmF5KDE2ICsgMHhlLCAxNiArIDB4ZiwgMTYgKyAxLCAxNiArIDAsIDE2ICsgMHhjKTtcclxuXHJcblx0XHRzY2hlZHVsZUJbMV0gPSBuZXcgQXJyYXkoNCk7XHJcblx0XHRzY2hlZHVsZUJbMV1bMF0gPSBuZXcgQXJyYXkoMywgMiwgMHhjLCAweGQsIDgpO1xyXG5cdFx0c2NoZWR1bGVCWzFdWzFdID0gbmV3IEFycmF5KDEsIDAsIDB4ZSwgMHhmLCAweGQpO1xyXG5cdFx0c2NoZWR1bGVCWzFdWzJdID0gbmV3IEFycmF5KDcsIDYsIDgsIDksIDMpO1xyXG5cdFx0c2NoZWR1bGVCWzFdWzNdID0gbmV3IEFycmF5KDUsIDQsIDB4YSwgMHhiLCA3KTtcclxuXHJcblxyXG5cdFx0c2NoZWR1bGVCWzJdID0gbmV3IEFycmF5KDQpO1xyXG5cdFx0c2NoZWR1bGVCWzJdWzBdID0gbmV3IEFycmF5KDE2ICsgMywgMTYgKyAyLCAxNiArIDB4YywgMTYgKyAweGQsIDE2ICsgOSk7XHJcblx0XHRzY2hlZHVsZUJbMl1bMV0gPSBuZXcgQXJyYXkoMTYgKyAxLCAxNiArIDAsIDE2ICsgMHhlLCAxNiArIDB4ZiwgMTYgKyAweGMpO1xyXG5cdFx0c2NoZWR1bGVCWzJdWzJdID0gbmV3IEFycmF5KDE2ICsgNywgMTYgKyA2LCAxNiArIDgsIDE2ICsgOSwgMTYgKyAyKTtcclxuXHRcdHNjaGVkdWxlQlsyXVszXSA9IG5ldyBBcnJheSgxNiArIDUsIDE2ICsgNCwgMTYgKyAweGEsIDE2ICsgMHhiLCAxNiArIDYpO1xyXG5cclxuXHJcblx0XHRzY2hlZHVsZUJbM10gPSBuZXcgQXJyYXkoNCk7XHJcblx0XHRzY2hlZHVsZUJbM11bMF0gPSBuZXcgQXJyYXkoOCwgOSwgNywgNiwgMyk7XHJcblx0XHRzY2hlZHVsZUJbM11bMV0gPSBuZXcgQXJyYXkoMHhhLCAweGIsIDUsIDQsIDcpO1xyXG5cdFx0c2NoZWR1bGVCWzNdWzJdID0gbmV3IEFycmF5KDB4YywgMHhkLCAzLCAyLCA4KTtcclxuXHRcdHNjaGVkdWxlQlszXVszXSA9IG5ldyBBcnJheSgweGUsIDB4ZiwgMSwgMCwgMHhkKTtcclxuXHJcblx0XHQvLyBjaGFuZ2VkICdpbicgdG8gJ2lubicgKGluIGphdmFzY3JpcHQgJ2luJyBpcyBhIHJlc2VydmVkIHdvcmQpXHJcblx0XHR0aGlzLmtleVNjaGVkdWxlID0gZnVuY3Rpb24oaW5uKVxyXG5cdFx0e1xyXG5cdFx0IHZhciB0ID0gbmV3IEFycmF5KDgpO1xyXG5cdFx0IHZhciBrID0gbmV3IEFycmF5KDMyKTtcclxuXHJcblx0XHQgZm9yICh2YXIgaSA9IDA7IGkgPCA0OyBpKyspXHJcblx0XHQge1xyXG5cdFx0ICB2YXIgaiA9IGkgKiA0O1xyXG5cdFx0ICB0W2ldID0gaW5uW2pdPDwyNCB8IGlubltqKzFdPDwxNiB8IGlubltqKzJdPDw4IHwgaW5uW2orM107XHJcblx0XHQgfVxyXG5cclxuXHRcdCB2YXIgeCA9IFs2LCA3LCA0LCA1XTtcclxuXHRcdCB2YXIga2kgPSAwO1xyXG5cclxuXHRcdCBmb3IgKHZhciBoYWxmID0gMDsgaGFsZiA8IDI7IGhhbGYrKylcclxuXHRcdCB7XHJcblx0XHQgIGZvciAodmFyIHJvdW5kID0gMDsgcm91bmQgPCA0OyByb3VuZCsrKVxyXG5cdFx0ICB7XHJcblx0XHQgICBmb3IgKHZhciBqID0gMDsgaiA8IDQ7IGorKylcclxuXHRcdCAgIHtcclxuXHRcdCAgICB2YXIgYSA9IHNjaGVkdWxlQVtyb3VuZF1bal07XHJcblx0XHQgICAgdmFyIHcgPSB0W2FbMV1dO1xyXG5cclxuXHRcdCAgICB3IF49IHNCb3hbNF1bKHRbYVsyXT4+PjJdPj4+KDI0LTgqKGFbMl0mMykpKSYweGZmXTtcclxuXHRcdCAgICB3IF49IHNCb3hbNV1bKHRbYVszXT4+PjJdPj4+KDI0LTgqKGFbM10mMykpKSYweGZmXTtcclxuXHRcdCAgICB3IF49IHNCb3hbNl1bKHRbYVs0XT4+PjJdPj4+KDI0LTgqKGFbNF0mMykpKSYweGZmXTtcclxuXHRcdCAgICB3IF49IHNCb3hbN11bKHRbYVs1XT4+PjJdPj4+KDI0LTgqKGFbNV0mMykpKSYweGZmXTtcclxuXHRcdCAgICB3IF49IHNCb3hbeFtqXV1bKHRbYVs2XT4+PjJdPj4+KDI0LTgqKGFbNl0mMykpKSYweGZmXTtcclxuXHRcdCAgICB0W2FbMF1dID0gdztcclxuXHRcdCAgIH1cclxuXHJcblx0XHQgICBmb3IgKHZhciBqID0gMDsgaiA8IDQ7IGorKylcclxuXHRcdCAgIHtcclxuXHRcdCAgICB2YXIgYiA9IHNjaGVkdWxlQltyb3VuZF1bal07XHJcblx0XHQgICAgdmFyIHcgPSBzQm94WzRdWyh0W2JbMF0+Pj4yXT4+PigyNC04KihiWzBdJjMpKSkmMHhmZl07XHJcblxyXG5cdFx0ICAgIHcgXj0gc0JveFs1XVsodFtiWzFdPj4+Ml0+Pj4oMjQtOCooYlsxXSYzKSkpJjB4ZmZdO1xyXG5cdFx0ICAgIHcgXj0gc0JveFs2XVsodFtiWzJdPj4+Ml0+Pj4oMjQtOCooYlsyXSYzKSkpJjB4ZmZdO1xyXG5cdFx0ICAgIHcgXj0gc0JveFs3XVsodFtiWzNdPj4+Ml0+Pj4oMjQtOCooYlszXSYzKSkpJjB4ZmZdO1xyXG5cdFx0ICAgIHcgXj0gc0JveFs0K2pdWyh0W2JbNF0+Pj4yXT4+PigyNC04KihiWzRdJjMpKSkmMHhmZl07XHJcblx0XHQgICAga1traV0gPSB3O1xyXG5cdFx0ICAgIGtpKys7XHJcblx0XHQgICB9XHJcblx0XHQgIH1cclxuXHRcdCB9XHJcblxyXG5cdFx0IGZvciAodmFyIGkgPSAwOyBpIDwgMTY7IGkrKylcclxuXHRcdCB7XHJcblx0XHQgIHRoaXMubWFza2luZ1tpXSA9IGtbaV07XHJcblx0XHQgIHRoaXMucm90YXRlW2ldICA9IGtbMTYraV0gJiAweDFmO1xyXG5cdFx0IH1cclxuXHRcdH07XHJcblxyXG5cdFx0Ly8gVGhlc2UgYXJlIHRoZSB0aHJlZSAnZicgZnVuY3Rpb25zLiBTZWUgUkZDIDIxNDQsIHNlY3Rpb24gMi4yLlxyXG5cclxuXHRcdGZ1bmN0aW9uIGYxKGQsIG0sIHIpXHJcblx0XHR7XHJcblx0XHQgdmFyIHQgPSBtICsgZDtcclxuXHRcdCB2YXIgSSA9ICh0IDw8IHIpIHwgKHQgPj4+ICgzMiAtIHIpKTtcclxuXHRcdCByZXR1cm4gKChzQm94WzBdW0k+Pj4yNF0gXiBzQm94WzFdWyhJPj4+MTYpJjI1NV0pIC0gc0JveFsyXVsoST4+PjgpJjI1NV0pICsgc0JveFszXVtJJjI1NV07XHJcblx0XHR9XHJcblxyXG5cdFx0ZnVuY3Rpb24gZjIoZCwgbSwgcilcclxuXHRcdHtcclxuXHRcdCB2YXIgdCA9IG0gXiBkO1xyXG5cdFx0IHZhciBJID0gKHQgPDwgcikgfCAodCA+Pj4gKDMyIC0gcikpO1xyXG5cdFx0IHJldHVybiAoKHNCb3hbMF1bST4+PjI0XSAtIHNCb3hbMV1bKEk+Pj4xNikmMjU1XSkgKyBzQm94WzJdWyhJPj4+OCkmMjU1XSkgXiBzQm94WzNdW0kmMjU1XTtcclxuXHRcdH1cclxuXHJcblx0XHRmdW5jdGlvbiBmMyhkLCBtLCByKVxyXG5cdFx0e1xyXG5cdFx0IHZhciB0ID0gbSAtIGQ7XHJcblx0XHQgdmFyIEkgPSAodCA8PCByKSB8ICh0ID4+PiAoMzIgLSByKSk7XHJcblx0XHQgcmV0dXJuICgoc0JveFswXVtJPj4+MjRdICsgc0JveFsxXVsoST4+PjE2KSYyNTVdKSBeIHNCb3hbMl1bKEk+Pj44KSYyNTVdKSAtIHNCb3hbM11bSSYyNTVdO1xyXG5cdFx0fVxyXG5cclxuXHRcdHZhciBzQm94ID0gbmV3IEFycmF5KDgpO1xyXG5cdFx0c0JveFswXSA9IG5ldyBBcnJheShcclxuXHRcdCAgMHgzMGZiNDBkNCwgMHg5ZmEwZmYwYiwgMHg2YmVjY2QyZiwgMHgzZjI1OGM3YSwgMHgxZTIxM2YyZiwgMHg5YzAwNGRkMywgMHg2MDAzZTU0MCwgMHhjZjlmYzk0OSxcclxuXHRcdCAgMHhiZmQ0YWYyNywgMHg4OGJiYmRiNSwgMHhlMjAzNDA5MCwgMHg5OGQwOTY3NSwgMHg2ZTYzYTBlMCwgMHgxNWMzNjFkMiwgMHhjMmU3NjYxZCwgMHgyMmQ0ZmY4ZSxcclxuXHRcdCAgMHgyODY4M2I2ZiwgMHhjMDdmZDA1OSwgMHhmZjIzNzljOCwgMHg3NzVmNTBlMiwgMHg0M2MzNDBkMywgMHhkZjJmODY1NiwgMHg4ODdjYTQxYSwgMHhhMmQyYmQyZCxcclxuXHRcdCAgMHhhMWM5ZTBkNiwgMHgzNDZjNDgxOSwgMHg2MWI3NmQ4NywgMHgyMjU0MGYyZiwgMHgyYWJlMzJlMSwgMHhhYTU0MTY2YiwgMHgyMjU2OGUzYSwgMHhhMmQzNDFkMCxcclxuXHRcdCAgMHg2NmRiNDBjOCwgMHhhNzg0MzkyZiwgMHgwMDRkZmYyZiwgMHgyZGI5ZDJkZSwgMHg5Nzk0M2ZhYywgMHg0YTk3YzFkOCwgMHg1Mjc2NDRiNywgMHhiNWY0MzdhNyxcclxuXHRcdCAgMHhiODJjYmFlZiwgMHhkNzUxZDE1OSwgMHg2ZmY3ZjBlZCwgMHg1YTA5N2ExZiwgMHg4MjdiNjhkMCwgMHg5MGVjZjUyZSwgMHgyMmIwYzA1NCwgMHhiYzhlNTkzNSxcclxuXHRcdCAgMHg0YjZkMmY3ZiwgMHg1MGJiNjRhMiwgMHhkMjY2NDkxMCwgMHhiZWU1ODEyZCwgMHhiNzMzMjI5MCwgMHhlOTNiMTU5ZiwgMHhiNDhlZTQxMSwgMHg0YmZmMzQ1ZCxcclxuXHRcdCAgMHhmZDQ1YzI0MCwgMHhhZDMxOTczZiwgMHhjNGY2ZDAyZSwgMHg1NWZjODE2NSwgMHhkNWIxY2FhZCwgMHhhMWFjMmRhZSwgMHhhMmQ0Yjc2ZCwgMHhjMTliMGM1MCxcclxuXHRcdCAgMHg4ODIyNDBmMiwgMHgwYzZlNGYzOCwgMHhhNGU0YmZkNywgMHg0ZjViYTI3MiwgMHg1NjRjMWQyZiwgMHhjNTljNTMxOSwgMHhiOTQ5ZTM1NCwgMHhiMDQ2NjlmZSxcclxuXHRcdCAgMHhiMWI2YWI4YSwgMHhjNzEzNThkZCwgMHg2Mzg1YzU0NSwgMHgxMTBmOTM1ZCwgMHg1NzUzOGFkNSwgMHg2YTM5MDQ5MywgMHhlNjNkMzdlMCwgMHgyYTU0ZjZiMyxcclxuXHRcdCAgMHgzYTc4N2Q1ZiwgMHg2Mjc2YTBiNSwgMHgxOWE2ZmNkZiwgMHg3YTQyMjA2YSwgMHgyOWY5ZDRkNSwgMHhmNjFiMTg5MSwgMHhiYjcyMjc1ZSwgMHhhYTUwODE2NyxcclxuXHRcdCAgMHgzODkwMTA5MSwgMHhjNmI1MDVlYiwgMHg4NGM3Y2I4YywgMHgyYWQ3NWEwZiwgMHg4NzRhMTQyNywgMHhhMmQxOTM2YiwgMHgyYWQyODZhZiwgMHhhYTU2ZDI5MSxcclxuXHRcdCAgMHhkNzg5NDM2MCwgMHg0MjVjNzUwZCwgMHg5M2IzOWUyNiwgMHgxODcxODRjOSwgMHg2YzAwYjMyZCwgMHg3M2UyYmIxNCwgMHhhMGJlYmMzYywgMHg1NDYyMzc3OSxcclxuXHRcdCAgMHg2NDQ1OWVhYiwgMHgzZjMyOGI4MiwgMHg3NzE4Y2Y4MiwgMHg1OWEyY2VhNiwgMHgwNGVlMDAyZSwgMHg4OWZlNzhlNiwgMHgzZmFiMDk1MCwgMHgzMjVmZjZjMixcclxuXHRcdCAgMHg4MTM4M2YwNSwgMHg2OTYzYzVjOCwgMHg3NmNiNWFkNiwgMHhkNDk5NzRjOSwgMHhjYTE4MGRjZiwgMHgzODA3ODJkNSwgMHhjN2ZhNWNmNiwgMHg4YWMzMTUxMSxcclxuXHRcdCAgMHgzNWU3OWUxMywgMHg0N2RhOTFkMCwgMHhmNDBmOTA4NiwgMHhhN2UyNDE5ZSwgMHgzMTM2NjI0MSwgMHgwNTFlZjQ5NSwgMHhhYTU3M2IwNCwgMHg0YTgwNWQ4ZCxcclxuXHRcdCAgMHg1NDgzMDBkMCwgMHgwMDMyMmEzYywgMHhiZjY0Y2RkZiwgMHhiYTU3YTY4ZSwgMHg3NWM2MzcyYiwgMHg1MGFmZDM0MSwgMHhhN2MxMzI3NSwgMHg5MTVhMGJmNSxcclxuXHRcdCAgMHg2YjU0YmZhYiwgMHgyYjBiMTQyNiwgMHhhYjRjYzlkNywgMHg0NDljY2Q4MiwgMHhmN2ZiZjI2NSwgMHhhYjg1YzVmMywgMHgxYjU1ZGI5NCwgMHhhYWQ0ZTMyNCxcclxuXHRcdCAgMHhjZmE0YmQzZiwgMHgyZGVhYTNlMiwgMHg5ZTIwNGQwMiwgMHhjOGJkMjVhYywgMHhlYWRmNTViMywgMHhkNWJkOWU5OCwgMHhlMzEyMzFiMiwgMHgyYWQ1YWQ2YyxcclxuXHRcdCAgMHg5NTQzMjlkZSwgMHhhZGJlNDUyOCwgMHhkODcxMGY2OSwgMHhhYTUxYzkwZiwgMHhhYTc4NmJmNiwgMHgyMjUxM2YxZSwgMHhhYTUxYTc5YiwgMHgyYWQzNDRjYyxcclxuXHRcdCAgMHg3YjVhNDFmMCwgMHhkMzdjZmJhZCwgMHgxYjA2OTUwNSwgMHg0MWVjZTQ5MSwgMHhiNGMzMzJlNiwgMHgwMzIyNjhkNCwgMHhjOTYwMGFjYywgMHhjZTM4N2U2ZCxcclxuXHRcdCAgMHhiZjZiYjE2YywgMHg2YTcwZmI3OCwgMHgwZDAzZDljOSwgMHhkNGRmMzlkZSwgMHhlMDEwNjNkYSwgMHg0NzM2ZjQ2NCwgMHg1YWQzMjhkOCwgMHhiMzQ3Y2M5NixcclxuXHRcdCAgMHg3NWJiMGZjMywgMHg5ODUxMWJmYiwgMHg0ZmZiY2MzNSwgMHhiNThiY2Y2YSwgMHhlMTFmMGFiYywgMHhiZmM1ZmU0YSwgMHhhNzBhZWMxMCwgMHhhYzM5NTcwYSxcclxuXHRcdCAgMHgzZjA0NDQyZiwgMHg2MTg4YjE1MywgMHhlMDM5N2EyZSwgMHg1NzI3Y2I3OSwgMHg5Y2ViNDE4ZiwgMHgxY2FjZDY4ZCwgMHgyYWQzN2M5NiwgMHgwMTc1Y2I5ZCxcclxuXHRcdCAgMHhjNjlkZmYwOSwgMHhjNzViNjVmMCwgMHhkOWRiNDBkOCwgMHhlYzBlNzc3OSwgMHg0NzQ0ZWFkNCwgMHhiMTFjMzI3NCwgMHhkZDI0Y2I5ZSwgMHg3ZTFjNTRiZCxcclxuXHRcdCAgMHhmMDExNDRmOSwgMHhkMjI0MGViMSwgMHg5Njc1YjNmZCwgMHhhM2FjMzc1NSwgMHhkNDdjMjdhZiwgMHg1MWM4NWY0ZCwgMHg1NjkwNzU5NiwgMHhhNWJiMTVlNixcclxuXHRcdCAgMHg1ODAzMDRmMCwgMHhjYTA0MmNmMSwgMHgwMTFhMzdlYSwgMHg4ZGJmYWFkYiwgMHgzNWJhM2U0YSwgMHgzNTI2ZmZhMCwgMHhjMzdiNGQwOSwgMHhiYzMwNmVkOSxcclxuXHRcdCAgMHg5OGE1MjY2NiwgMHg1NjQ4ZjcyNSwgMHhmZjVlNTY5ZCwgMHgwY2VkNjNkMCwgMHg3YzYzYjJjZiwgMHg3MDBiNDVlMSwgMHhkNWVhNTBmMSwgMHg4NWE5Mjg3MixcclxuXHRcdCAgMHhhZjFmYmRhNywgMHhkNDIzNDg3MCwgMHhhNzg3MGJmMywgMHgyZDNiNGQ3OSwgMHg0MmUwNDE5OCwgMHgwY2QwZWRlNywgMHgyNjQ3MGRiOCwgMHhmODgxODE0YyxcclxuXHRcdCAgMHg0NzRkNmFkNywgMHg3YzBjNWU1YywgMHhkMTIzMTk1OSwgMHgzODFiNzI5OCwgMHhmNWQyZjRkYiwgMHhhYjgzODY1MywgMHg2ZTJmMWUyMywgMHg4MzcxOWM5ZSxcclxuXHRcdCAgMHhiZDkxZTA0NiwgMHg5YTU2NDU2ZSwgMHhkYzM5MjAwYywgMHgyMGM4YzU3MSwgMHg5NjJiZGExYywgMHhlMWU2OTZmZiwgMHhiMTQxYWIwOCwgMHg3Y2NhODliOSxcclxuXHRcdCAgMHgxYTY5ZTc4MywgMHgwMmNjNDg0MywgMHhhMmY3YzU3OSwgMHg0MjllZjQ3ZCwgMHg0MjdiMTY5YywgMHg1YWM5ZjA0OSwgMHhkZDhmMGYwMCwgMHg1YzgxNjViZik7XHJcblxyXG5cdFx0c0JveFsxXSA9IG5ldyBBcnJheShcclxuXHRcdCAgMHgxZjIwMTA5NCwgMHhlZjBiYTc1YiwgMHg2OWUzY2Y3ZSwgMHgzOTNmNDM4MCwgMHhmZTYxY2Y3YSwgMHhlZWM1MjA3YSwgMHg1NTg4OWM5NCwgMHg3MmZjMDY1MSxcclxuXHRcdCAgMHhhZGE3ZWY3OSwgMHg0ZTFkNzIzNSwgMHhkNTVhNjNjZSwgMHhkZTA0MzZiYSwgMHg5OWM0MzBlZiwgMHg1ZjBjMDc5NCwgMHgxOGRjZGI3ZCwgMHhhMWQ2ZWZmMyxcclxuXHRcdCAgMHhhMGI1MmY3YiwgMHg1OWU4MzYwNSwgMHhlZTE1YjA5NCwgMHhlOWZmZDkwOSwgMHhkYzQ0MDA4NiwgMHhlZjk0NDQ1OSwgMHhiYTgzY2NiMywgMHhlMGMzY2RmYixcclxuXHRcdCAgMHhkMWRhNDE4MSwgMHgzYjA5MmFiMSwgMHhmOTk3ZjFjMSwgMHhhNWU2Y2Y3YiwgMHgwMTQyMGRkYiwgMHhlNGU3ZWY1YiwgMHgyNWExZmY0MSwgMHhlMTgwZjgwNixcclxuXHRcdCAgMHgxZmM0MTA4MCwgMHgxNzliZWU3YSwgMHhkMzdhYzZhOSwgMHhmZTU4MzBhNCwgMHg5OGRlOGI3ZiwgMHg3N2U4M2Y0ZSwgMHg3OTkyOTI2OSwgMHgyNGZhOWY3YixcclxuXHRcdCAgMHhlMTEzYzg1YiwgMHhhY2M0MDA4MywgMHhkNzUwMzUyNSwgMHhmN2VhNjE1ZiwgMHg2MjE0MzE1NCwgMHgwZDU1NGI2MywgMHg1ZDY4MTEyMSwgMHhjODY2YzM1OSxcclxuXHRcdCAgMHgzZDYzY2Y3MywgMHhjZWUyMzRjMCwgMHhkNGQ4N2U4NywgMHg1YzY3MmIyMSwgMHgwNzFmNjE4MSwgMHgzOWY3NjI3ZiwgMHgzNjFlMzA4NCwgMHhlNGViNTczYixcclxuXHRcdCAgMHg2MDJmNjRhNCwgMHhkNjNhY2Q5YywgMHgxYmJjNDYzNSwgMHg5ZTgxMDMyZCwgMHgyNzAxZjUwYywgMHg5OTg0N2FiNCwgMHhhMGUzZGY3OSwgMHhiYTZjZjM4YyxcclxuXHRcdCAgMHgxMDg0MzA5NCwgMHgyNTM3YTk1ZSwgMHhmNDZmNmZmZSwgMHhhMWZmM2IxZiwgMHgyMDhjZmI2YSwgMHg4ZjQ1OGM3NCwgMHhkOWUwYTIyNywgMHg0ZWM3M2EzNCxcclxuXHRcdCAgMHhmYzg4NGY2OSwgMHgzZTRkZThkZiwgMHhlZjBlMDA4OCwgMHgzNTU5NjQ4ZCwgMHg4YTQ1Mzg4YywgMHgxZDgwNDM2NiwgMHg3MjFkOWJmZCwgMHhhNTg2ODRiYixcclxuXHRcdCAgMHhlODI1NjMzMywgMHg4NDRlODIxMiwgMHgxMjhkODA5OCwgMHhmZWQzM2ZiNCwgMHhjZTI4MGFlMSwgMHgyN2UxOWJhNSwgMHhkNWE2YzI1MiwgMHhlNDk3NTRiZCxcclxuXHRcdCAgMHhjNWQ2NTVkZCwgMHhlYjY2NzA2NCwgMHg3Nzg0MGI0ZCwgMHhhMWI2YTgwMSwgMHg4NGRiMjZhOSwgMHhlMGI1NjcxNCwgMHgyMWYwNDNiNywgMHhlNWQwNTg2MCxcclxuXHRcdCAgMHg1NGYwMzA4NCwgMHgwNjZmZjQ3MiwgMHhhMzFhYTE1MywgMHhkYWRjNDc1NSwgMHhiNTYyNWRiZiwgMHg2ODU2MWJlNiwgMHg4M2NhNmI5NCwgMHgyZDZlZDIzYixcclxuXHRcdCAgMHhlY2NmMDFkYiwgMHhhNmQzZDBiYSwgMHhiNjgwM2Q1YywgMHhhZjc3YTcwOSwgMHgzM2I0YTM0YywgMHgzOTdiYzhkNiwgMHg1ZWUyMmI5NSwgMHg1ZjBlNTMwNCxcclxuXHRcdCAgMHg4MWVkNmY2MSwgMHgyMGU3NDM2NCwgMHhiNDVlMTM3OCwgMHhkZTE4NjM5YiwgMHg4ODFjYTEyMiwgMHhiOTY3MjZkMSwgMHg4MDQ5YTdlOCwgMHgyMmI3ZGE3YixcclxuXHRcdCAgMHg1ZTU1MmQyNSwgMHg1MjcyZDIzNywgMHg3OWQyOTUxYywgMHhjNjBkODk0YywgMHg0ODhjYjQwMiwgMHgxYmE0ZmU1YiwgMHhhNGIwOWY2YiwgMHgxY2E4MTVjZixcclxuXHRcdCAgMHhhMjBjMzAwNSwgMHg4ODcxZGY2MywgMHhiOWRlMmZjYiwgMHgwY2M2YzllOSwgMHgwYmVlZmY1MywgMHhlMzIxNDUxNywgMHhiNDU0MjgzNSwgMHg5ZjYzMjkzYyxcclxuXHRcdCAgMHhlZTQxZTcyOSwgMHg2ZTFkMmQ3YywgMHg1MDA0NTI4NiwgMHgxZTY2ODVmMywgMHhmMzM0MDFjNiwgMHgzMGEyMmM5NSwgMHgzMWE3MDg1MCwgMHg2MDkzMGYxMyxcclxuXHRcdCAgMHg3M2Y5ODQxNywgMHhhMTI2OTg1OSwgMHhlYzY0NWM0NCwgMHg1MmM4NzdhOSwgMHhjZGZmMzNhNiwgMHhhMDJiMTc0MSwgMHg3Y2JhZDlhMiwgMHgyMTgwMDM2ZixcclxuXHRcdCAgMHg1MGQ5OWMwOCwgMHhjYjNmNDg2MSwgMHhjMjZiZDc2NSwgMHg2NGEzZjZhYiwgMHg4MDM0MjY3NiwgMHgyNWE3NWU3YiwgMHhlNGU2ZDFmYywgMHgyMGM3MTBlNixcclxuXHRcdCAgMHhjZGYwYjY4MCwgMHgxNzg0NGQzYiwgMHgzMWVlZjg0ZCwgMHg3ZTA4MjRlNCwgMHgyY2NiNDllYiwgMHg4NDZhM2JhZSwgMHg4ZmY3Nzg4OCwgMHhlZTVkNjBmNixcclxuXHRcdCAgMHg3YWY3NTY3MywgMHgyZmRkNWNkYiwgMHhhMTE2MzFjMSwgMHgzMGY2NmY0MywgMHhiM2ZhZWM1NCwgMHgxNTdmZDdmYSwgMHhlZjg1NzljYywgMHhkMTUyZGU1OCxcclxuXHRcdCAgMHhkYjJmZmQ1ZSwgMHg4ZjMyY2UxOSwgMHgzMDZhZjk3YSwgMHgwMmYwM2VmOCwgMHg5OTMxOWFkNSwgMHhjMjQyZmEwZiwgMHhhN2UzZWJiMCwgMHhjNjhlNDkwNixcclxuXHRcdCAgMHhiOGRhMjMwYywgMHg4MDgyMzAyOCwgMHhkY2RlZjNjOCwgMHhkMzVmYjE3MSwgMHgwODhhMWJjOCwgMHhiZWMwYzU2MCwgMHg2MWEzYzllOCwgMHhiY2E4ZjU0ZCxcclxuXHRcdCAgMHhjNzJmZWZmYSwgMHgyMjgyMmU5OSwgMHg4MmM1NzBiNCwgMHhkOGQ5NGU4OSwgMHg4YjFjMzRiYywgMHgzMDFlMTZlNiwgMHgyNzNiZTk3OSwgMHhiMGZmZWFhNixcclxuXHRcdCAgMHg2MWQ5YjhjNiwgMHgwMGIyNDg2OSwgMHhiN2ZmY2UzZiwgMHgwOGRjMjgzYiwgMHg0M2RhZjY1YSwgMHhmN2UxOTc5OCwgMHg3NjE5YjcyZiwgMHg4ZjFjOWJhNCxcclxuXHRcdCAgMHhkYzg2MzdhMCwgMHgxNmE3ZDNiMSwgMHg5ZmMzOTNiNywgMHhhNzEzNmVlYiwgMHhjNmJjYzYzZSwgMHgxYTUxMzc0MiwgMHhlZjY4MjhiYywgMHg1MjAzNjVkNixcclxuXHRcdCAgMHgyZDZhNzdhYiwgMHgzNTI3ZWQ0YiwgMHg4MjFmZDIxNiwgMHgwOTVjNmUyZSwgMHhkYjkyZjJmYiwgMHg1ZWVhMjljYiwgMHgxNDU4OTJmNSwgMHg5MTU4NGY3ZixcclxuXHRcdCAgMHg1NDgzNjk3YiwgMHgyNjY3YThjYywgMHg4NTE5NjA0OCwgMHg4YzRiYWNlYSwgMHg4MzM4NjBkNCwgMHgwZDIzZTBmOSwgMHg2YzM4N2U4YSwgMHgwYWU2ZDI0OSxcclxuXHRcdCAgMHhiMjg0NjAwYywgMHhkODM1NzMxZCwgMHhkY2IxYzY0NywgMHhhYzRjNTZlYSwgMHgzZWJkODFiMywgMHgyMzBlYWJiMCwgMHg2NDM4YmM4NywgMHhmMGI1YjFmYSxcclxuXHRcdCAgMHg4ZjVlYTJiMywgMHhmYzE4NDY0MiwgMHgwYTAzNmI3YSwgMHg0ZmIwODliZCwgMHg2NDlkYTU4OSwgMHhhMzQ1NDE1ZSwgMHg1YzAzODMyMywgMHgzZTVkM2JiOSxcclxuXHRcdCAgMHg0M2Q3OTU3MiwgMHg3ZTZkZDA3YywgMHgwNmRmZGYxZSwgMHg2YzZjYzRlZiwgMHg3MTYwYTUzOSwgMHg3M2JmYmU3MCwgMHg4Mzg3NzYwNSwgMHg0NTIzZWNmMSk7XHJcblxyXG5cdFx0c0JveFsyXSA9IG5ldyBBcnJheShcclxuXHRcdCAgMHg4ZGVmYzI0MCwgMHgyNWZhNWQ5ZiwgMHhlYjkwM2RiZiwgMHhlODEwYzkwNywgMHg0NzYwN2ZmZiwgMHgzNjlmZTQ0YiwgMHg4YzFmYzY0NCwgMHhhZWNlY2E5MCxcclxuXHRcdCAgMHhiZWIxZjliZiwgMHhlZWZiY2FlYSwgMHhlOGNmMTk1MCwgMHg1MWRmMDdhZSwgMHg5MjBlODgwNiwgMHhmMGFkMDU0OCwgMHhlMTNjOGQ4MywgMHg5MjcwMTBkNSxcclxuXHRcdCAgMHgxMTEwN2Q5ZiwgMHgwNzY0N2RiOSwgMHhiMmUzZTRkNCwgMHgzZDRmMjg1ZSwgMHhiOWFmYTgyMCwgMHhmYWRlODJlMCwgMHhhMDY3MjY4YiwgMHg4MjcyNzkyZSxcclxuXHRcdCAgMHg1NTNmYjJjMCwgMHg0ODlhZTIyYiwgMHhkNGVmOTc5NCwgMHgxMjVlM2ZiYywgMHgyMWZmZmNlZSwgMHg4MjViMWJmZCwgMHg5MjU1YzVlZCwgMHgxMjU3YTI0MCxcclxuXHRcdCAgMHg0ZTFhODMwMiwgMHhiYWUwN2ZmZiwgMHg1MjgyNDZlNywgMHg4ZTU3MTQwZSwgMHgzMzczZjdiZiwgMHg4YzlmODE4OCwgMHhhNmZjNGVlOCwgMHhjOTgyYjVhNSxcclxuXHRcdCAgMHhhOGMwMWRiNywgMHg1NzlmYzI2NCwgMHg2NzA5NGYzMSwgMHhmMmJkM2Y1ZiwgMHg0MGZmZjdjMSwgMHgxZmI3OGRmYywgMHg4ZTZiZDJjMSwgMHg0MzdiZTU5YixcclxuXHRcdCAgMHg5OWIwM2RiZiwgMHhiNWRiYzY0YiwgMHg2MzhkYzBlNiwgMHg1NTgxOWQ5OSwgMHhhMTk3YzgxYywgMHg0YTAxMmQ2ZSwgMHhjNTg4NGEyOCwgMHhjY2MzNmY3MSxcclxuXHRcdCAgMHhiODQzYzIxMywgMHg2YzA3NDNmMSwgMHg4MzA5ODkzYywgMHgwZmVkZGQ1ZiwgMHgyZjdmZTg1MCwgMHhkN2MwN2Y3ZSwgMHgwMjUwN2ZiZiwgMHg1YWZiOWEwNCxcclxuXHRcdCAgMHhhNzQ3ZDJkMCwgMHgxNjUxMTkyZSwgMHhhZjcwYmYzZSwgMHg1OGMzMTM4MCwgMHg1Zjk4MzAyZSwgMHg3MjdjYzNjNCwgMHgwYTBmYjQwMiwgMHgwZjdmZWY4MixcclxuXHRcdCAgMHg4Yzk2ZmRhZCwgMHg1ZDJjMmFhZSwgMHg4ZWU5OWE0OSwgMHg1MGRhODhiOCwgMHg4NDI3ZjRhMCwgMHgxZWFjNTc5MCwgMHg3OTZmYjQ0OSwgMHg4MjUyZGMxNSxcclxuXHRcdCAgMHhlZmJkN2Q5YiwgMHhhNjcyNTk3ZCwgMHhhZGE4NDBkOCwgMHg0NWY1NDUwNCwgMHhmYTVkNzQwMywgMHhlODNlYzMwNSwgMHg0ZjkxNzUxYSwgMHg5MjU2NjljMixcclxuXHRcdCAgMHgyM2VmZTk0MSwgMHhhOTAzZjEyZSwgMHg2MDI3MGRmMiwgMHgwMjc2ZTRiNiwgMHg5NGZkNjU3NCwgMHg5Mjc5ODViMiwgMHg4Mjc2ZGJjYiwgMHgwMjc3ODE3NixcclxuXHRcdCAgMHhmOGFmOTE4ZCwgMHg0ZTQ4Zjc5ZSwgMHg4ZjYxNmRkZiwgMHhlMjlkODQwZSwgMHg4NDJmN2Q4MywgMHgzNDBjZTVjOCwgMHg5NmJiYjY4MiwgMHg5M2I0YjE0OCxcclxuXHRcdCAgMHhlZjMwM2NhYiwgMHg5ODRmYWYyOCwgMHg3NzlmYWY5YiwgMHg5MmRjNTYwZCwgMHgyMjRkMWUyMCwgMHg4NDM3YWE4OCwgMHg3ZDI5ZGM5NiwgMHgyNzU2ZDNkYyxcclxuXHRcdCAgMHg4YjkwN2NlZSwgMHhiNTFmZDI0MCwgMHhlN2MwN2NlMywgMHhlNTY2YjRhMSwgMHhjM2U5NjE1ZSwgMHgzY2Y4MjA5ZCwgMHg2MDk0ZDFlMywgMHhjZDljYTM0MSxcclxuXHRcdCAgMHg1Yzc2NDYwZSwgMHgwMGVhOTgzYiwgMHhkNGQ2Nzg4MSwgMHhmZDQ3NTcyYywgMHhmNzZjZWRkOSwgMHhiZGE4MjI5YywgMHgxMjdkYWRhYSwgMHg0MzhhMDc0ZSxcclxuXHRcdCAgMHgxZjk3YzA5MCwgMHgwODFiZGI4YSwgMHg5M2EwN2ViZSwgMHhiOTM4Y2ExNSwgMHg5N2IwM2NmZiwgMHgzZGMyYzBmOCwgMHg4ZDFhYjJlYywgMHg2NDM4MGU1MSxcclxuXHRcdCAgMHg2OGNjN2JmYiwgMHhkOTBmMjc4OCwgMHgxMjQ5MDE4MSwgMHg1ZGU1ZmZkNCwgMHhkZDdlZjg2YSwgMHg3NmEyZTIxNCwgMHhiOWE0MDM2OCwgMHg5MjVkOTU4ZixcclxuXHRcdCAgMHg0YjM5ZmZmYSwgMHhiYTM5YWVlOSwgMHhhNGZmZDMwYiwgMHhmYWY3OTMzYiwgMHg2ZDQ5ODYyMywgMHgxOTNjYmNmYSwgMHgyNzYyNzU0NSwgMHg4MjVjZjQ3YSxcclxuXHRcdCAgMHg2MWJkOGJhMCwgMHhkMTFlNDJkMSwgMHhjZWFkMDRmNCwgMHgxMjdlYTM5MiwgMHgxMDQyOGRiNywgMHg4MjcyYTk3MiwgMHg5MjcwYzRhOCwgMHgxMjdkZTUwYixcclxuXHRcdCAgMHgyODViYTFjOCwgMHgzYzYyZjQ0ZiwgMHgzNWMwZWFhNSwgMHhlODA1ZDIzMSwgMHg0Mjg5MjlmYiwgMHhiNGZjZGY4MiwgMHg0ZmI2NmE1MywgMHgwZTdkYzE1YixcclxuXHRcdCAgMHgxZjA4MWZhYiwgMHgxMDg2MThhZSwgMHhmY2ZkMDg2ZCwgMHhmOWZmMjg4OSwgMHg2OTRiY2MxMSwgMHgyMzZhNWNhZSwgMHgxMmRlY2E0ZCwgMHgyYzNmOGNjNSxcclxuXHRcdCAgMHhkMmQwMmRmZSwgMHhmOGVmNTg5NiwgMHhlNGNmNTJkYSwgMHg5NTE1NWI2NywgMHg0OTRhNDg4YywgMHhiOWI2YTgwYywgMHg1YzhmODJiYywgMHg4OWQzNmI0NSxcclxuXHRcdCAgMHgzYTYwOTQzNywgMHhlYzAwYzlhOSwgMHg0NDcxNTI1MywgMHgwYTg3NGI0OSwgMHhkNzczYmM0MCwgMHg3YzM0NjcxYywgMHgwMjcxN2VmNiwgMHg0ZmViNTUzNixcclxuXHRcdCAgMHhhMmQwMmZmZiwgMHhkMmJmNjBjNCwgMHhkNDNmMDNjMCwgMHg1MGI0ZWY2ZCwgMHgwNzQ3OGNkMSwgMHgwMDZlMTg4OCwgMHhhMmU1M2Y1NSwgMHhiOWU2ZDRiYyxcclxuXHRcdCAgMHhhMjA0ODAxNiwgMHg5NzU3MzgzMywgMHhkNzIwN2Q2NywgMHhkZTBmOGYzZCwgMHg3MmY4N2IzMywgMHhhYmNjNGYzMywgMHg3Njg4YzU1ZCwgMHg3YjAwYTZiMCxcclxuXHRcdCAgMHg5NDdiMDAwMSwgMHg1NzAwNzVkMiwgMHhmOWJiODhmOCwgMHg4OTQyMDE5ZSwgMHg0MjY0YTVmZiwgMHg4NTYzMDJlMCwgMHg3MmRiZDkyYiwgMHhlZTk3MWI2OSxcclxuXHRcdCAgMHg2ZWEyMmZkZSwgMHg1ZjA4YWUyYiwgMHhhZjdhNjE2ZCwgMHhlNWM5ODc2NywgMHhjZjFmZWJkMiwgMHg2MWVmYzhjMiwgMHhmMWFjMjU3MSwgMHhjYzgyMzljMixcclxuXHRcdCAgMHg2NzIxNGNiOCwgMHhiMWU1ODNkMSwgMHhiN2RjM2U2MiwgMHg3ZjEwYmRjZSwgMHhmOTBhNWMzOCwgMHgwZmYwNDQzZCwgMHg2MDZlNmRjNiwgMHg2MDU0M2E0OSxcclxuXHRcdCAgMHg1NzI3YzE0OCwgMHgyYmU5OGExZCwgMHg4YWI0MTczOCwgMHgyMGUxYmUyNCwgMHhhZjk2ZGEwZiwgMHg2ODQ1ODQyNSwgMHg5OTgzM2JlNSwgMHg2MDBkNDU3ZCxcclxuXHRcdCAgMHgyODJmOTM1MCwgMHg4MzM0YjM2MiwgMHhkOTFkMTEyMCwgMHgyYjZkOGRhMCwgMHg2NDJiMWUzMSwgMHg5YzMwNWEwMCwgMHg1MmJjZTY4OCwgMHgxYjAzNTg4YSxcclxuXHRcdCAgMHhmN2JhZWZkNSwgMHg0MTQyZWQ5YywgMHhhNDMxNWMxMSwgMHg4MzMyM2VjNSwgMHhkZmVmNDYzNiwgMHhhMTMzYzUwMSwgMHhlOWQzNTMxYywgMHhlZTM1Mzc4Myk7XHJcblxyXG5cdFx0c0JveFszXSA9IG5ldyBBcnJheShcclxuXHRcdCAgMHg5ZGIzMDQyMCwgMHgxZmI2ZTlkZSwgMHhhN2JlN2JlZiwgMHhkMjczYTI5OCwgMHg0YTRmN2JkYiwgMHg2NGFkOGM1NywgMHg4NTUxMDQ0MywgMHhmYTAyMGVkMSxcclxuXHRcdCAgMHg3ZTI4N2FmZiwgMHhlNjBmYjY2MywgMHgwOTVmMzVhMSwgMHg3OWViZjEyMCwgMHhmZDA1OWQ0MywgMHg2NDk3YjdiMSwgMHhmMzY0MWY2MywgMHgyNDFlNGFkZixcclxuXHRcdCAgMHgyODE0N2Y1ZiwgMHg0ZmEyYjhjZCwgMHhjOTQzMDA0MCwgMHgwY2MzMjIyMCwgMHhmZGQzMGIzMCwgMHhjMGE1Mzc0ZiwgMHgxZDJkMDBkOSwgMHgyNDE0N2IxNSxcclxuXHRcdCAgMHhlZTRkMTExYSwgMHgwZmNhNTE2NywgMHg3MWZmOTA0YywgMHgyZDE5NWZmZSwgMHgxYTA1NjQ1ZiwgMHgwYzEzZmVmZSwgMHgwODFiMDhjYSwgMHgwNTE3MDEyMSxcclxuXHRcdCAgMHg4MDUzMDEwMCwgMHhlODNlNWVmZSwgMHhhYzlhZjRmOCwgMHg3ZmU3MjcwMSwgMHhkMmI4ZWU1ZiwgMHgwNmRmNDI2MSwgMHhiYjllOWI4YSwgMHg3MjkzZWEyNSxcclxuXHRcdCAgMHhjZTg0ZmZkZiwgMHhmNTcxODgwMSwgMHgzZGQ2NGIwNCwgMHhhMjZmMjYzYiwgMHg3ZWQ0ODQwMCwgMHg1NDdlZWJlNiwgMHg0NDZkNGNhMCwgMHg2Y2YzZDZmNSxcclxuXHRcdCAgMHgyNjQ5YWJkZiwgMHhhZWEwYzdmNSwgMHgzNjMzOGNjMSwgMHg1MDNmN2U5MywgMHhkMzc3MjA2MSwgMHgxMWI2MzhlMSwgMHg3MjUwMGUwMywgMHhmODBlYjJiYixcclxuXHRcdCAgMHhhYmUwNTAyZSwgMHhlYzhkNzdkZSwgMHg1Nzk3MWU4MSwgMHhlMTRmNjc0NiwgMHhjOTMzNTQwMCwgMHg2OTIwMzE4ZiwgMHgwODFkYmI5OSwgMHhmZmMzMDRhNSxcclxuXHRcdCAgMHg0ZDM1MTgwNSwgMHg3ZjNkNWNlMywgMHhhNmM4NjZjNiwgMHg1ZDViY2NhOSwgMHhkYWVjNmZlYSwgMHg5ZjkyNmY5MSwgMHg5ZjQ2MjIyZiwgMHgzOTkxNDY3ZCxcclxuXHRcdCAgMHhhNWJmNmQ4ZSwgMHgxMTQzYzQ0ZiwgMHg0Mzk1ODMwMiwgMHhkMDIxNGVlYiwgMHgwMjIwODNiOCwgMHgzZmI2MTgwYywgMHgxOGY4OTMxZSwgMHgyODE2NThlNixcclxuXHRcdCAgMHgyNjQ4NmUzZSwgMHg4YmQ3OGE3MCwgMHg3NDc3ZTRjMSwgMHhiNTA2ZTA3YywgMHhmMzJkMGEyNSwgMHg3OTA5OGIwMiwgMHhlNGVhYmI4MSwgMHgyODEyM2IyMyxcclxuXHRcdCAgMHg2OWRlYWQzOCwgMHgxNTc0Y2ExNiwgMHhkZjg3MWI2MiwgMHgyMTFjNDBiNywgMHhhNTFhOWVmOSwgMHgwMDE0Mzc3YiwgMHgwNDFlOGFjOCwgMHgwOTExNDAwMyxcclxuXHRcdCAgMHhiZDU5ZTRkMiwgMHhlM2QxNTZkNSwgMHg0ZmU4NzZkNSwgMHgyZjkxYTM0MCwgMHg1NTdiZThkZSwgMHgwMGVhZTRhNywgMHgwY2U1YzJlYywgMHg0ZGI0YmJhNixcclxuXHRcdCAgMHhlNzU2YmRmZiwgMHhkZDMzNjlhYywgMHhlYzE3YjAzNSwgMHgwNjU3MjMyNywgMHg5OWFmYzhiMCwgMHg1NmM4YzM5MSwgMHg2YjY1ODExYywgMHg1ZTE0NjExOSxcclxuXHRcdCAgMHg2ZTg1Y2I3NSwgMHhiZTA3YzAwMiwgMHhjMjMyNTU3NywgMHg4OTNmZjRlYywgMHg1YmJmYzkyZCwgMHhkMGVjM2IyNSwgMHhiNzgwMWFiNywgMHg4ZDZkM2IyNCxcclxuXHRcdCAgMHgyMGM3NjNlZiwgMHhjMzY2YTVmYywgMHg5YzM4Mjg4MCwgMHgwYWNlMzIwNSwgMHhhYWM5NTQ4YSwgMHhlY2ExZDdjNywgMHgwNDFhZmEzMiwgMHgxZDE2NjI1YSxcclxuXHRcdCAgMHg2NzAxOTAyYywgMHg5Yjc1N2E1NCwgMHgzMWQ0NzdmNywgMHg5MTI2YjAzMSwgMHgzNmNjNmZkYiwgMHhjNzBiOGI0NiwgMHhkOWU2NmE0OCwgMHg1NmU1NWE3OSxcclxuXHRcdCAgMHgwMjZhNGNlYiwgMHg1MjQzN2VmZiwgMHgyZjhmNzZiNCwgMHgwZGY5ODBhNSwgMHg4Njc0Y2RlMywgMHhlZGRhMDRlYiwgMHgxN2E5YmUwNCwgMHgyYzE4ZjRkZixcclxuXHRcdCAgMHhiNzc0N2Y5ZCwgMHhhYjJhZjdiNCwgMHhlZmMzNGQyMCwgMHgyZTA5NmI3YywgMHgxNzQxYTI1NCwgMHhlNWI2YTAzNSwgMHgyMTNkNDJmNiwgMHgyYzFjN2MyNixcclxuXHRcdCAgMHg2MWMyZjUwZiwgMHg2NTUyZGFmOSwgMHhkMmMyMzFmOCwgMHgyNTEzMGY2OSwgMHhkODE2N2ZhMiwgMHgwNDE4ZjJjOCwgMHgwMDFhOTZhNiwgMHgwZDE1MjZhYixcclxuXHRcdCAgMHg2MzMxNWMyMSwgMHg1ZTBhNzJlYywgMHg0OWJhZmVmZCwgMHgxODc5MDhkOSwgMHg4ZDBkYmQ4NiwgMHgzMTExNzBhNywgMHgzZTliNjQwYywgMHhjYzNlMTBkNyxcclxuXHRcdCAgMHhkNWNhZDNiNiwgMHgwY2FlYzM4OCwgMHhmNzMwMDFlMSwgMHg2YzcyOGFmZiwgMHg3MWVhZTJhMSwgMHgxZjlhZjM2ZSwgMHhjZmNiZDEyZiwgMHhjMWRlODQxNyxcclxuXHRcdCAgMHhhYzA3YmU2YiwgMHhjYjQ0YTFkOCwgMHg4YjliMGY1NiwgMHgwMTM5ODhjMywgMHhiMWM1MmZjYSwgMHhiNGJlMzFjZCwgMHhkODc4MjgwNiwgMHgxMmEzYTRlMixcclxuXHRcdCAgMHg2ZjdkZTUzMiwgMHg1OGZkN2ViNiwgMHhkMDFlZTkwMCwgMHgyNGFkZmZjMiwgMHhmNDk5MGZjNSwgMHg5NzExYWFjNSwgMHgwMDFkN2I5NSwgMHg4MmU1ZTdkMixcclxuXHRcdCAgMHgxMDk4NzNmNiwgMHgwMDYxMzA5NiwgMHhjMzJkOTUyMSwgMHhhZGExMjFmZiwgMHgyOTkwODQxNSwgMHg3ZmJiOTc3ZiwgMHhhZjllYjNkYiwgMHgyOWM5ZWQyYSxcclxuXHRcdCAgMHg1Y2UyYTQ2NSwgMHhhNzMwZjMyYywgMHhkMGFhM2ZlOCwgMHg4YTVjYzA5MSwgMHhkNDllMmNlNywgMHgwY2U0NTRhOSwgMHhkNjBhY2Q4NiwgMHgwMTVmMTkxOSxcclxuXHRcdCAgMHg3NzA3OTEwMywgMHhkZWEwM2FmNiwgMHg3OGE4NTY1ZSwgMHhkZWUzNTZkZiwgMHgyMWYwNWNiZSwgMHg4Yjc1ZTM4NywgMHhiM2M1MDY1MSwgMHhiOGE1YzNlZixcclxuXHRcdCAgMHhkOGVlYjZkMiwgMHhlNTIzYmU3NywgMHhjMjE1NDUyOSwgMHgyZjY5ZWZkZiwgMHhhZmU2N2FmYiwgMHhmNDcwYzRiMiwgMHhmM2UwZWI1YiwgMHhkNmNjOTg3NixcclxuXHRcdCAgMHgzOWU0NDYwYywgMHgxZmRhODUzOCwgMHgxOTg3ODMyZiwgMHhjYTAwNzM2NywgMHhhOTkxNDRmOCwgMHgyOTZiMjk5ZSwgMHg0OTJmYzI5NSwgMHg5MjY2YmVhYixcclxuXHRcdCAgMHhiNTY3NmU2OSwgMHg5YmQzZGRkYSwgMHhkZjdlMDUyZiwgMHhkYjI1NzAxYywgMHgxYjVlNTFlZSwgMHhmNjUzMjRlNiwgMHg2YWZjZTM2YywgMHgwMzE2Y2MwNCxcclxuXHRcdCAgMHg4NjQ0MjEzZSwgMHhiN2RjNTlkMCwgMHg3OTY1MjkxZiwgMHhjY2Q2ZmQ0MywgMHg0MTgyMzk3OSwgMHg5MzJiY2RmNiwgMHhiNjU3YzM0ZCwgMHg0ZWRmZDI4MixcclxuXHRcdCAgMHg3YWU1MjkwYywgMHgzY2I5NTM2YiwgMHg4NTFlMjBmZSwgMHg5ODMzNTU3ZSwgMHgxM2VjZjBiMCwgMHhkM2ZmYjM3MiwgMHgzZjg1YzVjMSwgMHgwYWVmN2VkMik7XHJcblxyXG5cdFx0c0JveFs0XSA9IG5ldyBBcnJheShcclxuXHRcdCAgMHg3ZWM5MGMwNCwgMHgyYzZlNzRiOSwgMHg5YjBlNjZkZiwgMHhhNjMzNzkxMSwgMHhiODZhN2ZmZiwgMHgxZGQzNThmNSwgMHg0NGRkOWQ0NCwgMHgxNzMxMTY3ZixcclxuXHRcdCAgMHgwOGZiZjFmYSwgMHhlN2Y1MTFjYywgMHhkMjA1MWIwMCwgMHg3MzVhYmEwMCwgMHgyYWI3MjJkOCwgMHgzODYzODFjYiwgMHhhY2Y2MjQzYSwgMHg2OWJlZmQ3YSxcclxuXHRcdCAgMHhlNmEyZTc3ZiwgMHhmMGM3MjBjZCwgMHhjNDQ5NDgxNiwgMHhjY2Y1YzE4MCwgMHgzODg1MTY0MCwgMHgxNWIwYTg0OCwgMHhlNjhiMThjYiwgMHg0Y2FhZGVmZixcclxuXHRcdCAgMHg1ZjQ4MGEwMSwgMHgwNDEyYjJhYSwgMHgyNTk4MTRmYywgMHg0MWQwZWZlMiwgMHg0ZTQwYjQ4ZCwgMHgyNDhlYjZmYiwgMHg4ZGJhMWNmZSwgMHg0MWE5OWIwMixcclxuXHRcdCAgMHgxYTU1MGEwNCwgMHhiYThmNjVjYiwgMHg3MjUxZjRlNywgMHg5NWE1MTcyNSwgMHhjMTA2ZWNkNywgMHg5N2E1OTgwYSwgMHhjNTM5YjlhYSwgMHg0ZDc5ZmU2YSxcclxuXHRcdCAgMHhmMmYzZjc2MywgMHg2OGFmODA0MCwgMHhlZDBjOWU1NiwgMHgxMWI0OTU4YiwgMHhlMWViNWE4OCwgMHg4NzA5ZTZiMCwgMHhkN2UwNzE1NiwgMHg0ZTI5ZmVhNyxcclxuXHRcdCAgMHg2MzY2ZTUyZCwgMHgwMmQxYzAwMCwgMHhjNGFjOGUwNSwgMHg5Mzc3ZjU3MSwgMHgwYzA1MzcyYSwgMHg1Nzg1MzVmMiwgMHgyMjYxYmUwMiwgMHhkNjQyYTBjOSxcclxuXHRcdCAgMHhkZjEzYTI4MCwgMHg3NGI1NWJkMiwgMHg2ODIxOTljMCwgMHhkNDIxZTVlYywgMHg1M2ZiM2NlOCwgMHhjOGFkZWRiMywgMHgyOGE4N2ZjOSwgMHgzZDk1OTk4MSxcclxuXHRcdCAgMHg1YzFmZjkwMCwgMHhmZTM4ZDM5OSwgMHgwYzRlZmYwYiwgMHgwNjI0MDdlYSwgMHhhYTJmNGZiMSwgMHg0ZmI5Njk3NiwgMHg5MGM3OTUwNSwgMHhiMGE4YTc3NCxcclxuXHRcdCAgMHhlZjU1YTFmZiwgMHhlNTljYTJjMiwgMHhhNmI2MmQyNywgMHhlNjZhNDI2MywgMHhkZjY1MDAxZiwgMHgwZWM1MDk2NiwgMHhkZmRkNTViYywgMHgyOWRlMDY1NSxcclxuXHRcdCAgMHg5MTFlNzM5YSwgMHgxN2FmODk3NSwgMHgzMmM3OTExYywgMHg4OWY4OTQ2OCwgMHgwZDAxZTk4MCwgMHg1MjQ3NTVmNCwgMHgwM2I2M2NjOSwgMHgwY2M4NDRiMixcclxuXHRcdCAgMHhiY2YzZjBhYSwgMHg4N2FjMzZlOSwgMHhlNTNhNzQyNiwgMHgwMWIzZDgyYiwgMHgxYTllNzQ0OSwgMHg2NGVlMmQ3ZSwgMHhjZGRiYjFkYSwgMHgwMWM5NDkxMCxcclxuXHRcdCAgMHhiODY4YmY4MCwgMHgwZDI2ZjNmZCwgMHg5MzQyZWRlNywgMHgwNGE1YzI4NCwgMHg2MzY3MzdiNiwgMHg1MGY1YjYxNiwgMHhmMjQ3NjZlMywgMHg4ZWNhMzZjMSxcclxuXHRcdCAgMHgxMzZlMDVkYiwgMHhmZWYxODM5MSwgMHhmYjg4N2EzNywgMHhkNmU3ZjdkNCwgMHhjN2ZiN2RjOSwgMHgzMDYzZmNkZiwgMHhiNmY1ODlkZSwgMHhlYzI5NDFkYSxcclxuXHRcdCAgMHgyNmU0NjY5NSwgMHhiNzU2NjQxOSwgMHhmNjU0ZWZjNSwgMHhkMDhkNThiNywgMHg0ODkyNTQwMSwgMHhjMWJhY2I3ZiwgMHhlNWZmNTUwZiwgMHhiNjA4MzA0OSxcclxuXHRcdCAgMHg1YmI1ZDBlOCwgMHg4N2Q3MmU1YSwgMHhhYjZhNmVlMSwgMHgyMjNhNjZjZSwgMHhjNjJiZjNjZCwgMHg5ZTA4ODVmOSwgMHg2OGNiM2U0NywgMHgwODZjMDEwZixcclxuXHRcdCAgMHhhMjFkZTgyMCwgMHhkMThiNjlkZSwgMHhmM2Y2NTc3NywgMHhmYTAyYzNmNiwgMHg0MDdlZGFjMywgMHhjYmIzZDU1MCwgMHgxNzkzMDg0ZCwgMHhiMGQ3MGViYSxcclxuXHRcdCAgMHgwYWIzNzhkNSwgMHhkOTUxZmIwYywgMHhkZWQ3ZGE1NiwgMHg0MTI0YmJlNCwgMHg5NGNhMGI1NiwgMHgwZjU3NTVkMSwgMHhlMGUxZTU2ZSwgMHg2MTg0YjViZSxcclxuXHRcdCAgMHg1ODBhMjQ5ZiwgMHg5NGY3NGJjMCwgMHhlMzI3ODg4ZSwgMHg5ZjdiNTU2MSwgMHhjM2RjMDI4MCwgMHgwNTY4NzcxNSwgMHg2NDZjNmJkNywgMHg0NDkwNGRiMyxcclxuXHRcdCAgMHg2NmI0ZjBhMywgMHhjMGYxNjQ4YSwgMHg2OTdlZDVhZiwgMHg0OWU5MmZmNiwgMHgzMDllMzc0ZiwgMHgyY2I2MzU2YSwgMHg4NTgwODU3MywgMHg0OTkxZjg0MCxcclxuXHRcdCAgMHg3NmYwYWUwMiwgMHgwODNiZTg0ZCwgMHgyODQyMWM5YSwgMHg0NDQ4OTQwNiwgMHg3MzZlNGNiOCwgMHhjMTA5MjkxMCwgMHg4YmM5NWZjNiwgMHg3ZDg2OWNmNCxcclxuXHRcdCAgMHgxMzRmNjE2ZiwgMHgyZTc3MTE4ZCwgMHhiMzFiMmJlMSwgMHhhYTkwYjQ3MiwgMHgzY2E1ZDcxNywgMHg3ZDE2MWJiYSwgMHg5Y2FkOTAxMCwgMHhhZjQ2MmJhMixcclxuXHRcdCAgMHg5ZmU0NTlkMiwgMHg0NWQzNDU1OSwgMHhkOWYyZGExMywgMHhkYmM2NTQ4NywgMHhmM2U0Zjk0ZSwgMHgxNzZkNDg2ZiwgMHgwOTdjMTNlYSwgMHg2MzFkYTVjNyxcclxuXHRcdCAgMHg0NDVmNzM4MiwgMHgxNzU2ODNmNCwgMHhjZGM2NmE5NywgMHg3MGJlMDI4OCwgMHhiM2NkY2Y3MiwgMHg2ZTVkZDJmMywgMHgyMDkzNjA3OSwgMHg0NTliODBhNSxcclxuXHRcdCAgMHhiZTYwZTJkYiwgMHhhOWMyMzEwMSwgMHhlYmE1MzE1YywgMHgyMjRlNDJmMiwgMHgxYzVjMTU3MiwgMHhmNjcyMWIyYywgMHgxYWQyZmZmMywgMHg4YzI1NDA0ZSxcclxuXHRcdCAgMHgzMjRlZDcyZiwgMHg0MDY3YjdmZCwgMHgwNTIzMTM4ZSwgMHg1Y2EzYmM3OCwgMHhkYzBmZDY2ZSwgMHg3NTkyMjI4MywgMHg3ODRkNmIxNywgMHg1OGViYjE2ZSxcclxuXHRcdCAgMHg0NDA5NGY4NSwgMHgzZjQ4MWQ4NywgMHhmY2ZlYWU3YiwgMHg3N2I1ZmY3NiwgMHg4YzIzMDJiZiwgMHhhYWY0NzU1NiwgMHg1ZjQ2YjAyYSwgMHgyYjA5MjgwMSxcclxuXHRcdCAgMHgzZDM4ZjVmNywgMHgwY2E4MWYzNiwgMHg1MmFmNGE4YSwgMHg2NmQ1ZTdjMCwgMHhkZjNiMDg3NCwgMHg5NTA1NTExMCwgMHgxYjVhZDdhOCwgMHhmNjFlZDVhZCxcclxuXHRcdCAgMHg2Y2Y2ZTQ3OSwgMHgyMDc1ODE4NCwgMHhkMGNlZmE2NSwgMHg4OGY3YmU1OCwgMHg0YTA0NjgyNiwgMHgwZmY2ZjhmMywgMHhhMDljN2Y3MCwgMHg1MzQ2YWJhMCxcclxuXHRcdCAgMHg1Y2U5NmMyOCwgMHhlMTc2ZWRhMywgMHg2YmFjMzA3ZiwgMHgzNzY4MjlkMiwgMHg4NTM2MGZhOSwgMHgxN2UzZmUyYSwgMHgyNGI3OTc2NywgMHhmNWE5NmIyMCxcclxuXHRcdCAgMHhkNmNkMjU5NSwgMHg2OGZmMWViZiwgMHg3NTU1NDQyYywgMHhmMTlmMDZiZSwgMHhmOWUwNjU5YSwgMHhlZWI5NDkxZCwgMHgzNDAxMDcxOCwgMHhiYjMwY2FiOCxcclxuXHRcdCAgMHhlODIyZmUxNSwgMHg4ODU3MDk4MywgMHg3NTBlNjI0OSwgMHhkYTYyN2U1NSwgMHg1ZTc2ZmZhOCwgMHhiMTUzNDU0NiwgMHg2ZDQ3ZGUwOCwgMHhlZmU5ZTdkNCk7XHJcblxyXG5cdFx0c0JveFs1XSA9IG5ldyBBcnJheShcclxuXHRcdCAgMHhmNmZhOGY5ZCwgMHgyY2FjNmNlMSwgMHg0Y2EzNDg2NywgMHhlMjMzN2Y3YywgMHg5NWRiMDhlNywgMHgwMTY4NDNiNCwgMHhlY2VkNWNiYywgMHgzMjU1NTNhYyxcclxuXHRcdCAgMHhiZjlmMDk2MCwgMHhkZmExZTJlZCwgMHg4M2YwNTc5ZCwgMHg2M2VkODZiOSwgMHgxYWI2YTZiOCwgMHhkZTVlYmUzOSwgMHhmMzhmZjczMiwgMHg4OTg5YjEzOCxcclxuXHRcdCAgMHgzM2YxNDk2MSwgMHhjMDE5MzdiZCwgMHhmNTA2YzZkYSwgMHhlNDYyNWU3ZSwgMHhhMzA4ZWE5OSwgMHg0ZTIzZTMzYywgMHg3OWNiZDdjYywgMHg0OGExNDM2NyxcclxuXHRcdCAgMHhhMzE0OTYxOSwgMHhmZWM5NGJkNSwgMHhhMTE0MTc0YSwgMHhlYWEwMTg2NiwgMHhhMDg0ZGIyZCwgMHgwOWE4NDg2ZiwgMHhhODg4NjE0YSwgMHgyOTAwYWY5OCxcclxuXHRcdCAgMHgwMTY2NTk5MSwgMHhlMTk5Mjg2MywgMHhjOGYzMGM2MCwgMHgyZTc4ZWYzYywgMHhkMGQ1MTkzMiwgMHhjZjBmZWMxNCwgMHhmN2NhMDdkMiwgMHhkMGE4MjA3MixcclxuXHRcdCAgMHhmZDQxMTk3ZSwgMHg5MzA1YTZiMCwgMHhlODZiZTNkYSwgMHg3NGJlZDNjZCwgMHgzNzJkYTUzYywgMHg0YzdmNDQ0OCwgMHhkYWI1ZDQ0MCwgMHg2ZGJhMGVjMyxcclxuXHRcdCAgMHgwODM5MTlhNywgMHg5ZmJhZWVkOSwgMHg0OWRiY2ZiMCwgMHg0ZTY3MGM1MywgMHg1YzNkOWMwMSwgMHg2NGJkYjk0MSwgMHgyYzBlNjM2YSwgMHhiYTdkZDljZCxcclxuXHRcdCAgMHhlYTZmNzM4OCwgMHhlNzBiYzc2MiwgMHgzNWYyOWFkYiwgMHg1YzRjZGQ4ZCwgMHhmMGQ0OGQ4YywgMHhiODgxNTNlMiwgMHgwOGExOTg2NiwgMHgxYWUyZWFjOCxcclxuXHRcdCAgMHgyODRjYWY4OSwgMHhhYTkyODIyMywgMHg5MzM0YmU1MywgMHgzYjNhMjFiZiwgMHgxNjQzNGJlMywgMHg5YWVhMzkwNiwgMHhlZmU4YzM2ZSwgMHhmODkwY2RkOSxcclxuXHRcdCAgMHg4MDIyNmRhZSwgMHhjMzQwYTRhMywgMHhkZjdlOWMwOSwgMHhhNjk0YTgwNywgMHg1YjdjNWVjYywgMHgyMjFkYjNhNiwgMHg5YTY5YTAyZiwgMHg2ODgxOGE1NCxcclxuXHRcdCAgMHhjZWIyMjk2ZiwgMHg1M2MwODQzYSwgMHhmZTg5MzY1NSwgMHgyNWJmZTY4YSwgMHhiNDYyOGFiYywgMHhjZjIyMmViZiwgMHgyNWFjNmY0OCwgMHhhOWE5OTM4NyxcclxuXHRcdCAgMHg1M2JkZGI2NSwgMHhlNzZmZmJlNywgMHhlOTY3ZmQ3OCwgMHgwYmE5MzU2MywgMHg4ZTM0MmJjMSwgMHhlOGExMWJlOSwgMHg0OTgwNzQwZCwgMHhjODA4N2RmYyxcclxuXHRcdCAgMHg4ZGU0YmY5OSwgMHhhMTExMDFhMCwgMHg3ZmQzNzk3NSwgMHhkYTVhMjZjMCwgMHhlODFmOTk0ZiwgMHg5NTI4Y2Q4OSwgMHhmZDMzOWZlZCwgMHhiODc4MzRiZixcclxuXHRcdCAgMHg1ZjA0NDU2ZCwgMHgyMjI1ODY5OCwgMHhjOWM0YzgzYiwgMHgyZGMxNTZiZSwgMHg0ZjYyOGRhYSwgMHg1N2Y1NWVjNSwgMHhlMjIyMGFiZSwgMHhkMjkxNmViZixcclxuXHRcdCAgMHg0ZWM3NWI5NSwgMHgyNGYyYzNjMCwgMHg0MmQxNWQ5OSwgMHhjZDBkN2ZhMCwgMHg3YjZlMjdmZiwgMHhhOGRjOGFmMCwgMHg3MzQ1YzEwNiwgMHhmNDFlMjMyZixcclxuXHRcdCAgMHgzNTE2MjM4NiwgMHhlNmVhODkyNiwgMHgzMzMzYjA5NCwgMHgxNTdlYzZmMiwgMHgzNzJiNzRhZiwgMHg2OTI1NzNlNCwgMHhlOWE5ZDg0OCwgMHhmMzE2MDI4OSxcclxuXHRcdCAgMHgzYTYyZWYxZCwgMHhhNzg3ZTIzOCwgMHhmM2E1ZjY3NiwgMHg3NDM2NDg1MywgMHgyMDk1MTA2MywgMHg0NTc2Njk4ZCwgMHhiNmZhZDQwNywgMHg1OTJhZjk1MCxcclxuXHRcdCAgMHgzNmY3MzUyMywgMHg0Y2ZiNmU4NywgMHg3ZGE0Y2VjMCwgMHg2YzE1MmRhYSwgMHhjYjAzOTZhOCwgMHhjNTBkZmU1ZCwgMHhmY2Q3MDdhYiwgMHgwOTIxYzQyZixcclxuXHRcdCAgMHg4OWRmZjBiYiwgMHg1ZmUyYmU3OCwgMHg0NDhmNGYzMywgMHg3NTQ2MTNjOSwgMHgyYjA1ZDA4ZCwgMHg0OGI5ZDU4NSwgMHhkYzA0OTQ0MSwgMHhjODA5OGY5YixcclxuXHRcdCAgMHg3ZGVkZTc4NiwgMHhjMzlhMzM3MywgMHg0MjQxMDAwNSwgMHg2YTA5MTc1MSwgMHgwZWYzYzhhNiwgMHg4OTAwNzJkNiwgMHgyODIwNzY4MiwgMHhhOWE5ZjdiZSxcclxuXHRcdCAgMHhiZjMyNjc5ZCwgMHhkNDViNWI3NSwgMHhiMzUzZmQwMCwgMHhjYmIwZTM1OCwgMHg4MzBmMjIwYSwgMHgxZjhmYjIxNCwgMHhkMzcyY2YwOCwgMHhjYzNjNGExMyxcclxuXHRcdCAgMHg4Y2Y2MzE2NiwgMHgwNjFjODdiZSwgMHg4OGM5OGY4OCwgMHg2MDYyZTM5NywgMHg0N2NmOGU3YSwgMHhiNmM4NTI4MywgMHgzY2MyYWNmYiwgMHgzZmMwNjk3NixcclxuXHRcdCAgMHg0ZThmMDI1MiwgMHg2NGQ4MzE0ZCwgMHhkYTM4NzBlMywgMHgxZTY2NTQ1OSwgMHhjMTA5MDhmMCwgMHg1MTMwMjFhNSwgMHg2YzViNjhiNywgMHg4MjJmOGFhMCxcclxuXHRcdCAgMHgzMDA3Y2QzZSwgMHg3NDcxOWVlZiwgMHhkYzg3MjY4MSwgMHgwNzMzNDBkNCwgMHg3ZTQzMmZkOSwgMHgwYzVlYzI0MSwgMHg4ODA5Mjg2YywgMHhmNTkyZDg5MSxcclxuXHRcdCAgMHgwOGE5MzBmNiwgMHg5NTdlZjMwNSwgMHhiN2ZiZmZiZCwgMHhjMjY2ZTk2ZiwgMHg2ZmU0YWM5OCwgMHhiMTczZWNjMCwgMHhiYzYwYjQyYSwgMHg5NTM0OThkYSxcclxuXHRcdCAgMHhmYmExYWUxMiwgMHgyZDRiZDczNiwgMHgwZjI1ZmFhYiwgMHhhNGYzZmNlYiwgMHhlMjk2OTEyMywgMHgyNTdmMGMzZCwgMHg5MzQ4YWY0OSwgMHgzNjE0MDBiYyxcclxuXHRcdCAgMHhlODgxNmY0YSwgMHgzODE0ZjIwMCwgMHhhM2Y5NDA0MywgMHg5YzdhNTRjMiwgMHhiYzcwNGY1NywgMHhkYTQxZTdmOSwgMHhjMjVhZDMzYSwgMHg1NGY0YTA4NCxcclxuXHRcdCAgMHhiMTdmNTUwNSwgMHg1OTM1N2NiZSwgMHhlZGJkMTVjOCwgMHg3Zjk3YzVhYiwgMHhiYTVhYzdiNSwgMHhiNmY2ZGVhZiwgMHgzYTQ3OWMzYSwgMHg1MzAyZGEyNSxcclxuXHRcdCAgMHg2NTNkN2U2YSwgMHg1NDI2OGQ0OSwgMHg1MWE0NzdlYSwgMHg1MDE3ZDU1YiwgMHhkN2QyNWQ4OCwgMHg0NDEzNmM3NiwgMHgwNDA0YThjOCwgMHhiOGU1YTEyMSxcclxuXHRcdCAgMHhiODFhOTI4YSwgMHg2MGVkNTg2OSwgMHg5N2M1NWI5NiwgMHhlYWVjOTkxYiwgMHgyOTkzNTkxMywgMHgwMWZkYjdmMSwgMHgwODhlOGRmYSwgMHg5YWI2ZjZmNSxcclxuXHRcdCAgMHgzYjRjYmY5ZiwgMHg0YTVkZTNhYiwgMHhlNjA1MWQzNSwgMHhhMGUxZDg1NSwgMHhkMzZiNGNmMSwgMHhmNTQ0ZWRlYiwgMHhiMGU5MzUyNCwgMHhiZWJiOGZiZCxcclxuXHRcdCAgMHhhMmQ3NjJjZiwgMHg0OWM5MmY1NCwgMHgzOGI1ZjMzMSwgMHg3MTI4YTQ1NCwgMHg0ODM5MjkwNSwgMHhhNjViMWRiOCwgMHg4NTFjOTdiZCwgMHhkNjc1Y2YyZik7XHJcblxyXG5cdFx0c0JveFs2XSA9IG5ldyBBcnJheShcclxuXHRcdCAgMHg4NWUwNDAxOSwgMHgzMzJiZjU2NywgMHg2NjJkYmZmZiwgMHhjZmM2NTY5MywgMHgyYThkN2Y2ZiwgMHhhYjliYzkxMiwgMHhkZTYwMDhhMSwgMHgyMDI4ZGExZixcclxuXHRcdCAgMHgwMjI3YmNlNywgMHg0ZDY0MjkxNiwgMHgxOGZhYzMwMCwgMHg1MGYxOGI4MiwgMHgyY2IyY2IxMSwgMHhiMjMyZTc1YywgMHg0YjM2OTVmMiwgMHhiMjg3MDdkZSxcclxuXHRcdCAgMHhhMDVmYmNmNiwgMHhjZDQxODFlOSwgMHhlMTUwMjEwYywgMHhlMjRlZjFiZCwgMHhiMTY4YzM4MSwgMHhmZGU0ZTc4OSwgMHg1Yzc5YjBkOCwgMHgxZThiZmQ0MyxcclxuXHRcdCAgMHg0ZDQ5NTAwMSwgMHgzOGJlNDM0MSwgMHg5MTNjZWUxZCwgMHg5MmE3OWMzZiwgMHgwODk3NjZiZSwgMHhiYWVlYWRmNCwgMHgxMjg2YmVjZiwgMHhiNmVhY2IxOSxcclxuXHRcdCAgMHgyNjYwYzIwMCwgMHg3NTY1YmRlNCwgMHg2NDI0MWY3YSwgMHg4MjQ4ZGNhOSwgMHhjM2IzYWQ2NiwgMHgyODEzNjA4NiwgMHgwYmQ4ZGZhOCwgMHgzNTZkMWNmMixcclxuXHRcdCAgMHgxMDc3ODliZSwgMHhiM2IyZTljZSwgMHgwNTAyYWE4ZiwgMHgwYmMwMzUxZSwgMHgxNjZiZjUyYSwgMHhlYjEyZmY4MiwgMHhlMzQ4NjkxMSwgMHhkMzRkNzUxNixcclxuXHRcdCAgMHg0ZTdiM2FmZiwgMHg1ZjQzNjcxYiwgMHg5Y2Y2ZTAzNywgMHg0OTgxYWM4MywgMHgzMzQyNjZjZSwgMHg4YzkzNDFiNywgMHhkMGQ4NTRjMCwgMHhjYjNhNmM4OCxcclxuXHRcdCAgMHg0N2JjMjgyOSwgMHg0NzI1YmEzNywgMHhhNjZhZDIyYiwgMHg3YWQ2MWYxZSwgMHgwYzVjYmFmYSwgMHg0NDM3ZjEwNywgMHhiNmU3OTk2MiwgMHg0MmQyZDgxNixcclxuXHRcdCAgMHgwYTk2MTI4OCwgMHhlMWE1YzA2ZSwgMHgxMzc0OWU2NywgMHg3MmZjMDgxYSwgMHhiMWQxMzlmNywgMHhmOTU4Mzc0NSwgMHhjZjE5ZGY1OCwgMHhiZWMzZjc1NixcclxuXHRcdCAgMHhjMDZlYmEzMCwgMHgwNzIxMWIyNCwgMHg0NWMyODgyOSwgMHhjOTVlMzE3ZiwgMHhiYzhlYzUxMSwgMHgzOGJjNDZlOSwgMHhjNmU2ZmExNCwgMHhiYWU4NTg0YSxcclxuXHRcdCAgMHhhZDRlYmM0NiwgMHg0NjhmNTA4YiwgMHg3ODI5NDM1ZiwgMHhmMTI0MTgzYiwgMHg4MjFkYmE5ZiwgMHhhZmY2MGZmNCwgMHhlYTJjNGU2ZCwgMHgxNmUzOTI2NCxcclxuXHRcdCAgMHg5MjU0NGE4YiwgMHgwMDliNGZjMywgMHhhYmE2OGNlZCwgMHg5YWM5NmY3OCwgMHgwNmE1Yjc5YSwgMHhiMjg1NmU2ZSwgMHgxYWVjM2NhOSwgMHhiZTgzODY4OCxcclxuXHRcdCAgMHgwZTA4MDRlOSwgMHg1NWYxYmU1NiwgMHhlN2U1MzYzYiwgMHhiM2ExZjI1ZCwgMHhmN2RlYmI4NSwgMHg2MWZlMDMzYywgMHgxNjc0NjIzMywgMHgzYzAzNGMyOCxcclxuXHRcdCAgMHhkYTZkMGM3NCwgMHg3OWFhYzU2YywgMHgzY2U0ZTFhZCwgMHg1MWYwYzgwMiwgMHg5OGY4ZjM1YSwgMHgxNjI2YTQ5ZiwgMHhlZWQ4MmIyOSwgMHgxZDM4MmZlMyxcclxuXHRcdCAgMHgwYzRmYjk5YSwgMHhiYjMyNTc3OCwgMHgzZWM2ZDk3YiwgMHg2ZTc3YTZhOSwgMHhjYjY1OGI1YywgMHhkNDUyMzBjNywgMHgyYmQxNDA4YiwgMHg2MGMwM2ViNyxcclxuXHRcdCAgMHhiOTA2OGQ3OCwgMHhhMzM3NTRmNCwgMHhmNDMwYzg3ZCwgMHhjOGE3MTMwMiwgMHhiOTZkOGMzMiwgMHhlYmQ0ZTdiZSwgMHhiZThiOWQyZCwgMHg3OTc5ZmIwNixcclxuXHRcdCAgMHhlNzIyNTMwOCwgMHg4Yjc1Y2Y3NywgMHgxMWVmOGRhNCwgMHhlMDgzYzg1OCwgMHg4ZDZiNzg2ZiwgMHg1YTYzMTdhNiwgMHhmYTVjZjdhMCwgMHg1ZGRhMDAzMyxcclxuXHRcdCAgMHhmMjhlYmZiMCwgMHhmNWI5YzMxMCwgMHhhMGVhYzI4MCwgMHgwOGI5NzY3YSwgMHhhM2Q5ZDJiMCwgMHg3OWQzNDIxNywgMHgwMjFhNzE4ZCwgMHg5YWM2MzM2YSxcclxuXHRcdCAgMHgyNzExZmQ2MCwgMHg0MzgwNTBlMywgMHgwNjk5MDhhOCwgMHgzZDdmZWRjNCwgMHg4MjZkMmJlZiwgMHg0ZWViODQ3NiwgMHg0ODhkY2YyNSwgMHgzNmM5ZDU2NixcclxuXHRcdCAgMHgyOGU3NGU0MSwgMHhjMjYxMGFjYSwgMHgzZDQ5YTljZiwgMHhiYWUzYjlkZiwgMHhiNjVmOGRlNiwgMHg5MmFlYWY2NCwgMHgzYWM3ZDVlNiwgMHg5ZWE4MDUwOSxcclxuXHRcdCAgMHhmMjJiMDE3ZCwgMHhhNDE3M2Y3MCwgMHhkZDFlMTZjMywgMHgxNWUwZDdmOSwgMHg1MGIxYjg4NywgMHgyYjlmNGZkNSwgMHg2MjVhYmE4MiwgMHg2YTAxNzk2MixcclxuXHRcdCAgMHgyZWMwMWI5YywgMHgxNTQ4OGFhOSwgMHhkNzE2ZTc0MCwgMHg0MDA1NWEyYywgMHg5M2QyOWEyMiwgMHhlMzJkYmY5YSwgMHgwNTg3NDViOSwgMHgzNDUzZGMxZSxcclxuXHRcdCAgMHhkNjk5Mjk2ZSwgMHg0OTZjZmY2ZiwgMHgxYzlmNDk4NiwgMHhkZmUyZWQwNywgMHhiODcyNDJkMSwgMHgxOWRlN2VhZSwgMHgwNTNlNTYxYSwgMHgxNWFkNmY4YyxcclxuXHRcdCAgMHg2NjYyNmMxYywgMHg3MTU0YzI0YywgMHhlYTA4MmIyYSwgMHg5M2ViMjkzOSwgMHgxN2RjYjBmMCwgMHg1OGQ0ZjJhZSwgMHg5ZWEyOTRmYiwgMHg1MmNmNTY0YyxcclxuXHRcdCAgMHg5ODgzZmU2NiwgMHgyZWM0MDU4MSwgMHg3NjM5NTNjMywgMHgwMWQ2NjkyZSwgMHhkM2EwYzEwOCwgMHhhMWU3MTYwZSwgMHhlNGYyZGZhNiwgMHg2OTNlZDI4NSxcclxuXHRcdCAgMHg3NDkwNDY5OCwgMHg0YzJiMGVkZCwgMHg0Zjc1NzY1NiwgMHg1ZDM5MzM3OCwgMHhhMTMyMjM0ZiwgMHgzZDMyMWM1ZCwgMHhjM2Y1ZTE5NCwgMHg0YjI2OTMwMSxcclxuXHRcdCAgMHhjNzlmMDIyZiwgMHgzYzk5N2U3ZSwgMHg1ZTRmOTUwNCwgMHgzZmZhZmJiZCwgMHg3NmY3YWQwZSwgMHgyOTY2OTNmNCwgMHgzZDFmY2U2ZiwgMHhjNjFlNDViZSxcclxuXHRcdCAgMHhkM2I1YWIzNCwgMHhmNzJiZjliNywgMHgxYjA0MzRjMCwgMHg0ZTcyYjU2NywgMHg1NTkyYTMzZCwgMHhiNTIyOTMwMSwgMHhjZmQyYTg3ZiwgMHg2MGFlYjc2NyxcclxuXHRcdCAgMHgxODE0Mzg2YiwgMHgzMGJjYzMzZCwgMHgzOGEwYzA3ZCwgMHhmZDE2MDZmMiwgMHhjMzYzNTE5YiwgMHg1ODlkZDM5MCwgMHg1NDc5ZjhlNiwgMHgxY2I4ZDY0NyxcclxuXHRcdCAgMHg5N2ZkNjFhOSwgMHhlYTc3NTlmNCwgMHgyZDU3NTM5ZCwgMHg1NjlhNThjZiwgMHhlODRlNjNhZCwgMHg0NjJlMWI3OCwgMHg2NTgwZjg3ZSwgMHhmMzgxNzkxNCxcclxuXHRcdCAgMHg5MWRhNTVmNCwgMHg0MGEyMzBmMywgMHhkMTk4OGYzNSwgMHhiNmUzMThkMiwgMHgzZmZhNTBiYywgMHgzZDQwZjAyMSwgMHhjM2MwYmRhZSwgMHg0OTU4YzI0YyxcclxuXHRcdCAgMHg1MThmMzZiMiwgMHg4NGIxZDM3MCwgMHgwZmVkY2U4MywgMHg4NzhkZGFkYSwgMHhmMmEyNzljNywgMHg5NGUwMWJlOCwgMHg5MDcxNmY0YiwgMHg5NTRiOGFhMyk7XHJcblxyXG5cdFx0c0JveFs3XSA9IG5ldyBBcnJheShcclxuXHRcdCAgMHhlMjE2MzAwZCwgMHhiYmRkZmZmYywgMHhhN2ViZGFiZCwgMHgzNTY0ODA5NSwgMHg3Nzg5ZjhiNywgMHhlNmMxMTIxYiwgMHgwZTI0MTYwMCwgMHgwNTJjZThiNSxcclxuXHRcdCAgMHgxMWE5Y2ZiMCwgMHhlNTk1MmYxMSwgMHhlY2U3OTkwYSwgMHg5Mzg2ZDE3NCwgMHgyYTQyOTMxYywgMHg3NmUzODExMSwgMHhiMTJkZWYzYSwgMHgzN2RkZGRmYyxcclxuXHRcdCAgMHhkZTlhZGViMSwgMHgwYTBjYzMyYywgMHhiZTE5NzAyOSwgMHg4NGEwMDk0MCwgMHhiYjI0M2EwZiwgMHhiNGQxMzdjZiwgMHhiNDRlNzlmMCwgMHgwNDllZWRmZCxcclxuXHRcdCAgMHgwYjE1YTE1ZCwgMHg0ODBkMzE2OCwgMHg4YmJiZGU1YSwgMHg2NjlkZWQ0MiwgMHhjN2VjZTgzMSwgMHgzZjhmOTVlNywgMHg3MmRmMTkxYiwgMHg3NTgwMzMwZCxcclxuXHRcdCAgMHg5NDA3NDI1MSwgMHg1YzdkY2RmYSwgMHhhYmJlNmQ2MywgMHhhYTQwMjE2NCwgMHhiMzAxZDQwYSwgMHgwMmU3ZDFjYSwgMHg1MzU3MWRhZSwgMHg3YTMxODJhMixcclxuXHRcdCAgMHgxMmE4ZGRlYywgMHhmZGFhMzM1ZCwgMHgxNzZmNDNlOCwgMHg3MWZiNDZkNCwgMHgzODEyOTAyMiwgMHhjZTk0OWFkNCwgMHhiODQ3NjlhZCwgMHg5NjViZDg2MixcclxuXHRcdCAgMHg4MmYzZDA1NSwgMHg2NmZiOTc2NywgMHgxNWI4MGI0ZSwgMHgxZDViNDdhMCwgMHg0Y2ZkZTA2ZiwgMHhjMjhlYzRiOCwgMHg1N2U4NzI2ZSwgMHg2NDdhNzhmYyxcclxuXHRcdCAgMHg5OTg2NWQ0NCwgMHg2MDhiZDU5MywgMHg2YzIwMGUwMywgMHgzOWRjNWZmNiwgMHg1ZDBiMDBhMywgMHhhZTYzYWZmMiwgMHg3ZThiZDYzMiwgMHg3MDEwOGMwYyxcclxuXHRcdCAgMHhiYmQzNTA0OSwgMHgyOTk4ZGYwNCwgMHg5ODBjZjQyYSwgMHg5YjZkZjQ5MSwgMHg5ZTdlZGQ1MywgMHgwNjkxODU0OCwgMHg1OGNiN2UwNywgMHgzYjc0ZWYyZSxcclxuXHRcdCAgMHg1MjJmZmZiMSwgMHhkMjQ3MDhjYywgMHgxYzdlMjdjZCwgMHhhNGViMjE1YiwgMHgzY2YxZDJlMiwgMHgxOWI0N2EzOCwgMHg0MjRmNzYxOCwgMHgzNTg1NjAzOSxcclxuXHRcdCAgMHg5ZDE3ZGVlNywgMHgyN2ViMzVlNiwgMHhjOWFmZjY3YiwgMHgzNmJhZjViOCwgMHgwOWM0NjdjZCwgMHhjMTg5MTBiMSwgMHhlMTFkYmY3YiwgMHgwNmNkMWFmOCxcclxuXHRcdCAgMHg3MTcwYzYwOCwgMHgyZDVlMzM1NCwgMHhkNGRlNDk1YSwgMHg2NGM2ZDAwNiwgMHhiY2MwYzYyYywgMHgzZGQwMGRiMywgMHg3MDhmOGYzNCwgMHg3N2Q1MWI0MixcclxuXHRcdCAgMHgyNjRmNjIwZiwgMHgyNGI4ZDJiZiwgMHgxNWMxYjc5ZSwgMHg0NmE1MjU2NCwgMHhmOGQ3ZTU0ZSwgMHgzZTM3ODE2MCwgMHg3ODk1Y2RhNSwgMHg4NTljMTVhNSxcclxuXHRcdCAgMHhlNjQ1OTc4OCwgMHhjMzdiYzc1ZiwgMHhkYjA3YmEwYywgMHgwNjc2YTNhYiwgMHg3ZjIyOWIxZSwgMHgzMTg0MmU3YiwgMHgyNDI1OWZkNywgMHhmOGJlZjQ3MixcclxuXHRcdCAgMHg4MzVmZmNiOCwgMHg2ZGY0YzFmMiwgMHg5NmY1YjE5NSwgMHhmZDBhZjBmYywgMHhiMGZlMTM0YywgMHhlMjUwNmQzZCwgMHg0ZjliMTJlYSwgMHhmMjE1ZjIyNSxcclxuXHRcdCAgMHhhMjIzNzM2ZiwgMHg5ZmI0YzQyOCwgMHgyNWQwNDk3OSwgMHgzNGM3MTNmOCwgMHhjNDYxODE4NywgMHhlYTdhNmU5OCwgMHg3Y2QxNmVmYywgMHgxNDM2ODc2YyxcclxuXHRcdCAgMHhmMTU0NDEwNywgMHhiZWRlZWUxNCwgMHg1NmU5YWYyNywgMHhhMDRhYTQ0MSwgMHgzY2Y3Yzg5OSwgMHg5MmVjYmFlNiwgMHhkZDY3MDE2ZCwgMHgxNTE2ODJlYixcclxuXHRcdCAgMHhhODQyZWVkZiwgMHhmZGJhNjBiNCwgMHhmMTkwN2I3NSwgMHgyMGUzMDMwZiwgMHgyNGQ4YzI5ZSwgMHhlMTM5NjczYiwgMHhlZmE2M2ZiOCwgMHg3MTg3MzA1NCxcclxuXHRcdCAgMHhiNmYyY2YzYiwgMHg5ZjMyNjQ0MiwgMHhjYjE1YTRjYywgMHhiMDFhNDUwNCwgMHhmMWU0N2Q4ZCwgMHg4NDRhMWJlNSwgMHhiYWU3ZGZkYywgMHg0MmNiZGE3MCxcclxuXHRcdCAgMHhjZDdkYWUwYSwgMHg1N2U4NWI3YSwgMHhkNTNmNWFmNiwgMHgyMGNmNGQ4YywgMHhjZWE0ZDQyOCwgMHg3OWQxMzBhNCwgMHgzNDg2ZWJmYiwgMHgzM2QzY2RkYyxcclxuXHRcdCAgMHg3Nzg1M2I1MywgMHgzN2VmZmNiNSwgMHhjNTA2ODc3OCwgMHhlNTgwYjNlNiwgMHg0ZTY4YjhmNCwgMHhjNWM4YjM3ZSwgMHgwZDgwOWVhMiwgMHgzOThmZWI3YyxcclxuXHRcdCAgMHgxMzJhNGY5NCwgMHg0M2I3OTUwZSwgMHgyZmVlN2QxYywgMHgyMjM2MTNiZCwgMHhkZDA2Y2FhMiwgMHgzN2RmOTMyYiwgMHhjNDI0ODI4OSwgMHhhY2YzZWJjMyxcclxuXHRcdCAgMHg1NzE1ZjZiNywgMHhlZjM0NzhkZCwgMHhmMjY3NjE2ZiwgMHhjMTQ4Y2JlNCwgMHg5MDUyODE1ZSwgMHg1ZTQxMGZhYiwgMHhiNDhhMjQ2NSwgMHgyZWRhN2ZhNCxcclxuXHRcdCAgMHhlODdiNDBlNCwgMHhlOThlYTA4NCwgMHg1ODg5ZTllMSwgMHhlZmQzOTBmYywgMHhkZDA3ZDM1YiwgMHhkYjQ4NTY5NCwgMHgzOGQ3ZTViMiwgMHg1NzcyMDEwMSxcclxuXHRcdCAgMHg3MzBlZGViYywgMHg1YjY0MzExMywgMHg5NDkxN2U0ZiwgMHg1MDNjMmZiYSwgMHg2NDZmMTI4MiwgMHg3NTIzZDI0YSwgMHhlMDc3OTY5NSwgMHhmOWMxN2E4ZixcclxuXHRcdCAgMHg3YTViMjEyMSwgMHhkMTg3Yjg5NiwgMHgyOTI2M2E0ZCwgMHhiYTUxMGNkZiwgMHg4MWY0N2M5ZiwgMHhhZDExNjNlZCwgMHhlYTdiNTk2NSwgMHgxYTAwNzI2ZSxcclxuXHRcdCAgMHgxMTQwMzA5MiwgMHgwMGRhNmQ3NywgMHg0YTBjZGQ2MSwgMHhhZDFmNDYwMywgMHg2MDViZGZiMCwgMHg5ZWVkYzM2NCwgMHgyMmViZTZhOCwgMHhjZWU3ZDI4YSxcclxuXHRcdCAgMHhhMGU3MzZhMCwgMHg1NTY0YTZiOSwgMHgxMDg1MzIwOSwgMHhjN2ViOGYzNywgMHgyZGU3MDVjYSwgMHg4OTUxNTcwZiwgMHhkZjA5ODIyYiwgMHhiZDY5MWE2YyxcclxuXHRcdCAgMHhhYTEyZTRmMiwgMHg4NzQ1MWMwZiwgMHhlMGY2YTI3YSwgMHgzYWRhNDgxOSwgMHg0Y2YxNzY0ZiwgMHgwZDc3MWMyYiwgMHg2N2NkYjE1NiwgMHgzNTBkODM4NCxcclxuXHRcdCAgMHg1OTM4ZmEwZiwgMHg0MjM5OWVmMywgMHgzNjk5N2IwNywgMHgwZTg0MDkzZCwgMHg0YWE5M2U2MSwgMHg4MzYwZDg3YiwgMHgxZmE5OGIwYywgMHgxMTQ5MzgyYyxcclxuXHRcdCAgMHhlOTc2MjVhNSwgMHgwNjE0ZDFiNywgMHgwZTI1MjQ0YiwgMHgwYzc2ODM0NywgMHg1ODllOGQ4MiwgMHgwZDIwNTlkMSwgMHhhNDY2YmIxZSwgMHhmOGRhMGE4MixcclxuXHRcdCAgMHgwNGYxOTEzMCwgMHhiYTZlNGVjMCwgMHg5OTI2NTE2NCwgMHgxZWU3MjMwZCwgMHg1MGIyYWQ4MCwgMHhlYWVlNjgwMSwgMHg4ZGIyYTI4MywgMHhlYThiZjU5ZSk7XHJcblxyXG59O1xyXG5cclxuXHJcbm1vZHVsZS5leHBvcnRzID0gY2FzdDVfZW5jcnlwdDtcclxuIiwiLyogTW9kaWZpZWQgYnkgUmVjdXJpdHkgTGFicyBHbWJIIFxuICogXG4gKiBDaXBoZXIuanNcbiAqIEEgYmxvY2stY2lwaGVyIGFsZ29yaXRobSBpbXBsZW1lbnRhdGlvbiBvbiBKYXZhU2NyaXB0XG4gKiBTZWUgQ2lwaGVyLnJlYWRtZS50eHQgZm9yIGZ1cnRoZXIgaW5mb3JtYXRpb24uXG4gKlxuICogQ29weXJpZ2h0KGMpIDIwMDkgQXRzdXNoaSBPa2EgWyBodHRwOi8vb2thLm51LyBdXG4gKiBUaGlzIHNjcmlwdCBmaWxlIGlzIGRpc3RyaWJ1dGVkIHVuZGVyIHRoZSBMR1BMXG4gKlxuICogQUNLTk9XTEVER01FTlRcbiAqXG4gKiAgICAgVGhlIG1haW4gc3Vicm91dGluZXMgYXJlIHdyaXR0ZW4gYnkgTWljaGllbCB2YW4gRXZlcmRpbmdlbi5cbiAqIFxuICogICAgIE1pY2hpZWwgdmFuIEV2ZXJkaW5nZW5cbiAqICAgICBodHRwOi8vaG9tZS52ZXJzYXRlbC5ubC9NQXZhbkV2ZXJkaW5nZW4vaW5kZXguaHRtbFxuICogXG4gKiAgICAgQWxsIHJpZ2h0cyBmb3IgdGhlc2Ugcm91dGluZXMgYXJlIHJlc2VydmVkIHRvIE1pY2hpZWwgdmFuIEV2ZXJkaW5nZW4uXG4gKlxuICovXG5cbnZhciB1dGlsID0gcmVxdWlyZSgnLi4vLi4vdXRpbCcpO1xuXG4vLyBhZGRlZCBieSBSZWN1cml0eSBMYWJzXG5mdW5jdGlvbiBURmVuY3J5cHQoYmxvY2ssIGtleSkge1xuXHR2YXIgYmxvY2tfY29weSA9IFtdLmNvbmNhdChibG9jayk7XG5cdHZhciB0ZiA9IGNyZWF0ZVR3b2Zpc2goKTtcblx0dGYub3Blbih1dGlsLnN0cjJiaW4oa2V5KSwwKTtcblx0dmFyIHJlc3VsdCA9IHRmLmVuY3J5cHQoYmxvY2tfY29weSwgMCk7XG5cdHRmLmNsb3NlKCk7XG5cdHJldHVybiByZXN1bHQ7XG59XG5cbi8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1xuLy9NYXRoXG4vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9cblxudmFyIE1BWElOVCA9IDB4RkZGRkZGRkY7XG5cbmZ1bmN0aW9uIHJvdGIoYixuKXsgcmV0dXJuICggYjw8biB8IGI+Pj4oIDgtbikgKSAmIDB4RkY7IH1cbmZ1bmN0aW9uIHJvdHcodyxuKXsgcmV0dXJuICggdzw8biB8IHc+Pj4oMzItbikgKSAmIE1BWElOVDsgfVxuZnVuY3Rpb24gZ2V0VyhhLGkpeyByZXR1cm4gYVtpXXxhW2krMV08PDh8YVtpKzJdPDwxNnxhW2krM108PDI0OyB9XG5mdW5jdGlvbiBzZXRXKGEsaSx3KXsgYS5zcGxpY2UoaSw0LHcmMHhGRiwodz4+PjgpJjB4RkYsKHc+Pj4xNikmMHhGRiwodz4+PjI0KSYweEZGKTsgfVxuZnVuY3Rpb24gc2V0V0ludihhLGksdyl7IGEuc3BsaWNlKGksNCwodz4+PjI0KSYweEZGLCh3Pj4+MTYpJjB4RkYsKHc+Pj44KSYweEZGLHcmMHhGRik7IH1cbmZ1bmN0aW9uIGdldEIoeCxuKXsgcmV0dXJuICh4Pj4+KG4qOCkpJjB4RkY7IH1cblxuZnVuY3Rpb24gZ2V0TnJCaXRzKGkpeyB2YXIgbj0wOyB3aGlsZSAoaT4wKXsgbisrOyBpPj4+PTE7IH0gcmV0dXJuIG47IH1cbmZ1bmN0aW9uIGdldE1hc2sobil7IHJldHVybiAoMTw8biktMTsgfVxuXG4vL2FkZGVkIDIwMDgvMTEvMTMgWFhYIE1VU1QgVVNFIE9ORS1XQVkgSEFTSCBGVU5DVElPTiBGT1IgU0VDVVJJVFkgUkVBU09OXG5mdW5jdGlvbiByYW5kQnl0ZSgpIHtcbiByZXR1cm4gTWF0aC5mbG9vciggTWF0aC5yYW5kb20oKSAqIDI1NiApO1xufVxuLy8gLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1xuLy8gVHdvZmlzaFxuLy8gLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1xuXG5mdW5jdGlvbiBjcmVhdGVUd29maXNoKCkge1xuXHQvL1xuXHR2YXIga2V5Qnl0ZXMgPSBudWxsO1xuXHR2YXIgZGF0YUJ5dGVzID0gbnVsbDtcblx0dmFyIGRhdGFPZmZzZXQgPSAtMTtcblx0Ly8gdmFyIGRhdGFMZW5ndGggPSAtMTtcblx0dmFyIGFsZ29yaXRobU5hbWUgPSBudWxsO1xuXHQvLyB2YXIgaWR4MiA9IC0xO1xuXHQvL1xuXG5cdGFsZ29yaXRobU5hbWUgPSBcInR3b2Zpc2hcIjtcblxuXHR2YXIgdGZzS2V5ID0gW107XG5cdHZhciB0ZnNNID0gWyBbXSwgW10sIFtdLCBbXSBdO1xuXG5cdGZ1bmN0aW9uIHRmc0luaXQoa2V5KSB7XG5cdFx0a2V5Qnl0ZXMgPSBrZXk7XG5cdFx0dmFyIGksIGEsIGIsIGMsIGQsIG1lS2V5ID0gW10sIG1vS2V5ID0gW10sIGluS2V5ID0gW107XG5cdFx0dmFyIGtMZW47XG5cdFx0dmFyIHNLZXkgPSBbXTtcblx0XHR2YXIgZjAxLCBmNWIsIGZlZjtcblxuXHRcdHZhciBxMCA9IFsgWyA4LCAxLCA3LCAxMywgNiwgMTUsIDMsIDIsIDAsIDExLCA1LCA5LCAxNCwgMTIsIDEwLCA0IF0sXG5cdFx0XHRcdFsgMiwgOCwgMTEsIDEzLCAxNSwgNywgNiwgMTQsIDMsIDEsIDksIDQsIDAsIDEwLCAxMiwgNSBdIF07XG5cdFx0dmFyIHExID0gWyBbIDE0LCAxMiwgMTEsIDgsIDEsIDIsIDMsIDUsIDE1LCA0LCAxMCwgNiwgNywgMCwgOSwgMTMgXSxcblx0XHRcdFx0WyAxLCAxNCwgMiwgMTEsIDQsIDEyLCAzLCA3LCA2LCAxMywgMTAsIDUsIDE1LCA5LCAwLCA4IF0gXTtcblx0XHR2YXIgcTIgPSBbIFsgMTEsIDEwLCA1LCAxNCwgNiwgMTMsIDksIDAsIDEyLCA4LCAxNSwgMywgMiwgNCwgNywgMSBdLFxuXHRcdFx0XHRbIDQsIDEyLCA3LCA1LCAxLCA2LCA5LCAxMCwgMCwgMTQsIDEzLCA4LCAyLCAxMSwgMywgMTUgXSBdO1xuXHRcdHZhciBxMyA9IFsgWyAxMywgNywgMTUsIDQsIDEsIDIsIDYsIDE0LCA5LCAxMSwgMywgMCwgOCwgNSwgMTIsIDEwIF0sXG5cdFx0XHRcdFsgMTEsIDksIDUsIDEsIDEyLCAzLCAxMywgMTQsIDYsIDQsIDcsIDE1LCAyLCAwLCA4LCAxMCBdIF07XG5cdFx0dmFyIHJvcjQgPSBbIDAsIDgsIDEsIDksIDIsIDEwLCAzLCAxMSwgNCwgMTIsIDUsIDEzLCA2LCAxNCwgNywgMTUgXTtcblx0XHR2YXIgYXNoeCA9IFsgMCwgOSwgMiwgMTEsIDQsIDEzLCA2LCAxNSwgOCwgMSwgMTAsIDMsIDEyLCA1LCAxNCwgNyBdO1xuXHRcdHZhciBxID0gWyBbXSwgW10gXTtcblx0XHR2YXIgbSA9IFsgW10sIFtdLCBbXSwgW10gXTtcblxuXHRcdGZ1bmN0aW9uIGZmbTViKHgpIHtcblx0XHRcdHJldHVybiB4IF4gKHggPj4gMikgXiBbIDAsIDkwLCAxODAsIDIzOCBdW3ggJiAzXTtcblx0XHR9XG5cdFx0ZnVuY3Rpb24gZmZtRWYoeCkge1xuXHRcdFx0cmV0dXJuIHggXiAoeCA+PiAxKSBeICh4ID4+IDIpIF4gWyAwLCAyMzgsIDE4MCwgOTAgXVt4ICYgM107XG5cdFx0fVxuXG5cdFx0ZnVuY3Rpb24gbWRzUmVtKHAsIHEpIHtcblx0XHRcdHZhciBpLCB0LCB1O1xuXHRcdFx0Zm9yIChpID0gMDsgaSA8IDg7IGkrKykge1xuXHRcdFx0XHR0ID0gcSA+Pj4gMjQ7XG5cdFx0XHRcdHEgPSAoKHEgPDwgOCkgJiBNQVhJTlQpIHwgcCA+Pj4gMjQ7XG5cdFx0XHRcdHAgPSAocCA8PCA4KSAmIE1BWElOVDtcblx0XHRcdFx0dSA9IHQgPDwgMTtcblx0XHRcdFx0aWYgKHQgJiAxMjgpIHtcblx0XHRcdFx0XHR1IF49IDMzMztcblx0XHRcdFx0fVxuXHRcdFx0XHRxIF49IHQgXiAodSA8PCAxNik7XG5cdFx0XHRcdHUgXj0gdCA+Pj4gMTtcblx0XHRcdFx0aWYgKHQgJiAxKSB7XG5cdFx0XHRcdFx0dSBePSAxNjY7XG5cdFx0XHRcdH1cblx0XHRcdFx0cSBePSB1IDw8IDI0IHwgdSA8PCA4O1xuXHRcdFx0fVxuXHRcdFx0cmV0dXJuIHE7XG5cdFx0fVxuXG5cdFx0ZnVuY3Rpb24gcXAobiwgeCkge1xuXHRcdFx0dmFyIGEsIGIsIGMsIGQ7XG5cdFx0XHRhID0geCA+PiA0O1xuXHRcdFx0YiA9IHggJiAxNTtcblx0XHRcdGMgPSBxMFtuXVthIF4gYl07XG5cdFx0XHRkID0gcTFbbl1bcm9yNFtiXSBeIGFzaHhbYV1dO1xuXHRcdFx0cmV0dXJuIHEzW25dW3JvcjRbZF0gXiBhc2h4W2NdXSA8PCA0IHwgcTJbbl1bYyBeIGRdO1xuXHRcdH1cblxuXHRcdGZ1bmN0aW9uIGhGdW4oeCwga2V5KSB7XG5cdFx0XHR2YXIgYSA9IGdldEIoeCwgMCksIGIgPSBnZXRCKHgsIDEpLCBjID0gZ2V0Qih4LCAyKSwgZCA9IGdldEIoeCwgMyk7XG5cdFx0XHRzd2l0Y2ggKGtMZW4pIHtcblx0XHRcdGNhc2UgNDpcblx0XHRcdFx0YSA9IHFbMV1bYV0gXiBnZXRCKGtleVszXSwgMCk7XG5cdFx0XHRcdGIgPSBxWzBdW2JdIF4gZ2V0QihrZXlbM10sIDEpO1xuXHRcdFx0XHRjID0gcVswXVtjXSBeIGdldEIoa2V5WzNdLCAyKTtcblx0XHRcdFx0ZCA9IHFbMV1bZF0gXiBnZXRCKGtleVszXSwgMyk7XG5cdFx0XHRjYXNlIDM6XG5cdFx0XHRcdGEgPSBxWzFdW2FdIF4gZ2V0QihrZXlbMl0sIDApO1xuXHRcdFx0XHRiID0gcVsxXVtiXSBeIGdldEIoa2V5WzJdLCAxKTtcblx0XHRcdFx0YyA9IHFbMF1bY10gXiBnZXRCKGtleVsyXSwgMik7XG5cdFx0XHRcdGQgPSBxWzBdW2RdIF4gZ2V0QihrZXlbMl0sIDMpO1xuXHRcdFx0Y2FzZSAyOlxuXHRcdFx0XHRhID0gcVswXVtxWzBdW2FdIF4gZ2V0QihrZXlbMV0sIDApXSBeIGdldEIoa2V5WzBdLCAwKTtcblx0XHRcdFx0YiA9IHFbMF1bcVsxXVtiXSBeIGdldEIoa2V5WzFdLCAxKV0gXiBnZXRCKGtleVswXSwgMSk7XG5cdFx0XHRcdGMgPSBxWzFdW3FbMF1bY10gXiBnZXRCKGtleVsxXSwgMildIF4gZ2V0QihrZXlbMF0sIDIpO1xuXHRcdFx0XHRkID0gcVsxXVtxWzFdW2RdIF4gZ2V0QihrZXlbMV0sIDMpXSBeIGdldEIoa2V5WzBdLCAzKTtcblx0XHRcdH1cblx0XHRcdHJldHVybiBtWzBdW2FdIF4gbVsxXVtiXSBeIG1bMl1bY10gXiBtWzNdW2RdO1xuXHRcdH1cblxuXHRcdGtleUJ5dGVzID0ga2V5Qnl0ZXMuc2xpY2UoMCwgMzIpO1xuXHRcdGkgPSBrZXlCeXRlcy5sZW5ndGg7XG5cdFx0d2hpbGUgKGkgIT0gMTYgJiYgaSAhPSAyNCAmJiBpICE9IDMyKVxuXHRcdFx0a2V5Qnl0ZXNbaSsrXSA9IDA7XG5cblx0XHRmb3IgKGkgPSAwOyBpIDwga2V5Qnl0ZXMubGVuZ3RoOyBpICs9IDQpIHtcblx0XHRcdGluS2V5W2kgPj4gMl0gPSBnZXRXKGtleUJ5dGVzLCBpKTtcblx0XHR9XG5cdFx0Zm9yIChpID0gMDsgaSA8IDI1NjsgaSsrKSB7XG5cdFx0XHRxWzBdW2ldID0gcXAoMCwgaSk7XG5cdFx0XHRxWzFdW2ldID0gcXAoMSwgaSk7XG5cdFx0fVxuXHRcdGZvciAoaSA9IDA7IGkgPCAyNTY7IGkrKykge1xuXHRcdFx0ZjAxID0gcVsxXVtpXTtcblx0XHRcdGY1YiA9IGZmbTViKGYwMSk7XG5cdFx0XHRmZWYgPSBmZm1FZihmMDEpO1xuXHRcdFx0bVswXVtpXSA9IGYwMSArIChmNWIgPDwgOCkgKyAoZmVmIDw8IDE2KSArIChmZWYgPDwgMjQpO1xuXHRcdFx0bVsyXVtpXSA9IGY1YiArIChmZWYgPDwgOCkgKyAoZjAxIDw8IDE2KSArIChmZWYgPDwgMjQpO1xuXHRcdFx0ZjAxID0gcVswXVtpXTtcblx0XHRcdGY1YiA9IGZmbTViKGYwMSk7XG5cdFx0XHRmZWYgPSBmZm1FZihmMDEpO1xuXHRcdFx0bVsxXVtpXSA9IGZlZiArIChmZWYgPDwgOCkgKyAoZjViIDw8IDE2KSArIChmMDEgPDwgMjQpO1xuXHRcdFx0bVszXVtpXSA9IGY1YiArIChmMDEgPDwgOCkgKyAoZmVmIDw8IDE2KSArIChmNWIgPDwgMjQpO1xuXHRcdH1cblxuXHRcdGtMZW4gPSBpbktleS5sZW5ndGggLyAyO1xuXHRcdGZvciAoaSA9IDA7IGkgPCBrTGVuOyBpKyspIHtcblx0XHRcdGEgPSBpbktleVtpICsgaV07XG5cdFx0XHRtZUtleVtpXSA9IGE7XG5cdFx0XHRiID0gaW5LZXlbaSArIGkgKyAxXTtcblx0XHRcdG1vS2V5W2ldID0gYjtcblx0XHRcdHNLZXlba0xlbiAtIGkgLSAxXSA9IG1kc1JlbShhLCBiKTtcblx0XHR9XG5cdFx0Zm9yIChpID0gMDsgaSA8IDQwOyBpICs9IDIpIHtcblx0XHRcdGEgPSAweDEwMTAxMDEgKiBpO1xuXHRcdFx0YiA9IGEgKyAweDEwMTAxMDE7XG5cdFx0XHRhID0gaEZ1bihhLCBtZUtleSk7XG5cdFx0XHRiID0gcm90dyhoRnVuKGIsIG1vS2V5KSwgOCk7XG5cdFx0XHR0ZnNLZXlbaV0gPSAoYSArIGIpICYgTUFYSU5UO1xuXHRcdFx0dGZzS2V5W2kgKyAxXSA9IHJvdHcoYSArIDIgKiBiLCA5KTtcblx0XHR9XG5cdFx0Zm9yIChpID0gMDsgaSA8IDI1NjsgaSsrKSB7XG5cdFx0XHRhID0gYiA9IGMgPSBkID0gaTtcblx0XHRcdHN3aXRjaCAoa0xlbikge1xuXHRcdFx0Y2FzZSA0OlxuXHRcdFx0XHRhID0gcVsxXVthXSBeIGdldEIoc0tleVszXSwgMCk7XG5cdFx0XHRcdGIgPSBxWzBdW2JdIF4gZ2V0QihzS2V5WzNdLCAxKTtcblx0XHRcdFx0YyA9IHFbMF1bY10gXiBnZXRCKHNLZXlbM10sIDIpO1xuXHRcdFx0XHRkID0gcVsxXVtkXSBeIGdldEIoc0tleVszXSwgMyk7XG5cdFx0XHRjYXNlIDM6XG5cdFx0XHRcdGEgPSBxWzFdW2FdIF4gZ2V0QihzS2V5WzJdLCAwKTtcblx0XHRcdFx0YiA9IHFbMV1bYl0gXiBnZXRCKHNLZXlbMl0sIDEpO1xuXHRcdFx0XHRjID0gcVswXVtjXSBeIGdldEIoc0tleVsyXSwgMik7XG5cdFx0XHRcdGQgPSBxWzBdW2RdIF4gZ2V0QihzS2V5WzJdLCAzKTtcblx0XHRcdGNhc2UgMjpcblx0XHRcdFx0dGZzTVswXVtpXSA9IG1bMF1bcVswXVtxWzBdW2FdIF4gZ2V0QihzS2V5WzFdLCAwKV1cblx0XHRcdFx0XHRcdF4gZ2V0QihzS2V5WzBdLCAwKV07XG5cdFx0XHRcdHRmc01bMV1baV0gPSBtWzFdW3FbMF1bcVsxXVtiXSBeIGdldEIoc0tleVsxXSwgMSldXG5cdFx0XHRcdFx0XHReIGdldEIoc0tleVswXSwgMSldO1xuXHRcdFx0XHR0ZnNNWzJdW2ldID0gbVsyXVtxWzFdW3FbMF1bY10gXiBnZXRCKHNLZXlbMV0sIDIpXVxuXHRcdFx0XHRcdFx0XiBnZXRCKHNLZXlbMF0sIDIpXTtcblx0XHRcdFx0dGZzTVszXVtpXSA9IG1bM11bcVsxXVtxWzFdW2RdIF4gZ2V0QihzS2V5WzFdLCAzKV1cblx0XHRcdFx0XHRcdF4gZ2V0QihzS2V5WzBdLCAzKV07XG5cdFx0XHR9XG5cdFx0fVxuXHR9XG5cblx0ZnVuY3Rpb24gdGZzRzAoeCkge1xuXHRcdHJldHVybiB0ZnNNWzBdW2dldEIoeCwgMCldIF4gdGZzTVsxXVtnZXRCKHgsIDEpXSBeIHRmc01bMl1bZ2V0Qih4LCAyKV1cblx0XHRcdFx0XiB0ZnNNWzNdW2dldEIoeCwgMyldO1xuXHR9XG5cdGZ1bmN0aW9uIHRmc0cxKHgpIHtcblx0XHRyZXR1cm4gdGZzTVswXVtnZXRCKHgsIDMpXSBeIHRmc01bMV1bZ2V0Qih4LCAwKV0gXiB0ZnNNWzJdW2dldEIoeCwgMSldXG5cdFx0XHRcdF4gdGZzTVszXVtnZXRCKHgsIDIpXTtcblx0fVxuXG5cdGZ1bmN0aW9uIHRmc0ZybmQociwgYmxrKSB7XG5cdFx0dmFyIGEgPSB0ZnNHMChibGtbMF0pO1xuXHRcdHZhciBiID0gdGZzRzEoYmxrWzFdKTtcblx0XHRibGtbMl0gPSByb3R3KGJsa1syXSBeIChhICsgYiArIHRmc0tleVs0ICogciArIDhdKSAmIE1BWElOVCwgMzEpO1xuXHRcdGJsa1szXSA9IHJvdHcoYmxrWzNdLCAxKSBeIChhICsgMiAqIGIgKyB0ZnNLZXlbNCAqIHIgKyA5XSkgJiBNQVhJTlQ7XG5cdFx0YSA9IHRmc0cwKGJsa1syXSk7XG5cdFx0YiA9IHRmc0cxKGJsa1szXSk7XG5cdFx0YmxrWzBdID0gcm90dyhibGtbMF0gXiAoYSArIGIgKyB0ZnNLZXlbNCAqIHIgKyAxMF0pICYgTUFYSU5ULCAzMSk7XG5cdFx0YmxrWzFdID0gcm90dyhibGtbMV0sIDEpIF4gKGEgKyAyICogYiArIHRmc0tleVs0ICogciArIDExXSkgJiBNQVhJTlQ7XG5cdH1cblxuXHRmdW5jdGlvbiB0ZnNJcm5kKGksIGJsaykge1xuXHRcdHZhciBhID0gdGZzRzAoYmxrWzBdKTtcblx0XHR2YXIgYiA9IHRmc0cxKGJsa1sxXSk7XG5cdFx0YmxrWzJdID0gcm90dyhibGtbMl0sIDEpIF4gKGEgKyBiICsgdGZzS2V5WzQgKiBpICsgMTBdKSAmIE1BWElOVDtcblx0XHRibGtbM10gPSByb3R3KGJsa1szXSBeIChhICsgMiAqIGIgKyB0ZnNLZXlbNCAqIGkgKyAxMV0pICYgTUFYSU5ULCAzMSk7XG5cdFx0YSA9IHRmc0cwKGJsa1syXSk7XG5cdFx0YiA9IHRmc0cxKGJsa1szXSk7XG5cdFx0YmxrWzBdID0gcm90dyhibGtbMF0sIDEpIF4gKGEgKyBiICsgdGZzS2V5WzQgKiBpICsgOF0pICYgTUFYSU5UO1xuXHRcdGJsa1sxXSA9IHJvdHcoYmxrWzFdIF4gKGEgKyAyICogYiArIHRmc0tleVs0ICogaSArIDldKSAmIE1BWElOVCwgMzEpO1xuXHR9XG5cblx0ZnVuY3Rpb24gdGZzQ2xvc2UoKSB7XG5cdFx0dGZzS2V5ID0gW107XG5cdFx0dGZzTSA9IFsgW10sIFtdLCBbXSwgW10gXTtcblx0fVxuXG5cdGZ1bmN0aW9uIHRmc0VuY3J5cHQoZGF0YSwgb2Zmc2V0KSB7XG5cdFx0ZGF0YUJ5dGVzID0gZGF0YTtcblx0XHRkYXRhT2Zmc2V0ID0gb2Zmc2V0O1xuXHRcdHZhciBibGsgPSBbIGdldFcoZGF0YUJ5dGVzLCBkYXRhT2Zmc2V0KSBeIHRmc0tleVswXSxcblx0XHRcdFx0Z2V0VyhkYXRhQnl0ZXMsIGRhdGFPZmZzZXQgKyA0KSBeIHRmc0tleVsxXSxcblx0XHRcdFx0Z2V0VyhkYXRhQnl0ZXMsIGRhdGFPZmZzZXQgKyA4KSBeIHRmc0tleVsyXSxcblx0XHRcdFx0Z2V0VyhkYXRhQnl0ZXMsIGRhdGFPZmZzZXQgKyAxMikgXiB0ZnNLZXlbM10gXTtcblx0XHRmb3IgKCB2YXIgaiA9IDA7IGogPCA4OyBqKyspIHtcblx0XHRcdHRmc0ZybmQoaiwgYmxrKTtcblx0XHR9XG5cdFx0c2V0VyhkYXRhQnl0ZXMsIGRhdGFPZmZzZXQsIGJsa1syXSBeIHRmc0tleVs0XSk7XG5cdFx0c2V0VyhkYXRhQnl0ZXMsIGRhdGFPZmZzZXQgKyA0LCBibGtbM10gXiB0ZnNLZXlbNV0pO1xuXHRcdHNldFcoZGF0YUJ5dGVzLCBkYXRhT2Zmc2V0ICsgOCwgYmxrWzBdIF4gdGZzS2V5WzZdKTtcblx0XHRzZXRXKGRhdGFCeXRlcywgZGF0YU9mZnNldCArIDEyLCBibGtbMV0gXiB0ZnNLZXlbN10pO1xuXHRcdGRhdGFPZmZzZXQgKz0gMTY7XG5cdFx0cmV0dXJuIGRhdGFCeXRlcztcblx0fVxuXG5cdGZ1bmN0aW9uIHRmc0RlY3J5cHQoZGF0YSwgb2Zmc2V0KSB7XG5cdFx0ZGF0YUJ5dGVzID0gZGF0YTtcblx0XHRkYXRhT2Zmc2V0ID0gb2Zmc2V0O1xuXHRcdHZhciBibGsgPSBbIGdldFcoZGF0YUJ5dGVzLCBkYXRhT2Zmc2V0KSBeIHRmc0tleVs0XSxcblx0XHRcdFx0Z2V0VyhkYXRhQnl0ZXMsIGRhdGFPZmZzZXQgKyA0KSBeIHRmc0tleVs1XSxcblx0XHRcdFx0Z2V0VyhkYXRhQnl0ZXMsIGRhdGFPZmZzZXQgKyA4KSBeIHRmc0tleVs2XSxcblx0XHRcdFx0Z2V0VyhkYXRhQnl0ZXMsIGRhdGFPZmZzZXQgKyAxMikgXiB0ZnNLZXlbN10gXTtcblx0XHRmb3IgKCB2YXIgaiA9IDc7IGogPj0gMDsgai0tKSB7XG5cdFx0XHR0ZnNJcm5kKGosIGJsayk7XG5cdFx0fVxuXHRcdHNldFcoZGF0YUJ5dGVzLCBkYXRhT2Zmc2V0LCBibGtbMl0gXiB0ZnNLZXlbMF0pO1xuXHRcdHNldFcoZGF0YUJ5dGVzLCBkYXRhT2Zmc2V0ICsgNCwgYmxrWzNdIF4gdGZzS2V5WzFdKTtcblx0XHRzZXRXKGRhdGFCeXRlcywgZGF0YU9mZnNldCArIDgsIGJsa1swXSBeIHRmc0tleVsyXSk7XG5cdFx0c2V0VyhkYXRhQnl0ZXMsIGRhdGFPZmZzZXQgKyAxMiwgYmxrWzFdIF4gdGZzS2V5WzNdKTtcblx0XHRkYXRhT2Zmc2V0ICs9IDE2O1xuXHR9XG5cdFxuXHQvLyBhZGRlZCBieSBSZWN1cml0eSBMYWJzXG5cdGZ1bmN0aW9uIHRmc0ZpbmFsKCkge1xuXHRcdHJldHVybiBkYXRhQnl0ZXM7XG5cdH1cblxuXHRyZXR1cm4ge1xuXHRcdG5hbWUgOiBcInR3b2Zpc2hcIixcblx0XHRibG9ja3NpemUgOiAxMjggLyA4LFxuXHRcdG9wZW4gOiB0ZnNJbml0LFxuXHRcdGNsb3NlIDogdGZzQ2xvc2UsXG5cdFx0ZW5jcnlwdCA6IHRmc0VuY3J5cHQsXG5cdFx0ZGVjcnlwdCA6IHRmc0RlY3J5cHQsXG5cdFx0Ly8gYWRkZWQgYnkgUmVjdXJpdHkgTGFic1xuXHRcdGZpbmFsaXplOiB0ZnNGaW5hbFxuXHR9O1xufVxuXG5tb2R1bGUuZXhwb3J0cyA9IFRGZW5jcnlwdDtcbiIsIi8qIE1vZGlmaWVkIGJ5IFJlY3VyaXR5IExhYnMgR21iSCBcbiAqIFxuICogT3JpZ2luYWxseSB3cml0dGVuIGJ5IG5rbGVpbiBzb2Z0d2FyZSAobmtsZWluLmNvbSlcbiAqL1xuXG4vKiBcbiAqIEphdmFzY3JpcHQgaW1wbGVtZW50YXRpb24gYmFzZWQgb24gQnJ1Y2UgU2NobmVpZXIncyByZWZlcmVuY2UgaW1wbGVtZW50YXRpb24uXG4gKlxuICpcbiAqIFRoZSBjb25zdHJ1Y3RvciBkb2Vzbid0IGRvIG11Y2ggb2YgYW55dGhpbmcuICBJdCdzIGp1c3QgaGVyZVxuICogc28gd2UgY2FuIHN0YXJ0IGRlZmluaW5nIHByb3BlcnRpZXMgYW5kIG1ldGhvZHMgYW5kIHN1Y2guXG4gKi9cbmZ1bmN0aW9uIEJsb3dmaXNoKCkge1xufTtcblxuLypcbiAqIERlY2xhcmUgdGhlIGJsb2NrIHNpemUgc28gdGhhdCBwcm90b2NvbHMga25vdyB3aGF0IHNpemVcbiAqIEluaXRpYWxpemF0aW9uIFZlY3RvciAoSVYpIHRoZXkgd2lsbCBuZWVkLlxuICovXG5CbG93ZmlzaC5wcm90b3R5cGUuQkxPQ0tTSVpFID0gODtcblxuLypcbiAqIFRoZXNlIGFyZSB0aGUgZGVmYXVsdCBTQk9YRVMuXG4gKi9cbkJsb3dmaXNoLnByb3RvdHlwZS5TQk9YRVMgPSBbXG4gICAgW1xuXHQweGQxMzEwYmE2LCAweDk4ZGZiNWFjLCAweDJmZmQ3MmRiLCAweGQwMWFkZmI3LCAweGI4ZTFhZmVkLCAweDZhMjY3ZTk2LFxuXHQweGJhN2M5MDQ1LCAweGYxMmM3Zjk5LCAweDI0YTE5OTQ3LCAweGIzOTE2Y2Y3LCAweDA4MDFmMmUyLCAweDg1OGVmYzE2LFxuXHQweDYzNjkyMGQ4LCAweDcxNTc0ZTY5LCAweGE0NThmZWEzLCAweGY0OTMzZDdlLCAweDBkOTU3NDhmLCAweDcyOGViNjU4LFxuXHQweDcxOGJjZDU4LCAweDgyMTU0YWVlLCAweDdiNTRhNDFkLCAweGMyNWE1OWI1LCAweDljMzBkNTM5LCAweDJhZjI2MDEzLFxuXHQweGM1ZDFiMDIzLCAweDI4NjA4NWYwLCAweGNhNDE3OTE4LCAweGI4ZGIzOGVmLCAweDhlNzlkY2IwLCAweDYwM2ExODBlLFxuXHQweDZjOWUwZThiLCAweGIwMWU4YTNlLCAweGQ3MTU3N2MxLCAweGJkMzE0YjI3LCAweDc4YWYyZmRhLCAweDU1NjA1YzYwLFxuXHQweGU2NTUyNWYzLCAweGFhNTVhYjk0LCAweDU3NDg5ODYyLCAweDYzZTgxNDQwLCAweDU1Y2EzOTZhLCAweDJhYWIxMGI2LFxuXHQweGI0Y2M1YzM0LCAweDExNDFlOGNlLCAweGExNTQ4NmFmLCAweDdjNzJlOTkzLCAweGIzZWUxNDExLCAweDYzNmZiYzJhLFxuXHQweDJiYTljNTVkLCAweDc0MTgzMWY2LCAweGNlNWMzZTE2LCAweDliODc5MzFlLCAweGFmZDZiYTMzLCAweDZjMjRjZjVjLFxuXHQweDdhMzI1MzgxLCAweDI4OTU4Njc3LCAweDNiOGY0ODk4LCAweDZiNGJiOWFmLCAweGM0YmZlODFiLCAweDY2MjgyMTkzLFxuXHQweDYxZDgwOWNjLCAweGZiMjFhOTkxLCAweDQ4N2NhYzYwLCAweDVkZWM4MDMyLCAweGVmODQ1ZDVkLCAweGU5ODU3NWIxLFxuXHQweGRjMjYyMzAyLCAweGViNjUxYjg4LCAweDIzODkzZTgxLCAweGQzOTZhY2M1LCAweDBmNmQ2ZmYzLCAweDgzZjQ0MjM5LFxuXHQweDJlMGI0NDgyLCAweGE0ODQyMDA0LCAweDY5YzhmMDRhLCAweDllMWY5YjVlLCAweDIxYzY2ODQyLCAweGY2ZTk2YzlhLFxuXHQweDY3MGM5YzYxLCAweGFiZDM4OGYwLCAweDZhNTFhMGQyLCAweGQ4NTQyZjY4LCAweDk2MGZhNzI4LCAweGFiNTEzM2EzLFxuXHQweDZlZWYwYjZjLCAweDEzN2EzYmU0LCAweGJhM2JmMDUwLCAweDdlZmIyYTk4LCAweGExZjE2NTFkLCAweDM5YWYwMTc2LFxuXHQweDY2Y2E1OTNlLCAweDgyNDMwZTg4LCAweDhjZWU4NjE5LCAweDQ1NmY5ZmI0LCAweDdkODRhNWMzLCAweDNiOGI1ZWJlLFxuXHQweGUwNmY3NWQ4LCAweDg1YzEyMDczLCAweDQwMWE0NDlmLCAweDU2YzE2YWE2LCAweDRlZDNhYTYyLCAweDM2M2Y3NzA2LFxuXHQweDFiZmVkZjcyLCAweDQyOWIwMjNkLCAweDM3ZDBkNzI0LCAweGQwMGExMjQ4LCAweGRiMGZlYWQzLCAweDQ5ZjFjMDliLFxuXHQweDA3NTM3MmM5LCAweDgwOTkxYjdiLCAweDI1ZDQ3OWQ4LCAweGY2ZThkZWY3LCAweGUzZmU1MDFhLCAweGI2Nzk0YzNiLFxuXHQweDk3NmNlMGJkLCAweDA0YzAwNmJhLCAweGMxYTk0ZmI2LCAweDQwOWY2MGM0LCAweDVlNWM5ZWMyLCAweDE5NmEyNDYzLFxuXHQweDY4ZmI2ZmFmLCAweDNlNmM1M2I1LCAweDEzMzliMmViLCAweDNiNTJlYzZmLCAweDZkZmM1MTFmLCAweDliMzA5NTJjLFxuXHQweGNjODE0NTQ0LCAweGFmNWViZDA5LCAweGJlZTNkMDA0LCAweGRlMzM0YWZkLCAweDY2MGYyODA3LCAweDE5MmU0YmIzLFxuXHQweGMwY2JhODU3LCAweDQ1Yzg3NDBmLCAweGQyMGI1ZjM5LCAweGI5ZDNmYmRiLCAweDU1NzljMGJkLCAweDFhNjAzMjBhLFxuXHQweGQ2YTEwMGM2LCAweDQwMmM3Mjc5LCAweDY3OWYyNWZlLCAweGZiMWZhM2NjLCAweDhlYTVlOWY4LCAweGRiMzIyMmY4LFxuXHQweDNjNzUxNmRmLCAweGZkNjE2YjE1LCAweDJmNTAxZWM4LCAweGFkMDU1MmFiLCAweDMyM2RiNWZhLCAweGZkMjM4NzYwLFxuXHQweDUzMzE3YjQ4LCAweDNlMDBkZjgyLCAweDllNWM1N2JiLCAweGNhNmY4Y2EwLCAweDFhODc1NjJlLCAweGRmMTc2OWRiLFxuXHQweGQ1NDJhOGY2LCAweDI4N2VmZmMzLCAweGFjNjczMmM2LCAweDhjNGY1NTczLCAweDY5NWIyN2IwLCAweGJiY2E1OGM4LFxuXHQweGUxZmZhMzVkLCAweGI4ZjAxMWEwLCAweDEwZmEzZDk4LCAweGZkMjE4M2I4LCAweDRhZmNiNTZjLCAweDJkZDFkMzViLFxuXHQweDlhNTNlNDc5LCAweGI2Zjg0NTY1LCAweGQyOGU0OWJjLCAweDRiZmI5NzkwLCAweGUxZGRmMmRhLCAweGE0Y2I3ZTMzLFxuXHQweDYyZmIxMzQxLCAweGNlZTRjNmU4LCAweGVmMjBjYWRhLCAweDM2Nzc0YzAxLCAweGQwN2U5ZWZlLCAweDJiZjExZmI0LFxuXHQweDk1ZGJkYTRkLCAweGFlOTA5MTk4LCAweGVhYWQ4ZTcxLCAweDZiOTNkNWEwLCAweGQwOGVkMWQwLCAweGFmYzcyNWUwLFxuXHQweDhlM2M1YjJmLCAweDhlNzU5NGI3LCAweDhmZjZlMmZiLCAweGYyMTIyYjY0LCAweDg4ODhiODEyLCAweDkwMGRmMDFjLFxuXHQweDRmYWQ1ZWEwLCAweDY4OGZjMzFjLCAweGQxY2ZmMTkxLCAweGIzYThjMWFkLCAweDJmMmYyMjE4LCAweGJlMGUxNzc3LFxuXHQweGVhNzUyZGZlLCAweDhiMDIxZmExLCAweGU1YTBjYzBmLCAweGI1NmY3NGU4LCAweDE4YWNmM2Q2LCAweGNlODllMjk5LFxuXHQweGI0YTg0ZmUwLCAweGZkMTNlMGI3LCAweDdjYzQzYjgxLCAweGQyYWRhOGQ5LCAweDE2NWZhMjY2LCAweDgwOTU3NzA1LFxuXHQweDkzY2M3MzE0LCAweDIxMWExNDc3LCAweGU2YWQyMDY1LCAweDc3YjVmYTg2LCAweGM3NTQ0MmY1LCAweGZiOWQzNWNmLFxuXHQweGViY2RhZjBjLCAweDdiM2U4OWEwLCAweGQ2NDExYmQzLCAweGFlMWU3ZTQ5LCAweDAwMjUwZTJkLCAweDIwNzFiMzVlLFxuXHQweDIyNjgwMGJiLCAweDU3YjhlMGFmLCAweDI0NjQzNjliLCAweGYwMDliOTFlLCAweDU1NjM5MTFkLCAweDU5ZGZhNmFhLFxuXHQweDc4YzE0Mzg5LCAweGQ5NWE1MzdmLCAweDIwN2Q1YmEyLCAweDAyZTViOWM1LCAweDgzMjYwMzc2LCAweDYyOTVjZmE5LFxuXHQweDExYzgxOTY4LCAweDRlNzM0YTQxLCAweGIzNDcyZGNhLCAweDdiMTRhOTRhLCAweDFiNTEwMDUyLCAweDlhNTMyOTE1LFxuXHQweGQ2MGY1NzNmLCAweGJjOWJjNmU0LCAweDJiNjBhNDc2LCAweDgxZTY3NDAwLCAweDA4YmE2ZmI1LCAweDU3MWJlOTFmLFxuXHQweGYyOTZlYzZiLCAweDJhMGRkOTE1LCAweGI2NjM2NTIxLCAweGU3YjlmOWI2LCAweGZmMzQwNTJlLCAweGM1ODU1NjY0LFxuXHQweDUzYjAyZDVkLCAweGE5OWY4ZmExLCAweDA4YmE0Nzk5LCAweDZlODUwNzZhXG4gICAgXSwgW1xuXHQweDRiN2E3MGU5LCAweGI1YjMyOTQ0LCAweGRiNzUwOTJlLCAweGM0MTkyNjIzLCAweGFkNmVhNmIwLCAweDQ5YTdkZjdkLFxuXHQweDljZWU2MGI4LCAweDhmZWRiMjY2LCAweGVjYWE4YzcxLCAweDY5OWExN2ZmLCAweDU2NjQ1MjZjLCAweGMyYjE5ZWUxLFxuXHQweDE5MzYwMmE1LCAweDc1MDk0YzI5LCAweGEwNTkxMzQwLCAweGU0MTgzYTNlLCAweDNmNTQ5ODlhLCAweDViNDI5ZDY1LFxuXHQweDZiOGZlNGQ2LCAweDk5ZjczZmQ2LCAweGExZDI5YzA3LCAweGVmZTgzMGY1LCAweDRkMmQzOGU2LCAweGYwMjU1ZGMxLFxuXHQweDRjZGQyMDg2LCAweDg0NzBlYjI2LCAweDYzODJlOWM2LCAweDAyMWVjYzVlLCAweDA5Njg2YjNmLCAweDNlYmFlZmM5LFxuXHQweDNjOTcxODE0LCAweDZiNmE3MGExLCAweDY4N2YzNTg0LCAweDUyYTBlMjg2LCAweGI3OWM1MzA1LCAweGFhNTAwNzM3LFxuXHQweDNlMDc4NDFjLCAweDdmZGVhZTVjLCAweDhlN2Q0NGVjLCAweDU3MTZmMmI4LCAweGIwM2FkYTM3LCAweGYwNTAwYzBkLFxuXHQweGYwMWMxZjA0LCAweDAyMDBiM2ZmLCAweGFlMGNmNTFhLCAweDNjYjU3NGIyLCAweDI1ODM3YTU4LCAweGRjMDkyMWJkLFxuXHQweGQxOTExM2Y5LCAweDdjYTkyZmY2LCAweDk0MzI0NzczLCAweDIyZjU0NzAxLCAweDNhZTVlNTgxLCAweDM3YzJkYWRjLFxuXHQweGM4YjU3NjM0LCAweDlhZjNkZGE3LCAweGE5NDQ2MTQ2LCAweDBmZDAwMzBlLCAweGVjYzhjNzNlLCAweGE0NzUxZTQxLFxuXHQweGUyMzhjZDk5LCAweDNiZWEwZTJmLCAweDMyODBiYmExLCAweDE4M2ViMzMxLCAweDRlNTQ4YjM4LCAweDRmNmRiOTA4LFxuXHQweDZmNDIwZDAzLCAweGY2MGEwNGJmLCAweDJjYjgxMjkwLCAweDI0OTc3Yzc5LCAweDU2NzliMDcyLCAweGJjYWY4OWFmLFxuXHQweGRlOWE3NzFmLCAweGQ5OTMwODEwLCAweGIzOGJhZTEyLCAweGRjY2YzZjJlLCAweDU1MTI3MjFmLCAweDJlNmI3MTI0LFxuXHQweDUwMWFkZGU2LCAweDlmODRjZDg3LCAweDdhNTg0NzE4LCAweDc0MDhkYTE3LCAweGJjOWY5YWJjLCAweGU5NGI3ZDhjLFxuXHQweGVjN2FlYzNhLCAweGRiODUxZGZhLCAweDYzMDk0MzY2LCAweGM0NjRjM2QyLCAweGVmMWMxODQ3LCAweDMyMTVkOTA4LFxuXHQweGRkNDMzYjM3LCAweDI0YzJiYTE2LCAweDEyYTE0ZDQzLCAweDJhNjVjNDUxLCAweDUwOTQwMDAyLCAweDEzM2FlNGRkLFxuXHQweDcxZGZmODllLCAweDEwMzE0ZTU1LCAweDgxYWM3N2Q2LCAweDVmMTExOTliLCAweDA0MzU1NmYxLCAweGQ3YTNjNzZiLFxuXHQweDNjMTExODNiLCAweDU5MjRhNTA5LCAweGYyOGZlNmVkLCAweDk3ZjFmYmZhLCAweDllYmFiZjJjLCAweDFlMTUzYzZlLFxuXHQweDg2ZTM0NTcwLCAweGVhZTk2ZmIxLCAweDg2MGU1ZTBhLCAweDVhM2UyYWIzLCAweDc3MWZlNzFjLCAweDRlM2QwNmZhLFxuXHQweDI5NjVkY2I5LCAweDk5ZTcxZDBmLCAweDgwM2U4OWQ2LCAweDUyNjZjODI1LCAweDJlNGNjOTc4LCAweDljMTBiMzZhLFxuXHQweGM2MTUwZWJhLCAweDk0ZTJlYTc4LCAweGE1ZmMzYzUzLCAweDFlMGEyZGY0LCAweGYyZjc0ZWE3LCAweDM2MWQyYjNkLFxuXHQweDE5MzkyNjBmLCAweDE5YzI3OTYwLCAweDUyMjNhNzA4LCAweGY3MTMxMmI2LCAweGViYWRmZTZlLCAweGVhYzMxZjY2LFxuXHQweGUzYmM0NTk1LCAweGE2N2JjODgzLCAweGIxN2YzN2QxLCAweDAxOGNmZjI4LCAweGMzMzJkZGVmLCAweGJlNmM1YWE1LFxuXHQweDY1NTgyMTg1LCAweDY4YWI5ODAyLCAweGVlY2VhNTBmLCAweGRiMmY5NTNiLCAweDJhZWY3ZGFkLCAweDViNmUyZjg0LFxuXHQweDE1MjFiNjI4LCAweDI5MDc2MTcwLCAweGVjZGQ0Nzc1LCAweDYxOWYxNTEwLCAweDEzY2NhODMwLCAweGViNjFiZDk2LFxuXHQweDAzMzRmZTFlLCAweGFhMDM2M2NmLCAweGI1NzM1YzkwLCAweDRjNzBhMjM5LCAweGQ1OWU5ZTBiLCAweGNiYWFkZTE0LFxuXHQweGVlY2M4NmJjLCAweDYwNjIyY2E3LCAweDljYWI1Y2FiLCAweGIyZjM4NDZlLCAweDY0OGIxZWFmLCAweDE5YmRmMGNhLFxuXHQweGEwMjM2OWI5LCAweDY1NWFiYjUwLCAweDQwNjg1YTMyLCAweDNjMmFiNGIzLCAweDMxOWVlOWQ1LCAweGMwMjFiOGY3LFxuXHQweDliNTQwYjE5LCAweDg3NWZhMDk5LCAweDk1Zjc5OTdlLCAweDYyM2Q3ZGE4LCAweGY4Mzc4ODlhLCAweDk3ZTMyZDc3LFxuXHQweDExZWQ5MzVmLCAweDE2NjgxMjgxLCAweDBlMzU4ODI5LCAweGM3ZTYxZmQ2LCAweDk2ZGVkZmExLCAweDc4NThiYTk5LFxuXHQweDU3ZjU4NGE1LCAweDFiMjI3MjYzLCAweDliODNjM2ZmLCAweDFhYzI0Njk2LCAweGNkYjMwYWViLCAweDUzMmUzMDU0LFxuXHQweDhmZDk0OGU0LCAweDZkYmMzMTI4LCAweDU4ZWJmMmVmLCAweDM0YzZmZmVhLCAweGZlMjhlZDYxLCAweGVlN2MzYzczLFxuXHQweDVkNGExNGQ5LCAweGU4NjRiN2UzLCAweDQyMTA1ZDE0LCAweDIwM2UxM2UwLCAweDQ1ZWVlMmI2LCAweGEzYWFhYmVhLFxuXHQweGRiNmM0ZjE1LCAweGZhY2I0ZmQwLCAweGM3NDJmNDQyLCAweGVmNmFiYmI1LCAweDY1NGYzYjFkLCAweDQxY2QyMTA1LFxuXHQweGQ4MWU3OTllLCAweDg2ODU0ZGM3LCAweGU0NGI0NzZhLCAweDNkODE2MjUwLCAweGNmNjJhMWYyLCAweDViOGQyNjQ2LFxuXHQweGZjODg4M2EwLCAweGMxYzdiNmEzLCAweDdmMTUyNGMzLCAweDY5Y2I3NDkyLCAweDQ3ODQ4YTBiLCAweDU2OTJiMjg1LFxuXHQweDA5NWJiZjAwLCAweGFkMTk0ODlkLCAweDE0NjJiMTc0LCAweDIzODIwZTAwLCAweDU4NDI4ZDJhLCAweDBjNTVmNWVhLFxuXHQweDFkYWRmNDNlLCAweDIzM2Y3MDYxLCAweDMzNzJmMDkyLCAweDhkOTM3ZTQxLCAweGQ2NWZlY2YxLCAweDZjMjIzYmRiLFxuXHQweDdjZGUzNzU5LCAweGNiZWU3NDYwLCAweDQwODVmMmE3LCAweGNlNzczMjZlLCAweGE2MDc4MDg0LCAweDE5Zjg1MDllLFxuXHQweGU4ZWZkODU1LCAweDYxZDk5NzM1LCAweGE5NjlhN2FhLCAweGM1MGMwNmMyLCAweDVhMDRhYmZjLCAweDgwMGJjYWRjLFxuXHQweDllNDQ3YTJlLCAweGMzNDUzNDg0LCAweGZkZDU2NzA1LCAweDBlMWU5ZWM5LCAweGRiNzNkYmQzLCAweDEwNTU4OGNkLFxuXHQweDY3NWZkYTc5LCAweGUzNjc0MzQwLCAweGM1YzQzNDY1LCAweDcxM2UzOGQ4LCAweDNkMjhmODllLCAweGYxNmRmZjIwLFxuXHQweDE1M2UyMWU3LCAweDhmYjAzZDRhLCAweGU2ZTM5ZjJiLCAweGRiODNhZGY3XG4gICAgXSwgW1xuXHQweGU5M2Q1YTY4LCAweDk0ODE0MGY3LCAweGY2NGMyNjFjLCAweDk0NjkyOTM0LCAweDQxMTUyMGY3LCAweDc2MDJkNGY3LFxuXHQweGJjZjQ2YjJlLCAweGQ0YTIwMDY4LCAweGQ0MDgyNDcxLCAweDMzMjBmNDZhLCAweDQzYjdkNGI3LCAweDUwMDA2MWFmLFxuXHQweDFlMzlmNjJlLCAweDk3MjQ0NTQ2LCAweDE0MjE0Zjc0LCAweGJmOGI4ODQwLCAweDRkOTVmYzFkLCAweDk2YjU5MWFmLFxuXHQweDcwZjRkZGQzLCAweDY2YTAyZjQ1LCAweGJmYmMwOWVjLCAweDAzYmQ5Nzg1LCAweDdmYWM2ZGQwLCAweDMxY2I4NTA0LFxuXHQweDk2ZWIyN2IzLCAweDU1ZmQzOTQxLCAweGRhMjU0N2U2LCAweGFiY2EwYTlhLCAweDI4NTA3ODI1LCAweDUzMDQyOWY0LFxuXHQweDBhMmM4NmRhLCAweGU5YjY2ZGZiLCAweDY4ZGMxNDYyLCAweGQ3NDg2OTAwLCAweDY4MGVjMGE0LCAweDI3YTE4ZGVlLFxuXHQweDRmM2ZmZWEyLCAweGU4ODdhZDhjLCAweGI1OGNlMDA2LCAweDdhZjRkNmI2LCAweGFhY2UxZTdjLCAweGQzMzc1ZmVjLFxuXHQweGNlNzhhMzk5LCAweDQwNmIyYTQyLCAweDIwZmU5ZTM1LCAweGQ5ZjM4NWI5LCAweGVlMzlkN2FiLCAweDNiMTI0ZThiLFxuXHQweDFkYzlmYWY3LCAweDRiNmQxODU2LCAweDI2YTM2NjMxLCAweGVhZTM5N2IyLCAweDNhNmVmYTc0LCAweGRkNWI0MzMyLFxuXHQweDY4NDFlN2Y3LCAweGNhNzgyMGZiLCAweGZiMGFmNTRlLCAweGQ4ZmViMzk3LCAweDQ1NDA1NmFjLCAweGJhNDg5NTI3LFxuXHQweDU1NTMzYTNhLCAweDIwODM4ZDg3LCAweGZlNmJhOWI3LCAweGQwOTY5NTRiLCAweDU1YTg2N2JjLCAweGExMTU5YTU4LFxuXHQweGNjYTkyOTYzLCAweDk5ZTFkYjMzLCAweGE2MmE0YTU2LCAweDNmMzEyNWY5LCAweDVlZjQ3ZTFjLCAweDkwMjkzMTdjLFxuXHQweGZkZjhlODAyLCAweDA0MjcyZjcwLCAweDgwYmIxNTVjLCAweDA1MjgyY2UzLCAweDk1YzExNTQ4LCAweGU0YzY2ZDIyLFxuXHQweDQ4YzExMzNmLCAweGM3MGY4NmRjLCAweDA3ZjljOWVlLCAweDQxMDQxZjBmLCAweDQwNDc3OWE0LCAweDVkODg2ZTE3LFxuXHQweDMyNWY1MWViLCAweGQ1OWJjMGQxLCAweGYyYmNjMThmLCAweDQxMTEzNTY0LCAweDI1N2I3ODM0LCAweDYwMmE5YzYwLFxuXHQweGRmZjhlOGEzLCAweDFmNjM2YzFiLCAweDBlMTJiNGMyLCAweDAyZTEzMjllLCAweGFmNjY0ZmQxLCAweGNhZDE4MTE1LFxuXHQweDZiMjM5NWUwLCAweDMzM2U5MmUxLCAweDNiMjQwYjYyLCAweGVlYmViOTIyLCAweDg1YjJhMjBlLCAweGU2YmEwZDk5LFxuXHQweGRlNzIwYzhjLCAweDJkYTJmNzI4LCAweGQwMTI3ODQ1LCAweDk1Yjc5NGZkLCAweDY0N2QwODYyLCAweGU3Y2NmNWYwLFxuXHQweDU0NDlhMzZmLCAweDg3N2Q0OGZhLCAweGMzOWRmZDI3LCAweGYzM2U4ZDFlLCAweDBhNDc2MzQxLCAweDk5MmVmZjc0LFxuXHQweDNhNmY2ZWFiLCAweGY0ZjhmZDM3LCAweGE4MTJkYzYwLCAweGExZWJkZGY4LCAweDk5MWJlMTRjLCAweGRiNmU2YjBkLFxuXHQweGM2N2I1NTEwLCAweDZkNjcyYzM3LCAweDI3NjVkNDNiLCAweGRjZDBlODA0LCAweGYxMjkwZGM3LCAweGNjMDBmZmEzLFxuXHQweGI1MzkwZjkyLCAweDY5MGZlZDBiLCAweDY2N2I5ZmZiLCAweGNlZGI3ZDljLCAweGEwOTFjZjBiLCAweGQ5MTU1ZWEzLFxuXHQweGJiMTMyZjg4LCAweDUxNWJhZDI0LCAweDdiOTQ3OWJmLCAweDc2M2JkNmViLCAweDM3MzkyZWIzLCAweGNjMTE1OTc5LFxuXHQweDgwMjZlMjk3LCAweGY0MmUzMTJkLCAweDY4NDJhZGE3LCAweGM2NmEyYjNiLCAweDEyNzU0Y2NjLCAweDc4MmVmMTFjLFxuXHQweDZhMTI0MjM3LCAweGI3OTI1MWU3LCAweDA2YTFiYmU2LCAweDRiZmI2MzUwLCAweDFhNmIxMDE4LCAweDExY2FlZGZhLFxuXHQweDNkMjViZGQ4LCAweGUyZTFjM2M5LCAweDQ0NDIxNjU5LCAweDBhMTIxMzg2LCAweGQ5MGNlYzZlLCAweGQ1YWJlYTJhLFxuXHQweDY0YWY2NzRlLCAweGRhODZhODVmLCAweGJlYmZlOTg4LCAweDY0ZTRjM2ZlLCAweDlkYmM4MDU3LCAweGYwZjdjMDg2LFxuXHQweDYwNzg3YmY4LCAweDYwMDM2MDRkLCAweGQxZmQ4MzQ2LCAweGY2MzgxZmIwLCAweDc3NDVhZTA0LCAweGQ3MzZmY2NjLFxuXHQweDgzNDI2YjMzLCAweGYwMWVhYjcxLCAweGIwODA0MTg3LCAweDNjMDA1ZTVmLCAweDc3YTA1N2JlLCAweGJkZThhZTI0LFxuXHQweDU1NDY0Mjk5LCAweGJmNTgyZTYxLCAweDRlNThmNDhmLCAweGYyZGRmZGEyLCAweGY0NzRlZjM4LCAweDg3ODliZGMyLFxuXHQweDUzNjZmOWMzLCAweGM4YjM4ZTc0LCAweGI0NzVmMjU1LCAweDQ2ZmNkOWI5LCAweDdhZWIyNjYxLCAweDhiMWRkZjg0LFxuXHQweDg0NmEwZTc5LCAweDkxNWY5NWUyLCAweDQ2NmU1OThlLCAweDIwYjQ1NzcwLCAweDhjZDU1NTkxLCAweGM5MDJkZTRjLFxuXHQweGI5MGJhY2UxLCAweGJiODIwNWQwLCAweDExYTg2MjQ4LCAweDc1NzRhOTllLCAweGI3N2YxOWI2LCAweGUwYTlkYzA5LFxuXHQweDY2MmQwOWExLCAweGM0MzI0NjMzLCAweGU4NWExZjAyLCAweDA5ZjBiZThjLCAweDRhOTlhMDI1LCAweDFkNmVmZTEwLFxuXHQweDFhYjkzZDFkLCAweDBiYTVhNGRmLCAweGExODZmMjBmLCAweDI4NjhmMTY5LCAweGRjYjdkYTgzLCAweDU3MzkwNmZlLFxuXHQweGExZTJjZTliLCAweDRmY2Q3ZjUyLCAweDUwMTE1ZTAxLCAweGE3MDY4M2ZhLCAweGEwMDJiNWM0LCAweDBkZTZkMDI3LFxuXHQweDlhZjg4YzI3LCAweDc3M2Y4NjQxLCAweGMzNjA0YzA2LCAweDYxYTgwNmI1LCAweGYwMTc3YTI4LCAweGMwZjU4NmUwLFxuXHQweDAwNjA1OGFhLCAweDMwZGM3ZDYyLCAweDExZTY5ZWQ3LCAweDIzMzhlYTYzLCAweDUzYzJkZDk0LCAweGMyYzIxNjM0LFxuXHQweGJiY2JlZTU2LCAweDkwYmNiNmRlLCAweGViZmM3ZGExLCAweGNlNTkxZDc2LCAweDZmMDVlNDA5LCAweDRiN2MwMTg4LFxuXHQweDM5NzIwYTNkLCAweDdjOTI3YzI0LCAweDg2ZTM3MjVmLCAweDcyNGQ5ZGI5LCAweDFhYzE1YmI0LCAweGQzOWViOGZjLFxuXHQweGVkNTQ1NTc4LCAweDA4ZmNhNWI1LCAweGQ4M2Q3Y2QzLCAweDRkYWQwZmM0LCAweDFlNTBlZjVlLCAweGIxNjFlNmY4LFxuXHQweGEyODUxNGQ5LCAweDZjNTExMzNjLCAweDZmZDVjN2U3LCAweDU2ZTE0ZWM0LCAweDM2MmFiZmNlLCAweGRkYzZjODM3LFxuXHQweGQ3OWEzMjM0LCAweDkyNjM4MjEyLCAweDY3MGVmYThlLCAweDQwNjAwMGUwXG4gICAgXSwgW1xuXHQweDNhMzljZTM3LCAweGQzZmFmNWNmLCAweGFiYzI3NzM3LCAweDVhYzUyZDFiLCAweDVjYjA2NzllLCAweDRmYTMzNzQyLFxuXHQweGQzODIyNzQwLCAweDk5YmM5YmJlLCAweGQ1MTE4ZTlkLCAweGJmMGY3MzE1LCAweGQ2MmQxYzdlLCAweGM3MDBjNDdiLFxuXHQweGI3OGMxYjZiLCAweDIxYTE5MDQ1LCAweGIyNmViMWJlLCAweDZhMzY2ZWI0LCAweDU3NDhhYjJmLCAweGJjOTQ2ZTc5LFxuXHQweGM2YTM3NmQyLCAweDY1NDljMmM4LCAweDUzMGZmOGVlLCAweDQ2OGRkZTdkLCAweGQ1NzMwYTFkLCAweDRjZDA0ZGM2LFxuXHQweDI5MzliYmRiLCAweGE5YmE0NjUwLCAweGFjOTUyNmU4LCAweGJlNWVlMzA0LCAweGExZmFkNWYwLCAweDZhMmQ1MTlhLFxuXHQweDYzZWY4Y2UyLCAweDlhODZlZTIyLCAweGMwODljMmI4LCAweDQzMjQyZWY2LCAweGE1MWUwM2FhLCAweDljZjJkMGE0LFxuXHQweDgzYzA2MWJhLCAweDliZTk2YTRkLCAweDhmZTUxNTUwLCAweGJhNjQ1YmQ2LCAweDI4MjZhMmY5LCAweGE3M2EzYWUxLFxuXHQweDRiYTk5NTg2LCAweGVmNTU2MmU5LCAweGM3MmZlZmQzLCAweGY3NTJmN2RhLCAweDNmMDQ2ZjY5LCAweDc3ZmEwYTU5LFxuXHQweDgwZTRhOTE1LCAweDg3YjA4NjAxLCAweDliMDllNmFkLCAweDNiM2VlNTkzLCAweGU5OTBmZDVhLCAweDllMzRkNzk3LFxuXHQweDJjZjBiN2Q5LCAweDAyMmI4YjUxLCAweDk2ZDVhYzNhLCAweDAxN2RhNjdkLCAweGQxY2YzZWQ2LCAweDdjN2QyZDI4LFxuXHQweDFmOWYyNWNmLCAweGFkZjJiODliLCAweDVhZDZiNDcyLCAweDVhODhmNTRjLCAweGUwMjlhYzcxLCAweGUwMTlhNWU2LFxuXHQweDQ3YjBhY2ZkLCAweGVkOTNmYTliLCAweGU4ZDNjNDhkLCAweDI4M2I1N2NjLCAweGY4ZDU2NjI5LCAweDc5MTMyZTI4LFxuXHQweDc4NWYwMTkxLCAweGVkNzU2MDU1LCAweGY3OTYwZTQ0LCAweGUzZDM1ZThjLCAweDE1MDU2ZGQ0LCAweDg4ZjQ2ZGJhLFxuXHQweDAzYTE2MTI1LCAweDA1NjRmMGJkLCAweGMzZWI5ZTE1LCAweDNjOTA1N2EyLCAweDk3MjcxYWVjLCAweGE5M2EwNzJhLFxuXHQweDFiM2Y2ZDliLCAweDFlNjMyMWY1LCAweGY1OWM2NmZiLCAweDI2ZGNmMzE5LCAweDc1MzNkOTI4LCAweGIxNTVmZGY1LFxuXHQweDAzNTYzNDgyLCAweDhhYmEzY2JiLCAweDI4NTE3NzExLCAweGMyMGFkOWY4LCAweGFiY2M1MTY3LCAweGNjYWQ5MjVmLFxuXHQweDRkZTgxNzUxLCAweDM4MzBkYzhlLCAweDM3OWQ1ODYyLCAweDkzMjBmOTkxLCAweGVhN2E5MGMyLCAweGZiM2U3YmNlLFxuXHQweDUxMjFjZTY0LCAweDc3NGZiZTMyLCAweGE4YjZlMzdlLCAweGMzMjkzZDQ2LCAweDQ4ZGU1MzY5LCAweDY0MTNlNjgwLFxuXHQweGEyYWUwODEwLCAweGRkNmRiMjI0LCAweDY5ODUyZGZkLCAweDA5MDcyMTY2LCAweGIzOWE0NjBhLCAweDY0NDVjMGRkLFxuXHQweDU4NmNkZWNmLCAweDFjMjBjOGFlLCAweDViYmVmN2RkLCAweDFiNTg4ZDQwLCAweGNjZDIwMTdmLCAweDZiYjRlM2JiLFxuXHQweGRkYTI2YTdlLCAweDNhNTlmZjQ1LCAweDNlMzUwYTQ0LCAweGJjYjRjZGQ1LCAweDcyZWFjZWE4LCAweGZhNjQ4NGJiLFxuXHQweDhkNjYxMmFlLCAweGJmM2M2ZjQ3LCAweGQyOWJlNDYzLCAweDU0MmY1ZDllLCAweGFlYzI3NzFiLCAweGY2NGU2MzcwLFxuXHQweDc0MGUwZDhkLCAweGU3NWIxMzU3LCAweGY4NzIxNjcxLCAweGFmNTM3ZDVkLCAweDQwNDBjYjA4LCAweDRlYjRlMmNjLFxuXHQweDM0ZDI0NjZhLCAweDAxMTVhZjg0LCAweGUxYjAwNDI4LCAweDk1OTgzYTFkLCAweDA2Yjg5ZmI0LCAweGNlNmVhMDQ4LFxuXHQweDZmM2YzYjgyLCAweDM1MjBhYjgyLCAweDAxMWExZDRiLCAweDI3NzIyN2Y4LCAweDYxMTU2MGIxLCAweGU3OTMzZmRjLFxuXHQweGJiM2E3OTJiLCAweDM0NDUyNWJkLCAweGEwODgzOWUxLCAweDUxY2U3OTRiLCAweDJmMzJjOWI3LCAweGEwMWZiYWM5LFxuXHQweGUwMWNjODdlLCAweGJjYzdkMWY2LCAweGNmMDExMWMzLCAweGExZThhYWM3LCAweDFhOTA4NzQ5LCAweGQ0NGZiZDlhLFxuXHQweGQwZGFkZWNiLCAweGQ1MGFkYTM4LCAweDAzMzljMzJhLCAweGM2OTEzNjY3LCAweDhkZjkzMTdjLCAweGUwYjEyYjRmLFxuXHQweGY3OWU1OWI3LCAweDQzZjViYjNhLCAweGYyZDUxOWZmLCAweDI3ZDk0NTljLCAweGJmOTcyMjJjLCAweDE1ZTZmYzJhLFxuXHQweDBmOTFmYzcxLCAweDliOTQxNTI1LCAweGZhZTU5MzYxLCAweGNlYjY5Y2ViLCAweGMyYTg2NDU5LCAweDEyYmFhOGQxLFxuXHQweGI2YzEwNzVlLCAweGUzMDU2YTBjLCAweDEwZDI1MDY1LCAweGNiMDNhNDQyLCAweGUwZWM2ZTBlLCAweDE2OThkYjNiLFxuXHQweDRjOThhMGJlLCAweDMyNzhlOTY0LCAweDlmMWY5NTMyLCAweGUwZDM5MmRmLCAweGQzYTAzNDJiLCAweDg5NzFmMjFlLFxuXHQweDFiMGE3NDQxLCAweDRiYTMzNDhjLCAweGM1YmU3MTIwLCAweGMzNzYzMmQ4LCAweGRmMzU5ZjhkLCAweDliOTkyZjJlLFxuXHQweGU2MGI2ZjQ3LCAweDBmZTNmMTFkLCAweGU1NGNkYTU0LCAweDFlZGFkODkxLCAweGNlNjI3OWNmLCAweGNkM2U3ZTZmLFxuXHQweDE2MThiMTY2LCAweGZkMmMxZDA1LCAweDg0OGZkMmM1LCAweGY2ZmIyMjk5LCAweGY1MjNmMzU3LCAweGE2MzI3NjIzLFxuXHQweDkzYTgzNTMxLCAweDU2Y2NjZDAyLCAweGFjZjA4MTYyLCAweDVhNzVlYmI1LCAweDZlMTYzNjk3LCAweDg4ZDI3M2NjLFxuXHQweGRlOTY2MjkyLCAweDgxYjk0OWQwLCAweDRjNTA5MDFiLCAweDcxYzY1NjE0LCAweGU2YzZjN2JkLCAweDMyN2ExNDBhLFxuXHQweDQ1ZTFkMDA2LCAweGMzZjI3YjlhLCAweGM5YWE1M2ZkLCAweDYyYTgwZjAwLCAweGJiMjViZmUyLCAweDM1YmRkMmY2LFxuXHQweDcxMTI2OTA1LCAweGIyMDQwMjIyLCAweGI2Y2JjZjdjLCAweGNkNzY5YzJiLCAweDUzMTEzZWMwLCAweDE2NDBlM2QzLFxuXHQweDM4YWJiZDYwLCAweDI1NDdhZGYwLCAweGJhMzgyMDljLCAweGY3NDZjZTc2LCAweDc3YWZhMWM1LCAweDIwNzU2MDYwLFxuXHQweDg1Y2JmZTRlLCAweDhhZTg4ZGQ4LCAweDdhYWFmOWIwLCAweDRjZjlhYTdlLCAweDE5NDhjMjVjLCAweDAyZmI4YThjLFxuXHQweDAxYzM2YWU0LCAweGQ2ZWJlMWY5LCAweDkwZDRmODY5LCAweGE2NWNkZWEwLCAweDNmMDkyNTJkLCAweGMyMDhlNjlmLFxuXHQweGI3NGU2MTMyLCAweGNlNzdlMjViLCAweDU3OGZkZmUzLCAweDNhYzM3MmU2XG4gICAgXVxuXTtcblxuLy8qXG4vLyogVGhpcyBpcyB0aGUgZGVmYXVsdCBQQVJSQVlcbi8vKlxuQmxvd2Zpc2gucHJvdG90eXBlLlBBUlJBWSA9IFtcbiAgICAweDI0M2Y2YTg4LCAweDg1YTMwOGQzLCAweDEzMTk4YTJlLCAweDAzNzA3MzQ0LCAweGE0MDkzODIyLCAweDI5OWYzMWQwLFxuICAgIDB4MDgyZWZhOTgsIDB4ZWM0ZTZjODksIDB4NDUyODIxZTYsIDB4MzhkMDEzNzcsIDB4YmU1NDY2Y2YsIDB4MzRlOTBjNmMsXG4gICAgMHhjMGFjMjliNywgMHhjOTdjNTBkZCwgMHgzZjg0ZDViNSwgMHhiNTQ3MDkxNywgMHg5MjE2ZDVkOSwgMHg4OTc5ZmIxYlxuXTtcblxuLy8qXG4vLyogVGhpcyBpcyB0aGUgbnVtYmVyIG9mIHJvdW5kcyB0aGUgY2lwaGVyIHdpbGwgZ29cbi8vKlxuQmxvd2Zpc2gucHJvdG90eXBlLk5OID0gMTY7XG5cbi8vKlxuLy8qIFRoaXMgZnVuY3Rpb24gaXMgbmVlZGVkIHRvIGdldCByaWQgb2YgcHJvYmxlbXNcbi8vKiB3aXRoIHRoZSBoaWdoLWJpdCBnZXR0aW5nIHNldC4gIElmIHdlIGRvbid0IGRvXG4vLyogdGhpcywgdGhlbiBzb21ldGltZXMgKCBhYSAmIDB4MDBGRkZGRkZGRiApIGlzIG5vdFxuLy8qIGVxdWFsIHRvICggYmIgJiAweDAwRkZGRkZGRkYgKSBldmVuIHdoZW4gdGhleVxuLy8qIGFncmVlIGJpdC1mb3ItYml0IGZvciB0aGUgZmlyc3QgMzIgYml0cy5cbi8vKlxuQmxvd2Zpc2gucHJvdG90eXBlLl9jbGVhbiA9IGZ1bmN0aW9uKCB4eCApIHtcbiAgICBpZiAoIHh4IDwgMCApIHtcblx0dmFyIHl5ID0geHggJiAweDdGRkZGRkZGO1xuXHR4eCA9IHl5ICsgMHg4MDAwMDAwMDtcbiAgICB9XG4gICAgcmV0dXJuIHh4O1xufTtcblxuLy8qXG4vLyogVGhpcyBpcyB0aGUgbWl4aW5nIGZ1bmN0aW9uIHRoYXQgdXNlcyB0aGUgc2JveGVzXG4vLypcbkJsb3dmaXNoLnByb3RvdHlwZS5fRiA9IGZ1bmN0aW9uICggeHggKSB7XG4gICAgdmFyIGFhO1xuICAgIHZhciBiYjtcbiAgICB2YXIgY2M7XG4gICAgdmFyIGRkO1xuICAgIHZhciB5eTtcblxuICAgIGRkID0geHggJiAweDAwRkY7XG4gICAgeHggPj4+PSA4O1xuICAgIGNjID0geHggJiAweDAwRkY7XG4gICAgeHggPj4+PSA4O1xuICAgIGJiID0geHggJiAweDAwRkY7XG4gICAgeHggPj4+PSA4O1xuICAgIGFhID0geHggJiAweDAwRkY7XG5cbiAgICB5eSA9IHRoaXMuc2JveGVzWyAwIF1bIGFhIF0gKyB0aGlzLnNib3hlc1sgMSBdWyBiYiBdO1xuICAgIHl5ID0geXkgXiB0aGlzLnNib3hlc1sgMiBdWyBjYyBdO1xuICAgIHl5ID0geXkgKyB0aGlzLnNib3hlc1sgMyBdWyBkZCBdO1xuXG4gICAgcmV0dXJuIHl5O1xufTtcblxuLy8qXG4vLyogVGhpcyBtZXRob2QgdGFrZXMgYW4gYXJyYXkgd2l0aCB0d28gdmFsdWVzLCBsZWZ0IGFuZCByaWdodFxuLy8qIGFuZCBkb2VzIE5OIHJvdW5kcyBvZiBCbG93ZmlzaCBvbiB0aGVtLlxuLy8qXG5CbG93ZmlzaC5wcm90b3R5cGUuX2VuY3J5cHRfYmxvY2sgPSBmdW5jdGlvbiAoIHZhbHMgKSB7XG4gICAgdmFyIGRhdGFMID0gdmFsc1sgMCBdO1xuICAgIHZhciBkYXRhUiA9IHZhbHNbIDEgXTtcblxuICAgIHZhciBpaTtcblxuICAgIGZvciAoIGlpPTA7IGlpIDwgdGhpcy5OTjsgKytpaSApIHtcblx0ZGF0YUwgPSBkYXRhTCBeIHRoaXMucGFycmF5WyBpaSBdO1xuXHRkYXRhUiA9IHRoaXMuX0YoIGRhdGFMICkgXiBkYXRhUjtcblxuXHR2YXIgdG1wID0gZGF0YUw7XG5cdGRhdGFMID0gZGF0YVI7XG5cdGRhdGFSID0gdG1wO1xuICAgIH1cblxuICAgIGRhdGFMID0gZGF0YUwgXiB0aGlzLnBhcnJheVsgdGhpcy5OTiArIDAgXTtcbiAgICBkYXRhUiA9IGRhdGFSIF4gdGhpcy5wYXJyYXlbIHRoaXMuTk4gKyAxIF07XG5cbiAgICB2YWxzWyAwIF0gPSB0aGlzLl9jbGVhbiggZGF0YVIgKTtcbiAgICB2YWxzWyAxIF0gPSB0aGlzLl9jbGVhbiggZGF0YUwgKTtcbn07XG5cbi8vKlxuLy8qIFRoaXMgbWV0aG9kIHRha2VzIGEgdmVjdG9yIG9mIG51bWJlcnMgYW5kIHR1cm5zIHRoZW1cbi8vKiBpbnRvIGxvbmcgd29yZHMgc28gdGhhdCB0aGV5IGNhbiBiZSBwcm9jZXNzZWQgYnkgdGhlXG4vLyogcmVhbCBhbGdvcml0aG0uXG4vLypcbi8vKiBNYXliZSBJIHNob3VsZCBtYWtlIHRoZSByZWFsIGFsZ29yaXRobSBhYm92ZSB0YWtlIGEgdmVjdG9yXG4vLyogaW5zdGVhZC4gIFRoYXQgd2lsbCBpbnZvbHZlIG1vcmUgbG9vcGluZywgYnV0IGl0IHdvbid0IHJlcXVpcmVcbi8vKiB0aGUgRigpIG1ldGhvZCB0byBkZWNvbnN0cnVjdCB0aGUgdmVjdG9yLlxuLy8qXG5CbG93ZmlzaC5wcm90b3R5cGUuZW5jcnlwdF9ibG9jayA9IGZ1bmN0aW9uICggdmVjdG9yICkge1xuICAgIHZhciBpaTtcbiAgICB2YXIgdmFscyA9IFsgMCwgMCBdO1xuICAgIHZhciBvZmYgID0gdGhpcy5CTE9DS1NJWkUvMjtcbiAgICBmb3IgKCBpaSA9IDA7IGlpIDwgdGhpcy5CTE9DS1NJWkUvMjsgKytpaSApIHtcblx0dmFsc1swXSA9ICggdmFsc1swXSA8PCA4ICkgfCAoIHZlY3RvclsgaWkgKyAwICAgXSAmIDB4MDBGRiApO1xuXHR2YWxzWzFdID0gKCB2YWxzWzFdIDw8IDggKSB8ICggdmVjdG9yWyBpaSArIG9mZiBdICYgMHgwMEZGICk7XG4gICAgfVxuXG4gICAgdGhpcy5fZW5jcnlwdF9ibG9jayggdmFscyApO1xuXG4gICAgdmFyIHJldCA9IFsgXTtcbiAgICBmb3IgKCBpaSA9IDA7IGlpIDwgdGhpcy5CTE9DS1NJWkUvMjsgKytpaSApIHtcblx0cmV0WyBpaSArIDAgICBdID0gKCB2YWxzWyAwIF0gPj4+ICgyNCAtIDgqKGlpKSkgJiAweDAwRkYgKTtcblx0cmV0WyBpaSArIG9mZiBdID0gKCB2YWxzWyAxIF0gPj4+ICgyNCAtIDgqKGlpKSkgJiAweDAwRkYgKTtcblx0Ly8gdmFsc1sgMCBdID0gKCB2YWxzWyAwIF0gPj4+IDggKTtcblx0Ly8gdmFsc1sgMSBdID0gKCB2YWxzWyAxIF0gPj4+IDggKTtcbiAgICB9XG5cbiAgICByZXR1cm4gcmV0O1xufTtcblxuLy8qXG4vLyogVGhpcyBtZXRob2QgdGFrZXMgYW4gYXJyYXkgd2l0aCB0d28gdmFsdWVzLCBsZWZ0IGFuZCByaWdodFxuLy8qIGFuZCB1bmRvZXMgTk4gcm91bmRzIG9mIEJsb3dmaXNoIG9uIHRoZW0uXG4vLypcbkJsb3dmaXNoLnByb3RvdHlwZS5fZGVjcnlwdF9ibG9jayA9IGZ1bmN0aW9uICggdmFscyApIHtcbiAgICB2YXIgZGF0YUwgPSB2YWxzWyAwIF07XG4gICAgdmFyIGRhdGFSID0gdmFsc1sgMSBdO1xuXG4gICAgdmFyIGlpO1xuXG4gICAgZm9yICggaWk9dGhpcy5OTisxOyBpaSA+IDE7IC0taWkgKSB7XG5cdGRhdGFMID0gZGF0YUwgXiB0aGlzLnBhcnJheVsgaWkgXTtcblx0ZGF0YVIgPSB0aGlzLl9GKCBkYXRhTCApIF4gZGF0YVI7XG5cblx0dmFyIHRtcCA9IGRhdGFMO1xuXHRkYXRhTCA9IGRhdGFSO1xuXHRkYXRhUiA9IHRtcDtcbiAgICB9XG5cbiAgICBkYXRhTCA9IGRhdGFMIF4gdGhpcy5wYXJyYXlbIDEgXTtcbiAgICBkYXRhUiA9IGRhdGFSIF4gdGhpcy5wYXJyYXlbIDAgXTtcblxuICAgIHZhbHNbIDAgXSA9IHRoaXMuX2NsZWFuKCBkYXRhUiApO1xuICAgIHZhbHNbIDEgXSA9IHRoaXMuX2NsZWFuKCBkYXRhTCApO1xufTtcblxuLy8qXG4vLyogVGhpcyBtZXRob2QgdGFrZXMgYSBrZXkgYXJyYXkgYW5kIGluaXRpYWxpemVzIHRoZVxuLy8qIHNib3hlcyBhbmQgcGFycmF5IGZvciB0aGlzIGVuY3J5cHRpb24uXG4vLypcbkJsb3dmaXNoLnByb3RvdHlwZS5pbml0ID0gZnVuY3Rpb24gKCBrZXkgKSB7XG4gICAgdmFyIGlpO1xuICAgIHZhciBqaiA9IDA7XG5cbiAgICB0aGlzLnBhcnJheSA9IFtdO1xuICAgIGZvciAoIGlpPTA7IGlpIDwgdGhpcy5OTiArIDI7ICsraWkgKSB7XG5cdHZhciBkYXRhID0gMHgwMDAwMDAwMDtcblx0dmFyIGtrO1xuXHRmb3IgKCBraz0wOyBrayA8IDQ7ICsra2sgKSB7XG5cdCAgICBkYXRhID0gKCBkYXRhIDw8IDggKSB8ICgga2V5WyBqaiBdICYgMHgwMEZGICk7XG5cdCAgICBpZiAoICsramogPj0ga2V5Lmxlbmd0aCApIHtcblx0XHRqaiA9IDA7XG5cdCAgICB9XG5cdH1cblx0dGhpcy5wYXJyYXlbIGlpIF0gPSB0aGlzLlBBUlJBWVsgaWkgXSBeIGRhdGE7XG4gICAgfVxuXG4gICAgdGhpcy5zYm94ZXMgPSBbXTtcbiAgICBmb3IgKCBpaT0wOyBpaSA8IDQ7ICsraWkgKSB7XG5cdHRoaXMuc2JveGVzWyBpaSBdID0gW107XG5cdGZvciAoIGpqPTA7IGpqIDwgMjU2OyArK2pqICkge1xuXHQgICAgdGhpcy5zYm94ZXNbIGlpIF1bIGpqIF0gPSB0aGlzLlNCT1hFU1sgaWkgXVsgamogXTtcblx0fVxuICAgIH1cblxuICAgIHZhciB2YWxzID0gWyAweDAwMDAwMDAwLCAweDAwMDAwMDAwIF07XG5cbiAgICBmb3IgKCBpaT0wOyBpaSA8IHRoaXMuTk4rMjsgaWkgKz0gMiApIHtcblx0dGhpcy5fZW5jcnlwdF9ibG9jayggdmFscyApO1xuXHR0aGlzLnBhcnJheVsgaWkgKyAwIF0gPSB2YWxzWyAwIF07XG5cdHRoaXMucGFycmF5WyBpaSArIDEgXSA9IHZhbHNbIDEgXTtcbiAgICB9XG5cbiAgICBmb3IgKCBpaT0wOyBpaSA8IDQ7ICsraWkgKSB7XG5cdGZvciAoIGpqPTA7IGpqIDwgMjU2OyBqaiArPSAyICkge1xuXHQgICAgdGhpcy5fZW5jcnlwdF9ibG9jayggdmFscyApO1xuXHQgICAgdGhpcy5zYm94ZXNbIGlpIF1bIGpqICsgMCBdID0gdmFsc1sgMCBdO1xuXHQgICAgdGhpcy5zYm94ZXNbIGlpIF1bIGpqICsgMSBdID0gdmFsc1sgMSBdO1xuXHR9XG4gICAgfVxufTtcblxudmFyIHV0aWwgPSByZXF1aXJlKCcuLi8uLi91dGlsJyk7XG5cbi8vIGFkZGVkIGJ5IFJlY3VyaXR5IExhYnNcbmZ1bmN0aW9uIEJGZW5jcnlwdChibG9jayxrZXkpIHtcblx0dmFyIGJmID0gbmV3IEJsb3dmaXNoKCk7XG5cdGJmLmluaXQodXRpbC5zdHIyYmluKGtleSkpO1xuXHRyZXR1cm4gYmYuZW5jcnlwdF9ibG9jayhibG9jayk7XG59XG5cbm1vZHVsZS5leHBvcnRzID0gQkZlbmNyeXB0O1xuIiwiLy8gR1BHNEJyb3dzZXJzIC0gQW4gT3BlblBHUCBpbXBsZW1lbnRhdGlvbiBpbiBqYXZhc2NyaXB0XG4vLyBDb3B5cmlnaHQgKEMpIDIwMTEgUmVjdXJpdHkgTGFicyBHbWJIXG4vLyBcbi8vIFRoaXMgbGlicmFyeSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3Jcbi8vIG1vZGlmeSBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBMZXNzZXIgR2VuZXJhbCBQdWJsaWNcbi8vIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5IHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlclxuLy8gdmVyc2lvbiAyLjEgb2YgdGhlIExpY2Vuc2UsIG9yIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4vLyBcbi8vIFRoaXMgbGlicmFyeSBpcyBkaXN0cmlidXRlZCBpbiB0aGUgaG9wZSB0aGF0IGl0IHdpbGwgYmUgdXNlZnVsLFxuLy8gYnV0IFdJVEhPVVQgQU5ZIFdBUlJBTlRZOyB3aXRob3V0IGV2ZW4gdGhlIGltcGxpZWQgd2FycmFudHkgb2Zcbi8vIE1FUkNIQU5UQUJJTElUWSBvciBGSVRORVNTIEZPUiBBIFBBUlRJQ1VMQVIgUFVSUE9TRS4gIFNlZSB0aGUgR05VXG4vLyBMZXNzZXIgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBmb3IgbW9yZSBkZXRhaWxzLlxuLy8gXG4vLyBZb3Ugc2hvdWxkIGhhdmUgcmVjZWl2ZWQgYSBjb3B5IG9mIHRoZSBHTlUgTGVzc2VyIEdlbmVyYWwgUHVibGljXG4vLyBMaWNlbnNlIGFsb25nIHdpdGggdGhpcyBsaWJyYXJ5OyBpZiBub3QsIHdyaXRlIHRvIHRoZSBGcmVlIFNvZnR3YXJlXG4vLyBGb3VuZGF0aW9uLCBJbmMuLCA1MSBGcmFua2xpbiBTdHJlZXQsIEZpZnRoIEZsb29yLCBCb3N0b24sIE1BICAwMjExMC0xMzAxICBVU0Fcbi8vXG4vLyBFbEdhbWFsIGltcGxlbWVudGF0aW9uXG5cbnZhciBCaWdJbnRlZ2VyID0gcmVxdWlyZSgnLi9qc2JuLmpzJyksXG5cdHV0aWwgPSByZXF1aXJlKCcuLi8uLi91dGlsJyk7XG5cbmZ1bmN0aW9uIEVsZ2FtYWwoKSB7XG5cdFxuXHRmdW5jdGlvbiBlbmNyeXB0KG0sZyxwLHkpIHtcblx0XHQvLyAgY2hvb3NlIGsgaW4gezIsLi4uLHAtMn1cblx0XHR2YXIgdHdvID0gQmlnSW50ZWdlci5PTkUuYWRkKEJpZ0ludGVnZXIuT05FKTtcblx0XHR2YXIgcE1pbnVzMiA9IHAuc3VidHJhY3QodHdvKTtcblx0XHR2YXIgayA9IG9wZW5wZ3BfY3J5cHRvX2dldFJhbmRvbUJpZ0ludGVnZXJJblJhbmdlKHR3bywgcE1pbnVzMik7XG5cdFx0dmFyIGsgPSBrLm1vZChwTWludXMyKS5hZGQoQmlnSW50ZWdlci5PTkUpO1xuXHRcdHZhciBjID0gbmV3IEFycmF5KCk7XG5cdFx0Y1swXSA9IGcubW9kUG93KGssIHApO1xuXHRcdGNbMV0gPSB5Lm1vZFBvdyhrLCBwKS5tdWx0aXBseShtKS5tb2QocCkudG9NUEkoKTtcblx0XHRjWzBdID0gY1swXS50b01QSSgpO1xuXHRcdHJldHVybiBjO1xuXHR9XG5cdFxuXHRmdW5jdGlvbiBkZWNyeXB0KGMxLGMyLHAseCkge1xuXHRcdHV0aWwucHJpbnRfZGVidWcoXCJFbGdhbWFsIERlY3J5cHQ6XFxuYzE6XCIrdXRpbC5oZXhzdHJkdW1wKGMxLnRvTVBJKCkpK1wiXFxuXCIrXG5cdFx0XHQgIFwiYzI6XCIrdXRpbC5oZXhzdHJkdW1wKGMyLnRvTVBJKCkpK1wiXFxuXCIrXG5cdFx0XHQgIFwicDpcIit1dGlsLmhleHN0cmR1bXAocC50b01QSSgpKStcIlxcblwiK1xuXHRcdFx0ICBcIng6XCIrdXRpbC5oZXhzdHJkdW1wKHgudG9NUEkoKSkpO1xuXHRcdHJldHVybiAoYzEubW9kUG93KHgsIHApLm1vZEludmVyc2UocCkpLm11bHRpcGx5KGMyKS5tb2QocCk7XG5cdFx0Ly92YXIgYyA9IGMxLnBvdyh4KS5tb2RJbnZlcnNlKHApOyAvLyBjMF4tYSBtb2QgcFxuXHQgICAgLy9yZXR1cm4gYy5tdWx0aXBseShjMikubW9kKHApO1xuXHR9XG5cdFxuXHQvLyBzaWduaW5nIGFuZCBzaWduYXR1cmUgdmVyaWZpY2F0aW9uIHVzaW5nIEVsZ2FtYWwgaXMgbm90IHJlcXVpcmVkIGJ5IE9wZW5QR1AuXG5cdHRoaXMuZW5jcnlwdCA9IGVuY3J5cHQ7XG5cdHRoaXMuZGVjcnlwdCA9IGRlY3J5cHQ7XG59XG5cbm1vZHVsZS5leHBvcnRzID0gRWxnYW1hbDtcbiJdfQ==
;