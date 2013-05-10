require=(function(e,t,n){function i(n,s){if(!t[n]){if(!e[n]){var o=typeof require=="function"&&require;if(!s&&o)return o(n,!0);if(r)return r(n,!0);throw new Error("Cannot find module '"+n+"'")}var u=t[n]={exports:{}};e[n][0].call(u.exports,function(t){var r=e[n][1][t];return i(r?r:t)},u,u.exports)}return t[n].exports}var r=typeof require=="function"&&require;for(var s=0;s<n.length;s++)i(n[s]);return i})({"openpgp":[function(require,module,exports){
module.exports=require('ROoLW5');
},{}],"ROoLW5":[function(require,module,exports){
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

/** RFC4880, section 9.1 
 * @enum {Integer}
 */
openpgp.publickey = {
	rsa_encrypt_sign: 1,
	rsa_encrypt: 2,
	rsa_sign: 3,
	elgamal: 16,
	dsa: 17
};

/** RFC4880, section 9.2 
 * @enum {Integer}
 */
openpgp.symmetric = {
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
};

/** RFC4880, section 9.3
 * @enum {Integer}
 */
openpgp.compression = {
	uncompressed: 0,
	/** RFC1951 */
	zip: 1,
	/** RFC1950 */
	zlib: 2,
	bzip2: 3
};

/** RFC4880, section 9.4
 * @enum {Integer}
 */
openpgp.hash = {
	md5: 1,
	sha1: 2,
	ripemd: 3,
	sha256: 8,
	sha384: 9,
	sha512: 10,
	sha224: 11
};

module.exports = {
	cipher: {
		aes: require('./ciphers/symmetric/aes.js'),
		des: require('./ciphers/symmetric/dessrc.js'),
		cast5: require('./ciphers/symmetric/cast5.js'),
		twofish: require('./ciphers/symmetric/twofish.js'),
		blowfish: require('./ciphers/symmetric/blowfish.js')
	},
	hash: {
		md5: require('./ciphers/hash/md5.js'),
		sha: require('./ciphers/hash/sha.js'),
		ripemd: require('./ciphers/hash/ripe-md.js')
	},
	util: require('./util/util.js')
}


},{"./ciphers/symmetric/aes.js":1,"./ciphers/symmetric/dessrc.js":2,"./ciphers/symmetric/cast5.js":3,"./ciphers/symmetric/twofish.js":4,"./ciphers/symmetric/blowfish.js":5,"./ciphers/hash/md5.js":6,"./ciphers/hash/sha.js":7,"./ciphers/hash/ripe-md.js":8,"./util/util.js":9}],1:[function(require,module,exports){

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
	AESencrypt: AESencrypt,
	keyExpansion: keyExpansion
}

},{}],2:[function(require,module,exports){
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

},{}],4:[function(require,module,exports){
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

},{}],3:[function(require,module,exports){

// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Copyright 2010 pjacobs@xeekr.com . All rights reserved.

// Modified by Recurity Labs GmbH

// fixed/modified by Herbert Hanewinkel, www.haneWIN.de
// check www.haneWIN.de for the latest version

// cast5.js is a Javascript implementation of CAST-128, as defined in RFC 2144.
// CAST-128 is a common OpenPGP cipher.


// CAST5 constructor

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

},{}],5:[function(require,module,exports){
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

// added by Recurity Labs
function BFencrypt(block,key) {
	var bf = new Blowfish();
	bf.init(util.str2bin(key));
	return bf.encrypt_block(block);
}

module.exports = BFencrypt;

},{}],6:[function(require,module,exports){
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
},{}],7:[function(require,module,exports){
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

},{}],8:[function(require,module,exports){
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

},{}],9:[function(require,module,exports){
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

},{}]},{},[])
//@ sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZ2VuZXJhdGVkLmpzIiwic291cmNlcyI6WyIvaG9tZS9wYW5jYWtlL2NvZGUvb3BlbnBncGpzL3NyYy9vcGVucGdwLmpzIiwiL2hvbWUvcGFuY2FrZS9jb2RlL29wZW5wZ3Bqcy9zcmMvY2lwaGVycy9zeW1tZXRyaWMvYWVzLmpzIiwiL2hvbWUvcGFuY2FrZS9jb2RlL29wZW5wZ3Bqcy9zcmMvY2lwaGVycy9zeW1tZXRyaWMvZGVzc3JjLmpzIiwiL2hvbWUvcGFuY2FrZS9jb2RlL29wZW5wZ3Bqcy9zcmMvY2lwaGVycy9zeW1tZXRyaWMvdHdvZmlzaC5qcyIsIi9ob21lL3BhbmNha2UvY29kZS9vcGVucGdwanMvc3JjL2NpcGhlcnMvc3ltbWV0cmljL2Nhc3Q1LmpzIiwiL2hvbWUvcGFuY2FrZS9jb2RlL29wZW5wZ3Bqcy9zcmMvY2lwaGVycy9zeW1tZXRyaWMvYmxvd2Zpc2guanMiLCIvaG9tZS9wYW5jYWtlL2NvZGUvb3BlbnBncGpzL3NyYy9jaXBoZXJzL2hhc2gvbWQ1LmpzIiwiL2hvbWUvcGFuY2FrZS9jb2RlL29wZW5wZ3Bqcy9zcmMvY2lwaGVycy9oYXNoL3NoYS5qcyIsIi9ob21lL3BhbmNha2UvY29kZS9vcGVucGdwanMvc3JjL2NpcGhlcnMvaGFzaC9yaXBlLW1kLmpzIiwiL2hvbWUvcGFuY2FrZS9jb2RlL29wZW5wZ3Bqcy9zcmMvdXRpbC91dGlsLmpzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUFBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ2hoQkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDemVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNqTkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDL1NBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ3JpQkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQzNZQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUMvTUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDbHNDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ3ZTQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBIiwic291cmNlc0NvbnRlbnQiOlsiLy8gR1BHNEJyb3dzZXJzIC0gQW4gT3BlblBHUCBpbXBsZW1lbnRhdGlvbiBpbiBqYXZhc2NyaXB0XG4vLyBDb3B5cmlnaHQgKEMpIDIwMTEgUmVjdXJpdHkgTGFicyBHbWJIXG4vLyBcbi8vIFRoaXMgbGlicmFyeSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3Jcbi8vIG1vZGlmeSBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBMZXNzZXIgR2VuZXJhbCBQdWJsaWNcbi8vIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5IHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlclxuLy8gdmVyc2lvbiAyLjEgb2YgdGhlIExpY2Vuc2UsIG9yIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4vLyBcbi8vIFRoaXMgbGlicmFyeSBpcyBkaXN0cmlidXRlZCBpbiB0aGUgaG9wZSB0aGF0IGl0IHdpbGwgYmUgdXNlZnVsLFxuLy8gYnV0IFdJVEhPVVQgQU5ZIFdBUlJBTlRZOyB3aXRob3V0IGV2ZW4gdGhlIGltcGxpZWQgd2FycmFudHkgb2Zcbi8vIE1FUkNIQU5UQUJJTElUWSBvciBGSVRORVNTIEZPUiBBIFBBUlRJQ1VMQVIgUFVSUE9TRS4gIFNlZSB0aGUgR05VXG4vLyBMZXNzZXIgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBmb3IgbW9yZSBkZXRhaWxzLlxuLy8gXG4vLyBZb3Ugc2hvdWxkIGhhdmUgcmVjZWl2ZWQgYSBjb3B5IG9mIHRoZSBHTlUgTGVzc2VyIEdlbmVyYWwgUHVibGljXG4vLyBMaWNlbnNlIGFsb25nIHdpdGggdGhpcyBsaWJyYXJ5OyBpZiBub3QsIHdyaXRlIHRvIHRoZSBGcmVlIFNvZnR3YXJlXG4vLyBGb3VuZGF0aW9uLCBJbmMuLCA1MSBGcmFua2xpbiBTdHJlZXQsIEZpZnRoIEZsb29yLCBCb3N0b24sIE1BICAwMjExMC0xMzAxICBVU0FcblxuLyoqXG4gKiBAZmlsZW92ZXJ2aWV3IFRoZSBvcGVucGdwIGJhc2UgY2xhc3Mgc2hvdWxkIHByb3ZpZGUgYWxsIG9mIHRoZSBmdW5jdGlvbmFsaXR5IFxuICogdG8gY29uc3VtZSB0aGUgb3BlbnBncC5qcyBsaWJyYXJ5LiBBbGwgYWRkaXRpb25hbCBjbGFzc2VzIGFyZSBkb2N1bWVudGVkIFxuICogZm9yIGV4dGVuZGluZyBhbmQgZGV2ZWxvcGluZyBvbiB0b3Agb2YgdGhlIGJhc2UgbGlicmFyeS5cbiAqL1xuXG4vKipcbiAqIEdQRzRCcm93c2VycyBDb3JlIGludGVyZmFjZS4gQSBzaW5nbGUgaW5zdGFuY2UgaXMgaG9sZFxuICogZnJvbSB0aGUgYmVnaW5uaW5nLiBUbyB1c2UgdGhpcyBsaWJyYXJ5IGNhbGwgXCJvcGVucGdwLmluaXQoKVwiXG4gKiBAYWxpYXMgb3BlbnBncFxuICogQGNsYXNzXG4gKiBAY2xhc3NkZXNjIE1haW4gT3BlbnBncC5qcyBjbGFzcy4gVXNlIHRoaXMgdG8gaW5pdGlhdGUgYW5kIG1ha2UgYWxsIGNhbGxzIHRvIHRoaXMgbGlicmFyeS5cbiAqL1xuZnVuY3Rpb24gX29wZW5wZ3AgKCkge1xuXHR0aGlzLnRvc3RyaW5nID0gXCJcIjtcblx0XG5cdC8qKlxuXHQgKiBpbml0aWFsaXplcyB0aGUgbGlicmFyeTpcblx0ICogLSByZWFkaW5nIHRoZSBrZXlyaW5nIGZyb20gbG9jYWwgc3RvcmFnZVxuXHQgKiAtIHJlYWRpbmcgdGhlIGNvbmZpZyBmcm9tIGxvY2FsIHN0b3JhZ2Vcblx0ICovXG5cdGZ1bmN0aW9uIGluaXQoKSB7XG5cdFx0dGhpcy5jb25maWcgPSBuZXcgb3BlbnBncF9jb25maWcoKTtcblx0XHR0aGlzLmNvbmZpZy5yZWFkKCk7XG5cdFx0dGhpcy5rZXlyaW5nID0gbmV3IG9wZW5wZ3Bfa2V5cmluZygpO1xuXHRcdHRoaXMua2V5cmluZy5pbml0KCk7XG5cdH1cblx0XG5cdC8qKlxuXHQgKiByZWFkcyBzZXZlcmFsIHB1YmxpY0tleSBvYmplY3RzIGZyb20gYSBhc2NpaSBhcm1vcmVkXG5cdCAqIHJlcHJlc2VudGF0aW9uIGFuIHJldHVybnMgb3BlbnBncF9tc2dfcHVibGlja2V5IHBhY2tldHNcblx0ICogQHBhcmFtIHtTdHJpbmd9IGFybW9yZWRUZXh0IE9wZW5QR1AgYXJtb3JlZCB0ZXh0IGNvbnRhaW5pbmdcblx0ICogdGhlIHB1YmxpYyBrZXkocylcblx0ICogQHJldHVybiB7b3BlbnBncF9tc2dfcHVibGlja2V5W119IG9uIGVycm9yIHRoZSBmdW5jdGlvblxuXHQgKiByZXR1cm5zIG51bGxcblx0ICovXG5cdGZ1bmN0aW9uIHJlYWRfcHVibGljS2V5KGFybW9yZWRUZXh0KSB7XG5cdFx0dmFyIG15cG9zID0gMDtcblx0XHR2YXIgcHVibGljS2V5cyA9IG5ldyBBcnJheSgpO1xuXHRcdHZhciBwdWJsaWNLZXlDb3VudCA9IDA7XG5cdFx0dmFyIGlucHV0ID0gb3BlbnBncF9lbmNvZGluZ19kZUFybW9yKGFybW9yZWRUZXh0LnJlcGxhY2UoL1xcci9nLCcnKSkub3BlbnBncDtcblx0XHR2YXIgbCA9IGlucHV0Lmxlbmd0aDtcblx0XHR3aGlsZSAobXlwb3MgIT0gaW5wdXQubGVuZ3RoKSB7XG5cdFx0XHR2YXIgZmlyc3RfcGFja2V0ID0gb3BlbnBncF9wYWNrZXQucmVhZF9wYWNrZXQoaW5wdXQsIG15cG9zLCBsKTtcblx0XHRcdC8vIHB1YmxpYyBrZXkgcGFyc2VyXG5cdFx0XHRpZiAoaW5wdXRbbXlwb3NdLmNoYXJDb2RlQXQoKSA9PSAweDk5IHx8IGZpcnN0X3BhY2tldC50YWdUeXBlID09IDYpIHtcblx0XHRcdFx0cHVibGljS2V5c1twdWJsaWNLZXlDb3VudF0gPSBuZXcgb3BlbnBncF9tc2dfcHVibGlja2V5KCk7XHRcdFx0XHRcblx0XHRcdFx0cHVibGljS2V5c1twdWJsaWNLZXlDb3VudF0uaGVhZGVyID0gaW5wdXQuc3Vic3RyaW5nKG15cG9zLG15cG9zKzMpO1xuXHRcdFx0XHRpZiAoaW5wdXRbbXlwb3NdLmNoYXJDb2RlQXQoKSA9PSAweDk5KSB7XG5cdFx0XHRcdFx0Ly8gcGFyc2UgdGhlIGxlbmd0aCBhbmQgcmVhZCBhIHRhZzYgcGFja2V0XG5cdFx0XHRcdFx0bXlwb3MrKztcblx0XHRcdFx0XHR2YXIgbCA9IChpbnB1dFtteXBvcysrXS5jaGFyQ29kZUF0KCkgPDwgOClcblx0XHRcdFx0XHRcdFx0fCBpbnB1dFtteXBvcysrXS5jaGFyQ29kZUF0KCk7XG5cdFx0XHRcdFx0cHVibGljS2V5c1twdWJsaWNLZXlDb3VudF0ucHVibGljS2V5UGFja2V0ID0gbmV3IG9wZW5wZ3BfcGFja2V0X2tleW1hdGVyaWFsKCk7XG5cdFx0XHRcdFx0cHVibGljS2V5c1twdWJsaWNLZXlDb3VudF0ucHVibGljS2V5UGFja2V0LmhlYWRlciA9IHB1YmxpY0tleXNbcHVibGljS2V5Q291bnRdLmhlYWRlcjtcblx0XHRcdFx0XHRwdWJsaWNLZXlzW3B1YmxpY0tleUNvdW50XS5wdWJsaWNLZXlQYWNrZXQucmVhZF90YWc2KGlucHV0LCBteXBvcywgbCk7XG5cdFx0XHRcdFx0bXlwb3MgKz0gcHVibGljS2V5c1twdWJsaWNLZXlDb3VudF0ucHVibGljS2V5UGFja2V0LnBhY2tldExlbmd0aDtcblx0XHRcdFx0XHRteXBvcyArPSBwdWJsaWNLZXlzW3B1YmxpY0tleUNvdW50XS5yZWFkX25vZGVzKHB1YmxpY0tleXNbcHVibGljS2V5Q291bnRdLnB1YmxpY0tleVBhY2tldCwgaW5wdXQsIG15cG9zLCAoaW5wdXQubGVuZ3RoIC0gbXlwb3MpKTtcblx0XHRcdFx0fSBlbHNlIHtcblx0XHRcdFx0XHRwdWJsaWNLZXlzW3B1YmxpY0tleUNvdW50XSA9IG5ldyBvcGVucGdwX21zZ19wdWJsaWNrZXkoKTtcblx0XHRcdFx0XHRwdWJsaWNLZXlzW3B1YmxpY0tleUNvdW50XS5wdWJsaWNLZXlQYWNrZXQgPSBmaXJzdF9wYWNrZXQ7XG5cdFx0XHRcdFx0bXlwb3MgKz0gZmlyc3RfcGFja2V0LmhlYWRlckxlbmd0aCtmaXJzdF9wYWNrZXQucGFja2V0TGVuZ3RoO1xuXHRcdFx0XHRcdG15cG9zICs9IHB1YmxpY0tleXNbcHVibGljS2V5Q291bnRdLnJlYWRfbm9kZXMoZmlyc3RfcGFja2V0LCBpbnB1dCwgbXlwb3MsIGlucHV0Lmxlbmd0aCAtbXlwb3MpO1xuXHRcdFx0XHR9XG5cdFx0XHR9IGVsc2Uge1xuXHRcdFx0XHR1dGlsLnByaW50X2Vycm9yKFwibm8gcHVibGljIGtleSBmb3VuZCFcIik7XG5cdFx0XHRcdHJldHVybiBudWxsO1xuXHRcdFx0fVxuXHRcdFx0cHVibGljS2V5c1twdWJsaWNLZXlDb3VudF0uZGF0YSA9IGlucHV0LnN1YnN0cmluZygwLG15cG9zKTtcblx0XHRcdHB1YmxpY0tleUNvdW50Kys7XG5cdFx0fVxuXHRcdHJldHVybiBwdWJsaWNLZXlzO1xuXHR9XG5cdFxuXHQvKipcblx0ICogcmVhZHMgc2V2ZXJhbCBwcml2YXRlS2V5IG9iamVjdHMgZnJvbSBhIGFzY2lpIGFybW9yZWRcblx0ICogcmVwcmVzZW50YXRpb24gYW4gcmV0dXJucyBvcGVucGdwX21zZ19wcml2YXRla2V5IG9iamVjdHNcblx0ICogQHBhcmFtIHtTdHJpbmd9IGFybW9yZWRUZXh0IE9wZW5QR1AgYXJtb3JlZCB0ZXh0IGNvbnRhaW5pbmdcblx0ICogdGhlIHByaXZhdGUga2V5KHMpXG5cdCAqIEByZXR1cm4ge29wZW5wZ3BfbXNnX3ByaXZhdGVrZXlbXX0gb24gZXJyb3IgdGhlIGZ1bmN0aW9uXG5cdCAqIHJldHVybnMgbnVsbFxuXHQgKi9cblx0ZnVuY3Rpb24gcmVhZF9wcml2YXRlS2V5KGFybW9yZWRUZXh0KSB7XG5cdFx0dmFyIHByaXZhdGVLZXlzID0gbmV3IEFycmF5KCk7XG5cdFx0dmFyIHByaXZhdGVLZXlDb3VudCA9IDA7XG5cdFx0dmFyIG15cG9zID0gMDtcblx0XHR2YXIgaW5wdXQgPSBvcGVucGdwX2VuY29kaW5nX2RlQXJtb3IoYXJtb3JlZFRleHQucmVwbGFjZSgvXFxyL2csJycpKS5vcGVucGdwO1xuXHRcdHZhciBsID0gaW5wdXQubGVuZ3RoO1xuXHRcdHdoaWxlIChteXBvcyAhPSBpbnB1dC5sZW5ndGgpIHtcblx0XHRcdHZhciBmaXJzdF9wYWNrZXQgPSBvcGVucGdwX3BhY2tldC5yZWFkX3BhY2tldChpbnB1dCwgbXlwb3MsIGwpO1xuXHRcdFx0aWYgKGZpcnN0X3BhY2tldC50YWdUeXBlID09IDUpIHtcblx0XHRcdFx0cHJpdmF0ZUtleXNbcHJpdmF0ZUtleXMubGVuZ3RoXSA9IG5ldyBvcGVucGdwX21zZ19wcml2YXRla2V5KCk7XG5cdFx0XHRcdG15cG9zICs9IGZpcnN0X3BhY2tldC5oZWFkZXJMZW5ndGgrZmlyc3RfcGFja2V0LnBhY2tldExlbmd0aDtcblx0XHRcdFx0bXlwb3MgKz0gcHJpdmF0ZUtleXNbcHJpdmF0ZUtleUNvdW50XS5yZWFkX25vZGVzKGZpcnN0X3BhY2tldCwgaW5wdXQsIG15cG9zLCBsKTtcblx0XHRcdC8vIG90aGVyIGJsb2Nrc1x0ICAgICAgICAgICAgXG5cdFx0XHR9IGVsc2Uge1xuXHRcdFx0XHR1dGlsLnByaW50X2Vycm9yKCdubyBibG9jayBwYWNrZXQgZm91bmQhJyk7XG5cdFx0XHRcdHJldHVybiBudWxsO1xuXHRcdFx0fVxuXHRcdFx0cHJpdmF0ZUtleXNbcHJpdmF0ZUtleUNvdW50XS5kYXRhID0gaW5wdXQuc3Vic3RyaW5nKDAsbXlwb3MpO1xuXHRcdFx0cHJpdmF0ZUtleUNvdW50Kys7XG5cdFx0fVxuXHRcdHJldHVybiBwcml2YXRlS2V5cztcdFx0XG5cdH1cblxuXHQvKipcblx0ICogcmVhZHMgbWVzc2FnZSBwYWNrZXRzIG91dCBvZiBhbiBPcGVuUEdQIGFybW9yZWQgdGV4dCBhbmRcblx0ICogcmV0dXJucyBhbiBhcnJheSBvZiBtZXNzYWdlIG9iamVjdHNcblx0ICogQHBhcmFtIHtTdHJpbmd9IGFybW9yZWRUZXh0IHRleHQgdG8gYmUgcGFyc2VkXG5cdCAqIEByZXR1cm4ge29wZW5wZ3BfbXNnX21lc3NhZ2VbXX0gb24gZXJyb3IgdGhlIGZ1bmN0aW9uXG5cdCAqIHJldHVybnMgbnVsbFxuXHQgKi9cblx0ZnVuY3Rpb24gcmVhZF9tZXNzYWdlKGFybW9yZWRUZXh0KSB7XG5cdFx0dmFyIGRlYXJtb3JlZDtcblx0XHR0cnl7XG4gICAgXHRcdGRlYXJtb3JlZCA9IG9wZW5wZ3BfZW5jb2RpbmdfZGVBcm1vcihhcm1vcmVkVGV4dC5yZXBsYWNlKC9cXHIvZywnJykpO1xuXHRcdH1cblx0XHRjYXRjaChlKXtcbiAgICBcdFx0dXRpbC5wcmludF9lcnJvcignbm8gbWVzc2FnZSBmb3VuZCEnKTtcbiAgICBcdFx0cmV0dXJuIG51bGw7XG5cdFx0fVxuXHRcdHJldHVybiByZWFkX21lc3NhZ2VzX2RlYXJtb3JlZChkZWFybW9yZWQpO1xuXHRcdH1cblx0XHRcblx0LyoqXG5cdCAqIHJlYWRzIG1lc3NhZ2UgcGFja2V0cyBvdXQgb2YgYW4gT3BlblBHUCBhcm1vcmVkIHRleHQgYW5kXG5cdCAqIHJldHVybnMgYW4gYXJyYXkgb2YgbWVzc2FnZSBvYmplY3RzLiBDYW4gYmUgY2FsbGVkIGV4dGVybmFsbHkgb3IgaW50ZXJuYWxseS5cblx0ICogRXh0ZXJuYWwgY2FsbCB3aWxsIHBhcnNlIGEgZGUtYXJtb3JlZCBtZXNzYWdlZCBhbmQgcmV0dXJuIG1lc3NhZ2VzIGZvdW5kLlxuXHQgKiBJbnRlcm5hbCB3aWxsIGJlIGNhbGxlZCB0byByZWFkIHBhY2tldHMgd3JhcHBlZCBpbiBvdGhlciBwYWNrZXRzIChpLmUuIGNvbXByZXNzZWQpXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBpbnB1dCBkZWFybW9yZWQgdGV4dCBvZiBPcGVuUEdQIHBhY2tldHMsIHRvIGJlIHBhcnNlZFxuXHQgKiBAcmV0dXJuIHtvcGVucGdwX21zZ19tZXNzYWdlW119IG9uIGVycm9yIHRoZSBmdW5jdGlvblxuXHQgKiByZXR1cm5zIG51bGxcblx0ICovXG5cdGZ1bmN0aW9uIHJlYWRfbWVzc2FnZXNfZGVhcm1vcmVkKGlucHV0KXtcblx0XHR2YXIgbWVzc2FnZVN0cmluZyA9IGlucHV0Lm9wZW5wZ3A7XG5cdFx0dmFyIHNpZ25hdHVyZVRleHQgPSBpbnB1dC50ZXh0OyAvL3RleHQgdG8gdmVyaWZ5IHNpZ25hdHVyZXMgYWdhaW5zdC4gTW9kaWZpZWQgYnkgVGFnMTEuXG5cdFx0dmFyIG1lc3NhZ2VzID0gbmV3IEFycmF5KCk7XG5cdFx0dmFyIG1lc3NhZ2VDb3VudCA9IDA7XG5cdFx0dmFyIG15cG9zID0gMDtcblx0XHR2YXIgbCA9IG1lc3NhZ2VTdHJpbmcubGVuZ3RoO1xuXHRcdHdoaWxlIChteXBvcyA8IG1lc3NhZ2VTdHJpbmcubGVuZ3RoKSB7XG5cdFx0XHR2YXIgZmlyc3RfcGFja2V0ID0gb3BlbnBncF9wYWNrZXQucmVhZF9wYWNrZXQobWVzc2FnZVN0cmluZywgbXlwb3MsIGwpO1xuXHRcdFx0aWYgKCFmaXJzdF9wYWNrZXQpIHtcblx0XHRcdFx0YnJlYWs7XG5cdFx0XHR9XG5cdFx0XHQvLyBwdWJsaWMga2V5IHBhcnNlciAoZGVmaW5pdGlvbiBmcm9tIHRoZSBzdGFuZGFyZDopXG5cdFx0XHQvLyBPcGVuUEdQIE1lc3NhZ2UgICAgICA6LSBFbmNyeXB0ZWQgTWVzc2FnZSB8IFNpZ25lZCBNZXNzYWdlIHxcblx0XHRcdC8vICAgICAgICAgICAgICAgICAgICAgICAgIENvbXByZXNzZWQgTWVzc2FnZSB8IExpdGVyYWwgTWVzc2FnZS5cblx0XHRcdC8vIENvbXByZXNzZWQgTWVzc2FnZSAgIDotIENvbXByZXNzZWQgRGF0YSBQYWNrZXQuXG5cdFx0XHQvLyBcblx0XHRcdC8vIExpdGVyYWwgTWVzc2FnZSAgICAgIDotIExpdGVyYWwgRGF0YSBQYWNrZXQuXG5cdFx0XHQvLyBcblx0XHRcdC8vIEVTSyAgICAgICAgICAgICAgICAgIDotIFB1YmxpYy1LZXkgRW5jcnlwdGVkIFNlc3Npb24gS2V5IFBhY2tldCB8XG5cdFx0XHQvLyAgICAgICAgICAgICAgICAgICAgICAgICBTeW1tZXRyaWMtS2V5IEVuY3J5cHRlZCBTZXNzaW9uIEtleSBQYWNrZXQuXG5cdFx0XHQvLyBcblx0XHRcdC8vIEVTSyBTZXF1ZW5jZSAgICAgICAgIDotIEVTSyB8IEVTSyBTZXF1ZW5jZSwgRVNLLlxuXHRcdFx0Ly8gXG5cdFx0XHQvLyBFbmNyeXB0ZWQgRGF0YSAgICAgICA6LSBTeW1tZXRyaWNhbGx5IEVuY3J5cHRlZCBEYXRhIFBhY2tldCB8XG5cdFx0XHQvLyAgICAgICAgICAgICAgICAgICAgICAgICBTeW1tZXRyaWNhbGx5IEVuY3J5cHRlZCBJbnRlZ3JpdHkgUHJvdGVjdGVkIERhdGEgUGFja2V0XG5cdFx0XHQvLyBcblx0XHRcdC8vIEVuY3J5cHRlZCBNZXNzYWdlICAgIDotIEVuY3J5cHRlZCBEYXRhIHwgRVNLIFNlcXVlbmNlLCBFbmNyeXB0ZWQgRGF0YS5cblx0XHRcdC8vIFxuXHRcdFx0Ly8gT25lLVBhc3MgU2lnbmVkIE1lc3NhZ2UgOi0gT25lLVBhc3MgU2lnbmF0dXJlIFBhY2tldCxcblx0XHRcdC8vICAgICAgICAgICAgICAgICAgICAgICAgIE9wZW5QR1AgTWVzc2FnZSwgQ29ycmVzcG9uZGluZyBTaWduYXR1cmUgUGFja2V0LlxuXG5cdFx0XHQvLyBTaWduZWQgTWVzc2FnZSAgICAgICA6LSBTaWduYXR1cmUgUGFja2V0LCBPcGVuUEdQIE1lc3NhZ2UgfFxuXHRcdFx0Ly8gICAgICAgICAgICAgICAgICAgICAgICAgT25lLVBhc3MgU2lnbmVkIE1lc3NhZ2UuXG5cdFx0XHRpZiAoZmlyc3RfcGFja2V0LnRhZ1R5cGUgPT0gIDEgfHxcblx0XHRcdCAgICAoZmlyc3RfcGFja2V0LnRhZ1R5cGUgPT0gMiAmJiBmaXJzdF9wYWNrZXQuc2lnbmF0dXJlVHlwZSA8IDE2KSB8fFxuXHRcdFx0ICAgICBmaXJzdF9wYWNrZXQudGFnVHlwZSA9PSAgMyB8fFxuXHRcdFx0ICAgICBmaXJzdF9wYWNrZXQudGFnVHlwZSA9PSAgNCB8fFxuXHRcdFx0XHQgZmlyc3RfcGFja2V0LnRhZ1R5cGUgPT0gIDggfHxcblx0XHRcdFx0IGZpcnN0X3BhY2tldC50YWdUeXBlID09ICA5IHx8XG5cdFx0XHRcdCBmaXJzdF9wYWNrZXQudGFnVHlwZSA9PSAxMCB8fFxuXHRcdFx0XHQgZmlyc3RfcGFja2V0LnRhZ1R5cGUgPT0gMTEgfHxcblx0XHRcdFx0IGZpcnN0X3BhY2tldC50YWdUeXBlID09IDE4IHx8XG5cdFx0XHRcdCBmaXJzdF9wYWNrZXQudGFnVHlwZSA9PSAxOSkge1xuXHRcdFx0XHRtZXNzYWdlc1ttZXNzYWdlcy5sZW5ndGhdID0gbmV3IG9wZW5wZ3BfbXNnX21lc3NhZ2UoKTtcblx0XHRcdFx0bWVzc2FnZXNbbWVzc2FnZUNvdW50XS5tZXNzYWdlUGFja2V0ID0gZmlyc3RfcGFja2V0O1xuXHRcdFx0XHRtZXNzYWdlc1ttZXNzYWdlQ291bnRdLnR5cGUgPSBpbnB1dC50eXBlO1xuXHRcdFx0XHQvLyBFbmNyeXB0ZWQgTWVzc2FnZVxuXHRcdFx0XHRpZiAoZmlyc3RfcGFja2V0LnRhZ1R5cGUgPT0gOSB8fFxuXHRcdFx0XHQgICAgZmlyc3RfcGFja2V0LnRhZ1R5cGUgPT0gMSB8fFxuXHRcdFx0XHQgICAgZmlyc3RfcGFja2V0LnRhZ1R5cGUgPT0gMyB8fFxuXHRcdFx0XHQgICAgZmlyc3RfcGFja2V0LnRhZ1R5cGUgPT0gMTgpIHtcblx0XHRcdFx0XHRpZiAoZmlyc3RfcGFja2V0LnRhZ1R5cGUgPT0gOSkge1xuXHRcdFx0XHRcdFx0dXRpbC5wcmludF9lcnJvcihcInVuZXhwZWN0ZWQgb3BlbnBncCBwYWNrZXRcIik7XG5cdFx0XHRcdFx0XHRicmVhaztcblx0XHRcdFx0XHR9IGVsc2UgaWYgKGZpcnN0X3BhY2tldC50YWdUeXBlID09IDEpIHtcblx0XHRcdFx0XHRcdHV0aWwucHJpbnRfZGVidWcoXCJzZXNzaW9uIGtleSBmb3VuZDpcXG4gXCIrZmlyc3RfcGFja2V0LnRvU3RyaW5nKCkpO1xuXHRcdFx0XHRcdFx0dmFyIGlzc2Vzc2lvbmtleSA9IHRydWU7XG5cdFx0XHRcdFx0XHRtZXNzYWdlc1ttZXNzYWdlQ291bnRdLnNlc3Npb25LZXlzID0gbmV3IEFycmF5KCk7XG5cdFx0XHRcdFx0XHR2YXIgc2Vzc2lvbktleUNvdW50ID0gMDtcblx0XHRcdFx0XHRcdHdoaWxlIChpc3Nlc3Npb25rZXkpIHtcblx0XHRcdFx0XHRcdFx0bWVzc2FnZXNbbWVzc2FnZUNvdW50XS5zZXNzaW9uS2V5c1tzZXNzaW9uS2V5Q291bnRdID0gZmlyc3RfcGFja2V0O1xuXHRcdFx0XHRcdFx0XHRteXBvcyArPSBmaXJzdF9wYWNrZXQucGFja2V0TGVuZ3RoICsgZmlyc3RfcGFja2V0LmhlYWRlckxlbmd0aDtcblx0XHRcdFx0XHRcdFx0bCAtPSAoZmlyc3RfcGFja2V0LnBhY2tldExlbmd0aCArIGZpcnN0X3BhY2tldC5oZWFkZXJMZW5ndGgpO1xuXHRcdFx0XHRcdFx0XHRmaXJzdF9wYWNrZXQgPSBvcGVucGdwX3BhY2tldC5yZWFkX3BhY2tldChtZXNzYWdlU3RyaW5nLCBteXBvcywgbCk7XG5cdFx0XHRcdFx0XHRcdFxuXHRcdFx0XHRcdFx0XHRpZiAoZmlyc3RfcGFja2V0LnRhZ1R5cGUgIT0gMSAmJiBmaXJzdF9wYWNrZXQudGFnVHlwZSAhPSAzKVxuXHRcdFx0XHRcdFx0XHRcdGlzc2Vzc2lvbmtleSA9IGZhbHNlO1xuXHRcdFx0XHRcdFx0XHRzZXNzaW9uS2V5Q291bnQrKztcblx0XHRcdFx0XHRcdH1cblx0XHRcdFx0XHRcdGlmIChmaXJzdF9wYWNrZXQudGFnVHlwZSA9PSAxOCB8fCBmaXJzdF9wYWNrZXQudGFnVHlwZSA9PSA5KSB7XG5cdFx0XHRcdFx0XHRcdHV0aWwucHJpbnRfZGVidWcoXCJlbmNyeXB0ZWQgZGF0YSBmb3VuZDpcXG4gXCIrZmlyc3RfcGFja2V0LnRvU3RyaW5nKCkpO1xuXHRcdFx0XHRcdFx0XHRtZXNzYWdlc1ttZXNzYWdlQ291bnRdLmVuY3J5cHRlZERhdGEgPSBmaXJzdF9wYWNrZXQ7XG5cdFx0XHRcdFx0XHRcdG15cG9zICs9IGZpcnN0X3BhY2tldC5wYWNrZXRMZW5ndGgrZmlyc3RfcGFja2V0LmhlYWRlckxlbmd0aDtcblx0XHRcdFx0XHRcdFx0bCAtPSAoZmlyc3RfcGFja2V0LnBhY2tldExlbmd0aCtmaXJzdF9wYWNrZXQuaGVhZGVyTGVuZ3RoKTtcblx0XHRcdFx0XHRcdFx0bWVzc2FnZUNvdW50Kys7XG5cdFx0XHRcdFx0XHRcdFxuXHRcdFx0XHRcdFx0fSBlbHNlIHtcblx0XHRcdFx0XHRcdFx0dXRpbC5wcmludF9kZWJ1ZyhcInNvbWV0aGluZyBpcyB3cm9uZzogXCIrZmlyc3RfcGFja2V0LnRhZ1R5cGUpO1xuXHRcdFx0XHRcdFx0fVxuXHRcdFx0XHRcdFx0XG5cdFx0XHRcdFx0fSBlbHNlIGlmIChmaXJzdF9wYWNrZXQudGFnVHlwZSA9PSAxOCkge1xuXHRcdFx0XHRcdFx0dXRpbC5wcmludF9kZWJ1ZyhcInN5bW1ldHJpYyBlbmNyeXB0ZWQgZGF0YVwiKTtcblx0XHRcdFx0XHRcdGJyZWFrO1xuXHRcdFx0XHRcdH1cblx0XHRcdFx0fSBlbHNlIFxuXHRcdFx0XHRcdGlmIChmaXJzdF9wYWNrZXQudGFnVHlwZSA9PSAyICYmIGZpcnN0X3BhY2tldC5zaWduYXR1cmVUeXBlIDwgMykge1xuXHRcdFx0XHRcdC8vIFNpZ25lZCBNZXNzYWdlXG5cdFx0XHRcdFx0XHRteXBvcyArPSBmaXJzdF9wYWNrZXQucGFja2V0TGVuZ3RoICsgZmlyc3RfcGFja2V0LmhlYWRlckxlbmd0aDtcblx0XHRcdFx0XHRcdGwgLT0gKGZpcnN0X3BhY2tldC5wYWNrZXRMZW5ndGggKyBmaXJzdF9wYWNrZXQuaGVhZGVyTGVuZ3RoKTtcblx0XHRcdFx0XHRcdG1lc3NhZ2VzW21lc3NhZ2VDb3VudF0udGV4dCA9IHNpZ25hdHVyZVRleHQ7XG5cdFx0XHRcdFx0XHRtZXNzYWdlc1ttZXNzYWdlQ291bnRdLnNpZ25hdHVyZSA9IGZpcnN0X3BhY2tldDtcblx0XHRcdFx0ICAgICAgICBtZXNzYWdlQ291bnQrKztcblx0XHRcdFx0fSBlbHNlIFxuXHRcdFx0XHRcdC8vIFNpZ25lZCBNZXNzYWdlXG5cdFx0XHRcdFx0aWYgKGZpcnN0X3BhY2tldC50YWdUeXBlID09IDQpIHtcblx0XHRcdFx0XHRcdC8vVE9ETzogSW1wbGVtZW50IGNoZWNrXG5cdFx0XHRcdFx0XHRteXBvcyArPSBmaXJzdF9wYWNrZXQucGFja2V0TGVuZ3RoICsgZmlyc3RfcGFja2V0LmhlYWRlckxlbmd0aDtcblx0XHRcdFx0XHRcdGwgLT0gKGZpcnN0X3BhY2tldC5wYWNrZXRMZW5ndGggKyBmaXJzdF9wYWNrZXQuaGVhZGVyTGVuZ3RoKTtcblx0XHRcdFx0fSBlbHNlIFxuXHRcdFx0XHRcdGlmIChmaXJzdF9wYWNrZXQudGFnVHlwZSA9PSA4KSB7XG5cdFx0XHRcdFx0Ly8gQ29tcHJlc3NlZCBNZXNzYWdlXG5cdFx0XHRcdFx0XHRteXBvcyArPSBmaXJzdF9wYWNrZXQucGFja2V0TGVuZ3RoICsgZmlyc3RfcGFja2V0LmhlYWRlckxlbmd0aDtcblx0XHRcdFx0XHRcdGwgLT0gKGZpcnN0X3BhY2tldC5wYWNrZXRMZW5ndGggKyBmaXJzdF9wYWNrZXQuaGVhZGVyTGVuZ3RoKTtcblx0XHRcdFx0ICAgICAgICB2YXIgZGVjb21wcmVzc2VkVGV4dCA9IGZpcnN0X3BhY2tldC5kZWNvbXByZXNzKCk7XG5cdFx0XHRcdCAgICAgICAgbWVzc2FnZXMgPSBtZXNzYWdlcy5jb25jYXQob3BlbnBncC5yZWFkX21lc3NhZ2VzX2RlYXJtb3JlZCh7dGV4dDogZGVjb21wcmVzc2VkVGV4dCwgb3BlbnBncDogZGVjb21wcmVzc2VkVGV4dH0pKTtcblx0XHRcdFx0fSBlbHNlXG5cdFx0XHRcdFx0Ly8gTWFya2VyIFBhY2tldCAoT2Jzb2xldGUgTGl0ZXJhbCBQYWNrZXQpIChUYWcgMTApXG5cdFx0XHRcdFx0Ly8gXCJTdWNoIGEgcGFja2V0IE1VU1QgYmUgaWdub3JlZCB3aGVuIHJlY2VpdmVkLlwiIHNlZSBodHRwOi8vdG9vbHMuaWV0Zi5vcmcvaHRtbC9yZmM0ODgwI3NlY3Rpb24tNS44XG5cdFx0XHRcdFx0aWYgKGZpcnN0X3BhY2tldC50YWdUeXBlID09IDEwKSB7XG5cdFx0XHRcdFx0XHQvLyByZXNldCBtZXNzYWdlc1xuXHRcdFx0XHRcdFx0bWVzc2FnZXMubGVuZ3RoID0gMDtcblx0XHRcdFx0XHRcdC8vIGNvbnRpbnVlIHdpdGggbmV4dCBwYWNrZXRcblx0XHRcdFx0XHRcdG15cG9zICs9IGZpcnN0X3BhY2tldC5wYWNrZXRMZW5ndGggKyBmaXJzdF9wYWNrZXQuaGVhZGVyTGVuZ3RoO1xuXHRcdFx0XHRcdFx0bCAtPSAoZmlyc3RfcGFja2V0LnBhY2tldExlbmd0aCArIGZpcnN0X3BhY2tldC5oZWFkZXJMZW5ndGgpO1xuXHRcdFx0XHR9IGVsc2UgXG5cdFx0XHRcdFx0aWYgKGZpcnN0X3BhY2tldC50YWdUeXBlID09IDExKSB7XG5cdFx0XHRcdFx0Ly8gTGl0ZXJhbCBNZXNzYWdlIC0tIHdvcmsgaXMgYWxyZWFkeSBkb25lIGluIHJlYWRfcGFja2V0XG5cdFx0XHRcdFx0bXlwb3MgKz0gZmlyc3RfcGFja2V0LnBhY2tldExlbmd0aCArIGZpcnN0X3BhY2tldC5oZWFkZXJMZW5ndGg7XG5cdFx0XHRcdFx0bCAtPSAoZmlyc3RfcGFja2V0LnBhY2tldExlbmd0aCArIGZpcnN0X3BhY2tldC5oZWFkZXJMZW5ndGgpO1xuXHRcdFx0XHRcdHNpZ25hdHVyZVRleHQgPSBmaXJzdF9wYWNrZXQuZGF0YTtcblx0XHRcdFx0XHRtZXNzYWdlc1ttZXNzYWdlQ291bnRdLmRhdGEgPSBmaXJzdF9wYWNrZXQuZGF0YTtcblx0XHRcdFx0XHRtZXNzYWdlQ291bnQrKztcblx0XHRcdFx0fSBlbHNlIFxuXHRcdFx0XHRcdGlmIChmaXJzdF9wYWNrZXQudGFnVHlwZSA9PSAxOSkge1xuXHRcdFx0XHRcdC8vIE1vZGlmaWNhdGlvbiBEZXRlY3QgQ29kZVxuXHRcdFx0XHRcdFx0bXlwb3MgKz0gZmlyc3RfcGFja2V0LnBhY2tldExlbmd0aCArIGZpcnN0X3BhY2tldC5oZWFkZXJMZW5ndGg7XG5cdFx0XHRcdFx0XHRsIC09IChmaXJzdF9wYWNrZXQucGFja2V0TGVuZ3RoICsgZmlyc3RfcGFja2V0LmhlYWRlckxlbmd0aCk7XG5cdFx0XHRcdH1cblx0XHRcdH0gZWxzZSB7XG5cdFx0XHRcdHV0aWwucHJpbnRfZXJyb3IoJ25vIG1lc3NhZ2UgZm91bmQhJyk7XG5cdFx0XHRcdHJldHVybiBudWxsO1xuXHRcdFx0fVxuXHRcdH1cblx0XHRcblx0XHRyZXR1cm4gbWVzc2FnZXM7XG5cdH1cblx0XG5cdC8qKlxuXHQgKiBjcmVhdGVzIGEgYmluYXJ5IHN0cmluZyByZXByZXNlbnRhdGlvbiBvZiBhbiBlbmNyeXB0ZWQgYW5kIHNpZ25lZCBtZXNzYWdlLlxuXHQgKiBUaGUgbWVzc2FnZSB3aWxsIGJlIGVuY3J5cHRlZCB3aXRoIHRoZSBwdWJsaWMga2V5cyBzcGVjaWZpZWQgYW5kIHNpZ25lZFxuXHQgKiB3aXRoIHRoZSBzcGVjaWZpZWQgcHJpdmF0ZSBrZXkuXG5cdCAqIEBwYXJhbSB7T2JqZWN0fSBwcml2YXRla2V5IHtvYmo6IFtvcGVucGdwX21zZ19wcml2YXRla2V5XX0gUHJpdmF0ZSBrZXkgXG5cdCAqIHRvIGJlIHVzZWQgdG8gc2lnbiB0aGUgbWVzc2FnZVxuXHQgKiBAcGFyYW0ge09iamVjdFtdfSBwdWJsaWNrZXlzIEFuIGFycmFmIG9mIHtvYmo6IFtvcGVucGdwX21zZ19wdWJsaWNrZXldfVxuXHQgKiAtIHB1YmxpYyBrZXlzIHRvIGJlIHVzZWQgdG8gZW5jcnlwdCB0aGUgbWVzc2FnZSBcblx0ICogQHBhcmFtIHtTdHJpbmd9IG1lc3NhZ2V0ZXh0IG1lc3NhZ2UgdGV4dCB0byBlbmNyeXB0IGFuZCBzaWduXG5cdCAqIEByZXR1cm4ge1N0cmluZ30gYSBiaW5hcnkgc3RyaW5nIHJlcHJlc2VudGF0aW9uIG9mIHRoZSBtZXNzYWdlIHdoaWNoIFxuXHQgKiBjYW4gYmUgT3BlblBHUCBhcm1vcmVkXG5cdCAqL1xuXHRmdW5jdGlvbiB3cml0ZV9zaWduZWRfYW5kX2VuY3J5cHRlZF9tZXNzYWdlKHByaXZhdGVrZXksIHB1YmxpY2tleXMsIG1lc3NhZ2V0ZXh0KSB7XG5cdFx0dmFyIHJlc3VsdCA9IFwiXCI7XG5cdFx0dmFyIGxpdGVyYWwgPSBuZXcgb3BlbnBncF9wYWNrZXRfbGl0ZXJhbGRhdGEoKS53cml0ZV9wYWNrZXQobWVzc2FnZXRleHQucmVwbGFjZSgvXFxyXFxuL2csXCJcXG5cIikucmVwbGFjZSgvXFxuL2csXCJcXHJcXG5cIikpO1xuXHRcdHV0aWwucHJpbnRfZGVidWdfaGV4c3RyX2R1bXAoXCJsaXRlcmFsX3BhY2tldDogfFwiK2xpdGVyYWwrXCJ8XFxuXCIsbGl0ZXJhbCk7XG5cdFx0Zm9yICh2YXIgaSA9IDA7IGkgPCBwdWJsaWNrZXlzLmxlbmd0aDsgaSsrKSB7XG5cdFx0XHR2YXIgb25lcGFzc3NpZ25hdHVyZSA9IG5ldyBvcGVucGdwX3BhY2tldF9vbmVwYXNzc2lnbmF0dXJlKCk7XG5cdFx0XHR2YXIgb25lcGFzc3NpZ3N0ciA9IFwiXCI7XG5cdFx0XHRpZiAoaSA9PSAwKVxuXHRcdFx0XHRvbmVwYXNzc2lnc3RyID0gb25lcGFzc3NpZ25hdHVyZS53cml0ZV9wYWNrZXQoMSwgb3BlbnBncC5jb25maWcuY29uZmlnLnByZWZlcl9oYXNoX2FsZ29yaXRobSwgIHByaXZhdGVrZXksIGZhbHNlKTtcblx0XHRcdGVsc2Vcblx0XHRcdFx0b25lcGFzc3NpZ3N0ciA9IG9uZXBhc3NzaWduYXR1cmUud3JpdGVfcGFja2V0KDEsIG9wZW5wZ3AuY29uZmlnLmNvbmZpZy5wcmVmZXJfaGFzaF9hbGdvcml0aG0sICBwcml2YXRla2V5LCBmYWxzZSk7XG5cdFx0XHR1dGlsLnByaW50X2RlYnVnX2hleHN0cl9kdW1wKFwib25lcGFzc3NpZ3N0cjogfFwiK29uZXBhc3NzaWdzdHIrXCJ8XFxuXCIsb25lcGFzc3NpZ3N0cik7XG5cdFx0XHR2YXIgZGF0YXNpZ25hdHVyZSA9IG5ldyBvcGVucGdwX3BhY2tldF9zaWduYXR1cmUoKS53cml0ZV9tZXNzYWdlX3NpZ25hdHVyZSgxLCBtZXNzYWdldGV4dC5yZXBsYWNlKC9cXHJcXG4vZyxcIlxcblwiKS5yZXBsYWNlKC9cXG4vZyxcIlxcclxcblwiKSwgcHJpdmF0ZWtleSk7XG5cdFx0XHR1dGlsLnByaW50X2RlYnVnX2hleHN0cl9kdW1wKFwiZGF0YXNpZ25hdHVyZTogfFwiK2RhdGFzaWduYXR1cmUub3BlbnBncCtcInxcXG5cIixkYXRhc2lnbmF0dXJlLm9wZW5wZ3ApO1xuXHRcdFx0aWYgKGkgPT0gMCkge1xuXHRcdFx0XHRyZXN1bHQgPSBvbmVwYXNzc2lnc3RyK2xpdGVyYWwrZGF0YXNpZ25hdHVyZS5vcGVucGdwO1xuXHRcdFx0fSBlbHNlIHtcblx0XHRcdFx0cmVzdWx0ID0gb25lcGFzc3NpZ3N0cityZXN1bHQrZGF0YXNpZ25hdHVyZS5vcGVucGdwO1xuXHRcdFx0fVxuXHRcdH1cblx0XHRcblx0XHR1dGlsLnByaW50X2RlYnVnX2hleHN0cl9kdW1wKFwic2lnbmVkIHBhY2tldDogfFwiK3Jlc3VsdCtcInxcXG5cIixyZXN1bHQpO1xuXHRcdC8vIHNpZ25hdHVyZXMgZG9uZS4uIG5vdyBlbmNyeXB0aW9uXG5cdFx0dmFyIHNlc3Npb25rZXkgPSBvcGVucGdwX2NyeXB0b19nZW5lcmF0ZVNlc3Npb25LZXkob3BlbnBncC5jb25maWcuY29uZmlnLmVuY3J5cHRpb25fY2lwaGVyKTsgXG5cdFx0dmFyIHJlc3VsdDIgPSBcIlwiO1xuXHRcdFxuXHRcdC8vIGNyZWF0aW5nIHNlc3Npb24ga2V5cyBmb3IgZWFjaCByZWNpcGllbnRcblx0XHRmb3IgKHZhciBpID0gMDsgaSA8IHB1YmxpY2tleXMubGVuZ3RoOyBpKyspIHtcblx0XHRcdHZhciBwa2V5ID0gcHVibGlja2V5c1tpXS5nZXRFbmNyeXB0aW9uS2V5KCk7XG5cdFx0XHRpZiAocGtleSA9PSBudWxsKSB7XG5cdFx0XHRcdHV0aWwucHJpbnRfZXJyb3IoXCJubyBlbmNyeXB0aW9uIGtleSBmb3VuZCEgS2V5IGlzIGZvciBzaWduaW5nIG9ubHkuXCIpO1xuXHRcdFx0XHRyZXR1cm4gbnVsbDtcblx0XHRcdH1cblx0XHRcdHJlc3VsdDIgKz0gbmV3IG9wZW5wZ3BfcGFja2V0X2VuY3J5cHRlZHNlc3Npb25rZXkoKS5cblx0XHRcdFx0XHR3cml0ZV9wdWJfa2V5X3BhY2tldChcblx0XHRcdFx0XHRcdHBrZXkuZ2V0S2V5SWQoKSxcblx0XHRcdFx0XHRcdHBrZXkuTVBJcyxcblx0XHRcdFx0XHRcdHBrZXkucHVibGljS2V5QWxnb3JpdGhtLFxuXHRcdFx0XHRcdFx0b3BlbnBncC5jb25maWcuY29uZmlnLmVuY3J5cHRpb25fY2lwaGVyLFxuXHRcdFx0XHRcdFx0c2Vzc2lvbmtleSk7XG5cdFx0fVxuXHRcdGlmIChvcGVucGdwLmNvbmZpZy5jb25maWcuaW50ZWdyaXR5X3Byb3RlY3QpIHtcblx0XHRcdHJlc3VsdDIgKz0gbmV3IG9wZW5wZ3BfcGFja2V0X2VuY3J5cHRlZGludGVncml0eXByb3RlY3RlZGRhdGEoKS53cml0ZV9wYWNrZXQob3BlbnBncC5jb25maWcuY29uZmlnLmVuY3J5cHRpb25fY2lwaGVyLCBzZXNzaW9ua2V5LCByZXN1bHQpO1xuXHRcdH0gZWxzZSB7XG5cdFx0XHRyZXN1bHQyICs9IG5ldyBvcGVucGdwX3BhY2tldF9lbmNyeXB0ZWRkYXRhKCkud3JpdGVfcGFja2V0KG9wZW5wZ3AuY29uZmlnLmNvbmZpZy5lbmNyeXB0aW9uX2NpcGhlciwgc2Vzc2lvbmtleSwgcmVzdWx0KTtcblx0XHR9XG5cdFx0cmV0dXJuIG9wZW5wZ3BfZW5jb2RpbmdfYXJtb3IoMyxyZXN1bHQyLG51bGwsbnVsbCk7XG5cdH1cblx0LyoqXG5cdCAqIGNyZWF0ZXMgYSBiaW5hcnkgc3RyaW5nIHJlcHJlc2VudGF0aW9uIG9mIGFuIGVuY3J5cHRlZCBtZXNzYWdlLlxuXHQgKiBUaGUgbWVzc2FnZSB3aWxsIGJlIGVuY3J5cHRlZCB3aXRoIHRoZSBwdWJsaWMga2V5cyBzcGVjaWZpZWQgXG5cdCAqIEBwYXJhbSB7T2JqZWN0W119IHB1YmxpY2tleXMgQW4gYXJyYXkgb2Yge29iajogW29wZW5wZ3BfbXNnX3B1YmxpY2tleV19XG5cdCAqIC1wdWJsaWMga2V5cyB0byBiZSB1c2VkIHRvIGVuY3J5cHQgdGhlIG1lc3NhZ2UgXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBtZXNzYWdldGV4dCBtZXNzYWdlIHRleHQgdG8gZW5jcnlwdFxuXHQgKiBAcmV0dXJuIHtTdHJpbmd9IGEgYmluYXJ5IHN0cmluZyByZXByZXNlbnRhdGlvbiBvZiB0aGUgbWVzc2FnZVxuXHQgKiB3aGljaCBjYW4gYmUgT3BlblBHUCBhcm1vcmVkXG5cdCAqL1xuXHRmdW5jdGlvbiB3cml0ZV9lbmNyeXB0ZWRfbWVzc2FnZShwdWJsaWNrZXlzLCBtZXNzYWdldGV4dCkge1xuXHRcdHZhciByZXN1bHQgPSBcIlwiO1xuXHRcdHZhciBsaXRlcmFsID0gbmV3IG9wZW5wZ3BfcGFja2V0X2xpdGVyYWxkYXRhKCkud3JpdGVfcGFja2V0KG1lc3NhZ2V0ZXh0LnJlcGxhY2UoL1xcclxcbi9nLFwiXFxuXCIpLnJlcGxhY2UoL1xcbi9nLFwiXFxyXFxuXCIpKTtcblx0XHR1dGlsLnByaW50X2RlYnVnX2hleHN0cl9kdW1wKFwibGl0ZXJhbF9wYWNrZXQ6IHxcIitsaXRlcmFsK1wifFxcblwiLGxpdGVyYWwpO1xuXHRcdHJlc3VsdCA9IGxpdGVyYWw7XG5cdFx0XG5cdFx0Ly8gc2lnbmF0dXJlcyBkb25lLi4gbm93IGVuY3J5cHRpb25cblx0XHR2YXIgc2Vzc2lvbmtleSA9IG9wZW5wZ3BfY3J5cHRvX2dlbmVyYXRlU2Vzc2lvbktleShvcGVucGdwLmNvbmZpZy5jb25maWcuZW5jcnlwdGlvbl9jaXBoZXIpOyBcblx0XHR2YXIgcmVzdWx0MiA9IFwiXCI7XG5cdFx0XG5cdFx0Ly8gY3JlYXRpbmcgc2Vzc2lvbiBrZXlzIGZvciBlYWNoIHJlY2lwaWVudFxuXHRcdGZvciAodmFyIGkgPSAwOyBpIDwgcHVibGlja2V5cy5sZW5ndGg7IGkrKykge1xuXHRcdFx0dmFyIHBrZXkgPSBwdWJsaWNrZXlzW2ldLmdldEVuY3J5cHRpb25LZXkoKTtcblx0XHRcdGlmIChwa2V5ID09IG51bGwpIHtcblx0XHRcdFx0dXRpbC5wcmludF9lcnJvcihcIm5vIGVuY3J5cHRpb24ga2V5IGZvdW5kISBLZXkgaXMgZm9yIHNpZ25pbmcgb25seS5cIik7XG5cdFx0XHRcdHJldHVybiBudWxsO1xuXHRcdFx0fVxuXHRcdFx0cmVzdWx0MiArPSBuZXcgb3BlbnBncF9wYWNrZXRfZW5jcnlwdGVkc2Vzc2lvbmtleSgpLlxuXHRcdFx0XHRcdHdyaXRlX3B1Yl9rZXlfcGFja2V0KFxuXHRcdFx0XHRcdFx0cGtleS5nZXRLZXlJZCgpLFxuXHRcdFx0XHRcdFx0cGtleS5NUElzLFxuXHRcdFx0XHRcdFx0cGtleS5wdWJsaWNLZXlBbGdvcml0aG0sXG5cdFx0XHRcdFx0XHRvcGVucGdwLmNvbmZpZy5jb25maWcuZW5jcnlwdGlvbl9jaXBoZXIsXG5cdFx0XHRcdFx0XHRzZXNzaW9ua2V5KTtcblx0XHR9XG5cdFx0aWYgKG9wZW5wZ3AuY29uZmlnLmNvbmZpZy5pbnRlZ3JpdHlfcHJvdGVjdCkge1xuXHRcdFx0cmVzdWx0MiArPSBuZXcgb3BlbnBncF9wYWNrZXRfZW5jcnlwdGVkaW50ZWdyaXR5cHJvdGVjdGVkZGF0YSgpLndyaXRlX3BhY2tldChvcGVucGdwLmNvbmZpZy5jb25maWcuZW5jcnlwdGlvbl9jaXBoZXIsIHNlc3Npb25rZXksIHJlc3VsdCk7XG5cdFx0fSBlbHNlIHtcblx0XHRcdHJlc3VsdDIgKz0gbmV3IG9wZW5wZ3BfcGFja2V0X2VuY3J5cHRlZGRhdGEoKS53cml0ZV9wYWNrZXQob3BlbnBncC5jb25maWcuY29uZmlnLmVuY3J5cHRpb25fY2lwaGVyLCBzZXNzaW9ua2V5LCByZXN1bHQpO1xuXHRcdH1cblx0XHRyZXR1cm4gb3BlbnBncF9lbmNvZGluZ19hcm1vcigzLHJlc3VsdDIsbnVsbCxudWxsKTtcblx0fVxuXHRcblx0LyoqXG5cdCAqIGNyZWF0ZXMgYSBiaW5hcnkgc3RyaW5nIHJlcHJlc2VudGF0aW9uIGEgc2lnbmVkIG1lc3NhZ2UuXG5cdCAqIFRoZSBtZXNzYWdlIHdpbGwgYmUgc2lnbmVkIHdpdGggdGhlIHNwZWNpZmllZCBwcml2YXRlIGtleS5cblx0ICogQHBhcmFtIHtPYmplY3R9IHByaXZhdGVrZXkge29iajogW29wZW5wZ3BfbXNnX3ByaXZhdGVrZXldfVxuXHQgKiAtIHRoZSBwcml2YXRlIGtleSB0byBiZSB1c2VkIHRvIHNpZ24gdGhlIG1lc3NhZ2UgXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBtZXNzYWdldGV4dCBtZXNzYWdlIHRleHQgdG8gc2lnblxuXHQgKiBAcmV0dXJuIHtPYmplY3R9IHtPYmplY3Q6IHRleHQgW1N0cmluZ119LCBvcGVucGdwOiB7U3RyaW5nfSBhIGJpbmFyeVxuXHQgKiAgc3RyaW5nIHJlcHJlc2VudGF0aW9uIG9mIHRoZSBtZXNzYWdlIHdoaWNoIGNhbiBiZSBPcGVuUEdQXG5cdCAqICAgYXJtb3JlZChvcGVucGdwKSBhbmQgYSB0ZXh0IHJlcHJlc2VudGF0aW9uIG9mIHRoZSBtZXNzYWdlICh0ZXh0KS4gXG5cdCAqIFRoaXMgY2FuIGJlIGRpcmVjdGx5IHVzZWQgdG8gT3BlblBHUCBhcm1vciB0aGUgbWVzc2FnZVxuXHQgKi9cblx0ZnVuY3Rpb24gd3JpdGVfc2lnbmVkX21lc3NhZ2UocHJpdmF0ZWtleSwgbWVzc2FnZXRleHQpIHtcblx0XHR2YXIgc2lnID0gbmV3IG9wZW5wZ3BfcGFja2V0X3NpZ25hdHVyZSgpLndyaXRlX21lc3NhZ2Vfc2lnbmF0dXJlKDEsIG1lc3NhZ2V0ZXh0LnJlcGxhY2UoL1xcclxcbi9nLFwiXFxuXCIpLnJlcGxhY2UoL1xcbi8sXCJcXHJcXG5cIiksIHByaXZhdGVrZXkpO1xuXHRcdHZhciByZXN1bHQgPSB7dGV4dDogbWVzc2FnZXRleHQucmVwbGFjZSgvXFxyXFxuL2csXCJcXG5cIikucmVwbGFjZSgvXFxuLyxcIlxcclxcblwiKSwgb3BlbnBncDogc2lnLm9wZW5wZ3AsIGhhc2g6IHNpZy5oYXNofTtcblx0XHRyZXR1cm4gb3BlbnBncF9lbmNvZGluZ19hcm1vcigyLHJlc3VsdCwgbnVsbCwgbnVsbClcblx0fVxuXHRcblx0LyoqXG5cdCAqIGdlbmVyYXRlcyBhIG5ldyBrZXkgcGFpciBmb3Igb3BlbnBncC4gQmV0YSBzdGFnZS4gQ3VycmVudGx5IG9ubHkgXG5cdCAqIHN1cHBvcnRzIFJTQSBrZXlzLCBhbmQgbm8gc3Via2V5cy5cblx0ICogQHBhcmFtIHtJbnRlZ2VyfSBrZXlUeXBlIHRvIGluZGljYXRlIHdoYXQgdHlwZSBvZiBrZXkgdG8gbWFrZS4gXG5cdCAqIFJTQSBpcyAxLiBGb2xsb3dzIGFsZ29yaXRobXMgb3V0bGluZWQgaW4gT3BlblBHUC5cblx0ICogQHBhcmFtIHtJbnRlZ2VyfSBudW1CaXRzIG51bWJlciBvZiBiaXRzIGZvciB0aGUga2V5IGNyZWF0aW9uLiAoc2hvdWxkIFxuXHQgKiBiZSAxMDI0KywgZ2VuZXJhbGx5KVxuXHQgKiBAcGFyYW0ge1N0cmluZ30gdXNlcklkIGFzc3VtZXMgYWxyZWFkeSBpbiBmb3JtIG9mIFwiVXNlciBOYW1lIFxuXHQgKiA8dXNlcm5hbWVAZW1haWwuY29tPlwiXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBwYXNzcGhyYXNlIFRoZSBwYXNzcGhyYXNlIHVzZWQgdG8gZW5jcnlwdCB0aGUgcmVzdWx0aW5nIHByaXZhdGUga2V5XG5cdCAqIEByZXR1cm4ge09iamVjdH0ge3ByaXZhdGVLZXk6IFtvcGVucGdwX21zZ19wcml2YXRla2V5XSwgXG5cdCAqIHByaXZhdGVLZXlBcm1vcmVkOiBbc3RyaW5nXSwgcHVibGljS2V5QXJtb3JlZDogW3N0cmluZ119XG5cdCAqL1xuXHRmdW5jdGlvbiBnZW5lcmF0ZV9rZXlfcGFpcihrZXlUeXBlLCBudW1CaXRzLCB1c2VySWQsIHBhc3NwaHJhc2Upe1xuXHRcdHZhciB1c2VySWRQYWNrZXQgPSBuZXcgb3BlbnBncF9wYWNrZXRfdXNlcmlkKCk7XG5cdFx0dmFyIHVzZXJJZFN0cmluZyA9IHVzZXJJZFBhY2tldC53cml0ZV9wYWNrZXQodXNlcklkKTtcblx0XHRcblx0XHR2YXIga2V5UGFpciA9IG9wZW5wZ3BfY3J5cHRvX2dlbmVyYXRlS2V5UGFpcihrZXlUeXBlLG51bUJpdHMsIHBhc3NwaHJhc2UsIG9wZW5wZ3AuY29uZmlnLmNvbmZpZy5wcmVmZXJfaGFzaF9hbGdvcml0aG0sIDMpO1xuXHRcdHZhciBwcml2S2V5U3RyaW5nID0ga2V5UGFpci5wcml2YXRlS2V5O1xuXHRcdHZhciBwcml2S2V5UGFja2V0ID0gbmV3IG9wZW5wZ3BfcGFja2V0X2tleW1hdGVyaWFsKCkucmVhZF9wcml2X2tleShwcml2S2V5U3RyaW5nLnN0cmluZywzLHByaXZLZXlTdHJpbmcuc3RyaW5nLmxlbmd0aCk7XG5cdFx0aWYoIXByaXZLZXlQYWNrZXQuZGVjcnlwdFNlY3JldE1QSXMocGFzc3BocmFzZSkpXG5cdFx0ICAgIHV0aWwucHJpbnRfZXJyb3IoJ0lzc3VlIGNyZWF0aW5nIGtleS4gVW5hYmxlIHRvIHJlYWQgcmVzdWx0aW5nIHByaXZhdGUga2V5Jyk7XG5cdFx0dmFyIHByaXZLZXkgPSBuZXcgb3BlbnBncF9tc2dfcHJpdmF0ZWtleSgpO1xuXHRcdHByaXZLZXkucHJpdmF0ZUtleVBhY2tldCA9IHByaXZLZXlQYWNrZXQ7XG5cdFx0cHJpdktleS5nZXRQcmVmZXJyZWRTaWduYXR1cmVIYXNoQWxnb3JpdGhtID0gZnVuY3Rpb24oKXtyZXR1cm4gb3BlbnBncC5jb25maWcuY29uZmlnLnByZWZlcl9oYXNoX2FsZ29yaXRobX07Ly9uZWVkIHRvIG92ZXJyaWRlIHRoaXMgdG8gc29sdmUgY2F0Y2ggMjIgdG8gZ2VuZXJhdGUgc2lnbmF0dXJlLiA4IGlzIHZhbHVlIGZvciBTSEEyNTZcblx0XHRcblx0XHR2YXIgcHVibGljS2V5U3RyaW5nID0gcHJpdktleS5wcml2YXRlS2V5UGFja2V0LnB1YmxpY0tleS5kYXRhO1xuXHRcdHZhciBoYXNoRGF0YSA9IFN0cmluZy5mcm9tQ2hhckNvZGUoMHg5OSkrIFN0cmluZy5mcm9tQ2hhckNvZGUoKChwdWJsaWNLZXlTdHJpbmcubGVuZ3RoKSA+PiA4KSAmIDB4RkYpIFxuXHRcdFx0KyBTdHJpbmcuZnJvbUNoYXJDb2RlKChwdWJsaWNLZXlTdHJpbmcubGVuZ3RoKSAmIDB4RkYpICtwdWJsaWNLZXlTdHJpbmcrU3RyaW5nLmZyb21DaGFyQ29kZSgweEI0KSArXG5cdFx0XHRTdHJpbmcuZnJvbUNoYXJDb2RlKCh1c2VySWQubGVuZ3RoKSA+PiAyNCkgK1N0cmluZy5mcm9tQ2hhckNvZGUoKCh1c2VySWQubGVuZ3RoKSA+PiAxNikgJiAweEZGKSBcblx0XHRcdCsgU3RyaW5nLmZyb21DaGFyQ29kZSgoKHVzZXJJZC5sZW5ndGgpID4+IDgpICYgMHhGRikgKyBTdHJpbmcuZnJvbUNoYXJDb2RlKCh1c2VySWQubGVuZ3RoKSAmIDB4RkYpICsgdXNlcklkXG5cdFx0dmFyIHNpZ25hdHVyZSA9IG5ldyBvcGVucGdwX3BhY2tldF9zaWduYXR1cmUoKTtcblx0XHRzaWduYXR1cmUgPSBzaWduYXR1cmUud3JpdGVfbWVzc2FnZV9zaWduYXR1cmUoMTYsaGFzaERhdGEsIHByaXZLZXkpO1xuXHRcdHZhciBwdWJsaWNBcm1vcmVkID0gb3BlbnBncF9lbmNvZGluZ19hcm1vcig0LCBrZXlQYWlyLnB1YmxpY0tleS5zdHJpbmcgKyB1c2VySWRTdHJpbmcgKyBzaWduYXR1cmUub3BlbnBncCApO1xuXG5cdFx0dmFyIHByaXZBcm1vcmVkID0gb3BlbnBncF9lbmNvZGluZ19hcm1vcig1LHByaXZLZXlTdHJpbmcuc3RyaW5nK3VzZXJJZFN0cmluZytzaWduYXR1cmUub3BlbnBncCk7XG5cdFx0XG5cdFx0cmV0dXJuIHtwcml2YXRlS2V5IDogcHJpdktleSwgcHJpdmF0ZUtleUFybW9yZWQ6IHByaXZBcm1vcmVkLCBwdWJsaWNLZXlBcm1vcmVkOiBwdWJsaWNBcm1vcmVkfVxuXHR9XG5cdFxuXHR0aGlzLmdlbmVyYXRlX2tleV9wYWlyID0gZ2VuZXJhdGVfa2V5X3BhaXI7XG5cdHRoaXMud3JpdGVfc2lnbmVkX21lc3NhZ2UgPSB3cml0ZV9zaWduZWRfbWVzc2FnZTsgXG5cdHRoaXMud3JpdGVfc2lnbmVkX2FuZF9lbmNyeXB0ZWRfbWVzc2FnZSA9IHdyaXRlX3NpZ25lZF9hbmRfZW5jcnlwdGVkX21lc3NhZ2U7XG5cdHRoaXMud3JpdGVfZW5jcnlwdGVkX21lc3NhZ2UgPSB3cml0ZV9lbmNyeXB0ZWRfbWVzc2FnZTtcblx0dGhpcy5yZWFkX21lc3NhZ2UgPSByZWFkX21lc3NhZ2U7XG5cdHRoaXMucmVhZF9tZXNzYWdlc19kZWFybW9yZWQgPSByZWFkX21lc3NhZ2VzX2RlYXJtb3JlZDtcblx0dGhpcy5yZWFkX3B1YmxpY0tleSA9IHJlYWRfcHVibGljS2V5O1xuXHR0aGlzLnJlYWRfcHJpdmF0ZUtleSA9IHJlYWRfcHJpdmF0ZUtleTtcblx0dGhpcy5pbml0ID0gaW5pdDtcbn1cblxudmFyIG9wZW5wZ3AgPSBuZXcgX29wZW5wZ3AoKTtcblxuLyoqIFJGQzQ4ODAsIHNlY3Rpb24gOS4xIFxuICogQGVudW0ge0ludGVnZXJ9XG4gKi9cbm9wZW5wZ3AucHVibGlja2V5ID0ge1xuXHRyc2FfZW5jcnlwdF9zaWduOiAxLFxuXHRyc2FfZW5jcnlwdDogMixcblx0cnNhX3NpZ246IDMsXG5cdGVsZ2FtYWw6IDE2LFxuXHRkc2E6IDE3XG59O1xuXG4vKiogUkZDNDg4MCwgc2VjdGlvbiA5LjIgXG4gKiBAZW51bSB7SW50ZWdlcn1cbiAqL1xub3BlbnBncC5zeW1tZXRyaWMgPSB7XG5cdHBsYWludGV4dDogMCxcblx0LyoqIE5vdCBpbXBsZW1lbnRlZCEgKi9cblx0aWRlYTogMSxcblx0dHJpcGxlZGVzOiAyLFxuXHRjYXN0NTogMyxcblx0Ymxvd2Zpc2g6IDQsXG5cdGFlczEyODogNyxcblx0YWVzMTkyOiA4LFxuXHRhZXMyNTY6IDksXG5cdHR3b2Zpc2g6IDEwXG59O1xuXG4vKiogUkZDNDg4MCwgc2VjdGlvbiA5LjNcbiAqIEBlbnVtIHtJbnRlZ2VyfVxuICovXG5vcGVucGdwLmNvbXByZXNzaW9uID0ge1xuXHR1bmNvbXByZXNzZWQ6IDAsXG5cdC8qKiBSRkMxOTUxICovXG5cdHppcDogMSxcblx0LyoqIFJGQzE5NTAgKi9cblx0emxpYjogMixcblx0YnppcDI6IDNcbn07XG5cbi8qKiBSRkM0ODgwLCBzZWN0aW9uIDkuNFxuICogQGVudW0ge0ludGVnZXJ9XG4gKi9cbm9wZW5wZ3AuaGFzaCA9IHtcblx0bWQ1OiAxLFxuXHRzaGExOiAyLFxuXHRyaXBlbWQ6IDMsXG5cdHNoYTI1NjogOCxcblx0c2hhMzg0OiA5LFxuXHRzaGE1MTI6IDEwLFxuXHRzaGEyMjQ6IDExXG59O1xuXG5tb2R1bGUuZXhwb3J0cyA9IHtcblx0Y2lwaGVyOiB7XG5cdFx0YWVzOiByZXF1aXJlKCcuL2NpcGhlcnMvc3ltbWV0cmljL2Flcy5qcycpLFxuXHRcdGRlczogcmVxdWlyZSgnLi9jaXBoZXJzL3N5bW1ldHJpYy9kZXNzcmMuanMnKSxcblx0XHRjYXN0NTogcmVxdWlyZSgnLi9jaXBoZXJzL3N5bW1ldHJpYy9jYXN0NS5qcycpLFxuXHRcdHR3b2Zpc2g6IHJlcXVpcmUoJy4vY2lwaGVycy9zeW1tZXRyaWMvdHdvZmlzaC5qcycpLFxuXHRcdGJsb3dmaXNoOiByZXF1aXJlKCcuL2NpcGhlcnMvc3ltbWV0cmljL2Jsb3dmaXNoLmpzJylcblx0fSxcblx0aGFzaDoge1xuXHRcdG1kNTogcmVxdWlyZSgnLi9jaXBoZXJzL2hhc2gvbWQ1LmpzJyksXG5cdFx0c2hhOiByZXF1aXJlKCcuL2NpcGhlcnMvaGFzaC9zaGEuanMnKSxcblx0XHRyaXBlbWQ6IHJlcXVpcmUoJy4vY2lwaGVycy9oYXNoL3JpcGUtbWQuanMnKVxuXHR9LFxuXHR1dGlsOiByZXF1aXJlKCcuL3V0aWwvdXRpbC5qcycpXG59XG5cbiIsIlxuLyogUmlqbmRhZWwgKEFFUykgRW5jcnlwdGlvblxuICogQ29weXJpZ2h0IDIwMDUgSGVyYmVydCBIYW5ld2lua2VsLCB3d3cuaGFuZVdJTi5kZVxuICogdmVyc2lvbiAxLjEsIGNoZWNrIHd3dy5oYW5lV0lOLmRlIGZvciB0aGUgbGF0ZXN0IHZlcnNpb25cblxuICogVGhpcyBzb2Z0d2FyZSBpcyBwcm92aWRlZCBhcy1pcywgd2l0aG91dCBleHByZXNzIG9yIGltcGxpZWQgd2FycmFudHkuICBcbiAqIFBlcm1pc3Npb24gdG8gdXNlLCBjb3B5LCBtb2RpZnksIGRpc3RyaWJ1dGUgb3Igc2VsbCB0aGlzIHNvZnR3YXJlLCB3aXRoIG9yXG4gKiB3aXRob3V0IGZlZSwgZm9yIGFueSBwdXJwb3NlIGFuZCBieSBhbnkgaW5kaXZpZHVhbCBvciBvcmdhbml6YXRpb24sIGlzIGhlcmVieVxuICogZ3JhbnRlZCwgcHJvdmlkZWQgdGhhdCB0aGUgYWJvdmUgY29weXJpZ2h0IG5vdGljZSBhbmQgdGhpcyBwYXJhZ3JhcGggYXBwZWFyIFxuICogaW4gYWxsIGNvcGllcy4gRGlzdHJpYnV0aW9uIGFzIGEgcGFydCBvZiBhbiBhcHBsaWNhdGlvbiBvciBiaW5hcnkgbXVzdFxuICogaW5jbHVkZSB0aGUgYWJvdmUgY29weXJpZ2h0IG5vdGljZSBpbiB0aGUgZG9jdW1lbnRhdGlvbiBhbmQvb3Igb3RoZXJcbiAqIG1hdGVyaWFscyBwcm92aWRlZCB3aXRoIHRoZSBhcHBsaWNhdGlvbiBvciBkaXN0cmlidXRpb24uXG4gKi9cblxuLy8gVGhlIHJvdW5kIGNvbnN0YW50cyB1c2VkIGluIHN1YmtleSBleHBhbnNpb25cbnZhciBSY29uID0gWyBcbjB4MDEsIDB4MDIsIDB4MDQsIDB4MDgsIDB4MTAsIDB4MjAsIDB4NDAsIDB4ODAsIDB4MWIsIDB4MzYsIDB4NmMsIDB4ZDgsIFxuMHhhYiwgMHg0ZCwgMHg5YSwgMHgyZiwgMHg1ZSwgMHhiYywgMHg2MywgMHhjNiwgMHg5NywgMHgzNSwgMHg2YSwgMHhkNCwgXG4weGIzLCAweDdkLCAweGZhLCAweGVmLCAweGM1LCAweDkxIF07XG5cbi8vIFByZWNvbXB1dGVkIGxvb2t1cCB0YWJsZSBmb3IgdGhlIFNCb3hcbnZhciBTID0gW1xuIDk5LCAxMjQsIDExOSwgMTIzLCAyNDIsIDEwNywgMTExLCAxOTcsICA0OCwgICAxLCAxMDMsICA0MywgMjU0LCAyMTUsIDE3MSwgXG4xMTgsIDIwMiwgMTMwLCAyMDEsIDEyNSwgMjUwLCAgODksICA3MSwgMjQwLCAxNzMsIDIxMiwgMTYyLCAxNzUsIDE1NiwgMTY0LCBcbjExNCwgMTkyLCAxODMsIDI1MywgMTQ3LCAgMzgsICA1NCwgIDYzLCAyNDcsIDIwNCwgIDUyLCAxNjUsIDIyOSwgMjQxLCAxMTMsIFxuMjE2LCAgNDksICAyMSwgICA0LCAxOTksICAzNSwgMTk1LCAgMjQsIDE1MCwgICA1LCAxNTQsICAgNywgIDE4LCAxMjgsIDIyNiwgXG4yMzUsICAzOSwgMTc4LCAxMTcsICAgOSwgMTMxLCAgNDQsICAyNiwgIDI3LCAxMTAsICA5MCwgMTYwLCAgODIsICA1OSwgMjE0LCBcbjE3OSwgIDQxLCAyMjcsICA0NywgMTMyLCAgODMsIDIwOSwgICAwLCAyMzcsICAzMiwgMjUyLCAxNzcsICA5MSwgMTA2LCAyMDMsIFxuMTkwLCAgNTcsICA3NCwgIDc2LCAgODgsIDIwNywgMjA4LCAyMzksIDE3MCwgMjUxLCAgNjcsICA3NywgIDUxLCAxMzMsICA2OSwgXG4yNDksICAgMiwgMTI3LCAgODAsICA2MCwgMTU5LCAxNjgsICA4MSwgMTYzLCAgNjQsIDE0MywgMTQ2LCAxNTcsICA1NiwgMjQ1LCBcbjE4OCwgMTgyLCAyMTgsICAzMywgIDE2LCAyNTUsIDI0MywgMjEwLCAyMDUsICAxMiwgIDE5LCAyMzYsICA5NSwgMTUxLCAgNjgsICBcbjIzLCAgMTk2LCAxNjcsIDEyNiwgIDYxLCAxMDAsICA5MywgIDI1LCAxMTUsICA5NiwgMTI5LCAgNzksIDIyMCwgIDM0LCAgNDIsIFxuMTQ0LCAxMzYsICA3MCwgMjM4LCAxODQsICAyMCwgMjIyLCAgOTQsICAxMSwgMjE5LCAyMjQsICA1MCwgIDU4LCAgMTAsICA3MyxcbiAgNiwgIDM2LCAgOTIsIDE5NCwgMjExLCAxNzIsICA5OCwgMTQ1LCAxNDksIDIyOCwgMTIxLCAyMzEsIDIwMCwgIDU1LCAxMDksIFxuMTQxLCAyMTMsICA3OCwgMTY5LCAxMDgsICA4NiwgMjQ0LCAyMzQsIDEwMSwgMTIyLCAxNzQsICAgOCwgMTg2LCAxMjAsICAzNywgIFxuIDQ2LCAgMjgsIDE2NiwgMTgwLCAxOTgsIDIzMiwgMjIxLCAxMTYsICAzMSwgIDc1LCAxODksIDEzOSwgMTM4LCAxMTIsICA2MiwgXG4xODEsIDEwMiwgIDcyLCAgIDMsIDI0NiwgIDE0LCAgOTcsICA1MywgIDg3LCAxODUsIDEzNCwgMTkzLCAgMjksIDE1OCwgMjI1LFxuMjQ4LCAxNTIsICAxNywgMTA1LCAyMTcsIDE0MiwgMTQ4LCAxNTUsICAzMCwgMTM1LCAyMzMsIDIwNiwgIDg1LCAgNDAsIDIyMyxcbjE0MCwgMTYxLCAxMzcsICAxMywgMTkxLCAyMzAsICA2NiwgMTA0LCAgNjUsIDE1MywgIDQ1LCAgMTUsIDE3NiwgIDg0LCAxODcsICBcbiAyMiBdO1xuXG52YXIgVDEgPSBbXG4weGE1NjM2M2M2LCAweDg0N2M3Y2Y4LCAweDk5Nzc3N2VlLCAweDhkN2I3YmY2LFxuMHgwZGYyZjJmZiwgMHhiZDZiNmJkNiwgMHhiMTZmNmZkZSwgMHg1NGM1YzU5MSxcbjB4NTAzMDMwNjAsIDB4MDMwMTAxMDIsIDB4YTk2NzY3Y2UsIDB4N2QyYjJiNTYsXG4weDE5ZmVmZWU3LCAweDYyZDdkN2I1LCAweGU2YWJhYjRkLCAweDlhNzY3NmVjLFxuMHg0NWNhY2E4ZiwgMHg5ZDgyODIxZiwgMHg0MGM5Yzk4OSwgMHg4NzdkN2RmYSxcbjB4MTVmYWZhZWYsIDB4ZWI1OTU5YjIsIDB4Yzk0NzQ3OGUsIDB4MGJmMGYwZmIsXG4weGVjYWRhZDQxLCAweDY3ZDRkNGIzLCAweGZkYTJhMjVmLCAweGVhYWZhZjQ1LFxuMHhiZjljOWMyMywgMHhmN2E0YTQ1MywgMHg5NjcyNzJlNCwgMHg1YmMwYzA5YixcbjB4YzJiN2I3NzUsIDB4MWNmZGZkZTEsIDB4YWU5MzkzM2QsIDB4NmEyNjI2NGMsXG4weDVhMzYzNjZjLCAweDQxM2YzZjdlLCAweDAyZjdmN2Y1LCAweDRmY2NjYzgzLFxuMHg1YzM0MzQ2OCwgMHhmNGE1YTU1MSwgMHgzNGU1ZTVkMSwgMHgwOGYxZjFmOSxcbjB4OTM3MTcxZTIsIDB4NzNkOGQ4YWIsIDB4NTMzMTMxNjIsIDB4M2YxNTE1MmEsXG4weDBjMDQwNDA4LCAweDUyYzdjNzk1LCAweDY1MjMyMzQ2LCAweDVlYzNjMzlkLFxuMHgyODE4MTgzMCwgMHhhMTk2OTYzNywgMHgwZjA1MDUwYSwgMHhiNTlhOWEyZixcbjB4MDkwNzA3MGUsIDB4MzYxMjEyMjQsIDB4OWI4MDgwMWIsIDB4M2RlMmUyZGYsXG4weDI2ZWJlYmNkLCAweDY5MjcyNzRlLCAweGNkYjJiMjdmLCAweDlmNzU3NWVhLFxuMHgxYjA5MDkxMiwgMHg5ZTgzODMxZCwgMHg3NDJjMmM1OCwgMHgyZTFhMWEzNCxcbjB4MmQxYjFiMzYsIDB4YjI2ZTZlZGMsIDB4ZWU1YTVhYjQsIDB4ZmJhMGEwNWIsXG4weGY2NTI1MmE0LCAweDRkM2IzYjc2LCAweDYxZDZkNmI3LCAweGNlYjNiMzdkLFxuMHg3YjI5Mjk1MiwgMHgzZWUzZTNkZCwgMHg3MTJmMmY1ZSwgMHg5Nzg0ODQxMyxcbjB4ZjU1MzUzYTYsIDB4NjhkMWQxYjksIDB4MDAwMDAwMDAsIDB4MmNlZGVkYzEsXG4weDYwMjAyMDQwLCAweDFmZmNmY2UzLCAweGM4YjFiMTc5LCAweGVkNWI1YmI2LFxuMHhiZTZhNmFkNCwgMHg0NmNiY2I4ZCwgMHhkOWJlYmU2NywgMHg0YjM5Mzk3MixcbjB4ZGU0YTRhOTQsIDB4ZDQ0YzRjOTgsIDB4ZTg1ODU4YjAsIDB4NGFjZmNmODUsXG4weDZiZDBkMGJiLCAweDJhZWZlZmM1LCAweGU1YWFhYTRmLCAweDE2ZmJmYmVkLFxuMHhjNTQzNDM4NiwgMHhkNzRkNGQ5YSwgMHg1NTMzMzM2NiwgMHg5NDg1ODUxMSxcbjB4Y2Y0NTQ1OGEsIDB4MTBmOWY5ZTksIDB4MDYwMjAyMDQsIDB4ODE3ZjdmZmUsXG4weGYwNTA1MGEwLCAweDQ0M2MzYzc4LCAweGJhOWY5ZjI1LCAweGUzYThhODRiLFxuMHhmMzUxNTFhMiwgMHhmZWEzYTM1ZCwgMHhjMDQwNDA4MCwgMHg4YThmOGYwNSxcbjB4YWQ5MjkyM2YsIDB4YmM5ZDlkMjEsIDB4NDgzODM4NzAsIDB4MDRmNWY1ZjEsXG4weGRmYmNiYzYzLCAweGMxYjZiNjc3LCAweDc1ZGFkYWFmLCAweDYzMjEyMTQyLFxuMHgzMDEwMTAyMCwgMHgxYWZmZmZlNSwgMHgwZWYzZjNmZCwgMHg2ZGQyZDJiZixcbjB4NGNjZGNkODEsIDB4MTQwYzBjMTgsIDB4MzUxMzEzMjYsIDB4MmZlY2VjYzMsXG4weGUxNWY1ZmJlLCAweGEyOTc5NzM1LCAweGNjNDQ0NDg4LCAweDM5MTcxNzJlLFxuMHg1N2M0YzQ5MywgMHhmMmE3YTc1NSwgMHg4MjdlN2VmYywgMHg0NzNkM2Q3YSxcbjB4YWM2NDY0YzgsIDB4ZTc1ZDVkYmEsIDB4MmIxOTE5MzIsIDB4OTU3MzczZTYsXG4weGEwNjA2MGMwLCAweDk4ODE4MTE5LCAweGQxNGY0ZjllLCAweDdmZGNkY2EzLFxuMHg2NjIyMjI0NCwgMHg3ZTJhMmE1NCwgMHhhYjkwOTAzYiwgMHg4Mzg4ODgwYixcbjB4Y2E0NjQ2OGMsIDB4MjllZWVlYzcsIDB4ZDNiOGI4NmIsIDB4M2MxNDE0MjgsXG4weDc5ZGVkZWE3LCAweGUyNWU1ZWJjLCAweDFkMGIwYjE2LCAweDc2ZGJkYmFkLFxuMHgzYmUwZTBkYiwgMHg1NjMyMzI2NCwgMHg0ZTNhM2E3NCwgMHgxZTBhMGExNCxcbjB4ZGI0OTQ5OTIsIDB4MGEwNjA2MGMsIDB4NmMyNDI0NDgsIDB4ZTQ1YzVjYjgsXG4weDVkYzJjMjlmLCAweDZlZDNkM2JkLCAweGVmYWNhYzQzLCAweGE2NjI2MmM0LFxuMHhhODkxOTEzOSwgMHhhNDk1OTUzMSwgMHgzN2U0ZTRkMywgMHg4Yjc5NzlmMixcbjB4MzJlN2U3ZDUsIDB4NDNjOGM4OGIsIDB4NTkzNzM3NmUsIDB4Yjc2ZDZkZGEsXG4weDhjOGQ4ZDAxLCAweDY0ZDVkNWIxLCAweGQyNGU0ZTljLCAweGUwYTlhOTQ5LFxuMHhiNDZjNmNkOCwgMHhmYTU2NTZhYywgMHgwN2Y0ZjRmMywgMHgyNWVhZWFjZixcbjB4YWY2NTY1Y2EsIDB4OGU3YTdhZjQsIDB4ZTlhZWFlNDcsIDB4MTgwODA4MTAsXG4weGQ1YmFiYTZmLCAweDg4Nzg3OGYwLCAweDZmMjUyNTRhLCAweDcyMmUyZTVjLFxuMHgyNDFjMWMzOCwgMHhmMWE2YTY1NywgMHhjN2I0YjQ3MywgMHg1MWM2YzY5NyxcbjB4MjNlOGU4Y2IsIDB4N2NkZGRkYTEsIDB4OWM3NDc0ZTgsIDB4MjExZjFmM2UsXG4weGRkNGI0Yjk2LCAweGRjYmRiZDYxLCAweDg2OGI4YjBkLCAweDg1OGE4YTBmLFxuMHg5MDcwNzBlMCwgMHg0MjNlM2U3YywgMHhjNGI1YjU3MSwgMHhhYTY2NjZjYyxcbjB4ZDg0ODQ4OTAsIDB4MDUwMzAzMDYsIDB4MDFmNmY2ZjcsIDB4MTIwZTBlMWMsXG4weGEzNjE2MWMyLCAweDVmMzUzNTZhLCAweGY5NTc1N2FlLCAweGQwYjliOTY5LFxuMHg5MTg2ODYxNywgMHg1OGMxYzE5OSwgMHgyNzFkMWQzYSwgMHhiOTllOWUyNyxcbjB4MzhlMWUxZDksIDB4MTNmOGY4ZWIsIDB4YjM5ODk4MmIsIDB4MzMxMTExMjIsXG4weGJiNjk2OWQyLCAweDcwZDlkOWE5LCAweDg5OGU4ZTA3LCAweGE3OTQ5NDMzLFxuMHhiNjliOWIyZCwgMHgyMjFlMWUzYywgMHg5Mjg3ODcxNSwgMHgyMGU5ZTljOSxcbjB4NDljZWNlODcsIDB4ZmY1NTU1YWEsIDB4NzgyODI4NTAsIDB4N2FkZmRmYTUsXG4weDhmOGM4YzAzLCAweGY4YTFhMTU5LCAweDgwODk4OTA5LCAweDE3MGQwZDFhLFxuMHhkYWJmYmY2NSwgMHgzMWU2ZTZkNywgMHhjNjQyNDI4NCwgMHhiODY4NjhkMCxcbjB4YzM0MTQxODIsIDB4YjA5OTk5MjksIDB4NzcyZDJkNWEsIDB4MTEwZjBmMWUsXG4weGNiYjBiMDdiLCAweGZjNTQ1NGE4LCAweGQ2YmJiYjZkLCAweDNhMTYxNjJjIF07XG5cbnZhciBUMiA9IFtcbjB4NjM2M2M2YTUsIDB4N2M3Y2Y4ODQsIDB4Nzc3N2VlOTksIDB4N2I3YmY2OGQsXG4weGYyZjJmZjBkLCAweDZiNmJkNmJkLCAweDZmNmZkZWIxLCAweGM1YzU5MTU0LFxuMHgzMDMwNjA1MCwgMHgwMTAxMDIwMywgMHg2NzY3Y2VhOSwgMHgyYjJiNTY3ZCxcbjB4ZmVmZWU3MTksIDB4ZDdkN2I1NjIsIDB4YWJhYjRkZTYsIDB4NzY3NmVjOWEsXG4weGNhY2E4ZjQ1LCAweDgyODIxZjlkLCAweGM5Yzk4OTQwLCAweDdkN2RmYTg3LFxuMHhmYWZhZWYxNSwgMHg1OTU5YjJlYiwgMHg0NzQ3OGVjOSwgMHhmMGYwZmIwYixcbjB4YWRhZDQxZWMsIDB4ZDRkNGIzNjcsIDB4YTJhMjVmZmQsIDB4YWZhZjQ1ZWEsXG4weDljOWMyM2JmLCAweGE0YTQ1M2Y3LCAweDcyNzJlNDk2LCAweGMwYzA5YjViLFxuMHhiN2I3NzVjMiwgMHhmZGZkZTExYywgMHg5MzkzM2RhZSwgMHgyNjI2NGM2YSxcbjB4MzYzNjZjNWEsIDB4M2YzZjdlNDEsIDB4ZjdmN2Y1MDIsIDB4Y2NjYzgzNGYsXG4weDM0MzQ2ODVjLCAweGE1YTU1MWY0LCAweGU1ZTVkMTM0LCAweGYxZjFmOTA4LFxuMHg3MTcxZTI5MywgMHhkOGQ4YWI3MywgMHgzMTMxNjI1MywgMHgxNTE1MmEzZixcbjB4MDQwNDA4MGMsIDB4YzdjNzk1NTIsIDB4MjMyMzQ2NjUsIDB4YzNjMzlkNWUsXG4weDE4MTgzMDI4LCAweDk2OTYzN2ExLCAweDA1MDUwYTBmLCAweDlhOWEyZmI1LFxuMHgwNzA3MGUwOSwgMHgxMjEyMjQzNiwgMHg4MDgwMWI5YiwgMHhlMmUyZGYzZCxcbjB4ZWJlYmNkMjYsIDB4MjcyNzRlNjksIDB4YjJiMjdmY2QsIDB4NzU3NWVhOWYsXG4weDA5MDkxMjFiLCAweDgzODMxZDllLCAweDJjMmM1ODc0LCAweDFhMWEzNDJlLFxuMHgxYjFiMzYyZCwgMHg2ZTZlZGNiMiwgMHg1YTVhYjRlZSwgMHhhMGEwNWJmYixcbjB4NTI1MmE0ZjYsIDB4M2IzYjc2NGQsIDB4ZDZkNmI3NjEsIDB4YjNiMzdkY2UsXG4weDI5Mjk1MjdiLCAweGUzZTNkZDNlLCAweDJmMmY1ZTcxLCAweDg0ODQxMzk3LFxuMHg1MzUzYTZmNSwgMHhkMWQxYjk2OCwgMHgwMDAwMDAwMCwgMHhlZGVkYzEyYyxcbjB4MjAyMDQwNjAsIDB4ZmNmY2UzMWYsIDB4YjFiMTc5YzgsIDB4NWI1YmI2ZWQsXG4weDZhNmFkNGJlLCAweGNiY2I4ZDQ2LCAweGJlYmU2N2Q5LCAweDM5Mzk3MjRiLFxuMHg0YTRhOTRkZSwgMHg0YzRjOThkNCwgMHg1ODU4YjBlOCwgMHhjZmNmODU0YSxcbjB4ZDBkMGJiNmIsIDB4ZWZlZmM1MmEsIDB4YWFhYTRmZTUsIDB4ZmJmYmVkMTYsXG4weDQzNDM4NmM1LCAweDRkNGQ5YWQ3LCAweDMzMzM2NjU1LCAweDg1ODUxMTk0LFxuMHg0NTQ1OGFjZiwgMHhmOWY5ZTkxMCwgMHgwMjAyMDQwNiwgMHg3ZjdmZmU4MSxcbjB4NTA1MGEwZjAsIDB4M2MzYzc4NDQsIDB4OWY5ZjI1YmEsIDB4YThhODRiZTMsXG4weDUxNTFhMmYzLCAweGEzYTM1ZGZlLCAweDQwNDA4MGMwLCAweDhmOGYwNThhLFxuMHg5MjkyM2ZhZCwgMHg5ZDlkMjFiYywgMHgzODM4NzA0OCwgMHhmNWY1ZjEwNCxcbjB4YmNiYzYzZGYsIDB4YjZiNjc3YzEsIDB4ZGFkYWFmNzUsIDB4MjEyMTQyNjMsXG4weDEwMTAyMDMwLCAweGZmZmZlNTFhLCAweGYzZjNmZDBlLCAweGQyZDJiZjZkLFxuMHhjZGNkODE0YywgMHgwYzBjMTgxNCwgMHgxMzEzMjYzNSwgMHhlY2VjYzMyZixcbjB4NWY1ZmJlZTEsIDB4OTc5NzM1YTIsIDB4NDQ0NDg4Y2MsIDB4MTcxNzJlMzksXG4weGM0YzQ5MzU3LCAweGE3YTc1NWYyLCAweDdlN2VmYzgyLCAweDNkM2Q3YTQ3LFxuMHg2NDY0YzhhYywgMHg1ZDVkYmFlNywgMHgxOTE5MzIyYiwgMHg3MzczZTY5NSxcbjB4NjA2MGMwYTAsIDB4ODE4MTE5OTgsIDB4NGY0ZjllZDEsIDB4ZGNkY2EzN2YsXG4weDIyMjI0NDY2LCAweDJhMmE1NDdlLCAweDkwOTAzYmFiLCAweDg4ODgwYjgzLFxuMHg0NjQ2OGNjYSwgMHhlZWVlYzcyOSwgMHhiOGI4NmJkMywgMHgxNDE0MjgzYyxcbjB4ZGVkZWE3NzksIDB4NWU1ZWJjZTIsIDB4MGIwYjE2MWQsIDB4ZGJkYmFkNzYsXG4weGUwZTBkYjNiLCAweDMyMzI2NDU2LCAweDNhM2E3NDRlLCAweDBhMGExNDFlLFxuMHg0OTQ5OTJkYiwgMHgwNjA2MGMwYSwgMHgyNDI0NDg2YywgMHg1YzVjYjhlNCxcbjB4YzJjMjlmNWQsIDB4ZDNkM2JkNmUsIDB4YWNhYzQzZWYsIDB4NjI2MmM0YTYsXG4weDkxOTEzOWE4LCAweDk1OTUzMWE0LCAweGU0ZTRkMzM3LCAweDc5NzlmMjhiLFxuMHhlN2U3ZDUzMiwgMHhjOGM4OGI0MywgMHgzNzM3NmU1OSwgMHg2ZDZkZGFiNyxcbjB4OGQ4ZDAxOGMsIDB4ZDVkNWIxNjQsIDB4NGU0ZTljZDIsIDB4YTlhOTQ5ZTAsXG4weDZjNmNkOGI0LCAweDU2NTZhY2ZhLCAweGY0ZjRmMzA3LCAweGVhZWFjZjI1LFxuMHg2NTY1Y2FhZiwgMHg3YTdhZjQ4ZSwgMHhhZWFlNDdlOSwgMHgwODA4MTAxOCxcbjB4YmFiYTZmZDUsIDB4Nzg3OGYwODgsIDB4MjUyNTRhNmYsIDB4MmUyZTVjNzIsXG4weDFjMWMzODI0LCAweGE2YTY1N2YxLCAweGI0YjQ3M2M3LCAweGM2YzY5NzUxLFxuMHhlOGU4Y2IyMywgMHhkZGRkYTE3YywgMHg3NDc0ZTg5YywgMHgxZjFmM2UyMSxcbjB4NGI0Yjk2ZGQsIDB4YmRiZDYxZGMsIDB4OGI4YjBkODYsIDB4OGE4YTBmODUsXG4weDcwNzBlMDkwLCAweDNlM2U3YzQyLCAweGI1YjU3MWM0LCAweDY2NjZjY2FhLFxuMHg0ODQ4OTBkOCwgMHgwMzAzMDYwNSwgMHhmNmY2ZjcwMSwgMHgwZTBlMWMxMixcbjB4NjE2MWMyYTMsIDB4MzUzNTZhNWYsIDB4NTc1N2FlZjksIDB4YjliOTY5ZDAsXG4weDg2ODYxNzkxLCAweGMxYzE5OTU4LCAweDFkMWQzYTI3LCAweDllOWUyN2I5LFxuMHhlMWUxZDkzOCwgMHhmOGY4ZWIxMywgMHg5ODk4MmJiMywgMHgxMTExMjIzMyxcbjB4Njk2OWQyYmIsIDB4ZDlkOWE5NzAsIDB4OGU4ZTA3ODksIDB4OTQ5NDMzYTcsXG4weDliOWIyZGI2LCAweDFlMWUzYzIyLCAweDg3ODcxNTkyLCAweGU5ZTljOTIwLFxuMHhjZWNlODc0OSwgMHg1NTU1YWFmZiwgMHgyODI4NTA3OCwgMHhkZmRmYTU3YSxcbjB4OGM4YzAzOGYsIDB4YTFhMTU5ZjgsIDB4ODk4OTA5ODAsIDB4MGQwZDFhMTcsXG4weGJmYmY2NWRhLCAweGU2ZTZkNzMxLCAweDQyNDI4NGM2LCAweDY4NjhkMGI4LFxuMHg0MTQxODJjMywgMHg5OTk5MjliMCwgMHgyZDJkNWE3NywgMHgwZjBmMWUxMSxcbjB4YjBiMDdiY2IsIDB4NTQ1NGE4ZmMsIDB4YmJiYjZkZDYsIDB4MTYxNjJjM2EgXTtcblxudmFyIFQzID0gW1xuMHg2M2M2YTU2MywgMHg3Y2Y4ODQ3YywgMHg3N2VlOTk3NywgMHg3YmY2OGQ3YixcbjB4ZjJmZjBkZjIsIDB4NmJkNmJkNmIsIDB4NmZkZWIxNmYsIDB4YzU5MTU0YzUsXG4weDMwNjA1MDMwLCAweDAxMDIwMzAxLCAweDY3Y2VhOTY3LCAweDJiNTY3ZDJiLFxuMHhmZWU3MTlmZSwgMHhkN2I1NjJkNywgMHhhYjRkZTZhYiwgMHg3NmVjOWE3NixcbjB4Y2E4ZjQ1Y2EsIDB4ODIxZjlkODIsIDB4Yzk4OTQwYzksIDB4N2RmYTg3N2QsXG4weGZhZWYxNWZhLCAweDU5YjJlYjU5LCAweDQ3OGVjOTQ3LCAweGYwZmIwYmYwLFxuMHhhZDQxZWNhZCwgMHhkNGIzNjdkNCwgMHhhMjVmZmRhMiwgMHhhZjQ1ZWFhZixcbjB4OWMyM2JmOWMsIDB4YTQ1M2Y3YTQsIDB4NzJlNDk2NzIsIDB4YzA5YjViYzAsXG4weGI3NzVjMmI3LCAweGZkZTExY2ZkLCAweDkzM2RhZTkzLCAweDI2NGM2YTI2LFxuMHgzNjZjNWEzNiwgMHgzZjdlNDEzZiwgMHhmN2Y1MDJmNywgMHhjYzgzNGZjYyxcbjB4MzQ2ODVjMzQsIDB4YTU1MWY0YTUsIDB4ZTVkMTM0ZTUsIDB4ZjFmOTA4ZjEsXG4weDcxZTI5MzcxLCAweGQ4YWI3M2Q4LCAweDMxNjI1MzMxLCAweDE1MmEzZjE1LFxuMHgwNDA4MGMwNCwgMHhjNzk1NTJjNywgMHgyMzQ2NjUyMywgMHhjMzlkNWVjMyxcbjB4MTgzMDI4MTgsIDB4OTYzN2ExOTYsIDB4MDUwYTBmMDUsIDB4OWEyZmI1OWEsXG4weDA3MGUwOTA3LCAweDEyMjQzNjEyLCAweDgwMWI5YjgwLCAweGUyZGYzZGUyLFxuMHhlYmNkMjZlYiwgMHgyNzRlNjkyNywgMHhiMjdmY2RiMiwgMHg3NWVhOWY3NSxcbjB4MDkxMjFiMDksIDB4ODMxZDllODMsIDB4MmM1ODc0MmMsIDB4MWEzNDJlMWEsXG4weDFiMzYyZDFiLCAweDZlZGNiMjZlLCAweDVhYjRlZTVhLCAweGEwNWJmYmEwLFxuMHg1MmE0ZjY1MiwgMHgzYjc2NGQzYiwgMHhkNmI3NjFkNiwgMHhiMzdkY2ViMyxcbjB4Mjk1MjdiMjksIDB4ZTNkZDNlZTMsIDB4MmY1ZTcxMmYsIDB4ODQxMzk3ODQsXG4weDUzYTZmNTUzLCAweGQxYjk2OGQxLCAweDAwMDAwMDAwLCAweGVkYzEyY2VkLFxuMHgyMDQwNjAyMCwgMHhmY2UzMWZmYywgMHhiMTc5YzhiMSwgMHg1YmI2ZWQ1YixcbjB4NmFkNGJlNmEsIDB4Y2I4ZDQ2Y2IsIDB4YmU2N2Q5YmUsIDB4Mzk3MjRiMzksXG4weDRhOTRkZTRhLCAweDRjOThkNDRjLCAweDU4YjBlODU4LCAweGNmODU0YWNmLFxuMHhkMGJiNmJkMCwgMHhlZmM1MmFlZiwgMHhhYTRmZTVhYSwgMHhmYmVkMTZmYixcbjB4NDM4NmM1NDMsIDB4NGQ5YWQ3NGQsIDB4MzM2NjU1MzMsIDB4ODUxMTk0ODUsXG4weDQ1OGFjZjQ1LCAweGY5ZTkxMGY5LCAweDAyMDQwNjAyLCAweDdmZmU4MTdmLFxuMHg1MGEwZjA1MCwgMHgzYzc4NDQzYywgMHg5ZjI1YmE5ZiwgMHhhODRiZTNhOCxcbjB4NTFhMmYzNTEsIDB4YTM1ZGZlYTMsIDB4NDA4MGMwNDAsIDB4OGYwNThhOGYsXG4weDkyM2ZhZDkyLCAweDlkMjFiYzlkLCAweDM4NzA0ODM4LCAweGY1ZjEwNGY1LFxuMHhiYzYzZGZiYywgMHhiNjc3YzFiNiwgMHhkYWFmNzVkYSwgMHgyMTQyNjMyMSxcbjB4MTAyMDMwMTAsIDB4ZmZlNTFhZmYsIDB4ZjNmZDBlZjMsIDB4ZDJiZjZkZDIsXG4weGNkODE0Y2NkLCAweDBjMTgxNDBjLCAweDEzMjYzNTEzLCAweGVjYzMyZmVjLFxuMHg1ZmJlZTE1ZiwgMHg5NzM1YTI5NywgMHg0NDg4Y2M0NCwgMHgxNzJlMzkxNyxcbjB4YzQ5MzU3YzQsIDB4YTc1NWYyYTcsIDB4N2VmYzgyN2UsIDB4M2Q3YTQ3M2QsXG4weDY0YzhhYzY0LCAweDVkYmFlNzVkLCAweDE5MzIyYjE5LCAweDczZTY5NTczLFxuMHg2MGMwYTA2MCwgMHg4MTE5OTg4MSwgMHg0ZjllZDE0ZiwgMHhkY2EzN2ZkYyxcbjB4MjI0NDY2MjIsIDB4MmE1NDdlMmEsIDB4OTAzYmFiOTAsIDB4ODgwYjgzODgsXG4weDQ2OGNjYTQ2LCAweGVlYzcyOWVlLCAweGI4NmJkM2I4LCAweDE0MjgzYzE0LFxuMHhkZWE3NzlkZSwgMHg1ZWJjZTI1ZSwgMHgwYjE2MWQwYiwgMHhkYmFkNzZkYixcbjB4ZTBkYjNiZTAsIDB4MzI2NDU2MzIsIDB4M2E3NDRlM2EsIDB4MGExNDFlMGEsXG4weDQ5OTJkYjQ5LCAweDA2MGMwYTA2LCAweDI0NDg2YzI0LCAweDVjYjhlNDVjLFxuMHhjMjlmNWRjMiwgMHhkM2JkNmVkMywgMHhhYzQzZWZhYywgMHg2MmM0YTY2MixcbjB4OTEzOWE4OTEsIDB4OTUzMWE0OTUsIDB4ZTRkMzM3ZTQsIDB4NzlmMjhiNzksXG4weGU3ZDUzMmU3LCAweGM4OGI0M2M4LCAweDM3NmU1OTM3LCAweDZkZGFiNzZkLFxuMHg4ZDAxOGM4ZCwgMHhkNWIxNjRkNSwgMHg0ZTljZDI0ZSwgMHhhOTQ5ZTBhOSxcbjB4NmNkOGI0NmMsIDB4NTZhY2ZhNTYsIDB4ZjRmMzA3ZjQsIDB4ZWFjZjI1ZWEsXG4weDY1Y2FhZjY1LCAweDdhZjQ4ZTdhLCAweGFlNDdlOWFlLCAweDA4MTAxODA4LFxuMHhiYTZmZDViYSwgMHg3OGYwODg3OCwgMHgyNTRhNmYyNSwgMHgyZTVjNzIyZSxcbjB4MWMzODI0MWMsIDB4YTY1N2YxYTYsIDB4YjQ3M2M3YjQsIDB4YzY5NzUxYzYsXG4weGU4Y2IyM2U4LCAweGRkYTE3Y2RkLCAweDc0ZTg5Yzc0LCAweDFmM2UyMTFmLFxuMHg0Yjk2ZGQ0YiwgMHhiZDYxZGNiZCwgMHg4YjBkODY4YiwgMHg4YTBmODU4YSxcbjB4NzBlMDkwNzAsIDB4M2U3YzQyM2UsIDB4YjU3MWM0YjUsIDB4NjZjY2FhNjYsXG4weDQ4OTBkODQ4LCAweDAzMDYwNTAzLCAweGY2ZjcwMWY2LCAweDBlMWMxMjBlLFxuMHg2MWMyYTM2MSwgMHgzNTZhNWYzNSwgMHg1N2FlZjk1NywgMHhiOTY5ZDBiOSxcbjB4ODYxNzkxODYsIDB4YzE5OTU4YzEsIDB4MWQzYTI3MWQsIDB4OWUyN2I5OWUsXG4weGUxZDkzOGUxLCAweGY4ZWIxM2Y4LCAweDk4MmJiMzk4LCAweDExMjIzMzExLFxuMHg2OWQyYmI2OSwgMHhkOWE5NzBkOSwgMHg4ZTA3ODk4ZSwgMHg5NDMzYTc5NCxcbjB4OWIyZGI2OWIsIDB4MWUzYzIyMWUsIDB4ODcxNTkyODcsIDB4ZTljOTIwZTksXG4weGNlODc0OWNlLCAweDU1YWFmZjU1LCAweDI4NTA3ODI4LCAweGRmYTU3YWRmLFxuMHg4YzAzOGY4YywgMHhhMTU5ZjhhMSwgMHg4OTA5ODA4OSwgMHgwZDFhMTcwZCxcbjB4YmY2NWRhYmYsIDB4ZTZkNzMxZTYsIDB4NDI4NGM2NDIsIDB4NjhkMGI4NjgsXG4weDQxODJjMzQxLCAweDk5MjliMDk5LCAweDJkNWE3NzJkLCAweDBmMWUxMTBmLFxuMHhiMDdiY2JiMCwgMHg1NGE4ZmM1NCwgMHhiYjZkZDZiYiwgMHgxNjJjM2ExNiBdO1xuXG52YXIgVDQgPSBbXG4weGM2YTU2MzYzLCAweGY4ODQ3YzdjLCAweGVlOTk3Nzc3LCAweGY2OGQ3YjdiLFxuMHhmZjBkZjJmMiwgMHhkNmJkNmI2YiwgMHhkZWIxNmY2ZiwgMHg5MTU0YzVjNSxcbjB4NjA1MDMwMzAsIDB4MDIwMzAxMDEsIDB4Y2VhOTY3NjcsIDB4NTY3ZDJiMmIsXG4weGU3MTlmZWZlLCAweGI1NjJkN2Q3LCAweDRkZTZhYmFiLCAweGVjOWE3Njc2LFxuMHg4ZjQ1Y2FjYSwgMHgxZjlkODI4MiwgMHg4OTQwYzljOSwgMHhmYTg3N2Q3ZCxcbjB4ZWYxNWZhZmEsIDB4YjJlYjU5NTksIDB4OGVjOTQ3NDcsIDB4ZmIwYmYwZjAsXG4weDQxZWNhZGFkLCAweGIzNjdkNGQ0LCAweDVmZmRhMmEyLCAweDQ1ZWFhZmFmLFxuMHgyM2JmOWM5YywgMHg1M2Y3YTRhNCwgMHhlNDk2NzI3MiwgMHg5YjViYzBjMCxcbjB4NzVjMmI3YjcsIDB4ZTExY2ZkZmQsIDB4M2RhZTkzOTMsIDB4NGM2YTI2MjYsXG4weDZjNWEzNjM2LCAweDdlNDEzZjNmLCAweGY1MDJmN2Y3LCAweDgzNGZjY2NjLFxuMHg2ODVjMzQzNCwgMHg1MWY0YTVhNSwgMHhkMTM0ZTVlNSwgMHhmOTA4ZjFmMSxcbjB4ZTI5MzcxNzEsIDB4YWI3M2Q4ZDgsIDB4NjI1MzMxMzEsIDB4MmEzZjE1MTUsXG4weDA4MGMwNDA0LCAweDk1NTJjN2M3LCAweDQ2NjUyMzIzLCAweDlkNWVjM2MzLFxuMHgzMDI4MTgxOCwgMHgzN2ExOTY5NiwgMHgwYTBmMDUwNSwgMHgyZmI1OWE5YSxcbjB4MGUwOTA3MDcsIDB4MjQzNjEyMTIsIDB4MWI5YjgwODAsIDB4ZGYzZGUyZTIsXG4weGNkMjZlYmViLCAweDRlNjkyNzI3LCAweDdmY2RiMmIyLCAweGVhOWY3NTc1LFxuMHgxMjFiMDkwOSwgMHgxZDllODM4MywgMHg1ODc0MmMyYywgMHgzNDJlMWExYSxcbjB4MzYyZDFiMWIsIDB4ZGNiMjZlNmUsIDB4YjRlZTVhNWEsIDB4NWJmYmEwYTAsXG4weGE0ZjY1MjUyLCAweDc2NGQzYjNiLCAweGI3NjFkNmQ2LCAweDdkY2ViM2IzLFxuMHg1MjdiMjkyOSwgMHhkZDNlZTNlMywgMHg1ZTcxMmYyZiwgMHgxMzk3ODQ4NCxcbjB4YTZmNTUzNTMsIDB4Yjk2OGQxZDEsIDB4MDAwMDAwMDAsIDB4YzEyY2VkZWQsXG4weDQwNjAyMDIwLCAweGUzMWZmY2ZjLCAweDc5YzhiMWIxLCAweGI2ZWQ1YjViLFxuMHhkNGJlNmE2YSwgMHg4ZDQ2Y2JjYiwgMHg2N2Q5YmViZSwgMHg3MjRiMzkzOSxcbjB4OTRkZTRhNGEsIDB4OThkNDRjNGMsIDB4YjBlODU4NTgsIDB4ODU0YWNmY2YsXG4weGJiNmJkMGQwLCAweGM1MmFlZmVmLCAweDRmZTVhYWFhLCAweGVkMTZmYmZiLFxuMHg4NmM1NDM0MywgMHg5YWQ3NGQ0ZCwgMHg2NjU1MzMzMywgMHgxMTk0ODU4NSxcbjB4OGFjZjQ1NDUsIDB4ZTkxMGY5ZjksIDB4MDQwNjAyMDIsIDB4ZmU4MTdmN2YsXG4weGEwZjA1MDUwLCAweDc4NDQzYzNjLCAweDI1YmE5ZjlmLCAweDRiZTNhOGE4LFxuMHhhMmYzNTE1MSwgMHg1ZGZlYTNhMywgMHg4MGMwNDA0MCwgMHgwNThhOGY4ZixcbjB4M2ZhZDkyOTIsIDB4MjFiYzlkOWQsIDB4NzA0ODM4MzgsIDB4ZjEwNGY1ZjUsXG4weDYzZGZiY2JjLCAweDc3YzFiNmI2LCAweGFmNzVkYWRhLCAweDQyNjMyMTIxLFxuMHgyMDMwMTAxMCwgMHhlNTFhZmZmZiwgMHhmZDBlZjNmMywgMHhiZjZkZDJkMixcbjB4ODE0Y2NkY2QsIDB4MTgxNDBjMGMsIDB4MjYzNTEzMTMsIDB4YzMyZmVjZWMsXG4weGJlZTE1ZjVmLCAweDM1YTI5Nzk3LCAweDg4Y2M0NDQ0LCAweDJlMzkxNzE3LFxuMHg5MzU3YzRjNCwgMHg1NWYyYTdhNywgMHhmYzgyN2U3ZSwgMHg3YTQ3M2QzZCxcbjB4YzhhYzY0NjQsIDB4YmFlNzVkNWQsIDB4MzIyYjE5MTksIDB4ZTY5NTczNzMsXG4weGMwYTA2MDYwLCAweDE5OTg4MTgxLCAweDllZDE0ZjRmLCAweGEzN2ZkY2RjLFxuMHg0NDY2MjIyMiwgMHg1NDdlMmEyYSwgMHgzYmFiOTA5MCwgMHgwYjgzODg4OCxcbjB4OGNjYTQ2NDYsIDB4YzcyOWVlZWUsIDB4NmJkM2I4YjgsIDB4MjgzYzE0MTQsXG4weGE3NzlkZWRlLCAweGJjZTI1ZTVlLCAweDE2MWQwYjBiLCAweGFkNzZkYmRiLFxuMHhkYjNiZTBlMCwgMHg2NDU2MzIzMiwgMHg3NDRlM2EzYSwgMHgxNDFlMGEwYSxcbjB4OTJkYjQ5NDksIDB4MGMwYTA2MDYsIDB4NDg2YzI0MjQsIDB4YjhlNDVjNWMsXG4weDlmNWRjMmMyLCAweGJkNmVkM2QzLCAweDQzZWZhY2FjLCAweGM0YTY2MjYyLFxuMHgzOWE4OTE5MSwgMHgzMWE0OTU5NSwgMHhkMzM3ZTRlNCwgMHhmMjhiNzk3OSxcbjB4ZDUzMmU3ZTcsIDB4OGI0M2M4YzgsIDB4NmU1OTM3MzcsIDB4ZGFiNzZkNmQsXG4weDAxOGM4ZDhkLCAweGIxNjRkNWQ1LCAweDljZDI0ZTRlLCAweDQ5ZTBhOWE5LFxuMHhkOGI0NmM2YywgMHhhY2ZhNTY1NiwgMHhmMzA3ZjRmNCwgMHhjZjI1ZWFlYSxcbjB4Y2FhZjY1NjUsIDB4ZjQ4ZTdhN2EsIDB4NDdlOWFlYWUsIDB4MTAxODA4MDgsXG4weDZmZDViYWJhLCAweGYwODg3ODc4LCAweDRhNmYyNTI1LCAweDVjNzIyZTJlLFxuMHgzODI0MWMxYywgMHg1N2YxYTZhNiwgMHg3M2M3YjRiNCwgMHg5NzUxYzZjNixcbjB4Y2IyM2U4ZTgsIDB4YTE3Y2RkZGQsIDB4ZTg5Yzc0NzQsIDB4M2UyMTFmMWYsXG4weDk2ZGQ0YjRiLCAweDYxZGNiZGJkLCAweDBkODY4YjhiLCAweDBmODU4YThhLFxuMHhlMDkwNzA3MCwgMHg3YzQyM2UzZSwgMHg3MWM0YjViNSwgMHhjY2FhNjY2NixcbjB4OTBkODQ4NDgsIDB4MDYwNTAzMDMsIDB4ZjcwMWY2ZjYsIDB4MWMxMjBlMGUsXG4weGMyYTM2MTYxLCAweDZhNWYzNTM1LCAweGFlZjk1NzU3LCAweDY5ZDBiOWI5LFxuMHgxNzkxODY4NiwgMHg5OTU4YzFjMSwgMHgzYTI3MWQxZCwgMHgyN2I5OWU5ZSxcbjB4ZDkzOGUxZTEsIDB4ZWIxM2Y4ZjgsIDB4MmJiMzk4OTgsIDB4MjIzMzExMTEsXG4weGQyYmI2OTY5LCAweGE5NzBkOWQ5LCAweDA3ODk4ZThlLCAweDMzYTc5NDk0LFxuMHgyZGI2OWI5YiwgMHgzYzIyMWUxZSwgMHgxNTkyODc4NywgMHhjOTIwZTllOSxcbjB4ODc0OWNlY2UsIDB4YWFmZjU1NTUsIDB4NTA3ODI4MjgsIDB4YTU3YWRmZGYsXG4weDAzOGY4YzhjLCAweDU5ZjhhMWExLCAweDA5ODA4OTg5LCAweDFhMTcwZDBkLFxuMHg2NWRhYmZiZiwgMHhkNzMxZTZlNiwgMHg4NGM2NDI0MiwgMHhkMGI4Njg2OCxcbjB4ODJjMzQxNDEsIDB4MjliMDk5OTksIDB4NWE3NzJkMmQsIDB4MWUxMTBmMGYsXG4weDdiY2JiMGIwLCAweGE4ZmM1NDU0LCAweDZkZDZiYmJiLCAweDJjM2ExNjE2IF07XG5cbmZ1bmN0aW9uIEIwKHgpIHsgcmV0dXJuICh4JjI1NSk7IH1cbmZ1bmN0aW9uIEIxKHgpIHsgcmV0dXJuICgoeD4+OCkmMjU1KTsgfVxuZnVuY3Rpb24gQjIoeCkgeyByZXR1cm4gKCh4Pj4xNikmMjU1KTsgfVxuZnVuY3Rpb24gQjMoeCkgeyByZXR1cm4gKCh4Pj4yNCkmMjU1KTsgfVxuXG5mdW5jdGlvbiBGMSh4MCwgeDEsIHgyLCB4MylcbntcbiAgcmV0dXJuIEIxKFQxW3gwJjI1NV0pIHwgKEIxKFQxWyh4MT4+OCkmMjU1XSk8PDgpXG4gICAgICB8IChCMShUMVsoeDI+PjE2KSYyNTVdKTw8MTYpIHwgKEIxKFQxW3gzPj4+MjRdKTw8MjQpO1xufVxuXG5mdW5jdGlvbiBwYWNrQnl0ZXMob2N0ZXRzKVxue1xuICB2YXIgaSwgajtcbiAgdmFyIGxlbj1vY3RldHMubGVuZ3RoO1xuICB2YXIgYj1uZXcgQXJyYXkobGVuLzQpO1xuXG4gIGlmICghb2N0ZXRzIHx8IGxlbiAlIDQpIHJldHVybjtcblxuICBmb3IgKGk9MCwgaj0wOyBqPGxlbjsgais9IDQpXG4gICAgIGJbaSsrXSA9IG9jdGV0c1tqXSB8IChvY3RldHNbaisxXTw8OCkgfCAob2N0ZXRzW2orMl08PDE2KSB8IChvY3RldHNbaiszXTw8MjQpO1xuXG4gIHJldHVybiBiOyAgXG59XG5cbmZ1bmN0aW9uIHVucGFja0J5dGVzKHBhY2tlZClcbntcbiAgdmFyIGo7XG4gIHZhciBpPTAsIGwgPSBwYWNrZWQubGVuZ3RoO1xuICB2YXIgciA9IG5ldyBBcnJheShsKjQpO1xuXG4gIGZvciAoaj0wOyBqPGw7IGorKylcbiAge1xuICAgIHJbaSsrXSA9IEIwKHBhY2tlZFtqXSk7XG4gICAgcltpKytdID0gQjEocGFja2VkW2pdKTtcbiAgICByW2krK10gPSBCMihwYWNrZWRbal0pO1xuICAgIHJbaSsrXSA9IEIzKHBhY2tlZFtqXSk7XG4gIH1cbiAgcmV0dXJuIHI7XG59XG5cbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuXG52YXIgbWF4a2M9ODtcbnZhciBtYXhyaz0xNDtcblxuZnVuY3Rpb24ga2V5RXhwYW5zaW9uKGtleSlcbntcbiAgdmFyIGtjLCBpLCBqLCByLCB0O1xuICB2YXIgcm91bmRzO1xuICB2YXIga2V5U2NoZWQ9bmV3IEFycmF5KG1heHJrKzEpO1xuICB2YXIga2V5bGVuPWtleS5sZW5ndGg7XG4gIHZhciBrPW5ldyBBcnJheShtYXhrYyk7XG4gIHZhciB0az1uZXcgQXJyYXkobWF4a2MpO1xuICB2YXIgcmNvbnBvaW50ZXI9MDtcblxuICBpZihrZXlsZW49PTE2KVxuICB7XG4gICByb3VuZHM9MTA7XG4gICBrYz00O1xuICB9XG4gIGVsc2UgaWYoa2V5bGVuPT0yNClcbiAge1xuICAgcm91bmRzPTEyO1xuICAga2M9NjtcbiAgfVxuICBlbHNlIGlmKGtleWxlbj09MzIpXG4gIHtcbiAgIHJvdW5kcz0xNDtcbiAgIGtjPTg7XG4gIH1cbiAgZWxzZVxuICB7XG5cdHV0aWwucHJpbnRfZXJyb3IoJ2Flcy5qczogSW52YWxpZCBrZXktbGVuZ3RoIGZvciBBRVMga2V5Oicra2V5bGVuKTtcbiAgIHJldHVybjtcbiAgfVxuXG4gIGZvcihpPTA7IGk8bWF4cmsrMTsgaSsrKSBrZXlTY2hlZFtpXT1uZXcgQXJyYXkoNCk7XG5cbiAgZm9yKGk9MCxqPTA7IGo8a2V5bGVuOyBqKyssaSs9NClcbiAgICBrW2pdID0ga2V5LmNoYXJDb2RlQXQoaSkgfCAoa2V5LmNoYXJDb2RlQXQoaSsxKTw8OClcbiAgICAgICAgICAgICAgICAgICAgIHwgKGtleS5jaGFyQ29kZUF0KGkrMik8PDE2KSB8IChrZXkuY2hhckNvZGVBdChpKzMpPDwyNCk7XG5cbiAgZm9yKGo9a2MtMTsgaj49MDsgai0tKSB0a1tqXSA9IGtbal07XG5cbiAgcj0wO1xuICB0PTA7XG4gIGZvcihqPTA7IChqPGtjKSYmKHI8cm91bmRzKzEpOyApXG4gIHtcbiAgICBmb3IoOyAoajxrYykmJih0PDQpOyBqKyssdCsrKVxuICAgIHtcbiAgICAgIGtleVNjaGVkW3JdW3RdPXRrW2pdO1xuICAgIH1cbiAgICBpZih0PT00KVxuICAgIHtcbiAgICAgIHIrKztcbiAgICAgIHQ9MDtcbiAgICB9XG4gIH1cblxuICB3aGlsZShyPHJvdW5kcysxKVxuICB7XG4gICAgdmFyIHRlbXAgPSB0a1trYy0xXTtcblxuICAgIHRrWzBdIF49IFNbQjEodGVtcCldIHwgKFNbQjIodGVtcCldPDw4KSB8IChTW0IzKHRlbXApXTw8MTYpIHwgKFNbQjAodGVtcCldPDwyNCk7XG4gICAgdGtbMF0gXj0gUmNvbltyY29ucG9pbnRlcisrXTtcblxuICAgIGlmKGtjICE9IDgpXG4gICAge1xuICAgICAgZm9yKGo9MTsgajxrYzsgaisrKSB0a1tqXSBePSB0a1tqLTFdO1xuICAgIH1cbiAgICBlbHNlXG4gICAge1xuICAgICAgZm9yKGo9MTsgajxrYy8yOyBqKyspIHRrW2pdIF49IHRrW2otMV07XG4gXG4gICAgICB0ZW1wID0gdGtba2MvMi0xXTtcbiAgICAgIHRrW2tjLzJdIF49IFNbQjAodGVtcCldIHwgKFNbQjEodGVtcCldPDw4KSB8IChTW0IyKHRlbXApXTw8MTYpIHwgKFNbQjModGVtcCldPDwyNCk7XG5cbiAgICAgIGZvcihqPWtjLzIrMTsgajxrYzsgaisrKSB0a1tqXSBePSB0a1tqLTFdO1xuICAgIH1cblxuICAgIGZvcihqPTA7IChqPGtjKSYmKHI8cm91bmRzKzEpOyApXG4gICAge1xuICAgICAgZm9yKDsgKGo8a2MpJiYodDw0KTsgaisrLHQrKylcbiAgICAgIHtcbiAgICAgICAga2V5U2NoZWRbcl1bdF09dGtbal07XG4gICAgICB9XG4gICAgICBpZih0PT00KVxuICAgICAge1xuICAgICAgICByKys7XG4gICAgICAgIHQ9MDtcbiAgICAgIH1cbiAgICB9XG4gIH1cbiAgdGhpcy5yb3VuZHMgPSByb3VuZHM7XG4gIHRoaXMucmsgPSBrZXlTY2hlZDtcbiAgcmV0dXJuIHRoaXM7XG59XG5cbmZ1bmN0aW9uIEFFU2VuY3J5cHQoYmxvY2ssIGN0eClcbntcbiAgdmFyIHI7XG4gIHZhciB0MCx0MSx0Mix0MztcblxuICB2YXIgYiA9IHBhY2tCeXRlcyhibG9jayk7XG4gIHZhciByb3VuZHMgPSBjdHgucm91bmRzO1xuICB2YXIgYjAgPSBiWzBdO1xuICB2YXIgYjEgPSBiWzFdO1xuICB2YXIgYjIgPSBiWzJdO1xuICB2YXIgYjMgPSBiWzNdO1xuXG4gIGZvcihyPTA7IHI8cm91bmRzLTE7IHIrKylcbiAge1xuICAgIHQwID0gYjAgXiBjdHgucmtbcl1bMF07XG4gICAgdDEgPSBiMSBeIGN0eC5ya1tyXVsxXTtcbiAgICB0MiA9IGIyIF4gY3R4LnJrW3JdWzJdO1xuICAgIHQzID0gYjMgXiBjdHgucmtbcl1bM107XG5cbiAgICBiMCA9IFQxW3QwJjI1NV0gXiBUMlsodDE+PjgpJjI1NV0gXiBUM1sodDI+PjE2KSYyNTVdIF4gVDRbdDM+Pj4yNF07XG4gICAgYjEgPSBUMVt0MSYyNTVdIF4gVDJbKHQyPj44KSYyNTVdIF4gVDNbKHQzPj4xNikmMjU1XSBeIFQ0W3QwPj4+MjRdO1xuICAgIGIyID0gVDFbdDImMjU1XSBeIFQyWyh0Mz4+OCkmMjU1XSBeIFQzWyh0MD4+MTYpJjI1NV0gXiBUNFt0MT4+PjI0XTtcbiAgICBiMyA9IFQxW3QzJjI1NV0gXiBUMlsodDA+PjgpJjI1NV0gXiBUM1sodDE+PjE2KSYyNTVdIF4gVDRbdDI+Pj4yNF07XG4gIH1cblxuICAvLyBsYXN0IHJvdW5kIGlzIHNwZWNpYWxcbiAgciA9IHJvdW5kcy0xO1xuXG4gIHQwID0gYjAgXiBjdHgucmtbcl1bMF07XG4gIHQxID0gYjEgXiBjdHgucmtbcl1bMV07XG4gIHQyID0gYjIgXiBjdHgucmtbcl1bMl07XG4gIHQzID0gYjMgXiBjdHgucmtbcl1bM107XG5cbiAgYlswXSA9IEYxKHQwLCB0MSwgdDIsIHQzKSBeIGN0eC5ya1tyb3VuZHNdWzBdO1xuICBiWzFdID0gRjEodDEsIHQyLCB0MywgdDApIF4gY3R4LnJrW3JvdW5kc11bMV07XG4gIGJbMl0gPSBGMSh0MiwgdDMsIHQwLCB0MSkgXiBjdHgucmtbcm91bmRzXVsyXTtcbiAgYlszXSA9IEYxKHQzLCB0MCwgdDEsIHQyKSBeIGN0eC5ya1tyb3VuZHNdWzNdO1xuXG4gIHJldHVybiB1bnBhY2tCeXRlcyhiKTtcbn1cblxubW9kdWxlLmV4cG9ydHMgPSB7XG5cdEFFU2VuY3J5cHQ6IEFFU2VuY3J5cHQsXG5cdGtleUV4cGFuc2lvbjoga2V5RXhwYW5zaW9uXG59XG4iLCIvL1BhdWwgVGVybywgSnVseSAyMDAxXG4vL2h0dHA6Ly93d3cudGVyby5jby51ay9kZXMvXG4vL1xuLy9PcHRpbWlzZWQgZm9yIHBlcmZvcm1hbmNlIHdpdGggbGFyZ2UgYmxvY2tzIGJ5IE1pY2hhZWwgSGF5d29ydGgsIE5vdmVtYmVyIDIwMDFcbi8vaHR0cDovL3d3dy5uZXRkZWFsaW5nLmNvbVxuLy9cbi8vIE1vZGlmaWVkIGJ5IFJlY3VyaXR5IExhYnMgR21iSFxuXG4vL1RISVMgU09GVFdBUkUgSVMgUFJPVklERUQgXCJBUyBJU1wiIEFORFxuLy9BTlkgRVhQUkVTUyBPUiBJTVBMSUVEIFdBUlJBTlRJRVMsIElOQ0xVRElORywgQlVUIE5PVCBMSU1JVEVEIFRPLCBUSEVcbi8vSU1QTElFRCBXQVJSQU5USUVTIE9GIE1FUkNIQU5UQUJJTElUWSBBTkQgRklUTkVTUyBGT1IgQSBQQVJUSUNVTEFSIFBVUlBPU0Vcbi8vQVJFIERJU0NMQUlNRUQuICBJTiBOTyBFVkVOVCBTSEFMTCBUSEUgQVVUSE9SIE9SIENPTlRSSUJVVE9SUyBCRSBMSUFCTEVcbi8vRk9SIEFOWSBESVJFQ1QsIElORElSRUNULCBJTkNJREVOVEFMLCBTUEVDSUFMLCBFWEVNUExBUlksIE9SIENPTlNFUVVFTlRJQUxcbi8vREFNQUdFUyAoSU5DTFVESU5HLCBCVVQgTk9UIExJTUlURUQgVE8sIFBST0NVUkVNRU5UIE9GIFNVQlNUSVRVVEUgR09PRFNcbi8vT1IgU0VSVklDRVM7IExPU1MgT0YgVVNFLCBEQVRBLCBPUiBQUk9GSVRTOyBPUiBCVVNJTkVTUyBJTlRFUlJVUFRJT04pXG4vL0hPV0VWRVIgQ0FVU0VEIEFORCBPTiBBTlkgVEhFT1JZIE9GIExJQUJJTElUWSwgV0hFVEhFUiBJTiBDT05UUkFDVCwgU1RSSUNUXG4vL0xJQUJJTElUWSwgT1IgVE9SVCAoSU5DTFVESU5HIE5FR0xJR0VOQ0UgT1IgT1RIRVJXSVNFKSBBUklTSU5HIElOIEFOWSBXQVlcbi8vT1VUIE9GIFRIRSBVU0UgT0YgVEhJUyBTT0ZUV0FSRSwgRVZFTiBJRiBBRFZJU0VEIE9GIFRIRSBQT1NTSUJJTElUWSBPRlxuLy9TVUNIIERBTUFHRS5cblxuLy9kZXNcbi8vdGhpcyB0YWtlcyB0aGUga2V5LCB0aGUgbWVzc2FnZSwgYW5kIHdoZXRoZXIgdG8gZW5jcnlwdCBvciBkZWNyeXB0XG5cbi8vIGFkZGVkIGJ5IFJlY3VyaXR5IExhYnNcbmZ1bmN0aW9uIGRlc2VkZShibG9jayxrZXkpIHtcblx0dmFyIGtleTEgPSBrZXkuc3Vic3RyaW5nKDAsOCk7XG5cdHZhciBrZXkyID0ga2V5LnN1YnN0cmluZyg4LDE2KTtcblx0dmFyIGtleTMgPSBrZXkuc3Vic3RyaW5nKDE2LDI0KTtcblx0cmV0dXJuIHV0aWwuc3RyMmJpbihkZXMoZGVzX2NyZWF0ZUtleXMoa2V5MyksZGVzKGRlc19jcmVhdGVLZXlzKGtleTIpLGRlcyhkZXNfY3JlYXRlS2V5cyhrZXkxKSx1dGlsLmJpbjJzdHIoYmxvY2spLCB0cnVlLCAwLG51bGwsbnVsbCksIGZhbHNlLCAwLG51bGwsbnVsbCksIHRydWUsIDAsbnVsbCxudWxsKSk7XG59XG5cblxuZnVuY3Rpb24gZGVzIChrZXlzLCBtZXNzYWdlLCBlbmNyeXB0LCBtb2RlLCBpdiwgcGFkZGluZykge1xuICAvL2RlY2xhcmluZyB0aGlzIGxvY2FsbHkgc3BlZWRzIHRoaW5ncyB1cCBhIGJpdFxuICB2YXIgc3BmdW5jdGlvbjEgPSBuZXcgQXJyYXkgKDB4MTAxMDQwMCwwLDB4MTAwMDAsMHgxMDEwNDA0LDB4MTAxMDAwNCwweDEwNDA0LDB4NCwweDEwMDAwLDB4NDAwLDB4MTAxMDQwMCwweDEwMTA0MDQsMHg0MDAsMHgxMDAwNDA0LDB4MTAxMDAwNCwweDEwMDAwMDAsMHg0LDB4NDA0LDB4MTAwMDQwMCwweDEwMDA0MDAsMHgxMDQwMCwweDEwNDAwLDB4MTAxMDAwMCwweDEwMTAwMDAsMHgxMDAwNDA0LDB4MTAwMDQsMHgxMDAwMDA0LDB4MTAwMDAwNCwweDEwMDA0LDAsMHg0MDQsMHgxMDQwNCwweDEwMDAwMDAsMHgxMDAwMCwweDEwMTA0MDQsMHg0LDB4MTAxMDAwMCwweDEwMTA0MDAsMHgxMDAwMDAwLDB4MTAwMDAwMCwweDQwMCwweDEwMTAwMDQsMHgxMDAwMCwweDEwNDAwLDB4MTAwMDAwNCwweDQwMCwweDQsMHgxMDAwNDA0LDB4MTA0MDQsMHgxMDEwNDA0LDB4MTAwMDQsMHgxMDEwMDAwLDB4MTAwMDQwNCwweDEwMDAwMDQsMHg0MDQsMHgxMDQwNCwweDEwMTA0MDAsMHg0MDQsMHgxMDAwNDAwLDB4MTAwMDQwMCwwLDB4MTAwMDQsMHgxMDQwMCwwLDB4MTAxMDAwNCk7XG4gIHZhciBzcGZ1bmN0aW9uMiA9IG5ldyBBcnJheSAoLTB4N2ZlZjdmZTAsLTB4N2ZmZjgwMDAsMHg4MDAwLDB4MTA4MDIwLDB4MTAwMDAwLDB4MjAsLTB4N2ZlZmZmZTAsLTB4N2ZmZjdmZTAsLTB4N2ZmZmZmZTAsLTB4N2ZlZjdmZTAsLTB4N2ZlZjgwMDAsLTB4ODAwMDAwMDAsLTB4N2ZmZjgwMDAsMHgxMDAwMDAsMHgyMCwtMHg3ZmVmZmZlMCwweDEwODAwMCwweDEwMDAyMCwtMHg3ZmZmN2ZlMCwwLC0weDgwMDAwMDAwLDB4ODAwMCwweDEwODAyMCwtMHg3ZmYwMDAwMCwweDEwMDAyMCwtMHg3ZmZmZmZlMCwwLDB4MTA4MDAwLDB4ODAyMCwtMHg3ZmVmODAwMCwtMHg3ZmYwMDAwMCwweDgwMjAsMCwweDEwODAyMCwtMHg3ZmVmZmZlMCwweDEwMDAwMCwtMHg3ZmZmN2ZlMCwtMHg3ZmYwMDAwMCwtMHg3ZmVmODAwMCwweDgwMDAsLTB4N2ZmMDAwMDAsLTB4N2ZmZjgwMDAsMHgyMCwtMHg3ZmVmN2ZlMCwweDEwODAyMCwweDIwLDB4ODAwMCwtMHg4MDAwMDAwMCwweDgwMjAsLTB4N2ZlZjgwMDAsMHgxMDAwMDAsLTB4N2ZmZmZmZTAsMHgxMDAwMjAsLTB4N2ZmZjdmZTAsLTB4N2ZmZmZmZTAsMHgxMDAwMjAsMHgxMDgwMDAsMCwtMHg3ZmZmODAwMCwweDgwMjAsLTB4ODAwMDAwMDAsLTB4N2ZlZmZmZTAsLTB4N2ZlZjdmZTAsMHgxMDgwMDApO1xuICB2YXIgc3BmdW5jdGlvbjMgPSBuZXcgQXJyYXkgKDB4MjA4LDB4ODAyMDIwMCwwLDB4ODAyMDAwOCwweDgwMDAyMDAsMCwweDIwMjA4LDB4ODAwMDIwMCwweDIwMDA4LDB4ODAwMDAwOCwweDgwMDAwMDgsMHgyMDAwMCwweDgwMjAyMDgsMHgyMDAwOCwweDgwMjAwMDAsMHgyMDgsMHg4MDAwMDAwLDB4OCwweDgwMjAyMDAsMHgyMDAsMHgyMDIwMCwweDgwMjAwMDAsMHg4MDIwMDA4LDB4MjAyMDgsMHg4MDAwMjA4LDB4MjAyMDAsMHgyMDAwMCwweDgwMDAyMDgsMHg4LDB4ODAyMDIwOCwweDIwMCwweDgwMDAwMDAsMHg4MDIwMjAwLDB4ODAwMDAwMCwweDIwMDA4LDB4MjA4LDB4MjAwMDAsMHg4MDIwMjAwLDB4ODAwMDIwMCwwLDB4MjAwLDB4MjAwMDgsMHg4MDIwMjA4LDB4ODAwMDIwMCwweDgwMDAwMDgsMHgyMDAsMCwweDgwMjAwMDgsMHg4MDAwMjA4LDB4MjAwMDAsMHg4MDAwMDAwLDB4ODAyMDIwOCwweDgsMHgyMDIwOCwweDIwMjAwLDB4ODAwMDAwOCwweDgwMjAwMDAsMHg4MDAwMjA4LDB4MjA4LDB4ODAyMDAwMCwweDIwMjA4LDB4OCwweDgwMjAwMDgsMHgyMDIwMCk7XG4gIHZhciBzcGZ1bmN0aW9uNCA9IG5ldyBBcnJheSAoMHg4MDIwMDEsMHgyMDgxLDB4MjA4MSwweDgwLDB4ODAyMDgwLDB4ODAwMDgxLDB4ODAwMDAxLDB4MjAwMSwwLDB4ODAyMDAwLDB4ODAyMDAwLDB4ODAyMDgxLDB4ODEsMCwweDgwMDA4MCwweDgwMDAwMSwweDEsMHgyMDAwLDB4ODAwMDAwLDB4ODAyMDAxLDB4ODAsMHg4MDAwMDAsMHgyMDAxLDB4MjA4MCwweDgwMDA4MSwweDEsMHgyMDgwLDB4ODAwMDgwLDB4MjAwMCwweDgwMjA4MCwweDgwMjA4MSwweDgxLDB4ODAwMDgwLDB4ODAwMDAxLDB4ODAyMDAwLDB4ODAyMDgxLDB4ODEsMCwwLDB4ODAyMDAwLDB4MjA4MCwweDgwMDA4MCwweDgwMDA4MSwweDEsMHg4MDIwMDEsMHgyMDgxLDB4MjA4MSwweDgwLDB4ODAyMDgxLDB4ODEsMHgxLDB4MjAwMCwweDgwMDAwMSwweDIwMDEsMHg4MDIwODAsMHg4MDAwODEsMHgyMDAxLDB4MjA4MCwweDgwMDAwMCwweDgwMjAwMSwweDgwLDB4ODAwMDAwLDB4MjAwMCwweDgwMjA4MCk7XG4gIHZhciBzcGZ1bmN0aW9uNSA9IG5ldyBBcnJheSAoMHgxMDAsMHgyMDgwMTAwLDB4MjA4MDAwMCwweDQyMDAwMTAwLDB4ODAwMDAsMHgxMDAsMHg0MDAwMDAwMCwweDIwODAwMDAsMHg0MDA4MDEwMCwweDgwMDAwLDB4MjAwMDEwMCwweDQwMDgwMTAwLDB4NDIwMDAxMDAsMHg0MjA4MDAwMCwweDgwMTAwLDB4NDAwMDAwMDAsMHgyMDAwMDAwLDB4NDAwODAwMDAsMHg0MDA4MDAwMCwwLDB4NDAwMDAxMDAsMHg0MjA4MDEwMCwweDQyMDgwMTAwLDB4MjAwMDEwMCwweDQyMDgwMDAwLDB4NDAwMDAxMDAsMCwweDQyMDAwMDAwLDB4MjA4MDEwMCwweDIwMDAwMDAsMHg0MjAwMDAwMCwweDgwMTAwLDB4ODAwMDAsMHg0MjAwMDEwMCwweDEwMCwweDIwMDAwMDAsMHg0MDAwMDAwMCwweDIwODAwMDAsMHg0MjAwMDEwMCwweDQwMDgwMTAwLDB4MjAwMDEwMCwweDQwMDAwMDAwLDB4NDIwODAwMDAsMHgyMDgwMTAwLDB4NDAwODAxMDAsMHgxMDAsMHgyMDAwMDAwLDB4NDIwODAwMDAsMHg0MjA4MDEwMCwweDgwMTAwLDB4NDIwMDAwMDAsMHg0MjA4MDEwMCwweDIwODAwMDAsMCwweDQwMDgwMDAwLDB4NDIwMDAwMDAsMHg4MDEwMCwweDIwMDAxMDAsMHg0MDAwMDEwMCwweDgwMDAwLDAsMHg0MDA4MDAwMCwweDIwODAxMDAsMHg0MDAwMDEwMCk7XG4gIHZhciBzcGZ1bmN0aW9uNiA9IG5ldyBBcnJheSAoMHgyMDAwMDAxMCwweDIwNDAwMDAwLDB4NDAwMCwweDIwNDA0MDEwLDB4MjA0MDAwMDAsMHgxMCwweDIwNDA0MDEwLDB4NDAwMDAwLDB4MjAwMDQwMDAsMHg0MDQwMTAsMHg0MDAwMDAsMHgyMDAwMDAxMCwweDQwMDAxMCwweDIwMDA0MDAwLDB4MjAwMDAwMDAsMHg0MDEwLDAsMHg0MDAwMTAsMHgyMDAwNDAxMCwweDQwMDAsMHg0MDQwMDAsMHgyMDAwNDAxMCwweDEwLDB4MjA0MDAwMTAsMHgyMDQwMDAxMCwwLDB4NDA0MDEwLDB4MjA0MDQwMDAsMHg0MDEwLDB4NDA0MDAwLDB4MjA0MDQwMDAsMHgyMDAwMDAwMCwweDIwMDA0MDAwLDB4MTAsMHgyMDQwMDAxMCwweDQwNDAwMCwweDIwNDA0MDEwLDB4NDAwMDAwLDB4NDAxMCwweDIwMDAwMDEwLDB4NDAwMDAwLDB4MjAwMDQwMDAsMHgyMDAwMDAwMCwweDQwMTAsMHgyMDAwMDAxMCwweDIwNDA0MDEwLDB4NDA0MDAwLDB4MjA0MDAwMDAsMHg0MDQwMTAsMHgyMDQwNDAwMCwwLDB4MjA0MDAwMTAsMHgxMCwweDQwMDAsMHgyMDQwMDAwMCwweDQwNDAxMCwweDQwMDAsMHg0MDAwMTAsMHgyMDAwNDAxMCwwLDB4MjA0MDQwMDAsMHgyMDAwMDAwMCwweDQwMDAxMCwweDIwMDA0MDEwKTtcbiAgdmFyIHNwZnVuY3Rpb243ID0gbmV3IEFycmF5ICgweDIwMDAwMCwweDQyMDAwMDIsMHg0MDAwODAyLDAsMHg4MDAsMHg0MDAwODAyLDB4MjAwODAyLDB4NDIwMDgwMCwweDQyMDA4MDIsMHgyMDAwMDAsMCwweDQwMDAwMDIsMHgyLDB4NDAwMDAwMCwweDQyMDAwMDIsMHg4MDIsMHg0MDAwODAwLDB4MjAwODAyLDB4MjAwMDAyLDB4NDAwMDgwMCwweDQwMDAwMDIsMHg0MjAwMDAwLDB4NDIwMDgwMCwweDIwMDAwMiwweDQyMDAwMDAsMHg4MDAsMHg4MDIsMHg0MjAwODAyLDB4MjAwODAwLDB4MiwweDQwMDAwMDAsMHgyMDA4MDAsMHg0MDAwMDAwLDB4MjAwODAwLDB4MjAwMDAwLDB4NDAwMDgwMiwweDQwMDA4MDIsMHg0MjAwMDAyLDB4NDIwMDAwMiwweDIsMHgyMDAwMDIsMHg0MDAwMDAwLDB4NDAwMDgwMCwweDIwMDAwMCwweDQyMDA4MDAsMHg4MDIsMHgyMDA4MDIsMHg0MjAwODAwLDB4ODAyLDB4NDAwMDAwMiwweDQyMDA4MDIsMHg0MjAwMDAwLDB4MjAwODAwLDAsMHgyLDB4NDIwMDgwMiwwLDB4MjAwODAyLDB4NDIwMDAwMCwweDgwMCwweDQwMDAwMDIsMHg0MDAwODAwLDB4ODAwLDB4MjAwMDAyKTtcbiAgdmFyIHNwZnVuY3Rpb244ID0gbmV3IEFycmF5ICgweDEwMDAxMDQwLDB4MTAwMCwweDQwMDAwLDB4MTAwNDEwNDAsMHgxMDAwMDAwMCwweDEwMDAxMDQwLDB4NDAsMHgxMDAwMDAwMCwweDQwMDQwLDB4MTAwNDAwMDAsMHgxMDA0MTA0MCwweDQxMDAwLDB4MTAwNDEwMDAsMHg0MTA0MCwweDEwMDAsMHg0MCwweDEwMDQwMDAwLDB4MTAwMDAwNDAsMHgxMDAwMTAwMCwweDEwNDAsMHg0MTAwMCwweDQwMDQwLDB4MTAwNDAwNDAsMHgxMDA0MTAwMCwweDEwNDAsMCwwLDB4MTAwNDAwNDAsMHgxMDAwMDA0MCwweDEwMDAxMDAwLDB4NDEwNDAsMHg0MDAwMCwweDQxMDQwLDB4NDAwMDAsMHgxMDA0MTAwMCwweDEwMDAsMHg0MCwweDEwMDQwMDQwLDB4MTAwMCwweDQxMDQwLDB4MTAwMDEwMDAsMHg0MCwweDEwMDAwMDQwLDB4MTAwNDAwMDAsMHgxMDA0MDA0MCwweDEwMDAwMDAwLDB4NDAwMDAsMHgxMDAwMTA0MCwwLDB4MTAwNDEwNDAsMHg0MDA0MCwweDEwMDAwMDQwLDB4MTAwNDAwMDAsMHgxMDAwMTAwMCwweDEwMDAxMDQwLDAsMHgxMDA0MTA0MCwweDQxMDAwLDB4NDEwMDAsMHgxMDQwLDB4MTA0MCwweDQwMDQwLDB4MTAwMDAwMDAsMHgxMDA0MTAwMCk7XG5cbiAgLy9jcmVhdGUgdGhlIDE2IG9yIDQ4IHN1YmtleXMgd2Ugd2lsbCBuZWVkXG4gIHZhciBtPTAsIGksIGosIHRlbXAsIHRlbXAyLCByaWdodDEsIHJpZ2h0MiwgbGVmdCwgcmlnaHQsIGxvb3Bpbmc7XG4gIHZhciBjYmNsZWZ0LCBjYmNsZWZ0MiwgY2JjcmlnaHQsIGNiY3JpZ2h0MlxuICB2YXIgZW5kbG9vcCwgbG9vcGluYztcbiAgdmFyIGxlbiA9IG1lc3NhZ2UubGVuZ3RoO1xuICB2YXIgY2h1bmsgPSAwO1xuICAvL3NldCB1cCB0aGUgbG9vcHMgZm9yIHNpbmdsZSBhbmQgdHJpcGxlIGRlc1xuICB2YXIgaXRlcmF0aW9ucyA9IGtleXMubGVuZ3RoID09IDMyID8gMyA6IDk7IC8vc2luZ2xlIG9yIHRyaXBsZSBkZXNcbiAgaWYgKGl0ZXJhdGlvbnMgPT0gMykge2xvb3BpbmcgPSBlbmNyeXB0ID8gbmV3IEFycmF5ICgwLCAzMiwgMikgOiBuZXcgQXJyYXkgKDMwLCAtMiwgLTIpO31cbiAgZWxzZSB7bG9vcGluZyA9IGVuY3J5cHQgPyBuZXcgQXJyYXkgKDAsIDMyLCAyLCA2MiwgMzAsIC0yLCA2NCwgOTYsIDIpIDogbmV3IEFycmF5ICg5NCwgNjIsIC0yLCAzMiwgNjQsIDIsIDMwLCAtMiwgLTIpO31cblxuICAvL3BhZCB0aGUgbWVzc2FnZSBkZXBlbmRpbmcgb24gdGhlIHBhZGRpbmcgcGFyYW1ldGVyXG4gIGlmIChwYWRkaW5nID09IDIpIG1lc3NhZ2UgKz0gXCIgICAgICAgIFwiOyAvL3BhZCB0aGUgbWVzc2FnZSB3aXRoIHNwYWNlc1xuICBlbHNlIGlmIChwYWRkaW5nID09IDEpIHt0ZW1wID0gOC0obGVuJTgpOyBtZXNzYWdlICs9IFN0cmluZy5mcm9tQ2hhckNvZGUgKHRlbXAsdGVtcCx0ZW1wLHRlbXAsdGVtcCx0ZW1wLHRlbXAsdGVtcCk7IGlmICh0ZW1wPT04KSBsZW4rPTg7fSAvL1BLQ1M3IHBhZGRpbmdcbiAgZWxzZSBpZiAoIXBhZGRpbmcpIG1lc3NhZ2UgKz0gXCJcXDBcXDBcXDBcXDBcXDBcXDBcXDBcXDBcIjsgLy9wYWQgdGhlIG1lc3NhZ2Ugb3V0IHdpdGggbnVsbCBieXRlc1xuXG4gIC8vc3RvcmUgdGhlIHJlc3VsdCBoZXJlXG4gIHJlc3VsdCA9IFwiXCI7XG4gIHRlbXByZXN1bHQgPSBcIlwiO1xuXG4gIGlmIChtb2RlID09IDEpIHsgLy9DQkMgbW9kZVxuICAgIGNiY2xlZnQgPSAoaXYuY2hhckNvZGVBdChtKyspIDw8IDI0KSB8IChpdi5jaGFyQ29kZUF0KG0rKykgPDwgMTYpIHwgKGl2LmNoYXJDb2RlQXQobSsrKSA8PCA4KSB8IGl2LmNoYXJDb2RlQXQobSsrKTtcbiAgICBjYmNyaWdodCA9IChpdi5jaGFyQ29kZUF0KG0rKykgPDwgMjQpIHwgKGl2LmNoYXJDb2RlQXQobSsrKSA8PCAxNikgfCAoaXYuY2hhckNvZGVBdChtKyspIDw8IDgpIHwgaXYuY2hhckNvZGVBdChtKyspO1xuICAgIG09MDtcbiAgfVxuXG4gIC8vbG9vcCB0aHJvdWdoIGVhY2ggNjQgYml0IGNodW5rIG9mIHRoZSBtZXNzYWdlXG4gIHdoaWxlIChtIDwgbGVuKSB7XG4gICAgbGVmdCA9IChtZXNzYWdlLmNoYXJDb2RlQXQobSsrKSA8PCAyNCkgfCAobWVzc2FnZS5jaGFyQ29kZUF0KG0rKykgPDwgMTYpIHwgKG1lc3NhZ2UuY2hhckNvZGVBdChtKyspIDw8IDgpIHwgbWVzc2FnZS5jaGFyQ29kZUF0KG0rKyk7XG4gICAgcmlnaHQgPSAobWVzc2FnZS5jaGFyQ29kZUF0KG0rKykgPDwgMjQpIHwgKG1lc3NhZ2UuY2hhckNvZGVBdChtKyspIDw8IDE2KSB8IChtZXNzYWdlLmNoYXJDb2RlQXQobSsrKSA8PCA4KSB8IG1lc3NhZ2UuY2hhckNvZGVBdChtKyspO1xuXG4gICAgLy9mb3IgQ2lwaGVyIEJsb2NrIENoYWluaW5nIG1vZGUsIHhvciB0aGUgbWVzc2FnZSB3aXRoIHRoZSBwcmV2aW91cyByZXN1bHRcbiAgICBpZiAobW9kZSA9PSAxKSB7aWYgKGVuY3J5cHQpIHtsZWZ0IF49IGNiY2xlZnQ7IHJpZ2h0IF49IGNiY3JpZ2h0O30gZWxzZSB7Y2JjbGVmdDIgPSBjYmNsZWZ0OyBjYmNyaWdodDIgPSBjYmNyaWdodDsgY2JjbGVmdCA9IGxlZnQ7IGNiY3JpZ2h0ID0gcmlnaHQ7fX1cblxuICAgIC8vZmlyc3QgZWFjaCA2NCBidXQgY2h1bmsgb2YgdGhlIG1lc3NhZ2UgbXVzdCBiZSBwZXJtdXRlZCBhY2NvcmRpbmcgdG8gSVBcbiAgICB0ZW1wID0gKChsZWZ0ID4+PiA0KSBeIHJpZ2h0KSAmIDB4MGYwZjBmMGY7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgNCk7XG4gICAgdGVtcCA9ICgobGVmdCA+Pj4gMTYpIF4gcmlnaHQpICYgMHgwMDAwZmZmZjsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCAxNik7XG4gICAgdGVtcCA9ICgocmlnaHQgPj4+IDIpIF4gbGVmdCkgJiAweDMzMzMzMzMzOyBsZWZ0IF49IHRlbXA7IHJpZ2h0IF49ICh0ZW1wIDw8IDIpO1xuICAgIHRlbXAgPSAoKHJpZ2h0ID4+PiA4KSBeIGxlZnQpICYgMHgwMGZmMDBmZjsgbGVmdCBePSB0ZW1wOyByaWdodCBePSAodGVtcCA8PCA4KTtcbiAgICB0ZW1wID0gKChsZWZ0ID4+PiAxKSBeIHJpZ2h0KSAmIDB4NTU1NTU1NTU7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgMSk7XG5cbiAgICBsZWZ0ID0gKChsZWZ0IDw8IDEpIHwgKGxlZnQgPj4+IDMxKSk7IFxuICAgIHJpZ2h0ID0gKChyaWdodCA8PCAxKSB8IChyaWdodCA+Pj4gMzEpKTsgXG5cbiAgICAvL2RvIHRoaXMgZWl0aGVyIDEgb3IgMyB0aW1lcyBmb3IgZWFjaCBjaHVuayBvZiB0aGUgbWVzc2FnZVxuICAgIGZvciAoaj0wOyBqPGl0ZXJhdGlvbnM7IGorPTMpIHtcbiAgICAgIGVuZGxvb3AgPSBsb29waW5nW2orMV07XG4gICAgICBsb29waW5jID0gbG9vcGluZ1tqKzJdO1xuICAgICAgLy9ub3cgZ28gdGhyb3VnaCBhbmQgcGVyZm9ybSB0aGUgZW5jcnlwdGlvbiBvciBkZWNyeXB0aW9uICBcbiAgICAgIGZvciAoaT1sb29waW5nW2pdOyBpIT1lbmRsb29wOyBpKz1sb29waW5jKSB7IC8vZm9yIGVmZmljaWVuY3lcbiAgICAgICAgcmlnaHQxID0gcmlnaHQgXiBrZXlzW2ldOyBcbiAgICAgICAgcmlnaHQyID0gKChyaWdodCA+Pj4gNCkgfCAocmlnaHQgPDwgMjgpKSBeIGtleXNbaSsxXTtcbiAgICAgICAgLy90aGUgcmVzdWx0IGlzIGF0dGFpbmVkIGJ5IHBhc3NpbmcgdGhlc2UgYnl0ZXMgdGhyb3VnaCB0aGUgUyBzZWxlY3Rpb24gZnVuY3Rpb25zXG4gICAgICAgIHRlbXAgPSBsZWZ0O1xuICAgICAgICBsZWZ0ID0gcmlnaHQ7XG4gICAgICAgIHJpZ2h0ID0gdGVtcCBeIChzcGZ1bmN0aW9uMlsocmlnaHQxID4+PiAyNCkgJiAweDNmXSB8IHNwZnVuY3Rpb240WyhyaWdodDEgPj4+IDE2KSAmIDB4M2ZdXG4gICAgICAgICAgICAgIHwgc3BmdW5jdGlvbjZbKHJpZ2h0MSA+Pj4gIDgpICYgMHgzZl0gfCBzcGZ1bmN0aW9uOFtyaWdodDEgJiAweDNmXVxuICAgICAgICAgICAgICB8IHNwZnVuY3Rpb24xWyhyaWdodDIgPj4+IDI0KSAmIDB4M2ZdIHwgc3BmdW5jdGlvbjNbKHJpZ2h0MiA+Pj4gMTYpICYgMHgzZl1cbiAgICAgICAgICAgICAgfCBzcGZ1bmN0aW9uNVsocmlnaHQyID4+PiAgOCkgJiAweDNmXSB8IHNwZnVuY3Rpb243W3JpZ2h0MiAmIDB4M2ZdKTtcbiAgICAgIH1cbiAgICAgIHRlbXAgPSBsZWZ0OyBsZWZ0ID0gcmlnaHQ7IHJpZ2h0ID0gdGVtcDsgLy91bnJldmVyc2UgbGVmdCBhbmQgcmlnaHRcbiAgICB9IC8vZm9yIGVpdGhlciAxIG9yIDMgaXRlcmF0aW9uc1xuXG4gICAgLy9tb3ZlIHRoZW4gZWFjaCBvbmUgYml0IHRvIHRoZSByaWdodFxuICAgIGxlZnQgPSAoKGxlZnQgPj4+IDEpIHwgKGxlZnQgPDwgMzEpKTsgXG4gICAgcmlnaHQgPSAoKHJpZ2h0ID4+PiAxKSB8IChyaWdodCA8PCAzMSkpOyBcblxuICAgIC8vbm93IHBlcmZvcm0gSVAtMSwgd2hpY2ggaXMgSVAgaW4gdGhlIG9wcG9zaXRlIGRpcmVjdGlvblxuICAgIHRlbXAgPSAoKGxlZnQgPj4+IDEpIF4gcmlnaHQpICYgMHg1NTU1NTU1NTsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCAxKTtcbiAgICB0ZW1wID0gKChyaWdodCA+Pj4gOCkgXiBsZWZ0KSAmIDB4MDBmZjAwZmY7IGxlZnQgXj0gdGVtcDsgcmlnaHQgXj0gKHRlbXAgPDwgOCk7XG4gICAgdGVtcCA9ICgocmlnaHQgPj4+IDIpIF4gbGVmdCkgJiAweDMzMzMzMzMzOyBsZWZ0IF49IHRlbXA7IHJpZ2h0IF49ICh0ZW1wIDw8IDIpO1xuICAgIHRlbXAgPSAoKGxlZnQgPj4+IDE2KSBeIHJpZ2h0KSAmIDB4MDAwMGZmZmY7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgMTYpO1xuICAgIHRlbXAgPSAoKGxlZnQgPj4+IDQpIF4gcmlnaHQpICYgMHgwZjBmMGYwZjsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCA0KTtcblxuICAgIC8vZm9yIENpcGhlciBCbG9jayBDaGFpbmluZyBtb2RlLCB4b3IgdGhlIG1lc3NhZ2Ugd2l0aCB0aGUgcHJldmlvdXMgcmVzdWx0XG4gICAgaWYgKG1vZGUgPT0gMSkge2lmIChlbmNyeXB0KSB7Y2JjbGVmdCA9IGxlZnQ7IGNiY3JpZ2h0ID0gcmlnaHQ7fSBlbHNlIHtsZWZ0IF49IGNiY2xlZnQyOyByaWdodCBePSBjYmNyaWdodDI7fX1cbiAgICB0ZW1wcmVzdWx0ICs9IFN0cmluZy5mcm9tQ2hhckNvZGUgKChsZWZ0Pj4+MjQpLCAoKGxlZnQ+Pj4xNikgJiAweGZmKSwgKChsZWZ0Pj4+OCkgJiAweGZmKSwgKGxlZnQgJiAweGZmKSwgKHJpZ2h0Pj4+MjQpLCAoKHJpZ2h0Pj4+MTYpICYgMHhmZiksICgocmlnaHQ+Pj44KSAmIDB4ZmYpLCAocmlnaHQgJiAweGZmKSk7XG5cbiAgICBjaHVuayArPSA4O1xuICAgIGlmIChjaHVuayA9PSA1MTIpIHtyZXN1bHQgKz0gdGVtcHJlc3VsdDsgdGVtcHJlc3VsdCA9IFwiXCI7IGNodW5rID0gMDt9XG4gIH0gLy9mb3IgZXZlcnkgOCBjaGFyYWN0ZXJzLCBvciA2NCBiaXRzIGluIHRoZSBtZXNzYWdlXG5cbiAgLy9yZXR1cm4gdGhlIHJlc3VsdCBhcyBhbiBhcnJheVxuICByZXN1bHQgKz0gdGVtcHJlc3VsdDtcbiAgcmVzdWx0ID0gcmVzdWx0LnJlcGxhY2UoL1xcMCokL2csIFwiXCIpO1xuICByZXR1cm4gcmVzdWx0O1xufSAvL2VuZCBvZiBkZXNcblxuXG5cbi8vZGVzX2NyZWF0ZUtleXNcbi8vdGhpcyB0YWtlcyBhcyBpbnB1dCBhIDY0IGJpdCBrZXkgKGV2ZW4gdGhvdWdoIG9ubHkgNTYgYml0cyBhcmUgdXNlZClcbi8vYXMgYW4gYXJyYXkgb2YgMiBpbnRlZ2VycywgYW5kIHJldHVybnMgMTYgNDggYml0IGtleXNcbmZ1bmN0aW9uIGRlc19jcmVhdGVLZXlzIChrZXkpIHtcbiAgLy9kZWNsYXJpbmcgdGhpcyBsb2NhbGx5IHNwZWVkcyB0aGluZ3MgdXAgYSBiaXRcbiAgcGMyYnl0ZXMwICA9IG5ldyBBcnJheSAoMCwweDQsMHgyMDAwMDAwMCwweDIwMDAwMDA0LDB4MTAwMDAsMHgxMDAwNCwweDIwMDEwMDAwLDB4MjAwMTAwMDQsMHgyMDAsMHgyMDQsMHgyMDAwMDIwMCwweDIwMDAwMjA0LDB4MTAyMDAsMHgxMDIwNCwweDIwMDEwMjAwLDB4MjAwMTAyMDQpO1xuICBwYzJieXRlczEgID0gbmV3IEFycmF5ICgwLDB4MSwweDEwMDAwMCwweDEwMDAwMSwweDQwMDAwMDAsMHg0MDAwMDAxLDB4NDEwMDAwMCwweDQxMDAwMDEsMHgxMDAsMHgxMDEsMHgxMDAxMDAsMHgxMDAxMDEsMHg0MDAwMTAwLDB4NDAwMDEwMSwweDQxMDAxMDAsMHg0MTAwMTAxKTtcbiAgcGMyYnl0ZXMyICA9IG5ldyBBcnJheSAoMCwweDgsMHg4MDAsMHg4MDgsMHgxMDAwMDAwLDB4MTAwMDAwOCwweDEwMDA4MDAsMHgxMDAwODA4LDAsMHg4LDB4ODAwLDB4ODA4LDB4MTAwMDAwMCwweDEwMDAwMDgsMHgxMDAwODAwLDB4MTAwMDgwOCk7XG4gIHBjMmJ5dGVzMyAgPSBuZXcgQXJyYXkgKDAsMHgyMDAwMDAsMHg4MDAwMDAwLDB4ODIwMDAwMCwweDIwMDAsMHgyMDIwMDAsMHg4MDAyMDAwLDB4ODIwMjAwMCwweDIwMDAwLDB4MjIwMDAwLDB4ODAyMDAwMCwweDgyMjAwMDAsMHgyMjAwMCwweDIyMjAwMCwweDgwMjIwMDAsMHg4MjIyMDAwKTtcbiAgcGMyYnl0ZXM0ICA9IG5ldyBBcnJheSAoMCwweDQwMDAwLDB4MTAsMHg0MDAxMCwwLDB4NDAwMDAsMHgxMCwweDQwMDEwLDB4MTAwMCwweDQxMDAwLDB4MTAxMCwweDQxMDEwLDB4MTAwMCwweDQxMDAwLDB4MTAxMCwweDQxMDEwKTtcbiAgcGMyYnl0ZXM1ICA9IG5ldyBBcnJheSAoMCwweDQwMCwweDIwLDB4NDIwLDAsMHg0MDAsMHgyMCwweDQyMCwweDIwMDAwMDAsMHgyMDAwNDAwLDB4MjAwMDAyMCwweDIwMDA0MjAsMHgyMDAwMDAwLDB4MjAwMDQwMCwweDIwMDAwMjAsMHgyMDAwNDIwKTtcbiAgcGMyYnl0ZXM2ICA9IG5ldyBBcnJheSAoMCwweDEwMDAwMDAwLDB4ODAwMDAsMHgxMDA4MDAwMCwweDIsMHgxMDAwMDAwMiwweDgwMDAyLDB4MTAwODAwMDIsMCwweDEwMDAwMDAwLDB4ODAwMDAsMHgxMDA4MDAwMCwweDIsMHgxMDAwMDAwMiwweDgwMDAyLDB4MTAwODAwMDIpO1xuICBwYzJieXRlczcgID0gbmV3IEFycmF5ICgwLDB4MTAwMDAsMHg4MDAsMHgxMDgwMCwweDIwMDAwMDAwLDB4MjAwMTAwMDAsMHgyMDAwMDgwMCwweDIwMDEwODAwLDB4MjAwMDAsMHgzMDAwMCwweDIwODAwLDB4MzA4MDAsMHgyMDAyMDAwMCwweDIwMDMwMDAwLDB4MjAwMjA4MDAsMHgyMDAzMDgwMCk7XG4gIHBjMmJ5dGVzOCAgPSBuZXcgQXJyYXkgKDAsMHg0MDAwMCwwLDB4NDAwMDAsMHgyLDB4NDAwMDIsMHgyLDB4NDAwMDIsMHgyMDAwMDAwLDB4MjA0MDAwMCwweDIwMDAwMDAsMHgyMDQwMDAwLDB4MjAwMDAwMiwweDIwNDAwMDIsMHgyMDAwMDAyLDB4MjA0MDAwMik7XG4gIHBjMmJ5dGVzOSAgPSBuZXcgQXJyYXkgKDAsMHgxMDAwMDAwMCwweDgsMHgxMDAwMDAwOCwwLDB4MTAwMDAwMDAsMHg4LDB4MTAwMDAwMDgsMHg0MDAsMHgxMDAwMDQwMCwweDQwOCwweDEwMDAwNDA4LDB4NDAwLDB4MTAwMDA0MDAsMHg0MDgsMHgxMDAwMDQwOCk7XG4gIHBjMmJ5dGVzMTAgPSBuZXcgQXJyYXkgKDAsMHgyMCwwLDB4MjAsMHgxMDAwMDAsMHgxMDAwMjAsMHgxMDAwMDAsMHgxMDAwMjAsMHgyMDAwLDB4MjAyMCwweDIwMDAsMHgyMDIwLDB4MTAyMDAwLDB4MTAyMDIwLDB4MTAyMDAwLDB4MTAyMDIwKTtcbiAgcGMyYnl0ZXMxMSA9IG5ldyBBcnJheSAoMCwweDEwMDAwMDAsMHgyMDAsMHgxMDAwMjAwLDB4MjAwMDAwLDB4MTIwMDAwMCwweDIwMDIwMCwweDEyMDAyMDAsMHg0MDAwMDAwLDB4NTAwMDAwMCwweDQwMDAyMDAsMHg1MDAwMjAwLDB4NDIwMDAwMCwweDUyMDAwMDAsMHg0MjAwMjAwLDB4NTIwMDIwMCk7XG4gIHBjMmJ5dGVzMTIgPSBuZXcgQXJyYXkgKDAsMHgxMDAwLDB4ODAwMDAwMCwweDgwMDEwMDAsMHg4MDAwMCwweDgxMDAwLDB4ODA4MDAwMCwweDgwODEwMDAsMHgxMCwweDEwMTAsMHg4MDAwMDEwLDB4ODAwMTAxMCwweDgwMDEwLDB4ODEwMTAsMHg4MDgwMDEwLDB4ODA4MTAxMCk7XG4gIHBjMmJ5dGVzMTMgPSBuZXcgQXJyYXkgKDAsMHg0LDB4MTAwLDB4MTA0LDAsMHg0LDB4MTAwLDB4MTA0LDB4MSwweDUsMHgxMDEsMHgxMDUsMHgxLDB4NSwweDEwMSwweDEwNSk7XG5cbiAgLy9ob3cgbWFueSBpdGVyYXRpb25zICgxIGZvciBkZXMsIDMgZm9yIHRyaXBsZSBkZXMpXG4gIHZhciBpdGVyYXRpb25zID0ga2V5Lmxlbmd0aCA+IDggPyAzIDogMTsgLy9jaGFuZ2VkIGJ5IFBhdWwgMTYvNi8yMDA3IHRvIHVzZSBUcmlwbGUgREVTIGZvciA5KyBieXRlIGtleXNcbiAgLy9zdG9yZXMgdGhlIHJldHVybiBrZXlzXG4gIHZhciBrZXlzID0gbmV3IEFycmF5ICgzMiAqIGl0ZXJhdGlvbnMpO1xuICAvL25vdyBkZWZpbmUgdGhlIGxlZnQgc2hpZnRzIHdoaWNoIG5lZWQgdG8gYmUgZG9uZVxuICB2YXIgc2hpZnRzID0gbmV3IEFycmF5ICgwLCAwLCAxLCAxLCAxLCAxLCAxLCAxLCAwLCAxLCAxLCAxLCAxLCAxLCAxLCAwKTtcbiAgLy9vdGhlciB2YXJpYWJsZXNcbiAgdmFyIGxlZnR0ZW1wLCByaWdodHRlbXAsIG09MCwgbj0wLCB0ZW1wO1xuXG4gIGZvciAodmFyIGo9MDsgajxpdGVyYXRpb25zOyBqKyspIHsgLy9laXRoZXIgMSBvciAzIGl0ZXJhdGlvbnNcbiAgICBsZWZ0ID0gKGtleS5jaGFyQ29kZUF0KG0rKykgPDwgMjQpIHwgKGtleS5jaGFyQ29kZUF0KG0rKykgPDwgMTYpIHwgKGtleS5jaGFyQ29kZUF0KG0rKykgPDwgOCkgfCBrZXkuY2hhckNvZGVBdChtKyspO1xuICAgIHJpZ2h0ID0gKGtleS5jaGFyQ29kZUF0KG0rKykgPDwgMjQpIHwgKGtleS5jaGFyQ29kZUF0KG0rKykgPDwgMTYpIHwgKGtleS5jaGFyQ29kZUF0KG0rKykgPDwgOCkgfCBrZXkuY2hhckNvZGVBdChtKyspO1xuXG4gICAgdGVtcCA9ICgobGVmdCA+Pj4gNCkgXiByaWdodCkgJiAweDBmMGYwZjBmOyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDQpO1xuICAgIHRlbXAgPSAoKHJpZ2h0ID4+PiAtMTYpIF4gbGVmdCkgJiAweDAwMDBmZmZmOyBsZWZ0IF49IHRlbXA7IHJpZ2h0IF49ICh0ZW1wIDw8IC0xNik7XG4gICAgdGVtcCA9ICgobGVmdCA+Pj4gMikgXiByaWdodCkgJiAweDMzMzMzMzMzOyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDIpO1xuICAgIHRlbXAgPSAoKHJpZ2h0ID4+PiAtMTYpIF4gbGVmdCkgJiAweDAwMDBmZmZmOyBsZWZ0IF49IHRlbXA7IHJpZ2h0IF49ICh0ZW1wIDw8IC0xNik7XG4gICAgdGVtcCA9ICgobGVmdCA+Pj4gMSkgXiByaWdodCkgJiAweDU1NTU1NTU1OyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDEpO1xuICAgIHRlbXAgPSAoKHJpZ2h0ID4+PiA4KSBeIGxlZnQpICYgMHgwMGZmMDBmZjsgbGVmdCBePSB0ZW1wOyByaWdodCBePSAodGVtcCA8PCA4KTtcbiAgICB0ZW1wID0gKChsZWZ0ID4+PiAxKSBeIHJpZ2h0KSAmIDB4NTU1NTU1NTU7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgMSk7XG5cbiAgICAvL3RoZSByaWdodCBzaWRlIG5lZWRzIHRvIGJlIHNoaWZ0ZWQgYW5kIHRvIGdldCB0aGUgbGFzdCBmb3VyIGJpdHMgb2YgdGhlIGxlZnQgc2lkZVxuICAgIHRlbXAgPSAobGVmdCA8PCA4KSB8ICgocmlnaHQgPj4+IDIwKSAmIDB4MDAwMDAwZjApO1xuICAgIC8vbGVmdCBuZWVkcyB0byBiZSBwdXQgdXBzaWRlIGRvd25cbiAgICBsZWZ0ID0gKHJpZ2h0IDw8IDI0KSB8ICgocmlnaHQgPDwgOCkgJiAweGZmMDAwMCkgfCAoKHJpZ2h0ID4+PiA4KSAmIDB4ZmYwMCkgfCAoKHJpZ2h0ID4+PiAyNCkgJiAweGYwKTtcbiAgICByaWdodCA9IHRlbXA7XG5cbiAgICAvL25vdyBnbyB0aHJvdWdoIGFuZCBwZXJmb3JtIHRoZXNlIHNoaWZ0cyBvbiB0aGUgbGVmdCBhbmQgcmlnaHQga2V5c1xuICAgIGZvciAoaT0wOyBpIDwgc2hpZnRzLmxlbmd0aDsgaSsrKSB7XG4gICAgICAvL3NoaWZ0IHRoZSBrZXlzIGVpdGhlciBvbmUgb3IgdHdvIGJpdHMgdG8gdGhlIGxlZnRcbiAgICAgIGlmIChzaGlmdHNbaV0pIHtsZWZ0ID0gKGxlZnQgPDwgMikgfCAobGVmdCA+Pj4gMjYpOyByaWdodCA9IChyaWdodCA8PCAyKSB8IChyaWdodCA+Pj4gMjYpO31cbiAgICAgIGVsc2Uge2xlZnQgPSAobGVmdCA8PCAxKSB8IChsZWZ0ID4+PiAyNyk7IHJpZ2h0ID0gKHJpZ2h0IDw8IDEpIHwgKHJpZ2h0ID4+PiAyNyk7fVxuICAgICAgbGVmdCAmPSAtMHhmOyByaWdodCAmPSAtMHhmO1xuXG4gICAgICAvL25vdyBhcHBseSBQQy0yLCBpbiBzdWNoIGEgd2F5IHRoYXQgRSBpcyBlYXNpZXIgd2hlbiBlbmNyeXB0aW5nIG9yIGRlY3J5cHRpbmdcbiAgICAgIC8vdGhpcyBjb252ZXJzaW9uIHdpbGwgbG9vayBsaWtlIFBDLTIgZXhjZXB0IG9ubHkgdGhlIGxhc3QgNiBiaXRzIG9mIGVhY2ggYnl0ZSBhcmUgdXNlZFxuICAgICAgLy9yYXRoZXIgdGhhbiA0OCBjb25zZWN1dGl2ZSBiaXRzIGFuZCB0aGUgb3JkZXIgb2YgbGluZXMgd2lsbCBiZSBhY2NvcmRpbmcgdG8gXG4gICAgICAvL2hvdyB0aGUgUyBzZWxlY3Rpb24gZnVuY3Rpb25zIHdpbGwgYmUgYXBwbGllZDogUzIsIFM0LCBTNiwgUzgsIFMxLCBTMywgUzUsIFM3XG4gICAgICBsZWZ0dGVtcCA9IHBjMmJ5dGVzMFtsZWZ0ID4+PiAyOF0gfCBwYzJieXRlczFbKGxlZnQgPj4+IDI0KSAmIDB4Zl1cbiAgICAgICAgICAgICAgfCBwYzJieXRlczJbKGxlZnQgPj4+IDIwKSAmIDB4Zl0gfCBwYzJieXRlczNbKGxlZnQgPj4+IDE2KSAmIDB4Zl1cbiAgICAgICAgICAgICAgfCBwYzJieXRlczRbKGxlZnQgPj4+IDEyKSAmIDB4Zl0gfCBwYzJieXRlczVbKGxlZnQgPj4+IDgpICYgMHhmXVxuICAgICAgICAgICAgICB8IHBjMmJ5dGVzNlsobGVmdCA+Pj4gNCkgJiAweGZdO1xuICAgICAgcmlnaHR0ZW1wID0gcGMyYnl0ZXM3W3JpZ2h0ID4+PiAyOF0gfCBwYzJieXRlczhbKHJpZ2h0ID4+PiAyNCkgJiAweGZdXG4gICAgICAgICAgICAgICAgfCBwYzJieXRlczlbKHJpZ2h0ID4+PiAyMCkgJiAweGZdIHwgcGMyYnl0ZXMxMFsocmlnaHQgPj4+IDE2KSAmIDB4Zl1cbiAgICAgICAgICAgICAgICB8IHBjMmJ5dGVzMTFbKHJpZ2h0ID4+PiAxMikgJiAweGZdIHwgcGMyYnl0ZXMxMlsocmlnaHQgPj4+IDgpICYgMHhmXVxuICAgICAgICAgICAgICAgIHwgcGMyYnl0ZXMxM1socmlnaHQgPj4+IDQpICYgMHhmXTtcbiAgICAgIHRlbXAgPSAoKHJpZ2h0dGVtcCA+Pj4gMTYpIF4gbGVmdHRlbXApICYgMHgwMDAwZmZmZjsgXG4gICAgICBrZXlzW24rK10gPSBsZWZ0dGVtcCBeIHRlbXA7IGtleXNbbisrXSA9IHJpZ2h0dGVtcCBeICh0ZW1wIDw8IDE2KTtcbiAgICB9XG4gIH0gLy9mb3IgZWFjaCBpdGVyYXRpb25zXG4gIC8vcmV0dXJuIHRoZSBrZXlzIHdlJ3ZlIGNyZWF0ZWRcbiAgcmV0dXJuIGtleXM7XG59IC8vZW5kIG9mIGRlc19jcmVhdGVLZXlzXG5cblxubW9kdWxlLmV4cG9ydHMgPSBkZXNlZGU7XG4iLCIvKiBNb2RpZmllZCBieSBSZWN1cml0eSBMYWJzIEdtYkggXG4gKiBcbiAqIENpcGhlci5qc1xuICogQSBibG9jay1jaXBoZXIgYWxnb3JpdGhtIGltcGxlbWVudGF0aW9uIG9uIEphdmFTY3JpcHRcbiAqIFNlZSBDaXBoZXIucmVhZG1lLnR4dCBmb3IgZnVydGhlciBpbmZvcm1hdGlvbi5cbiAqXG4gKiBDb3B5cmlnaHQoYykgMjAwOSBBdHN1c2hpIE9rYSBbIGh0dHA6Ly9va2EubnUvIF1cbiAqIFRoaXMgc2NyaXB0IGZpbGUgaXMgZGlzdHJpYnV0ZWQgdW5kZXIgdGhlIExHUExcbiAqXG4gKiBBQ0tOT1dMRURHTUVOVFxuICpcbiAqICAgICBUaGUgbWFpbiBzdWJyb3V0aW5lcyBhcmUgd3JpdHRlbiBieSBNaWNoaWVsIHZhbiBFdmVyZGluZ2VuLlxuICogXG4gKiAgICAgTWljaGllbCB2YW4gRXZlcmRpbmdlblxuICogICAgIGh0dHA6Ly9ob21lLnZlcnNhdGVsLm5sL01BdmFuRXZlcmRpbmdlbi9pbmRleC5odG1sXG4gKiBcbiAqICAgICBBbGwgcmlnaHRzIGZvciB0aGVzZSByb3V0aW5lcyBhcmUgcmVzZXJ2ZWQgdG8gTWljaGllbCB2YW4gRXZlcmRpbmdlbi5cbiAqXG4gKi9cblxuLy8gYWRkZWQgYnkgUmVjdXJpdHkgTGFic1xuZnVuY3Rpb24gVEZlbmNyeXB0KGJsb2NrLCBrZXkpIHtcblx0dmFyIGJsb2NrX2NvcHkgPSBbXS5jb25jYXQoYmxvY2spO1xuXHR2YXIgdGYgPSBjcmVhdGVUd29maXNoKCk7XG5cdHRmLm9wZW4odXRpbC5zdHIyYmluKGtleSksMCk7XG5cdHZhciByZXN1bHQgPSB0Zi5lbmNyeXB0KGJsb2NrX2NvcHksIDApO1xuXHR0Zi5jbG9zZSgpO1xuXHRyZXR1cm4gcmVzdWx0O1xufVxuXG4vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9cbi8vTWF0aFxuLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vXG5cbnZhciBNQVhJTlQgPSAweEZGRkZGRkZGO1xuXG5mdW5jdGlvbiByb3RiKGIsbil7IHJldHVybiAoIGI8PG4gfCBiPj4+KCA4LW4pICkgJiAweEZGOyB9XG5mdW5jdGlvbiByb3R3KHcsbil7IHJldHVybiAoIHc8PG4gfCB3Pj4+KDMyLW4pICkgJiBNQVhJTlQ7IH1cbmZ1bmN0aW9uIGdldFcoYSxpKXsgcmV0dXJuIGFbaV18YVtpKzFdPDw4fGFbaSsyXTw8MTZ8YVtpKzNdPDwyNDsgfVxuZnVuY3Rpb24gc2V0VyhhLGksdyl7IGEuc3BsaWNlKGksNCx3JjB4RkYsKHc+Pj44KSYweEZGLCh3Pj4+MTYpJjB4RkYsKHc+Pj4yNCkmMHhGRik7IH1cbmZ1bmN0aW9uIHNldFdJbnYoYSxpLHcpeyBhLnNwbGljZShpLDQsKHc+Pj4yNCkmMHhGRiwodz4+PjE2KSYweEZGLCh3Pj4+OCkmMHhGRix3JjB4RkYpOyB9XG5mdW5jdGlvbiBnZXRCKHgsbil7IHJldHVybiAoeD4+PihuKjgpKSYweEZGOyB9XG5cbmZ1bmN0aW9uIGdldE5yQml0cyhpKXsgdmFyIG49MDsgd2hpbGUgKGk+MCl7IG4rKzsgaT4+Pj0xOyB9IHJldHVybiBuOyB9XG5mdW5jdGlvbiBnZXRNYXNrKG4peyByZXR1cm4gKDE8PG4pLTE7IH1cblxuLy9hZGRlZCAyMDA4LzExLzEzIFhYWCBNVVNUIFVTRSBPTkUtV0FZIEhBU0ggRlVOQ1RJT04gRk9SIFNFQ1VSSVRZIFJFQVNPTlxuZnVuY3Rpb24gcmFuZEJ5dGUoKSB7XG4gcmV0dXJuIE1hdGguZmxvb3IoIE1hdGgucmFuZG9tKCkgKiAyNTYgKTtcbn1cbi8vIC8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9cbi8vIFR3b2Zpc2hcbi8vIC8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy9cblxuZnVuY3Rpb24gY3JlYXRlVHdvZmlzaCgpIHtcblx0Ly9cblx0dmFyIGtleUJ5dGVzID0gbnVsbDtcblx0dmFyIGRhdGFCeXRlcyA9IG51bGw7XG5cdHZhciBkYXRhT2Zmc2V0ID0gLTE7XG5cdC8vIHZhciBkYXRhTGVuZ3RoID0gLTE7XG5cdHZhciBhbGdvcml0aG1OYW1lID0gbnVsbDtcblx0Ly8gdmFyIGlkeDIgPSAtMTtcblx0Ly9cblxuXHRhbGdvcml0aG1OYW1lID0gXCJ0d29maXNoXCI7XG5cblx0dmFyIHRmc0tleSA9IFtdO1xuXHR2YXIgdGZzTSA9IFsgW10sIFtdLCBbXSwgW10gXTtcblxuXHRmdW5jdGlvbiB0ZnNJbml0KGtleSkge1xuXHRcdGtleUJ5dGVzID0ga2V5O1xuXHRcdHZhciBpLCBhLCBiLCBjLCBkLCBtZUtleSA9IFtdLCBtb0tleSA9IFtdLCBpbktleSA9IFtdO1xuXHRcdHZhciBrTGVuO1xuXHRcdHZhciBzS2V5ID0gW107XG5cdFx0dmFyIGYwMSwgZjViLCBmZWY7XG5cblx0XHR2YXIgcTAgPSBbIFsgOCwgMSwgNywgMTMsIDYsIDE1LCAzLCAyLCAwLCAxMSwgNSwgOSwgMTQsIDEyLCAxMCwgNCBdLFxuXHRcdFx0XHRbIDIsIDgsIDExLCAxMywgMTUsIDcsIDYsIDE0LCAzLCAxLCA5LCA0LCAwLCAxMCwgMTIsIDUgXSBdO1xuXHRcdHZhciBxMSA9IFsgWyAxNCwgMTIsIDExLCA4LCAxLCAyLCAzLCA1LCAxNSwgNCwgMTAsIDYsIDcsIDAsIDksIDEzIF0sXG5cdFx0XHRcdFsgMSwgMTQsIDIsIDExLCA0LCAxMiwgMywgNywgNiwgMTMsIDEwLCA1LCAxNSwgOSwgMCwgOCBdIF07XG5cdFx0dmFyIHEyID0gWyBbIDExLCAxMCwgNSwgMTQsIDYsIDEzLCA5LCAwLCAxMiwgOCwgMTUsIDMsIDIsIDQsIDcsIDEgXSxcblx0XHRcdFx0WyA0LCAxMiwgNywgNSwgMSwgNiwgOSwgMTAsIDAsIDE0LCAxMywgOCwgMiwgMTEsIDMsIDE1IF0gXTtcblx0XHR2YXIgcTMgPSBbIFsgMTMsIDcsIDE1LCA0LCAxLCAyLCA2LCAxNCwgOSwgMTEsIDMsIDAsIDgsIDUsIDEyLCAxMCBdLFxuXHRcdFx0XHRbIDExLCA5LCA1LCAxLCAxMiwgMywgMTMsIDE0LCA2LCA0LCA3LCAxNSwgMiwgMCwgOCwgMTAgXSBdO1xuXHRcdHZhciByb3I0ID0gWyAwLCA4LCAxLCA5LCAyLCAxMCwgMywgMTEsIDQsIDEyLCA1LCAxMywgNiwgMTQsIDcsIDE1IF07XG5cdFx0dmFyIGFzaHggPSBbIDAsIDksIDIsIDExLCA0LCAxMywgNiwgMTUsIDgsIDEsIDEwLCAzLCAxMiwgNSwgMTQsIDcgXTtcblx0XHR2YXIgcSA9IFsgW10sIFtdIF07XG5cdFx0dmFyIG0gPSBbIFtdLCBbXSwgW10sIFtdIF07XG5cblx0XHRmdW5jdGlvbiBmZm01Yih4KSB7XG5cdFx0XHRyZXR1cm4geCBeICh4ID4+IDIpIF4gWyAwLCA5MCwgMTgwLCAyMzggXVt4ICYgM107XG5cdFx0fVxuXHRcdGZ1bmN0aW9uIGZmbUVmKHgpIHtcblx0XHRcdHJldHVybiB4IF4gKHggPj4gMSkgXiAoeCA+PiAyKSBeIFsgMCwgMjM4LCAxODAsIDkwIF1beCAmIDNdO1xuXHRcdH1cblxuXHRcdGZ1bmN0aW9uIG1kc1JlbShwLCBxKSB7XG5cdFx0XHR2YXIgaSwgdCwgdTtcblx0XHRcdGZvciAoaSA9IDA7IGkgPCA4OyBpKyspIHtcblx0XHRcdFx0dCA9IHEgPj4+IDI0O1xuXHRcdFx0XHRxID0gKChxIDw8IDgpICYgTUFYSU5UKSB8IHAgPj4+IDI0O1xuXHRcdFx0XHRwID0gKHAgPDwgOCkgJiBNQVhJTlQ7XG5cdFx0XHRcdHUgPSB0IDw8IDE7XG5cdFx0XHRcdGlmICh0ICYgMTI4KSB7XG5cdFx0XHRcdFx0dSBePSAzMzM7XG5cdFx0XHRcdH1cblx0XHRcdFx0cSBePSB0IF4gKHUgPDwgMTYpO1xuXHRcdFx0XHR1IF49IHQgPj4+IDE7XG5cdFx0XHRcdGlmICh0ICYgMSkge1xuXHRcdFx0XHRcdHUgXj0gMTY2O1xuXHRcdFx0XHR9XG5cdFx0XHRcdHEgXj0gdSA8PCAyNCB8IHUgPDwgODtcblx0XHRcdH1cblx0XHRcdHJldHVybiBxO1xuXHRcdH1cblxuXHRcdGZ1bmN0aW9uIHFwKG4sIHgpIHtcblx0XHRcdHZhciBhLCBiLCBjLCBkO1xuXHRcdFx0YSA9IHggPj4gNDtcblx0XHRcdGIgPSB4ICYgMTU7XG5cdFx0XHRjID0gcTBbbl1bYSBeIGJdO1xuXHRcdFx0ZCA9IHExW25dW3JvcjRbYl0gXiBhc2h4W2FdXTtcblx0XHRcdHJldHVybiBxM1tuXVtyb3I0W2RdIF4gYXNoeFtjXV0gPDwgNCB8IHEyW25dW2MgXiBkXTtcblx0XHR9XG5cblx0XHRmdW5jdGlvbiBoRnVuKHgsIGtleSkge1xuXHRcdFx0dmFyIGEgPSBnZXRCKHgsIDApLCBiID0gZ2V0Qih4LCAxKSwgYyA9IGdldEIoeCwgMiksIGQgPSBnZXRCKHgsIDMpO1xuXHRcdFx0c3dpdGNoIChrTGVuKSB7XG5cdFx0XHRjYXNlIDQ6XG5cdFx0XHRcdGEgPSBxWzFdW2FdIF4gZ2V0QihrZXlbM10sIDApO1xuXHRcdFx0XHRiID0gcVswXVtiXSBeIGdldEIoa2V5WzNdLCAxKTtcblx0XHRcdFx0YyA9IHFbMF1bY10gXiBnZXRCKGtleVszXSwgMik7XG5cdFx0XHRcdGQgPSBxWzFdW2RdIF4gZ2V0QihrZXlbM10sIDMpO1xuXHRcdFx0Y2FzZSAzOlxuXHRcdFx0XHRhID0gcVsxXVthXSBeIGdldEIoa2V5WzJdLCAwKTtcblx0XHRcdFx0YiA9IHFbMV1bYl0gXiBnZXRCKGtleVsyXSwgMSk7XG5cdFx0XHRcdGMgPSBxWzBdW2NdIF4gZ2V0QihrZXlbMl0sIDIpO1xuXHRcdFx0XHRkID0gcVswXVtkXSBeIGdldEIoa2V5WzJdLCAzKTtcblx0XHRcdGNhc2UgMjpcblx0XHRcdFx0YSA9IHFbMF1bcVswXVthXSBeIGdldEIoa2V5WzFdLCAwKV0gXiBnZXRCKGtleVswXSwgMCk7XG5cdFx0XHRcdGIgPSBxWzBdW3FbMV1bYl0gXiBnZXRCKGtleVsxXSwgMSldIF4gZ2V0QihrZXlbMF0sIDEpO1xuXHRcdFx0XHRjID0gcVsxXVtxWzBdW2NdIF4gZ2V0QihrZXlbMV0sIDIpXSBeIGdldEIoa2V5WzBdLCAyKTtcblx0XHRcdFx0ZCA9IHFbMV1bcVsxXVtkXSBeIGdldEIoa2V5WzFdLCAzKV0gXiBnZXRCKGtleVswXSwgMyk7XG5cdFx0XHR9XG5cdFx0XHRyZXR1cm4gbVswXVthXSBeIG1bMV1bYl0gXiBtWzJdW2NdIF4gbVszXVtkXTtcblx0XHR9XG5cblx0XHRrZXlCeXRlcyA9IGtleUJ5dGVzLnNsaWNlKDAsIDMyKTtcblx0XHRpID0ga2V5Qnl0ZXMubGVuZ3RoO1xuXHRcdHdoaWxlIChpICE9IDE2ICYmIGkgIT0gMjQgJiYgaSAhPSAzMilcblx0XHRcdGtleUJ5dGVzW2krK10gPSAwO1xuXG5cdFx0Zm9yIChpID0gMDsgaSA8IGtleUJ5dGVzLmxlbmd0aDsgaSArPSA0KSB7XG5cdFx0XHRpbktleVtpID4+IDJdID0gZ2V0VyhrZXlCeXRlcywgaSk7XG5cdFx0fVxuXHRcdGZvciAoaSA9IDA7IGkgPCAyNTY7IGkrKykge1xuXHRcdFx0cVswXVtpXSA9IHFwKDAsIGkpO1xuXHRcdFx0cVsxXVtpXSA9IHFwKDEsIGkpO1xuXHRcdH1cblx0XHRmb3IgKGkgPSAwOyBpIDwgMjU2OyBpKyspIHtcblx0XHRcdGYwMSA9IHFbMV1baV07XG5cdFx0XHRmNWIgPSBmZm01YihmMDEpO1xuXHRcdFx0ZmVmID0gZmZtRWYoZjAxKTtcblx0XHRcdG1bMF1baV0gPSBmMDEgKyAoZjViIDw8IDgpICsgKGZlZiA8PCAxNikgKyAoZmVmIDw8IDI0KTtcblx0XHRcdG1bMl1baV0gPSBmNWIgKyAoZmVmIDw8IDgpICsgKGYwMSA8PCAxNikgKyAoZmVmIDw8IDI0KTtcblx0XHRcdGYwMSA9IHFbMF1baV07XG5cdFx0XHRmNWIgPSBmZm01YihmMDEpO1xuXHRcdFx0ZmVmID0gZmZtRWYoZjAxKTtcblx0XHRcdG1bMV1baV0gPSBmZWYgKyAoZmVmIDw8IDgpICsgKGY1YiA8PCAxNikgKyAoZjAxIDw8IDI0KTtcblx0XHRcdG1bM11baV0gPSBmNWIgKyAoZjAxIDw8IDgpICsgKGZlZiA8PCAxNikgKyAoZjViIDw8IDI0KTtcblx0XHR9XG5cblx0XHRrTGVuID0gaW5LZXkubGVuZ3RoIC8gMjtcblx0XHRmb3IgKGkgPSAwOyBpIDwga0xlbjsgaSsrKSB7XG5cdFx0XHRhID0gaW5LZXlbaSArIGldO1xuXHRcdFx0bWVLZXlbaV0gPSBhO1xuXHRcdFx0YiA9IGluS2V5W2kgKyBpICsgMV07XG5cdFx0XHRtb0tleVtpXSA9IGI7XG5cdFx0XHRzS2V5W2tMZW4gLSBpIC0gMV0gPSBtZHNSZW0oYSwgYik7XG5cdFx0fVxuXHRcdGZvciAoaSA9IDA7IGkgPCA0MDsgaSArPSAyKSB7XG5cdFx0XHRhID0gMHgxMDEwMTAxICogaTtcblx0XHRcdGIgPSBhICsgMHgxMDEwMTAxO1xuXHRcdFx0YSA9IGhGdW4oYSwgbWVLZXkpO1xuXHRcdFx0YiA9IHJvdHcoaEZ1bihiLCBtb0tleSksIDgpO1xuXHRcdFx0dGZzS2V5W2ldID0gKGEgKyBiKSAmIE1BWElOVDtcblx0XHRcdHRmc0tleVtpICsgMV0gPSByb3R3KGEgKyAyICogYiwgOSk7XG5cdFx0fVxuXHRcdGZvciAoaSA9IDA7IGkgPCAyNTY7IGkrKykge1xuXHRcdFx0YSA9IGIgPSBjID0gZCA9IGk7XG5cdFx0XHRzd2l0Y2ggKGtMZW4pIHtcblx0XHRcdGNhc2UgNDpcblx0XHRcdFx0YSA9IHFbMV1bYV0gXiBnZXRCKHNLZXlbM10sIDApO1xuXHRcdFx0XHRiID0gcVswXVtiXSBeIGdldEIoc0tleVszXSwgMSk7XG5cdFx0XHRcdGMgPSBxWzBdW2NdIF4gZ2V0QihzS2V5WzNdLCAyKTtcblx0XHRcdFx0ZCA9IHFbMV1bZF0gXiBnZXRCKHNLZXlbM10sIDMpO1xuXHRcdFx0Y2FzZSAzOlxuXHRcdFx0XHRhID0gcVsxXVthXSBeIGdldEIoc0tleVsyXSwgMCk7XG5cdFx0XHRcdGIgPSBxWzFdW2JdIF4gZ2V0QihzS2V5WzJdLCAxKTtcblx0XHRcdFx0YyA9IHFbMF1bY10gXiBnZXRCKHNLZXlbMl0sIDIpO1xuXHRcdFx0XHRkID0gcVswXVtkXSBeIGdldEIoc0tleVsyXSwgMyk7XG5cdFx0XHRjYXNlIDI6XG5cdFx0XHRcdHRmc01bMF1baV0gPSBtWzBdW3FbMF1bcVswXVthXSBeIGdldEIoc0tleVsxXSwgMCldXG5cdFx0XHRcdFx0XHReIGdldEIoc0tleVswXSwgMCldO1xuXHRcdFx0XHR0ZnNNWzFdW2ldID0gbVsxXVtxWzBdW3FbMV1bYl0gXiBnZXRCKHNLZXlbMV0sIDEpXVxuXHRcdFx0XHRcdFx0XiBnZXRCKHNLZXlbMF0sIDEpXTtcblx0XHRcdFx0dGZzTVsyXVtpXSA9IG1bMl1bcVsxXVtxWzBdW2NdIF4gZ2V0QihzS2V5WzFdLCAyKV1cblx0XHRcdFx0XHRcdF4gZ2V0QihzS2V5WzBdLCAyKV07XG5cdFx0XHRcdHRmc01bM11baV0gPSBtWzNdW3FbMV1bcVsxXVtkXSBeIGdldEIoc0tleVsxXSwgMyldXG5cdFx0XHRcdFx0XHReIGdldEIoc0tleVswXSwgMyldO1xuXHRcdFx0fVxuXHRcdH1cblx0fVxuXG5cdGZ1bmN0aW9uIHRmc0cwKHgpIHtcblx0XHRyZXR1cm4gdGZzTVswXVtnZXRCKHgsIDApXSBeIHRmc01bMV1bZ2V0Qih4LCAxKV0gXiB0ZnNNWzJdW2dldEIoeCwgMildXG5cdFx0XHRcdF4gdGZzTVszXVtnZXRCKHgsIDMpXTtcblx0fVxuXHRmdW5jdGlvbiB0ZnNHMSh4KSB7XG5cdFx0cmV0dXJuIHRmc01bMF1bZ2V0Qih4LCAzKV0gXiB0ZnNNWzFdW2dldEIoeCwgMCldIF4gdGZzTVsyXVtnZXRCKHgsIDEpXVxuXHRcdFx0XHReIHRmc01bM11bZ2V0Qih4LCAyKV07XG5cdH1cblxuXHRmdW5jdGlvbiB0ZnNGcm5kKHIsIGJsaykge1xuXHRcdHZhciBhID0gdGZzRzAoYmxrWzBdKTtcblx0XHR2YXIgYiA9IHRmc0cxKGJsa1sxXSk7XG5cdFx0YmxrWzJdID0gcm90dyhibGtbMl0gXiAoYSArIGIgKyB0ZnNLZXlbNCAqIHIgKyA4XSkgJiBNQVhJTlQsIDMxKTtcblx0XHRibGtbM10gPSByb3R3KGJsa1szXSwgMSkgXiAoYSArIDIgKiBiICsgdGZzS2V5WzQgKiByICsgOV0pICYgTUFYSU5UO1xuXHRcdGEgPSB0ZnNHMChibGtbMl0pO1xuXHRcdGIgPSB0ZnNHMShibGtbM10pO1xuXHRcdGJsa1swXSA9IHJvdHcoYmxrWzBdIF4gKGEgKyBiICsgdGZzS2V5WzQgKiByICsgMTBdKSAmIE1BWElOVCwgMzEpO1xuXHRcdGJsa1sxXSA9IHJvdHcoYmxrWzFdLCAxKSBeIChhICsgMiAqIGIgKyB0ZnNLZXlbNCAqIHIgKyAxMV0pICYgTUFYSU5UO1xuXHR9XG5cblx0ZnVuY3Rpb24gdGZzSXJuZChpLCBibGspIHtcblx0XHR2YXIgYSA9IHRmc0cwKGJsa1swXSk7XG5cdFx0dmFyIGIgPSB0ZnNHMShibGtbMV0pO1xuXHRcdGJsa1syXSA9IHJvdHcoYmxrWzJdLCAxKSBeIChhICsgYiArIHRmc0tleVs0ICogaSArIDEwXSkgJiBNQVhJTlQ7XG5cdFx0YmxrWzNdID0gcm90dyhibGtbM10gXiAoYSArIDIgKiBiICsgdGZzS2V5WzQgKiBpICsgMTFdKSAmIE1BWElOVCwgMzEpO1xuXHRcdGEgPSB0ZnNHMChibGtbMl0pO1xuXHRcdGIgPSB0ZnNHMShibGtbM10pO1xuXHRcdGJsa1swXSA9IHJvdHcoYmxrWzBdLCAxKSBeIChhICsgYiArIHRmc0tleVs0ICogaSArIDhdKSAmIE1BWElOVDtcblx0XHRibGtbMV0gPSByb3R3KGJsa1sxXSBeIChhICsgMiAqIGIgKyB0ZnNLZXlbNCAqIGkgKyA5XSkgJiBNQVhJTlQsIDMxKTtcblx0fVxuXG5cdGZ1bmN0aW9uIHRmc0Nsb3NlKCkge1xuXHRcdHRmc0tleSA9IFtdO1xuXHRcdHRmc00gPSBbIFtdLCBbXSwgW10sIFtdIF07XG5cdH1cblxuXHRmdW5jdGlvbiB0ZnNFbmNyeXB0KGRhdGEsIG9mZnNldCkge1xuXHRcdGRhdGFCeXRlcyA9IGRhdGE7XG5cdFx0ZGF0YU9mZnNldCA9IG9mZnNldDtcblx0XHR2YXIgYmxrID0gWyBnZXRXKGRhdGFCeXRlcywgZGF0YU9mZnNldCkgXiB0ZnNLZXlbMF0sXG5cdFx0XHRcdGdldFcoZGF0YUJ5dGVzLCBkYXRhT2Zmc2V0ICsgNCkgXiB0ZnNLZXlbMV0sXG5cdFx0XHRcdGdldFcoZGF0YUJ5dGVzLCBkYXRhT2Zmc2V0ICsgOCkgXiB0ZnNLZXlbMl0sXG5cdFx0XHRcdGdldFcoZGF0YUJ5dGVzLCBkYXRhT2Zmc2V0ICsgMTIpIF4gdGZzS2V5WzNdIF07XG5cdFx0Zm9yICggdmFyIGogPSAwOyBqIDwgODsgaisrKSB7XG5cdFx0XHR0ZnNGcm5kKGosIGJsayk7XG5cdFx0fVxuXHRcdHNldFcoZGF0YUJ5dGVzLCBkYXRhT2Zmc2V0LCBibGtbMl0gXiB0ZnNLZXlbNF0pO1xuXHRcdHNldFcoZGF0YUJ5dGVzLCBkYXRhT2Zmc2V0ICsgNCwgYmxrWzNdIF4gdGZzS2V5WzVdKTtcblx0XHRzZXRXKGRhdGFCeXRlcywgZGF0YU9mZnNldCArIDgsIGJsa1swXSBeIHRmc0tleVs2XSk7XG5cdFx0c2V0VyhkYXRhQnl0ZXMsIGRhdGFPZmZzZXQgKyAxMiwgYmxrWzFdIF4gdGZzS2V5WzddKTtcblx0XHRkYXRhT2Zmc2V0ICs9IDE2O1xuXHRcdHJldHVybiBkYXRhQnl0ZXM7XG5cdH1cblxuXHRmdW5jdGlvbiB0ZnNEZWNyeXB0KGRhdGEsIG9mZnNldCkge1xuXHRcdGRhdGFCeXRlcyA9IGRhdGE7XG5cdFx0ZGF0YU9mZnNldCA9IG9mZnNldDtcblx0XHR2YXIgYmxrID0gWyBnZXRXKGRhdGFCeXRlcywgZGF0YU9mZnNldCkgXiB0ZnNLZXlbNF0sXG5cdFx0XHRcdGdldFcoZGF0YUJ5dGVzLCBkYXRhT2Zmc2V0ICsgNCkgXiB0ZnNLZXlbNV0sXG5cdFx0XHRcdGdldFcoZGF0YUJ5dGVzLCBkYXRhT2Zmc2V0ICsgOCkgXiB0ZnNLZXlbNl0sXG5cdFx0XHRcdGdldFcoZGF0YUJ5dGVzLCBkYXRhT2Zmc2V0ICsgMTIpIF4gdGZzS2V5WzddIF07XG5cdFx0Zm9yICggdmFyIGogPSA3OyBqID49IDA7IGotLSkge1xuXHRcdFx0dGZzSXJuZChqLCBibGspO1xuXHRcdH1cblx0XHRzZXRXKGRhdGFCeXRlcywgZGF0YU9mZnNldCwgYmxrWzJdIF4gdGZzS2V5WzBdKTtcblx0XHRzZXRXKGRhdGFCeXRlcywgZGF0YU9mZnNldCArIDQsIGJsa1szXSBeIHRmc0tleVsxXSk7XG5cdFx0c2V0VyhkYXRhQnl0ZXMsIGRhdGFPZmZzZXQgKyA4LCBibGtbMF0gXiB0ZnNLZXlbMl0pO1xuXHRcdHNldFcoZGF0YUJ5dGVzLCBkYXRhT2Zmc2V0ICsgMTIsIGJsa1sxXSBeIHRmc0tleVszXSk7XG5cdFx0ZGF0YU9mZnNldCArPSAxNjtcblx0fVxuXHRcblx0Ly8gYWRkZWQgYnkgUmVjdXJpdHkgTGFic1xuXHRmdW5jdGlvbiB0ZnNGaW5hbCgpIHtcblx0XHRyZXR1cm4gZGF0YUJ5dGVzO1xuXHR9XG5cblx0cmV0dXJuIHtcblx0XHRuYW1lIDogXCJ0d29maXNoXCIsXG5cdFx0YmxvY2tzaXplIDogMTI4IC8gOCxcblx0XHRvcGVuIDogdGZzSW5pdCxcblx0XHRjbG9zZSA6IHRmc0Nsb3NlLFxuXHRcdGVuY3J5cHQgOiB0ZnNFbmNyeXB0LFxuXHRcdGRlY3J5cHQgOiB0ZnNEZWNyeXB0LFxuXHRcdC8vIGFkZGVkIGJ5IFJlY3VyaXR5IExhYnNcblx0XHRmaW5hbGl6ZTogdGZzRmluYWxcblx0fTtcbn1cblxubW9kdWxlLmV4cG9ydHMgPSBURmVuY3J5cHQ7XG4iLCJcclxuLy8gVXNlIG9mIHRoaXMgc291cmNlIGNvZGUgaXMgZ292ZXJuZWQgYnkgYSBCU0Qtc3R5bGVcclxuLy8gbGljZW5zZSB0aGF0IGNhbiBiZSBmb3VuZCBpbiB0aGUgTElDRU5TRSBmaWxlLlxyXG5cclxuLy8gQ29weXJpZ2h0IDIwMTAgcGphY29ic0B4ZWVrci5jb20gLiBBbGwgcmlnaHRzIHJlc2VydmVkLlxyXG5cclxuLy8gTW9kaWZpZWQgYnkgUmVjdXJpdHkgTGFicyBHbWJIXHJcblxyXG4vLyBmaXhlZC9tb2RpZmllZCBieSBIZXJiZXJ0IEhhbmV3aW5rZWwsIHd3dy5oYW5lV0lOLmRlXHJcbi8vIGNoZWNrIHd3dy5oYW5lV0lOLmRlIGZvciB0aGUgbGF0ZXN0IHZlcnNpb25cclxuXHJcbi8vIGNhc3Q1LmpzIGlzIGEgSmF2YXNjcmlwdCBpbXBsZW1lbnRhdGlvbiBvZiBDQVNULTEyOCwgYXMgZGVmaW5lZCBpbiBSRkMgMjE0NC5cclxuLy8gQ0FTVC0xMjggaXMgYSBjb21tb24gT3BlblBHUCBjaXBoZXIuXHJcblxyXG5cclxuLy8gQ0FTVDUgY29uc3RydWN0b3JcclxuXHJcbmZ1bmN0aW9uIGNhc3Q1X2VuY3J5cHQoYmxvY2ssIGtleSkge1xyXG5cdHZhciBjYXN0NSA9IG5ldyBvcGVucGdwX3N5bWVuY19jYXN0NSgpO1xyXG5cdGNhc3Q1LnNldEtleSh1dGlsLnN0cjJiaW4oa2V5KSk7XHJcblx0cmV0dXJuIGNhc3Q1LmVuY3J5cHQoYmxvY2spO1xyXG59XHJcblxyXG5mdW5jdGlvbiBvcGVucGdwX3N5bWVuY19jYXN0NSgpIHtcclxuXHR0aGlzLkJsb2NrU2l6ZT0gODtcclxuXHR0aGlzLktleVNpemUgPSAxNjtcclxuXHJcblx0dGhpcy5zZXRLZXkgPSBmdW5jdGlvbiAoa2V5KSB7XHJcblx0XHQgdGhpcy5tYXNraW5nID0gbmV3IEFycmF5KDE2KTtcclxuXHRcdCB0aGlzLnJvdGF0ZSA9IG5ldyBBcnJheSgxNik7XHJcblxyXG5cdFx0IHRoaXMucmVzZXQoKTtcclxuXHJcblx0XHQgaWYgKGtleS5sZW5ndGggPT0gdGhpcy5LZXlTaXplKVxyXG5cdFx0IHtcclxuXHRcdCAgIHRoaXMua2V5U2NoZWR1bGUoa2V5KTtcclxuXHRcdCB9XHJcblx0XHQgZWxzZVxyXG5cdFx0IHtcclxuXHRcdCAgIHV0aWwucHJpbnRfZXJyb3IoJ2Nhc3Q1LmpzOiBDQVNULTEyODoga2V5cyBtdXN0IGJlIDE2IGJ5dGVzJyk7XHJcblx0XHQgICByZXR1cm4gZmFsc2U7XHJcblx0XHQgfVxyXG5cdFx0IHJldHVybiB0cnVlO1xyXG5cdH07XHJcblx0XHJcblx0dGhpcy5yZXNldCA9IGZ1bmN0aW9uKCkge1xyXG5cdFx0IGZvciAodmFyIGkgPSAwOyBpIDwgMTY7IGkrKylcclxuXHRcdCB7XHJcblx0XHQgIHRoaXMubWFza2luZ1tpXSA9IDA7XHJcblx0XHQgIHRoaXMucm90YXRlW2ldID0gMDtcclxuXHRcdCB9XHJcblx0fTtcclxuXHJcblx0dGhpcy5nZXRCbG9ja1NpemUgPSBmdW5jdGlvbigpIHtcclxuXHRcdCByZXR1cm4gQmxvY2tTaXplO1xyXG5cdH07XHJcblxyXG5cdHRoaXMuZW5jcnlwdCA9IGZ1bmN0aW9uKHNyYykge1xyXG5cdFx0IHZhciBkc3QgPSBuZXcgQXJyYXkoc3JjLmxlbmd0aCk7XHJcblxyXG5cdFx0IGZvcih2YXIgaSA9IDA7IGkgPCBzcmMubGVuZ3RoOyBpKz04KVxyXG5cdFx0IHtcclxuXHRcdCAgdmFyIGwgPSBzcmNbaV08PDI0IHwgc3JjW2krMV08PDE2IHwgc3JjW2krMl08PDggfCBzcmNbaSszXTtcclxuXHRcdCAgdmFyIHIgPSBzcmNbaSs0XTw8MjQgfCBzcmNbaSs1XTw8MTYgfCBzcmNbaSs2XTw8OCB8IHNyY1tpKzddO1xyXG5cdFx0ICB2YXIgdDtcclxuXHJcblx0XHQgIHQgPSByOyByID0gbF5mMShyLCB0aGlzLm1hc2tpbmdbMF0sIHRoaXMucm90YXRlWzBdKTsgbCA9IHQ7XHJcblx0XHQgIHQgPSByOyByID0gbF5mMihyLCB0aGlzLm1hc2tpbmdbMV0sIHRoaXMucm90YXRlWzFdKTsgbCA9IHQ7XHJcblx0XHQgIHQgPSByOyByID0gbF5mMyhyLCB0aGlzLm1hc2tpbmdbMl0sIHRoaXMucm90YXRlWzJdKTsgbCA9IHQ7XHJcblx0XHQgIHQgPSByOyByID0gbF5mMShyLCB0aGlzLm1hc2tpbmdbM10sIHRoaXMucm90YXRlWzNdKTsgbCA9IHQ7XHJcblxyXG5cdFx0ICB0ID0gcjsgciA9IGxeZjIociwgdGhpcy5tYXNraW5nWzRdLCB0aGlzLnJvdGF0ZVs0XSk7IGwgPSB0O1xyXG5cdFx0ICB0ID0gcjsgciA9IGxeZjMociwgdGhpcy5tYXNraW5nWzVdLCB0aGlzLnJvdGF0ZVs1XSk7IGwgPSB0O1xyXG5cdFx0ICB0ID0gcjsgciA9IGxeZjEociwgdGhpcy5tYXNraW5nWzZdLCB0aGlzLnJvdGF0ZVs2XSk7IGwgPSB0O1xyXG5cdFx0ICB0ID0gcjsgciA9IGxeZjIociwgdGhpcy5tYXNraW5nWzddLCB0aGlzLnJvdGF0ZVs3XSk7IGwgPSB0O1xyXG5cclxuXHRcdCAgdCA9IHI7IHIgPSBsXmYzKHIsIHRoaXMubWFza2luZ1s4XSwgdGhpcy5yb3RhdGVbOF0pOyBsID0gdDtcclxuXHRcdCAgdCA9IHI7IHIgPSBsXmYxKHIsIHRoaXMubWFza2luZ1s5XSwgdGhpcy5yb3RhdGVbOV0pOyBsID0gdDtcclxuXHRcdCAgdCA9IHI7IHIgPSBsXmYyKHIsIHRoaXMubWFza2luZ1sxMF0sIHRoaXMucm90YXRlWzEwXSk7IGwgPSB0O1xyXG5cdFx0ICB0ID0gcjsgciA9IGxeZjMociwgdGhpcy5tYXNraW5nWzExXSwgdGhpcy5yb3RhdGVbMTFdKTsgbCA9IHQ7XHJcblxyXG5cdFx0ICB0ID0gcjsgciA9IGxeZjEociwgdGhpcy5tYXNraW5nWzEyXSwgdGhpcy5yb3RhdGVbMTJdKTsgbCA9IHQ7XHJcblx0XHQgIHQgPSByOyByID0gbF5mMihyLCB0aGlzLm1hc2tpbmdbMTNdLCB0aGlzLnJvdGF0ZVsxM10pOyBsID0gdDtcclxuXHRcdCAgdCA9IHI7IHIgPSBsXmYzKHIsIHRoaXMubWFza2luZ1sxNF0sIHRoaXMucm90YXRlWzE0XSk7IGwgPSB0O1xyXG5cdFx0ICB0ID0gcjsgciA9IGxeZjEociwgdGhpcy5tYXNraW5nWzE1XSwgdGhpcy5yb3RhdGVbMTVdKTsgbCA9IHQ7XHJcblxyXG5cdFx0ICBkc3RbaV0gICA9IChyID4+PiAyNCkmMjU1O1xyXG5cdFx0ICBkc3RbaSsxXSA9IChyID4+PiAxNikmMjU1O1xyXG5cdFx0ICBkc3RbaSsyXSA9IChyID4+PiA4KSYyNTU7XHJcblx0XHQgIGRzdFtpKzNdID0gciYyNTU7XHJcblx0XHQgIGRzdFtpKzRdID0gKGwgPj4+IDI0KSYyNTU7XHJcblx0XHQgIGRzdFtpKzVdID0gKGwgPj4+IDE2KSYyNTU7XHJcblx0XHQgIGRzdFtpKzZdID0gKGwgPj4+IDgpJjI1NTtcclxuXHRcdCAgZHN0W2krN10gPSBsJjI1NTtcclxuXHRcdCB9XHJcblxyXG5cdFx0IHJldHVybiBkc3Q7XHJcblx0fTtcclxuXHRcclxuXHR0aGlzLmRlY3J5cHQgPSBmdW5jdGlvbihzcmMpIHtcclxuXHRcdCB2YXIgZHN0ID0gbmV3IEFycmF5KHNyYy5sZW5ndGgpO1xyXG5cclxuXHRcdCBmb3IodmFyIGkgPSAwOyBpIDwgc3JjLmxlbmd0aDsgaSs9OClcclxuXHRcdCB7XHJcblx0XHQgIHZhciBsID0gc3JjW2ldPDwyNCB8IHNyY1tpKzFdPDwxNiB8IHNyY1tpKzJdPDw4IHwgc3JjW2krM107XHJcblx0XHQgIHZhciByID0gc3JjW2krNF08PDI0IHwgc3JjW2krNV08PDE2IHwgc3JjW2krNl08PDggfCBzcmNbaSs3XTtcclxuXHRcdCAgdmFyIHQ7XHJcblxyXG5cdFx0ICB0ID0gcjsgciA9IGxeZjEociwgdGhpcy5tYXNraW5nWzE1XSwgdGhpcy5yb3RhdGVbMTVdKTsgbCA9IHQ7XHJcblx0XHQgIHQgPSByOyByID0gbF5mMyhyLCB0aGlzLm1hc2tpbmdbMTRdLCB0aGlzLnJvdGF0ZVsxNF0pOyBsID0gdDtcclxuXHRcdCAgdCA9IHI7IHIgPSBsXmYyKHIsIHRoaXMubWFza2luZ1sxM10sIHRoaXMucm90YXRlWzEzXSk7IGwgPSB0O1xyXG5cdFx0ICB0ID0gcjsgciA9IGxeZjEociwgdGhpcy5tYXNraW5nWzEyXSwgdGhpcy5yb3RhdGVbMTJdKTsgbCA9IHQ7XHJcblxyXG5cdFx0ICB0ID0gcjsgciA9IGxeZjMociwgdGhpcy5tYXNraW5nWzExXSwgdGhpcy5yb3RhdGVbMTFdKTsgbCA9IHQ7XHJcblx0XHQgIHQgPSByOyByID0gbF5mMihyLCB0aGlzLm1hc2tpbmdbMTBdLCB0aGlzLnJvdGF0ZVsxMF0pOyBsID0gdDtcclxuXHRcdCAgdCA9IHI7IHIgPSBsXmYxKHIsIHRoaXMubWFza2luZ1s5XSwgdGhpcy5yb3RhdGVbOV0pOyBsID0gdDtcclxuXHRcdCAgdCA9IHI7IHIgPSBsXmYzKHIsIHRoaXMubWFza2luZ1s4XSwgdGhpcy5yb3RhdGVbOF0pOyBsID0gdDtcclxuXHJcblx0XHQgIHQgPSByOyByID0gbF5mMihyLCB0aGlzLm1hc2tpbmdbN10sIHRoaXMucm90YXRlWzddKTsgbCA9IHQ7XHJcblx0XHQgIHQgPSByOyByID0gbF5mMShyLCB0aGlzLm1hc2tpbmdbNl0sIHRoaXMucm90YXRlWzZdKTsgbCA9IHQ7XHJcblx0XHQgIHQgPSByOyByID0gbF5mMyhyLCB0aGlzLm1hc2tpbmdbNV0sIHRoaXMucm90YXRlWzVdKTsgbCA9IHQ7XHJcblx0XHQgIHQgPSByOyByID0gbF5mMihyLCB0aGlzLm1hc2tpbmdbNF0sIHRoaXMucm90YXRlWzRdKTsgbCA9IHQ7XHJcblxyXG5cdFx0ICB0ID0gcjsgciA9IGxeZjEociwgdGhpcy5tYXNraW5nWzNdLCB0aGlzLnJvdGF0ZVszXSk7IGwgPSB0O1xyXG5cdFx0ICB0ID0gcjsgciA9IGxeZjMociwgdGhpcy5tYXNraW5nWzJdLCB0aGlzLnJvdGF0ZVsyXSk7IGwgPSB0O1xyXG5cdFx0ICB0ID0gcjsgciA9IGxeZjIociwgdGhpcy5tYXNraW5nWzFdLCB0aGlzLnJvdGF0ZVsxXSk7IGwgPSB0O1xyXG5cdFx0ICB0ID0gcjsgciA9IGxeZjEociwgdGhpcy5tYXNraW5nWzBdLCB0aGlzLnJvdGF0ZVswXSk7IGwgPSB0O1xyXG5cclxuXHRcdCAgZHN0W2ldICAgPSAociA+Pj4gMjQpJjI1NTtcclxuXHRcdCAgZHN0W2krMV0gPSAociA+Pj4gMTYpJjI1NTtcclxuXHRcdCAgZHN0W2krMl0gPSAociA+Pj4gOCkmMjU1O1xyXG5cdFx0ICBkc3RbaSszXSA9IHImMjU1O1xyXG5cdFx0ICBkc3RbaSs0XSA9IChsID4+PiAyNCkmMjU1O1xyXG5cdFx0ICBkc3RbaSs1XSA9IChsID4+IDE2KSYyNTU7XHJcblx0XHQgIGRzdFtpKzZdID0gKGwgPj4gOCkmMjU1O1xyXG5cdFx0ICBkc3RbaSs3XSA9IGwmMjU1O1xyXG5cdFx0IH1cclxuXHJcblx0XHQgcmV0dXJuIGRzdDtcclxuXHRcdH07XHJcblx0XHR2YXIgc2NoZWR1bGVBID0gbmV3IEFycmF5KDQpO1xyXG5cclxuXHRcdHNjaGVkdWxlQVswXSA9IG5ldyBBcnJheSg0KTtcclxuXHRcdHNjaGVkdWxlQVswXVswXSA9IG5ldyBBcnJheSg0LCAwLCAweGQsIDB4ZiwgMHhjLCAweGUsIDB4OCk7XHJcblx0XHRzY2hlZHVsZUFbMF1bMV0gPSBuZXcgQXJyYXkoNSwgMiwgMTYgKyAwLCAxNiArIDIsIDE2ICsgMSwgMTYgKyAzLCAweGEpO1xyXG5cdFx0c2NoZWR1bGVBWzBdWzJdID0gbmV3IEFycmF5KDYsIDMsIDE2ICsgNywgMTYgKyA2LCAxNiArIDUsIDE2ICsgNCwgOSk7XHJcblx0XHRzY2hlZHVsZUFbMF1bM10gPSBuZXcgQXJyYXkoNywgMSwgMTYgKyAweGEsIDE2ICsgOSwgMTYgKyAweGIsIDE2ICsgOCwgMHhiKTtcclxuXHJcblx0XHRzY2hlZHVsZUFbMV0gPSBuZXcgQXJyYXkoNCk7XHJcblx0XHRzY2hlZHVsZUFbMV1bMF0gPSBuZXcgQXJyYXkoMCwgNiwgMTYgKyA1LCAxNiArIDcsIDE2ICsgNCwgMTYgKyA2LCAxNiArIDApO1xyXG5cdFx0c2NoZWR1bGVBWzFdWzFdID0gbmV3IEFycmF5KDEsIDQsIDAsIDIsIDEsIDMsIDE2ICsgMik7XHJcblx0XHRzY2hlZHVsZUFbMV1bMl0gPSBuZXcgQXJyYXkoMiwgNSwgNywgNiwgNSwgNCwgMTYgKyAxKTtcclxuXHRcdHNjaGVkdWxlQVsxXVszXSA9IG5ldyBBcnJheSgzLCA3LCAweGEsIDksIDB4YiwgOCwgMTYgKyAzKTtcclxuXHJcblx0XHRzY2hlZHVsZUFbMl0gPSBuZXcgQXJyYXkoNCk7XHJcblx0XHRzY2hlZHVsZUFbMl1bMF0gPSBuZXcgQXJyYXkoNCwgMCwgMHhkLCAweGYsIDB4YywgMHhlLCA4KTtcclxuXHRcdHNjaGVkdWxlQVsyXVsxXSA9IG5ldyBBcnJheSg1LCAyLCAxNiArIDAsIDE2ICsgMiwgMTYgKyAxLCAxNiArIDMsIDB4YSk7XHJcblx0XHRzY2hlZHVsZUFbMl1bMl0gPSBuZXcgQXJyYXkoNiwgMywgMTYgKyA3LCAxNiArIDYsIDE2ICsgNSwgMTYgKyA0LCA5KTtcclxuXHRcdHNjaGVkdWxlQVsyXVszXSA9IG5ldyBBcnJheSg3LCAxLCAxNiArIDB4YSwgMTYgKyA5LCAxNiArIDB4YiwgMTYgKyA4LCAweGIpO1xyXG5cclxuXHJcblx0XHRzY2hlZHVsZUFbM10gPSBuZXcgQXJyYXkoNCk7XHJcblx0XHRzY2hlZHVsZUFbM11bMF0gPSBuZXcgQXJyYXkoMCwgNiwgMTYgKyA1LCAxNiArIDcsIDE2ICsgNCwgMTYgKyA2LCAxNiArIDApO1xyXG5cdFx0c2NoZWR1bGVBWzNdWzFdID0gbmV3IEFycmF5KDEsIDQsIDAsIDIsIDEsIDMsIDE2ICsgMik7XHJcblx0XHRzY2hlZHVsZUFbM11bMl0gPSBuZXcgQXJyYXkoMiwgNSwgNywgNiwgNSwgNCwgMTYgKyAxKTtcclxuXHRcdHNjaGVkdWxlQVszXVszXSA9IG5ldyBBcnJheSgzLCA3LCAweGEsIDksIDB4YiwgOCwgMTYgKyAzKTtcclxuXHJcblx0XHR2YXIgc2NoZWR1bGVCID0gbmV3IEFycmF5KDQpO1xyXG5cclxuXHRcdHNjaGVkdWxlQlswXSA9IG5ldyBBcnJheSg0KTtcclxuXHRcdHNjaGVkdWxlQlswXVswXSA9IG5ldyBBcnJheSgxNiArIDgsIDE2ICsgOSwgMTYgKyA3LCAxNiArIDYsIDE2ICsgMik7XHJcblx0XHRzY2hlZHVsZUJbMF1bMV0gPSBuZXcgQXJyYXkoMTYgKyAweGEsIDE2ICsgMHhiLCAxNiArIDUsIDE2ICsgNCwgMTYgKyA2KTtcclxuXHRcdHNjaGVkdWxlQlswXVsyXSA9IG5ldyBBcnJheSgxNiArIDB4YywgMTYgKyAweGQsIDE2ICsgMywgMTYgKyAyLCAxNiArIDkpO1xyXG5cdFx0c2NoZWR1bGVCWzBdWzNdID0gbmV3IEFycmF5KDE2ICsgMHhlLCAxNiArIDB4ZiwgMTYgKyAxLCAxNiArIDAsIDE2ICsgMHhjKTtcclxuXHJcblx0XHRzY2hlZHVsZUJbMV0gPSBuZXcgQXJyYXkoNCk7XHJcblx0XHRzY2hlZHVsZUJbMV1bMF0gPSBuZXcgQXJyYXkoMywgMiwgMHhjLCAweGQsIDgpO1xyXG5cdFx0c2NoZWR1bGVCWzFdWzFdID0gbmV3IEFycmF5KDEsIDAsIDB4ZSwgMHhmLCAweGQpO1xyXG5cdFx0c2NoZWR1bGVCWzFdWzJdID0gbmV3IEFycmF5KDcsIDYsIDgsIDksIDMpO1xyXG5cdFx0c2NoZWR1bGVCWzFdWzNdID0gbmV3IEFycmF5KDUsIDQsIDB4YSwgMHhiLCA3KTtcclxuXHJcblxyXG5cdFx0c2NoZWR1bGVCWzJdID0gbmV3IEFycmF5KDQpO1xyXG5cdFx0c2NoZWR1bGVCWzJdWzBdID0gbmV3IEFycmF5KDE2ICsgMywgMTYgKyAyLCAxNiArIDB4YywgMTYgKyAweGQsIDE2ICsgOSk7XHJcblx0XHRzY2hlZHVsZUJbMl1bMV0gPSBuZXcgQXJyYXkoMTYgKyAxLCAxNiArIDAsIDE2ICsgMHhlLCAxNiArIDB4ZiwgMTYgKyAweGMpO1xyXG5cdFx0c2NoZWR1bGVCWzJdWzJdID0gbmV3IEFycmF5KDE2ICsgNywgMTYgKyA2LCAxNiArIDgsIDE2ICsgOSwgMTYgKyAyKTtcclxuXHRcdHNjaGVkdWxlQlsyXVszXSA9IG5ldyBBcnJheSgxNiArIDUsIDE2ICsgNCwgMTYgKyAweGEsIDE2ICsgMHhiLCAxNiArIDYpO1xyXG5cclxuXHJcblx0XHRzY2hlZHVsZUJbM10gPSBuZXcgQXJyYXkoNCk7XHJcblx0XHRzY2hlZHVsZUJbM11bMF0gPSBuZXcgQXJyYXkoOCwgOSwgNywgNiwgMyk7XHJcblx0XHRzY2hlZHVsZUJbM11bMV0gPSBuZXcgQXJyYXkoMHhhLCAweGIsIDUsIDQsIDcpO1xyXG5cdFx0c2NoZWR1bGVCWzNdWzJdID0gbmV3IEFycmF5KDB4YywgMHhkLCAzLCAyLCA4KTtcclxuXHRcdHNjaGVkdWxlQlszXVszXSA9IG5ldyBBcnJheSgweGUsIDB4ZiwgMSwgMCwgMHhkKTtcclxuXHJcblx0XHQvLyBjaGFuZ2VkICdpbicgdG8gJ2lubicgKGluIGphdmFzY3JpcHQgJ2luJyBpcyBhIHJlc2VydmVkIHdvcmQpXHJcblx0XHR0aGlzLmtleVNjaGVkdWxlID0gZnVuY3Rpb24oaW5uKVxyXG5cdFx0e1xyXG5cdFx0IHZhciB0ID0gbmV3IEFycmF5KDgpO1xyXG5cdFx0IHZhciBrID0gbmV3IEFycmF5KDMyKTtcclxuXHJcblx0XHQgZm9yICh2YXIgaSA9IDA7IGkgPCA0OyBpKyspXHJcblx0XHQge1xyXG5cdFx0ICB2YXIgaiA9IGkgKiA0O1xyXG5cdFx0ICB0W2ldID0gaW5uW2pdPDwyNCB8IGlubltqKzFdPDwxNiB8IGlubltqKzJdPDw4IHwgaW5uW2orM107XHJcblx0XHQgfVxyXG5cclxuXHRcdCB2YXIgeCA9IFs2LCA3LCA0LCA1XTtcclxuXHRcdCB2YXIga2kgPSAwO1xyXG5cclxuXHRcdCBmb3IgKHZhciBoYWxmID0gMDsgaGFsZiA8IDI7IGhhbGYrKylcclxuXHRcdCB7XHJcblx0XHQgIGZvciAodmFyIHJvdW5kID0gMDsgcm91bmQgPCA0OyByb3VuZCsrKVxyXG5cdFx0ICB7XHJcblx0XHQgICBmb3IgKHZhciBqID0gMDsgaiA8IDQ7IGorKylcclxuXHRcdCAgIHtcclxuXHRcdCAgICB2YXIgYSA9IHNjaGVkdWxlQVtyb3VuZF1bal07XHJcblx0XHQgICAgdmFyIHcgPSB0W2FbMV1dO1xyXG5cclxuXHRcdCAgICB3IF49IHNCb3hbNF1bKHRbYVsyXT4+PjJdPj4+KDI0LTgqKGFbMl0mMykpKSYweGZmXTtcclxuXHRcdCAgICB3IF49IHNCb3hbNV1bKHRbYVszXT4+PjJdPj4+KDI0LTgqKGFbM10mMykpKSYweGZmXTtcclxuXHRcdCAgICB3IF49IHNCb3hbNl1bKHRbYVs0XT4+PjJdPj4+KDI0LTgqKGFbNF0mMykpKSYweGZmXTtcclxuXHRcdCAgICB3IF49IHNCb3hbN11bKHRbYVs1XT4+PjJdPj4+KDI0LTgqKGFbNV0mMykpKSYweGZmXTtcclxuXHRcdCAgICB3IF49IHNCb3hbeFtqXV1bKHRbYVs2XT4+PjJdPj4+KDI0LTgqKGFbNl0mMykpKSYweGZmXTtcclxuXHRcdCAgICB0W2FbMF1dID0gdztcclxuXHRcdCAgIH1cclxuXHJcblx0XHQgICBmb3IgKHZhciBqID0gMDsgaiA8IDQ7IGorKylcclxuXHRcdCAgIHtcclxuXHRcdCAgICB2YXIgYiA9IHNjaGVkdWxlQltyb3VuZF1bal07XHJcblx0XHQgICAgdmFyIHcgPSBzQm94WzRdWyh0W2JbMF0+Pj4yXT4+PigyNC04KihiWzBdJjMpKSkmMHhmZl07XHJcblxyXG5cdFx0ICAgIHcgXj0gc0JveFs1XVsodFtiWzFdPj4+Ml0+Pj4oMjQtOCooYlsxXSYzKSkpJjB4ZmZdO1xyXG5cdFx0ICAgIHcgXj0gc0JveFs2XVsodFtiWzJdPj4+Ml0+Pj4oMjQtOCooYlsyXSYzKSkpJjB4ZmZdO1xyXG5cdFx0ICAgIHcgXj0gc0JveFs3XVsodFtiWzNdPj4+Ml0+Pj4oMjQtOCooYlszXSYzKSkpJjB4ZmZdO1xyXG5cdFx0ICAgIHcgXj0gc0JveFs0K2pdWyh0W2JbNF0+Pj4yXT4+PigyNC04KihiWzRdJjMpKSkmMHhmZl07XHJcblx0XHQgICAga1traV0gPSB3O1xyXG5cdFx0ICAgIGtpKys7XHJcblx0XHQgICB9XHJcblx0XHQgIH1cclxuXHRcdCB9XHJcblxyXG5cdFx0IGZvciAodmFyIGkgPSAwOyBpIDwgMTY7IGkrKylcclxuXHRcdCB7XHJcblx0XHQgIHRoaXMubWFza2luZ1tpXSA9IGtbaV07XHJcblx0XHQgIHRoaXMucm90YXRlW2ldICA9IGtbMTYraV0gJiAweDFmO1xyXG5cdFx0IH1cclxuXHRcdH07XHJcblxyXG5cdFx0Ly8gVGhlc2UgYXJlIHRoZSB0aHJlZSAnZicgZnVuY3Rpb25zLiBTZWUgUkZDIDIxNDQsIHNlY3Rpb24gMi4yLlxyXG5cclxuXHRcdGZ1bmN0aW9uIGYxKGQsIG0sIHIpXHJcblx0XHR7XHJcblx0XHQgdmFyIHQgPSBtICsgZDtcclxuXHRcdCB2YXIgSSA9ICh0IDw8IHIpIHwgKHQgPj4+ICgzMiAtIHIpKTtcclxuXHRcdCByZXR1cm4gKChzQm94WzBdW0k+Pj4yNF0gXiBzQm94WzFdWyhJPj4+MTYpJjI1NV0pIC0gc0JveFsyXVsoST4+PjgpJjI1NV0pICsgc0JveFszXVtJJjI1NV07XHJcblx0XHR9XHJcblxyXG5cdFx0ZnVuY3Rpb24gZjIoZCwgbSwgcilcclxuXHRcdHtcclxuXHRcdCB2YXIgdCA9IG0gXiBkO1xyXG5cdFx0IHZhciBJID0gKHQgPDwgcikgfCAodCA+Pj4gKDMyIC0gcikpO1xyXG5cdFx0IHJldHVybiAoKHNCb3hbMF1bST4+PjI0XSAtIHNCb3hbMV1bKEk+Pj4xNikmMjU1XSkgKyBzQm94WzJdWyhJPj4+OCkmMjU1XSkgXiBzQm94WzNdW0kmMjU1XTtcclxuXHRcdH1cclxuXHJcblx0XHRmdW5jdGlvbiBmMyhkLCBtLCByKVxyXG5cdFx0e1xyXG5cdFx0IHZhciB0ID0gbSAtIGQ7XHJcblx0XHQgdmFyIEkgPSAodCA8PCByKSB8ICh0ID4+PiAoMzIgLSByKSk7XHJcblx0XHQgcmV0dXJuICgoc0JveFswXVtJPj4+MjRdICsgc0JveFsxXVsoST4+PjE2KSYyNTVdKSBeIHNCb3hbMl1bKEk+Pj44KSYyNTVdKSAtIHNCb3hbM11bSSYyNTVdO1xyXG5cdFx0fVxyXG5cclxuXHRcdHZhciBzQm94ID0gbmV3IEFycmF5KDgpO1xyXG5cdFx0c0JveFswXSA9IG5ldyBBcnJheShcclxuXHRcdCAgMHgzMGZiNDBkNCwgMHg5ZmEwZmYwYiwgMHg2YmVjY2QyZiwgMHgzZjI1OGM3YSwgMHgxZTIxM2YyZiwgMHg5YzAwNGRkMywgMHg2MDAzZTU0MCwgMHhjZjlmYzk0OSxcclxuXHRcdCAgMHhiZmQ0YWYyNywgMHg4OGJiYmRiNSwgMHhlMjAzNDA5MCwgMHg5OGQwOTY3NSwgMHg2ZTYzYTBlMCwgMHgxNWMzNjFkMiwgMHhjMmU3NjYxZCwgMHgyMmQ0ZmY4ZSxcclxuXHRcdCAgMHgyODY4M2I2ZiwgMHhjMDdmZDA1OSwgMHhmZjIzNzljOCwgMHg3NzVmNTBlMiwgMHg0M2MzNDBkMywgMHhkZjJmODY1NiwgMHg4ODdjYTQxYSwgMHhhMmQyYmQyZCxcclxuXHRcdCAgMHhhMWM5ZTBkNiwgMHgzNDZjNDgxOSwgMHg2MWI3NmQ4NywgMHgyMjU0MGYyZiwgMHgyYWJlMzJlMSwgMHhhYTU0MTY2YiwgMHgyMjU2OGUzYSwgMHhhMmQzNDFkMCxcclxuXHRcdCAgMHg2NmRiNDBjOCwgMHhhNzg0MzkyZiwgMHgwMDRkZmYyZiwgMHgyZGI5ZDJkZSwgMHg5Nzk0M2ZhYywgMHg0YTk3YzFkOCwgMHg1Mjc2NDRiNywgMHhiNWY0MzdhNyxcclxuXHRcdCAgMHhiODJjYmFlZiwgMHhkNzUxZDE1OSwgMHg2ZmY3ZjBlZCwgMHg1YTA5N2ExZiwgMHg4MjdiNjhkMCwgMHg5MGVjZjUyZSwgMHgyMmIwYzA1NCwgMHhiYzhlNTkzNSxcclxuXHRcdCAgMHg0YjZkMmY3ZiwgMHg1MGJiNjRhMiwgMHhkMjY2NDkxMCwgMHhiZWU1ODEyZCwgMHhiNzMzMjI5MCwgMHhlOTNiMTU5ZiwgMHhiNDhlZTQxMSwgMHg0YmZmMzQ1ZCxcclxuXHRcdCAgMHhmZDQ1YzI0MCwgMHhhZDMxOTczZiwgMHhjNGY2ZDAyZSwgMHg1NWZjODE2NSwgMHhkNWIxY2FhZCwgMHhhMWFjMmRhZSwgMHhhMmQ0Yjc2ZCwgMHhjMTliMGM1MCxcclxuXHRcdCAgMHg4ODIyNDBmMiwgMHgwYzZlNGYzOCwgMHhhNGU0YmZkNywgMHg0ZjViYTI3MiwgMHg1NjRjMWQyZiwgMHhjNTljNTMxOSwgMHhiOTQ5ZTM1NCwgMHhiMDQ2NjlmZSxcclxuXHRcdCAgMHhiMWI2YWI4YSwgMHhjNzEzNThkZCwgMHg2Mzg1YzU0NSwgMHgxMTBmOTM1ZCwgMHg1NzUzOGFkNSwgMHg2YTM5MDQ5MywgMHhlNjNkMzdlMCwgMHgyYTU0ZjZiMyxcclxuXHRcdCAgMHgzYTc4N2Q1ZiwgMHg2Mjc2YTBiNSwgMHgxOWE2ZmNkZiwgMHg3YTQyMjA2YSwgMHgyOWY5ZDRkNSwgMHhmNjFiMTg5MSwgMHhiYjcyMjc1ZSwgMHhhYTUwODE2NyxcclxuXHRcdCAgMHgzODkwMTA5MSwgMHhjNmI1MDVlYiwgMHg4NGM3Y2I4YywgMHgyYWQ3NWEwZiwgMHg4NzRhMTQyNywgMHhhMmQxOTM2YiwgMHgyYWQyODZhZiwgMHhhYTU2ZDI5MSxcclxuXHRcdCAgMHhkNzg5NDM2MCwgMHg0MjVjNzUwZCwgMHg5M2IzOWUyNiwgMHgxODcxODRjOSwgMHg2YzAwYjMyZCwgMHg3M2UyYmIxNCwgMHhhMGJlYmMzYywgMHg1NDYyMzc3OSxcclxuXHRcdCAgMHg2NDQ1OWVhYiwgMHgzZjMyOGI4MiwgMHg3NzE4Y2Y4MiwgMHg1OWEyY2VhNiwgMHgwNGVlMDAyZSwgMHg4OWZlNzhlNiwgMHgzZmFiMDk1MCwgMHgzMjVmZjZjMixcclxuXHRcdCAgMHg4MTM4M2YwNSwgMHg2OTYzYzVjOCwgMHg3NmNiNWFkNiwgMHhkNDk5NzRjOSwgMHhjYTE4MGRjZiwgMHgzODA3ODJkNSwgMHhjN2ZhNWNmNiwgMHg4YWMzMTUxMSxcclxuXHRcdCAgMHgzNWU3OWUxMywgMHg0N2RhOTFkMCwgMHhmNDBmOTA4NiwgMHhhN2UyNDE5ZSwgMHgzMTM2NjI0MSwgMHgwNTFlZjQ5NSwgMHhhYTU3M2IwNCwgMHg0YTgwNWQ4ZCxcclxuXHRcdCAgMHg1NDgzMDBkMCwgMHgwMDMyMmEzYywgMHhiZjY0Y2RkZiwgMHhiYTU3YTY4ZSwgMHg3NWM2MzcyYiwgMHg1MGFmZDM0MSwgMHhhN2MxMzI3NSwgMHg5MTVhMGJmNSxcclxuXHRcdCAgMHg2YjU0YmZhYiwgMHgyYjBiMTQyNiwgMHhhYjRjYzlkNywgMHg0NDljY2Q4MiwgMHhmN2ZiZjI2NSwgMHhhYjg1YzVmMywgMHgxYjU1ZGI5NCwgMHhhYWQ0ZTMyNCxcclxuXHRcdCAgMHhjZmE0YmQzZiwgMHgyZGVhYTNlMiwgMHg5ZTIwNGQwMiwgMHhjOGJkMjVhYywgMHhlYWRmNTViMywgMHhkNWJkOWU5OCwgMHhlMzEyMzFiMiwgMHgyYWQ1YWQ2YyxcclxuXHRcdCAgMHg5NTQzMjlkZSwgMHhhZGJlNDUyOCwgMHhkODcxMGY2OSwgMHhhYTUxYzkwZiwgMHhhYTc4NmJmNiwgMHgyMjUxM2YxZSwgMHhhYTUxYTc5YiwgMHgyYWQzNDRjYyxcclxuXHRcdCAgMHg3YjVhNDFmMCwgMHhkMzdjZmJhZCwgMHgxYjA2OTUwNSwgMHg0MWVjZTQ5MSwgMHhiNGMzMzJlNiwgMHgwMzIyNjhkNCwgMHhjOTYwMGFjYywgMHhjZTM4N2U2ZCxcclxuXHRcdCAgMHhiZjZiYjE2YywgMHg2YTcwZmI3OCwgMHgwZDAzZDljOSwgMHhkNGRmMzlkZSwgMHhlMDEwNjNkYSwgMHg0NzM2ZjQ2NCwgMHg1YWQzMjhkOCwgMHhiMzQ3Y2M5NixcclxuXHRcdCAgMHg3NWJiMGZjMywgMHg5ODUxMWJmYiwgMHg0ZmZiY2MzNSwgMHhiNThiY2Y2YSwgMHhlMTFmMGFiYywgMHhiZmM1ZmU0YSwgMHhhNzBhZWMxMCwgMHhhYzM5NTcwYSxcclxuXHRcdCAgMHgzZjA0NDQyZiwgMHg2MTg4YjE1MywgMHhlMDM5N2EyZSwgMHg1NzI3Y2I3OSwgMHg5Y2ViNDE4ZiwgMHgxY2FjZDY4ZCwgMHgyYWQzN2M5NiwgMHgwMTc1Y2I5ZCxcclxuXHRcdCAgMHhjNjlkZmYwOSwgMHhjNzViNjVmMCwgMHhkOWRiNDBkOCwgMHhlYzBlNzc3OSwgMHg0NzQ0ZWFkNCwgMHhiMTFjMzI3NCwgMHhkZDI0Y2I5ZSwgMHg3ZTFjNTRiZCxcclxuXHRcdCAgMHhmMDExNDRmOSwgMHhkMjI0MGViMSwgMHg5Njc1YjNmZCwgMHhhM2FjMzc1NSwgMHhkNDdjMjdhZiwgMHg1MWM4NWY0ZCwgMHg1NjkwNzU5NiwgMHhhNWJiMTVlNixcclxuXHRcdCAgMHg1ODAzMDRmMCwgMHhjYTA0MmNmMSwgMHgwMTFhMzdlYSwgMHg4ZGJmYWFkYiwgMHgzNWJhM2U0YSwgMHgzNTI2ZmZhMCwgMHhjMzdiNGQwOSwgMHhiYzMwNmVkOSxcclxuXHRcdCAgMHg5OGE1MjY2NiwgMHg1NjQ4ZjcyNSwgMHhmZjVlNTY5ZCwgMHgwY2VkNjNkMCwgMHg3YzYzYjJjZiwgMHg3MDBiNDVlMSwgMHhkNWVhNTBmMSwgMHg4NWE5Mjg3MixcclxuXHRcdCAgMHhhZjFmYmRhNywgMHhkNDIzNDg3MCwgMHhhNzg3MGJmMywgMHgyZDNiNGQ3OSwgMHg0MmUwNDE5OCwgMHgwY2QwZWRlNywgMHgyNjQ3MGRiOCwgMHhmODgxODE0YyxcclxuXHRcdCAgMHg0NzRkNmFkNywgMHg3YzBjNWU1YywgMHhkMTIzMTk1OSwgMHgzODFiNzI5OCwgMHhmNWQyZjRkYiwgMHhhYjgzODY1MywgMHg2ZTJmMWUyMywgMHg4MzcxOWM5ZSxcclxuXHRcdCAgMHhiZDkxZTA0NiwgMHg5YTU2NDU2ZSwgMHhkYzM5MjAwYywgMHgyMGM4YzU3MSwgMHg5NjJiZGExYywgMHhlMWU2OTZmZiwgMHhiMTQxYWIwOCwgMHg3Y2NhODliOSxcclxuXHRcdCAgMHgxYTY5ZTc4MywgMHgwMmNjNDg0MywgMHhhMmY3YzU3OSwgMHg0MjllZjQ3ZCwgMHg0MjdiMTY5YywgMHg1YWM5ZjA0OSwgMHhkZDhmMGYwMCwgMHg1YzgxNjViZik7XHJcblxyXG5cdFx0c0JveFsxXSA9IG5ldyBBcnJheShcclxuXHRcdCAgMHgxZjIwMTA5NCwgMHhlZjBiYTc1YiwgMHg2OWUzY2Y3ZSwgMHgzOTNmNDM4MCwgMHhmZTYxY2Y3YSwgMHhlZWM1MjA3YSwgMHg1NTg4OWM5NCwgMHg3MmZjMDY1MSxcclxuXHRcdCAgMHhhZGE3ZWY3OSwgMHg0ZTFkNzIzNSwgMHhkNTVhNjNjZSwgMHhkZTA0MzZiYSwgMHg5OWM0MzBlZiwgMHg1ZjBjMDc5NCwgMHgxOGRjZGI3ZCwgMHhhMWQ2ZWZmMyxcclxuXHRcdCAgMHhhMGI1MmY3YiwgMHg1OWU4MzYwNSwgMHhlZTE1YjA5NCwgMHhlOWZmZDkwOSwgMHhkYzQ0MDA4NiwgMHhlZjk0NDQ1OSwgMHhiYTgzY2NiMywgMHhlMGMzY2RmYixcclxuXHRcdCAgMHhkMWRhNDE4MSwgMHgzYjA5MmFiMSwgMHhmOTk3ZjFjMSwgMHhhNWU2Y2Y3YiwgMHgwMTQyMGRkYiwgMHhlNGU3ZWY1YiwgMHgyNWExZmY0MSwgMHhlMTgwZjgwNixcclxuXHRcdCAgMHgxZmM0MTA4MCwgMHgxNzliZWU3YSwgMHhkMzdhYzZhOSwgMHhmZTU4MzBhNCwgMHg5OGRlOGI3ZiwgMHg3N2U4M2Y0ZSwgMHg3OTkyOTI2OSwgMHgyNGZhOWY3YixcclxuXHRcdCAgMHhlMTEzYzg1YiwgMHhhY2M0MDA4MywgMHhkNzUwMzUyNSwgMHhmN2VhNjE1ZiwgMHg2MjE0MzE1NCwgMHgwZDU1NGI2MywgMHg1ZDY4MTEyMSwgMHhjODY2YzM1OSxcclxuXHRcdCAgMHgzZDYzY2Y3MywgMHhjZWUyMzRjMCwgMHhkNGQ4N2U4NywgMHg1YzY3MmIyMSwgMHgwNzFmNjE4MSwgMHgzOWY3NjI3ZiwgMHgzNjFlMzA4NCwgMHhlNGViNTczYixcclxuXHRcdCAgMHg2MDJmNjRhNCwgMHhkNjNhY2Q5YywgMHgxYmJjNDYzNSwgMHg5ZTgxMDMyZCwgMHgyNzAxZjUwYywgMHg5OTg0N2FiNCwgMHhhMGUzZGY3OSwgMHhiYTZjZjM4YyxcclxuXHRcdCAgMHgxMDg0MzA5NCwgMHgyNTM3YTk1ZSwgMHhmNDZmNmZmZSwgMHhhMWZmM2IxZiwgMHgyMDhjZmI2YSwgMHg4ZjQ1OGM3NCwgMHhkOWUwYTIyNywgMHg0ZWM3M2EzNCxcclxuXHRcdCAgMHhmYzg4NGY2OSwgMHgzZTRkZThkZiwgMHhlZjBlMDA4OCwgMHgzNTU5NjQ4ZCwgMHg4YTQ1Mzg4YywgMHgxZDgwNDM2NiwgMHg3MjFkOWJmZCwgMHhhNTg2ODRiYixcclxuXHRcdCAgMHhlODI1NjMzMywgMHg4NDRlODIxMiwgMHgxMjhkODA5OCwgMHhmZWQzM2ZiNCwgMHhjZTI4MGFlMSwgMHgyN2UxOWJhNSwgMHhkNWE2YzI1MiwgMHhlNDk3NTRiZCxcclxuXHRcdCAgMHhjNWQ2NTVkZCwgMHhlYjY2NzA2NCwgMHg3Nzg0MGI0ZCwgMHhhMWI2YTgwMSwgMHg4NGRiMjZhOSwgMHhlMGI1NjcxNCwgMHgyMWYwNDNiNywgMHhlNWQwNTg2MCxcclxuXHRcdCAgMHg1NGYwMzA4NCwgMHgwNjZmZjQ3MiwgMHhhMzFhYTE1MywgMHhkYWRjNDc1NSwgMHhiNTYyNWRiZiwgMHg2ODU2MWJlNiwgMHg4M2NhNmI5NCwgMHgyZDZlZDIzYixcclxuXHRcdCAgMHhlY2NmMDFkYiwgMHhhNmQzZDBiYSwgMHhiNjgwM2Q1YywgMHhhZjc3YTcwOSwgMHgzM2I0YTM0YywgMHgzOTdiYzhkNiwgMHg1ZWUyMmI5NSwgMHg1ZjBlNTMwNCxcclxuXHRcdCAgMHg4MWVkNmY2MSwgMHgyMGU3NDM2NCwgMHhiNDVlMTM3OCwgMHhkZTE4NjM5YiwgMHg4ODFjYTEyMiwgMHhiOTY3MjZkMSwgMHg4MDQ5YTdlOCwgMHgyMmI3ZGE3YixcclxuXHRcdCAgMHg1ZTU1MmQyNSwgMHg1MjcyZDIzNywgMHg3OWQyOTUxYywgMHhjNjBkODk0YywgMHg0ODhjYjQwMiwgMHgxYmE0ZmU1YiwgMHhhNGIwOWY2YiwgMHgxY2E4MTVjZixcclxuXHRcdCAgMHhhMjBjMzAwNSwgMHg4ODcxZGY2MywgMHhiOWRlMmZjYiwgMHgwY2M2YzllOSwgMHgwYmVlZmY1MywgMHhlMzIxNDUxNywgMHhiNDU0MjgzNSwgMHg5ZjYzMjkzYyxcclxuXHRcdCAgMHhlZTQxZTcyOSwgMHg2ZTFkMmQ3YywgMHg1MDA0NTI4NiwgMHgxZTY2ODVmMywgMHhmMzM0MDFjNiwgMHgzMGEyMmM5NSwgMHgzMWE3MDg1MCwgMHg2MDkzMGYxMyxcclxuXHRcdCAgMHg3M2Y5ODQxNywgMHhhMTI2OTg1OSwgMHhlYzY0NWM0NCwgMHg1MmM4NzdhOSwgMHhjZGZmMzNhNiwgMHhhMDJiMTc0MSwgMHg3Y2JhZDlhMiwgMHgyMTgwMDM2ZixcclxuXHRcdCAgMHg1MGQ5OWMwOCwgMHhjYjNmNDg2MSwgMHhjMjZiZDc2NSwgMHg2NGEzZjZhYiwgMHg4MDM0MjY3NiwgMHgyNWE3NWU3YiwgMHhlNGU2ZDFmYywgMHgyMGM3MTBlNixcclxuXHRcdCAgMHhjZGYwYjY4MCwgMHgxNzg0NGQzYiwgMHgzMWVlZjg0ZCwgMHg3ZTA4MjRlNCwgMHgyY2NiNDllYiwgMHg4NDZhM2JhZSwgMHg4ZmY3Nzg4OCwgMHhlZTVkNjBmNixcclxuXHRcdCAgMHg3YWY3NTY3MywgMHgyZmRkNWNkYiwgMHhhMTE2MzFjMSwgMHgzMGY2NmY0MywgMHhiM2ZhZWM1NCwgMHgxNTdmZDdmYSwgMHhlZjg1NzljYywgMHhkMTUyZGU1OCxcclxuXHRcdCAgMHhkYjJmZmQ1ZSwgMHg4ZjMyY2UxOSwgMHgzMDZhZjk3YSwgMHgwMmYwM2VmOCwgMHg5OTMxOWFkNSwgMHhjMjQyZmEwZiwgMHhhN2UzZWJiMCwgMHhjNjhlNDkwNixcclxuXHRcdCAgMHhiOGRhMjMwYywgMHg4MDgyMzAyOCwgMHhkY2RlZjNjOCwgMHhkMzVmYjE3MSwgMHgwODhhMWJjOCwgMHhiZWMwYzU2MCwgMHg2MWEzYzllOCwgMHhiY2E4ZjU0ZCxcclxuXHRcdCAgMHhjNzJmZWZmYSwgMHgyMjgyMmU5OSwgMHg4MmM1NzBiNCwgMHhkOGQ5NGU4OSwgMHg4YjFjMzRiYywgMHgzMDFlMTZlNiwgMHgyNzNiZTk3OSwgMHhiMGZmZWFhNixcclxuXHRcdCAgMHg2MWQ5YjhjNiwgMHgwMGIyNDg2OSwgMHhiN2ZmY2UzZiwgMHgwOGRjMjgzYiwgMHg0M2RhZjY1YSwgMHhmN2UxOTc5OCwgMHg3NjE5YjcyZiwgMHg4ZjFjOWJhNCxcclxuXHRcdCAgMHhkYzg2MzdhMCwgMHgxNmE3ZDNiMSwgMHg5ZmMzOTNiNywgMHhhNzEzNmVlYiwgMHhjNmJjYzYzZSwgMHgxYTUxMzc0MiwgMHhlZjY4MjhiYywgMHg1MjAzNjVkNixcclxuXHRcdCAgMHgyZDZhNzdhYiwgMHgzNTI3ZWQ0YiwgMHg4MjFmZDIxNiwgMHgwOTVjNmUyZSwgMHhkYjkyZjJmYiwgMHg1ZWVhMjljYiwgMHgxNDU4OTJmNSwgMHg5MTU4NGY3ZixcclxuXHRcdCAgMHg1NDgzNjk3YiwgMHgyNjY3YThjYywgMHg4NTE5NjA0OCwgMHg4YzRiYWNlYSwgMHg4MzM4NjBkNCwgMHgwZDIzZTBmOSwgMHg2YzM4N2U4YSwgMHgwYWU2ZDI0OSxcclxuXHRcdCAgMHhiMjg0NjAwYywgMHhkODM1NzMxZCwgMHhkY2IxYzY0NywgMHhhYzRjNTZlYSwgMHgzZWJkODFiMywgMHgyMzBlYWJiMCwgMHg2NDM4YmM4NywgMHhmMGI1YjFmYSxcclxuXHRcdCAgMHg4ZjVlYTJiMywgMHhmYzE4NDY0MiwgMHgwYTAzNmI3YSwgMHg0ZmIwODliZCwgMHg2NDlkYTU4OSwgMHhhMzQ1NDE1ZSwgMHg1YzAzODMyMywgMHgzZTVkM2JiOSxcclxuXHRcdCAgMHg0M2Q3OTU3MiwgMHg3ZTZkZDA3YywgMHgwNmRmZGYxZSwgMHg2YzZjYzRlZiwgMHg3MTYwYTUzOSwgMHg3M2JmYmU3MCwgMHg4Mzg3NzYwNSwgMHg0NTIzZWNmMSk7XHJcblxyXG5cdFx0c0JveFsyXSA9IG5ldyBBcnJheShcclxuXHRcdCAgMHg4ZGVmYzI0MCwgMHgyNWZhNWQ5ZiwgMHhlYjkwM2RiZiwgMHhlODEwYzkwNywgMHg0NzYwN2ZmZiwgMHgzNjlmZTQ0YiwgMHg4YzFmYzY0NCwgMHhhZWNlY2E5MCxcclxuXHRcdCAgMHhiZWIxZjliZiwgMHhlZWZiY2FlYSwgMHhlOGNmMTk1MCwgMHg1MWRmMDdhZSwgMHg5MjBlODgwNiwgMHhmMGFkMDU0OCwgMHhlMTNjOGQ4MywgMHg5MjcwMTBkNSxcclxuXHRcdCAgMHgxMTEwN2Q5ZiwgMHgwNzY0N2RiOSwgMHhiMmUzZTRkNCwgMHgzZDRmMjg1ZSwgMHhiOWFmYTgyMCwgMHhmYWRlODJlMCwgMHhhMDY3MjY4YiwgMHg4MjcyNzkyZSxcclxuXHRcdCAgMHg1NTNmYjJjMCwgMHg0ODlhZTIyYiwgMHhkNGVmOTc5NCwgMHgxMjVlM2ZiYywgMHgyMWZmZmNlZSwgMHg4MjViMWJmZCwgMHg5MjU1YzVlZCwgMHgxMjU3YTI0MCxcclxuXHRcdCAgMHg0ZTFhODMwMiwgMHhiYWUwN2ZmZiwgMHg1MjgyNDZlNywgMHg4ZTU3MTQwZSwgMHgzMzczZjdiZiwgMHg4YzlmODE4OCwgMHhhNmZjNGVlOCwgMHhjOTgyYjVhNSxcclxuXHRcdCAgMHhhOGMwMWRiNywgMHg1NzlmYzI2NCwgMHg2NzA5NGYzMSwgMHhmMmJkM2Y1ZiwgMHg0MGZmZjdjMSwgMHgxZmI3OGRmYywgMHg4ZTZiZDJjMSwgMHg0MzdiZTU5YixcclxuXHRcdCAgMHg5OWIwM2RiZiwgMHhiNWRiYzY0YiwgMHg2MzhkYzBlNiwgMHg1NTgxOWQ5OSwgMHhhMTk3YzgxYywgMHg0YTAxMmQ2ZSwgMHhjNTg4NGEyOCwgMHhjY2MzNmY3MSxcclxuXHRcdCAgMHhiODQzYzIxMywgMHg2YzA3NDNmMSwgMHg4MzA5ODkzYywgMHgwZmVkZGQ1ZiwgMHgyZjdmZTg1MCwgMHhkN2MwN2Y3ZSwgMHgwMjUwN2ZiZiwgMHg1YWZiOWEwNCxcclxuXHRcdCAgMHhhNzQ3ZDJkMCwgMHgxNjUxMTkyZSwgMHhhZjcwYmYzZSwgMHg1OGMzMTM4MCwgMHg1Zjk4MzAyZSwgMHg3MjdjYzNjNCwgMHgwYTBmYjQwMiwgMHgwZjdmZWY4MixcclxuXHRcdCAgMHg4Yzk2ZmRhZCwgMHg1ZDJjMmFhZSwgMHg4ZWU5OWE0OSwgMHg1MGRhODhiOCwgMHg4NDI3ZjRhMCwgMHgxZWFjNTc5MCwgMHg3OTZmYjQ0OSwgMHg4MjUyZGMxNSxcclxuXHRcdCAgMHhlZmJkN2Q5YiwgMHhhNjcyNTk3ZCwgMHhhZGE4NDBkOCwgMHg0NWY1NDUwNCwgMHhmYTVkNzQwMywgMHhlODNlYzMwNSwgMHg0ZjkxNzUxYSwgMHg5MjU2NjljMixcclxuXHRcdCAgMHgyM2VmZTk0MSwgMHhhOTAzZjEyZSwgMHg2MDI3MGRmMiwgMHgwMjc2ZTRiNiwgMHg5NGZkNjU3NCwgMHg5Mjc5ODViMiwgMHg4Mjc2ZGJjYiwgMHgwMjc3ODE3NixcclxuXHRcdCAgMHhmOGFmOTE4ZCwgMHg0ZTQ4Zjc5ZSwgMHg4ZjYxNmRkZiwgMHhlMjlkODQwZSwgMHg4NDJmN2Q4MywgMHgzNDBjZTVjOCwgMHg5NmJiYjY4MiwgMHg5M2I0YjE0OCxcclxuXHRcdCAgMHhlZjMwM2NhYiwgMHg5ODRmYWYyOCwgMHg3NzlmYWY5YiwgMHg5MmRjNTYwZCwgMHgyMjRkMWUyMCwgMHg4NDM3YWE4OCwgMHg3ZDI5ZGM5NiwgMHgyNzU2ZDNkYyxcclxuXHRcdCAgMHg4YjkwN2NlZSwgMHhiNTFmZDI0MCwgMHhlN2MwN2NlMywgMHhlNTY2YjRhMSwgMHhjM2U5NjE1ZSwgMHgzY2Y4MjA5ZCwgMHg2MDk0ZDFlMywgMHhjZDljYTM0MSxcclxuXHRcdCAgMHg1Yzc2NDYwZSwgMHgwMGVhOTgzYiwgMHhkNGQ2Nzg4MSwgMHhmZDQ3NTcyYywgMHhmNzZjZWRkOSwgMHhiZGE4MjI5YywgMHgxMjdkYWRhYSwgMHg0MzhhMDc0ZSxcclxuXHRcdCAgMHgxZjk3YzA5MCwgMHgwODFiZGI4YSwgMHg5M2EwN2ViZSwgMHhiOTM4Y2ExNSwgMHg5N2IwM2NmZiwgMHgzZGMyYzBmOCwgMHg4ZDFhYjJlYywgMHg2NDM4MGU1MSxcclxuXHRcdCAgMHg2OGNjN2JmYiwgMHhkOTBmMjc4OCwgMHgxMjQ5MDE4MSwgMHg1ZGU1ZmZkNCwgMHhkZDdlZjg2YSwgMHg3NmEyZTIxNCwgMHhiOWE0MDM2OCwgMHg5MjVkOTU4ZixcclxuXHRcdCAgMHg0YjM5ZmZmYSwgMHhiYTM5YWVlOSwgMHhhNGZmZDMwYiwgMHhmYWY3OTMzYiwgMHg2ZDQ5ODYyMywgMHgxOTNjYmNmYSwgMHgyNzYyNzU0NSwgMHg4MjVjZjQ3YSxcclxuXHRcdCAgMHg2MWJkOGJhMCwgMHhkMTFlNDJkMSwgMHhjZWFkMDRmNCwgMHgxMjdlYTM5MiwgMHgxMDQyOGRiNywgMHg4MjcyYTk3MiwgMHg5MjcwYzRhOCwgMHgxMjdkZTUwYixcclxuXHRcdCAgMHgyODViYTFjOCwgMHgzYzYyZjQ0ZiwgMHgzNWMwZWFhNSwgMHhlODA1ZDIzMSwgMHg0Mjg5MjlmYiwgMHhiNGZjZGY4MiwgMHg0ZmI2NmE1MywgMHgwZTdkYzE1YixcclxuXHRcdCAgMHgxZjA4MWZhYiwgMHgxMDg2MThhZSwgMHhmY2ZkMDg2ZCwgMHhmOWZmMjg4OSwgMHg2OTRiY2MxMSwgMHgyMzZhNWNhZSwgMHgxMmRlY2E0ZCwgMHgyYzNmOGNjNSxcclxuXHRcdCAgMHhkMmQwMmRmZSwgMHhmOGVmNTg5NiwgMHhlNGNmNTJkYSwgMHg5NTE1NWI2NywgMHg0OTRhNDg4YywgMHhiOWI2YTgwYywgMHg1YzhmODJiYywgMHg4OWQzNmI0NSxcclxuXHRcdCAgMHgzYTYwOTQzNywgMHhlYzAwYzlhOSwgMHg0NDcxNTI1MywgMHgwYTg3NGI0OSwgMHhkNzczYmM0MCwgMHg3YzM0NjcxYywgMHgwMjcxN2VmNiwgMHg0ZmViNTUzNixcclxuXHRcdCAgMHhhMmQwMmZmZiwgMHhkMmJmNjBjNCwgMHhkNDNmMDNjMCwgMHg1MGI0ZWY2ZCwgMHgwNzQ3OGNkMSwgMHgwMDZlMTg4OCwgMHhhMmU1M2Y1NSwgMHhiOWU2ZDRiYyxcclxuXHRcdCAgMHhhMjA0ODAxNiwgMHg5NzU3MzgzMywgMHhkNzIwN2Q2NywgMHhkZTBmOGYzZCwgMHg3MmY4N2IzMywgMHhhYmNjNGYzMywgMHg3Njg4YzU1ZCwgMHg3YjAwYTZiMCxcclxuXHRcdCAgMHg5NDdiMDAwMSwgMHg1NzAwNzVkMiwgMHhmOWJiODhmOCwgMHg4OTQyMDE5ZSwgMHg0MjY0YTVmZiwgMHg4NTYzMDJlMCwgMHg3MmRiZDkyYiwgMHhlZTk3MWI2OSxcclxuXHRcdCAgMHg2ZWEyMmZkZSwgMHg1ZjA4YWUyYiwgMHhhZjdhNjE2ZCwgMHhlNWM5ODc2NywgMHhjZjFmZWJkMiwgMHg2MWVmYzhjMiwgMHhmMWFjMjU3MSwgMHhjYzgyMzljMixcclxuXHRcdCAgMHg2NzIxNGNiOCwgMHhiMWU1ODNkMSwgMHhiN2RjM2U2MiwgMHg3ZjEwYmRjZSwgMHhmOTBhNWMzOCwgMHgwZmYwNDQzZCwgMHg2MDZlNmRjNiwgMHg2MDU0M2E0OSxcclxuXHRcdCAgMHg1NzI3YzE0OCwgMHgyYmU5OGExZCwgMHg4YWI0MTczOCwgMHgyMGUxYmUyNCwgMHhhZjk2ZGEwZiwgMHg2ODQ1ODQyNSwgMHg5OTgzM2JlNSwgMHg2MDBkNDU3ZCxcclxuXHRcdCAgMHgyODJmOTM1MCwgMHg4MzM0YjM2MiwgMHhkOTFkMTEyMCwgMHgyYjZkOGRhMCwgMHg2NDJiMWUzMSwgMHg5YzMwNWEwMCwgMHg1MmJjZTY4OCwgMHgxYjAzNTg4YSxcclxuXHRcdCAgMHhmN2JhZWZkNSwgMHg0MTQyZWQ5YywgMHhhNDMxNWMxMSwgMHg4MzMyM2VjNSwgMHhkZmVmNDYzNiwgMHhhMTMzYzUwMSwgMHhlOWQzNTMxYywgMHhlZTM1Mzc4Myk7XHJcblxyXG5cdFx0c0JveFszXSA9IG5ldyBBcnJheShcclxuXHRcdCAgMHg5ZGIzMDQyMCwgMHgxZmI2ZTlkZSwgMHhhN2JlN2JlZiwgMHhkMjczYTI5OCwgMHg0YTRmN2JkYiwgMHg2NGFkOGM1NywgMHg4NTUxMDQ0MywgMHhmYTAyMGVkMSxcclxuXHRcdCAgMHg3ZTI4N2FmZiwgMHhlNjBmYjY2MywgMHgwOTVmMzVhMSwgMHg3OWViZjEyMCwgMHhmZDA1OWQ0MywgMHg2NDk3YjdiMSwgMHhmMzY0MWY2MywgMHgyNDFlNGFkZixcclxuXHRcdCAgMHgyODE0N2Y1ZiwgMHg0ZmEyYjhjZCwgMHhjOTQzMDA0MCwgMHgwY2MzMjIyMCwgMHhmZGQzMGIzMCwgMHhjMGE1Mzc0ZiwgMHgxZDJkMDBkOSwgMHgyNDE0N2IxNSxcclxuXHRcdCAgMHhlZTRkMTExYSwgMHgwZmNhNTE2NywgMHg3MWZmOTA0YywgMHgyZDE5NWZmZSwgMHgxYTA1NjQ1ZiwgMHgwYzEzZmVmZSwgMHgwODFiMDhjYSwgMHgwNTE3MDEyMSxcclxuXHRcdCAgMHg4MDUzMDEwMCwgMHhlODNlNWVmZSwgMHhhYzlhZjRmOCwgMHg3ZmU3MjcwMSwgMHhkMmI4ZWU1ZiwgMHgwNmRmNDI2MSwgMHhiYjllOWI4YSwgMHg3MjkzZWEyNSxcclxuXHRcdCAgMHhjZTg0ZmZkZiwgMHhmNTcxODgwMSwgMHgzZGQ2NGIwNCwgMHhhMjZmMjYzYiwgMHg3ZWQ0ODQwMCwgMHg1NDdlZWJlNiwgMHg0NDZkNGNhMCwgMHg2Y2YzZDZmNSxcclxuXHRcdCAgMHgyNjQ5YWJkZiwgMHhhZWEwYzdmNSwgMHgzNjMzOGNjMSwgMHg1MDNmN2U5MywgMHhkMzc3MjA2MSwgMHgxMWI2MzhlMSwgMHg3MjUwMGUwMywgMHhmODBlYjJiYixcclxuXHRcdCAgMHhhYmUwNTAyZSwgMHhlYzhkNzdkZSwgMHg1Nzk3MWU4MSwgMHhlMTRmNjc0NiwgMHhjOTMzNTQwMCwgMHg2OTIwMzE4ZiwgMHgwODFkYmI5OSwgMHhmZmMzMDRhNSxcclxuXHRcdCAgMHg0ZDM1MTgwNSwgMHg3ZjNkNWNlMywgMHhhNmM4NjZjNiwgMHg1ZDViY2NhOSwgMHhkYWVjNmZlYSwgMHg5ZjkyNmY5MSwgMHg5ZjQ2MjIyZiwgMHgzOTkxNDY3ZCxcclxuXHRcdCAgMHhhNWJmNmQ4ZSwgMHgxMTQzYzQ0ZiwgMHg0Mzk1ODMwMiwgMHhkMDIxNGVlYiwgMHgwMjIwODNiOCwgMHgzZmI2MTgwYywgMHgxOGY4OTMxZSwgMHgyODE2NThlNixcclxuXHRcdCAgMHgyNjQ4NmUzZSwgMHg4YmQ3OGE3MCwgMHg3NDc3ZTRjMSwgMHhiNTA2ZTA3YywgMHhmMzJkMGEyNSwgMHg3OTA5OGIwMiwgMHhlNGVhYmI4MSwgMHgyODEyM2IyMyxcclxuXHRcdCAgMHg2OWRlYWQzOCwgMHgxNTc0Y2ExNiwgMHhkZjg3MWI2MiwgMHgyMTFjNDBiNywgMHhhNTFhOWVmOSwgMHgwMDE0Mzc3YiwgMHgwNDFlOGFjOCwgMHgwOTExNDAwMyxcclxuXHRcdCAgMHhiZDU5ZTRkMiwgMHhlM2QxNTZkNSwgMHg0ZmU4NzZkNSwgMHgyZjkxYTM0MCwgMHg1NTdiZThkZSwgMHgwMGVhZTRhNywgMHgwY2U1YzJlYywgMHg0ZGI0YmJhNixcclxuXHRcdCAgMHhlNzU2YmRmZiwgMHhkZDMzNjlhYywgMHhlYzE3YjAzNSwgMHgwNjU3MjMyNywgMHg5OWFmYzhiMCwgMHg1NmM4YzM5MSwgMHg2YjY1ODExYywgMHg1ZTE0NjExOSxcclxuXHRcdCAgMHg2ZTg1Y2I3NSwgMHhiZTA3YzAwMiwgMHhjMjMyNTU3NywgMHg4OTNmZjRlYywgMHg1YmJmYzkyZCwgMHhkMGVjM2IyNSwgMHhiNzgwMWFiNywgMHg4ZDZkM2IyNCxcclxuXHRcdCAgMHgyMGM3NjNlZiwgMHhjMzY2YTVmYywgMHg5YzM4Mjg4MCwgMHgwYWNlMzIwNSwgMHhhYWM5NTQ4YSwgMHhlY2ExZDdjNywgMHgwNDFhZmEzMiwgMHgxZDE2NjI1YSxcclxuXHRcdCAgMHg2NzAxOTAyYywgMHg5Yjc1N2E1NCwgMHgzMWQ0NzdmNywgMHg5MTI2YjAzMSwgMHgzNmNjNmZkYiwgMHhjNzBiOGI0NiwgMHhkOWU2NmE0OCwgMHg1NmU1NWE3OSxcclxuXHRcdCAgMHgwMjZhNGNlYiwgMHg1MjQzN2VmZiwgMHgyZjhmNzZiNCwgMHgwZGY5ODBhNSwgMHg4Njc0Y2RlMywgMHhlZGRhMDRlYiwgMHgxN2E5YmUwNCwgMHgyYzE4ZjRkZixcclxuXHRcdCAgMHhiNzc0N2Y5ZCwgMHhhYjJhZjdiNCwgMHhlZmMzNGQyMCwgMHgyZTA5NmI3YywgMHgxNzQxYTI1NCwgMHhlNWI2YTAzNSwgMHgyMTNkNDJmNiwgMHgyYzFjN2MyNixcclxuXHRcdCAgMHg2MWMyZjUwZiwgMHg2NTUyZGFmOSwgMHhkMmMyMzFmOCwgMHgyNTEzMGY2OSwgMHhkODE2N2ZhMiwgMHgwNDE4ZjJjOCwgMHgwMDFhOTZhNiwgMHgwZDE1MjZhYixcclxuXHRcdCAgMHg2MzMxNWMyMSwgMHg1ZTBhNzJlYywgMHg0OWJhZmVmZCwgMHgxODc5MDhkOSwgMHg4ZDBkYmQ4NiwgMHgzMTExNzBhNywgMHgzZTliNjQwYywgMHhjYzNlMTBkNyxcclxuXHRcdCAgMHhkNWNhZDNiNiwgMHgwY2FlYzM4OCwgMHhmNzMwMDFlMSwgMHg2YzcyOGFmZiwgMHg3MWVhZTJhMSwgMHgxZjlhZjM2ZSwgMHhjZmNiZDEyZiwgMHhjMWRlODQxNyxcclxuXHRcdCAgMHhhYzA3YmU2YiwgMHhjYjQ0YTFkOCwgMHg4YjliMGY1NiwgMHgwMTM5ODhjMywgMHhiMWM1MmZjYSwgMHhiNGJlMzFjZCwgMHhkODc4MjgwNiwgMHgxMmEzYTRlMixcclxuXHRcdCAgMHg2ZjdkZTUzMiwgMHg1OGZkN2ViNiwgMHhkMDFlZTkwMCwgMHgyNGFkZmZjMiwgMHhmNDk5MGZjNSwgMHg5NzExYWFjNSwgMHgwMDFkN2I5NSwgMHg4MmU1ZTdkMixcclxuXHRcdCAgMHgxMDk4NzNmNiwgMHgwMDYxMzA5NiwgMHhjMzJkOTUyMSwgMHhhZGExMjFmZiwgMHgyOTkwODQxNSwgMHg3ZmJiOTc3ZiwgMHhhZjllYjNkYiwgMHgyOWM5ZWQyYSxcclxuXHRcdCAgMHg1Y2UyYTQ2NSwgMHhhNzMwZjMyYywgMHhkMGFhM2ZlOCwgMHg4YTVjYzA5MSwgMHhkNDllMmNlNywgMHgwY2U0NTRhOSwgMHhkNjBhY2Q4NiwgMHgwMTVmMTkxOSxcclxuXHRcdCAgMHg3NzA3OTEwMywgMHhkZWEwM2FmNiwgMHg3OGE4NTY1ZSwgMHhkZWUzNTZkZiwgMHgyMWYwNWNiZSwgMHg4Yjc1ZTM4NywgMHhiM2M1MDY1MSwgMHhiOGE1YzNlZixcclxuXHRcdCAgMHhkOGVlYjZkMiwgMHhlNTIzYmU3NywgMHhjMjE1NDUyOSwgMHgyZjY5ZWZkZiwgMHhhZmU2N2FmYiwgMHhmNDcwYzRiMiwgMHhmM2UwZWI1YiwgMHhkNmNjOTg3NixcclxuXHRcdCAgMHgzOWU0NDYwYywgMHgxZmRhODUzOCwgMHgxOTg3ODMyZiwgMHhjYTAwNzM2NywgMHhhOTkxNDRmOCwgMHgyOTZiMjk5ZSwgMHg0OTJmYzI5NSwgMHg5MjY2YmVhYixcclxuXHRcdCAgMHhiNTY3NmU2OSwgMHg5YmQzZGRkYSwgMHhkZjdlMDUyZiwgMHhkYjI1NzAxYywgMHgxYjVlNTFlZSwgMHhmNjUzMjRlNiwgMHg2YWZjZTM2YywgMHgwMzE2Y2MwNCxcclxuXHRcdCAgMHg4NjQ0MjEzZSwgMHhiN2RjNTlkMCwgMHg3OTY1MjkxZiwgMHhjY2Q2ZmQ0MywgMHg0MTgyMzk3OSwgMHg5MzJiY2RmNiwgMHhiNjU3YzM0ZCwgMHg0ZWRmZDI4MixcclxuXHRcdCAgMHg3YWU1MjkwYywgMHgzY2I5NTM2YiwgMHg4NTFlMjBmZSwgMHg5ODMzNTU3ZSwgMHgxM2VjZjBiMCwgMHhkM2ZmYjM3MiwgMHgzZjg1YzVjMSwgMHgwYWVmN2VkMik7XHJcblxyXG5cdFx0c0JveFs0XSA9IG5ldyBBcnJheShcclxuXHRcdCAgMHg3ZWM5MGMwNCwgMHgyYzZlNzRiOSwgMHg5YjBlNjZkZiwgMHhhNjMzNzkxMSwgMHhiODZhN2ZmZiwgMHgxZGQzNThmNSwgMHg0NGRkOWQ0NCwgMHgxNzMxMTY3ZixcclxuXHRcdCAgMHgwOGZiZjFmYSwgMHhlN2Y1MTFjYywgMHhkMjA1MWIwMCwgMHg3MzVhYmEwMCwgMHgyYWI3MjJkOCwgMHgzODYzODFjYiwgMHhhY2Y2MjQzYSwgMHg2OWJlZmQ3YSxcclxuXHRcdCAgMHhlNmEyZTc3ZiwgMHhmMGM3MjBjZCwgMHhjNDQ5NDgxNiwgMHhjY2Y1YzE4MCwgMHgzODg1MTY0MCwgMHgxNWIwYTg0OCwgMHhlNjhiMThjYiwgMHg0Y2FhZGVmZixcclxuXHRcdCAgMHg1ZjQ4MGEwMSwgMHgwNDEyYjJhYSwgMHgyNTk4MTRmYywgMHg0MWQwZWZlMiwgMHg0ZTQwYjQ4ZCwgMHgyNDhlYjZmYiwgMHg4ZGJhMWNmZSwgMHg0MWE5OWIwMixcclxuXHRcdCAgMHgxYTU1MGEwNCwgMHhiYThmNjVjYiwgMHg3MjUxZjRlNywgMHg5NWE1MTcyNSwgMHhjMTA2ZWNkNywgMHg5N2E1OTgwYSwgMHhjNTM5YjlhYSwgMHg0ZDc5ZmU2YSxcclxuXHRcdCAgMHhmMmYzZjc2MywgMHg2OGFmODA0MCwgMHhlZDBjOWU1NiwgMHgxMWI0OTU4YiwgMHhlMWViNWE4OCwgMHg4NzA5ZTZiMCwgMHhkN2UwNzE1NiwgMHg0ZTI5ZmVhNyxcclxuXHRcdCAgMHg2MzY2ZTUyZCwgMHgwMmQxYzAwMCwgMHhjNGFjOGUwNSwgMHg5Mzc3ZjU3MSwgMHgwYzA1MzcyYSwgMHg1Nzg1MzVmMiwgMHgyMjYxYmUwMiwgMHhkNjQyYTBjOSxcclxuXHRcdCAgMHhkZjEzYTI4MCwgMHg3NGI1NWJkMiwgMHg2ODIxOTljMCwgMHhkNDIxZTVlYywgMHg1M2ZiM2NlOCwgMHhjOGFkZWRiMywgMHgyOGE4N2ZjOSwgMHgzZDk1OTk4MSxcclxuXHRcdCAgMHg1YzFmZjkwMCwgMHhmZTM4ZDM5OSwgMHgwYzRlZmYwYiwgMHgwNjI0MDdlYSwgMHhhYTJmNGZiMSwgMHg0ZmI5Njk3NiwgMHg5MGM3OTUwNSwgMHhiMGE4YTc3NCxcclxuXHRcdCAgMHhlZjU1YTFmZiwgMHhlNTljYTJjMiwgMHhhNmI2MmQyNywgMHhlNjZhNDI2MywgMHhkZjY1MDAxZiwgMHgwZWM1MDk2NiwgMHhkZmRkNTViYywgMHgyOWRlMDY1NSxcclxuXHRcdCAgMHg5MTFlNzM5YSwgMHgxN2FmODk3NSwgMHgzMmM3OTExYywgMHg4OWY4OTQ2OCwgMHgwZDAxZTk4MCwgMHg1MjQ3NTVmNCwgMHgwM2I2M2NjOSwgMHgwY2M4NDRiMixcclxuXHRcdCAgMHhiY2YzZjBhYSwgMHg4N2FjMzZlOSwgMHhlNTNhNzQyNiwgMHgwMWIzZDgyYiwgMHgxYTllNzQ0OSwgMHg2NGVlMmQ3ZSwgMHhjZGRiYjFkYSwgMHgwMWM5NDkxMCxcclxuXHRcdCAgMHhiODY4YmY4MCwgMHgwZDI2ZjNmZCwgMHg5MzQyZWRlNywgMHgwNGE1YzI4NCwgMHg2MzY3MzdiNiwgMHg1MGY1YjYxNiwgMHhmMjQ3NjZlMywgMHg4ZWNhMzZjMSxcclxuXHRcdCAgMHgxMzZlMDVkYiwgMHhmZWYxODM5MSwgMHhmYjg4N2EzNywgMHhkNmU3ZjdkNCwgMHhjN2ZiN2RjOSwgMHgzMDYzZmNkZiwgMHhiNmY1ODlkZSwgMHhlYzI5NDFkYSxcclxuXHRcdCAgMHgyNmU0NjY5NSwgMHhiNzU2NjQxOSwgMHhmNjU0ZWZjNSwgMHhkMDhkNThiNywgMHg0ODkyNTQwMSwgMHhjMWJhY2I3ZiwgMHhlNWZmNTUwZiwgMHhiNjA4MzA0OSxcclxuXHRcdCAgMHg1YmI1ZDBlOCwgMHg4N2Q3MmU1YSwgMHhhYjZhNmVlMSwgMHgyMjNhNjZjZSwgMHhjNjJiZjNjZCwgMHg5ZTA4ODVmOSwgMHg2OGNiM2U0NywgMHgwODZjMDEwZixcclxuXHRcdCAgMHhhMjFkZTgyMCwgMHhkMThiNjlkZSwgMHhmM2Y2NTc3NywgMHhmYTAyYzNmNiwgMHg0MDdlZGFjMywgMHhjYmIzZDU1MCwgMHgxNzkzMDg0ZCwgMHhiMGQ3MGViYSxcclxuXHRcdCAgMHgwYWIzNzhkNSwgMHhkOTUxZmIwYywgMHhkZWQ3ZGE1NiwgMHg0MTI0YmJlNCwgMHg5NGNhMGI1NiwgMHgwZjU3NTVkMSwgMHhlMGUxZTU2ZSwgMHg2MTg0YjViZSxcclxuXHRcdCAgMHg1ODBhMjQ5ZiwgMHg5NGY3NGJjMCwgMHhlMzI3ODg4ZSwgMHg5ZjdiNTU2MSwgMHhjM2RjMDI4MCwgMHgwNTY4NzcxNSwgMHg2NDZjNmJkNywgMHg0NDkwNGRiMyxcclxuXHRcdCAgMHg2NmI0ZjBhMywgMHhjMGYxNjQ4YSwgMHg2OTdlZDVhZiwgMHg0OWU5MmZmNiwgMHgzMDllMzc0ZiwgMHgyY2I2MzU2YSwgMHg4NTgwODU3MywgMHg0OTkxZjg0MCxcclxuXHRcdCAgMHg3NmYwYWUwMiwgMHgwODNiZTg0ZCwgMHgyODQyMWM5YSwgMHg0NDQ4OTQwNiwgMHg3MzZlNGNiOCwgMHhjMTA5MjkxMCwgMHg4YmM5NWZjNiwgMHg3ZDg2OWNmNCxcclxuXHRcdCAgMHgxMzRmNjE2ZiwgMHgyZTc3MTE4ZCwgMHhiMzFiMmJlMSwgMHhhYTkwYjQ3MiwgMHgzY2E1ZDcxNywgMHg3ZDE2MWJiYSwgMHg5Y2FkOTAxMCwgMHhhZjQ2MmJhMixcclxuXHRcdCAgMHg5ZmU0NTlkMiwgMHg0NWQzNDU1OSwgMHhkOWYyZGExMywgMHhkYmM2NTQ4NywgMHhmM2U0Zjk0ZSwgMHgxNzZkNDg2ZiwgMHgwOTdjMTNlYSwgMHg2MzFkYTVjNyxcclxuXHRcdCAgMHg0NDVmNzM4MiwgMHgxNzU2ODNmNCwgMHhjZGM2NmE5NywgMHg3MGJlMDI4OCwgMHhiM2NkY2Y3MiwgMHg2ZTVkZDJmMywgMHgyMDkzNjA3OSwgMHg0NTliODBhNSxcclxuXHRcdCAgMHhiZTYwZTJkYiwgMHhhOWMyMzEwMSwgMHhlYmE1MzE1YywgMHgyMjRlNDJmMiwgMHgxYzVjMTU3MiwgMHhmNjcyMWIyYywgMHgxYWQyZmZmMywgMHg4YzI1NDA0ZSxcclxuXHRcdCAgMHgzMjRlZDcyZiwgMHg0MDY3YjdmZCwgMHgwNTIzMTM4ZSwgMHg1Y2EzYmM3OCwgMHhkYzBmZDY2ZSwgMHg3NTkyMjI4MywgMHg3ODRkNmIxNywgMHg1OGViYjE2ZSxcclxuXHRcdCAgMHg0NDA5NGY4NSwgMHgzZjQ4MWQ4NywgMHhmY2ZlYWU3YiwgMHg3N2I1ZmY3NiwgMHg4YzIzMDJiZiwgMHhhYWY0NzU1NiwgMHg1ZjQ2YjAyYSwgMHgyYjA5MjgwMSxcclxuXHRcdCAgMHgzZDM4ZjVmNywgMHgwY2E4MWYzNiwgMHg1MmFmNGE4YSwgMHg2NmQ1ZTdjMCwgMHhkZjNiMDg3NCwgMHg5NTA1NTExMCwgMHgxYjVhZDdhOCwgMHhmNjFlZDVhZCxcclxuXHRcdCAgMHg2Y2Y2ZTQ3OSwgMHgyMDc1ODE4NCwgMHhkMGNlZmE2NSwgMHg4OGY3YmU1OCwgMHg0YTA0NjgyNiwgMHgwZmY2ZjhmMywgMHhhMDljN2Y3MCwgMHg1MzQ2YWJhMCxcclxuXHRcdCAgMHg1Y2U5NmMyOCwgMHhlMTc2ZWRhMywgMHg2YmFjMzA3ZiwgMHgzNzY4MjlkMiwgMHg4NTM2MGZhOSwgMHgxN2UzZmUyYSwgMHgyNGI3OTc2NywgMHhmNWE5NmIyMCxcclxuXHRcdCAgMHhkNmNkMjU5NSwgMHg2OGZmMWViZiwgMHg3NTU1NDQyYywgMHhmMTlmMDZiZSwgMHhmOWUwNjU5YSwgMHhlZWI5NDkxZCwgMHgzNDAxMDcxOCwgMHhiYjMwY2FiOCxcclxuXHRcdCAgMHhlODIyZmUxNSwgMHg4ODU3MDk4MywgMHg3NTBlNjI0OSwgMHhkYTYyN2U1NSwgMHg1ZTc2ZmZhOCwgMHhiMTUzNDU0NiwgMHg2ZDQ3ZGUwOCwgMHhlZmU5ZTdkNCk7XHJcblxyXG5cdFx0c0JveFs1XSA9IG5ldyBBcnJheShcclxuXHRcdCAgMHhmNmZhOGY5ZCwgMHgyY2FjNmNlMSwgMHg0Y2EzNDg2NywgMHhlMjMzN2Y3YywgMHg5NWRiMDhlNywgMHgwMTY4NDNiNCwgMHhlY2VkNWNiYywgMHgzMjU1NTNhYyxcclxuXHRcdCAgMHhiZjlmMDk2MCwgMHhkZmExZTJlZCwgMHg4M2YwNTc5ZCwgMHg2M2VkODZiOSwgMHgxYWI2YTZiOCwgMHhkZTVlYmUzOSwgMHhmMzhmZjczMiwgMHg4OTg5YjEzOCxcclxuXHRcdCAgMHgzM2YxNDk2MSwgMHhjMDE5MzdiZCwgMHhmNTA2YzZkYSwgMHhlNDYyNWU3ZSwgMHhhMzA4ZWE5OSwgMHg0ZTIzZTMzYywgMHg3OWNiZDdjYywgMHg0OGExNDM2NyxcclxuXHRcdCAgMHhhMzE0OTYxOSwgMHhmZWM5NGJkNSwgMHhhMTE0MTc0YSwgMHhlYWEwMTg2NiwgMHhhMDg0ZGIyZCwgMHgwOWE4NDg2ZiwgMHhhODg4NjE0YSwgMHgyOTAwYWY5OCxcclxuXHRcdCAgMHgwMTY2NTk5MSwgMHhlMTk5Mjg2MywgMHhjOGYzMGM2MCwgMHgyZTc4ZWYzYywgMHhkMGQ1MTkzMiwgMHhjZjBmZWMxNCwgMHhmN2NhMDdkMiwgMHhkMGE4MjA3MixcclxuXHRcdCAgMHhmZDQxMTk3ZSwgMHg5MzA1YTZiMCwgMHhlODZiZTNkYSwgMHg3NGJlZDNjZCwgMHgzNzJkYTUzYywgMHg0YzdmNDQ0OCwgMHhkYWI1ZDQ0MCwgMHg2ZGJhMGVjMyxcclxuXHRcdCAgMHgwODM5MTlhNywgMHg5ZmJhZWVkOSwgMHg0OWRiY2ZiMCwgMHg0ZTY3MGM1MywgMHg1YzNkOWMwMSwgMHg2NGJkYjk0MSwgMHgyYzBlNjM2YSwgMHhiYTdkZDljZCxcclxuXHRcdCAgMHhlYTZmNzM4OCwgMHhlNzBiYzc2MiwgMHgzNWYyOWFkYiwgMHg1YzRjZGQ4ZCwgMHhmMGQ0OGQ4YywgMHhiODgxNTNlMiwgMHgwOGExOTg2NiwgMHgxYWUyZWFjOCxcclxuXHRcdCAgMHgyODRjYWY4OSwgMHhhYTkyODIyMywgMHg5MzM0YmU1MywgMHgzYjNhMjFiZiwgMHgxNjQzNGJlMywgMHg5YWVhMzkwNiwgMHhlZmU4YzM2ZSwgMHhmODkwY2RkOSxcclxuXHRcdCAgMHg4MDIyNmRhZSwgMHhjMzQwYTRhMywgMHhkZjdlOWMwOSwgMHhhNjk0YTgwNywgMHg1YjdjNWVjYywgMHgyMjFkYjNhNiwgMHg5YTY5YTAyZiwgMHg2ODgxOGE1NCxcclxuXHRcdCAgMHhjZWIyMjk2ZiwgMHg1M2MwODQzYSwgMHhmZTg5MzY1NSwgMHgyNWJmZTY4YSwgMHhiNDYyOGFiYywgMHhjZjIyMmViZiwgMHgyNWFjNmY0OCwgMHhhOWE5OTM4NyxcclxuXHRcdCAgMHg1M2JkZGI2NSwgMHhlNzZmZmJlNywgMHhlOTY3ZmQ3OCwgMHgwYmE5MzU2MywgMHg4ZTM0MmJjMSwgMHhlOGExMWJlOSwgMHg0OTgwNzQwZCwgMHhjODA4N2RmYyxcclxuXHRcdCAgMHg4ZGU0YmY5OSwgMHhhMTExMDFhMCwgMHg3ZmQzNzk3NSwgMHhkYTVhMjZjMCwgMHhlODFmOTk0ZiwgMHg5NTI4Y2Q4OSwgMHhmZDMzOWZlZCwgMHhiODc4MzRiZixcclxuXHRcdCAgMHg1ZjA0NDU2ZCwgMHgyMjI1ODY5OCwgMHhjOWM0YzgzYiwgMHgyZGMxNTZiZSwgMHg0ZjYyOGRhYSwgMHg1N2Y1NWVjNSwgMHhlMjIyMGFiZSwgMHhkMjkxNmViZixcclxuXHRcdCAgMHg0ZWM3NWI5NSwgMHgyNGYyYzNjMCwgMHg0MmQxNWQ5OSwgMHhjZDBkN2ZhMCwgMHg3YjZlMjdmZiwgMHhhOGRjOGFmMCwgMHg3MzQ1YzEwNiwgMHhmNDFlMjMyZixcclxuXHRcdCAgMHgzNTE2MjM4NiwgMHhlNmVhODkyNiwgMHgzMzMzYjA5NCwgMHgxNTdlYzZmMiwgMHgzNzJiNzRhZiwgMHg2OTI1NzNlNCwgMHhlOWE5ZDg0OCwgMHhmMzE2MDI4OSxcclxuXHRcdCAgMHgzYTYyZWYxZCwgMHhhNzg3ZTIzOCwgMHhmM2E1ZjY3NiwgMHg3NDM2NDg1MywgMHgyMDk1MTA2MywgMHg0NTc2Njk4ZCwgMHhiNmZhZDQwNywgMHg1OTJhZjk1MCxcclxuXHRcdCAgMHgzNmY3MzUyMywgMHg0Y2ZiNmU4NywgMHg3ZGE0Y2VjMCwgMHg2YzE1MmRhYSwgMHhjYjAzOTZhOCwgMHhjNTBkZmU1ZCwgMHhmY2Q3MDdhYiwgMHgwOTIxYzQyZixcclxuXHRcdCAgMHg4OWRmZjBiYiwgMHg1ZmUyYmU3OCwgMHg0NDhmNGYzMywgMHg3NTQ2MTNjOSwgMHgyYjA1ZDA4ZCwgMHg0OGI5ZDU4NSwgMHhkYzA0OTQ0MSwgMHhjODA5OGY5YixcclxuXHRcdCAgMHg3ZGVkZTc4NiwgMHhjMzlhMzM3MywgMHg0MjQxMDAwNSwgMHg2YTA5MTc1MSwgMHgwZWYzYzhhNiwgMHg4OTAwNzJkNiwgMHgyODIwNzY4MiwgMHhhOWE5ZjdiZSxcclxuXHRcdCAgMHhiZjMyNjc5ZCwgMHhkNDViNWI3NSwgMHhiMzUzZmQwMCwgMHhjYmIwZTM1OCwgMHg4MzBmMjIwYSwgMHgxZjhmYjIxNCwgMHhkMzcyY2YwOCwgMHhjYzNjNGExMyxcclxuXHRcdCAgMHg4Y2Y2MzE2NiwgMHgwNjFjODdiZSwgMHg4OGM5OGY4OCwgMHg2MDYyZTM5NywgMHg0N2NmOGU3YSwgMHhiNmM4NTI4MywgMHgzY2MyYWNmYiwgMHgzZmMwNjk3NixcclxuXHRcdCAgMHg0ZThmMDI1MiwgMHg2NGQ4MzE0ZCwgMHhkYTM4NzBlMywgMHgxZTY2NTQ1OSwgMHhjMTA5MDhmMCwgMHg1MTMwMjFhNSwgMHg2YzViNjhiNywgMHg4MjJmOGFhMCxcclxuXHRcdCAgMHgzMDA3Y2QzZSwgMHg3NDcxOWVlZiwgMHhkYzg3MjY4MSwgMHgwNzMzNDBkNCwgMHg3ZTQzMmZkOSwgMHgwYzVlYzI0MSwgMHg4ODA5Mjg2YywgMHhmNTkyZDg5MSxcclxuXHRcdCAgMHgwOGE5MzBmNiwgMHg5NTdlZjMwNSwgMHhiN2ZiZmZiZCwgMHhjMjY2ZTk2ZiwgMHg2ZmU0YWM5OCwgMHhiMTczZWNjMCwgMHhiYzYwYjQyYSwgMHg5NTM0OThkYSxcclxuXHRcdCAgMHhmYmExYWUxMiwgMHgyZDRiZDczNiwgMHgwZjI1ZmFhYiwgMHhhNGYzZmNlYiwgMHhlMjk2OTEyMywgMHgyNTdmMGMzZCwgMHg5MzQ4YWY0OSwgMHgzNjE0MDBiYyxcclxuXHRcdCAgMHhlODgxNmY0YSwgMHgzODE0ZjIwMCwgMHhhM2Y5NDA0MywgMHg5YzdhNTRjMiwgMHhiYzcwNGY1NywgMHhkYTQxZTdmOSwgMHhjMjVhZDMzYSwgMHg1NGY0YTA4NCxcclxuXHRcdCAgMHhiMTdmNTUwNSwgMHg1OTM1N2NiZSwgMHhlZGJkMTVjOCwgMHg3Zjk3YzVhYiwgMHhiYTVhYzdiNSwgMHhiNmY2ZGVhZiwgMHgzYTQ3OWMzYSwgMHg1MzAyZGEyNSxcclxuXHRcdCAgMHg2NTNkN2U2YSwgMHg1NDI2OGQ0OSwgMHg1MWE0NzdlYSwgMHg1MDE3ZDU1YiwgMHhkN2QyNWQ4OCwgMHg0NDEzNmM3NiwgMHgwNDA0YThjOCwgMHhiOGU1YTEyMSxcclxuXHRcdCAgMHhiODFhOTI4YSwgMHg2MGVkNTg2OSwgMHg5N2M1NWI5NiwgMHhlYWVjOTkxYiwgMHgyOTkzNTkxMywgMHgwMWZkYjdmMSwgMHgwODhlOGRmYSwgMHg5YWI2ZjZmNSxcclxuXHRcdCAgMHgzYjRjYmY5ZiwgMHg0YTVkZTNhYiwgMHhlNjA1MWQzNSwgMHhhMGUxZDg1NSwgMHhkMzZiNGNmMSwgMHhmNTQ0ZWRlYiwgMHhiMGU5MzUyNCwgMHhiZWJiOGZiZCxcclxuXHRcdCAgMHhhMmQ3NjJjZiwgMHg0OWM5MmY1NCwgMHgzOGI1ZjMzMSwgMHg3MTI4YTQ1NCwgMHg0ODM5MjkwNSwgMHhhNjViMWRiOCwgMHg4NTFjOTdiZCwgMHhkNjc1Y2YyZik7XHJcblxyXG5cdFx0c0JveFs2XSA9IG5ldyBBcnJheShcclxuXHRcdCAgMHg4NWUwNDAxOSwgMHgzMzJiZjU2NywgMHg2NjJkYmZmZiwgMHhjZmM2NTY5MywgMHgyYThkN2Y2ZiwgMHhhYjliYzkxMiwgMHhkZTYwMDhhMSwgMHgyMDI4ZGExZixcclxuXHRcdCAgMHgwMjI3YmNlNywgMHg0ZDY0MjkxNiwgMHgxOGZhYzMwMCwgMHg1MGYxOGI4MiwgMHgyY2IyY2IxMSwgMHhiMjMyZTc1YywgMHg0YjM2OTVmMiwgMHhiMjg3MDdkZSxcclxuXHRcdCAgMHhhMDVmYmNmNiwgMHhjZDQxODFlOSwgMHhlMTUwMjEwYywgMHhlMjRlZjFiZCwgMHhiMTY4YzM4MSwgMHhmZGU0ZTc4OSwgMHg1Yzc5YjBkOCwgMHgxZThiZmQ0MyxcclxuXHRcdCAgMHg0ZDQ5NTAwMSwgMHgzOGJlNDM0MSwgMHg5MTNjZWUxZCwgMHg5MmE3OWMzZiwgMHgwODk3NjZiZSwgMHhiYWVlYWRmNCwgMHgxMjg2YmVjZiwgMHhiNmVhY2IxOSxcclxuXHRcdCAgMHgyNjYwYzIwMCwgMHg3NTY1YmRlNCwgMHg2NDI0MWY3YSwgMHg4MjQ4ZGNhOSwgMHhjM2IzYWQ2NiwgMHgyODEzNjA4NiwgMHgwYmQ4ZGZhOCwgMHgzNTZkMWNmMixcclxuXHRcdCAgMHgxMDc3ODliZSwgMHhiM2IyZTljZSwgMHgwNTAyYWE4ZiwgMHgwYmMwMzUxZSwgMHgxNjZiZjUyYSwgMHhlYjEyZmY4MiwgMHhlMzQ4NjkxMSwgMHhkMzRkNzUxNixcclxuXHRcdCAgMHg0ZTdiM2FmZiwgMHg1ZjQzNjcxYiwgMHg5Y2Y2ZTAzNywgMHg0OTgxYWM4MywgMHgzMzQyNjZjZSwgMHg4YzkzNDFiNywgMHhkMGQ4NTRjMCwgMHhjYjNhNmM4OCxcclxuXHRcdCAgMHg0N2JjMjgyOSwgMHg0NzI1YmEzNywgMHhhNjZhZDIyYiwgMHg3YWQ2MWYxZSwgMHgwYzVjYmFmYSwgMHg0NDM3ZjEwNywgMHhiNmU3OTk2MiwgMHg0MmQyZDgxNixcclxuXHRcdCAgMHgwYTk2MTI4OCwgMHhlMWE1YzA2ZSwgMHgxMzc0OWU2NywgMHg3MmZjMDgxYSwgMHhiMWQxMzlmNywgMHhmOTU4Mzc0NSwgMHhjZjE5ZGY1OCwgMHhiZWMzZjc1NixcclxuXHRcdCAgMHhjMDZlYmEzMCwgMHgwNzIxMWIyNCwgMHg0NWMyODgyOSwgMHhjOTVlMzE3ZiwgMHhiYzhlYzUxMSwgMHgzOGJjNDZlOSwgMHhjNmU2ZmExNCwgMHhiYWU4NTg0YSxcclxuXHRcdCAgMHhhZDRlYmM0NiwgMHg0NjhmNTA4YiwgMHg3ODI5NDM1ZiwgMHhmMTI0MTgzYiwgMHg4MjFkYmE5ZiwgMHhhZmY2MGZmNCwgMHhlYTJjNGU2ZCwgMHgxNmUzOTI2NCxcclxuXHRcdCAgMHg5MjU0NGE4YiwgMHgwMDliNGZjMywgMHhhYmE2OGNlZCwgMHg5YWM5NmY3OCwgMHgwNmE1Yjc5YSwgMHhiMjg1NmU2ZSwgMHgxYWVjM2NhOSwgMHhiZTgzODY4OCxcclxuXHRcdCAgMHgwZTA4MDRlOSwgMHg1NWYxYmU1NiwgMHhlN2U1MzYzYiwgMHhiM2ExZjI1ZCwgMHhmN2RlYmI4NSwgMHg2MWZlMDMzYywgMHgxNjc0NjIzMywgMHgzYzAzNGMyOCxcclxuXHRcdCAgMHhkYTZkMGM3NCwgMHg3OWFhYzU2YywgMHgzY2U0ZTFhZCwgMHg1MWYwYzgwMiwgMHg5OGY4ZjM1YSwgMHgxNjI2YTQ5ZiwgMHhlZWQ4MmIyOSwgMHgxZDM4MmZlMyxcclxuXHRcdCAgMHgwYzRmYjk5YSwgMHhiYjMyNTc3OCwgMHgzZWM2ZDk3YiwgMHg2ZTc3YTZhOSwgMHhjYjY1OGI1YywgMHhkNDUyMzBjNywgMHgyYmQxNDA4YiwgMHg2MGMwM2ViNyxcclxuXHRcdCAgMHhiOTA2OGQ3OCwgMHhhMzM3NTRmNCwgMHhmNDMwYzg3ZCwgMHhjOGE3MTMwMiwgMHhiOTZkOGMzMiwgMHhlYmQ0ZTdiZSwgMHhiZThiOWQyZCwgMHg3OTc5ZmIwNixcclxuXHRcdCAgMHhlNzIyNTMwOCwgMHg4Yjc1Y2Y3NywgMHgxMWVmOGRhNCwgMHhlMDgzYzg1OCwgMHg4ZDZiNzg2ZiwgMHg1YTYzMTdhNiwgMHhmYTVjZjdhMCwgMHg1ZGRhMDAzMyxcclxuXHRcdCAgMHhmMjhlYmZiMCwgMHhmNWI5YzMxMCwgMHhhMGVhYzI4MCwgMHgwOGI5NzY3YSwgMHhhM2Q5ZDJiMCwgMHg3OWQzNDIxNywgMHgwMjFhNzE4ZCwgMHg5YWM2MzM2YSxcclxuXHRcdCAgMHgyNzExZmQ2MCwgMHg0MzgwNTBlMywgMHgwNjk5MDhhOCwgMHgzZDdmZWRjNCwgMHg4MjZkMmJlZiwgMHg0ZWViODQ3NiwgMHg0ODhkY2YyNSwgMHgzNmM5ZDU2NixcclxuXHRcdCAgMHgyOGU3NGU0MSwgMHhjMjYxMGFjYSwgMHgzZDQ5YTljZiwgMHhiYWUzYjlkZiwgMHhiNjVmOGRlNiwgMHg5MmFlYWY2NCwgMHgzYWM3ZDVlNiwgMHg5ZWE4MDUwOSxcclxuXHRcdCAgMHhmMjJiMDE3ZCwgMHhhNDE3M2Y3MCwgMHhkZDFlMTZjMywgMHgxNWUwZDdmOSwgMHg1MGIxYjg4NywgMHgyYjlmNGZkNSwgMHg2MjVhYmE4MiwgMHg2YTAxNzk2MixcclxuXHRcdCAgMHgyZWMwMWI5YywgMHgxNTQ4OGFhOSwgMHhkNzE2ZTc0MCwgMHg0MDA1NWEyYywgMHg5M2QyOWEyMiwgMHhlMzJkYmY5YSwgMHgwNTg3NDViOSwgMHgzNDUzZGMxZSxcclxuXHRcdCAgMHhkNjk5Mjk2ZSwgMHg0OTZjZmY2ZiwgMHgxYzlmNDk4NiwgMHhkZmUyZWQwNywgMHhiODcyNDJkMSwgMHgxOWRlN2VhZSwgMHgwNTNlNTYxYSwgMHgxNWFkNmY4YyxcclxuXHRcdCAgMHg2NjYyNmMxYywgMHg3MTU0YzI0YywgMHhlYTA4MmIyYSwgMHg5M2ViMjkzOSwgMHgxN2RjYjBmMCwgMHg1OGQ0ZjJhZSwgMHg5ZWEyOTRmYiwgMHg1MmNmNTY0YyxcclxuXHRcdCAgMHg5ODgzZmU2NiwgMHgyZWM0MDU4MSwgMHg3NjM5NTNjMywgMHgwMWQ2NjkyZSwgMHhkM2EwYzEwOCwgMHhhMWU3MTYwZSwgMHhlNGYyZGZhNiwgMHg2OTNlZDI4NSxcclxuXHRcdCAgMHg3NDkwNDY5OCwgMHg0YzJiMGVkZCwgMHg0Zjc1NzY1NiwgMHg1ZDM5MzM3OCwgMHhhMTMyMjM0ZiwgMHgzZDMyMWM1ZCwgMHhjM2Y1ZTE5NCwgMHg0YjI2OTMwMSxcclxuXHRcdCAgMHhjNzlmMDIyZiwgMHgzYzk5N2U3ZSwgMHg1ZTRmOTUwNCwgMHgzZmZhZmJiZCwgMHg3NmY3YWQwZSwgMHgyOTY2OTNmNCwgMHgzZDFmY2U2ZiwgMHhjNjFlNDViZSxcclxuXHRcdCAgMHhkM2I1YWIzNCwgMHhmNzJiZjliNywgMHgxYjA0MzRjMCwgMHg0ZTcyYjU2NywgMHg1NTkyYTMzZCwgMHhiNTIyOTMwMSwgMHhjZmQyYTg3ZiwgMHg2MGFlYjc2NyxcclxuXHRcdCAgMHgxODE0Mzg2YiwgMHgzMGJjYzMzZCwgMHgzOGEwYzA3ZCwgMHhmZDE2MDZmMiwgMHhjMzYzNTE5YiwgMHg1ODlkZDM5MCwgMHg1NDc5ZjhlNiwgMHgxY2I4ZDY0NyxcclxuXHRcdCAgMHg5N2ZkNjFhOSwgMHhlYTc3NTlmNCwgMHgyZDU3NTM5ZCwgMHg1NjlhNThjZiwgMHhlODRlNjNhZCwgMHg0NjJlMWI3OCwgMHg2NTgwZjg3ZSwgMHhmMzgxNzkxNCxcclxuXHRcdCAgMHg5MWRhNTVmNCwgMHg0MGEyMzBmMywgMHhkMTk4OGYzNSwgMHhiNmUzMThkMiwgMHgzZmZhNTBiYywgMHgzZDQwZjAyMSwgMHhjM2MwYmRhZSwgMHg0OTU4YzI0YyxcclxuXHRcdCAgMHg1MThmMzZiMiwgMHg4NGIxZDM3MCwgMHgwZmVkY2U4MywgMHg4NzhkZGFkYSwgMHhmMmEyNzljNywgMHg5NGUwMWJlOCwgMHg5MDcxNmY0YiwgMHg5NTRiOGFhMyk7XHJcblxyXG5cdFx0c0JveFs3XSA9IG5ldyBBcnJheShcclxuXHRcdCAgMHhlMjE2MzAwZCwgMHhiYmRkZmZmYywgMHhhN2ViZGFiZCwgMHgzNTY0ODA5NSwgMHg3Nzg5ZjhiNywgMHhlNmMxMTIxYiwgMHgwZTI0MTYwMCwgMHgwNTJjZThiNSxcclxuXHRcdCAgMHgxMWE5Y2ZiMCwgMHhlNTk1MmYxMSwgMHhlY2U3OTkwYSwgMHg5Mzg2ZDE3NCwgMHgyYTQyOTMxYywgMHg3NmUzODExMSwgMHhiMTJkZWYzYSwgMHgzN2RkZGRmYyxcclxuXHRcdCAgMHhkZTlhZGViMSwgMHgwYTBjYzMyYywgMHhiZTE5NzAyOSwgMHg4NGEwMDk0MCwgMHhiYjI0M2EwZiwgMHhiNGQxMzdjZiwgMHhiNDRlNzlmMCwgMHgwNDllZWRmZCxcclxuXHRcdCAgMHgwYjE1YTE1ZCwgMHg0ODBkMzE2OCwgMHg4YmJiZGU1YSwgMHg2NjlkZWQ0MiwgMHhjN2VjZTgzMSwgMHgzZjhmOTVlNywgMHg3MmRmMTkxYiwgMHg3NTgwMzMwZCxcclxuXHRcdCAgMHg5NDA3NDI1MSwgMHg1YzdkY2RmYSwgMHhhYmJlNmQ2MywgMHhhYTQwMjE2NCwgMHhiMzAxZDQwYSwgMHgwMmU3ZDFjYSwgMHg1MzU3MWRhZSwgMHg3YTMxODJhMixcclxuXHRcdCAgMHgxMmE4ZGRlYywgMHhmZGFhMzM1ZCwgMHgxNzZmNDNlOCwgMHg3MWZiNDZkNCwgMHgzODEyOTAyMiwgMHhjZTk0OWFkNCwgMHhiODQ3NjlhZCwgMHg5NjViZDg2MixcclxuXHRcdCAgMHg4MmYzZDA1NSwgMHg2NmZiOTc2NywgMHgxNWI4MGI0ZSwgMHgxZDViNDdhMCwgMHg0Y2ZkZTA2ZiwgMHhjMjhlYzRiOCwgMHg1N2U4NzI2ZSwgMHg2NDdhNzhmYyxcclxuXHRcdCAgMHg5OTg2NWQ0NCwgMHg2MDhiZDU5MywgMHg2YzIwMGUwMywgMHgzOWRjNWZmNiwgMHg1ZDBiMDBhMywgMHhhZTYzYWZmMiwgMHg3ZThiZDYzMiwgMHg3MDEwOGMwYyxcclxuXHRcdCAgMHhiYmQzNTA0OSwgMHgyOTk4ZGYwNCwgMHg5ODBjZjQyYSwgMHg5YjZkZjQ5MSwgMHg5ZTdlZGQ1MywgMHgwNjkxODU0OCwgMHg1OGNiN2UwNywgMHgzYjc0ZWYyZSxcclxuXHRcdCAgMHg1MjJmZmZiMSwgMHhkMjQ3MDhjYywgMHgxYzdlMjdjZCwgMHhhNGViMjE1YiwgMHgzY2YxZDJlMiwgMHgxOWI0N2EzOCwgMHg0MjRmNzYxOCwgMHgzNTg1NjAzOSxcclxuXHRcdCAgMHg5ZDE3ZGVlNywgMHgyN2ViMzVlNiwgMHhjOWFmZjY3YiwgMHgzNmJhZjViOCwgMHgwOWM0NjdjZCwgMHhjMTg5MTBiMSwgMHhlMTFkYmY3YiwgMHgwNmNkMWFmOCxcclxuXHRcdCAgMHg3MTcwYzYwOCwgMHgyZDVlMzM1NCwgMHhkNGRlNDk1YSwgMHg2NGM2ZDAwNiwgMHhiY2MwYzYyYywgMHgzZGQwMGRiMywgMHg3MDhmOGYzNCwgMHg3N2Q1MWI0MixcclxuXHRcdCAgMHgyNjRmNjIwZiwgMHgyNGI4ZDJiZiwgMHgxNWMxYjc5ZSwgMHg0NmE1MjU2NCwgMHhmOGQ3ZTU0ZSwgMHgzZTM3ODE2MCwgMHg3ODk1Y2RhNSwgMHg4NTljMTVhNSxcclxuXHRcdCAgMHhlNjQ1OTc4OCwgMHhjMzdiYzc1ZiwgMHhkYjA3YmEwYywgMHgwNjc2YTNhYiwgMHg3ZjIyOWIxZSwgMHgzMTg0MmU3YiwgMHgyNDI1OWZkNywgMHhmOGJlZjQ3MixcclxuXHRcdCAgMHg4MzVmZmNiOCwgMHg2ZGY0YzFmMiwgMHg5NmY1YjE5NSwgMHhmZDBhZjBmYywgMHhiMGZlMTM0YywgMHhlMjUwNmQzZCwgMHg0ZjliMTJlYSwgMHhmMjE1ZjIyNSxcclxuXHRcdCAgMHhhMjIzNzM2ZiwgMHg5ZmI0YzQyOCwgMHgyNWQwNDk3OSwgMHgzNGM3MTNmOCwgMHhjNDYxODE4NywgMHhlYTdhNmU5OCwgMHg3Y2QxNmVmYywgMHgxNDM2ODc2YyxcclxuXHRcdCAgMHhmMTU0NDEwNywgMHhiZWRlZWUxNCwgMHg1NmU5YWYyNywgMHhhMDRhYTQ0MSwgMHgzY2Y3Yzg5OSwgMHg5MmVjYmFlNiwgMHhkZDY3MDE2ZCwgMHgxNTE2ODJlYixcclxuXHRcdCAgMHhhODQyZWVkZiwgMHhmZGJhNjBiNCwgMHhmMTkwN2I3NSwgMHgyMGUzMDMwZiwgMHgyNGQ4YzI5ZSwgMHhlMTM5NjczYiwgMHhlZmE2M2ZiOCwgMHg3MTg3MzA1NCxcclxuXHRcdCAgMHhiNmYyY2YzYiwgMHg5ZjMyNjQ0MiwgMHhjYjE1YTRjYywgMHhiMDFhNDUwNCwgMHhmMWU0N2Q4ZCwgMHg4NDRhMWJlNSwgMHhiYWU3ZGZkYywgMHg0MmNiZGE3MCxcclxuXHRcdCAgMHhjZDdkYWUwYSwgMHg1N2U4NWI3YSwgMHhkNTNmNWFmNiwgMHgyMGNmNGQ4YywgMHhjZWE0ZDQyOCwgMHg3OWQxMzBhNCwgMHgzNDg2ZWJmYiwgMHgzM2QzY2RkYyxcclxuXHRcdCAgMHg3Nzg1M2I1MywgMHgzN2VmZmNiNSwgMHhjNTA2ODc3OCwgMHhlNTgwYjNlNiwgMHg0ZTY4YjhmNCwgMHhjNWM4YjM3ZSwgMHgwZDgwOWVhMiwgMHgzOThmZWI3YyxcclxuXHRcdCAgMHgxMzJhNGY5NCwgMHg0M2I3OTUwZSwgMHgyZmVlN2QxYywgMHgyMjM2MTNiZCwgMHhkZDA2Y2FhMiwgMHgzN2RmOTMyYiwgMHhjNDI0ODI4OSwgMHhhY2YzZWJjMyxcclxuXHRcdCAgMHg1NzE1ZjZiNywgMHhlZjM0NzhkZCwgMHhmMjY3NjE2ZiwgMHhjMTQ4Y2JlNCwgMHg5MDUyODE1ZSwgMHg1ZTQxMGZhYiwgMHhiNDhhMjQ2NSwgMHgyZWRhN2ZhNCxcclxuXHRcdCAgMHhlODdiNDBlNCwgMHhlOThlYTA4NCwgMHg1ODg5ZTllMSwgMHhlZmQzOTBmYywgMHhkZDA3ZDM1YiwgMHhkYjQ4NTY5NCwgMHgzOGQ3ZTViMiwgMHg1NzcyMDEwMSxcclxuXHRcdCAgMHg3MzBlZGViYywgMHg1YjY0MzExMywgMHg5NDkxN2U0ZiwgMHg1MDNjMmZiYSwgMHg2NDZmMTI4MiwgMHg3NTIzZDI0YSwgMHhlMDc3OTY5NSwgMHhmOWMxN2E4ZixcclxuXHRcdCAgMHg3YTViMjEyMSwgMHhkMTg3Yjg5NiwgMHgyOTI2M2E0ZCwgMHhiYTUxMGNkZiwgMHg4MWY0N2M5ZiwgMHhhZDExNjNlZCwgMHhlYTdiNTk2NSwgMHgxYTAwNzI2ZSxcclxuXHRcdCAgMHgxMTQwMzA5MiwgMHgwMGRhNmQ3NywgMHg0YTBjZGQ2MSwgMHhhZDFmNDYwMywgMHg2MDViZGZiMCwgMHg5ZWVkYzM2NCwgMHgyMmViZTZhOCwgMHhjZWU3ZDI4YSxcclxuXHRcdCAgMHhhMGU3MzZhMCwgMHg1NTY0YTZiOSwgMHgxMDg1MzIwOSwgMHhjN2ViOGYzNywgMHgyZGU3MDVjYSwgMHg4OTUxNTcwZiwgMHhkZjA5ODIyYiwgMHhiZDY5MWE2YyxcclxuXHRcdCAgMHhhYTEyZTRmMiwgMHg4NzQ1MWMwZiwgMHhlMGY2YTI3YSwgMHgzYWRhNDgxOSwgMHg0Y2YxNzY0ZiwgMHgwZDc3MWMyYiwgMHg2N2NkYjE1NiwgMHgzNTBkODM4NCxcclxuXHRcdCAgMHg1OTM4ZmEwZiwgMHg0MjM5OWVmMywgMHgzNjk5N2IwNywgMHgwZTg0MDkzZCwgMHg0YWE5M2U2MSwgMHg4MzYwZDg3YiwgMHgxZmE5OGIwYywgMHgxMTQ5MzgyYyxcclxuXHRcdCAgMHhlOTc2MjVhNSwgMHgwNjE0ZDFiNywgMHgwZTI1MjQ0YiwgMHgwYzc2ODM0NywgMHg1ODllOGQ4MiwgMHgwZDIwNTlkMSwgMHhhNDY2YmIxZSwgMHhmOGRhMGE4MixcclxuXHRcdCAgMHgwNGYxOTEzMCwgMHhiYTZlNGVjMCwgMHg5OTI2NTE2NCwgMHgxZWU3MjMwZCwgMHg1MGIyYWQ4MCwgMHhlYWVlNjgwMSwgMHg4ZGIyYTI4MywgMHhlYThiZjU5ZSk7XHJcblxyXG59O1xyXG5cclxuXHJcbm1vZHVsZS5leHBvcnRzID0gY2FzdDVfZW5jcnlwdDtcclxuIiwiLyogTW9kaWZpZWQgYnkgUmVjdXJpdHkgTGFicyBHbWJIIFxuICogXG4gKiBPcmlnaW5hbGx5IHdyaXR0ZW4gYnkgbmtsZWluIHNvZnR3YXJlIChua2xlaW4uY29tKVxuICovXG5cbi8qIFxuICogSmF2YXNjcmlwdCBpbXBsZW1lbnRhdGlvbiBiYXNlZCBvbiBCcnVjZSBTY2huZWllcidzIHJlZmVyZW5jZSBpbXBsZW1lbnRhdGlvbi5cbiAqXG4gKlxuICogVGhlIGNvbnN0cnVjdG9yIGRvZXNuJ3QgZG8gbXVjaCBvZiBhbnl0aGluZy4gIEl0J3MganVzdCBoZXJlXG4gKiBzbyB3ZSBjYW4gc3RhcnQgZGVmaW5pbmcgcHJvcGVydGllcyBhbmQgbWV0aG9kcyBhbmQgc3VjaC5cbiAqL1xuZnVuY3Rpb24gQmxvd2Zpc2goKSB7XG59O1xuXG4vKlxuICogRGVjbGFyZSB0aGUgYmxvY2sgc2l6ZSBzbyB0aGF0IHByb3RvY29scyBrbm93IHdoYXQgc2l6ZVxuICogSW5pdGlhbGl6YXRpb24gVmVjdG9yIChJVikgdGhleSB3aWxsIG5lZWQuXG4gKi9cbkJsb3dmaXNoLnByb3RvdHlwZS5CTE9DS1NJWkUgPSA4O1xuXG4vKlxuICogVGhlc2UgYXJlIHRoZSBkZWZhdWx0IFNCT1hFUy5cbiAqL1xuQmxvd2Zpc2gucHJvdG90eXBlLlNCT1hFUyA9IFtcbiAgICBbXG5cdDB4ZDEzMTBiYTYsIDB4OThkZmI1YWMsIDB4MmZmZDcyZGIsIDB4ZDAxYWRmYjcsIDB4YjhlMWFmZWQsIDB4NmEyNjdlOTYsXG5cdDB4YmE3YzkwNDUsIDB4ZjEyYzdmOTksIDB4MjRhMTk5NDcsIDB4YjM5MTZjZjcsIDB4MDgwMWYyZTIsIDB4ODU4ZWZjMTYsXG5cdDB4NjM2OTIwZDgsIDB4NzE1NzRlNjksIDB4YTQ1OGZlYTMsIDB4ZjQ5MzNkN2UsIDB4MGQ5NTc0OGYsIDB4NzI4ZWI2NTgsXG5cdDB4NzE4YmNkNTgsIDB4ODIxNTRhZWUsIDB4N2I1NGE0MWQsIDB4YzI1YTU5YjUsIDB4OWMzMGQ1MzksIDB4MmFmMjYwMTMsXG5cdDB4YzVkMWIwMjMsIDB4Mjg2MDg1ZjAsIDB4Y2E0MTc5MTgsIDB4YjhkYjM4ZWYsIDB4OGU3OWRjYjAsIDB4NjAzYTE4MGUsXG5cdDB4NmM5ZTBlOGIsIDB4YjAxZThhM2UsIDB4ZDcxNTc3YzEsIDB4YmQzMTRiMjcsIDB4NzhhZjJmZGEsIDB4NTU2MDVjNjAsXG5cdDB4ZTY1NTI1ZjMsIDB4YWE1NWFiOTQsIDB4NTc0ODk4NjIsIDB4NjNlODE0NDAsIDB4NTVjYTM5NmEsIDB4MmFhYjEwYjYsXG5cdDB4YjRjYzVjMzQsIDB4MTE0MWU4Y2UsIDB4YTE1NDg2YWYsIDB4N2M3MmU5OTMsIDB4YjNlZTE0MTEsIDB4NjM2ZmJjMmEsXG5cdDB4MmJhOWM1NWQsIDB4NzQxODMxZjYsIDB4Y2U1YzNlMTYsIDB4OWI4NzkzMWUsIDB4YWZkNmJhMzMsIDB4NmMyNGNmNWMsXG5cdDB4N2EzMjUzODEsIDB4Mjg5NTg2NzcsIDB4M2I4ZjQ4OTgsIDB4NmI0YmI5YWYsIDB4YzRiZmU4MWIsIDB4NjYyODIxOTMsXG5cdDB4NjFkODA5Y2MsIDB4ZmIyMWE5OTEsIDB4NDg3Y2FjNjAsIDB4NWRlYzgwMzIsIDB4ZWY4NDVkNWQsIDB4ZTk4NTc1YjEsXG5cdDB4ZGMyNjIzMDIsIDB4ZWI2NTFiODgsIDB4MjM4OTNlODEsIDB4ZDM5NmFjYzUsIDB4MGY2ZDZmZjMsIDB4ODNmNDQyMzksXG5cdDB4MmUwYjQ0ODIsIDB4YTQ4NDIwMDQsIDB4NjljOGYwNGEsIDB4OWUxZjliNWUsIDB4MjFjNjY4NDIsIDB4ZjZlOTZjOWEsXG5cdDB4NjcwYzljNjEsIDB4YWJkMzg4ZjAsIDB4NmE1MWEwZDIsIDB4ZDg1NDJmNjgsIDB4OTYwZmE3MjgsIDB4YWI1MTMzYTMsXG5cdDB4NmVlZjBiNmMsIDB4MTM3YTNiZTQsIDB4YmEzYmYwNTAsIDB4N2VmYjJhOTgsIDB4YTFmMTY1MWQsIDB4MzlhZjAxNzYsXG5cdDB4NjZjYTU5M2UsIDB4ODI0MzBlODgsIDB4OGNlZTg2MTksIDB4NDU2ZjlmYjQsIDB4N2Q4NGE1YzMsIDB4M2I4YjVlYmUsXG5cdDB4ZTA2Zjc1ZDgsIDB4ODVjMTIwNzMsIDB4NDAxYTQ0OWYsIDB4NTZjMTZhYTYsIDB4NGVkM2FhNjIsIDB4MzYzZjc3MDYsXG5cdDB4MWJmZWRmNzIsIDB4NDI5YjAyM2QsIDB4MzdkMGQ3MjQsIDB4ZDAwYTEyNDgsIDB4ZGIwZmVhZDMsIDB4NDlmMWMwOWIsXG5cdDB4MDc1MzcyYzksIDB4ODA5OTFiN2IsIDB4MjVkNDc5ZDgsIDB4ZjZlOGRlZjcsIDB4ZTNmZTUwMWEsIDB4YjY3OTRjM2IsXG5cdDB4OTc2Y2UwYmQsIDB4MDRjMDA2YmEsIDB4YzFhOTRmYjYsIDB4NDA5ZjYwYzQsIDB4NWU1YzllYzIsIDB4MTk2YTI0NjMsXG5cdDB4NjhmYjZmYWYsIDB4M2U2YzUzYjUsIDB4MTMzOWIyZWIsIDB4M2I1MmVjNmYsIDB4NmRmYzUxMWYsIDB4OWIzMDk1MmMsXG5cdDB4Y2M4MTQ1NDQsIDB4YWY1ZWJkMDksIDB4YmVlM2QwMDQsIDB4ZGUzMzRhZmQsIDB4NjYwZjI4MDcsIDB4MTkyZTRiYjMsXG5cdDB4YzBjYmE4NTcsIDB4NDVjODc0MGYsIDB4ZDIwYjVmMzksIDB4YjlkM2ZiZGIsIDB4NTU3OWMwYmQsIDB4MWE2MDMyMGEsXG5cdDB4ZDZhMTAwYzYsIDB4NDAyYzcyNzksIDB4Njc5ZjI1ZmUsIDB4ZmIxZmEzY2MsIDB4OGVhNWU5ZjgsIDB4ZGIzMjIyZjgsXG5cdDB4M2M3NTE2ZGYsIDB4ZmQ2MTZiMTUsIDB4MmY1MDFlYzgsIDB4YWQwNTUyYWIsIDB4MzIzZGI1ZmEsIDB4ZmQyMzg3NjAsXG5cdDB4NTMzMTdiNDgsIDB4M2UwMGRmODIsIDB4OWU1YzU3YmIsIDB4Y2E2ZjhjYTAsIDB4MWE4NzU2MmUsIDB4ZGYxNzY5ZGIsXG5cdDB4ZDU0MmE4ZjYsIDB4Mjg3ZWZmYzMsIDB4YWM2NzMyYzYsIDB4OGM0ZjU1NzMsIDB4Njk1YjI3YjAsIDB4YmJjYTU4YzgsXG5cdDB4ZTFmZmEzNWQsIDB4YjhmMDExYTAsIDB4MTBmYTNkOTgsIDB4ZmQyMTgzYjgsIDB4NGFmY2I1NmMsIDB4MmRkMWQzNWIsXG5cdDB4OWE1M2U0NzksIDB4YjZmODQ1NjUsIDB4ZDI4ZTQ5YmMsIDB4NGJmYjk3OTAsIDB4ZTFkZGYyZGEsIDB4YTRjYjdlMzMsXG5cdDB4NjJmYjEzNDEsIDB4Y2VlNGM2ZTgsIDB4ZWYyMGNhZGEsIDB4MzY3NzRjMDEsIDB4ZDA3ZTllZmUsIDB4MmJmMTFmYjQsXG5cdDB4OTVkYmRhNGQsIDB4YWU5MDkxOTgsIDB4ZWFhZDhlNzEsIDB4NmI5M2Q1YTAsIDB4ZDA4ZWQxZDAsIDB4YWZjNzI1ZTAsXG5cdDB4OGUzYzViMmYsIDB4OGU3NTk0YjcsIDB4OGZmNmUyZmIsIDB4ZjIxMjJiNjQsIDB4ODg4OGI4MTIsIDB4OTAwZGYwMWMsXG5cdDB4NGZhZDVlYTAsIDB4Njg4ZmMzMWMsIDB4ZDFjZmYxOTEsIDB4YjNhOGMxYWQsIDB4MmYyZjIyMTgsIDB4YmUwZTE3NzcsXG5cdDB4ZWE3NTJkZmUsIDB4OGIwMjFmYTEsIDB4ZTVhMGNjMGYsIDB4YjU2Zjc0ZTgsIDB4MThhY2YzZDYsIDB4Y2U4OWUyOTksXG5cdDB4YjRhODRmZTAsIDB4ZmQxM2UwYjcsIDB4N2NjNDNiODEsIDB4ZDJhZGE4ZDksIDB4MTY1ZmEyNjYsIDB4ODA5NTc3MDUsXG5cdDB4OTNjYzczMTQsIDB4MjExYTE0NzcsIDB4ZTZhZDIwNjUsIDB4NzdiNWZhODYsIDB4Yzc1NDQyZjUsIDB4ZmI5ZDM1Y2YsXG5cdDB4ZWJjZGFmMGMsIDB4N2IzZTg5YTAsIDB4ZDY0MTFiZDMsIDB4YWUxZTdlNDksIDB4MDAyNTBlMmQsIDB4MjA3MWIzNWUsXG5cdDB4MjI2ODAwYmIsIDB4NTdiOGUwYWYsIDB4MjQ2NDM2OWIsIDB4ZjAwOWI5MWUsIDB4NTU2MzkxMWQsIDB4NTlkZmE2YWEsXG5cdDB4NzhjMTQzODksIDB4ZDk1YTUzN2YsIDB4MjA3ZDViYTIsIDB4MDJlNWI5YzUsIDB4ODMyNjAzNzYsIDB4NjI5NWNmYTksXG5cdDB4MTFjODE5NjgsIDB4NGU3MzRhNDEsIDB4YjM0NzJkY2EsIDB4N2IxNGE5NGEsIDB4MWI1MTAwNTIsIDB4OWE1MzI5MTUsXG5cdDB4ZDYwZjU3M2YsIDB4YmM5YmM2ZTQsIDB4MmI2MGE0NzYsIDB4ODFlNjc0MDAsIDB4MDhiYTZmYjUsIDB4NTcxYmU5MWYsXG5cdDB4ZjI5NmVjNmIsIDB4MmEwZGQ5MTUsIDB4YjY2MzY1MjEsIDB4ZTdiOWY5YjYsIDB4ZmYzNDA1MmUsIDB4YzU4NTU2NjQsXG5cdDB4NTNiMDJkNWQsIDB4YTk5ZjhmYTEsIDB4MDhiYTQ3OTksIDB4NmU4NTA3NmFcbiAgICBdLCBbXG5cdDB4NGI3YTcwZTksIDB4YjViMzI5NDQsIDB4ZGI3NTA5MmUsIDB4YzQxOTI2MjMsIDB4YWQ2ZWE2YjAsIDB4NDlhN2RmN2QsXG5cdDB4OWNlZTYwYjgsIDB4OGZlZGIyNjYsIDB4ZWNhYThjNzEsIDB4Njk5YTE3ZmYsIDB4NTY2NDUyNmMsIDB4YzJiMTllZTEsXG5cdDB4MTkzNjAyYTUsIDB4NzUwOTRjMjksIDB4YTA1OTEzNDAsIDB4ZTQxODNhM2UsIDB4M2Y1NDk4OWEsIDB4NWI0MjlkNjUsXG5cdDB4NmI4ZmU0ZDYsIDB4OTlmNzNmZDYsIDB4YTFkMjljMDcsIDB4ZWZlODMwZjUsIDB4NGQyZDM4ZTYsIDB4ZjAyNTVkYzEsXG5cdDB4NGNkZDIwODYsIDB4ODQ3MGViMjYsIDB4NjM4MmU5YzYsIDB4MDIxZWNjNWUsIDB4MDk2ODZiM2YsIDB4M2ViYWVmYzksXG5cdDB4M2M5NzE4MTQsIDB4NmI2YTcwYTEsIDB4Njg3ZjM1ODQsIDB4NTJhMGUyODYsIDB4Yjc5YzUzMDUsIDB4YWE1MDA3MzcsXG5cdDB4M2UwNzg0MWMsIDB4N2ZkZWFlNWMsIDB4OGU3ZDQ0ZWMsIDB4NTcxNmYyYjgsIDB4YjAzYWRhMzcsIDB4ZjA1MDBjMGQsXG5cdDB4ZjAxYzFmMDQsIDB4MDIwMGIzZmYsIDB4YWUwY2Y1MWEsIDB4M2NiNTc0YjIsIDB4MjU4MzdhNTgsIDB4ZGMwOTIxYmQsXG5cdDB4ZDE5MTEzZjksIDB4N2NhOTJmZjYsIDB4OTQzMjQ3NzMsIDB4MjJmNTQ3MDEsIDB4M2FlNWU1ODEsIDB4MzdjMmRhZGMsXG5cdDB4YzhiNTc2MzQsIDB4OWFmM2RkYTcsIDB4YTk0NDYxNDYsIDB4MGZkMDAzMGUsIDB4ZWNjOGM3M2UsIDB4YTQ3NTFlNDEsXG5cdDB4ZTIzOGNkOTksIDB4M2JlYTBlMmYsIDB4MzI4MGJiYTEsIDB4MTgzZWIzMzEsIDB4NGU1NDhiMzgsIDB4NGY2ZGI5MDgsXG5cdDB4NmY0MjBkMDMsIDB4ZjYwYTA0YmYsIDB4MmNiODEyOTAsIDB4MjQ5NzdjNzksIDB4NTY3OWIwNzIsIDB4YmNhZjg5YWYsXG5cdDB4ZGU5YTc3MWYsIDB4ZDk5MzA4MTAsIDB4YjM4YmFlMTIsIDB4ZGNjZjNmMmUsIDB4NTUxMjcyMWYsIDB4MmU2YjcxMjQsXG5cdDB4NTAxYWRkZTYsIDB4OWY4NGNkODcsIDB4N2E1ODQ3MTgsIDB4NzQwOGRhMTcsIDB4YmM5ZjlhYmMsIDB4ZTk0YjdkOGMsXG5cdDB4ZWM3YWVjM2EsIDB4ZGI4NTFkZmEsIDB4NjMwOTQzNjYsIDB4YzQ2NGMzZDIsIDB4ZWYxYzE4NDcsIDB4MzIxNWQ5MDgsXG5cdDB4ZGQ0MzNiMzcsIDB4MjRjMmJhMTYsIDB4MTJhMTRkNDMsIDB4MmE2NWM0NTEsIDB4NTA5NDAwMDIsIDB4MTMzYWU0ZGQsXG5cdDB4NzFkZmY4OWUsIDB4MTAzMTRlNTUsIDB4ODFhYzc3ZDYsIDB4NWYxMTE5OWIsIDB4MDQzNTU2ZjEsIDB4ZDdhM2M3NmIsXG5cdDB4M2MxMTE4M2IsIDB4NTkyNGE1MDksIDB4ZjI4ZmU2ZWQsIDB4OTdmMWZiZmEsIDB4OWViYWJmMmMsIDB4MWUxNTNjNmUsXG5cdDB4ODZlMzQ1NzAsIDB4ZWFlOTZmYjEsIDB4ODYwZTVlMGEsIDB4NWEzZTJhYjMsIDB4NzcxZmU3MWMsIDB4NGUzZDA2ZmEsXG5cdDB4Mjk2NWRjYjksIDB4OTllNzFkMGYsIDB4ODAzZTg5ZDYsIDB4NTI2NmM4MjUsIDB4MmU0Y2M5NzgsIDB4OWMxMGIzNmEsXG5cdDB4YzYxNTBlYmEsIDB4OTRlMmVhNzgsIDB4YTVmYzNjNTMsIDB4MWUwYTJkZjQsIDB4ZjJmNzRlYTcsIDB4MzYxZDJiM2QsXG5cdDB4MTkzOTI2MGYsIDB4MTljMjc5NjAsIDB4NTIyM2E3MDgsIDB4ZjcxMzEyYjYsIDB4ZWJhZGZlNmUsIDB4ZWFjMzFmNjYsXG5cdDB4ZTNiYzQ1OTUsIDB4YTY3YmM4ODMsIDB4YjE3ZjM3ZDEsIDB4MDE4Y2ZmMjgsIDB4YzMzMmRkZWYsIDB4YmU2YzVhYTUsXG5cdDB4NjU1ODIxODUsIDB4NjhhYjk4MDIsIDB4ZWVjZWE1MGYsIDB4ZGIyZjk1M2IsIDB4MmFlZjdkYWQsIDB4NWI2ZTJmODQsXG5cdDB4MTUyMWI2MjgsIDB4MjkwNzYxNzAsIDB4ZWNkZDQ3NzUsIDB4NjE5ZjE1MTAsIDB4MTNjY2E4MzAsIDB4ZWI2MWJkOTYsXG5cdDB4MDMzNGZlMWUsIDB4YWEwMzYzY2YsIDB4YjU3MzVjOTAsIDB4NGM3MGEyMzksIDB4ZDU5ZTllMGIsIDB4Y2JhYWRlMTQsXG5cdDB4ZWVjYzg2YmMsIDB4NjA2MjJjYTcsIDB4OWNhYjVjYWIsIDB4YjJmMzg0NmUsIDB4NjQ4YjFlYWYsIDB4MTliZGYwY2EsXG5cdDB4YTAyMzY5YjksIDB4NjU1YWJiNTAsIDB4NDA2ODVhMzIsIDB4M2MyYWI0YjMsIDB4MzE5ZWU5ZDUsIDB4YzAyMWI4ZjcsXG5cdDB4OWI1NDBiMTksIDB4ODc1ZmEwOTksIDB4OTVmNzk5N2UsIDB4NjIzZDdkYTgsIDB4ZjgzNzg4OWEsIDB4OTdlMzJkNzcsXG5cdDB4MTFlZDkzNWYsIDB4MTY2ODEyODEsIDB4MGUzNTg4MjksIDB4YzdlNjFmZDYsIDB4OTZkZWRmYTEsIDB4Nzg1OGJhOTksXG5cdDB4NTdmNTg0YTUsIDB4MWIyMjcyNjMsIDB4OWI4M2MzZmYsIDB4MWFjMjQ2OTYsIDB4Y2RiMzBhZWIsIDB4NTMyZTMwNTQsXG5cdDB4OGZkOTQ4ZTQsIDB4NmRiYzMxMjgsIDB4NThlYmYyZWYsIDB4MzRjNmZmZWEsIDB4ZmUyOGVkNjEsIDB4ZWU3YzNjNzMsXG5cdDB4NWQ0YTE0ZDksIDB4ZTg2NGI3ZTMsIDB4NDIxMDVkMTQsIDB4MjAzZTEzZTAsIDB4NDVlZWUyYjYsIDB4YTNhYWFiZWEsXG5cdDB4ZGI2YzRmMTUsIDB4ZmFjYjRmZDAsIDB4Yzc0MmY0NDIsIDB4ZWY2YWJiYjUsIDB4NjU0ZjNiMWQsIDB4NDFjZDIxMDUsXG5cdDB4ZDgxZTc5OWUsIDB4ODY4NTRkYzcsIDB4ZTQ0YjQ3NmEsIDB4M2Q4MTYyNTAsIDB4Y2Y2MmExZjIsIDB4NWI4ZDI2NDYsXG5cdDB4ZmM4ODgzYTAsIDB4YzFjN2I2YTMsIDB4N2YxNTI0YzMsIDB4NjljYjc0OTIsIDB4NDc4NDhhMGIsIDB4NTY5MmIyODUsXG5cdDB4MDk1YmJmMDAsIDB4YWQxOTQ4OWQsIDB4MTQ2MmIxNzQsIDB4MjM4MjBlMDAsIDB4NTg0MjhkMmEsIDB4MGM1NWY1ZWEsXG5cdDB4MWRhZGY0M2UsIDB4MjMzZjcwNjEsIDB4MzM3MmYwOTIsIDB4OGQ5MzdlNDEsIDB4ZDY1ZmVjZjEsIDB4NmMyMjNiZGIsXG5cdDB4N2NkZTM3NTksIDB4Y2JlZTc0NjAsIDB4NDA4NWYyYTcsIDB4Y2U3NzMyNmUsIDB4YTYwNzgwODQsIDB4MTlmODUwOWUsXG5cdDB4ZThlZmQ4NTUsIDB4NjFkOTk3MzUsIDB4YTk2OWE3YWEsIDB4YzUwYzA2YzIsIDB4NWEwNGFiZmMsIDB4ODAwYmNhZGMsXG5cdDB4OWU0NDdhMmUsIDB4YzM0NTM0ODQsIDB4ZmRkNTY3MDUsIDB4MGUxZTllYzksIDB4ZGI3M2RiZDMsIDB4MTA1NTg4Y2QsXG5cdDB4Njc1ZmRhNzksIDB4ZTM2NzQzNDAsIDB4YzVjNDM0NjUsIDB4NzEzZTM4ZDgsIDB4M2QyOGY4OWUsIDB4ZjE2ZGZmMjAsXG5cdDB4MTUzZTIxZTcsIDB4OGZiMDNkNGEsIDB4ZTZlMzlmMmIsIDB4ZGI4M2FkZjdcbiAgICBdLCBbXG5cdDB4ZTkzZDVhNjgsIDB4OTQ4MTQwZjcsIDB4ZjY0YzI2MWMsIDB4OTQ2OTI5MzQsIDB4NDExNTIwZjcsIDB4NzYwMmQ0ZjcsXG5cdDB4YmNmNDZiMmUsIDB4ZDRhMjAwNjgsIDB4ZDQwODI0NzEsIDB4MzMyMGY0NmEsIDB4NDNiN2Q0YjcsIDB4NTAwMDYxYWYsXG5cdDB4MWUzOWY2MmUsIDB4OTcyNDQ1NDYsIDB4MTQyMTRmNzQsIDB4YmY4Yjg4NDAsIDB4NGQ5NWZjMWQsIDB4OTZiNTkxYWYsXG5cdDB4NzBmNGRkZDMsIDB4NjZhMDJmNDUsIDB4YmZiYzA5ZWMsIDB4MDNiZDk3ODUsIDB4N2ZhYzZkZDAsIDB4MzFjYjg1MDQsXG5cdDB4OTZlYjI3YjMsIDB4NTVmZDM5NDEsIDB4ZGEyNTQ3ZTYsIDB4YWJjYTBhOWEsIDB4Mjg1MDc4MjUsIDB4NTMwNDI5ZjQsXG5cdDB4MGEyYzg2ZGEsIDB4ZTliNjZkZmIsIDB4NjhkYzE0NjIsIDB4ZDc0ODY5MDAsIDB4NjgwZWMwYTQsIDB4MjdhMThkZWUsXG5cdDB4NGYzZmZlYTIsIDB4ZTg4N2FkOGMsIDB4YjU4Y2UwMDYsIDB4N2FmNGQ2YjYsIDB4YWFjZTFlN2MsIDB4ZDMzNzVmZWMsXG5cdDB4Y2U3OGEzOTksIDB4NDA2YjJhNDIsIDB4MjBmZTllMzUsIDB4ZDlmMzg1YjksIDB4ZWUzOWQ3YWIsIDB4M2IxMjRlOGIsXG5cdDB4MWRjOWZhZjcsIDB4NGI2ZDE4NTYsIDB4MjZhMzY2MzEsIDB4ZWFlMzk3YjIsIDB4M2E2ZWZhNzQsIDB4ZGQ1YjQzMzIsXG5cdDB4Njg0MWU3ZjcsIDB4Y2E3ODIwZmIsIDB4ZmIwYWY1NGUsIDB4ZDhmZWIzOTcsIDB4NDU0MDU2YWMsIDB4YmE0ODk1MjcsXG5cdDB4NTU1MzNhM2EsIDB4MjA4MzhkODcsIDB4ZmU2YmE5YjcsIDB4ZDA5Njk1NGIsIDB4NTVhODY3YmMsIDB4YTExNTlhNTgsXG5cdDB4Y2NhOTI5NjMsIDB4OTllMWRiMzMsIDB4YTYyYTRhNTYsIDB4M2YzMTI1ZjksIDB4NWVmNDdlMWMsIDB4OTAyOTMxN2MsXG5cdDB4ZmRmOGU4MDIsIDB4MDQyNzJmNzAsIDB4ODBiYjE1NWMsIDB4MDUyODJjZTMsIDB4OTVjMTE1NDgsIDB4ZTRjNjZkMjIsXG5cdDB4NDhjMTEzM2YsIDB4YzcwZjg2ZGMsIDB4MDdmOWM5ZWUsIDB4NDEwNDFmMGYsIDB4NDA0Nzc5YTQsIDB4NWQ4ODZlMTcsXG5cdDB4MzI1ZjUxZWIsIDB4ZDU5YmMwZDEsIDB4ZjJiY2MxOGYsIDB4NDExMTM1NjQsIDB4MjU3Yjc4MzQsIDB4NjAyYTljNjAsXG5cdDB4ZGZmOGU4YTMsIDB4MWY2MzZjMWIsIDB4MGUxMmI0YzIsIDB4MDJlMTMyOWUsIDB4YWY2NjRmZDEsIDB4Y2FkMTgxMTUsXG5cdDB4NmIyMzk1ZTAsIDB4MzMzZTkyZTEsIDB4M2IyNDBiNjIsIDB4ZWViZWI5MjIsIDB4ODViMmEyMGUsIDB4ZTZiYTBkOTksXG5cdDB4ZGU3MjBjOGMsIDB4MmRhMmY3MjgsIDB4ZDAxMjc4NDUsIDB4OTViNzk0ZmQsIDB4NjQ3ZDA4NjIsIDB4ZTdjY2Y1ZjAsXG5cdDB4NTQ0OWEzNmYsIDB4ODc3ZDQ4ZmEsIDB4YzM5ZGZkMjcsIDB4ZjMzZThkMWUsIDB4MGE0NzYzNDEsIDB4OTkyZWZmNzQsXG5cdDB4M2E2ZjZlYWIsIDB4ZjRmOGZkMzcsIDB4YTgxMmRjNjAsIDB4YTFlYmRkZjgsIDB4OTkxYmUxNGMsIDB4ZGI2ZTZiMGQsXG5cdDB4YzY3YjU1MTAsIDB4NmQ2NzJjMzcsIDB4Mjc2NWQ0M2IsIDB4ZGNkMGU4MDQsIDB4ZjEyOTBkYzcsIDB4Y2MwMGZmYTMsXG5cdDB4YjUzOTBmOTIsIDB4NjkwZmVkMGIsIDB4NjY3YjlmZmIsIDB4Y2VkYjdkOWMsIDB4YTA5MWNmMGIsIDB4ZDkxNTVlYTMsXG5cdDB4YmIxMzJmODgsIDB4NTE1YmFkMjQsIDB4N2I5NDc5YmYsIDB4NzYzYmQ2ZWIsIDB4MzczOTJlYjMsIDB4Y2MxMTU5NzksXG5cdDB4ODAyNmUyOTcsIDB4ZjQyZTMxMmQsIDB4Njg0MmFkYTcsIDB4YzY2YTJiM2IsIDB4MTI3NTRjY2MsIDB4NzgyZWYxMWMsXG5cdDB4NmExMjQyMzcsIDB4Yjc5MjUxZTcsIDB4MDZhMWJiZTYsIDB4NGJmYjYzNTAsIDB4MWE2YjEwMTgsIDB4MTFjYWVkZmEsXG5cdDB4M2QyNWJkZDgsIDB4ZTJlMWMzYzksIDB4NDQ0MjE2NTksIDB4MGExMjEzODYsIDB4ZDkwY2VjNmUsIDB4ZDVhYmVhMmEsXG5cdDB4NjRhZjY3NGUsIDB4ZGE4NmE4NWYsIDB4YmViZmU5ODgsIDB4NjRlNGMzZmUsIDB4OWRiYzgwNTcsIDB4ZjBmN2MwODYsXG5cdDB4NjA3ODdiZjgsIDB4NjAwMzYwNGQsIDB4ZDFmZDgzNDYsIDB4ZjYzODFmYjAsIDB4Nzc0NWFlMDQsIDB4ZDczNmZjY2MsXG5cdDB4ODM0MjZiMzMsIDB4ZjAxZWFiNzEsIDB4YjA4MDQxODcsIDB4M2MwMDVlNWYsIDB4NzdhMDU3YmUsIDB4YmRlOGFlMjQsXG5cdDB4NTU0NjQyOTksIDB4YmY1ODJlNjEsIDB4NGU1OGY0OGYsIDB4ZjJkZGZkYTIsIDB4ZjQ3NGVmMzgsIDB4ODc4OWJkYzIsXG5cdDB4NTM2NmY5YzMsIDB4YzhiMzhlNzQsIDB4YjQ3NWYyNTUsIDB4NDZmY2Q5YjksIDB4N2FlYjI2NjEsIDB4OGIxZGRmODQsXG5cdDB4ODQ2YTBlNzksIDB4OTE1Zjk1ZTIsIDB4NDY2ZTU5OGUsIDB4MjBiNDU3NzAsIDB4OGNkNTU1OTEsIDB4YzkwMmRlNGMsXG5cdDB4YjkwYmFjZTEsIDB4YmI4MjA1ZDAsIDB4MTFhODYyNDgsIDB4NzU3NGE5OWUsIDB4Yjc3ZjE5YjYsIDB4ZTBhOWRjMDksXG5cdDB4NjYyZDA5YTEsIDB4YzQzMjQ2MzMsIDB4ZTg1YTFmMDIsIDB4MDlmMGJlOGMsIDB4NGE5OWEwMjUsIDB4MWQ2ZWZlMTAsXG5cdDB4MWFiOTNkMWQsIDB4MGJhNWE0ZGYsIDB4YTE4NmYyMGYsIDB4Mjg2OGYxNjksIDB4ZGNiN2RhODMsIDB4NTczOTA2ZmUsXG5cdDB4YTFlMmNlOWIsIDB4NGZjZDdmNTIsIDB4NTAxMTVlMDEsIDB4YTcwNjgzZmEsIDB4YTAwMmI1YzQsIDB4MGRlNmQwMjcsXG5cdDB4OWFmODhjMjcsIDB4NzczZjg2NDEsIDB4YzM2MDRjMDYsIDB4NjFhODA2YjUsIDB4ZjAxNzdhMjgsIDB4YzBmNTg2ZTAsXG5cdDB4MDA2MDU4YWEsIDB4MzBkYzdkNjIsIDB4MTFlNjllZDcsIDB4MjMzOGVhNjMsIDB4NTNjMmRkOTQsIDB4YzJjMjE2MzQsXG5cdDB4YmJjYmVlNTYsIDB4OTBiY2I2ZGUsIDB4ZWJmYzdkYTEsIDB4Y2U1OTFkNzYsIDB4NmYwNWU0MDksIDB4NGI3YzAxODgsXG5cdDB4Mzk3MjBhM2QsIDB4N2M5MjdjMjQsIDB4ODZlMzcyNWYsIDB4NzI0ZDlkYjksIDB4MWFjMTViYjQsIDB4ZDM5ZWI4ZmMsXG5cdDB4ZWQ1NDU1NzgsIDB4MDhmY2E1YjUsIDB4ZDgzZDdjZDMsIDB4NGRhZDBmYzQsIDB4MWU1MGVmNWUsIDB4YjE2MWU2ZjgsXG5cdDB4YTI4NTE0ZDksIDB4NmM1MTEzM2MsIDB4NmZkNWM3ZTcsIDB4NTZlMTRlYzQsIDB4MzYyYWJmY2UsIDB4ZGRjNmM4MzcsXG5cdDB4ZDc5YTMyMzQsIDB4OTI2MzgyMTIsIDB4NjcwZWZhOGUsIDB4NDA2MDAwZTBcbiAgICBdLCBbXG5cdDB4M2EzOWNlMzcsIDB4ZDNmYWY1Y2YsIDB4YWJjMjc3MzcsIDB4NWFjNTJkMWIsIDB4NWNiMDY3OWUsIDB4NGZhMzM3NDIsXG5cdDB4ZDM4MjI3NDAsIDB4OTliYzliYmUsIDB4ZDUxMThlOWQsIDB4YmYwZjczMTUsIDB4ZDYyZDFjN2UsIDB4YzcwMGM0N2IsXG5cdDB4Yjc4YzFiNmIsIDB4MjFhMTkwNDUsIDB4YjI2ZWIxYmUsIDB4NmEzNjZlYjQsIDB4NTc0OGFiMmYsIDB4YmM5NDZlNzksXG5cdDB4YzZhMzc2ZDIsIDB4NjU0OWMyYzgsIDB4NTMwZmY4ZWUsIDB4NDY4ZGRlN2QsIDB4ZDU3MzBhMWQsIDB4NGNkMDRkYzYsXG5cdDB4MjkzOWJiZGIsIDB4YTliYTQ2NTAsIDB4YWM5NTI2ZTgsIDB4YmU1ZWUzMDQsIDB4YTFmYWQ1ZjAsIDB4NmEyZDUxOWEsXG5cdDB4NjNlZjhjZTIsIDB4OWE4NmVlMjIsIDB4YzA4OWMyYjgsIDB4NDMyNDJlZjYsIDB4YTUxZTAzYWEsIDB4OWNmMmQwYTQsXG5cdDB4ODNjMDYxYmEsIDB4OWJlOTZhNGQsIDB4OGZlNTE1NTAsIDB4YmE2NDViZDYsIDB4MjgyNmEyZjksIDB4YTczYTNhZTEsXG5cdDB4NGJhOTk1ODYsIDB4ZWY1NTYyZTksIDB4YzcyZmVmZDMsIDB4Zjc1MmY3ZGEsIDB4M2YwNDZmNjksIDB4NzdmYTBhNTksXG5cdDB4ODBlNGE5MTUsIDB4ODdiMDg2MDEsIDB4OWIwOWU2YWQsIDB4M2IzZWU1OTMsIDB4ZTk5MGZkNWEsIDB4OWUzNGQ3OTcsXG5cdDB4MmNmMGI3ZDksIDB4MDIyYjhiNTEsIDB4OTZkNWFjM2EsIDB4MDE3ZGE2N2QsIDB4ZDFjZjNlZDYsIDB4N2M3ZDJkMjgsXG5cdDB4MWY5ZjI1Y2YsIDB4YWRmMmI4OWIsIDB4NWFkNmI0NzIsIDB4NWE4OGY1NGMsIDB4ZTAyOWFjNzEsIDB4ZTAxOWE1ZTYsXG5cdDB4NDdiMGFjZmQsIDB4ZWQ5M2ZhOWIsIDB4ZThkM2M0OGQsIDB4MjgzYjU3Y2MsIDB4ZjhkNTY2MjksIDB4NzkxMzJlMjgsXG5cdDB4Nzg1ZjAxOTEsIDB4ZWQ3NTYwNTUsIDB4Zjc5NjBlNDQsIDB4ZTNkMzVlOGMsIDB4MTUwNTZkZDQsIDB4ODhmNDZkYmEsXG5cdDB4MDNhMTYxMjUsIDB4MDU2NGYwYmQsIDB4YzNlYjllMTUsIDB4M2M5MDU3YTIsIDB4OTcyNzFhZWMsIDB4YTkzYTA3MmEsXG5cdDB4MWIzZjZkOWIsIDB4MWU2MzIxZjUsIDB4ZjU5YzY2ZmIsIDB4MjZkY2YzMTksIDB4NzUzM2Q5MjgsIDB4YjE1NWZkZjUsXG5cdDB4MDM1NjM0ODIsIDB4OGFiYTNjYmIsIDB4Mjg1MTc3MTEsIDB4YzIwYWQ5ZjgsIDB4YWJjYzUxNjcsIDB4Y2NhZDkyNWYsXG5cdDB4NGRlODE3NTEsIDB4MzgzMGRjOGUsIDB4Mzc5ZDU4NjIsIDB4OTMyMGY5OTEsIDB4ZWE3YTkwYzIsIDB4ZmIzZTdiY2UsXG5cdDB4NTEyMWNlNjQsIDB4Nzc0ZmJlMzIsIDB4YThiNmUzN2UsIDB4YzMyOTNkNDYsIDB4NDhkZTUzNjksIDB4NjQxM2U2ODAsXG5cdDB4YTJhZTA4MTAsIDB4ZGQ2ZGIyMjQsIDB4Njk4NTJkZmQsIDB4MDkwNzIxNjYsIDB4YjM5YTQ2MGEsIDB4NjQ0NWMwZGQsXG5cdDB4NTg2Y2RlY2YsIDB4MWMyMGM4YWUsIDB4NWJiZWY3ZGQsIDB4MWI1ODhkNDAsIDB4Y2NkMjAxN2YsIDB4NmJiNGUzYmIsXG5cdDB4ZGRhMjZhN2UsIDB4M2E1OWZmNDUsIDB4M2UzNTBhNDQsIDB4YmNiNGNkZDUsIDB4NzJlYWNlYTgsIDB4ZmE2NDg0YmIsXG5cdDB4OGQ2NjEyYWUsIDB4YmYzYzZmNDcsIDB4ZDI5YmU0NjMsIDB4NTQyZjVkOWUsIDB4YWVjMjc3MWIsIDB4ZjY0ZTYzNzAsXG5cdDB4NzQwZTBkOGQsIDB4ZTc1YjEzNTcsIDB4Zjg3MjE2NzEsIDB4YWY1MzdkNWQsIDB4NDA0MGNiMDgsIDB4NGViNGUyY2MsXG5cdDB4MzRkMjQ2NmEsIDB4MDExNWFmODQsIDB4ZTFiMDA0MjgsIDB4OTU5ODNhMWQsIDB4MDZiODlmYjQsIDB4Y2U2ZWEwNDgsXG5cdDB4NmYzZjNiODIsIDB4MzUyMGFiODIsIDB4MDExYTFkNGIsIDB4Mjc3MjI3ZjgsIDB4NjExNTYwYjEsIDB4ZTc5MzNmZGMsXG5cdDB4YmIzYTc5MmIsIDB4MzQ0NTI1YmQsIDB4YTA4ODM5ZTEsIDB4NTFjZTc5NGIsIDB4MmYzMmM5YjcsIDB4YTAxZmJhYzksXG5cdDB4ZTAxY2M4N2UsIDB4YmNjN2QxZjYsIDB4Y2YwMTExYzMsIDB4YTFlOGFhYzcsIDB4MWE5MDg3NDksIDB4ZDQ0ZmJkOWEsXG5cdDB4ZDBkYWRlY2IsIDB4ZDUwYWRhMzgsIDB4MDMzOWMzMmEsIDB4YzY5MTM2NjcsIDB4OGRmOTMxN2MsIDB4ZTBiMTJiNGYsXG5cdDB4Zjc5ZTU5YjcsIDB4NDNmNWJiM2EsIDB4ZjJkNTE5ZmYsIDB4MjdkOTQ1OWMsIDB4YmY5NzIyMmMsIDB4MTVlNmZjMmEsXG5cdDB4MGY5MWZjNzEsIDB4OWI5NDE1MjUsIDB4ZmFlNTkzNjEsIDB4Y2ViNjljZWIsIDB4YzJhODY0NTksIDB4MTJiYWE4ZDEsXG5cdDB4YjZjMTA3NWUsIDB4ZTMwNTZhMGMsIDB4MTBkMjUwNjUsIDB4Y2IwM2E0NDIsIDB4ZTBlYzZlMGUsIDB4MTY5OGRiM2IsXG5cdDB4NGM5OGEwYmUsIDB4MzI3OGU5NjQsIDB4OWYxZjk1MzIsIDB4ZTBkMzkyZGYsIDB4ZDNhMDM0MmIsIDB4ODk3MWYyMWUsXG5cdDB4MWIwYTc0NDEsIDB4NGJhMzM0OGMsIDB4YzViZTcxMjAsIDB4YzM3NjMyZDgsIDB4ZGYzNTlmOGQsIDB4OWI5OTJmMmUsXG5cdDB4ZTYwYjZmNDcsIDB4MGZlM2YxMWQsIDB4ZTU0Y2RhNTQsIDB4MWVkYWQ4OTEsIDB4Y2U2Mjc5Y2YsIDB4Y2QzZTdlNmYsXG5cdDB4MTYxOGIxNjYsIDB4ZmQyYzFkMDUsIDB4ODQ4ZmQyYzUsIDB4ZjZmYjIyOTksIDB4ZjUyM2YzNTcsIDB4YTYzMjc2MjMsXG5cdDB4OTNhODM1MzEsIDB4NTZjY2NkMDIsIDB4YWNmMDgxNjIsIDB4NWE3NWViYjUsIDB4NmUxNjM2OTcsIDB4ODhkMjczY2MsXG5cdDB4ZGU5NjYyOTIsIDB4ODFiOTQ5ZDAsIDB4NGM1MDkwMWIsIDB4NzFjNjU2MTQsIDB4ZTZjNmM3YmQsIDB4MzI3YTE0MGEsXG5cdDB4NDVlMWQwMDYsIDB4YzNmMjdiOWEsIDB4YzlhYTUzZmQsIDB4NjJhODBmMDAsIDB4YmIyNWJmZTIsIDB4MzViZGQyZjYsXG5cdDB4NzExMjY5MDUsIDB4YjIwNDAyMjIsIDB4YjZjYmNmN2MsIDB4Y2Q3NjljMmIsIDB4NTMxMTNlYzAsIDB4MTY0MGUzZDMsXG5cdDB4MzhhYmJkNjAsIDB4MjU0N2FkZjAsIDB4YmEzODIwOWMsIDB4Zjc0NmNlNzYsIDB4NzdhZmExYzUsIDB4MjA3NTYwNjAsXG5cdDB4ODVjYmZlNGUsIDB4OGFlODhkZDgsIDB4N2FhYWY5YjAsIDB4NGNmOWFhN2UsIDB4MTk0OGMyNWMsIDB4MDJmYjhhOGMsXG5cdDB4MDFjMzZhZTQsIDB4ZDZlYmUxZjksIDB4OTBkNGY4NjksIDB4YTY1Y2RlYTAsIDB4M2YwOTI1MmQsIDB4YzIwOGU2OWYsXG5cdDB4Yjc0ZTYxMzIsIDB4Y2U3N2UyNWIsIDB4NTc4ZmRmZTMsIDB4M2FjMzcyZTZcbiAgICBdXG5dO1xuXG4vLypcbi8vKiBUaGlzIGlzIHRoZSBkZWZhdWx0IFBBUlJBWVxuLy8qXG5CbG93ZmlzaC5wcm90b3R5cGUuUEFSUkFZID0gW1xuICAgIDB4MjQzZjZhODgsIDB4ODVhMzA4ZDMsIDB4MTMxOThhMmUsIDB4MDM3MDczNDQsIDB4YTQwOTM4MjIsIDB4Mjk5ZjMxZDAsXG4gICAgMHgwODJlZmE5OCwgMHhlYzRlNmM4OSwgMHg0NTI4MjFlNiwgMHgzOGQwMTM3NywgMHhiZTU0NjZjZiwgMHgzNGU5MGM2YyxcbiAgICAweGMwYWMyOWI3LCAweGM5N2M1MGRkLCAweDNmODRkNWI1LCAweGI1NDcwOTE3LCAweDkyMTZkNWQ5LCAweDg5NzlmYjFiXG5dO1xuXG4vLypcbi8vKiBUaGlzIGlzIHRoZSBudW1iZXIgb2Ygcm91bmRzIHRoZSBjaXBoZXIgd2lsbCBnb1xuLy8qXG5CbG93ZmlzaC5wcm90b3R5cGUuTk4gPSAxNjtcblxuLy8qXG4vLyogVGhpcyBmdW5jdGlvbiBpcyBuZWVkZWQgdG8gZ2V0IHJpZCBvZiBwcm9ibGVtc1xuLy8qIHdpdGggdGhlIGhpZ2gtYml0IGdldHRpbmcgc2V0LiAgSWYgd2UgZG9uJ3QgZG9cbi8vKiB0aGlzLCB0aGVuIHNvbWV0aW1lcyAoIGFhICYgMHgwMEZGRkZGRkZGICkgaXMgbm90XG4vLyogZXF1YWwgdG8gKCBiYiAmIDB4MDBGRkZGRkZGRiApIGV2ZW4gd2hlbiB0aGV5XG4vLyogYWdyZWUgYml0LWZvci1iaXQgZm9yIHRoZSBmaXJzdCAzMiBiaXRzLlxuLy8qXG5CbG93ZmlzaC5wcm90b3R5cGUuX2NsZWFuID0gZnVuY3Rpb24oIHh4ICkge1xuICAgIGlmICggeHggPCAwICkge1xuXHR2YXIgeXkgPSB4eCAmIDB4N0ZGRkZGRkY7XG5cdHh4ID0geXkgKyAweDgwMDAwMDAwO1xuICAgIH1cbiAgICByZXR1cm4geHg7XG59O1xuXG4vLypcbi8vKiBUaGlzIGlzIHRoZSBtaXhpbmcgZnVuY3Rpb24gdGhhdCB1c2VzIHRoZSBzYm94ZXNcbi8vKlxuQmxvd2Zpc2gucHJvdG90eXBlLl9GID0gZnVuY3Rpb24gKCB4eCApIHtcbiAgICB2YXIgYWE7XG4gICAgdmFyIGJiO1xuICAgIHZhciBjYztcbiAgICB2YXIgZGQ7XG4gICAgdmFyIHl5O1xuXG4gICAgZGQgPSB4eCAmIDB4MDBGRjtcbiAgICB4eCA+Pj49IDg7XG4gICAgY2MgPSB4eCAmIDB4MDBGRjtcbiAgICB4eCA+Pj49IDg7XG4gICAgYmIgPSB4eCAmIDB4MDBGRjtcbiAgICB4eCA+Pj49IDg7XG4gICAgYWEgPSB4eCAmIDB4MDBGRjtcblxuICAgIHl5ID0gdGhpcy5zYm94ZXNbIDAgXVsgYWEgXSArIHRoaXMuc2JveGVzWyAxIF1bIGJiIF07XG4gICAgeXkgPSB5eSBeIHRoaXMuc2JveGVzWyAyIF1bIGNjIF07XG4gICAgeXkgPSB5eSArIHRoaXMuc2JveGVzWyAzIF1bIGRkIF07XG5cbiAgICByZXR1cm4geXk7XG59O1xuXG4vLypcbi8vKiBUaGlzIG1ldGhvZCB0YWtlcyBhbiBhcnJheSB3aXRoIHR3byB2YWx1ZXMsIGxlZnQgYW5kIHJpZ2h0XG4vLyogYW5kIGRvZXMgTk4gcm91bmRzIG9mIEJsb3dmaXNoIG9uIHRoZW0uXG4vLypcbkJsb3dmaXNoLnByb3RvdHlwZS5fZW5jcnlwdF9ibG9jayA9IGZ1bmN0aW9uICggdmFscyApIHtcbiAgICB2YXIgZGF0YUwgPSB2YWxzWyAwIF07XG4gICAgdmFyIGRhdGFSID0gdmFsc1sgMSBdO1xuXG4gICAgdmFyIGlpO1xuXG4gICAgZm9yICggaWk9MDsgaWkgPCB0aGlzLk5OOyArK2lpICkge1xuXHRkYXRhTCA9IGRhdGFMIF4gdGhpcy5wYXJyYXlbIGlpIF07XG5cdGRhdGFSID0gdGhpcy5fRiggZGF0YUwgKSBeIGRhdGFSO1xuXG5cdHZhciB0bXAgPSBkYXRhTDtcblx0ZGF0YUwgPSBkYXRhUjtcblx0ZGF0YVIgPSB0bXA7XG4gICAgfVxuXG4gICAgZGF0YUwgPSBkYXRhTCBeIHRoaXMucGFycmF5WyB0aGlzLk5OICsgMCBdO1xuICAgIGRhdGFSID0gZGF0YVIgXiB0aGlzLnBhcnJheVsgdGhpcy5OTiArIDEgXTtcblxuICAgIHZhbHNbIDAgXSA9IHRoaXMuX2NsZWFuKCBkYXRhUiApO1xuICAgIHZhbHNbIDEgXSA9IHRoaXMuX2NsZWFuKCBkYXRhTCApO1xufTtcblxuLy8qXG4vLyogVGhpcyBtZXRob2QgdGFrZXMgYSB2ZWN0b3Igb2YgbnVtYmVycyBhbmQgdHVybnMgdGhlbVxuLy8qIGludG8gbG9uZyB3b3JkcyBzbyB0aGF0IHRoZXkgY2FuIGJlIHByb2Nlc3NlZCBieSB0aGVcbi8vKiByZWFsIGFsZ29yaXRobS5cbi8vKlxuLy8qIE1heWJlIEkgc2hvdWxkIG1ha2UgdGhlIHJlYWwgYWxnb3JpdGhtIGFib3ZlIHRha2UgYSB2ZWN0b3Jcbi8vKiBpbnN0ZWFkLiAgVGhhdCB3aWxsIGludm9sdmUgbW9yZSBsb29waW5nLCBidXQgaXQgd29uJ3QgcmVxdWlyZVxuLy8qIHRoZSBGKCkgbWV0aG9kIHRvIGRlY29uc3RydWN0IHRoZSB2ZWN0b3IuXG4vLypcbkJsb3dmaXNoLnByb3RvdHlwZS5lbmNyeXB0X2Jsb2NrID0gZnVuY3Rpb24gKCB2ZWN0b3IgKSB7XG4gICAgdmFyIGlpO1xuICAgIHZhciB2YWxzID0gWyAwLCAwIF07XG4gICAgdmFyIG9mZiAgPSB0aGlzLkJMT0NLU0laRS8yO1xuICAgIGZvciAoIGlpID0gMDsgaWkgPCB0aGlzLkJMT0NLU0laRS8yOyArK2lpICkge1xuXHR2YWxzWzBdID0gKCB2YWxzWzBdIDw8IDggKSB8ICggdmVjdG9yWyBpaSArIDAgICBdICYgMHgwMEZGICk7XG5cdHZhbHNbMV0gPSAoIHZhbHNbMV0gPDwgOCApIHwgKCB2ZWN0b3JbIGlpICsgb2ZmIF0gJiAweDAwRkYgKTtcbiAgICB9XG5cbiAgICB0aGlzLl9lbmNyeXB0X2Jsb2NrKCB2YWxzICk7XG5cbiAgICB2YXIgcmV0ID0gWyBdO1xuICAgIGZvciAoIGlpID0gMDsgaWkgPCB0aGlzLkJMT0NLU0laRS8yOyArK2lpICkge1xuXHRyZXRbIGlpICsgMCAgIF0gPSAoIHZhbHNbIDAgXSA+Pj4gKDI0IC0gOCooaWkpKSAmIDB4MDBGRiApO1xuXHRyZXRbIGlpICsgb2ZmIF0gPSAoIHZhbHNbIDEgXSA+Pj4gKDI0IC0gOCooaWkpKSAmIDB4MDBGRiApO1xuXHQvLyB2YWxzWyAwIF0gPSAoIHZhbHNbIDAgXSA+Pj4gOCApO1xuXHQvLyB2YWxzWyAxIF0gPSAoIHZhbHNbIDEgXSA+Pj4gOCApO1xuICAgIH1cblxuICAgIHJldHVybiByZXQ7XG59O1xuXG4vLypcbi8vKiBUaGlzIG1ldGhvZCB0YWtlcyBhbiBhcnJheSB3aXRoIHR3byB2YWx1ZXMsIGxlZnQgYW5kIHJpZ2h0XG4vLyogYW5kIHVuZG9lcyBOTiByb3VuZHMgb2YgQmxvd2Zpc2ggb24gdGhlbS5cbi8vKlxuQmxvd2Zpc2gucHJvdG90eXBlLl9kZWNyeXB0X2Jsb2NrID0gZnVuY3Rpb24gKCB2YWxzICkge1xuICAgIHZhciBkYXRhTCA9IHZhbHNbIDAgXTtcbiAgICB2YXIgZGF0YVIgPSB2YWxzWyAxIF07XG5cbiAgICB2YXIgaWk7XG5cbiAgICBmb3IgKCBpaT10aGlzLk5OKzE7IGlpID4gMTsgLS1paSApIHtcblx0ZGF0YUwgPSBkYXRhTCBeIHRoaXMucGFycmF5WyBpaSBdO1xuXHRkYXRhUiA9IHRoaXMuX0YoIGRhdGFMICkgXiBkYXRhUjtcblxuXHR2YXIgdG1wID0gZGF0YUw7XG5cdGRhdGFMID0gZGF0YVI7XG5cdGRhdGFSID0gdG1wO1xuICAgIH1cblxuICAgIGRhdGFMID0gZGF0YUwgXiB0aGlzLnBhcnJheVsgMSBdO1xuICAgIGRhdGFSID0gZGF0YVIgXiB0aGlzLnBhcnJheVsgMCBdO1xuXG4gICAgdmFsc1sgMCBdID0gdGhpcy5fY2xlYW4oIGRhdGFSICk7XG4gICAgdmFsc1sgMSBdID0gdGhpcy5fY2xlYW4oIGRhdGFMICk7XG59O1xuXG4vLypcbi8vKiBUaGlzIG1ldGhvZCB0YWtlcyBhIGtleSBhcnJheSBhbmQgaW5pdGlhbGl6ZXMgdGhlXG4vLyogc2JveGVzIGFuZCBwYXJyYXkgZm9yIHRoaXMgZW5jcnlwdGlvbi5cbi8vKlxuQmxvd2Zpc2gucHJvdG90eXBlLmluaXQgPSBmdW5jdGlvbiAoIGtleSApIHtcbiAgICB2YXIgaWk7XG4gICAgdmFyIGpqID0gMDtcblxuICAgIHRoaXMucGFycmF5ID0gW107XG4gICAgZm9yICggaWk9MDsgaWkgPCB0aGlzLk5OICsgMjsgKytpaSApIHtcblx0dmFyIGRhdGEgPSAweDAwMDAwMDAwO1xuXHR2YXIga2s7XG5cdGZvciAoIGtrPTA7IGtrIDwgNDsgKytrayApIHtcblx0ICAgIGRhdGEgPSAoIGRhdGEgPDwgOCApIHwgKCBrZXlbIGpqIF0gJiAweDAwRkYgKTtcblx0ICAgIGlmICggKytqaiA+PSBrZXkubGVuZ3RoICkge1xuXHRcdGpqID0gMDtcblx0ICAgIH1cblx0fVxuXHR0aGlzLnBhcnJheVsgaWkgXSA9IHRoaXMuUEFSUkFZWyBpaSBdIF4gZGF0YTtcbiAgICB9XG5cbiAgICB0aGlzLnNib3hlcyA9IFtdO1xuICAgIGZvciAoIGlpPTA7IGlpIDwgNDsgKytpaSApIHtcblx0dGhpcy5zYm94ZXNbIGlpIF0gPSBbXTtcblx0Zm9yICggamo9MDsgamogPCAyNTY7ICsramogKSB7XG5cdCAgICB0aGlzLnNib3hlc1sgaWkgXVsgamogXSA9IHRoaXMuU0JPWEVTWyBpaSBdWyBqaiBdO1xuXHR9XG4gICAgfVxuXG4gICAgdmFyIHZhbHMgPSBbIDB4MDAwMDAwMDAsIDB4MDAwMDAwMDAgXTtcblxuICAgIGZvciAoIGlpPTA7IGlpIDwgdGhpcy5OTisyOyBpaSArPSAyICkge1xuXHR0aGlzLl9lbmNyeXB0X2Jsb2NrKCB2YWxzICk7XG5cdHRoaXMucGFycmF5WyBpaSArIDAgXSA9IHZhbHNbIDAgXTtcblx0dGhpcy5wYXJyYXlbIGlpICsgMSBdID0gdmFsc1sgMSBdO1xuICAgIH1cblxuICAgIGZvciAoIGlpPTA7IGlpIDwgNDsgKytpaSApIHtcblx0Zm9yICggamo9MDsgamogPCAyNTY7IGpqICs9IDIgKSB7XG5cdCAgICB0aGlzLl9lbmNyeXB0X2Jsb2NrKCB2YWxzICk7XG5cdCAgICB0aGlzLnNib3hlc1sgaWkgXVsgamogKyAwIF0gPSB2YWxzWyAwIF07XG5cdCAgICB0aGlzLnNib3hlc1sgaWkgXVsgamogKyAxIF0gPSB2YWxzWyAxIF07XG5cdH1cbiAgICB9XG59O1xuXG4vLyBhZGRlZCBieSBSZWN1cml0eSBMYWJzXG5mdW5jdGlvbiBCRmVuY3J5cHQoYmxvY2ssa2V5KSB7XG5cdHZhciBiZiA9IG5ldyBCbG93ZmlzaCgpO1xuXHRiZi5pbml0KHV0aWwuc3RyMmJpbihrZXkpKTtcblx0cmV0dXJuIGJmLmVuY3J5cHRfYmxvY2soYmxvY2spO1xufVxuXG5tb2R1bGUuZXhwb3J0cyA9IEJGZW5jcnlwdDtcbiIsIihmdW5jdGlvbigpey8qKlxuICogQSBmYXN0IE1ENSBKYXZhU2NyaXB0IGltcGxlbWVudGF0aW9uXG4gKiBDb3B5cmlnaHQgKGMpIDIwMTIgSm9zZXBoIE15ZXJzXG4gKiBodHRwOi8vd3d3Lm15ZXJzZGFpbHkub3JnL2pvc2VwaC9qYXZhc2NyaXB0L21kNS10ZXh0Lmh0bWxcbiAqXG4gKiBQZXJtaXNzaW9uIHRvIHVzZSwgY29weSwgbW9kaWZ5LCBhbmQgZGlzdHJpYnV0ZSB0aGlzIHNvZnR3YXJlXG4gKiBhbmQgaXRzIGRvY3VtZW50YXRpb24gZm9yIGFueSBwdXJwb3NlcyBhbmQgd2l0aG91dFxuICogZmVlIGlzIGhlcmVieSBncmFudGVkIHByb3ZpZGVkIHRoYXQgdGhpcyBjb3B5cmlnaHQgbm90aWNlXG4gKiBhcHBlYXJzIGluIGFsbCBjb3BpZXMuXG4gKlxuICogT2YgY291cnNlLCB0aGlzIHNvZnQgaXMgcHJvdmlkZWQgXCJhcyBpc1wiIHdpdGhvdXQgZXhwcmVzcyBvciBpbXBsaWVkXG4gKiB3YXJyYW50eSBvZiBhbnkga2luZC5cbiAqL1xuXG5mdW5jdGlvbiBNRDUoZW50cmVlKSB7XG5cdHZhciBoZXggPSBtZDUoZW50cmVlKTtcblx0dmFyIGJpbiA9IHV0aWwuaGV4MmJpbihoZXgpO1xuXHRyZXR1cm4gYmluO1xufVxuXG5mdW5jdGlvbiBtZDVjeWNsZSh4LCBrKSB7XG52YXIgYSA9IHhbMF0sIGIgPSB4WzFdLCBjID0geFsyXSwgZCA9IHhbM107XG5cbmEgPSBmZihhLCBiLCBjLCBkLCBrWzBdLCA3LCAtNjgwODc2OTM2KTtcbmQgPSBmZihkLCBhLCBiLCBjLCBrWzFdLCAxMiwgLTM4OTU2NDU4Nik7XG5jID0gZmYoYywgZCwgYSwgYiwga1syXSwgMTcsICA2MDYxMDU4MTkpO1xuYiA9IGZmKGIsIGMsIGQsIGEsIGtbM10sIDIyLCAtMTA0NDUyNTMzMCk7XG5hID0gZmYoYSwgYiwgYywgZCwga1s0XSwgNywgLTE3NjQxODg5Nyk7XG5kID0gZmYoZCwgYSwgYiwgYywga1s1XSwgMTIsICAxMjAwMDgwNDI2KTtcbmMgPSBmZihjLCBkLCBhLCBiLCBrWzZdLCAxNywgLTE0NzMyMzEzNDEpO1xuYiA9IGZmKGIsIGMsIGQsIGEsIGtbN10sIDIyLCAtNDU3MDU5ODMpO1xuYSA9IGZmKGEsIGIsIGMsIGQsIGtbOF0sIDcsICAxNzcwMDM1NDE2KTtcbmQgPSBmZihkLCBhLCBiLCBjLCBrWzldLCAxMiwgLTE5NTg0MTQ0MTcpO1xuYyA9IGZmKGMsIGQsIGEsIGIsIGtbMTBdLCAxNywgLTQyMDYzKTtcbmIgPSBmZihiLCBjLCBkLCBhLCBrWzExXSwgMjIsIC0xOTkwNDA0MTYyKTtcbmEgPSBmZihhLCBiLCBjLCBkLCBrWzEyXSwgNywgIDE4MDQ2MDM2ODIpO1xuZCA9IGZmKGQsIGEsIGIsIGMsIGtbMTNdLCAxMiwgLTQwMzQxMTAxKTtcbmMgPSBmZihjLCBkLCBhLCBiLCBrWzE0XSwgMTcsIC0xNTAyMDAyMjkwKTtcbmIgPSBmZihiLCBjLCBkLCBhLCBrWzE1XSwgMjIsICAxMjM2NTM1MzI5KTtcblxuYSA9IGdnKGEsIGIsIGMsIGQsIGtbMV0sIDUsIC0xNjU3OTY1MTApO1xuZCA9IGdnKGQsIGEsIGIsIGMsIGtbNl0sIDksIC0xMDY5NTAxNjMyKTtcbmMgPSBnZyhjLCBkLCBhLCBiLCBrWzExXSwgMTQsICA2NDM3MTc3MTMpO1xuYiA9IGdnKGIsIGMsIGQsIGEsIGtbMF0sIDIwLCAtMzczODk3MzAyKTtcbmEgPSBnZyhhLCBiLCBjLCBkLCBrWzVdLCA1LCAtNzAxNTU4NjkxKTtcbmQgPSBnZyhkLCBhLCBiLCBjLCBrWzEwXSwgOSwgIDM4MDE2MDgzKTtcbmMgPSBnZyhjLCBkLCBhLCBiLCBrWzE1XSwgMTQsIC02NjA0NzgzMzUpO1xuYiA9IGdnKGIsIGMsIGQsIGEsIGtbNF0sIDIwLCAtNDA1NTM3ODQ4KTtcbmEgPSBnZyhhLCBiLCBjLCBkLCBrWzldLCA1LCAgNTY4NDQ2NDM4KTtcbmQgPSBnZyhkLCBhLCBiLCBjLCBrWzE0XSwgOSwgLTEwMTk4MDM2OTApO1xuYyA9IGdnKGMsIGQsIGEsIGIsIGtbM10sIDE0LCAtMTg3MzYzOTYxKTtcbmIgPSBnZyhiLCBjLCBkLCBhLCBrWzhdLCAyMCwgIDExNjM1MzE1MDEpO1xuYSA9IGdnKGEsIGIsIGMsIGQsIGtbMTNdLCA1LCAtMTQ0NDY4MTQ2Nyk7XG5kID0gZ2coZCwgYSwgYiwgYywga1syXSwgOSwgLTUxNDAzNzg0KTtcbmMgPSBnZyhjLCBkLCBhLCBiLCBrWzddLCAxNCwgIDE3MzUzMjg0NzMpO1xuYiA9IGdnKGIsIGMsIGQsIGEsIGtbMTJdLCAyMCwgLTE5MjY2MDc3MzQpO1xuXG5hID0gaGgoYSwgYiwgYywgZCwga1s1XSwgNCwgLTM3ODU1OCk7XG5kID0gaGgoZCwgYSwgYiwgYywga1s4XSwgMTEsIC0yMDIyNTc0NDYzKTtcbmMgPSBoaChjLCBkLCBhLCBiLCBrWzExXSwgMTYsICAxODM5MDMwNTYyKTtcbmIgPSBoaChiLCBjLCBkLCBhLCBrWzE0XSwgMjMsIC0zNTMwOTU1Nik7XG5hID0gaGgoYSwgYiwgYywgZCwga1sxXSwgNCwgLTE1MzA5OTIwNjApO1xuZCA9IGhoKGQsIGEsIGIsIGMsIGtbNF0sIDExLCAgMTI3Mjg5MzM1Myk7XG5jID0gaGgoYywgZCwgYSwgYiwga1s3XSwgMTYsIC0xNTU0OTc2MzIpO1xuYiA9IGhoKGIsIGMsIGQsIGEsIGtbMTBdLCAyMywgLTEwOTQ3MzA2NDApO1xuYSA9IGhoKGEsIGIsIGMsIGQsIGtbMTNdLCA0LCAgNjgxMjc5MTc0KTtcbmQgPSBoaChkLCBhLCBiLCBjLCBrWzBdLCAxMSwgLTM1ODUzNzIyMik7XG5jID0gaGgoYywgZCwgYSwgYiwga1szXSwgMTYsIC03MjI1MjE5NzkpO1xuYiA9IGhoKGIsIGMsIGQsIGEsIGtbNl0sIDIzLCAgNzYwMjkxODkpO1xuYSA9IGhoKGEsIGIsIGMsIGQsIGtbOV0sIDQsIC02NDAzNjQ0ODcpO1xuZCA9IGhoKGQsIGEsIGIsIGMsIGtbMTJdLCAxMSwgLTQyMTgxNTgzNSk7XG5jID0gaGgoYywgZCwgYSwgYiwga1sxNV0sIDE2LCAgNTMwNzQyNTIwKTtcbmIgPSBoaChiLCBjLCBkLCBhLCBrWzJdLCAyMywgLTk5NTMzODY1MSk7XG5cbmEgPSBpaShhLCBiLCBjLCBkLCBrWzBdLCA2LCAtMTk4NjMwODQ0KTtcbmQgPSBpaShkLCBhLCBiLCBjLCBrWzddLCAxMCwgIDExMjY4OTE0MTUpO1xuYyA9IGlpKGMsIGQsIGEsIGIsIGtbMTRdLCAxNSwgLTE0MTYzNTQ5MDUpO1xuYiA9IGlpKGIsIGMsIGQsIGEsIGtbNV0sIDIxLCAtNTc0MzQwNTUpO1xuYSA9IGlpKGEsIGIsIGMsIGQsIGtbMTJdLCA2LCAgMTcwMDQ4NTU3MSk7XG5kID0gaWkoZCwgYSwgYiwgYywga1szXSwgMTAsIC0xODk0OTg2NjA2KTtcbmMgPSBpaShjLCBkLCBhLCBiLCBrWzEwXSwgMTUsIC0xMDUxNTIzKTtcbmIgPSBpaShiLCBjLCBkLCBhLCBrWzFdLCAyMSwgLTIwNTQ5MjI3OTkpO1xuYSA9IGlpKGEsIGIsIGMsIGQsIGtbOF0sIDYsICAxODczMzEzMzU5KTtcbmQgPSBpaShkLCBhLCBiLCBjLCBrWzE1XSwgMTAsIC0zMDYxMTc0NCk7XG5jID0gaWkoYywgZCwgYSwgYiwga1s2XSwgMTUsIC0xNTYwMTk4MzgwKTtcbmIgPSBpaShiLCBjLCBkLCBhLCBrWzEzXSwgMjEsICAxMzA5MTUxNjQ5KTtcbmEgPSBpaShhLCBiLCBjLCBkLCBrWzRdLCA2LCAtMTQ1NTIzMDcwKTtcbmQgPSBpaShkLCBhLCBiLCBjLCBrWzExXSwgMTAsIC0xMTIwMjEwMzc5KTtcbmMgPSBpaShjLCBkLCBhLCBiLCBrWzJdLCAxNSwgIDcxODc4NzI1OSk7XG5iID0gaWkoYiwgYywgZCwgYSwga1s5XSwgMjEsIC0zNDM0ODU1NTEpO1xuXG54WzBdID0gYWRkMzIoYSwgeFswXSk7XG54WzFdID0gYWRkMzIoYiwgeFsxXSk7XG54WzJdID0gYWRkMzIoYywgeFsyXSk7XG54WzNdID0gYWRkMzIoZCwgeFszXSk7XG5cbn1cblxuZnVuY3Rpb24gY21uKHEsIGEsIGIsIHgsIHMsIHQpIHtcbmEgPSBhZGQzMihhZGQzMihhLCBxKSwgYWRkMzIoeCwgdCkpO1xucmV0dXJuIGFkZDMyKChhIDw8IHMpIHwgKGEgPj4+ICgzMiAtIHMpKSwgYik7XG59XG5cbmZ1bmN0aW9uIGZmKGEsIGIsIGMsIGQsIHgsIHMsIHQpIHtcbnJldHVybiBjbW4oKGIgJiBjKSB8ICgofmIpICYgZCksIGEsIGIsIHgsIHMsIHQpO1xufVxuXG5mdW5jdGlvbiBnZyhhLCBiLCBjLCBkLCB4LCBzLCB0KSB7XG5yZXR1cm4gY21uKChiICYgZCkgfCAoYyAmICh+ZCkpLCBhLCBiLCB4LCBzLCB0KTtcbn1cblxuZnVuY3Rpb24gaGgoYSwgYiwgYywgZCwgeCwgcywgdCkge1xucmV0dXJuIGNtbihiIF4gYyBeIGQsIGEsIGIsIHgsIHMsIHQpO1xufVxuXG5mdW5jdGlvbiBpaShhLCBiLCBjLCBkLCB4LCBzLCB0KSB7XG5yZXR1cm4gY21uKGMgXiAoYiB8ICh+ZCkpLCBhLCBiLCB4LCBzLCB0KTtcbn1cblxuZnVuY3Rpb24gbWQ1MShzKSB7XG50eHQgPSAnJztcbnZhciBuID0gcy5sZW5ndGgsXG5zdGF0ZSA9IFsxNzMyNTg0MTkzLCAtMjcxNzMzODc5LCAtMTczMjU4NDE5NCwgMjcxNzMzODc4XSwgaTtcbmZvciAoaT02NDsgaTw9cy5sZW5ndGg7IGkrPTY0KSB7XG5tZDVjeWNsZShzdGF0ZSwgbWQ1YmxrKHMuc3Vic3RyaW5nKGktNjQsIGkpKSk7XG59XG5zID0gcy5zdWJzdHJpbmcoaS02NCk7XG52YXIgdGFpbCA9IFswLDAsMCwwLCAwLDAsMCwwLCAwLDAsMCwwLCAwLDAsMCwwXTtcbmZvciAoaT0wOyBpPHMubGVuZ3RoOyBpKyspXG50YWlsW2k+PjJdIHw9IHMuY2hhckNvZGVBdChpKSA8PCAoKGklNCkgPDwgMyk7XG50YWlsW2k+PjJdIHw9IDB4ODAgPDwgKChpJTQpIDw8IDMpO1xuaWYgKGkgPiA1NSkge1xubWQ1Y3ljbGUoc3RhdGUsIHRhaWwpO1xuZm9yIChpPTA7IGk8MTY7IGkrKykgdGFpbFtpXSA9IDA7XG59XG50YWlsWzE0XSA9IG4qODtcbm1kNWN5Y2xlKHN0YXRlLCB0YWlsKTtcbnJldHVybiBzdGF0ZTtcbn1cblxuLyogdGhlcmUgbmVlZHMgdG8gYmUgc3VwcG9ydCBmb3IgVW5pY29kZSBoZXJlLFxuICogdW5sZXNzIHdlIHByZXRlbmQgdGhhdCB3ZSBjYW4gcmVkZWZpbmUgdGhlIE1ELTVcbiAqIGFsZ29yaXRobSBmb3IgbXVsdGktYnl0ZSBjaGFyYWN0ZXJzIChwZXJoYXBzXG4gKiBieSBhZGRpbmcgZXZlcnkgZm91ciAxNi1iaXQgY2hhcmFjdGVycyBhbmRcbiAqIHNob3J0ZW5pbmcgdGhlIHN1bSB0byAzMiBiaXRzKS4gT3RoZXJ3aXNlXG4gKiBJIHN1Z2dlc3QgcGVyZm9ybWluZyBNRC01IGFzIGlmIGV2ZXJ5IGNoYXJhY3RlclxuICogd2FzIHR3byBieXRlcy0tZS5nLiwgMDA0MCAwMDI1ID0gQCUtLWJ1dCB0aGVuXG4gKiBob3cgd2lsbCBhbiBvcmRpbmFyeSBNRC01IHN1bSBiZSBtYXRjaGVkP1xuICogVGhlcmUgaXMgbm8gd2F5IHRvIHN0YW5kYXJkaXplIHRleHQgdG8gc29tZXRoaW5nXG4gKiBsaWtlIFVURi04IGJlZm9yZSB0cmFuc2Zvcm1hdGlvbjsgc3BlZWQgY29zdCBpc1xuICogdXR0ZXJseSBwcm9oaWJpdGl2ZS4gVGhlIEphdmFTY3JpcHQgc3RhbmRhcmRcbiAqIGl0c2VsZiBuZWVkcyB0byBsb29rIGF0IHRoaXM6IGl0IHNob3VsZCBzdGFydFxuICogcHJvdmlkaW5nIGFjY2VzcyB0byBzdHJpbmdzIGFzIHByZWZvcm1lZCBVVEYtOFxuICogOC1iaXQgdW5zaWduZWQgdmFsdWUgYXJyYXlzLlxuICovXG5mdW5jdGlvbiBtZDVibGsocykgeyAvKiBJIGZpZ3VyZWQgZ2xvYmFsIHdhcyBmYXN0ZXIuICAgKi9cbnZhciBtZDVibGtzID0gW10sIGk7IC8qIEFuZHkgS2luZyBzYWlkIGRvIGl0IHRoaXMgd2F5LiAqL1xuZm9yIChpPTA7IGk8NjQ7IGkrPTQpIHtcbm1kNWJsa3NbaT4+Ml0gPSBzLmNoYXJDb2RlQXQoaSlcbisgKHMuY2hhckNvZGVBdChpKzEpIDw8IDgpXG4rIChzLmNoYXJDb2RlQXQoaSsyKSA8PCAxNilcbisgKHMuY2hhckNvZGVBdChpKzMpIDw8IDI0KTtcbn1cbnJldHVybiBtZDVibGtzO1xufVxuXG52YXIgaGV4X2NociA9ICcwMTIzNDU2Nzg5YWJjZGVmJy5zcGxpdCgnJyk7XG5cbmZ1bmN0aW9uIHJoZXgobilcbntcbnZhciBzPScnLCBqPTA7XG5mb3IoOyBqPDQ7IGorKylcbnMgKz0gaGV4X2NoclsobiA+PiAoaiAqIDggKyA0KSkgJiAweDBGXVxuKyBoZXhfY2hyWyhuID4+IChqICogOCkpICYgMHgwRl07XG5yZXR1cm4gcztcbn1cblxuZnVuY3Rpb24gaGV4KHgpIHtcbmZvciAodmFyIGk9MDsgaTx4Lmxlbmd0aDsgaSsrKVxueFtpXSA9IHJoZXgoeFtpXSk7XG5yZXR1cm4geC5qb2luKCcnKTtcbn1cblxuZnVuY3Rpb24gbWQ1KHMpIHtcbnJldHVybiBoZXgobWQ1MShzKSk7XG59XG5cbi8qIHRoaXMgZnVuY3Rpb24gaXMgbXVjaCBmYXN0ZXIsXG5zbyBpZiBwb3NzaWJsZSB3ZSB1c2UgaXQuIFNvbWUgSUVzXG5hcmUgdGhlIG9ubHkgb25lcyBJIGtub3cgb2YgdGhhdFxubmVlZCB0aGUgaWRpb3RpYyBzZWNvbmQgZnVuY3Rpb24sXG5nZW5lcmF0ZWQgYnkgYW4gaWYgY2xhdXNlLiAgKi9cblxuZnVuY3Rpb24gYWRkMzIoYSwgYikge1xucmV0dXJuIChhICsgYikgJiAweEZGRkZGRkZGO1xufVxuXG5pZiAobWQ1KCdoZWxsbycpICE9ICc1ZDQxNDAyYWJjNGIyYTc2Yjk3MTlkOTExMDE3YzU5MicpIHtcbmZ1bmN0aW9uIGFkZDMyKHgsIHkpIHtcbnZhciBsc3cgPSAoeCAmIDB4RkZGRikgKyAoeSAmIDB4RkZGRiksXG5tc3cgPSAoeCA+PiAxNikgKyAoeSA+PiAxNikgKyAobHN3ID4+IDE2KTtcbnJldHVybiAobXN3IDw8IDE2KSB8IChsc3cgJiAweEZGRkYpO1xufVxufVxuXG5tb2R1bGUuZXhwb3J0cyA9IE1ENVxuXG59KSgpIiwiLyogQSBKYXZhU2NyaXB0IGltcGxlbWVudGF0aW9uIG9mIHRoZSBTSEEgZmFtaWx5IG9mIGhhc2hlcywgYXMgZGVmaW5lZCBpbiBGSVBTIFxuICogUFVCIDE4MC0yIGFzIHdlbGwgYXMgdGhlIGNvcnJlc3BvbmRpbmcgSE1BQyBpbXBsZW1lbnRhdGlvbiBhcyBkZWZpbmVkIGluXG4gKiBGSVBTIFBVQiAxOThhXG4gKlxuICogVmVyc2lvbiAxLjMgQ29weXJpZ2h0IEJyaWFuIFR1cmVrIDIwMDgtMjAxMFxuICogRGlzdHJpYnV0ZWQgdW5kZXIgdGhlIEJTRCBMaWNlbnNlXG4gKiBTZWUgaHR0cDovL2pzc2hhLnNvdXJjZWZvcmdlLm5ldC8gZm9yIG1vcmUgaW5mb3JtYXRpb25cbiAqXG4gKiBTZXZlcmFsIGZ1bmN0aW9ucyB0YWtlbiBmcm9tIFBhdWwgSm9obnNvblxuICovXG5cbi8qIE1vZGlmaWVkIGJ5IFJlY3VyaXR5IExhYnMgR21iSFxuICogXG4gKiBUaGlzIGNvZGUgaGFzIGJlZW4gc2xpZ2h0bHkgbW9kaWZpZWQgZGlyZWN0IHN0cmluZyBvdXRwdXQ6XG4gKiAtIGJpbjJic3RyIGhhcyBiZWVuIGFkZGVkXG4gKiAtIGZvbGxvd2luZyB3cmFwcGVycyBvZiB0aGlzIGxpYnJhcnkgaGF2ZSBiZWVuIGFkZGVkOlxuICogICAtIHN0cl9zaGExXG4gKiAgIC0gc3RyX3NoYTI1NlxuICogICAtIHN0cl9zaGEyMjRcbiAqICAgLSBzdHJfc2hhMzg0XG4gKiAgIC0gc3RyX3NoYTUxMlxuICovXG5cbnZhciBqc1NIQSA9IChmdW5jdGlvbiAoKSB7XG5cdFxuXHQvKlxuXHQgKiBDb25maWd1cmFibGUgdmFyaWFibGVzLiBEZWZhdWx0cyB0eXBpY2FsbHkgd29ya1xuXHQgKi9cblx0LyogTnVtYmVyIG9mIEJpdHMgUGVyIGNoYXJhY3RlciAoOCBmb3IgQVNDSUksIDE2IGZvciBVbmljb2RlKSAqL1xuXHR2YXIgY2hhclNpemUgPSA4LCBcblx0LyogYmFzZS02NCBwYWQgY2hhcmFjdGVyLiBcIj1cIiBmb3Igc3RyaWN0IFJGQyBjb21wbGlhbmNlICovXG5cdGI2NHBhZCA9IFwiXCIsIFxuXHQvKiBoZXggb3V0cHV0IGZvcm1hdC4gMCAtIGxvd2VyY2FzZTsgMSAtIHVwcGVyY2FzZSAqL1xuXHRoZXhDYXNlID0gMCwgXG5cblx0Lypcblx0ICogSW50XzY0IGlzIGEgb2JqZWN0IGZvciAyIDMyLWJpdCBudW1iZXJzIGVtdWxhdGluZyBhIDY0LWJpdCBudW1iZXJcblx0ICpcblx0ICogQGNvbnN0cnVjdG9yXG5cdCAqIEBwYXJhbSB7TnVtYmVyfSBtc2ludF8zMiBUaGUgbW9zdCBzaWduaWZpY2FudCAzMi1iaXRzIG9mIGEgNjQtYml0IG51bWJlclxuXHQgKiBAcGFyYW0ge051bWJlcn0gbHNpbnRfMzIgVGhlIGxlYXN0IHNpZ25pZmljYW50IDMyLWJpdHMgb2YgYSA2NC1iaXQgbnVtYmVyXG5cdCAqL1xuXHRJbnRfNjQgPSBmdW5jdGlvbiAobXNpbnRfMzIsIGxzaW50XzMyKVxuXHR7XG5cdFx0dGhpcy5oaWdoT3JkZXIgPSBtc2ludF8zMjtcblx0XHR0aGlzLmxvd09yZGVyID0gbHNpbnRfMzI7XG5cdH0sXG5cblx0Lypcblx0ICogQ29udmVydCBhIHN0cmluZyB0byBhbiBhcnJheSBvZiBiaWctZW5kaWFuIHdvcmRzXG5cdCAqIElmIGNoYXJTaXplIGlzIEFTQ0lJLCBjaGFyYWN0ZXJzID4yNTUgaGF2ZSB0aGVpciBoaS1ieXRlIHNpbGVudGx5XG5cdCAqIGlnbm9yZWQuXG5cdCAqXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBzdHIgU3RyaW5nIHRvIGJlIGNvbnZlcnRlZCB0byBiaW5hcnkgcmVwcmVzZW50YXRpb25cblx0ICogQHJldHVybiBJbnRlZ2VyIGFycmF5IHJlcHJlc2VudGF0aW9uIG9mIHRoZSBwYXJhbWV0ZXJcblx0ICovXG5cdHN0cjJiaW5iID0gZnVuY3Rpb24gKHN0cilcblx0e1xuXHRcdHZhciBiaW4gPSBbXSwgbWFzayA9ICgxIDw8IGNoYXJTaXplKSAtIDEsXG5cdFx0XHRsZW5ndGggPSBzdHIubGVuZ3RoICogY2hhclNpemUsIGk7XG5cblx0XHRmb3IgKGkgPSAwOyBpIDwgbGVuZ3RoOyBpICs9IGNoYXJTaXplKVxuXHRcdHtcblx0XHRcdGJpbltpID4+IDVdIHw9IChzdHIuY2hhckNvZGVBdChpIC8gY2hhclNpemUpICYgbWFzaykgPDxcblx0XHRcdFx0KDMyIC0gY2hhclNpemUgLSAoaSAlIDMyKSk7XG5cdFx0fVxuXG5cdFx0cmV0dXJuIGJpbjtcblx0fSxcblxuXHQvKlxuXHQgKiBDb252ZXJ0IGEgaGV4IHN0cmluZyB0byBhbiBhcnJheSBvZiBiaWctZW5kaWFuIHdvcmRzXG5cdCAqXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBzdHIgU3RyaW5nIHRvIGJlIGNvbnZlcnRlZCB0byBiaW5hcnkgcmVwcmVzZW50YXRpb25cblx0ICogQHJldHVybiBJbnRlZ2VyIGFycmF5IHJlcHJlc2VudGF0aW9uIG9mIHRoZSBwYXJhbWV0ZXJcblx0ICovXG5cdGhleDJiaW5iID0gZnVuY3Rpb24gKHN0cilcblx0e1xuXHRcdHZhciBiaW4gPSBbXSwgbGVuZ3RoID0gc3RyLmxlbmd0aCwgaSwgbnVtO1xuXG5cdFx0Zm9yIChpID0gMDsgaSA8IGxlbmd0aDsgaSArPSAyKVxuXHRcdHtcblx0XHRcdG51bSA9IHBhcnNlSW50KHN0ci5zdWJzdHIoaSwgMiksIDE2KTtcblx0XHRcdGlmICghaXNOYU4obnVtKSlcblx0XHRcdHtcblx0XHRcdFx0YmluW2kgPj4gM10gfD0gbnVtIDw8ICgyNCAtICg0ICogKGkgJSA4KSkpO1xuXHRcdFx0fVxuXHRcdFx0ZWxzZVxuXHRcdFx0e1xuXHRcdFx0XHRyZXR1cm4gXCJJTlZBTElEIEhFWCBTVFJJTkdcIjtcblx0XHRcdH1cblx0XHR9XG5cblx0XHRyZXR1cm4gYmluO1xuXHR9LFxuXG5cdC8qXG5cdCAqIENvbnZlcnQgYW4gYXJyYXkgb2YgYmlnLWVuZGlhbiB3b3JkcyB0byBhIGhleCBzdHJpbmcuXG5cdCAqXG5cdCAqIEBwcml2YXRlXG5cdCAqIEBwYXJhbSB7QXJyYXl9IGJpbmFycmF5IEFycmF5IG9mIGludGVnZXJzIHRvIGJlIGNvbnZlcnRlZCB0byBoZXhpZGVjaW1hbFxuXHQgKlx0IHJlcHJlc2VudGF0aW9uXG5cdCAqIEByZXR1cm4gSGV4aWRlY2ltYWwgcmVwcmVzZW50YXRpb24gb2YgdGhlIHBhcmFtZXRlciBpbiBTdHJpbmcgZm9ybVxuXHQgKi9cblx0YmluYjJoZXggPSBmdW5jdGlvbiAoYmluYXJyYXkpXG5cdHtcblx0XHR2YXIgaGV4X3RhYiA9IChoZXhDYXNlKSA/IFwiMDEyMzQ1Njc4OUFCQ0RFRlwiIDogXCIwMTIzNDU2Nzg5YWJjZGVmXCIsXG5cdFx0XHRzdHIgPSBcIlwiLCBsZW5ndGggPSBiaW5hcnJheS5sZW5ndGggKiA0LCBpLCBzcmNCeXRlO1xuXG5cdFx0Zm9yIChpID0gMDsgaSA8IGxlbmd0aDsgaSArPSAxKVxuXHRcdHtcblx0XHRcdHNyY0J5dGUgPSBiaW5hcnJheVtpID4+IDJdID4+ICgoMyAtIChpICUgNCkpICogOCk7XG5cdFx0XHRzdHIgKz0gaGV4X3RhYi5jaGFyQXQoKHNyY0J5dGUgPj4gNCkgJiAweEYpICtcblx0XHRcdFx0aGV4X3RhYi5jaGFyQXQoc3JjQnl0ZSAmIDB4Rik7XG5cdFx0fVxuXG5cdFx0cmV0dXJuIHN0cjtcblx0fSxcblxuXHQvKlxuXHQgKiBDb252ZXJ0IGFuIGFycmF5IG9mIGJpZy1lbmRpYW4gd29yZHMgdG8gYSBiYXNlLTY0IHN0cmluZ1xuXHQgKlxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge0FycmF5fSBiaW5hcnJheSBBcnJheSBvZiBpbnRlZ2VycyB0byBiZSBjb252ZXJ0ZWQgdG8gYmFzZS02NFxuXHQgKlx0IHJlcHJlc2VudGF0aW9uXG5cdCAqIEByZXR1cm4gQmFzZS02NCBlbmNvZGVkIHJlcHJlc2VudGF0aW9uIG9mIHRoZSBwYXJhbWV0ZXIgaW4gU3RyaW5nIGZvcm1cblx0ICovXG5cdGJpbmIyYjY0ID0gZnVuY3Rpb24gKGJpbmFycmF5KVxuXHR7XG5cdFx0dmFyIHRhYiA9IFwiQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5elwiICtcblx0XHRcdFwiMDEyMzQ1Njc4OSsvXCIsIHN0ciA9IFwiXCIsIGxlbmd0aCA9IGJpbmFycmF5Lmxlbmd0aCAqIDQsIGksIGosXG5cdFx0XHR0cmlwbGV0O1xuXG5cdFx0Zm9yIChpID0gMDsgaSA8IGxlbmd0aDsgaSArPSAzKVxuXHRcdHtcblx0XHRcdHRyaXBsZXQgPSAoKChiaW5hcnJheVtpID4+IDJdID4+IDggKiAoMyAtIGkgJSA0KSkgJiAweEZGKSA8PCAxNikgfFxuXHRcdFx0XHQoKChiaW5hcnJheVtpICsgMSA+PiAyXSA+PiA4ICogKDMgLSAoaSArIDEpICUgNCkpICYgMHhGRikgPDwgOCkgfFxuXHRcdFx0XHQoKGJpbmFycmF5W2kgKyAyID4+IDJdID4+IDggKiAoMyAtIChpICsgMikgJSA0KSkgJiAweEZGKTtcblx0XHRcdGZvciAoaiA9IDA7IGogPCA0OyBqICs9IDEpXG5cdFx0XHR7XG5cdFx0XHRcdGlmIChpICogOCArIGogKiA2IDw9IGJpbmFycmF5Lmxlbmd0aCAqIDMyKVxuXHRcdFx0XHR7XG5cdFx0XHRcdFx0c3RyICs9IHRhYi5jaGFyQXQoKHRyaXBsZXQgPj4gNiAqICgzIC0gaikpICYgMHgzRik7XG5cdFx0XHRcdH1cblx0XHRcdFx0ZWxzZVxuXHRcdFx0XHR7XG5cdFx0XHRcdFx0c3RyICs9IGI2NHBhZDtcblx0XHRcdFx0fVxuXHRcdFx0fVxuXHRcdH1cblx0XHRyZXR1cm4gc3RyO1xuXHR9LFxuXG5cdC8qXG5cdCAqIENvbnZlcnQgYW4gYXJyYXkgb2YgYmlnLWVuZGlhbiB3b3JkcyB0byBhIHN0cmluZ1xuXHQgKi9cblx0YmluYjJzdHIgPSBmdW5jdGlvbiAoYmluKVxuXHR7XG5cdCAgdmFyIHN0ciA9IFwiXCI7XG5cdCAgdmFyIG1hc2sgPSAoMSA8PCA4KSAtIDE7XG5cdCAgZm9yKHZhciBpID0gMDsgaSA8IGJpbi5sZW5ndGggKiAzMjsgaSArPSA4KVxuXHQgICAgc3RyICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoKGJpbltpPj41XSA+Pj4gKDI0IC0gaSUzMikpICYgbWFzayk7XG5cdCAgcmV0dXJuIHN0cjtcblx0fSxcblx0Lypcblx0ICogVGhlIDMyLWJpdCBpbXBsZW1lbnRhdGlvbiBvZiBjaXJjdWxhciByb3RhdGUgbGVmdFxuXHQgKlxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge051bWJlcn0geCBUaGUgMzItYml0IGludGVnZXIgYXJndW1lbnRcblx0ICogQHBhcmFtIHtOdW1iZXJ9IG4gVGhlIG51bWJlciBvZiBiaXRzIHRvIHNoaWZ0XG5cdCAqIEByZXR1cm4gVGhlIHggc2hpZnRlZCBjaXJjdWxhcmx5IGJ5IG4gYml0c1xuXHQgKi9cblx0cm90bF8zMiA9IGZ1bmN0aW9uICh4LCBuKVxuXHR7XG5cdFx0cmV0dXJuICh4IDw8IG4pIHwgKHggPj4+ICgzMiAtIG4pKTtcblx0fSxcblxuXHQvKlxuXHQgKiBUaGUgMzItYml0IGltcGxlbWVudGF0aW9uIG9mIGNpcmN1bGFyIHJvdGF0ZSByaWdodFxuXHQgKlxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge051bWJlcn0geCBUaGUgMzItYml0IGludGVnZXIgYXJndW1lbnRcblx0ICogQHBhcmFtIHtOdW1iZXJ9IG4gVGhlIG51bWJlciBvZiBiaXRzIHRvIHNoaWZ0XG5cdCAqIEByZXR1cm4gVGhlIHggc2hpZnRlZCBjaXJjdWxhcmx5IGJ5IG4gYml0c1xuXHQgKi9cblx0cm90cl8zMiA9IGZ1bmN0aW9uICh4LCBuKVxuXHR7XG5cdFx0cmV0dXJuICh4ID4+PiBuKSB8ICh4IDw8ICgzMiAtIG4pKTtcblx0fSxcblxuXHQvKlxuXHQgKiBUaGUgNjQtYml0IGltcGxlbWVudGF0aW9uIG9mIGNpcmN1bGFyIHJvdGF0ZSByaWdodFxuXHQgKlxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge0ludF82NH0geCBUaGUgNjQtYml0IGludGVnZXIgYXJndW1lbnRcblx0ICogQHBhcmFtIHtOdW1iZXJ9IG4gVGhlIG51bWJlciBvZiBiaXRzIHRvIHNoaWZ0XG5cdCAqIEByZXR1cm4gVGhlIHggc2hpZnRlZCBjaXJjdWxhcmx5IGJ5IG4gYml0c1xuXHQgKi9cblx0cm90cl82NCA9IGZ1bmN0aW9uICh4LCBuKVxuXHR7XG5cdFx0aWYgKG4gPD0gMzIpXG5cdFx0e1xuXHRcdFx0cmV0dXJuIG5ldyBJbnRfNjQoXG5cdFx0XHRcdFx0KHguaGlnaE9yZGVyID4+PiBuKSB8ICh4Lmxvd09yZGVyIDw8ICgzMiAtIG4pKSxcblx0XHRcdFx0XHQoeC5sb3dPcmRlciA+Pj4gbikgfCAoeC5oaWdoT3JkZXIgPDwgKDMyIC0gbikpXG5cdFx0XHRcdCk7XG5cdFx0fVxuXHRcdGVsc2Vcblx0XHR7XG5cdFx0XHRyZXR1cm4gbmV3IEludF82NChcblx0XHRcdFx0XHQoeC5sb3dPcmRlciA+Pj4gbikgfCAoeC5oaWdoT3JkZXIgPDwgKDMyIC0gbikpLFxuXHRcdFx0XHRcdCh4LmhpZ2hPcmRlciA+Pj4gbikgfCAoeC5sb3dPcmRlciA8PCAoMzIgLSBuKSlcblx0XHRcdFx0KTtcblx0XHR9XG5cdH0sXG5cblx0Lypcblx0ICogVGhlIDMyLWJpdCBpbXBsZW1lbnRhdGlvbiBvZiBzaGlmdCByaWdodFxuXHQgKlxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge051bWJlcn0geCBUaGUgMzItYml0IGludGVnZXIgYXJndW1lbnRcblx0ICogQHBhcmFtIHtOdW1iZXJ9IG4gVGhlIG51bWJlciBvZiBiaXRzIHRvIHNoaWZ0XG5cdCAqIEByZXR1cm4gVGhlIHggc2hpZnRlZCBieSBuIGJpdHNcblx0ICovXG5cdHNocl8zMiA9IGZ1bmN0aW9uICh4LCBuKVxuXHR7XG5cdFx0cmV0dXJuIHggPj4+IG47XG5cdH0sXG5cblx0Lypcblx0ICogVGhlIDY0LWJpdCBpbXBsZW1lbnRhdGlvbiBvZiBzaGlmdCByaWdodFxuXHQgKlxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge0ludF82NH0geCBUaGUgNjQtYml0IGludGVnZXIgYXJndW1lbnRcblx0ICogQHBhcmFtIHtOdW1iZXJ9IG4gVGhlIG51bWJlciBvZiBiaXRzIHRvIHNoaWZ0XG5cdCAqIEByZXR1cm4gVGhlIHggc2hpZnRlZCBieSBuIGJpdHNcblx0ICovXG5cdHNocl82NCA9IGZ1bmN0aW9uICh4LCBuKVxuXHR7XG5cdFx0aWYgKG4gPD0gMzIpXG5cdFx0e1xuXHRcdFx0cmV0dXJuIG5ldyBJbnRfNjQoXG5cdFx0XHRcdFx0eC5oaWdoT3JkZXIgPj4+IG4sXG5cdFx0XHRcdFx0eC5sb3dPcmRlciA+Pj4gbiB8ICh4LmhpZ2hPcmRlciA8PCAoMzIgLSBuKSlcblx0XHRcdFx0KTtcblx0XHR9XG5cdFx0ZWxzZVxuXHRcdHtcblx0XHRcdHJldHVybiBuZXcgSW50XzY0KFxuXHRcdFx0XHRcdDAsXG5cdFx0XHRcdFx0eC5oaWdoT3JkZXIgPDwgKDMyIC0gbilcblx0XHRcdFx0KTtcblx0XHR9XG5cdH0sXG5cblx0Lypcblx0ICogVGhlIDMyLWJpdCBpbXBsZW1lbnRhdGlvbiBvZiB0aGUgTklTVCBzcGVjaWZpZWQgUGFyaXR5IGZ1bmN0aW9uXG5cdCAqXG5cdCAqIEBwcml2YXRlXG5cdCAqIEBwYXJhbSB7TnVtYmVyfSB4IFRoZSBmaXJzdCAzMi1iaXQgaW50ZWdlciBhcmd1bWVudFxuXHQgKiBAcGFyYW0ge051bWJlcn0geSBUaGUgc2Vjb25kIDMyLWJpdCBpbnRlZ2VyIGFyZ3VtZW50XG5cdCAqIEBwYXJhbSB7TnVtYmVyfSB6IFRoZSB0aGlyZCAzMi1iaXQgaW50ZWdlciBhcmd1bWVudFxuXHQgKiBAcmV0dXJuIFRoZSBOSVNUIHNwZWNpZmllZCBvdXRwdXQgb2YgdGhlIGZ1bmN0aW9uXG5cdCAqL1xuXHRwYXJpdHlfMzIgPSBmdW5jdGlvbiAoeCwgeSwgeilcblx0e1xuXHRcdHJldHVybiB4IF4geSBeIHo7XG5cdH0sXG5cblx0Lypcblx0ICogVGhlIDMyLWJpdCBpbXBsZW1lbnRhdGlvbiBvZiB0aGUgTklTVCBzcGVjaWZpZWQgQ2ggZnVuY3Rpb25cblx0ICpcblx0ICogQHByaXZhdGVcblx0ICogQHBhcmFtIHtOdW1iZXJ9IHggVGhlIGZpcnN0IDMyLWJpdCBpbnRlZ2VyIGFyZ3VtZW50XG5cdCAqIEBwYXJhbSB7TnVtYmVyfSB5IFRoZSBzZWNvbmQgMzItYml0IGludGVnZXIgYXJndW1lbnRcblx0ICogQHBhcmFtIHtOdW1iZXJ9IHogVGhlIHRoaXJkIDMyLWJpdCBpbnRlZ2VyIGFyZ3VtZW50XG5cdCAqIEByZXR1cm4gVGhlIE5JU1Qgc3BlY2lmaWVkIG91dHB1dCBvZiB0aGUgZnVuY3Rpb25cblx0ICovXG5cdGNoXzMyID0gZnVuY3Rpb24gKHgsIHksIHopXG5cdHtcblx0XHRyZXR1cm4gKHggJiB5KSBeICh+eCAmIHopO1xuXHR9LFxuXG5cdC8qXG5cdCAqIFRoZSA2NC1iaXQgaW1wbGVtZW50YXRpb24gb2YgdGhlIE5JU1Qgc3BlY2lmaWVkIENoIGZ1bmN0aW9uXG5cdCAqXG5cdCAqIEBwcml2YXRlXG5cdCAqIEBwYXJhbSB7SW50XzY0fSB4IFRoZSBmaXJzdCA2NC1iaXQgaW50ZWdlciBhcmd1bWVudFxuXHQgKiBAcGFyYW0ge0ludF82NH0geSBUaGUgc2Vjb25kIDY0LWJpdCBpbnRlZ2VyIGFyZ3VtZW50XG5cdCAqIEBwYXJhbSB7SW50XzY0fSB6IFRoZSB0aGlyZCA2NC1iaXQgaW50ZWdlciBhcmd1bWVudFxuXHQgKiBAcmV0dXJuIFRoZSBOSVNUIHNwZWNpZmllZCBvdXRwdXQgb2YgdGhlIGZ1bmN0aW9uXG5cdCAqL1xuXHRjaF82NCA9IGZ1bmN0aW9uICh4LCB5LCB6KVxuXHR7XG5cdFx0cmV0dXJuIG5ldyBJbnRfNjQoXG5cdFx0XHRcdCh4LmhpZ2hPcmRlciAmIHkuaGlnaE9yZGVyKSBeICh+eC5oaWdoT3JkZXIgJiB6LmhpZ2hPcmRlciksXG5cdFx0XHRcdCh4Lmxvd09yZGVyICYgeS5sb3dPcmRlcikgXiAofngubG93T3JkZXIgJiB6Lmxvd09yZGVyKVxuXHRcdFx0KTtcblx0fSxcblxuXHQvKlxuXHQgKiBUaGUgMzItYml0IGltcGxlbWVudGF0aW9uIG9mIHRoZSBOSVNUIHNwZWNpZmllZCBNYWogZnVuY3Rpb25cblx0ICpcblx0ICogQHByaXZhdGVcblx0ICogQHBhcmFtIHtOdW1iZXJ9IHggVGhlIGZpcnN0IDMyLWJpdCBpbnRlZ2VyIGFyZ3VtZW50XG5cdCAqIEBwYXJhbSB7TnVtYmVyfSB5IFRoZSBzZWNvbmQgMzItYml0IGludGVnZXIgYXJndW1lbnRcblx0ICogQHBhcmFtIHtOdW1iZXJ9IHogVGhlIHRoaXJkIDMyLWJpdCBpbnRlZ2VyIGFyZ3VtZW50XG5cdCAqIEByZXR1cm4gVGhlIE5JU1Qgc3BlY2lmaWVkIG91dHB1dCBvZiB0aGUgZnVuY3Rpb25cblx0ICovXG5cdG1hal8zMiA9IGZ1bmN0aW9uICh4LCB5LCB6KVxuXHR7XG5cdFx0cmV0dXJuICh4ICYgeSkgXiAoeCAmIHopIF4gKHkgJiB6KTtcblx0fSxcblxuXHQvKlxuXHQgKiBUaGUgNjQtYml0IGltcGxlbWVudGF0aW9uIG9mIHRoZSBOSVNUIHNwZWNpZmllZCBNYWogZnVuY3Rpb25cblx0ICpcblx0ICogQHByaXZhdGVcblx0ICogQHBhcmFtIHtJbnRfNjR9IHggVGhlIGZpcnN0IDY0LWJpdCBpbnRlZ2VyIGFyZ3VtZW50XG5cdCAqIEBwYXJhbSB7SW50XzY0fSB5IFRoZSBzZWNvbmQgNjQtYml0IGludGVnZXIgYXJndW1lbnRcblx0ICogQHBhcmFtIHtJbnRfNjR9IHogVGhlIHRoaXJkIDY0LWJpdCBpbnRlZ2VyIGFyZ3VtZW50XG5cdCAqIEByZXR1cm4gVGhlIE5JU1Qgc3BlY2lmaWVkIG91dHB1dCBvZiB0aGUgZnVuY3Rpb25cblx0ICovXG5cdG1hal82NCA9IGZ1bmN0aW9uICh4LCB5LCB6KVxuXHR7XG5cdFx0cmV0dXJuIG5ldyBJbnRfNjQoXG5cdFx0XHRcdCh4LmhpZ2hPcmRlciAmIHkuaGlnaE9yZGVyKSBeXG5cdFx0XHRcdCh4LmhpZ2hPcmRlciAmIHouaGlnaE9yZGVyKSBeXG5cdFx0XHRcdCh5LmhpZ2hPcmRlciAmIHouaGlnaE9yZGVyKSxcblx0XHRcdFx0KHgubG93T3JkZXIgJiB5Lmxvd09yZGVyKSBeXG5cdFx0XHRcdCh4Lmxvd09yZGVyICYgei5sb3dPcmRlcikgXlxuXHRcdFx0XHQoeS5sb3dPcmRlciAmIHoubG93T3JkZXIpXG5cdFx0XHQpO1xuXHR9LFxuXG5cdC8qXG5cdCAqIFRoZSAzMi1iaXQgaW1wbGVtZW50YXRpb24gb2YgdGhlIE5JU1Qgc3BlY2lmaWVkIFNpZ21hMCBmdW5jdGlvblxuXHQgKlxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge051bWJlcn0geCBUaGUgMzItYml0IGludGVnZXIgYXJndW1lbnRcblx0ICogQHJldHVybiBUaGUgTklTVCBzcGVjaWZpZWQgb3V0cHV0IG9mIHRoZSBmdW5jdGlvblxuXHQgKi9cblx0c2lnbWEwXzMyID0gZnVuY3Rpb24gKHgpXG5cdHtcblx0XHRyZXR1cm4gcm90cl8zMih4LCAyKSBeIHJvdHJfMzIoeCwgMTMpIF4gcm90cl8zMih4LCAyMik7XG5cdH0sXG5cblx0Lypcblx0ICogVGhlIDY0LWJpdCBpbXBsZW1lbnRhdGlvbiBvZiB0aGUgTklTVCBzcGVjaWZpZWQgU2lnbWEwIGZ1bmN0aW9uXG5cdCAqXG5cdCAqIEBwcml2YXRlXG5cdCAqIEBwYXJhbSB7SW50XzY0fSB4IFRoZSA2NC1iaXQgaW50ZWdlciBhcmd1bWVudFxuXHQgKiBAcmV0dXJuIFRoZSBOSVNUIHNwZWNpZmllZCBvdXRwdXQgb2YgdGhlIGZ1bmN0aW9uXG5cdCAqL1xuXHRzaWdtYTBfNjQgPSBmdW5jdGlvbiAoeClcblx0e1xuXHRcdHZhciByb3RyMjggPSByb3RyXzY0KHgsIDI4KSwgcm90cjM0ID0gcm90cl82NCh4LCAzNCksXG5cdFx0XHRyb3RyMzkgPSByb3RyXzY0KHgsIDM5KTtcblxuXHRcdHJldHVybiBuZXcgSW50XzY0KFxuXHRcdFx0XHRyb3RyMjguaGlnaE9yZGVyIF4gcm90cjM0LmhpZ2hPcmRlciBeIHJvdHIzOS5oaWdoT3JkZXIsXG5cdFx0XHRcdHJvdHIyOC5sb3dPcmRlciBeIHJvdHIzNC5sb3dPcmRlciBeIHJvdHIzOS5sb3dPcmRlcik7XG5cdH0sXG5cblx0Lypcblx0ICogVGhlIDMyLWJpdCBpbXBsZW1lbnRhdGlvbiBvZiB0aGUgTklTVCBzcGVjaWZpZWQgU2lnbWExIGZ1bmN0aW9uXG5cdCAqXG5cdCAqIEBwcml2YXRlXG5cdCAqIEBwYXJhbSB7TnVtYmVyfSB4IFRoZSAzMi1iaXQgaW50ZWdlciBhcmd1bWVudFxuXHQgKiBAcmV0dXJuIFRoZSBOSVNUIHNwZWNpZmllZCBvdXRwdXQgb2YgdGhlIGZ1bmN0aW9uXG5cdCAqL1xuXHRzaWdtYTFfMzIgPSBmdW5jdGlvbiAoeClcblx0e1xuXHRcdHJldHVybiByb3RyXzMyKHgsIDYpIF4gcm90cl8zMih4LCAxMSkgXiByb3RyXzMyKHgsIDI1KTtcblx0fSxcblxuXHQvKlxuXHQgKiBUaGUgNjQtYml0IGltcGxlbWVudGF0aW9uIG9mIHRoZSBOSVNUIHNwZWNpZmllZCBTaWdtYTEgZnVuY3Rpb25cblx0ICpcblx0ICogQHByaXZhdGVcblx0ICogQHBhcmFtIHtJbnRfNjR9IHggVGhlIDY0LWJpdCBpbnRlZ2VyIGFyZ3VtZW50XG5cdCAqIEByZXR1cm4gVGhlIE5JU1Qgc3BlY2lmaWVkIG91dHB1dCBvZiB0aGUgZnVuY3Rpb25cblx0ICovXG5cdHNpZ21hMV82NCA9IGZ1bmN0aW9uICh4KVxuXHR7XG5cdFx0dmFyIHJvdHIxNCA9IHJvdHJfNjQoeCwgMTQpLCByb3RyMTggPSByb3RyXzY0KHgsIDE4KSxcblx0XHRcdHJvdHI0MSA9IHJvdHJfNjQoeCwgNDEpO1xuXG5cdFx0cmV0dXJuIG5ldyBJbnRfNjQoXG5cdFx0XHRcdHJvdHIxNC5oaWdoT3JkZXIgXiByb3RyMTguaGlnaE9yZGVyIF4gcm90cjQxLmhpZ2hPcmRlcixcblx0XHRcdFx0cm90cjE0Lmxvd09yZGVyIF4gcm90cjE4Lmxvd09yZGVyIF4gcm90cjQxLmxvd09yZGVyKTtcblx0fSxcblxuXHQvKlxuXHQgKiBUaGUgMzItYml0IGltcGxlbWVudGF0aW9uIG9mIHRoZSBOSVNUIHNwZWNpZmllZCBHYW1tYTAgZnVuY3Rpb25cblx0ICpcblx0ICogQHByaXZhdGVcblx0ICogQHBhcmFtIHtOdW1iZXJ9IHggVGhlIDMyLWJpdCBpbnRlZ2VyIGFyZ3VtZW50XG5cdCAqIEByZXR1cm4gVGhlIE5JU1Qgc3BlY2lmaWVkIG91dHB1dCBvZiB0aGUgZnVuY3Rpb25cblx0ICovXG5cdGdhbW1hMF8zMiA9IGZ1bmN0aW9uICh4KVxuXHR7XG5cdFx0cmV0dXJuIHJvdHJfMzIoeCwgNykgXiByb3RyXzMyKHgsIDE4KSBeIHNocl8zMih4LCAzKTtcblx0fSxcblxuXHQvKlxuXHQgKiBUaGUgNjQtYml0IGltcGxlbWVudGF0aW9uIG9mIHRoZSBOSVNUIHNwZWNpZmllZCBHYW1tYTAgZnVuY3Rpb25cblx0ICpcblx0ICogQHByaXZhdGVcblx0ICogQHBhcmFtIHtJbnRfNjR9IHggVGhlIDY0LWJpdCBpbnRlZ2VyIGFyZ3VtZW50XG5cdCAqIEByZXR1cm4gVGhlIE5JU1Qgc3BlY2lmaWVkIG91dHB1dCBvZiB0aGUgZnVuY3Rpb25cblx0ICovXG5cdGdhbW1hMF82NCA9IGZ1bmN0aW9uICh4KVxuXHR7XG5cdFx0dmFyIHJvdHIxID0gcm90cl82NCh4LCAxKSwgcm90cjggPSByb3RyXzY0KHgsIDgpLCBzaHI3ID0gc2hyXzY0KHgsIDcpO1xuXG5cdFx0cmV0dXJuIG5ldyBJbnRfNjQoXG5cdFx0XHRcdHJvdHIxLmhpZ2hPcmRlciBeIHJvdHI4LmhpZ2hPcmRlciBeIHNocjcuaGlnaE9yZGVyLFxuXHRcdFx0XHRyb3RyMS5sb3dPcmRlciBeIHJvdHI4Lmxvd09yZGVyIF4gc2hyNy5sb3dPcmRlclxuXHRcdFx0KTtcblx0fSxcblxuXHQvKlxuXHQgKiBUaGUgMzItYml0IGltcGxlbWVudGF0aW9uIG9mIHRoZSBOSVNUIHNwZWNpZmllZCBHYW1tYTEgZnVuY3Rpb25cblx0ICpcblx0ICogQHByaXZhdGVcblx0ICogQHBhcmFtIHtOdW1iZXJ9IHggVGhlIDMyLWJpdCBpbnRlZ2VyIGFyZ3VtZW50XG5cdCAqIEByZXR1cm4gVGhlIE5JU1Qgc3BlY2lmaWVkIG91dHB1dCBvZiB0aGUgZnVuY3Rpb25cblx0ICovXG5cdGdhbW1hMV8zMiA9IGZ1bmN0aW9uICh4KVxuXHR7XG5cdFx0cmV0dXJuIHJvdHJfMzIoeCwgMTcpIF4gcm90cl8zMih4LCAxOSkgXiBzaHJfMzIoeCwgMTApO1xuXHR9LFxuXG5cdC8qXG5cdCAqIFRoZSA2NC1iaXQgaW1wbGVtZW50YXRpb24gb2YgdGhlIE5JU1Qgc3BlY2lmaWVkIEdhbW1hMSBmdW5jdGlvblxuXHQgKlxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge0ludF82NH0geCBUaGUgNjQtYml0IGludGVnZXIgYXJndW1lbnRcblx0ICogQHJldHVybiBUaGUgTklTVCBzcGVjaWZpZWQgb3V0cHV0IG9mIHRoZSBmdW5jdGlvblxuXHQgKi9cblx0Z2FtbWExXzY0ID0gZnVuY3Rpb24gKHgpXG5cdHtcblx0XHR2YXIgcm90cjE5ID0gcm90cl82NCh4LCAxOSksIHJvdHI2MSA9IHJvdHJfNjQoeCwgNjEpLFxuXHRcdFx0c2hyNiA9IHNocl82NCh4LCA2KTtcblxuXHRcdHJldHVybiBuZXcgSW50XzY0KFxuXHRcdFx0XHRyb3RyMTkuaGlnaE9yZGVyIF4gcm90cjYxLmhpZ2hPcmRlciBeIHNocjYuaGlnaE9yZGVyLFxuXHRcdFx0XHRyb3RyMTkubG93T3JkZXIgXiByb3RyNjEubG93T3JkZXIgXiBzaHI2Lmxvd09yZGVyXG5cdFx0XHQpO1xuXHR9LFxuXG5cdC8qXG5cdCAqIEFkZCB0d28gMzItYml0IGludGVnZXJzLCB3cmFwcGluZyBhdCAyXjMyLiBUaGlzIHVzZXMgMTYtYml0IG9wZXJhdGlvbnNcblx0ICogaW50ZXJuYWxseSB0byB3b3JrIGFyb3VuZCBidWdzIGluIHNvbWUgSlMgaW50ZXJwcmV0ZXJzLlxuXHQgKlxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge051bWJlcn0geCBUaGUgZmlyc3QgMzItYml0IGludGVnZXIgYXJndW1lbnQgdG8gYmUgYWRkZWRcblx0ICogQHBhcmFtIHtOdW1iZXJ9IHkgVGhlIHNlY29uZCAzMi1iaXQgaW50ZWdlciBhcmd1bWVudCB0byBiZSBhZGRlZFxuXHQgKiBAcmV0dXJuIFRoZSBzdW0gb2YgeCArIHlcblx0ICovXG5cdHNhZmVBZGRfMzJfMiA9IGZ1bmN0aW9uICh4LCB5KVxuXHR7XG5cdFx0dmFyIGxzdyA9ICh4ICYgMHhGRkZGKSArICh5ICYgMHhGRkZGKSxcblx0XHRcdG1zdyA9ICh4ID4+PiAxNikgKyAoeSA+Pj4gMTYpICsgKGxzdyA+Pj4gMTYpO1xuXG5cdFx0cmV0dXJuICgobXN3ICYgMHhGRkZGKSA8PCAxNikgfCAobHN3ICYgMHhGRkZGKTtcblx0fSxcblxuXHQvKlxuXHQgKiBBZGQgZm91ciAzMi1iaXQgaW50ZWdlcnMsIHdyYXBwaW5nIGF0IDJeMzIuIFRoaXMgdXNlcyAxNi1iaXQgb3BlcmF0aW9uc1xuXHQgKiBpbnRlcm5hbGx5IHRvIHdvcmsgYXJvdW5kIGJ1Z3MgaW4gc29tZSBKUyBpbnRlcnByZXRlcnMuXG5cdCAqXG5cdCAqIEBwcml2YXRlXG5cdCAqIEBwYXJhbSB7TnVtYmVyfSBhIFRoZSBmaXJzdCAzMi1iaXQgaW50ZWdlciBhcmd1bWVudCB0byBiZSBhZGRlZFxuXHQgKiBAcGFyYW0ge051bWJlcn0gYiBUaGUgc2Vjb25kIDMyLWJpdCBpbnRlZ2VyIGFyZ3VtZW50IHRvIGJlIGFkZGVkXG5cdCAqIEBwYXJhbSB7TnVtYmVyfSBjIFRoZSB0aGlyZCAzMi1iaXQgaW50ZWdlciBhcmd1bWVudCB0byBiZSBhZGRlZFxuXHQgKiBAcGFyYW0ge051bWJlcn0gZCBUaGUgZm91cnRoIDMyLWJpdCBpbnRlZ2VyIGFyZ3VtZW50IHRvIGJlIGFkZGVkXG5cdCAqIEByZXR1cm4gVGhlIHN1bSBvZiBhICsgYiArIGMgKyBkXG5cdCAqL1xuXHRzYWZlQWRkXzMyXzQgPSBmdW5jdGlvbiAoYSwgYiwgYywgZClcblx0e1xuXHRcdHZhciBsc3cgPSAoYSAmIDB4RkZGRikgKyAoYiAmIDB4RkZGRikgKyAoYyAmIDB4RkZGRikgKyAoZCAmIDB4RkZGRiksXG5cdFx0XHRtc3cgPSAoYSA+Pj4gMTYpICsgKGIgPj4+IDE2KSArIChjID4+PiAxNikgKyAoZCA+Pj4gMTYpICtcblx0XHRcdFx0KGxzdyA+Pj4gMTYpO1xuXG5cdFx0cmV0dXJuICgobXN3ICYgMHhGRkZGKSA8PCAxNikgfCAobHN3ICYgMHhGRkZGKTtcblx0fSxcblxuXHQvKlxuXHQgKiBBZGQgZml2ZSAzMi1iaXQgaW50ZWdlcnMsIHdyYXBwaW5nIGF0IDJeMzIuIFRoaXMgdXNlcyAxNi1iaXQgb3BlcmF0aW9uc1xuXHQgKiBpbnRlcm5hbGx5IHRvIHdvcmsgYXJvdW5kIGJ1Z3MgaW4gc29tZSBKUyBpbnRlcnByZXRlcnMuXG5cdCAqXG5cdCAqIEBwcml2YXRlXG5cdCAqIEBwYXJhbSB7TnVtYmVyfSBhIFRoZSBmaXJzdCAzMi1iaXQgaW50ZWdlciBhcmd1bWVudCB0byBiZSBhZGRlZFxuXHQgKiBAcGFyYW0ge051bWJlcn0gYiBUaGUgc2Vjb25kIDMyLWJpdCBpbnRlZ2VyIGFyZ3VtZW50IHRvIGJlIGFkZGVkXG5cdCAqIEBwYXJhbSB7TnVtYmVyfSBjIFRoZSB0aGlyZCAzMi1iaXQgaW50ZWdlciBhcmd1bWVudCB0byBiZSBhZGRlZFxuXHQgKiBAcGFyYW0ge051bWJlcn0gZCBUaGUgZm91cnRoIDMyLWJpdCBpbnRlZ2VyIGFyZ3VtZW50IHRvIGJlIGFkZGVkXG5cdCAqIEBwYXJhbSB7TnVtYmVyfSBlIFRoZSBmaWZ0aCAzMi1iaXQgaW50ZWdlciBhcmd1bWVudCB0byBiZSBhZGRlZFxuXHQgKiBAcmV0dXJuIFRoZSBzdW0gb2YgYSArIGIgKyBjICsgZCArIGVcblx0ICovXG5cdHNhZmVBZGRfMzJfNSA9IGZ1bmN0aW9uIChhLCBiLCBjLCBkLCBlKVxuXHR7XG5cdFx0dmFyIGxzdyA9IChhICYgMHhGRkZGKSArIChiICYgMHhGRkZGKSArIChjICYgMHhGRkZGKSArIChkICYgMHhGRkZGKSArXG5cdFx0XHRcdChlICYgMHhGRkZGKSxcblx0XHRcdG1zdyA9IChhID4+PiAxNikgKyAoYiA+Pj4gMTYpICsgKGMgPj4+IDE2KSArIChkID4+PiAxNikgK1xuXHRcdFx0XHQoZSA+Pj4gMTYpICsgKGxzdyA+Pj4gMTYpO1xuXG5cdFx0cmV0dXJuICgobXN3ICYgMHhGRkZGKSA8PCAxNikgfCAobHN3ICYgMHhGRkZGKTtcblx0fSxcblxuXHQvKlxuXHQgKiBBZGQgdHdvIDY0LWJpdCBpbnRlZ2Vycywgd3JhcHBpbmcgYXQgMl42NC4gVGhpcyB1c2VzIDE2LWJpdCBvcGVyYXRpb25zXG5cdCAqIGludGVybmFsbHkgdG8gd29yayBhcm91bmQgYnVncyBpbiBzb21lIEpTIGludGVycHJldGVycy5cblx0ICpcblx0ICogQHByaXZhdGVcblx0ICogQHBhcmFtIHtJbnRfNjR9IHggVGhlIGZpcnN0IDY0LWJpdCBpbnRlZ2VyIGFyZ3VtZW50IHRvIGJlIGFkZGVkXG5cdCAqIEBwYXJhbSB7SW50XzY0fSB5IFRoZSBzZWNvbmQgNjQtYml0IGludGVnZXIgYXJndW1lbnQgdG8gYmUgYWRkZWRcblx0ICogQHJldHVybiBUaGUgc3VtIG9mIHggKyB5XG5cdCAqL1xuXHRzYWZlQWRkXzY0XzIgPSBmdW5jdGlvbiAoeCwgeSlcblx0e1xuXHRcdHZhciBsc3csIG1zdywgbG93T3JkZXIsIGhpZ2hPcmRlcjtcblxuXHRcdGxzdyA9ICh4Lmxvd09yZGVyICYgMHhGRkZGKSArICh5Lmxvd09yZGVyICYgMHhGRkZGKTtcblx0XHRtc3cgPSAoeC5sb3dPcmRlciA+Pj4gMTYpICsgKHkubG93T3JkZXIgPj4+IDE2KSArIChsc3cgPj4+IDE2KTtcblx0XHRsb3dPcmRlciA9ICgobXN3ICYgMHhGRkZGKSA8PCAxNikgfCAobHN3ICYgMHhGRkZGKTtcblxuXHRcdGxzdyA9ICh4LmhpZ2hPcmRlciAmIDB4RkZGRikgKyAoeS5oaWdoT3JkZXIgJiAweEZGRkYpICsgKG1zdyA+Pj4gMTYpO1xuXHRcdG1zdyA9ICh4LmhpZ2hPcmRlciA+Pj4gMTYpICsgKHkuaGlnaE9yZGVyID4+PiAxNikgKyAobHN3ID4+PiAxNik7XG5cdFx0aGlnaE9yZGVyID0gKChtc3cgJiAweEZGRkYpIDw8IDE2KSB8IChsc3cgJiAweEZGRkYpO1xuXG5cdFx0cmV0dXJuIG5ldyBJbnRfNjQoaGlnaE9yZGVyLCBsb3dPcmRlcik7XG5cdH0sXG5cblx0Lypcblx0ICogQWRkIGZvdXIgNjQtYml0IGludGVnZXJzLCB3cmFwcGluZyBhdCAyXjY0LiBUaGlzIHVzZXMgMTYtYml0IG9wZXJhdGlvbnNcblx0ICogaW50ZXJuYWxseSB0byB3b3JrIGFyb3VuZCBidWdzIGluIHNvbWUgSlMgaW50ZXJwcmV0ZXJzLlxuXHQgKlxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge0ludF82NH0gYSBUaGUgZmlyc3QgNjQtYml0IGludGVnZXIgYXJndW1lbnQgdG8gYmUgYWRkZWRcblx0ICogQHBhcmFtIHtJbnRfNjR9IGIgVGhlIHNlY29uZCA2NC1iaXQgaW50ZWdlciBhcmd1bWVudCB0byBiZSBhZGRlZFxuXHQgKiBAcGFyYW0ge0ludF82NH0gYyBUaGUgdGhpcmQgNjQtYml0IGludGVnZXIgYXJndW1lbnQgdG8gYmUgYWRkZWRcblx0ICogQHBhcmFtIHtJbnRfNjR9IGQgVGhlIGZvdXRoIDY0LWJpdCBpbnRlZ2VyIGFyZ3VtZW50IHRvIGJlIGFkZGVkXG5cdCAqIEByZXR1cm4gVGhlIHN1bSBvZiBhICsgYiArIGMgKyBkXG5cdCAqL1xuXHRzYWZlQWRkXzY0XzQgPSBmdW5jdGlvbiAoYSwgYiwgYywgZClcblx0e1xuXHRcdHZhciBsc3csIG1zdywgbG93T3JkZXIsIGhpZ2hPcmRlcjtcblxuXHRcdGxzdyA9IChhLmxvd09yZGVyICYgMHhGRkZGKSArIChiLmxvd09yZGVyICYgMHhGRkZGKSArXG5cdFx0XHQoYy5sb3dPcmRlciAmIDB4RkZGRikgKyAoZC5sb3dPcmRlciAmIDB4RkZGRik7XG5cdFx0bXN3ID0gKGEubG93T3JkZXIgPj4+IDE2KSArIChiLmxvd09yZGVyID4+PiAxNikgK1xuXHRcdFx0KGMubG93T3JkZXIgPj4+IDE2KSArIChkLmxvd09yZGVyID4+PiAxNikgKyAobHN3ID4+PiAxNik7XG5cdFx0bG93T3JkZXIgPSAoKG1zdyAmIDB4RkZGRikgPDwgMTYpIHwgKGxzdyAmIDB4RkZGRik7XG5cblx0XHRsc3cgPSAoYS5oaWdoT3JkZXIgJiAweEZGRkYpICsgKGIuaGlnaE9yZGVyICYgMHhGRkZGKSArXG5cdFx0XHQoYy5oaWdoT3JkZXIgJiAweEZGRkYpICsgKGQuaGlnaE9yZGVyICYgMHhGRkZGKSArIChtc3cgPj4+IDE2KTtcblx0XHRtc3cgPSAoYS5oaWdoT3JkZXIgPj4+IDE2KSArIChiLmhpZ2hPcmRlciA+Pj4gMTYpICtcblx0XHRcdChjLmhpZ2hPcmRlciA+Pj4gMTYpICsgKGQuaGlnaE9yZGVyID4+PiAxNikgKyAobHN3ID4+PiAxNik7XG5cdFx0aGlnaE9yZGVyID0gKChtc3cgJiAweEZGRkYpIDw8IDE2KSB8IChsc3cgJiAweEZGRkYpO1xuXG5cdFx0cmV0dXJuIG5ldyBJbnRfNjQoaGlnaE9yZGVyLCBsb3dPcmRlcik7XG5cdH0sXG5cblx0Lypcblx0ICogQWRkIGZpdmUgNjQtYml0IGludGVnZXJzLCB3cmFwcGluZyBhdCAyXjY0LiBUaGlzIHVzZXMgMTYtYml0IG9wZXJhdGlvbnNcblx0ICogaW50ZXJuYWxseSB0byB3b3JrIGFyb3VuZCBidWdzIGluIHNvbWUgSlMgaW50ZXJwcmV0ZXJzLlxuXHQgKlxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge0ludF82NH0gYSBUaGUgZmlyc3QgNjQtYml0IGludGVnZXIgYXJndW1lbnQgdG8gYmUgYWRkZWRcblx0ICogQHBhcmFtIHtJbnRfNjR9IGIgVGhlIHNlY29uZCA2NC1iaXQgaW50ZWdlciBhcmd1bWVudCB0byBiZSBhZGRlZFxuXHQgKiBAcGFyYW0ge0ludF82NH0gYyBUaGUgdGhpcmQgNjQtYml0IGludGVnZXIgYXJndW1lbnQgdG8gYmUgYWRkZWRcblx0ICogQHBhcmFtIHtJbnRfNjR9IGQgVGhlIGZvdXRoIDY0LWJpdCBpbnRlZ2VyIGFyZ3VtZW50IHRvIGJlIGFkZGVkXG5cdCAqIEBwYXJhbSB7SW50XzY0fSBlIFRoZSBmb3V0aCA2NC1iaXQgaW50ZWdlciBhcmd1bWVudCB0byBiZSBhZGRlZFxuXHQgKiBAcmV0dXJuIFRoZSBzdW0gb2YgYSArIGIgKyBjICsgZCArIGVcblx0ICovXG5cdHNhZmVBZGRfNjRfNSA9IGZ1bmN0aW9uIChhLCBiLCBjLCBkLCBlKVxuXHR7XG5cdFx0dmFyIGxzdywgbXN3LCBsb3dPcmRlciwgaGlnaE9yZGVyO1xuXG5cdFx0bHN3ID0gKGEubG93T3JkZXIgJiAweEZGRkYpICsgKGIubG93T3JkZXIgJiAweEZGRkYpICtcblx0XHRcdChjLmxvd09yZGVyICYgMHhGRkZGKSArIChkLmxvd09yZGVyICYgMHhGRkZGKSArXG5cdFx0XHQoZS5sb3dPcmRlciAmIDB4RkZGRik7XG5cdFx0bXN3ID0gKGEubG93T3JkZXIgPj4+IDE2KSArIChiLmxvd09yZGVyID4+PiAxNikgK1xuXHRcdFx0KGMubG93T3JkZXIgPj4+IDE2KSArIChkLmxvd09yZGVyID4+PiAxNikgKyAoZS5sb3dPcmRlciA+Pj4gMTYpICtcblx0XHRcdChsc3cgPj4+IDE2KTtcblx0XHRsb3dPcmRlciA9ICgobXN3ICYgMHhGRkZGKSA8PCAxNikgfCAobHN3ICYgMHhGRkZGKTtcblxuXHRcdGxzdyA9IChhLmhpZ2hPcmRlciAmIDB4RkZGRikgKyAoYi5oaWdoT3JkZXIgJiAweEZGRkYpICtcblx0XHRcdChjLmhpZ2hPcmRlciAmIDB4RkZGRikgKyAoZC5oaWdoT3JkZXIgJiAweEZGRkYpICtcblx0XHRcdChlLmhpZ2hPcmRlciAmIDB4RkZGRikgKyAobXN3ID4+PiAxNik7XG5cdFx0bXN3ID0gKGEuaGlnaE9yZGVyID4+PiAxNikgKyAoYi5oaWdoT3JkZXIgPj4+IDE2KSArXG5cdFx0XHQoYy5oaWdoT3JkZXIgPj4+IDE2KSArIChkLmhpZ2hPcmRlciA+Pj4gMTYpICtcblx0XHRcdChlLmhpZ2hPcmRlciA+Pj4gMTYpICsgKGxzdyA+Pj4gMTYpO1xuXHRcdGhpZ2hPcmRlciA9ICgobXN3ICYgMHhGRkZGKSA8PCAxNikgfCAobHN3ICYgMHhGRkZGKTtcblxuXHRcdHJldHVybiBuZXcgSW50XzY0KGhpZ2hPcmRlciwgbG93T3JkZXIpO1xuXHR9LFxuXG5cdC8qXG5cdCAqIENhbGN1bGF0ZXMgdGhlIFNIQS0xIGhhc2ggb2YgdGhlIHN0cmluZyBzZXQgYXQgaW5zdGFudGlhdGlvblxuXHQgKlxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge0FycmF5fSBtZXNzYWdlIFRoZSBiaW5hcnkgYXJyYXkgcmVwcmVzZW50YXRpb24gb2YgdGhlIHN0cmluZyB0b1xuXHQgKlx0IGhhc2hcblx0ICogQHBhcmFtIHtOdW1iZXJ9IG1lc3NhZ2VMZW4gVGhlIG51bWJlciBvZiBiaXRzIGluIHRoZSBtZXNzYWdlXG5cdCAqIEByZXR1cm4gVGhlIGFycmF5IG9mIGludGVnZXJzIHJlcHJlc2VudGluZyB0aGUgU0hBLTEgaGFzaCBvZiBtZXNzYWdlXG5cdCAqL1xuXHRjb3JlU0hBMSA9IGZ1bmN0aW9uIChtZXNzYWdlLCBtZXNzYWdlTGVuKVxuXHR7XG5cdFx0dmFyIFcgPSBbXSwgYSwgYiwgYywgZCwgZSwgVCwgY2ggPSBjaF8zMiwgcGFyaXR5ID0gcGFyaXR5XzMyLFxuXHRcdFx0bWFqID0gbWFqXzMyLCByb3RsID0gcm90bF8zMiwgc2FmZUFkZF8yID0gc2FmZUFkZF8zMl8yLCBpLCB0LFxuXHRcdFx0c2FmZUFkZF81ID0gc2FmZUFkZF8zMl81LCBhcHBlbmRlZE1lc3NhZ2VMZW5ndGgsXG5cdFx0XHRIID0gW1xuXHRcdFx0XHQweDY3NDUyMzAxLCAweGVmY2RhYjg5LCAweDk4YmFkY2ZlLCAweDEwMzI1NDc2LCAweGMzZDJlMWYwXG5cdFx0XHRdLFxuXHRcdFx0SyA9IFtcblx0XHRcdFx0MHg1YTgyNzk5OSwgMHg1YTgyNzk5OSwgMHg1YTgyNzk5OSwgMHg1YTgyNzk5OSxcblx0XHRcdFx0MHg1YTgyNzk5OSwgMHg1YTgyNzk5OSwgMHg1YTgyNzk5OSwgMHg1YTgyNzk5OSxcblx0XHRcdFx0MHg1YTgyNzk5OSwgMHg1YTgyNzk5OSwgMHg1YTgyNzk5OSwgMHg1YTgyNzk5OSxcblx0XHRcdFx0MHg1YTgyNzk5OSwgMHg1YTgyNzk5OSwgMHg1YTgyNzk5OSwgMHg1YTgyNzk5OSxcblx0XHRcdFx0MHg1YTgyNzk5OSwgMHg1YTgyNzk5OSwgMHg1YTgyNzk5OSwgMHg1YTgyNzk5OSxcblx0XHRcdFx0MHg2ZWQ5ZWJhMSwgMHg2ZWQ5ZWJhMSwgMHg2ZWQ5ZWJhMSwgMHg2ZWQ5ZWJhMSxcblx0XHRcdFx0MHg2ZWQ5ZWJhMSwgMHg2ZWQ5ZWJhMSwgMHg2ZWQ5ZWJhMSwgMHg2ZWQ5ZWJhMSxcblx0XHRcdFx0MHg2ZWQ5ZWJhMSwgMHg2ZWQ5ZWJhMSwgMHg2ZWQ5ZWJhMSwgMHg2ZWQ5ZWJhMSxcblx0XHRcdFx0MHg2ZWQ5ZWJhMSwgMHg2ZWQ5ZWJhMSwgMHg2ZWQ5ZWJhMSwgMHg2ZWQ5ZWJhMSxcblx0XHRcdFx0MHg2ZWQ5ZWJhMSwgMHg2ZWQ5ZWJhMSwgMHg2ZWQ5ZWJhMSwgMHg2ZWQ5ZWJhMSxcblx0XHRcdFx0MHg4ZjFiYmNkYywgMHg4ZjFiYmNkYywgMHg4ZjFiYmNkYywgMHg4ZjFiYmNkYyxcblx0XHRcdFx0MHg4ZjFiYmNkYywgMHg4ZjFiYmNkYywgMHg4ZjFiYmNkYywgMHg4ZjFiYmNkYyxcblx0XHRcdFx0MHg4ZjFiYmNkYywgMHg4ZjFiYmNkYywgMHg4ZjFiYmNkYywgMHg4ZjFiYmNkYyxcblx0XHRcdFx0MHg4ZjFiYmNkYywgMHg4ZjFiYmNkYywgMHg4ZjFiYmNkYywgMHg4ZjFiYmNkYyxcblx0XHRcdFx0MHg4ZjFiYmNkYywgMHg4ZjFiYmNkYywgMHg4ZjFiYmNkYywgMHg4ZjFiYmNkYyxcblx0XHRcdFx0MHhjYTYyYzFkNiwgMHhjYTYyYzFkNiwgMHhjYTYyYzFkNiwgMHhjYTYyYzFkNixcblx0XHRcdFx0MHhjYTYyYzFkNiwgMHhjYTYyYzFkNiwgMHhjYTYyYzFkNiwgMHhjYTYyYzFkNixcblx0XHRcdFx0MHhjYTYyYzFkNiwgMHhjYTYyYzFkNiwgMHhjYTYyYzFkNiwgMHhjYTYyYzFkNixcblx0XHRcdFx0MHhjYTYyYzFkNiwgMHhjYTYyYzFkNiwgMHhjYTYyYzFkNiwgMHhjYTYyYzFkNixcblx0XHRcdFx0MHhjYTYyYzFkNiwgMHhjYTYyYzFkNiwgMHhjYTYyYzFkNiwgMHhjYTYyYzFkNlxuXHRcdFx0XTtcblxuXHRcdC8qIEFwcGVuZCAnMScgYXQgdGhlIGVuZCBvZiB0aGUgYmluYXJ5IHN0cmluZyAqL1xuXHRcdG1lc3NhZ2VbbWVzc2FnZUxlbiA+PiA1XSB8PSAweDgwIDw8ICgyNCAtIChtZXNzYWdlTGVuICUgMzIpKTtcblx0XHQvKiBBcHBlbmQgbGVuZ3RoIG9mIGJpbmFyeSBzdHJpbmcgaW4gdGhlIHBvc2l0aW9uIHN1Y2ggdGhhdCB0aGUgbmV3XG5cdFx0bGVuZ3RoIGlzIGEgbXVsdGlwbGUgb2YgNTEyLiAgTG9naWMgZG9lcyBub3Qgd29yayBmb3IgZXZlbiBtdWx0aXBsZXNcblx0XHRvZiA1MTIgYnV0IHRoZXJlIGNhbiBuZXZlciBiZSBldmVuIG11bHRpcGxlcyBvZiA1MTIgKi9cblx0XHRtZXNzYWdlWygoKG1lc3NhZ2VMZW4gKyA2NSkgPj4gOSkgPDwgNCkgKyAxNV0gPSBtZXNzYWdlTGVuO1xuXG5cdFx0YXBwZW5kZWRNZXNzYWdlTGVuZ3RoID0gbWVzc2FnZS5sZW5ndGg7XG5cblx0XHRmb3IgKGkgPSAwOyBpIDwgYXBwZW5kZWRNZXNzYWdlTGVuZ3RoOyBpICs9IDE2KVxuXHRcdHtcblx0XHRcdGEgPSBIWzBdO1xuXHRcdFx0YiA9IEhbMV07XG5cdFx0XHRjID0gSFsyXTtcblx0XHRcdGQgPSBIWzNdO1xuXHRcdFx0ZSA9IEhbNF07XG5cblx0XHRcdGZvciAodCA9IDA7IHQgPCA4MDsgdCArPSAxKVxuXHRcdFx0e1xuXHRcdFx0XHRpZiAodCA8IDE2KVxuXHRcdFx0XHR7XG5cdFx0XHRcdFx0V1t0XSA9IG1lc3NhZ2VbdCArIGldO1xuXHRcdFx0XHR9XG5cdFx0XHRcdGVsc2Vcblx0XHRcdFx0e1xuXHRcdFx0XHRcdFdbdF0gPSByb3RsKFdbdCAtIDNdIF4gV1t0IC0gOF0gXiBXW3QgLSAxNF0gXiBXW3QgLSAxNl0sIDEpO1xuXHRcdFx0XHR9XG5cblx0XHRcdFx0aWYgKHQgPCAyMClcblx0XHRcdFx0e1xuXHRcdFx0XHRcdFQgPSBzYWZlQWRkXzUocm90bChhLCA1KSwgY2goYiwgYywgZCksIGUsIEtbdF0sIFdbdF0pO1xuXHRcdFx0XHR9XG5cdFx0XHRcdGVsc2UgaWYgKHQgPCA0MClcblx0XHRcdFx0e1xuXHRcdFx0XHRcdFQgPSBzYWZlQWRkXzUocm90bChhLCA1KSwgcGFyaXR5KGIsIGMsIGQpLCBlLCBLW3RdLCBXW3RdKTtcblx0XHRcdFx0fVxuXHRcdFx0XHRlbHNlIGlmICh0IDwgNjApXG5cdFx0XHRcdHtcblx0XHRcdFx0XHRUID0gc2FmZUFkZF81KHJvdGwoYSwgNSksIG1haihiLCBjLCBkKSwgZSwgS1t0XSwgV1t0XSk7XG5cdFx0XHRcdH0gZWxzZSB7XG5cdFx0XHRcdFx0VCA9IHNhZmVBZGRfNShyb3RsKGEsIDUpLCBwYXJpdHkoYiwgYywgZCksIGUsIEtbdF0sIFdbdF0pO1xuXHRcdFx0XHR9XG5cblx0XHRcdFx0ZSA9IGQ7XG5cdFx0XHRcdGQgPSBjO1xuXHRcdFx0XHRjID0gcm90bChiLCAzMCk7XG5cdFx0XHRcdGIgPSBhO1xuXHRcdFx0XHRhID0gVDtcblx0XHRcdH1cblxuXHRcdFx0SFswXSA9IHNhZmVBZGRfMihhLCBIWzBdKTtcblx0XHRcdEhbMV0gPSBzYWZlQWRkXzIoYiwgSFsxXSk7XG5cdFx0XHRIWzJdID0gc2FmZUFkZF8yKGMsIEhbMl0pO1xuXHRcdFx0SFszXSA9IHNhZmVBZGRfMihkLCBIWzNdKTtcblx0XHRcdEhbNF0gPSBzYWZlQWRkXzIoZSwgSFs0XSk7XG5cdFx0fVxuXG5cdFx0cmV0dXJuIEg7XG5cdH0sXG5cblx0Lypcblx0ICogQ2FsY3VsYXRlcyB0aGUgZGVzaXJlZCBTSEEtMiBoYXNoIG9mIHRoZSBzdHJpbmcgc2V0IGF0IGluc3RhbnRpYXRpb25cblx0ICpcblx0ICogQHByaXZhdGVcblx0ICogQHBhcmFtIHtBcnJheX0gVGhlIGJpbmFyeSBhcnJheSByZXByZXNlbnRhdGlvbiBvZiB0aGUgc3RyaW5nIHRvIGhhc2hcblx0ICogQHBhcmFtIHtOdW1iZXJ9IFRoZSBudW1iZXIgb2YgYml0cyBpbiBtZXNzYWdlXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSB2YXJpYW50IFRoZSBkZXNpcmVkIFNIQS0yIHZhcmlhbnRcblx0ICogQHJldHVybiBUaGUgYXJyYXkgb2YgaW50ZWdlcnMgcmVwcmVzZW50aW5nIHRoZSBTSEEtMiBoYXNoIG9mIG1lc3NhZ2Vcblx0ICovXG5cdGNvcmVTSEEyID0gZnVuY3Rpb24gKG1lc3NhZ2UsIG1lc3NhZ2VMZW4sIHZhcmlhbnQpXG5cdHtcblx0XHR2YXIgYSwgYiwgYywgZCwgZSwgZiwgZywgaCwgVDEsIFQyLCBILCBudW1Sb3VuZHMsIGxlbmd0aFBvc2l0aW9uLCBpLCB0LFxuXHRcdFx0YmluYXJ5U3RyaW5nSW5jLCBiaW5hcnlTdHJpbmdNdWx0LCBzYWZlQWRkXzIsIHNhZmVBZGRfNCwgc2FmZUFkZF81LFxuXHRcdFx0Z2FtbWEwLCBnYW1tYTEsIHNpZ21hMCwgc2lnbWExLCBjaCwgbWFqLCBJbnQsIEssIFcgPSBbXSxcblx0XHRcdGFwcGVuZGVkTWVzc2FnZUxlbmd0aDtcblxuXHRcdC8qIFNldCB1cCB0aGUgdmFyaW91cyBmdW5jdGlvbiBoYW5kbGVzIGFuZCB2YXJpYWJsZSBmb3IgdGhlIHNwZWNpZmljIFxuXHRcdCAqIHZhcmlhbnQgKi9cblx0XHRpZiAodmFyaWFudCA9PT0gXCJTSEEtMjI0XCIgfHwgdmFyaWFudCA9PT0gXCJTSEEtMjU2XCIpXG5cdFx0e1xuXHRcdFx0LyogMzItYml0IHZhcmlhbnQgKi9cblx0XHRcdG51bVJvdW5kcyA9IDY0O1xuXHRcdFx0bGVuZ3RoUG9zaXRpb24gPSAoKChtZXNzYWdlTGVuICsgNjUpID4+IDkpIDw8IDQpICsgMTU7XG5cdFx0XHRiaW5hcnlTdHJpbmdJbmMgPSAxNjtcblx0XHRcdGJpbmFyeVN0cmluZ011bHQgPSAxO1xuXHRcdFx0SW50ID0gTnVtYmVyO1xuXHRcdFx0c2FmZUFkZF8yID0gc2FmZUFkZF8zMl8yO1xuXHRcdFx0c2FmZUFkZF80ID0gc2FmZUFkZF8zMl80O1xuXHRcdFx0c2FmZUFkZF81ID0gc2FmZUFkZF8zMl81O1xuXHRcdFx0Z2FtbWEwID0gZ2FtbWEwXzMyO1xuXHRcdFx0Z2FtbWExID0gZ2FtbWExXzMyO1xuXHRcdFx0c2lnbWEwID0gc2lnbWEwXzMyO1xuXHRcdFx0c2lnbWExID0gc2lnbWExXzMyO1xuXHRcdFx0bWFqID0gbWFqXzMyO1xuXHRcdFx0Y2ggPSBjaF8zMjtcblx0XHRcdEsgPSBbXG5cdFx0XHRcdFx0MHg0MjhBMkY5OCwgMHg3MTM3NDQ5MSwgMHhCNUMwRkJDRiwgMHhFOUI1REJBNSxcblx0XHRcdFx0XHQweDM5NTZDMjVCLCAweDU5RjExMUYxLCAweDkyM0Y4MkE0LCAweEFCMUM1RUQ1LFxuXHRcdFx0XHRcdDB4RDgwN0FBOTgsIDB4MTI4MzVCMDEsIDB4MjQzMTg1QkUsIDB4NTUwQzdEQzMsXG5cdFx0XHRcdFx0MHg3MkJFNUQ3NCwgMHg4MERFQjFGRSwgMHg5QkRDMDZBNywgMHhDMTlCRjE3NCxcblx0XHRcdFx0XHQweEU0OUI2OUMxLCAweEVGQkU0Nzg2LCAweDBGQzE5REM2LCAweDI0MENBMUNDLFxuXHRcdFx0XHRcdDB4MkRFOTJDNkYsIDB4NEE3NDg0QUEsIDB4NUNCMEE5REMsIDB4NzZGOTg4REEsXG5cdFx0XHRcdFx0MHg5ODNFNTE1MiwgMHhBODMxQzY2RCwgMHhCMDAzMjdDOCwgMHhCRjU5N0ZDNyxcblx0XHRcdFx0XHQweEM2RTAwQkYzLCAweEQ1QTc5MTQ3LCAweDA2Q0E2MzUxLCAweDE0MjkyOTY3LFxuXHRcdFx0XHRcdDB4MjdCNzBBODUsIDB4MkUxQjIxMzgsIDB4NEQyQzZERkMsIDB4NTMzODBEMTMsXG5cdFx0XHRcdFx0MHg2NTBBNzM1NCwgMHg3NjZBMEFCQiwgMHg4MUMyQzkyRSwgMHg5MjcyMkM4NSxcblx0XHRcdFx0XHQweEEyQkZFOEExLCAweEE4MUE2NjRCLCAweEMyNEI4QjcwLCAweEM3NkM1MUEzLFxuXHRcdFx0XHRcdDB4RDE5MkU4MTksIDB4RDY5OTA2MjQsIDB4RjQwRTM1ODUsIDB4MTA2QUEwNzAsXG5cdFx0XHRcdFx0MHgxOUE0QzExNiwgMHgxRTM3NkMwOCwgMHgyNzQ4Nzc0QywgMHgzNEIwQkNCNSxcblx0XHRcdFx0XHQweDM5MUMwQ0IzLCAweDRFRDhBQTRBLCAweDVCOUNDQTRGLCAweDY4MkU2RkYzLFxuXHRcdFx0XHRcdDB4NzQ4RjgyRUUsIDB4NzhBNTYzNkYsIDB4ODRDODc4MTQsIDB4OENDNzAyMDgsXG5cdFx0XHRcdFx0MHg5MEJFRkZGQSwgMHhBNDUwNkNFQiwgMHhCRUY5QTNGNywgMHhDNjcxNzhGMlxuXHRcdFx0XHRdO1xuXG5cdFx0XHRpZiAodmFyaWFudCA9PT0gXCJTSEEtMjI0XCIpXG5cdFx0XHR7XG5cdFx0XHRcdEggPSBbXG5cdFx0XHRcdFx0XHQweGMxMDU5ZWQ4LCAweDM2N2NkNTA3LCAweDMwNzBkZDE3LCAweGY3MGU1OTM5LFxuXHRcdFx0XHRcdFx0MHhmZmMwMGIzMSwgMHg2ODU4MTUxMSwgMHg2NGY5OGZhNywgMHhiZWZhNGZhNFxuXHRcdFx0XHRcdF07XG5cdFx0XHR9XG5cdFx0XHRlbHNlXG5cdFx0XHR7XG5cdFx0XHRcdEggPSBbXG5cdFx0XHRcdFx0XHQweDZBMDlFNjY3LCAweEJCNjdBRTg1LCAweDNDNkVGMzcyLCAweEE1NEZGNTNBLFxuXHRcdFx0XHRcdFx0MHg1MTBFNTI3RiwgMHg5QjA1Njg4QywgMHgxRjgzRDlBQiwgMHg1QkUwQ0QxOVxuXHRcdFx0XHRcdF07XG5cdFx0XHR9XG5cdFx0fVxuXHRcdGVsc2UgaWYgKHZhcmlhbnQgPT09IFwiU0hBLTM4NFwiIHx8IHZhcmlhbnQgPT09IFwiU0hBLTUxMlwiKVxuXHRcdHtcblx0XHRcdC8qIDY0LWJpdCB2YXJpYW50ICovXG5cdFx0XHRudW1Sb3VuZHMgPSA4MDtcblx0XHRcdGxlbmd0aFBvc2l0aW9uID0gKCgobWVzc2FnZUxlbiArIDEyOCkgPj4gMTApIDw8IDUpICsgMzE7XG5cdFx0XHRiaW5hcnlTdHJpbmdJbmMgPSAzMjtcblx0XHRcdGJpbmFyeVN0cmluZ011bHQgPSAyO1xuXHRcdFx0SW50ID0gSW50XzY0O1xuXHRcdFx0c2FmZUFkZF8yID0gc2FmZUFkZF82NF8yO1xuXHRcdFx0c2FmZUFkZF80ID0gc2FmZUFkZF82NF80O1xuXHRcdFx0c2FmZUFkZF81ID0gc2FmZUFkZF82NF81O1xuXHRcdFx0Z2FtbWEwID0gZ2FtbWEwXzY0O1xuXHRcdFx0Z2FtbWExID0gZ2FtbWExXzY0O1xuXHRcdFx0c2lnbWEwID0gc2lnbWEwXzY0O1xuXHRcdFx0c2lnbWExID0gc2lnbWExXzY0O1xuXHRcdFx0bWFqID0gbWFqXzY0O1xuXHRcdFx0Y2ggPSBjaF82NDtcblxuXHRcdFx0SyA9IFtcblx0XHRcdFx0bmV3IEludCgweDQyOGEyZjk4LCAweGQ3MjhhZTIyKSwgbmV3IEludCgweDcxMzc0NDkxLCAweDIzZWY2NWNkKSxcblx0XHRcdFx0bmV3IEludCgweGI1YzBmYmNmLCAweGVjNGQzYjJmKSwgbmV3IEludCgweGU5YjVkYmE1LCAweDgxODlkYmJjKSxcblx0XHRcdFx0bmV3IEludCgweDM5NTZjMjViLCAweGYzNDhiNTM4KSwgbmV3IEludCgweDU5ZjExMWYxLCAweGI2MDVkMDE5KSxcblx0XHRcdFx0bmV3IEludCgweDkyM2Y4MmE0LCAweGFmMTk0ZjliKSwgbmV3IEludCgweGFiMWM1ZWQ1LCAweGRhNmQ4MTE4KSxcblx0XHRcdFx0bmV3IEludCgweGQ4MDdhYTk4LCAweGEzMDMwMjQyKSwgbmV3IEludCgweDEyODM1YjAxLCAweDQ1NzA2ZmJlKSxcblx0XHRcdFx0bmV3IEludCgweDI0MzE4NWJlLCAweDRlZTRiMjhjKSwgbmV3IEludCgweDU1MGM3ZGMzLCAweGQ1ZmZiNGUyKSxcblx0XHRcdFx0bmV3IEludCgweDcyYmU1ZDc0LCAweGYyN2I4OTZmKSwgbmV3IEludCgweDgwZGViMWZlLCAweDNiMTY5NmIxKSxcblx0XHRcdFx0bmV3IEludCgweDliZGMwNmE3LCAweDI1YzcxMjM1KSwgbmV3IEludCgweGMxOWJmMTc0LCAweGNmNjkyNjk0KSxcblx0XHRcdFx0bmV3IEludCgweGU0OWI2OWMxLCAweDllZjE0YWQyKSwgbmV3IEludCgweGVmYmU0Nzg2LCAweDM4NGYyNWUzKSxcblx0XHRcdFx0bmV3IEludCgweDBmYzE5ZGM2LCAweDhiOGNkNWI1KSwgbmV3IEludCgweDI0MGNhMWNjLCAweDc3YWM5YzY1KSxcblx0XHRcdFx0bmV3IEludCgweDJkZTkyYzZmLCAweDU5MmIwMjc1KSwgbmV3IEludCgweDRhNzQ4NGFhLCAweDZlYTZlNDgzKSxcblx0XHRcdFx0bmV3IEludCgweDVjYjBhOWRjLCAweGJkNDFmYmQ0KSwgbmV3IEludCgweDc2Zjk4OGRhLCAweDgzMTE1M2I1KSxcblx0XHRcdFx0bmV3IEludCgweDk4M2U1MTUyLCAweGVlNjZkZmFiKSwgbmV3IEludCgweGE4MzFjNjZkLCAweDJkYjQzMjEwKSxcblx0XHRcdFx0bmV3IEludCgweGIwMDMyN2M4LCAweDk4ZmIyMTNmKSwgbmV3IEludCgweGJmNTk3ZmM3LCAweGJlZWYwZWU0KSxcblx0XHRcdFx0bmV3IEludCgweGM2ZTAwYmYzLCAweDNkYTg4ZmMyKSwgbmV3IEludCgweGQ1YTc5MTQ3LCAweDkzMGFhNzI1KSxcblx0XHRcdFx0bmV3IEludCgweDA2Y2E2MzUxLCAweGUwMDM4MjZmKSwgbmV3IEludCgweDE0MjkyOTY3LCAweDBhMGU2ZTcwKSxcblx0XHRcdFx0bmV3IEludCgweDI3YjcwYTg1LCAweDQ2ZDIyZmZjKSwgbmV3IEludCgweDJlMWIyMTM4LCAweDVjMjZjOTI2KSxcblx0XHRcdFx0bmV3IEludCgweDRkMmM2ZGZjLCAweDVhYzQyYWVkKSwgbmV3IEludCgweDUzMzgwZDEzLCAweDlkOTViM2RmKSxcblx0XHRcdFx0bmV3IEludCgweDY1MGE3MzU0LCAweDhiYWY2M2RlKSwgbmV3IEludCgweDc2NmEwYWJiLCAweDNjNzdiMmE4KSxcblx0XHRcdFx0bmV3IEludCgweDgxYzJjOTJlLCAweDQ3ZWRhZWU2KSwgbmV3IEludCgweDkyNzIyYzg1LCAweDE0ODIzNTNiKSxcblx0XHRcdFx0bmV3IEludCgweGEyYmZlOGExLCAweDRjZjEwMzY0KSwgbmV3IEludCgweGE4MWE2NjRiLCAweGJjNDIzMDAxKSxcblx0XHRcdFx0bmV3IEludCgweGMyNGI4YjcwLCAweGQwZjg5NzkxKSwgbmV3IEludCgweGM3NmM1MWEzLCAweDA2NTRiZTMwKSxcblx0XHRcdFx0bmV3IEludCgweGQxOTJlODE5LCAweGQ2ZWY1MjE4KSwgbmV3IEludCgweGQ2OTkwNjI0LCAweDU1NjVhOTEwKSxcblx0XHRcdFx0bmV3IEludCgweGY0MGUzNTg1LCAweDU3NzEyMDJhKSwgbmV3IEludCgweDEwNmFhMDcwLCAweDMyYmJkMWI4KSxcblx0XHRcdFx0bmV3IEludCgweDE5YTRjMTE2LCAweGI4ZDJkMGM4KSwgbmV3IEludCgweDFlMzc2YzA4LCAweDUxNDFhYjUzKSxcblx0XHRcdFx0bmV3IEludCgweDI3NDg3NzRjLCAweGRmOGVlYjk5KSwgbmV3IEludCgweDM0YjBiY2I1LCAweGUxOWI0OGE4KSxcblx0XHRcdFx0bmV3IEludCgweDM5MWMwY2IzLCAweGM1Yzk1YTYzKSwgbmV3IEludCgweDRlZDhhYTRhLCAweGUzNDE4YWNiKSxcblx0XHRcdFx0bmV3IEludCgweDViOWNjYTRmLCAweDc3NjNlMzczKSwgbmV3IEludCgweDY4MmU2ZmYzLCAweGQ2YjJiOGEzKSxcblx0XHRcdFx0bmV3IEludCgweDc0OGY4MmVlLCAweDVkZWZiMmZjKSwgbmV3IEludCgweDc4YTU2MzZmLCAweDQzMTcyZjYwKSxcblx0XHRcdFx0bmV3IEludCgweDg0Yzg3ODE0LCAweGExZjBhYjcyKSwgbmV3IEludCgweDhjYzcwMjA4LCAweDFhNjQzOWVjKSxcblx0XHRcdFx0bmV3IEludCgweDkwYmVmZmZhLCAweDIzNjMxZTI4KSwgbmV3IEludCgweGE0NTA2Y2ViLCAweGRlODJiZGU5KSxcblx0XHRcdFx0bmV3IEludCgweGJlZjlhM2Y3LCAweGIyYzY3OTE1KSwgbmV3IEludCgweGM2NzE3OGYyLCAweGUzNzI1MzJiKSxcblx0XHRcdFx0bmV3IEludCgweGNhMjczZWNlLCAweGVhMjY2MTljKSwgbmV3IEludCgweGQxODZiOGM3LCAweDIxYzBjMjA3KSxcblx0XHRcdFx0bmV3IEludCgweGVhZGE3ZGQ2LCAweGNkZTBlYjFlKSwgbmV3IEludCgweGY1N2Q0ZjdmLCAweGVlNmVkMTc4KSxcblx0XHRcdFx0bmV3IEludCgweDA2ZjA2N2FhLCAweDcyMTc2ZmJhKSwgbmV3IEludCgweDBhNjM3ZGM1LCAweGEyYzg5OGE2KSxcblx0XHRcdFx0bmV3IEludCgweDExM2Y5ODA0LCAweGJlZjkwZGFlKSwgbmV3IEludCgweDFiNzEwYjM1LCAweDEzMWM0NzFiKSxcblx0XHRcdFx0bmV3IEludCgweDI4ZGI3N2Y1LCAweDIzMDQ3ZDg0KSwgbmV3IEludCgweDMyY2FhYjdiLCAweDQwYzcyNDkzKSxcblx0XHRcdFx0bmV3IEludCgweDNjOWViZTBhLCAweDE1YzliZWJjKSwgbmV3IEludCgweDQzMWQ2N2M0LCAweDljMTAwZDRjKSxcblx0XHRcdFx0bmV3IEludCgweDRjYzVkNGJlLCAweGNiM2U0MmI2KSwgbmV3IEludCgweDU5N2YyOTljLCAweGZjNjU3ZTJhKSxcblx0XHRcdFx0bmV3IEludCgweDVmY2I2ZmFiLCAweDNhZDZmYWVjKSwgbmV3IEludCgweDZjNDQxOThjLCAweDRhNDc1ODE3KVxuXHRcdFx0XTtcblxuXHRcdFx0aWYgKHZhcmlhbnQgPT09IFwiU0hBLTM4NFwiKVxuXHRcdFx0e1xuXHRcdFx0XHRIID0gW1xuXHRcdFx0XHRcdG5ldyBJbnQoMHhjYmJiOWQ1ZCwgMHhjMTA1OWVkOCksIG5ldyBJbnQoMHgwNjI5YTI5MmEsIDB4MzY3Y2Q1MDcpLFxuXHRcdFx0XHRcdG5ldyBJbnQoMHg5MTU5MDE1YSwgMHgzMDcwZGQxNyksIG5ldyBJbnQoMHgwMTUyZmVjZDgsIDB4ZjcwZTU5MzkpLFxuXHRcdFx0XHRcdG5ldyBJbnQoMHg2NzMzMjY2NywgMHhmZmMwMGIzMSksIG5ldyBJbnQoMHg5OGViNDRhODcsIDB4Njg1ODE1MTEpLFxuXHRcdFx0XHRcdG5ldyBJbnQoMHhkYjBjMmUwZCwgMHg2NGY5OGZhNyksIG5ldyBJbnQoMHgwNDdiNTQ4MWQsIDB4YmVmYTRmYTQpXG5cdFx0XHRcdF07XG5cdFx0XHR9XG5cdFx0XHRlbHNlXG5cdFx0XHR7XG5cdFx0XHRcdEggPSBbXG5cdFx0XHRcdFx0bmV3IEludCgweDZhMDllNjY3LCAweGYzYmNjOTA4KSwgbmV3IEludCgweGJiNjdhZTg1LCAweDg0Y2FhNzNiKSxcblx0XHRcdFx0XHRuZXcgSW50KDB4M2M2ZWYzNzIsIDB4ZmU5NGY4MmIpLCBuZXcgSW50KDB4YTU0ZmY1M2EsIDB4NWYxZDM2ZjEpLFxuXHRcdFx0XHRcdG5ldyBJbnQoMHg1MTBlNTI3ZiwgMHhhZGU2ODJkMSksIG5ldyBJbnQoMHg5YjA1Njg4YywgMHgyYjNlNmMxZiksXG5cdFx0XHRcdFx0bmV3IEludCgweDFmODNkOWFiLCAweGZiNDFiZDZiKSwgbmV3IEludCgweDViZTBjZDE5LCAweDEzN2UyMTc5KVxuXHRcdFx0XHRdO1xuXHRcdFx0fVxuXHRcdH1cblxuXHRcdC8qIEFwcGVuZCAnMScgYXQgdGhlIGVuZCBvZiB0aGUgYmluYXJ5IHN0cmluZyAqL1xuXHRcdG1lc3NhZ2VbbWVzc2FnZUxlbiA+PiA1XSB8PSAweDgwIDw8ICgyNCAtIG1lc3NhZ2VMZW4gJSAzMik7XG5cdFx0LyogQXBwZW5kIGxlbmd0aCBvZiBiaW5hcnkgc3RyaW5nIGluIHRoZSBwb3NpdGlvbiBzdWNoIHRoYXQgdGhlIG5ld1xuXHRcdCAqIGxlbmd0aCBpcyBjb3JyZWN0ICovXG5cdFx0bWVzc2FnZVtsZW5ndGhQb3NpdGlvbl0gPSBtZXNzYWdlTGVuO1xuXG5cdFx0YXBwZW5kZWRNZXNzYWdlTGVuZ3RoID0gbWVzc2FnZS5sZW5ndGg7XG5cblx0XHRmb3IgKGkgPSAwOyBpIDwgYXBwZW5kZWRNZXNzYWdlTGVuZ3RoOyBpICs9IGJpbmFyeVN0cmluZ0luYylcblx0XHR7XG5cdFx0XHRhID0gSFswXTtcblx0XHRcdGIgPSBIWzFdO1xuXHRcdFx0YyA9IEhbMl07XG5cdFx0XHRkID0gSFszXTtcblx0XHRcdGUgPSBIWzRdO1xuXHRcdFx0ZiA9IEhbNV07XG5cdFx0XHRnID0gSFs2XTtcblx0XHRcdGggPSBIWzddO1xuXG5cdFx0XHRmb3IgKHQgPSAwOyB0IDwgbnVtUm91bmRzOyB0ICs9IDEpXG5cdFx0XHR7XG5cdFx0XHRcdGlmICh0IDwgMTYpXG5cdFx0XHRcdHtcblx0XHRcdFx0XHQvKiBCaXQgb2YgYSBoYWNrIC0gZm9yIDMyLWJpdCwgdGhlIHNlY29uZCB0ZXJtIGlzIGlnbm9yZWQgKi9cblx0XHRcdFx0XHRXW3RdID0gbmV3IEludChtZXNzYWdlW3QgKiBiaW5hcnlTdHJpbmdNdWx0ICsgaV0sXG5cdFx0XHRcdFx0XHRcdG1lc3NhZ2VbdCAqIGJpbmFyeVN0cmluZ011bHQgKyBpICsgMV0pO1xuXHRcdFx0XHR9XG5cdFx0XHRcdGVsc2Vcblx0XHRcdFx0e1xuXHRcdFx0XHRcdFdbdF0gPSBzYWZlQWRkXzQoXG5cdFx0XHRcdFx0XHRcdGdhbW1hMShXW3QgLSAyXSksIFdbdCAtIDddLFxuXHRcdFx0XHRcdFx0XHRnYW1tYTAoV1t0IC0gMTVdKSwgV1t0IC0gMTZdXG5cdFx0XHRcdFx0XHQpO1xuXHRcdFx0XHR9XG5cblx0XHRcdFx0VDEgPSBzYWZlQWRkXzUoaCwgc2lnbWExKGUpLCBjaChlLCBmLCBnKSwgS1t0XSwgV1t0XSk7XG5cdFx0XHRcdFQyID0gc2FmZUFkZF8yKHNpZ21hMChhKSwgbWFqKGEsIGIsIGMpKTtcblx0XHRcdFx0aCA9IGc7XG5cdFx0XHRcdGcgPSBmO1xuXHRcdFx0XHRmID0gZTtcblx0XHRcdFx0ZSA9IHNhZmVBZGRfMihkLCBUMSk7XG5cdFx0XHRcdGQgPSBjO1xuXHRcdFx0XHRjID0gYjtcblx0XHRcdFx0YiA9IGE7XG5cdFx0XHRcdGEgPSBzYWZlQWRkXzIoVDEsIFQyKTtcblx0XHRcdH1cblxuXHRcdFx0SFswXSA9IHNhZmVBZGRfMihhLCBIWzBdKTtcblx0XHRcdEhbMV0gPSBzYWZlQWRkXzIoYiwgSFsxXSk7XG5cdFx0XHRIWzJdID0gc2FmZUFkZF8yKGMsIEhbMl0pO1xuXHRcdFx0SFszXSA9IHNhZmVBZGRfMihkLCBIWzNdKTtcblx0XHRcdEhbNF0gPSBzYWZlQWRkXzIoZSwgSFs0XSk7XG5cdFx0XHRIWzVdID0gc2FmZUFkZF8yKGYsIEhbNV0pO1xuXHRcdFx0SFs2XSA9IHNhZmVBZGRfMihnLCBIWzZdKTtcblx0XHRcdEhbN10gPSBzYWZlQWRkXzIoaCwgSFs3XSk7XG5cdFx0fVxuXG5cdFx0c3dpdGNoICh2YXJpYW50KVxuXHRcdHtcblx0XHRjYXNlIFwiU0hBLTIyNFwiOlxuXHRcdFx0cmV0dXJuXHRbXG5cdFx0XHRcdEhbMF0sIEhbMV0sIEhbMl0sIEhbM10sXG5cdFx0XHRcdEhbNF0sIEhbNV0sIEhbNl1cblx0XHRcdF07XG5cdFx0Y2FzZSBcIlNIQS0yNTZcIjpcblx0XHRcdHJldHVybiBIO1xuXHRcdGNhc2UgXCJTSEEtMzg0XCI6XG5cdFx0XHRyZXR1cm4gW1xuXHRcdFx0XHRIWzBdLmhpZ2hPcmRlciwgSFswXS5sb3dPcmRlcixcblx0XHRcdFx0SFsxXS5oaWdoT3JkZXIsIEhbMV0ubG93T3JkZXIsXG5cdFx0XHRcdEhbMl0uaGlnaE9yZGVyLCBIWzJdLmxvd09yZGVyLFxuXHRcdFx0XHRIWzNdLmhpZ2hPcmRlciwgSFszXS5sb3dPcmRlcixcblx0XHRcdFx0SFs0XS5oaWdoT3JkZXIsIEhbNF0ubG93T3JkZXIsXG5cdFx0XHRcdEhbNV0uaGlnaE9yZGVyLCBIWzVdLmxvd09yZGVyXG5cdFx0XHRdO1xuXHRcdGNhc2UgXCJTSEEtNTEyXCI6XG5cdFx0XHRyZXR1cm4gW1xuXHRcdFx0XHRIWzBdLmhpZ2hPcmRlciwgSFswXS5sb3dPcmRlcixcblx0XHRcdFx0SFsxXS5oaWdoT3JkZXIsIEhbMV0ubG93T3JkZXIsXG5cdFx0XHRcdEhbMl0uaGlnaE9yZGVyLCBIWzJdLmxvd09yZGVyLFxuXHRcdFx0XHRIWzNdLmhpZ2hPcmRlciwgSFszXS5sb3dPcmRlcixcblx0XHRcdFx0SFs0XS5oaWdoT3JkZXIsIEhbNF0ubG93T3JkZXIsXG5cdFx0XHRcdEhbNV0uaGlnaE9yZGVyLCBIWzVdLmxvd09yZGVyLFxuXHRcdFx0XHRIWzZdLmhpZ2hPcmRlciwgSFs2XS5sb3dPcmRlcixcblx0XHRcdFx0SFs3XS5oaWdoT3JkZXIsIEhbN10ubG93T3JkZXJcblx0XHRcdF07XG5cdFx0ZGVmYXVsdDpcblx0XHRcdC8qIFRoaXMgc2hvdWxkIG5ldmVyIGJlIHJlYWNoZWQgKi9cblx0XHRcdHJldHVybiBbXTsgXG5cdFx0fVxuXHR9LFxuXG5cdC8qXG5cdCAqIGpzU0hBIGlzIHRoZSB3b3JraG9yc2Ugb2YgdGhlIGxpYnJhcnkuICBJbnN0YW50aWF0ZSBpdCB3aXRoIHRoZSBzdHJpbmcgdG9cblx0ICogYmUgaGFzaGVkIGFzIHRoZSBwYXJhbWV0ZXJcblx0ICpcblx0ICogQGNvbnN0cnVjdG9yXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBzcmNTdHJpbmcgVGhlIHN0cmluZyB0byBiZSBoYXNoZWRcblx0ICogQHBhcmFtIHtTdHJpbmd9IGlucHV0Rm9ybWF0IFRoZSBmb3JtYXQgb2Ygc3JjU3RyaW5nLCBBU0NJSSBvciBIRVhcblx0ICovXG5cdGpzU0hBID0gZnVuY3Rpb24gKHNyY1N0cmluZywgaW5wdXRGb3JtYXQpXG5cdHtcblxuXHRcdHRoaXMuc2hhMSA9IG51bGw7XG5cdFx0dGhpcy5zaGEyMjQgPSBudWxsO1xuXHRcdHRoaXMuc2hhMjU2ID0gbnVsbDtcblx0XHR0aGlzLnNoYTM4NCA9IG51bGw7XG5cdFx0dGhpcy5zaGE1MTIgPSBudWxsO1xuXG5cdFx0dGhpcy5zdHJCaW5MZW4gPSBudWxsO1xuXHRcdHRoaXMuc3RyVG9IYXNoID0gbnVsbDtcblxuXHRcdC8qIENvbnZlcnQgdGhlIGlucHV0IHN0cmluZyBpbnRvIHRoZSBjb3JyZWN0IHR5cGUgKi9cblx0XHRpZiAoXCJIRVhcIiA9PT0gaW5wdXRGb3JtYXQpXG5cdFx0e1xuXHRcdFx0aWYgKDAgIT09IChzcmNTdHJpbmcubGVuZ3RoICUgMikpXG5cdFx0XHR7XG5cdFx0XHRcdHJldHVybiBcIlRFWFQgTVVTVCBCRSBJTiBCWVRFIElOQ1JFTUVOVFNcIjtcblx0XHRcdH1cblx0XHRcdHRoaXMuc3RyQmluTGVuID0gc3JjU3RyaW5nLmxlbmd0aCAqIDQ7XG5cdFx0XHR0aGlzLnN0clRvSGFzaCA9IGhleDJiaW5iKHNyY1N0cmluZyk7XG5cdFx0fVxuXHRcdGVsc2UgaWYgKChcIkFTQ0lJXCIgPT09IGlucHV0Rm9ybWF0KSB8fFxuXHRcdFx0ICgndW5kZWZpbmVkJyA9PT0gdHlwZW9mKGlucHV0Rm9ybWF0KSkpXG5cdFx0e1xuXHRcdFx0dGhpcy5zdHJCaW5MZW4gPSBzcmNTdHJpbmcubGVuZ3RoICogY2hhclNpemU7XG5cdFx0XHR0aGlzLnN0clRvSGFzaCA9IHN0cjJiaW5iKHNyY1N0cmluZyk7XG5cdFx0fVxuXHRcdGVsc2Vcblx0XHR7XG5cdFx0XHRyZXR1cm4gXCJVTktOT1dOIFRFWFQgSU5QVVQgVFlQRVwiO1xuXHRcdH1cblx0fTtcblxuXHRqc1NIQS5wcm90b3R5cGUgPSB7XG5cdFx0Lypcblx0XHQgKiBSZXR1cm5zIHRoZSBkZXNpcmVkIFNIQSBoYXNoIG9mIHRoZSBzdHJpbmcgc3BlY2lmaWVkIGF0IGluc3RhbnRpYXRpb25cblx0XHQgKiB1c2luZyB0aGUgc3BlY2lmaWVkIHBhcmFtZXRlcnNcblx0XHQgKlxuXHRcdCAqIEBwYXJhbSB7U3RyaW5nfSB2YXJpYW50IFRoZSBkZXNpcmVkIFNIQSB2YXJpYW50IChTSEEtMSwgU0hBLTIyNCxcblx0XHQgKlx0IFNIQS0yNTYsIFNIQS0zODQsIG9yIFNIQS01MTIpXG5cdFx0ICogQHBhcmFtIHtTdHJpbmd9IGZvcm1hdCBUaGUgZGVzaXJlZCBvdXRwdXQgZm9ybWF0dGluZyAoQjY0IG9yIEhFWClcblx0XHQgKiBAcmV0dXJuIFRoZSBzdHJpbmcgcmVwcmVzZW50YXRpb24gb2YgdGhlIGhhc2ggaW4gdGhlIGZvcm1hdCBzcGVjaWZpZWRcblx0XHQgKi9cblx0XHRnZXRIYXNoIDogZnVuY3Rpb24gKHZhcmlhbnQsIGZvcm1hdClcblx0XHR7XG5cdFx0XHR2YXIgZm9ybWF0RnVuYyA9IG51bGwsIG1lc3NhZ2UgPSB0aGlzLnN0clRvSGFzaC5zbGljZSgpO1xuXG5cdFx0XHRzd2l0Y2ggKGZvcm1hdClcblx0XHRcdHtcblx0XHRcdGNhc2UgXCJIRVhcIjpcblx0XHRcdFx0Zm9ybWF0RnVuYyA9IGJpbmIyaGV4O1xuXHRcdFx0XHRicmVhaztcblx0XHRcdGNhc2UgXCJCNjRcIjpcblx0XHRcdFx0Zm9ybWF0RnVuYyA9IGJpbmIyYjY0O1xuXHRcdFx0XHRicmVhaztcblx0XHRcdGNhc2UgXCJBU0NJSVwiOlxuXHRcdFx0XHRmb3JtYXRGdW5jID0gYmluYjJzdHI7XG5cdFx0XHRcdGJyZWFrO1xuXHRcdFx0ZGVmYXVsdDpcblx0XHRcdFx0cmV0dXJuIFwiRk9STUFUIE5PVCBSRUNPR05JWkVEXCI7XG5cdFx0XHR9XG5cblx0XHRcdHN3aXRjaCAodmFyaWFudClcblx0XHRcdHtcblx0XHRcdGNhc2UgXCJTSEEtMVwiOlxuXHRcdFx0XHRpZiAobnVsbCA9PT0gdGhpcy5zaGExKVxuXHRcdFx0XHR7XG5cdFx0XHRcdFx0dGhpcy5zaGExID0gY29yZVNIQTEobWVzc2FnZSwgdGhpcy5zdHJCaW5MZW4pO1xuXHRcdFx0XHR9XG5cdFx0XHRcdHJldHVybiBmb3JtYXRGdW5jKHRoaXMuc2hhMSk7XG5cdFx0XHRjYXNlIFwiU0hBLTIyNFwiOlxuXHRcdFx0XHRpZiAobnVsbCA9PT0gdGhpcy5zaGEyMjQpXG5cdFx0XHRcdHtcblx0XHRcdFx0XHR0aGlzLnNoYTIyNCA9IGNvcmVTSEEyKG1lc3NhZ2UsIHRoaXMuc3RyQmluTGVuLCB2YXJpYW50KTtcblx0XHRcdFx0fVxuXHRcdFx0XHRyZXR1cm4gZm9ybWF0RnVuYyh0aGlzLnNoYTIyNCk7XG5cdFx0XHRjYXNlIFwiU0hBLTI1NlwiOlxuXHRcdFx0XHRpZiAobnVsbCA9PT0gdGhpcy5zaGEyNTYpXG5cdFx0XHRcdHtcblx0XHRcdFx0XHR0aGlzLnNoYTI1NiA9IGNvcmVTSEEyKG1lc3NhZ2UsIHRoaXMuc3RyQmluTGVuLCB2YXJpYW50KTtcblx0XHRcdFx0fVxuXHRcdFx0XHRyZXR1cm4gZm9ybWF0RnVuYyh0aGlzLnNoYTI1Nik7XG5cdFx0XHRjYXNlIFwiU0hBLTM4NFwiOlxuXHRcdFx0XHRpZiAobnVsbCA9PT0gdGhpcy5zaGEzODQpXG5cdFx0XHRcdHtcblx0XHRcdFx0XHR0aGlzLnNoYTM4NCA9IGNvcmVTSEEyKG1lc3NhZ2UsIHRoaXMuc3RyQmluTGVuLCB2YXJpYW50KTtcblx0XHRcdFx0fVxuXHRcdFx0XHRyZXR1cm4gZm9ybWF0RnVuYyh0aGlzLnNoYTM4NCk7XG5cdFx0XHRjYXNlIFwiU0hBLTUxMlwiOlxuXHRcdFx0XHRpZiAobnVsbCA9PT0gdGhpcy5zaGE1MTIpXG5cdFx0XHRcdHtcblx0XHRcdFx0XHR0aGlzLnNoYTUxMiA9IGNvcmVTSEEyKG1lc3NhZ2UsIHRoaXMuc3RyQmluTGVuLCB2YXJpYW50KTtcblx0XHRcdFx0fVxuXHRcdFx0XHRyZXR1cm4gZm9ybWF0RnVuYyh0aGlzLnNoYTUxMik7XG5cdFx0XHRkZWZhdWx0OlxuXHRcdFx0XHRyZXR1cm4gXCJIQVNIIE5PVCBSRUNPR05JWkVEXCI7XG5cdFx0XHR9XG5cdFx0fSxcblxuXHRcdC8qXG5cdFx0ICogUmV0dXJucyB0aGUgZGVzaXJlZCBITUFDIG9mIHRoZSBzdHJpbmcgc3BlY2lmaWVkIGF0IGluc3RhbnRpYXRpb25cblx0XHQgKiB1c2luZyB0aGUga2V5IGFuZCB2YXJpYW50IHBhcmFtLlxuXHRcdCAqXG5cdFx0ICogQHBhcmFtIHtTdHJpbmd9IGtleSBUaGUga2V5IHVzZWQgdG8gY2FsY3VsYXRlIHRoZSBITUFDXG5cdFx0ICogQHBhcmFtIHtTdHJpbmd9IGlucHV0Rm9ybWF0IFRoZSBmb3JtYXQgb2Yga2V5LCBBU0NJSSBvciBIRVhcblx0XHQgKiBAcGFyYW0ge1N0cmluZ30gdmFyaWFudCBUaGUgZGVzaXJlZCBTSEEgdmFyaWFudCAoU0hBLTEsIFNIQS0yMjQsXG5cdFx0ICpcdCBTSEEtMjU2LCBTSEEtMzg0LCBvciBTSEEtNTEyKVxuXHRcdCAqIEBwYXJhbSB7U3RyaW5nfSBvdXRwdXRGb3JtYXQgVGhlIGRlc2lyZWQgb3V0cHV0IGZvcm1hdHRpbmdcblx0XHQgKlx0IChCNjQgb3IgSEVYKVxuXHRcdCAqIEByZXR1cm4gVGhlIHN0cmluZyByZXByZXNlbnRhdGlvbiBvZiB0aGUgaGFzaCBpbiB0aGUgZm9ybWF0IHNwZWNpZmllZFxuXHRcdCAqL1xuXHRcdGdldEhNQUMgOiBmdW5jdGlvbiAoa2V5LCBpbnB1dEZvcm1hdCwgdmFyaWFudCwgb3V0cHV0Rm9ybWF0KVxuXHRcdHtcblx0XHRcdHZhciBmb3JtYXRGdW5jLCBrZXlUb1VzZSwgYmxvY2tCeXRlU2l6ZSwgYmxvY2tCaXRTaXplLCBpLFxuXHRcdFx0XHRyZXRWYWwsIGxhc3RBcnJheUluZGV4LCBrZXlCaW5MZW4sIGhhc2hCaXRTaXplLFxuXHRcdFx0XHRrZXlXaXRoSVBhZCA9IFtdLCBrZXlXaXRoT1BhZCA9IFtdO1xuXG5cdFx0XHQvKiBWYWxpZGF0ZSB0aGUgb3V0cHV0IGZvcm1hdCBzZWxlY3Rpb24gKi9cblx0XHRcdHN3aXRjaCAob3V0cHV0Rm9ybWF0KVxuXHRcdFx0e1xuXHRcdFx0Y2FzZSBcIkhFWFwiOlxuXHRcdFx0XHRmb3JtYXRGdW5jID0gYmluYjJoZXg7XG5cdFx0XHRcdGJyZWFrO1xuXHRcdFx0Y2FzZSBcIkI2NFwiOlxuXHRcdFx0XHRmb3JtYXRGdW5jID0gYmluYjJiNjQ7XG5cdFx0XHRcdGJyZWFrO1xuXHRcdFx0Y2FzZSBcIkFTQ0lJXCI6XG5cdFx0XHRcdGZvcm1hdEZ1bmMgPSBiaW5iMnN0cjtcblx0XHRcdFx0YnJlYWs7XG5cdFx0XHRkZWZhdWx0OlxuXHRcdFx0XHRyZXR1cm4gXCJGT1JNQVQgTk9UIFJFQ09HTklaRURcIjtcblx0XHRcdH1cblxuXHRcdFx0LyogVmFsaWRhdGUgdGhlIGhhc2ggdmFyaWFudCBzZWxlY3Rpb24gYW5kIHNldCBuZWVkZWQgdmFyaWFibGVzICovXG5cdFx0XHRzd2l0Y2ggKHZhcmlhbnQpXG5cdFx0XHR7XG5cdFx0XHRjYXNlIFwiU0hBLTFcIjpcblx0XHRcdFx0YmxvY2tCeXRlU2l6ZSA9IDY0O1xuXHRcdFx0XHRoYXNoQml0U2l6ZSA9IDE2MDtcblx0XHRcdFx0YnJlYWs7XG5cdFx0XHRjYXNlIFwiU0hBLTIyNFwiOlxuXHRcdFx0XHRibG9ja0J5dGVTaXplID0gNjQ7XG5cdFx0XHRcdGhhc2hCaXRTaXplID0gMjI0O1xuXHRcdFx0XHRicmVhaztcblx0XHRcdGNhc2UgXCJTSEEtMjU2XCI6XG5cdFx0XHRcdGJsb2NrQnl0ZVNpemUgPSA2NDtcblx0XHRcdFx0aGFzaEJpdFNpemUgPSAyNTY7XG5cdFx0XHRcdGJyZWFrO1xuXHRcdFx0Y2FzZSBcIlNIQS0zODRcIjpcblx0XHRcdFx0YmxvY2tCeXRlU2l6ZSA9IDEyODtcblx0XHRcdFx0aGFzaEJpdFNpemUgPSAzODQ7XG5cdFx0XHRcdGJyZWFrO1xuXHRcdFx0Y2FzZSBcIlNIQS01MTJcIjpcblx0XHRcdFx0YmxvY2tCeXRlU2l6ZSA9IDEyODtcblx0XHRcdFx0aGFzaEJpdFNpemUgPSA1MTI7XG5cdFx0XHRcdGJyZWFrO1xuXHRcdFx0ZGVmYXVsdDpcblx0XHRcdFx0cmV0dXJuIFwiSEFTSCBOT1QgUkVDT0dOSVpFRFwiO1xuXHRcdFx0fVxuXG5cdFx0XHQvKiBWYWxpZGF0ZSBpbnB1dCBmb3JtYXQgc2VsZWN0aW9uICovXG5cdFx0XHRpZiAoXCJIRVhcIiA9PT0gaW5wdXRGb3JtYXQpXG5cdFx0XHR7XG5cdFx0XHRcdC8qIE5pYmJsZXMgbXVzdCBjb21lIGluIHBhaXJzICovXG5cdFx0XHRcdGlmICgwICE9PSAoa2V5Lmxlbmd0aCAlIDIpKVxuXHRcdFx0XHR7XG5cdFx0XHRcdFx0cmV0dXJuIFwiS0VZIE1VU1QgQkUgSU4gQllURSBJTkNSRU1FTlRTXCI7XG5cdFx0XHRcdH1cblx0XHRcdFx0a2V5VG9Vc2UgPSBoZXgyYmluYihrZXkpO1xuXHRcdFx0XHRrZXlCaW5MZW4gPSBrZXkubGVuZ3RoICogNDtcblx0XHRcdH1cblx0XHRcdGVsc2UgaWYgKFwiQVNDSUlcIiA9PT0gaW5wdXRGb3JtYXQpXG5cdFx0XHR7XG5cdFx0XHRcdGtleVRvVXNlID0gc3RyMmJpbmIoa2V5KTtcblx0XHRcdFx0a2V5QmluTGVuID0ga2V5Lmxlbmd0aCAqIGNoYXJTaXplO1xuXHRcdFx0fVxuXHRcdFx0ZWxzZVxuXHRcdFx0e1xuXHRcdFx0XHRyZXR1cm4gXCJVTktOT1dOIEtFWSBJTlBVVCBUWVBFXCI7XG5cdFx0XHR9XG5cblx0XHRcdC8qIFRoZXNlIGFyZSB1c2VkIG11bHRpcGxlIHRpbWVzLCBjYWxjdWxhdGUgYW5kIHN0b3JlIHRoZW0gKi9cblx0XHRcdGJsb2NrQml0U2l6ZSA9IGJsb2NrQnl0ZVNpemUgKiA4O1xuXHRcdFx0bGFzdEFycmF5SW5kZXggPSAoYmxvY2tCeXRlU2l6ZSAvIDQpIC0gMTtcblxuXHRcdFx0LyogRmlndXJlIG91dCB3aGF0IHRvIGRvIHdpdGggdGhlIGtleSBiYXNlZCBvbiBpdHMgc2l6ZSByZWxhdGl2ZSB0b1xuXHRcdFx0ICogdGhlIGhhc2gncyBibG9jayBzaXplICovXG5cdFx0XHRpZiAoYmxvY2tCeXRlU2l6ZSA8IChrZXlCaW5MZW4gLyA4KSlcblx0XHRcdHtcblx0XHRcdFx0aWYgKFwiU0hBLTFcIiA9PT0gdmFyaWFudClcblx0XHRcdFx0e1xuXHRcdFx0XHRcdGtleVRvVXNlID0gY29yZVNIQTEoa2V5VG9Vc2UsIGtleUJpbkxlbik7XG5cdFx0XHRcdH1cblx0XHRcdFx0ZWxzZVxuXHRcdFx0XHR7XG5cdFx0XHRcdFx0a2V5VG9Vc2UgPSBjb3JlU0hBMihrZXlUb1VzZSwga2V5QmluTGVuLCB2YXJpYW50KTtcblx0XHRcdFx0fVxuXHRcdFx0XHQvKiBGb3IgYWxsIHZhcmlhbnRzLCB0aGUgYmxvY2sgc2l6ZSBpcyBiaWdnZXIgdGhhbiB0aGUgb3V0cHV0XG5cdFx0XHRcdCAqIHNpemUgc28gdGhlcmUgd2lsbCBuZXZlciBiZSBhIHVzZWZ1bCBieXRlIGF0IHRoZSBlbmQgb2YgdGhlXG5cdFx0XHRcdCAqIHN0cmluZyAqL1xuXHRcdFx0XHRrZXlUb1VzZVtsYXN0QXJyYXlJbmRleF0gJj0gMHhGRkZGRkYwMDtcblx0XHRcdH1cblx0XHRcdGVsc2UgaWYgKGJsb2NrQnl0ZVNpemUgPiAoa2V5QmluTGVuIC8gOCkpXG5cdFx0XHR7XG5cdFx0XHRcdC8qIElmIHRoZSBibG9ja0J5dGVTaXplIGlzIGdyZWF0ZXIgdGhhbiB0aGUga2V5IGxlbmd0aCwgdGhlcmVcblx0XHRcdFx0ICogd2lsbCBhbHdheXMgYmUgYXQgTEVBU1Qgb25lIFwidXNlbGVzc1wiIGJ5dGUgYXQgdGhlIGVuZCBvZiB0aGVcblx0XHRcdFx0ICogc3RyaW5nICovXG5cdFx0XHRcdGtleVRvVXNlW2xhc3RBcnJheUluZGV4XSAmPSAweEZGRkZGRjAwO1xuXHRcdFx0fVxuXG5cdFx0XHQvKiBDcmVhdGUgaXBhZCBhbmQgb3BhZCAqL1xuXHRcdFx0Zm9yIChpID0gMDsgaSA8PSBsYXN0QXJyYXlJbmRleDsgaSArPSAxKVxuXHRcdFx0e1xuXHRcdFx0XHRrZXlXaXRoSVBhZFtpXSA9IGtleVRvVXNlW2ldIF4gMHgzNjM2MzYzNjtcblx0XHRcdFx0a2V5V2l0aE9QYWRbaV0gPSBrZXlUb1VzZVtpXSBeIDB4NUM1QzVDNUM7XG5cdFx0XHR9XG5cblx0XHRcdC8qIENhbGN1bGF0ZSB0aGUgSE1BQyAqL1xuXHRcdFx0aWYgKFwiU0hBLTFcIiA9PT0gdmFyaWFudClcblx0XHRcdHtcblx0XHRcdFx0cmV0VmFsID0gY29yZVNIQTEoXG5cdFx0XHRcdFx0XHRcdGtleVdpdGhJUGFkLmNvbmNhdCh0aGlzLnN0clRvSGFzaCksXG5cdFx0XHRcdFx0XHRcdGJsb2NrQml0U2l6ZSArIHRoaXMuc3RyQmluTGVuKTtcblx0XHRcdFx0cmV0VmFsID0gY29yZVNIQTEoXG5cdFx0XHRcdFx0XHRcdGtleVdpdGhPUGFkLmNvbmNhdChyZXRWYWwpLFxuXHRcdFx0XHRcdFx0XHRibG9ja0JpdFNpemUgKyBoYXNoQml0U2l6ZSk7XG5cdFx0XHR9XG5cdFx0XHRlbHNlXG5cdFx0XHR7XG5cdFx0XHRcdHJldFZhbCA9IGNvcmVTSEEyKFxuXHRcdFx0XHRcdFx0XHRrZXlXaXRoSVBhZC5jb25jYXQodGhpcy5zdHJUb0hhc2gpLFxuXHRcdFx0XHRcdFx0XHRibG9ja0JpdFNpemUgKyB0aGlzLnN0ckJpbkxlbiwgdmFyaWFudCk7XG5cdFx0XHRcdHJldFZhbCA9IGNvcmVTSEEyKFxuXHRcdFx0XHRcdFx0XHRrZXlXaXRoT1BhZC5jb25jYXQocmV0VmFsKSxcblx0XHRcdFx0XHRcdFx0YmxvY2tCaXRTaXplICsgaGFzaEJpdFNpemUsIHZhcmlhbnQpO1xuXHRcdFx0fVxuXG5cdFx0XHRyZXR1cm4gKGZvcm1hdEZ1bmMocmV0VmFsKSk7XG5cdFx0fVxuXHR9O1xuXG5cdHJldHVybiBqc1NIQTtcbn0oKSk7XG5cbm1vZHVsZS5leHBvcnRzID0ge1xuXHRzaGExOiBmdW5jdGlvbihzdHIpIHtcblx0XHR2YXIgc2hhT2JqID0gbmV3IGpzU0hBKHN0ciwgXCJBU0NJSVwiKTtcblx0XHRyZXR1cm4gc2hhT2JqLmdldEhhc2goXCJTSEEtMVwiLCBcIkFTQ0lJXCIpO1xuXHR9LFxuXHRzaGEyMjQ6IGZ1bmN0aW9uKHN0cikge1xuXHRcdHZhciBzaGFPYmogPSBuZXcganNTSEEoc3RyLCBcIkFTQ0lJXCIpO1xuXHRcdHJldHVybiBzaGFPYmouZ2V0SGFzaChcIlNIQS0yMjRcIiwgXCJBU0NJSVwiKTtcblx0fSxcblx0c2hhMjU2OiBmdW5jdGlvbihzdHIpIHtcblx0XHR2YXIgc2hhT2JqID0gbmV3IGpzU0hBKHN0ciwgXCJBU0NJSVwiKTtcblx0XHRyZXR1cm4gc2hhT2JqLmdldEhhc2goXCJTSEEtMjU2XCIsIFwiQVNDSUlcIik7XG5cdH0sXG5cdHNoYTM4NDogZnVuY3Rpb24oc3RyKSB7XG5cdFx0dmFyIHNoYU9iaiA9IG5ldyBqc1NIQShzdHIsIFwiQVNDSUlcIik7XG5cdFx0cmV0dXJuIHNoYU9iai5nZXRIYXNoKFwiU0hBLTM4NFwiLCBcIkFTQ0lJXCIpO1xuXG5cdH0sXG5cdHNoYTUxMjogZnVuY3Rpb24oc3RyKSB7XG5cdFx0dmFyIHNoYU9iaiA9IG5ldyBqc1NIQShzdHIsIFwiQVNDSUlcIik7XG5cdFx0cmV0dXJuIHNoYU9iai5nZXRIYXNoKFwiU0hBLTUxMlwiLCBcIkFTQ0lJXCIpO1xuXHR9XG59XG4iLCIvKlxuICogQ3J5cHRvTVggVG9vbHNcbiAqIENvcHlyaWdodCAoQykgMjAwNCAtIDIwMDYgRGVyZWsgQnVpdGVuaHVpc1xuICpcbiAqIFRoaXMgcHJvZ3JhbSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3JcbiAqIG1vZGlmeSBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlXG4gKiBhcyBwdWJsaXNoZWQgYnkgdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyIHZlcnNpb24gMlxuICogb2YgdGhlIExpY2Vuc2UsIG9yIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4gKlxuICogVGhpcyBwcm9ncmFtIGlzIGRpc3RyaWJ1dGVkIGluIHRoZSBob3BlIHRoYXQgaXQgd2lsbCBiZSB1c2VmdWwsXG4gKiBidXQgV0lUSE9VVCBBTlkgV0FSUkFOVFk7IHdpdGhvdXQgZXZlbiB0aGUgaW1wbGllZCB3YXJyYW50eSBvZlxuICogTUVSQ0hBTlRBQklMSVRZIG9yIEZJVE5FU1MgRk9SIEEgUEFSVElDVUxBUiBQVVJQT1NFLiAgU2VlIHRoZVxuICogR05VIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgZm9yIG1vcmUgZGV0YWlscy5cbiAqXG4gKiBZb3Ugc2hvdWxkIGhhdmUgcmVjZWl2ZWQgYSBjb3B5IG9mIHRoZSBHTlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZVxuICogYWxvbmcgd2l0aCB0aGlzIHByb2dyYW07IGlmIG5vdCwgd3JpdGUgdG8gdGhlIEZyZWUgU29mdHdhcmVcbiAqIEZvdW5kYXRpb24sIEluYy4sIDU5IFRlbXBsZSBQbGFjZSAtIFN1aXRlIDMzMCwgQm9zdG9uLCBNQSAgMDIxMTEtMTMwNywgVVNBLlxuICovXG5cbi8qIE1vZGlmaWVkIGJ5IFJlY3VyaXR5IExhYnMgR21iSFxuICovXG5cbnZhciBSTURzaXplICAgPSAxNjA7XG52YXIgWCA9IG5ldyBBcnJheSgpO1xuXG5mdW5jdGlvbiBST0woeCwgbilcbntcbiAgcmV0dXJuIG5ldyBOdW1iZXIgKCh4IDw8IG4pIHwgKCB4ID4+PiAoMzIgLSBuKSkpO1xufVxuXG5mdW5jdGlvbiBGKHgsIHksIHopXG57XG4gIHJldHVybiBuZXcgTnVtYmVyKHggXiB5IF4geik7XG59XG5cbmZ1bmN0aW9uIEcoeCwgeSwgeilcbntcbiAgcmV0dXJuIG5ldyBOdW1iZXIoKHggJiB5KSB8ICh+eCAmIHopKTtcbn1cblxuZnVuY3Rpb24gSCh4LCB5LCB6KVxue1xuICByZXR1cm4gbmV3IE51bWJlcigoeCB8IH55KSBeIHopO1xufVxuXG5mdW5jdGlvbiBJKHgsIHksIHopXG57XG4gIHJldHVybiBuZXcgTnVtYmVyKCh4ICYgeikgfCAoeSAmIH56KSk7XG59XG5cbmZ1bmN0aW9uIEooeCwgeSwgeilcbntcbiAgcmV0dXJuIG5ldyBOdW1iZXIoeCBeICh5IHwgfnopKTtcbn1cblxuZnVuY3Rpb24gbWl4T25lUm91bmQoYSwgYiwgYywgZCwgZSwgeCwgcywgcm91bmROdW1iZXIpXG57XG4gIHN3aXRjaCAocm91bmROdW1iZXIpXG4gIHtcbiAgICBjYXNlIDAgOiBhICs9IEYoYiwgYywgZCkgKyB4ICsgMHgwMDAwMDAwMDsgYnJlYWs7XG4gICAgY2FzZSAxIDogYSArPSBHKGIsIGMsIGQpICsgeCArIDB4NWE4Mjc5OTk7IGJyZWFrO1xuICAgIGNhc2UgMiA6IGEgKz0gSChiLCBjLCBkKSArIHggKyAweDZlZDllYmExOyBicmVhaztcbiAgICBjYXNlIDMgOiBhICs9IEkoYiwgYywgZCkgKyB4ICsgMHg4ZjFiYmNkYzsgYnJlYWs7XG4gICAgY2FzZSA0IDogYSArPSBKKGIsIGMsIGQpICsgeCArIDB4YTk1M2ZkNGU7IGJyZWFrO1xuICAgIGNhc2UgNSA6IGEgKz0gSihiLCBjLCBkKSArIHggKyAweDUwYTI4YmU2OyBicmVhaztcbiAgICBjYXNlIDYgOiBhICs9IEkoYiwgYywgZCkgKyB4ICsgMHg1YzRkZDEyNDsgYnJlYWs7XG4gICAgY2FzZSA3IDogYSArPSBIKGIsIGMsIGQpICsgeCArIDB4NmQ3MDNlZjM7IGJyZWFrO1xuICAgIGNhc2UgOCA6IGEgKz0gRyhiLCBjLCBkKSArIHggKyAweDdhNmQ3NmU5OyBicmVhaztcbiAgICBjYXNlIDkgOiBhICs9IEYoYiwgYywgZCkgKyB4ICsgMHgwMDAwMDAwMDsgYnJlYWs7XG4gICAgXG4gICAgZGVmYXVsdCA6IGRvY3VtZW50LndyaXRlKFwiQm9ndXMgcm91bmQgbnVtYmVyXCIpOyBicmVhaztcbiAgfSAgXG4gIFxuICBhID0gUk9MKGEsIHMpICsgZTtcbiAgYyA9IFJPTChjLCAxMCk7XG5cbiAgYSAmPSAweGZmZmZmZmZmO1xuICBiICY9IDB4ZmZmZmZmZmY7XG4gIGMgJj0gMHhmZmZmZmZmZjtcbiAgZCAmPSAweGZmZmZmZmZmO1xuICBlICY9IDB4ZmZmZmZmZmY7XG5cbiAgdmFyIHJldEJsb2NrID0gbmV3IEFycmF5KCk7XG4gIHJldEJsb2NrWzBdID0gYTtcbiAgcmV0QmxvY2tbMV0gPSBiO1xuICByZXRCbG9ja1syXSA9IGM7XG4gIHJldEJsb2NrWzNdID0gZDtcbiAgcmV0QmxvY2tbNF0gPSBlO1xuICByZXRCbG9ja1s1XSA9IHg7XG4gIHJldEJsb2NrWzZdID0gcztcblxuICByZXR1cm4gcmV0QmxvY2s7XG59XG5cbmZ1bmN0aW9uIE1EaW5pdCAoTURidWYpXG57XG4gIE1EYnVmWzBdID0gMHg2NzQ1MjMwMTtcbiAgTURidWZbMV0gPSAweGVmY2RhYjg5O1xuICBNRGJ1ZlsyXSA9IDB4OThiYWRjZmU7XG4gIE1EYnVmWzNdID0gMHgxMDMyNTQ3NjtcbiAgTURidWZbNF0gPSAweGMzZDJlMWYwO1xufVxuXG52YXIgUk9McyA9IFtcbiAgWzExLCAxNCwgMTUsIDEyLCAgNSwgIDgsICA3LCAgOSwgMTEsIDEzLCAxNCwgMTUsICA2LCAgNywgIDksICA4XSxcbiAgWyA3LCAgNiwgIDgsIDEzLCAxMSwgIDksICA3LCAxNSwgIDcsIDEyLCAxNSwgIDksIDExLCAgNywgMTMsIDEyXSxcbiAgWzExLCAxMywgIDYsICA3LCAxNCwgIDksIDEzLCAxNSwgMTQsICA4LCAxMywgIDYsICA1LCAxMiwgIDcsICA1XSxcbiAgWzExLCAxMiwgMTQsIDE1LCAxNCwgMTUsICA5LCAgOCwgIDksIDE0LCAgNSwgIDYsICA4LCAgNiwgIDUsIDEyXSxcbiAgWyA5LCAxNSwgIDUsIDExLCAgNiwgIDgsIDEzLCAxMiwgIDUsIDEyLCAxMywgMTQsIDExLCAgOCwgIDUsICA2XSxcbiAgWyA4LCAgOSwgIDksIDExLCAxMywgMTUsIDE1LCAgNSwgIDcsICA3LCAgOCwgMTEsIDE0LCAxNCwgMTIsICA2XSxcbiAgWyA5LCAxMywgMTUsICA3LCAxMiwgIDgsICA5LCAxMSwgIDcsICA3LCAxMiwgIDcsICA2LCAxNSwgMTMsIDExXSxcbiAgWyA5LCAgNywgMTUsIDExLCAgOCwgIDYsICA2LCAxNCwgMTIsIDEzLCAgNSwgMTQsIDEzLCAxMywgIDcsICA1XSxcbiAgWzE1LCAgNSwgIDgsIDExLCAxNCwgMTQsICA2LCAxNCwgIDYsICA5LCAxMiwgIDksIDEyLCAgNSwgMTUsICA4XSxcbiAgWyA4LCAgNSwgMTIsICA5LCAxMiwgIDUsIDE0LCAgNiwgIDgsIDEzLCAgNiwgIDUsIDE1LCAxMywgMTEsIDExXVxuXTtcblxudmFyIGluZGV4ZXMgPSBbXG4gIFsgMCwgIDEsICAyLCAgMywgIDQsICA1LCAgNiwgIDcsICA4LCAgOSwgMTAsIDExLCAxMiwgMTMsIDE0LCAxNV0sXG4gIFsgNywgIDQsIDEzLCAgMSwgMTAsICA2LCAxNSwgIDMsIDEyLCAgMCwgIDksICA1LCAgMiwgMTQsIDExLCAgOF0sXG4gIFsgMywgMTAsIDE0LCAgNCwgIDksIDE1LCAgOCwgIDEsICAyLCAgNywgIDAsICA2LCAxMywgMTEsICA1LCAxMl0sXG4gIFsgMSwgIDksIDExLCAxMCwgIDAsICA4LCAxMiwgIDQsIDEzLCAgMywgIDcsIDE1LCAxNCwgIDUsICA2LCAgMl0sXG4gIFsgNCwgIDAsICA1LCAgOSwgIDcsIDEyLCAgMiwgMTAsIDE0LCAgMSwgIDMsICA4LCAxMSwgIDYsIDE1LCAxM10sXG4gIFsgNSwgMTQsICA3LCAgMCwgIDksICAyLCAxMSwgIDQsIDEzLCAgNiwgMTUsICA4LCAgMSwgMTAsICAzLCAxMl0sXG4gIFsgNiwgMTEsICAzLCAgNywgIDAsIDEzLCAgNSwgMTAsIDE0LCAxNSwgIDgsIDEyLCAgNCwgIDksICAxLCAgMl0sXG4gIFsxNSwgIDUsICAxLCAgMywgIDcsIDE0LCAgNiwgIDksIDExLCAgOCwgMTIsICAyLCAxMCwgIDAsICA0LCAxM10sXG4gIFsgOCwgIDYsICA0LCAgMSwgIDMsIDExLCAxNSwgIDAsICA1LCAxMiwgIDIsIDEzLCAgOSwgIDcsIDEwLCAxNF0sXG4gIFsxMiwgMTUsIDEwLCAgNCwgIDEsICA1LCAgOCwgIDcsICA2LCAgMiwgMTMsIDE0LCAgMCwgIDMsICA5LCAxMV1cbl07XG5cbmZ1bmN0aW9uIGNvbXByZXNzIChNRGJ1ZiwgWClcbntcbiAgYmxvY2tBID0gbmV3IEFycmF5KCk7XG4gIGJsb2NrQiA9IG5ldyBBcnJheSgpO1xuXG4gIHZhciByZXRCbG9jaztcblxuICBmb3IgKHZhciBpPTA7IGkgPCA1OyBpKyspXG4gIHtcbiAgICBibG9ja0FbaV0gPSBuZXcgTnVtYmVyKE1EYnVmW2ldKTtcbiAgICBibG9ja0JbaV0gPSBuZXcgTnVtYmVyKE1EYnVmW2ldKTtcbiAgfVxuXG4gIHZhciBzdGVwID0gMDtcbiAgZm9yICh2YXIgaiA9IDA7IGogPCA1OyBqKyspXG4gIHtcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IDE2OyBpKyspXG4gICAge1xuICAgICAgcmV0QmxvY2sgPSBtaXhPbmVSb3VuZChcbiAgICAgICAgYmxvY2tBWyhzdGVwKzApICUgNV0sXG4gICAgICAgIGJsb2NrQVsoc3RlcCsxKSAlIDVdLCAgIFxuICAgICAgICBibG9ja0FbKHN0ZXArMikgJSA1XSwgICBcbiAgICAgICAgYmxvY2tBWyhzdGVwKzMpICUgNV0sICAgXG4gICAgICAgIGJsb2NrQVsoc3RlcCs0KSAlIDVdLCAgXG4gICAgICAgIFhbaW5kZXhlc1tqXVtpXV0sIFxuICAgICAgICBST0xzW2pdW2ldLFxuICAgICAgICBqXG4gICAgICApO1xuXG4gICAgICBibG9ja0FbKHN0ZXArMCkgJSA1XSA9IHJldEJsb2NrWzBdO1xuICAgICAgYmxvY2tBWyhzdGVwKzEpICUgNV0gPSByZXRCbG9ja1sxXTtcbiAgICAgIGJsb2NrQVsoc3RlcCsyKSAlIDVdID0gcmV0QmxvY2tbMl07XG4gICAgICBibG9ja0FbKHN0ZXArMykgJSA1XSA9IHJldEJsb2NrWzNdO1xuICAgICAgYmxvY2tBWyhzdGVwKzQpICUgNV0gPSByZXRCbG9ja1s0XTtcblxuICAgICAgc3RlcCArPSA0O1xuICAgIH1cbiAgfVxuXG4gIHN0ZXAgPSAwO1xuICBmb3IgKHZhciBqID0gNTsgaiA8IDEwOyBqKyspXG4gIHtcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IDE2OyBpKyspXG4gICAgeyAgXG4gICAgICByZXRCbG9jayA9IG1peE9uZVJvdW5kKFxuICAgICAgICBibG9ja0JbKHN0ZXArMCkgJSA1XSwgXG4gICAgICAgIGJsb2NrQlsoc3RlcCsxKSAlIDVdLCBcbiAgICAgICAgYmxvY2tCWyhzdGVwKzIpICUgNV0sIFxuICAgICAgICBibG9ja0JbKHN0ZXArMykgJSA1XSwgXG4gICAgICAgIGJsb2NrQlsoc3RlcCs0KSAlIDVdLCAgXG4gICAgICAgIFhbaW5kZXhlc1tqXVtpXV0sIFxuICAgICAgICBST0xzW2pdW2ldLFxuICAgICAgICBqXG4gICAgICApO1xuXG4gICAgICBibG9ja0JbKHN0ZXArMCkgJSA1XSA9IHJldEJsb2NrWzBdO1xuICAgICAgYmxvY2tCWyhzdGVwKzEpICUgNV0gPSByZXRCbG9ja1sxXTtcbiAgICAgIGJsb2NrQlsoc3RlcCsyKSAlIDVdID0gcmV0QmxvY2tbMl07XG4gICAgICBibG9ja0JbKHN0ZXArMykgJSA1XSA9IHJldEJsb2NrWzNdO1xuICAgICAgYmxvY2tCWyhzdGVwKzQpICUgNV0gPSByZXRCbG9ja1s0XTtcblxuICAgICAgc3RlcCArPSA0O1xuICAgIH1cbiAgfVxuXG4gIGJsb2NrQlszXSArPSBibG9ja0FbMl0gKyBNRGJ1ZlsxXTtcbiAgTURidWZbMV0gID0gTURidWZbMl0gKyBibG9ja0FbM10gKyBibG9ja0JbNF07XG4gIE1EYnVmWzJdICA9IE1EYnVmWzNdICsgYmxvY2tBWzRdICsgYmxvY2tCWzBdO1xuICBNRGJ1ZlszXSAgPSBNRGJ1Zls0XSArIGJsb2NrQVswXSArIGJsb2NrQlsxXTtcbiAgTURidWZbNF0gID0gTURidWZbMF0gKyBibG9ja0FbMV0gKyBibG9ja0JbMl07XG4gIE1EYnVmWzBdICA9IGJsb2NrQlszXTtcbn1cblxuZnVuY3Rpb24gemVyb1goWClcbntcbiAgZm9yICh2YXIgaSA9IDA7IGkgPCAxNjsgaSsrKSB7IFhbaV0gPSAwOyB9XG59XG5cbmZ1bmN0aW9uIE1EZmluaXNoIChNRGJ1Ziwgc3RycHRyLCBsc3dsZW4sIG1zd2xlbilcbntcbiAgdmFyIFggPSBuZXcgQXJyYXkoMTYpO1xuICB6ZXJvWChYKTtcblxuICB2YXIgaiA9IDA7XG4gIGZvciAodmFyIGk9MDsgaSA8IChsc3dsZW4gJiA2Myk7IGkrKylcbiAge1xuICAgIFhbaSA+Pj4gMl0gXj0gKHN0cnB0ci5jaGFyQ29kZUF0KGorKykgJiAyNTUpIDw8ICg4ICogKGkgJiAzKSk7XG4gIH1cblxuICBYWyhsc3dsZW4gPj4+IDIpICYgMTVdIF49IDEgPDwgKDggKiAobHN3bGVuICYgMykgKyA3KTtcblxuICBpZiAoKGxzd2xlbiAmIDYzKSA+IDU1KVxuICB7XG4gICAgY29tcHJlc3MoTURidWYsIFgpO1xuICAgIHZhciBYID0gbmV3IEFycmF5KDE2KTtcbiAgICB6ZXJvWChYKTtcbiAgfVxuXG4gIFhbMTRdID0gbHN3bGVuIDw8IDM7XG4gIFhbMTVdID0gKGxzd2xlbiA+Pj4gMjkpIHwgKG1zd2xlbiA8PCAzKTtcblxuICBjb21wcmVzcyhNRGJ1ZiwgWCk7XG59XG5cbmZ1bmN0aW9uIEJZVEVTX1RPX0RXT1JEKGZvdXJDaGFycylcbntcbiAgdmFyIHRtcCAgPSAoZm91ckNoYXJzLmNoYXJDb2RlQXQoMykgJiAyNTUpIDw8IDI0O1xuICB0bXAgICB8PSAoZm91ckNoYXJzLmNoYXJDb2RlQXQoMikgJiAyNTUpIDw8IDE2O1xuICB0bXAgICB8PSAoZm91ckNoYXJzLmNoYXJDb2RlQXQoMSkgJiAyNTUpIDw8IDg7XG4gIHRtcCAgIHw9IChmb3VyQ2hhcnMuY2hhckNvZGVBdCgwKSAmIDI1NSk7ICBcblxuICByZXR1cm4gdG1wO1xufVxuXG5mdW5jdGlvbiBSTUQobWVzc2FnZSlcbntcbiAgdmFyIE1EYnVmICAgPSBuZXcgQXJyYXkoUk1Ec2l6ZSAvIDMyKTtcbiAgdmFyIGhhc2hjb2RlICAgPSBuZXcgQXJyYXkoUk1Ec2l6ZSAvIDgpO1xuICB2YXIgbGVuZ3RoOyAgXG4gIHZhciBuYnl0ZXM7XG5cbiAgTURpbml0KE1EYnVmKTtcbiAgbGVuZ3RoID0gbWVzc2FnZS5sZW5ndGg7XG5cbiAgdmFyIFggPSBuZXcgQXJyYXkoMTYpO1xuICB6ZXJvWChYKTtcblxuICB2YXIgaj0wO1xuICBmb3IgKHZhciBuYnl0ZXM9bGVuZ3RoOyBuYnl0ZXMgPiA2MzsgbmJ5dGVzIC09IDY0KVxuICB7XG4gICAgZm9yICh2YXIgaT0wOyBpIDwgMTY7IGkrKylcbiAgICB7XG4gICAgICBYW2ldID0gQllURVNfVE9fRFdPUkQobWVzc2FnZS5zdWJzdHIoaiwgNCkpO1xuICAgICAgaiArPSA0O1xuICAgIH1cbiAgICBjb21wcmVzcyhNRGJ1ZiwgWCk7XG4gIH1cblxuICBNRGZpbmlzaChNRGJ1ZiwgbWVzc2FnZS5zdWJzdHIoaiksIGxlbmd0aCwgMCk7XG5cbiAgZm9yICh2YXIgaT0wOyBpIDwgUk1Ec2l6ZSAvIDg7IGkgKz0gNClcbiAge1xuICAgIGhhc2hjb2RlW2ldICAgPSAgTURidWZbaSA+Pj4gMl0gICAmIDI1NTtcbiAgICBoYXNoY29kZVtpKzFdID0gKE1EYnVmW2kgPj4+IDJdID4+PiA4KSAgICYgMjU1O1xuICAgIGhhc2hjb2RlW2krMl0gPSAoTURidWZbaSA+Pj4gMl0gPj4+IDE2KSAmIDI1NTtcbiAgICBoYXNoY29kZVtpKzNdID0gKE1EYnVmW2kgPj4+IDJdID4+PiAyNCkgJiAyNTU7XG4gIH1cblxuICByZXR1cm4gaGFzaGNvZGU7XG59XG5cblxuZnVuY3Rpb24gUk1Ec3RyaW5nKG1lc3NhZ2UpXG57XG4gIHZhciBoYXNoY29kZSA9IFJNRChtZXNzYWdlKTtcbiAgdmFyIHJldFN0cmluZyA9IFwiXCI7XG5cbiAgZm9yICh2YXIgaT0wOyBpIDwgUk1Ec2l6ZS84OyBpKyspXG4gIHtcbiAgICByZXRTdHJpbmcgKz0gU3RyaW5nLmZyb21DaGFyQ29kZShoYXNoY29kZVtpXSk7XG4gIH0gIFxuXG4gIHJldHVybiByZXRTdHJpbmc7ICBcbn1cblxubW9kdWxlLmV4cG9ydHMgPSBSTURzdHJpbmc7XG4iLCIvLyBHUEc0QnJvd3NlcnMgLSBBbiBPcGVuUEdQIGltcGxlbWVudGF0aW9uIGluIGphdmFzY3JpcHRcbi8vIENvcHlyaWdodCAoQykgMjAxMSBSZWN1cml0eSBMYWJzIEdtYkhcbi8vIFxuLy8gVGhpcyBsaWJyYXJ5IGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vclxuLy8gbW9kaWZ5IGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIExlc3NlciBHZW5lcmFsIFB1YmxpY1xuLy8gTGljZW5zZSBhcyBwdWJsaXNoZWQgYnkgdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyXG4vLyB2ZXJzaW9uIDIuMSBvZiB0aGUgTGljZW5zZSwgb3IgKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbi8vIFxuLy8gVGhpcyBsaWJyYXJ5IGlzIGRpc3RyaWJ1dGVkIGluIHRoZSBob3BlIHRoYXQgaXQgd2lsbCBiZSB1c2VmdWwsXG4vLyBidXQgV0lUSE9VVCBBTlkgV0FSUkFOVFk7IHdpdGhvdXQgZXZlbiB0aGUgaW1wbGllZCB3YXJyYW50eSBvZlxuLy8gTUVSQ0hBTlRBQklMSVRZIG9yIEZJVE5FU1MgRk9SIEEgUEFSVElDVUxBUiBQVVJQT1NFLiAgU2VlIHRoZSBHTlVcbi8vIExlc3NlciBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGZvciBtb3JlIGRldGFpbHMuXG4vLyBcbi8vIFlvdSBzaG91bGQgaGF2ZSByZWNlaXZlZCBhIGNvcHkgb2YgdGhlIEdOVSBMZXNzZXIgR2VuZXJhbCBQdWJsaWNcbi8vIExpY2Vuc2UgYWxvbmcgd2l0aCB0aGlzIGxpYnJhcnk7IGlmIG5vdCwgd3JpdGUgdG8gdGhlIEZyZWUgU29mdHdhcmVcbi8vIEZvdW5kYXRpb24sIEluYy4sIDUxIEZyYW5rbGluIFN0cmVldCwgRmlmdGggRmxvb3IsIEJvc3RvbiwgTUEgIDAyMTEwLTEzMDEgIFVTQVxuXG52YXIgVXRpbCA9IGZ1bmN0aW9uKCkge1xuXG4gICAgdGhpcy5lbWFpbFJlZ0V4ID0gL1thLXowLTkhIyQlJicqKy89P15fYHt8fX4tXSsoPzpcXC5bYS16MC05ISMkJSYnKisvPT9eX2B7fH1+LV0rKSpAKD86W2EtejAtOV0oPzpbYS16MC05LV0qW2EtejAtOV0pP1xcLikrW2EtejAtOV0oPzpbYS16MC05LV0qW2EtejAtOV0pPy87XG5cdFxuXHR0aGlzLmRlYnVnID0gZmFsc2U7XG5cblx0dGhpcy5oZXhkdW1wID0gZnVuY3Rpb24oc3RyKSB7XG5cdCAgICB2YXIgcj1bXTtcblx0ICAgIHZhciBlPXN0ci5sZW5ndGg7XG5cdCAgICB2YXIgYz0wO1xuXHQgICAgdmFyIGg7XG5cdCAgICB2YXIgaSA9IDA7XG5cdCAgICB3aGlsZShjPGUpe1xuXHQgICAgICAgIGg9c3RyLmNoYXJDb2RlQXQoYysrKS50b1N0cmluZygxNik7XG5cdCAgICAgICAgd2hpbGUoaC5sZW5ndGg8MikgaD1cIjBcIitoO1xuXHQgICAgICAgIHIucHVzaChcIiBcIitoKTtcblx0ICAgICAgICBpKys7XG5cdCAgICAgICAgaWYgKGkgJSAzMiA9PSAwKVxuXHQgICAgICAgIFx0ci5wdXNoKFwiXFxuICAgICAgICAgICBcIik7XG5cdCAgICB9XG5cdCAgICByZXR1cm4gci5qb2luKCcnKTtcblx0fTtcblx0XG5cdC8qKlxuXHQgKiBDcmVhdGUgaGV4c3RyaW5nIGZyb20gYSBiaW5hcnlcblx0ICogQHBhcmFtIHtTdHJpbmd9IHN0ciBTdHJpbmcgdG8gY29udmVydFxuXHQgKiBAcmV0dXJuIHtTdHJpbmd9IFN0cmluZyBjb250YWluaW5nIHRoZSBoZXhhZGVjaW1hbCB2YWx1ZXNcblx0ICovXG5cdHRoaXMuaGV4c3RyZHVtcCA9IGZ1bmN0aW9uKHN0cikge1xuXHRcdGlmIChzdHIgPT0gbnVsbClcblx0XHRcdHJldHVybiBcIlwiO1xuXHQgICAgdmFyIHI9W107XG5cdCAgICB2YXIgZT1zdHIubGVuZ3RoO1xuXHQgICAgdmFyIGM9MDtcblx0ICAgIHZhciBoO1xuXHQgICAgd2hpbGUoYzxlKXtcblx0ICAgICAgICBoPXN0cltjKytdLmNoYXJDb2RlQXQoKS50b1N0cmluZygxNik7XG5cdCAgICAgICAgd2hpbGUoaC5sZW5ndGg8MikgaD1cIjBcIitoO1xuXHQgICAgICAgIHIucHVzaChcIlwiK2gpO1xuXHQgICAgfVxuXHQgICAgcmV0dXJuIHIuam9pbignJyk7XG5cdH07XG5cdFxuXHQvKipcblx0ICogQ3JlYXRlIGJpbmFyeSBzdHJpbmcgZnJvbSBhIGhleCBlbmNvZGVkIHN0cmluZ1xuXHQgKiBAcGFyYW0ge1N0cmluZ30gc3RyIEhleCBzdHJpbmcgdG8gY29udmVydFxuXHQgKiBAcmV0dXJuIHtTdHJpbmd9IFN0cmluZyBjb250YWluaW5nIHRoZSBiaW5hcnkgdmFsdWVzXG5cdCAqL1xuXHR0aGlzLmhleDJiaW4gPSBmdW5jdGlvbihoZXgpIHtcblx0ICAgIHZhciBzdHIgPSAnJztcblx0ICAgIGZvciAodmFyIGkgPSAwOyBpIDwgaGV4Lmxlbmd0aDsgaSArPSAyKVxuXHQgICAgICAgIHN0ciArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKHBhcnNlSW50KGhleC5zdWJzdHIoaSwgMiksIDE2KSk7XG5cdCAgICByZXR1cm4gc3RyO1xuXHR9O1xuXHRcblx0LyoqXG5cdCAqIENyZWF0aW5nIGEgaGV4IHN0cmluZyBmcm9tIGFuIGJpbmFyeSBhcnJheSBvZiBpbnRlZ2VycyAoMC4uMjU1KVxuXHQgKiBAcGFyYW0ge1N0cmluZ30gc3RyIEFycmF5IG9mIGJ5dGVzIHRvIGNvbnZlcnRcblx0ICogQHJldHVybiB7U3RyaW5nfSBIZXhhZGVjaW1hbCByZXByZXNlbnRhdGlvbiBvZiB0aGUgYXJyYXlcblx0ICovXG5cdHRoaXMuaGV4aWR1bXAgPSBmdW5jdGlvbihzdHIpIHtcblx0ICAgIHZhciByPVtdO1xuXHQgICAgdmFyIGU9c3RyLmxlbmd0aDtcblx0ICAgIHZhciBjPTA7XG5cdCAgICB2YXIgaDtcblx0ICAgIHdoaWxlKGM8ZSl7XG5cdCAgICAgICAgaD1zdHJbYysrXS50b1N0cmluZygxNik7XG5cdCAgICAgICAgd2hpbGUoaC5sZW5ndGg8MikgaD1cIjBcIitoO1xuXHQgICAgICAgIHIucHVzaChcIlwiK2gpO1xuXHQgICAgfVxuXHQgICAgcmV0dXJuIHIuam9pbignJyk7XG5cdH07XG5cblxuXHQvKipcblx0ICogQ29udmVydCBhIG5hdGl2ZSBqYXZhc2NyaXB0IHN0cmluZyB0byBhIHN0cmluZyBvZiB1dGY4IGJ5dGVzXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBzdHIgVGhlIHN0cmluZyB0byBjb252ZXJ0XG5cdCAqIEByZXR1cm4ge1N0cmluZ30gQSB2YWxpZCBzcXVlbmNlIG9mIHV0ZjggYnl0ZXNcblx0ICovXG5cdHRoaXMuZW5jb2RlX3V0ZjggPSBmdW5jdGlvbihzdHIpIHtcblx0XHRyZXR1cm4gdW5lc2NhcGUoZW5jb2RlVVJJQ29tcG9uZW50KHN0cikpO1xuXHR9O1xuXG5cdC8qKlxuXHQgKiBDb252ZXJ0IGEgc3RyaW5nIG9mIHV0ZjggYnl0ZXMgdG8gYSBuYXRpdmUgamF2YXNjcmlwdCBzdHJpbmdcblx0ICogQHBhcmFtIHtTdHJpbmd9IHV0ZjggQSB2YWxpZCBzcXVlbmNlIG9mIHV0ZjggYnl0ZXNcblx0ICogQHJldHVybiB7U3RyaW5nfSBBIG5hdGl2ZSBqYXZhc2NyaXB0IHN0cmluZ1xuXHQgKi9cblx0dGhpcy5kZWNvZGVfdXRmOCA9IGZ1bmN0aW9uKHV0ZjgpIHtcblx0XHRyZXR1cm4gZGVjb2RlVVJJQ29tcG9uZW50KGVzY2FwZSh1dGY4KSk7XG5cdH07XG5cblx0dmFyIHN0cjJiaW4gPSBmdW5jdGlvbihzdHIsIHJlc3VsdCkge1xuXHRcdGZvciAodmFyIGkgPSAwOyBpIDwgc3RyLmxlbmd0aDsgaSsrKSB7XG5cdFx0XHRyZXN1bHRbaV0gPSBzdHIuY2hhckNvZGVBdChpKTtcblx0XHR9XG5cblx0XHRyZXR1cm4gcmVzdWx0O1xuXHR9O1xuXHRcblx0dmFyIGJpbjJzdHIgPSBmdW5jdGlvbihiaW4pIHtcblx0XHR2YXIgcmVzdWx0ID0gW107XG5cblx0XHRmb3IgKHZhciBpID0gMDsgaSA8IGJpbi5sZW5ndGg7IGkrKykge1xuXHRcdFx0cmVzdWx0LnB1c2goU3RyaW5nLmZyb21DaGFyQ29kZShiaW5baV0pKTtcblx0XHR9XG5cblx0XHRyZXR1cm4gcmVzdWx0LmpvaW4oJycpO1xuXHR9O1xuXG5cdC8qKlxuXHQgKiBDb252ZXJ0IGEgc3RyaW5nIHRvIGFuIGFycmF5IG9mIGludGVnZXJzKDAuMjU1KVxuXHQgKiBAcGFyYW0ge1N0cmluZ30gc3RyIFN0cmluZyB0byBjb252ZXJ0XG5cdCAqIEByZXR1cm4ge0ludGVnZXJbXX0gQW4gYXJyYXkgb2YgKGJpbmFyeSkgaW50ZWdlcnNcblx0ICovXG5cdHRoaXMuc3RyMmJpbiA9IGZ1bmN0aW9uKHN0cikgeyBcblx0XHRyZXR1cm4gc3RyMmJpbihzdHIsIG5ldyBBcnJheShzdHIubGVuZ3RoKSk7XG5cdH07XG5cdFxuXHRcblx0LyoqXG5cdCAqIENvbnZlcnQgYW4gYXJyYXkgb2YgaW50ZWdlcnMoMC4yNTUpIHRvIGEgc3RyaW5nIFxuXHQgKiBAcGFyYW0ge0ludGVnZXJbXX0gYmluIEFuIGFycmF5IG9mIChiaW5hcnkpIGludGVnZXJzIHRvIGNvbnZlcnRcblx0ICogQHJldHVybiB7U3RyaW5nfSBUaGUgc3RyaW5nIHJlcHJlc2VudGF0aW9uIG9mIHRoZSBhcnJheVxuXHQgKi9cblx0dGhpcy5iaW4yc3RyID0gYmluMnN0cjtcblx0XG5cdC8qKlxuXHQgKiBDb252ZXJ0IGEgc3RyaW5nIHRvIGEgVWludDhBcnJheVxuXHQgKiBAcGFyYW0ge1N0cmluZ30gc3RyIFN0cmluZyB0byBjb252ZXJ0XG5cdCAqIEByZXR1cm4ge1VpbnQ4QXJyYXl9IFRoZSBhcnJheSBvZiAoYmluYXJ5KSBpbnRlZ2Vyc1xuXHQgKi9cblx0dGhpcy5zdHIyVWludDhBcnJheSA9IGZ1bmN0aW9uKHN0cikgeyBcblx0XHRyZXR1cm4gc3RyMmJpbihzdHIsIG5ldyBVaW50OEFycmF5KG5ldyBBcnJheUJ1ZmZlcihzdHIubGVuZ3RoKSkpOyBcblx0fTtcblx0XG5cdC8qKlxuXHQgKiBDb252ZXJ0IGEgVWludDhBcnJheSB0byBhIHN0cmluZy4gVGhpcyBjdXJyZW50bHkgZnVuY3Rpb25zIFxuXHQgKiB0aGUgc2FtZSBhcyBiaW4yc3RyLiBcblx0ICogQHBhcmFtIHtVaW50OEFycmF5fSBiaW4gQW4gYXJyYXkgb2YgKGJpbmFyeSkgaW50ZWdlcnMgdG8gY29udmVydFxuXHQgKiBAcmV0dXJuIHtTdHJpbmd9IFN0cmluZyByZXByZXNlbnRhdGlvbiBvZiB0aGUgYXJyYXlcblx0ICovXG5cdHRoaXMuVWludDhBcnJheTJzdHIgPSBiaW4yc3RyO1xuXHRcblx0LyoqXG5cdCAqIENhbGN1bGF0ZXMgYSAxNmJpdCBzdW0gb2YgYSBzdHJpbmcgYnkgYWRkaW5nIGVhY2ggY2hhcmFjdGVyIFxuXHQgKiBjb2RlcyBtb2R1bHVzIDY1NTM1XG5cdCAqIEBwYXJhbSB7U3RyaW5nfSB0ZXh0IFN0cmluZyB0byBjcmVhdGUgYSBzdW0gb2Zcblx0ICogQHJldHVybiB7SW50ZWdlcn0gQW4gaW50ZWdlciBjb250YWluaW5nIHRoZSBzdW0gb2YgYWxsIGNoYXJhY3RlciBcblx0ICogY29kZXMgJSA2NTUzNVxuXHQgKi9cblx0dGhpcy5jYWxjX2NoZWNrc3VtID0gZnVuY3Rpb24odGV4dCkge1xuXHRcdHZhciBjaGVja3N1bSA9IHsgIHM6IDAsIGFkZDogZnVuY3Rpb24gKHNhZGQpIHsgdGhpcy5zID0gKHRoaXMucyArIHNhZGQpICUgNjU1MzY7IH19O1xuXHRcdGZvciAodmFyIGkgPSAwOyBpIDwgdGV4dC5sZW5ndGg7IGkrKykge1xuXHRcdFx0Y2hlY2tzdW0uYWRkKHRleHQuY2hhckNvZGVBdChpKSk7XG5cdFx0fVxuXHRcdHJldHVybiBjaGVja3N1bS5zO1xuXHR9O1xuXHRcblx0LyoqXG5cdCAqIEhlbHBlciBmdW5jdGlvbiB0byBwcmludCBhIGRlYnVnIG1lc3NhZ2UuIERlYnVnIFxuXHQgKiBtZXNzYWdlcyBhcmUgb25seSBwcmludGVkIGlmXG5cdCAqIG9wZW5wZ3AuY29uZmlnLmRlYnVnIGlzIHNldCB0byB0cnVlLiBUaGUgY2FsbGluZ1xuXHQgKiBKYXZhc2NyaXB0IGNvbnRleHQgTVVTVCBkZWZpbmVcblx0ICogYSBcInNob3dNZXNzYWdlcyh0ZXh0KVwiIGZ1bmN0aW9uLiBMaW5lIGZlZWRzICgnXFxuJylcblx0ICogYXJlIGF1dG9tYXRpY2FsbHkgY29udmVydGVkIHRvIEhUTUwgbGluZSBmZWVkcyAnPGJyLz4nXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBzdHIgU3RyaW5nIG9mIHRoZSBkZWJ1ZyBtZXNzYWdlXG5cdCAqIEByZXR1cm4ge1N0cmluZ30gQW4gSFRNTCB0dCBlbnRpdHkgY29udGFpbmluZyBhIHBhcmFncmFwaCB3aXRoIGEgXG5cdCAqIHN0eWxlIGF0dHJpYnV0ZSB3aGVyZSB0aGUgZGVidWcgbWVzc2FnZSBpcyBIVE1MZW5jb2RlZCBpbi4gXG5cdCAqL1xuXHR0aGlzLnByaW50X2RlYnVnID0gZnVuY3Rpb24oc3RyKSB7XG5cdFx0aWYgKHRoaXMuZGVidWcpIHtcblx0XHRcdGNvbnNvbGUubG9nKHN0cik7XG5cdFx0fVxuXHR9O1xuXHRcblx0LyoqXG5cdCAqIEhlbHBlciBmdW5jdGlvbiB0byBwcmludCBhIGRlYnVnIG1lc3NhZ2UuIERlYnVnIFxuXHQgKiBtZXNzYWdlcyBhcmUgb25seSBwcmludGVkIGlmXG5cdCAqIG9wZW5wZ3AuY29uZmlnLmRlYnVnIGlzIHNldCB0byB0cnVlLiBUaGUgY2FsbGluZ1xuXHQgKiBKYXZhc2NyaXB0IGNvbnRleHQgTVVTVCBkZWZpbmVcblx0ICogYSBcInNob3dNZXNzYWdlcyh0ZXh0KVwiIGZ1bmN0aW9uLiBMaW5lIGZlZWRzICgnXFxuJylcblx0ICogYXJlIGF1dG9tYXRpY2FsbHkgY29udmVydGVkIHRvIEhUTUwgbGluZSBmZWVkcyAnPGJyLz4nXG5cdCAqIERpZmZlcmVudCB0aGFuIHByaW50X2RlYnVnIGJlY2F1c2Ugd2lsbCBjYWxsIGhleHN0cmR1bXAgaWZmIG5lY2Vzc2FyeS5cblx0ICogQHBhcmFtIHtTdHJpbmd9IHN0ciBTdHJpbmcgb2YgdGhlIGRlYnVnIG1lc3NhZ2Vcblx0ICogQHJldHVybiB7U3RyaW5nfSBBbiBIVE1MIHR0IGVudGl0eSBjb250YWluaW5nIGEgcGFyYWdyYXBoIHdpdGggYSBcblx0ICogc3R5bGUgYXR0cmlidXRlIHdoZXJlIHRoZSBkZWJ1ZyBtZXNzYWdlIGlzIEhUTUxlbmNvZGVkIGluLiBcblx0ICovXG5cdHRoaXMucHJpbnRfZGVidWdfaGV4c3RyX2R1bXAgPSBmdW5jdGlvbihzdHIsc3RyVG9IZXgpIHtcblx0XHRpZiAodGhpcy5kZWJ1Zykge1xuXHRcdFx0c3RyID0gc3RyICsgdGhpcy5oZXhzdHJkdW1wKHN0clRvSGV4KTtcblx0XHRcdGNvbnNvbGUubG9nKHN0cik7XG5cdFx0fVxuXHR9O1xuXHRcblx0LyoqXG5cdCAqIEhlbHBlciBmdW5jdGlvbiB0byBwcmludCBhbiBlcnJvciBtZXNzYWdlLiBcblx0ICogVGhlIGNhbGxpbmcgSmF2YXNjcmlwdCBjb250ZXh0IE1VU1QgZGVmaW5lXG5cdCAqIGEgXCJzaG93TWVzc2FnZXModGV4dClcIiBmdW5jdGlvbi4gTGluZSBmZWVkcyAoJ1xcbicpXG5cdCAqIGFyZSBhdXRvbWF0aWNhbGx5IGNvbnZlcnRlZCB0byBIVE1MIGxpbmUgZmVlZHMgJzxici8+J1xuXHQgKiBAcGFyYW0ge1N0cmluZ30gc3RyIFN0cmluZyBvZiB0aGUgZXJyb3IgbWVzc2FnZVxuXHQgKiBAcmV0dXJuIHtTdHJpbmd9IEEgSFRNTCBwYXJhZ3JhcGggZW50aXR5IHdpdGggYSBzdHlsZSBhdHRyaWJ1dGUgXG5cdCAqIGNvbnRhaW5pbmcgdGhlIEhUTUwgZW5jb2RlZCBlcnJvciBtZXNzYWdlXG5cdCAqL1xuXHR0aGlzLnByaW50X2Vycm9yID0gZnVuY3Rpb24oc3RyKSB7XG5cdFx0aWYodGhpcy5kZWJ1Zylcblx0XHRcdHRocm93IHN0cjtcblx0XHRjb25zb2xlLmxvZyhzdHIpO1xuXHR9O1xuXHRcblx0LyoqXG5cdCAqIEhlbHBlciBmdW5jdGlvbiB0byBwcmludCBhbiBpbmZvIG1lc3NhZ2UuIFxuXHQgKiBUaGUgY2FsbGluZyBKYXZhc2NyaXB0IGNvbnRleHQgTVVTVCBkZWZpbmVcblx0ICogYSBcInNob3dNZXNzYWdlcyh0ZXh0KVwiIGZ1bmN0aW9uLiBMaW5lIGZlZWRzICgnXFxuJylcblx0ICogYXJlIGF1dG9tYXRpY2FsbHkgY29udmVydGVkIHRvIEhUTUwgbGluZSBmZWVkcyAnPGJyLz4nLlxuXHQgKiBAcGFyYW0ge1N0cmluZ30gc3RyIFN0cmluZyBvZiB0aGUgaW5mbyBtZXNzYWdlXG5cdCAqIEByZXR1cm4ge1N0cmluZ30gQSBIVE1MIHBhcmFncmFwaCBlbnRpdHkgd2l0aCBhIHN0eWxlIGF0dHJpYnV0ZSBcblx0ICogY29udGFpbmluZyB0aGUgSFRNTCBlbmNvZGVkIGluZm8gbWVzc2FnZVxuXHQgKi9cblx0dGhpcy5wcmludF9pbmZvID0gZnVuY3Rpb24oc3RyKSB7XG5cdFx0aWYodGhpcy5kZWJ1Zylcblx0XHRcdGNvbnNvbGUubG9nKHN0cik7XG5cdH07XG5cdFxuXHR0aGlzLnByaW50X3dhcm5pbmcgPSBmdW5jdGlvbihzdHIpIHtcblx0XHRjb25zb2xlLmxvZyhzdHIpO1xuXHR9O1xuXHRcblx0dGhpcy5nZXRMZWZ0TkJpdHMgPSBmdW5jdGlvbiAoc3RyaW5nLCBiaXRjb3VudCkge1xuXHRcdHZhciByZXN0ID0gYml0Y291bnQgJSA4O1xuXHRcdGlmIChyZXN0ID09IDApXG5cdFx0XHRyZXR1cm4gc3RyaW5nLnN1YnN0cmluZygwLCBiaXRjb3VudCAvIDgpO1xuXHRcdHZhciBieXRlcyA9IChiaXRjb3VudCAtIHJlc3QpIC8gOCArMTtcblx0XHR2YXIgcmVzdWx0ID0gc3RyaW5nLnN1YnN0cmluZygwLCBieXRlcyk7XG5cdFx0cmV0dXJuIHRoaXMuc2hpZnRSaWdodChyZXN1bHQsIDgtcmVzdCk7IC8vICtTdHJpbmcuZnJvbUNoYXJDb2RlKHN0cmluZy5jaGFyQ29kZUF0KGJ5dGVzIC0xKSA8PCAoOC1yZXN0KSAmIDB4RkYpO1xuXHR9O1xuXG5cdC8qKlxuXHQgKiBTaGlmdGluZyBhIHN0cmluZyB0byBuIGJpdHMgcmlnaHRcblx0ICogQHBhcmFtIHtTdHJpbmd9IHZhbHVlIFRoZSBzdHJpbmcgdG8gc2hpZnRcblx0ICogQHBhcmFtIHtJbnRlZ2VyfSBiaXRjb3VudCBBbW91bnQgb2YgYml0cyB0byBzaGlmdCAoTVVTVCBiZSBzbWFsbGVyIFxuXHQgKiB0aGFuIDkpXG5cdCAqIEByZXR1cm4ge1N0cmluZ30gUmVzdWx0aW5nIHN0cmluZy4gXG5cdCAqL1xuXHR0aGlzLnNoaWZ0UmlnaHQgPSBmdW5jdGlvbih2YWx1ZSwgYml0Y291bnQpIHtcblx0XHR2YXIgdGVtcCA9IHV0aWwuc3RyMmJpbih2YWx1ZSk7XG4gICAgICAgIGlmIChiaXRjb3VudCAlIDggIT0gMCkge1xuICAgICAgICBcdGZvciAodmFyIGkgPSB0ZW1wLmxlbmd0aC0xOyBpID49IDA7IGktLSkge1xuICAgICAgICBcdFx0dGVtcFtpXSA+Pj0gYml0Y291bnQgJSA4O1xuICAgICAgICBcdFx0aWYgKGkgPiAwKVxuICAgICAgICBcdFx0XHR0ZW1wW2ldIHw9ICh0ZW1wW2kgLSAxXSA8PCAoOCAtIChiaXRjb3VudCAlIDgpKSkgJiAweEZGO1xuICAgICAgICBcdH1cbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgXHRyZXR1cm4gdmFsdWU7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHV0aWwuYmluMnN0cih0ZW1wKTtcblx0fTtcblx0XG5cdC8qKlxuXHQgKiBSZXR1cm4gdGhlIGFsZ29yaXRobSB0eXBlIGFzIHN0cmluZ1xuXHQgKiBAcmV0dXJuIHtTdHJpbmd9IFN0cmluZyByZXByZXNlbnRpbmcgdGhlIG1lc3NhZ2UgdHlwZVxuXHQgKi9cblx0dGhpcy5nZXRfaGFzaEFsZ29yaXRobVN0cmluZyA9IGZ1bmN0aW9uKGFsZ28pIHtcblx0XHRzd2l0Y2goYWxnbykge1xuXHRcdGNhc2UgMTpcblx0XHRcdHJldHVybiBcIk1ENVwiO1xuXHRcdGNhc2UgMjpcblx0XHRcdHJldHVybiBcIlNIQTFcIjtcblx0XHRjYXNlIDM6XG5cdFx0XHRyZXR1cm4gXCJSSVBFTUQxNjBcIjtcblx0XHRjYXNlIDg6XG5cdFx0XHRyZXR1cm4gXCJTSEEyNTZcIjtcblx0XHRjYXNlIDk6XG5cdFx0XHRyZXR1cm4gXCJTSEEzODRcIjtcblx0XHRjYXNlIDEwOlxuXHRcdFx0cmV0dXJuIFwiU0hBNTEyXCI7XG5cdFx0Y2FzZSAxMTpcblx0XHRcdHJldHVybiBcIlNIQTIyNFwiO1xuXHRcdH1cblx0XHRyZXR1cm4gXCJ1bmtub3duXCI7XG5cdH07XG59O1xuXG4vKipcbiAqIGFuIGluc3RhbmNlIHRoYXQgc2hvdWxkIGJlIHVzZWQuIFxuICovXG5tb2R1bGUuZXhwb3J0cyA9IG5ldyBVdGlsKCk7XG4iXX0=
;