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
function openpgp_packet_sym_encrypted_session_key() {
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

