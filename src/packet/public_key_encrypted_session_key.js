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
function openpgp_packet_public_key_encrypted_session_key() {
	this.tag = 1;
	this.version = 3;

	this.public_key_id = new openpgp_type_keyid();
	this.public_key_algorithm = openpgp.publickey.rsa_encrypt_sign;

	this.symmetric_key = null;
	this.symmetric_algorithm = openpgp.symmetric.plaintext;

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
			util.print_error("openpgp.packet.encryptedsessionkey.js\n" + 'invalid length');
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
			this.encrypted[0].read(bytes, i, bytes.length - i);
			break;

		case openpgp.publickey.elgamal:
			this.encrypted = [];
			this.encrypted[0] = new openpgp_type_mpi();
			this.encrypted[0].read(bytes, i, bytes.length - i);
			i += this.encrypted[0].packetLength;
			this.encrypted[1] = new openpgp_type_mpi();
			this.encrypted[1].read(bytes, i, bytes.length - i);
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
			result += this.encrypted[i].toBin();
		}

		return result;
	}

	this.encrypt = function(public_key_mpi) {
		
		var data = String.fromCharCode(this.symmetric_algorithm);
		data += this.symmetric_key;
		var checksum = util.calc_checksum(this.symmetric_key);
		data += String.fromCharCode((checksum >> 8) & 0xFF);
		data += String.fromCharCode((checksum) & 0xFF);

		var mpi = new openpgp_type_mpi();

		var encrypted = openpgp_crypto_asymetricEncrypt(
			this.public_key_algorithm, 
			public_key_mpi,
			mpi.create(openpgp_encoding_eme_pkcs1_encode(data,
					public_key_mpi[0].mpiByteLength)));

		// TODO: fix this - make openpgp_crypto_ interfaces uniform
		this.encrypted = encrypted.map(function(k) {
				var mpi = new openpgp_type_mpi;
				var b = k.toMPI();
				mpi.read(b, 0, b.length);
				return mpi;
			});
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
	this.decrypt = function(public_key_mpi, private_key_mpi) {
		var result = openpgp_crypto_asymetricDecrypt(
				this.public_key_algorithm,
				public_key_mpi,
				private_key_mpi,
				this.encrypted).toMPI();

		var checksum = ((result.charCodeAt(result.length - 2) << 8) + result
				.charCodeAt(result.length - 1));

		var decoded = openpgp_encoding_eme_pkcs1_decode(
			result.substring(2, result.length - 2), 
			public_key_mpi[0].getByteLength());

		var key = decoded.substring(1);

		if(checksum != util.calc_checksum(key)) {
			util.print_error("Checksum mismatch");
		}
		else {
			this.symmetric_key = key;
			this.symmetric_algorithm = decoded.charCodeAt(0);
		}
	}

	/**
	 * Creates a string representation of this object (useful for debug
	 * purposes)
	 * 
	 * @return {String} The string containing a openpgp description
	 */
	this.toString = function() {
		var result = '5.1.  Public-Key Encrypted Session Key Packets (Tag 1)\n'
				+ '    KeyId:  '
				+ this.keyId.toString()
				+ '\n'
				+ '    length: '
				+ this.packetLength
				+ '\n'
				+ '    version:'
				+ this.version
				+ '\n'
				+ '    pubAlgUs:'
				+ this.publicKeyAlgorithmUsed + '\n';
		for ( var i = 0; i < this.encrypted.length; i++) {
			result += this.encrypted[i].toString();
		}
		return result;
	}
};

