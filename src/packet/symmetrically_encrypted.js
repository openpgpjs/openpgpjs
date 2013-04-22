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

function openpgp_packet_symmetrically_encrypted() {
	this.tag = 9;
	this.encrypted = null;
	this.data = new openpgp_packetlist();
	this.algorithm = openpgp.symmetric.plaintext;

	

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

		this.data.read(decrypted);
	}

	this.encrypt = function(algo, key) {
		var data = this.data.write();

		this.encrypted = openpgp_crypto_symmetricEncrypt(
				openpgp_crypto_getPrefixRandom(algo), algo, key, data, true);
	}


	this.toString = function () {
		return '5.7.  Symmetrically Encrypted Data Packet (Tag 9)\n'
				+ '    Used symmetric algorithm: ' + this.algorithmType + '\n'
				+ '    encrypted data: Bytes ['
				+ util.hexstrdump(this.encryptedData) + ']\n';
	}
};
