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
