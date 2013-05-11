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

