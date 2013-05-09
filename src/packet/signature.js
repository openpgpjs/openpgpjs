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
 * @classdesc Implementation of the Signature Packet (Tag 2)
 * 
 * RFC4480 5.2:
 * A Signature packet describes a binding between some public key and
 * some data.  The most common signatures are a signature of a file or a
 * block of text, and a signature that is a certification of a User ID.
 */
function openpgp_packet_signature() {
	this.tag = 2;
	this.signatureType = null;
	this.created = null;
	this.signatureData = null;
	this.signatureExpirationTime = null;
	this.signatureNeverExpires = null;
	this.signedHashValue = null;
	this.mpi = null;
	this.publicKeyAlgorithm = null; 
	this.hashAlgorithm = null;
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

		this.version = bytes[i++].charCodeAt();
		// switch on version (3 and 4)
		switch (this.version) {
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
			this.created = openpgp_packet_time_read(bytes.substr(i, 4));
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
				var subpacket_length = openpgp_packet_number_read(
					bytes.substr(0, 2));

				var i = 2;

				// Hashed subpacket data set (zero or more subpackets)
				var subpacked_read = 0;
				while (i < 2 + subpacket_length) {

					var len = openpgp_packet.read_simple_length(bytes.substr(i));
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
			util.print_error("openpgp.packet.signature.js\n"+
				'unknown signature packet version'+this.version);
			break;
		}

		// Two-octet field holding left 16 bits of signed hash value.
		this.signedHashValue = bytes.substr(i, 2);
		i += 2;

		var mpicount = 0;
		// Algorithm-Specific Fields for RSA signatures:
		// 	    - multiprecision number (MPI) of RSA signature value m**d mod n.
		if (this.publicKeyAlgorithm > 0 && this.publicKeyAlgorithm < 4)
			mpicount = 1;
		//    Algorithm-Specific Fields for DSA signatures:
		//      - MPI of DSA value r.
		//      - MPI of DSA value s.
		else if (this.publicKeyAlgorithm == 17)
			mpicount = 2;
		
		this.mpi = [];
		for (var j = 0; j < mpicount; j++) {
			this.mpi[j] = new openpgp_type_mpi();
			i += this.mpi[j].read(bytes.substr(i));
		}
	}

	/**
	 * creates a string representation of a message signature packet (tag 2).
	 * This can be only used on text data
	 * @param {Integer} signature_type should be 1 (one) 
	 * @param {String} data data to be signed
	 * @param {openpgp_msg_privatekey} privatekey private key used to sign the message. (secmpi MUST be unlocked)
	 * @return {String} string representation of a signature packet
	 */
	function write_message_signature(signature_type, data, privatekey) {
		var publickey = privatekey.privateKeyPacket.publicKey;
		var hash_algo = privatekey.getPreferredSignatureHashAlgorithm();
		var result = String.fromCharCode(4); 
		result += String.fromCharCode(signature_type);
		result += String.fromCharCode(publickey.publicKeyAlgorithm);
		result += String.fromCharCode(hash_algo);
		var d = Math.round(new Date().getTime() / 1000);
		var datesubpacket = write_sub_signature_packet(2,""+
				String.fromCharCode((d >> 24) & 0xFF) + 
				String.fromCharCode((d >> 16) & 0xFF) +
				String.fromCharCode((d >> 8) & 0xFF) + 
				String.fromCharCode(d & 0xFF));
		var issuersubpacket = write_sub_signature_packet(16, privatekey.getKeyId());
		result += String.fromCharCode(((datesubpacket.length + issuersubpacket.length) >> 8) & 0xFF);
		result += String.fromCharCode ((datesubpacket.length + issuersubpacket.length) & 0xFF);
		result += datesubpacket;
		result += issuersubpacket;
		var trailer = '';
		
		trailer += String.fromCharCode(4);
		trailer += String.fromCharCode(0xFF);
		trailer += String.fromCharCode((result.length) >> 24);
		trailer += String.fromCharCode(((result.length) >> 16) & 0xFF);
		trailer += String.fromCharCode(((result.length) >> 8) & 0xFF);
		trailer += String.fromCharCode((result.length) & 0xFF);
		var result2 = String.fromCharCode(0);
		result2 += String.fromCharCode(0);
		var hash = openpgp_crypto_hashData(hash_algo, data+result+trailer);
		util.print_debug("DSA Signature is calculated with:|"+data+result+trailer+"|\n"+util.hexstrdump(data+result+trailer)+"\n hash:"+util.hexstrdump(hash));
		result2 += hash.charAt(0);
		result2 += hash.charAt(1);
		result2 += openpgp_crypto_signData(hash_algo,privatekey.privateKeyPacket.publicKey.publicKeyAlgorithm,
				publickey.mpi,
				privatekey.privateKeyPacket.secmpi,
				data+result+trailer);
		return {openpgp: (openpgp_packet.write_packet_header(2, (result+result2).length)+result + result2), 
				hash: util.get_hashAlgorithmString(hash_algo)};
	}
	/**
	 * creates a string representation of a sub signature packet (See RFC 4880 5.2.3.1)
	 * @param {Integer} type subpacket signature type. Signature types as described 
	 * in RFC4880 Section 5.2.3.2
	 * @param {String} data data to be included
	 * @return {String} a string-representation of a sub signature packet (See RFC 4880 5.2.3.1)
	 */
	function write_sub_signature_packet(type, data) {
		var result = "";
		result += openpgp_packet.encode_length(data.length+1);
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
			this.created = openpgp_packet_time_read(bytes.substr(mypos));
			break;
		case 3: // Signature Expiration Time
			var time = openpgp_packet_time_read(bytes.substr(mypos));

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
			var time = openpgp_packet_time_read(bytes.substr(mypos));

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

				mypos += 4;
				var m = openpgp_packet_number_read(bytes.substr(mypos, 2));
				mypos += 2
				var n = openpgp_packet_number_read(bytes.substr(mypos, 2));
				mypos += 2

				var name = bytes.substr(mypos, m),
					value = bytes.substr(mypos + m, n);

				this.notation[name] = value;
			}
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

			var len = openpgp_crypto_getHashByteLength(this.signatureTargetHashAlgorithm);

			this.signatureTargetHash = bytes.substr(mypos, len);
			break;
		case 32: // Embedded Signature
			this.embeddedSignature = new openpgp_packet_signature();
			this.embeddedSignature.read(bytes.substr(mypos));
			break;
		default:
			util.print_error("openpgp.packet.signature.js\n"+
				'unknown signature subpacket type '+type+" @:"+mypos+
				" subplen:"+subplen+" len:"+len);
			break;
		}
	};

	this.toSign = function(type, data) {
		var t = openpgp_packet_signature.type;

		switch(type) {
		case t.binary:
			return data.literal.get_data_bytes();

		case t.text:
			return toSign(t.binary, data)
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
				openpgp_packet_number_write(bytes.length, 4) +
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
			
			var bytes = data.key.write();

			return String.fromCharCode(0x99) +
				openpgp_packet_number_write(bytes.length, 2) +
				bytes;
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


	/**
	 * verifys the signature packet. Note: not signature types are implemented
	 * @param {String} data data which on the signature applies
	 * @param {openpgp_msg_privatekey} key the public key to verify the signature
	 * @return {boolean} True if message is verified, else false.
	 */
	this.verify = function(key, data) {

		var bytes = this.toSign(this.signatureType, data);

		// calculating the trailer
		var trailer = '';
		trailer += String.fromCharCode(this.version);
		trailer += String.fromCharCode(0xFF);
		trailer += openpgp_packet_number_write(this.signatureData.length, 4);

		this.verified = openpgp_crypto_verifySignature(this.publicKeyAlgorithm, 
			this.hashAlgorithm, this.mpi, key.mpi, 
			bytes + this.signatureData + trailer);

		return this.verified;
	}
}


/** One pass signature packet type
 * @enum {Integer} */
openpgp_packet_signature.type = {
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
}
	
