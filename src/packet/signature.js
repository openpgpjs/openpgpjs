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
	this.keyId = null;
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
	this.regular_expression = null;
	this.revocable = null;
	this.keyExpirationTime = null;
	this.keyNeverExpires = null;
	this.preferredSymmetricAlgorithms = null;
	this.revocationKeyClass = null;
	this.revocationKeyAlgorithm = null;
	this.revocationKeyFingerprint = null;
	this.issuerKeyId = null;
	this.notationFlags = null; 
	this.notationName = null;
	this.notationValue = null;
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
		var mypos = 0;

		this.version = bytes[mypos++].charCodeAt();
		// switch on version (3 and 4)
		switch (this.version) {
		case 3:
			// One-octet length of following hashed material. MUST be 5.
			if (bytes[mypos++].charCodeAt() != 5)
				util.print_debug("openpgp.packet.signature.js\n"+
					'invalid One-octet length of following hashed material.' +
					'MUST be 5. @:'+(mypos-1));

			var sigpos = mypos;
			// One-octet signature type.
			this.signatureType = bytes[mypos++].charCodeAt();

			// Four-octet creation time.
			this.created = openpgp_packet_parse_date(bytes.substr(mypos, 4));
			mypos += 4;
			
			// storing data appended to data which gets verified
			this.signatureData = bytes.substring(position, mypos);
			
			// Eight-octet Key ID of signer.
			this.keyId = bytes.substring(mypos, mypos +8);
			mypos += 8;

			// One-octet public-key algorithm.
			this.publicKeyAlgorithm = bytes[mypos++].charCodeAt();

			// One-octet hash algorithm.
			this.hashAlgorithm = bytes[mypos++].charCodeAt();

			// Two-octet field holding left 16 bits of signed hash value.
			this.signedHashValue = openpgp_packet_read_integer(bytes.substr(mypos, 2));
			mypos += 2;

			var mpicount = 0;
			// Algorithm-Specific Fields for RSA signatures:
			// 	    - multiprecision integer (MPI) of RSA signature value m**d mod n.
			if (this.publicKeyAlgorithm > 0 && this.publicKeyAlgorithm < 4)
				mpicount = 1;
			//    Algorithm-Specific Fields for DSA signatures:
			//      - MPI of DSA value r.
			//      - MPI of DSA value s.
			else if (this.publicKeyAlgorithm == 17)
				mpicount = 2;
			
			this.mpi = new Array();
			for (var i = 0; i < mpicount; i++) {
				this.mpi[i] = new openpgp_type_mpi();
				mypos += this.mpi[i].read(bytes.substr(mypos));
			}
		break;
		case 4:
			this.signatureType = bytes[mypos++].charCodeAt();
			this.publicKeyAlgorithm = bytes[mypos++].charCodeAt();
			this.hashAlgorithm = bytes[mypos++].charCodeAt();


			function subpackets(bytes, signed) {
				// Two-octet scalar octet count for following hashed subpacket
				// data.
				var subpacket_length = openpgp_packet_integer_read(
					bytes.substr(0, 2));

				var i = 2;

				// Hashed subpacket data set (zero or more subpackets)
				var subpacked_read = 0;
				while (subpacket_length != subpacked_read) {
					if (subpacket_length < subpacked_read) {
						util.print_debug("openpgp.packet.signature.js\n"+
							"hashed missed something: "+i+" c:"+
							subpacket_length+" l:"+subpacked_read);
					}

					var len = openpgp_packet.read_simple_length(bytes.substr(i));
					i += len.offset;

					// Since it is trivial to add data to the unhashed portion of the packet
					// we simply ignore all unauthenticated data.
					if(signed)
						this.read_sub_packet(bytes.substr(i, len));

					i += len.len;
				}
				
				i += subpacket_length;

				if(signed)
					this.signatureData = bytes.substring(0, i);

				return i;
			}
			
			mypos += subpackets(bytes.substr(mypos), true);
			mypos += subpackets(bytes.substr(mypos), false);

			// Two-octet field holding the left 16 bits of the signed hash
			// value.
			this.signedHashValue = (bytes[mypos++].charCodeAt() << 8) | bytes[mypos++].charCodeAt();

			// One or more multiprecision integers comprising the signature.
			// This portion is algorithm specific, as described above.
			var mpicount = 0;
			if (this.publicKeyAlgorithm > 0 && this.publicKeyAlgorithm < 4)
				mpicount = 1;
			else if (this.publicKeyAlgorithm == 17)
				mpicount = 2;
			
			this.mpi = new Array();
			for (var i = 0; i < mpicount; i++) {
				this.mpi[i] = new openpgp_type_mpi();
				if (this.mpi[i].read(bytes, mypos, (mypos-position)) != null && 
						!this.packetLength < (mypos-position)) {
					mypos += this.mpi[i].packetLength;
				} else {
			 		util.print_error('signature contains invalid MPI @:'+mypos);
				}
			}
			break;
		default:
			util.print_error("openpgp.packet.signature.js\n"+
				'unknown signature packet version'+this.version);
			break;
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
	 * @param {Integer} type subpacket signature type. Signature types as described in RFC4880 Section 5.2.3.2
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

		
		var type = bytes[mypos++].charCodeAt() & 0x7F;

		// subpacket type
		switch (type) {
		case 2: // Signature Creation Time
			this.created = openpgp_packet_read_date(bytes.substr(mypos));
			break;
		case 3: // Signature Expiration Time
			this.signatureExpirationTime =  (bytes[mypos++].charCodeAt() << 24)
					| (bytes[mypos++].charCodeAt() << 16) | (bytes[mypos++].charCodeAt() << 8)
					| bytes[mypos++].charCodeAt();
			this.signatureNeverExpires = (this.signature_expiration_time == 0);
			
			break;
		case 4: // Exportable Certification
			this.exportable = bytes[mypos++].charCodeAt() == 1;
			break;
		case 5: // Trust Signature
			this.trustLevel = bytes[mypos++].charCodeAt();
			this.trustAmount = bytes[mypos++].charCodeAt();
			break;
		case 6: // Regular Expression
			this.regular_expression = new String();
			for (var i = 0; i < subplen - 1; i++)
				this.regular_expression += (bytes[mypos++]);
			break;
		case 7: // Revocable
			this.revocable = bytes[mypos++].charCodeAt() == 1;
			break;
		case 9: // Key Expiration Time
			this.keyExpirationTime = (bytes[mypos++].charCodeAt() << 24)
					| (bytes[mypos++].charCodeAt() << 16) | (bytes[mypos++].charCodeAt() << 8)
					| bytes[mypos++].charCodeAt();
			this.keyNeverExpires = (this.keyExpirationTime == 0);
			break;
		case 11: // Preferred Symmetric Algorithms
			this.preferredSymmetricAlgorithms = new Array();
			for (var i = 0; i < subplen-1; i++) {
				this.preferredSymmetricAlgorithms = bytes[mypos++].charCodeAt();
			}
			break;
		case 12: // Revocation Key
			// (1 octet of class, 1 octet of public-key algorithm ID, 20
			// octets of
			// fingerprint)
			this.revocationKeyClass = bytes[mypos++].charCodeAt();
			this.revocationKeyAlgorithm = bytes[mypos++].charCodeAt();
			this.revocationKeyFingerprint = new Array();
			for ( var i = 0; i < 20; i++) {
				this.revocationKeyFingerprint = bytes[mypos++].charCodeAt();
			}
			break;
		case 16: // Issuer
			this.issuerKeyId = bytes.substring(mypos,mypos+8);
			mypos += 8;
			break;
		case 20: // Notation Data
			this.notationFlags = (bytes[mypos++].charCodeAt() << 24) | 
								 (bytes[mypos++].charCodeAt() << 16) |
								 (bytes[mypos++].charCodeAt() <<  8) | 
								 (bytes[mypos++].charCodeAt());
			var nameLength = (bytes[mypos++].charCodeAt() <<  8) | (bytes[mypos++].charCodeAt());
			var valueLength = (bytes[mypos++].charCodeAt() <<  8) | (bytes[mypos++].charCodeAt());
			this.notationName = "";
			for (var i = 0; i < nameLength; i++) {
				this.notationName += bytes[mypos++];
			}
			this.notationValue = "";
			for (var i = 0; i < valueLength; i++) {
				this.notationValue += bytes[mypos++];
			}
			break;
		case 21: // Preferred Hash Algorithms
			this.preferredHashAlgorithms = new Array();
			for (var i = 0; i < subplen-1; i++) {
				this.preferredHashAlgorithms = bytes[mypos++].charCodeAt();
			}
			break;
		case 22: // Preferred Compression Algorithms
			this.preferredCompressionAlgorithms = new Array();
			for ( var i = 0; i < subplen-1; i++) {
				this.preferredCompressionAlgorithms = bytes[mypos++].charCodeAt();
			}
			break;
		case 23: // Key Server Preferences
			this.keyServerPreferences = new Array();
			for ( var i = 0; i < subplen-1; i++) {
				this.keyServerPreferences = bytes[mypos++].charCodeAt();
			}
			break;
		case 24: // Preferred Key Server
			this.preferredKeyServer = new String();
			for ( var i = 0; i < subplen-1; i++) {
				this.preferredKeyServer += bytes[mypos++];
			}
			break;
		case 25: // Primary User ID
			this.isPrimaryUserID = bytes[mypos++] != 0;
			break;
		case 26: // Policy URI
			this.policyURI = new String();
			for ( var i = 0; i < subplen-1; i++) {
				this.policyURI += bytes[mypos++];
			}
			break;
		case 27: // Key Flags
			this.keyFlags = new Array();
			for ( var i = 0; i < subplen-1; i++) {
				this.keyFlags = bytes[mypos++].charCodeAt();
			}
			break;
		case 28: // Signer's User ID
			this.signersUserId += bytes.substr(mypos);
			break;
		case 29: // Reason for Revocation
			this.reasonForRevocationFlag = bytes[mypos++].charCodeAt();
			this.reasonForRevocationString = new String();
			for ( var i = 0; i < subplen -2; i++) {
				this.reasonForRevocationString += bytes[mypos++];
			}
			break;
		case 30: // Features
			// TODO: to be implemented
			return subplen+1;
		case 31: // Signature Target
			// (1 octet public-key algorithm, 1 octet hash algorithm, N octets hash)
			this.signatureTargetPublicKeyAlgorithm = bytes[mypos++].charCodeAt();
			this.signatureTargetHashAlgorithm = bytes[mypos++].charCodeAt();
			var signatureTargetHashAlgorithmLength = 0;
			switch(this.signatureTargetHashAlgorithm) {
			case  1: // - MD5 [HAC]                             "MD5"
			case  2: // - SHA-1 [FIPS180]                       "SHA1"
				signatureTargetHashAlgorithmLength = 20;
				break;
			case  3: // - RIPE-MD/160 [HAC]                     "RIPEMD160"
			case  8: // - SHA256 [FIPS180]                      "SHA256"
			case  9: // - SHA384 [FIPS180]                      "SHA384"
			case 10: // - SHA512 [FIPS180]                      "SHA512"
			case 11: // - SHA224 [FIPS180]                      "SHA224"
				break;
			// 100 to 110 - Private/Experimental algorithm
	    	default:
	    		util.print_error("openpgp.packet.signature.js\n"+"unknown signature target hash algorithm:"+this.signatureTargetHashAlgorithm);
	    		return null;
			}
			this.signatureTargetHash = new Array();
			for (var i = 0; i < signatureTargetHashAlgorithmLength; i++) {
				this.signatureTargetHash[i] = bytes[mypos++]; 
			}
		case 32: // Embedded Signature
			this.embeddedSignature = new openpgp_packet_signature();
			this.embeddedSignature.read_packet(bytes, mypos, len -(mypos-position));
			return ((mypos+ this.embeddedSignature.packetLength) - position);
			break;
		case 100: // Private or experimental
		case 101: // Private or experimental
		case 102: // Private or experimental
		case 103: // Private or experimental
		case 104: // Private or experimental
		case 105: // Private or experimental
		case 106: // Private or experimental
		case 107: // Private or experimental
		case 108: // Private or experimental
		case 109: // Private or experimental
		case 110: // Private or experimental
			util.print_error("openpgp.packet.signature.js\n"+'private or experimental signature subpacket type '+type+" @:"+mypos+" subplen:"+subplen+" len:"+len);
			return subplen+1;
			break;	
		case 0: // Reserved
		case 1: // Reserved
		case 8: // Reserved
		case 10: // Placeholder for backward compatibility
		case 13: // Reserved
		case 14: // Reserved
		case 15: // Reserved
		case 17: // Reserved
		case 18: // Reserved
		case 19: // Reserved
		default:
			util.print_error("openpgp.packet.signature.js\n"+'unknown signature subpacket type '+type+" @:"+mypos+" subplen:"+subplen+" len:"+len);
			return subplen+1;
			break;
		}
		return mypos -position;
	};
	/**
	 * verifys the signature packet. Note: not signature types are implemented
	 * @param {String} data data which on the signature applies
	 * @param {openpgp_msg_privatekey} key the public key to verify the signature
	 * @return {boolean} True if message is verified, else false.
	 */
	function verify(data, key) {
		// calculating the trailer
		var trailer = '';
		trailer += String.fromCharCode(this.version);
		trailer += String.fromCharCode(0xFF);
		trailer += String.fromCharCode(this.signatureData.length >> 24);
		trailer += String.fromCharCode((this.signatureData.length >> 16) &0xFF);
		trailer += String.fromCharCode((this.signatureData.length >> 8) &0xFF);
		trailer += String.fromCharCode(this.signatureData.length & 0xFF);
		switch(this.signatureType) {
		case 0: // 0x00: Signature of a binary document.
			if (this.version == 4) {
				this.verified = openpgp_crypto_verifySignature(this.publicKeyAlgorithm, this.hashAlgorithm, 
					this.mpi, key.obj.publicKeyPacket.mpi, data+this.signatureData+trailer);
			}
			break;

		case 1: // 0x01: Signature of a canonical text document.
			if (this.version == 4) {
				this.verified = openpgp_crypto_verifySignature(this.publicKeyAlgorithm, this.hashAlgorithm, 
					this.mpi, key.obj.publicKeyPacket.mpi, data+this.signatureData+trailer);
				return this.verified;
			}
			break;
				
		case 2: // 0x02: Standalone signature.
			// This signature is a signature of only its own subpacket contents.
			// It is calculated identically to a signature over a zero-lengh
			// binary document.  Note that it doesn't make sense to have a V3
			// standalone signature.
			if (this.version == 3) {
				this.verified = false;
				break;
				}
			
			this.verified = openpgp_crypto_verifySignature(this.publicKeyAlgorithm, this.hashAlgorithm, 
					this.mpi, key.obj.publicKeyPacket.mpi, this.signatureData+trailer);
			break;
		case 16:			
			// 0x10: Generic certification of a User ID and Public-Key packet.
			// The issuer of this certification does not make any particular
			// assertion as to how well the certifier has checked that the owner
			// of the key is in fact the person described by the User ID.
		case 17:
			// 0x11: Persona certification of a User ID and Public-Key packet.
			// The issuer of this certification has not done any verification of
			// the claim that the owner of this key is the User ID specified.
		case 18:
			// 0x12: Casual certification of a User ID and Public-Key packet.
			// The issuer of this certification has done some casual
			// verification of the claim of identity.
		case 19:
			// 0x13: Positive certification of a User ID and Public-Key packet.
			// The issuer of this certification has done substantial
			// verification of the claim of identity.
			// 
			// Most OpenPGP implementations make their "key signatures" as 0x10
			// certifications.  Some implementations can issue 0x11-0x13
			// certifications, but few differentiate between the types.
		case 48:
			// 0x30: Certification revocation signature
			// This signature revokes an earlier User ID certification signature
			// (signature class 0x10 through 0x13) or direct-key signature
			// (0x1F).  It should be issued by the same key that issued the
			// revoked signature or an authorized revocation key.  The signature
			// is computed over the same data as the certificate that it
			// revokes, and should have a later creation date than that
			// certificate.

			this.verified = openpgp_crypto_verifySignature(this.publicKeyAlgorithm, this.hashAlgorithm, 
					this.mpi, key.mpi, data+this.signatureData+trailer);
			break;
						
		case 24:
			// 0x18: Subkey Binding Signature
			// This signature is a statement by the top-level signing key that
			// indicates that it owns the subkey.  This signature is calculated
			// directly on the primary key and subkey, and not on any User ID or
			// other packets.  A signature that binds a signing subkey MUST have
			// an Embedded Signature subpacket in this binding signature that
			// contains a 0x19 signature made by the signing subkey on the
			// primary key and subkey.
			if (this.version == 3) {
				this.verified = false;
				break;
			}
			
			this.verified = openpgp_crypto_verifySignature(this.publicKeyAlgorithm, this.hashAlgorithm, 
					this.mpi, key.mpi, data+this.signatureData+trailer);
			break;
		case 25:
			// 0x19: Primary Key Binding Signature
			// This signature is a statement by a signing subkey, indicating
			// that it is owned by the primary key and subkey.  This signature
			// is calculated the same way as a 0x18 signature: directly on the
			// primary key and subkey, and not on any User ID or other packets.
			
			// When a signature is made over a key, the hash data starts with the
			// octet 0x99, followed by a two-octet length of the key, and then body
			// of the key packet.  (Note that this is an old-style packet header for
			// a key packet with two-octet length.)  A subkey binding signature
			// (type 0x18) or primary key binding signature (type 0x19) then hashes
			// the subkey using the same format as the main key (also using 0x99 as
			// the first octet).
		case 31:
			// 0x1F: Signature directly on a key
			// This signature is calculated directly on a key.  It binds the
			// information in the Signature subpackets to the key, and is
			// appropriate to be used for subpackets that provide information
			// about the key, such as the Revocation Key subpacket.  It is also
			// appropriate for statements that non-self certifiers want to make
			// about the key itself, rather than the binding between a key and a
			// name.
		case 32:
			// 0x20: Key revocation signature
			// The signature is calculated directly on the key being revoked.  A
			// revoked key is not to be used.  Only revocation signatures by the
			// key being revoked, or by an authorized revocation key, should be
			// considered valid revocation signatures.
		case 40:
			// 0x28: Subkey revocation signature
			// The signature is calculated directly on the subkey being revoked.
			// A revoked subkey is not to be used.  Only revocation signatures
			// by the top-level signature key that is bound to this subkey, or
			// by an authorized revocation key, should be considered valid
			// revocation signatures.
			this.verified = openpgp_crypto_verifySignature(this.publicKeyAlgorithm, this.hashAlgorithm, 
					this.mpi, key.mpi, data+this.signatureData+trailer);
			break;
			
			// Key revocation signatures (types 0x20 and 0x28)
			// hash only the key being revoked.
		case 64:
			// 0x40: Timestamp signature.
			// This signature is only meaningful for the timestamp contained in
			// it.
		case 80:
			//    0x50: Third-Party Confirmation signature.
			// This signature is a signature over some other OpenPGP Signature
			// packet(s).  It is analogous to a notary seal on the signed data.
			// A third-party signature SHOULD include Signature Target
			// subpacket(s) to give easy identification.  Note that we really do
			// mean SHOULD.  There are plausible uses for this (such as a blind
			// party that only sees the signature, not the key or source
			// document) that cannot include a target subpacket.
		default:
			util.print_error("openpgp.packet.signature.js\n"+"signature verification for type"+ this.signatureType+" not implemented");
			break;
		}
		return this.verified;
	}
	/**
	 * generates debug output (pretty print)
	 * @return {String} String which gives some information about the signature packet
	 */

	function toString () {
		if (this.version == 3) {
			var result = '5.2. Signature Packet (Tag 2)\n'+
	          "Packet Length:                     :"+this.packetLength+'\n'+
	          "Packet version:                    :"+this.version+'\n'+
	          "One-octet signature type           :"+this.signatureType+'\n'+
	          "Four-octet creation time.          :"+this.created+'\n'+
	         "Eight-octet Key ID of signer.       :"+util.hexidump(this.keyId)+'\n'+
	          "One-octet public-key algorithm.    :"+this.publicKeyAlgorithm+'\n'+
	          "One-octet hash algorithm.          :"+this.hashAlgorithm+'\n'+
	          "Two-octet field holding left\n" +
	          " 16 bits of signed hash value.     :"+this.signedHashValue+'\n';
		} else {
          var result = '5.2. Signature Packet (Tag 2)\n'+
          "Packet Length:                     :"+this.packetLength+'\n'+
          "Packet version:                    :"+this.version+'\n'+
          "One-octet signature type           :"+this.signatureType+'\n'+
          "One-octet public-key algorithm.    :"+this.publicKeyAlgorithm+'\n'+
          "One-octet hash algorithm.          :"+this.hashAlgorithm+'\n'+
          "Two-octet field holding left\n" +
          " 16 bits of signed hash value.     :"+this.signedHashValue+'\n'+
          "Signature Creation Time            :"+this.created+'\n'+
          "Signature Expiration Time          :"+this.signatureExpirationTime+'\n'+
          "Signature Never Expires            :"+this.signatureNeverExpires+'\n'+
          "Exportable Certification           :"+this.exportable+'\n'+
          "Trust Signature level:             :"+this.trustLevel+' amount'+this.trustAmount+'\n'+
          "Regular Expression                 :"+this.regular_expression+'\n'+
          "Revocable                          :"+this.revocable+'\n'+
          "Key Expiration Time                :"+this.keyExpirationTime+" "+this.keyNeverExpires+'\n'+
          "Preferred Symmetric Algorithms     :"+this.preferredSymmetricAlgorithms+'\n'+
          "Revocation Key"+'\n'+
          "   ( 1 octet of class,             :"+this.revocationKeyClass +'\n'+
          "     1 octet of public-key ID,     :" +this.revocationKeyAlgorithm+'\n'+
          "    20 octets of fingerprint)      :"+this.revocationKeyFingerprint+'\n'+
          "Issuer                             :"+util.hexstrdump(this.issuerKeyId)+'\n'+
          "Preferred Hash Algorithms          :"+this.preferredHashAlgorithms+'\n'+
          "Preferred Compression Alg.         :"+this.preferredCompressionAlgorithms+'\n'+
          "Key Server Preferences             :"+this.keyServerPreferences+'\n'+
          "Preferred Key Server               :"+this.preferredKeyServer+'\n'+
          "Primary User ID                    :"+this.isPrimaryUserID+'\n'+
          "Policy URI                         :"+this.policyURI+'\n'+
          "Key Flags                          :"+this.keyFlags+'\n'+
          "Signer's User ID                   :"+this.signersUserId+'\n'+
          "Notation                           :"+this.notationName+" = "+this.notationValue+"\n"+
          "Reason for Revocation\n"+
          "      Flag                         :"+this.reasonForRevocationFlag+'\n'+
          "      Reason                       :"+this.reasonForRevocationString+'\nMPI:\n';
		}
          for (var i = 0; i < this.mpi.length; i++) {
        	  result += this.mpi[i].toString();
          }
          return result;
     }

	/**
	 * gets the issuer key id of this signature
	 * @return {String} issuer key id as string (8bytes)
	 */
	function getIssuer() {
		 if (this.version == 4)
			 return this.issuerKeyId;
		 if (this.verions == 4)
			 return this.keyId;
		 return null;
	}

	/**
	 * Tries to get the corresponding public key out of the public keyring for the issuer created this signature
	 * @return {Object} {obj: [openpgp_msg_publickey], text: [String]} if found the public key will be returned. null otherwise
	 */
	function getIssuerKey() {
		 var result = null;
		 if (this.version == 4) {
			 result = openpgp.keyring.getPublicKeysForKeyId(this.issuerKeyId);
		 } else if (this.version == 3) {
			 result = openpgp.keyring.getPublicKeysForKeyId(this.keyId);
		 } else return null;
		 if (result.length == 0)
			 return null;
		 return result[0];
	}
	this.getIssuerKey = getIssuerKey;
	this.getIssuer = getIssuer;	 
	this.write_message_signature = write_message_signature;
	this.verify = verify;
    this.read_packet = read_packet;
    this.toString = toString;
}
