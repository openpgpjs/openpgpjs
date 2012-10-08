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
function openpgp_packet_onepasssignature() {
	this.tagType = 4;
	this.version = null; // A one-octet version number.  The current version is 3.
	this.type == null; 	 // A one-octet signature type.  Signature types are described in RFC4880 Section 5.2.1.
	this.hashAlgorithm = null; 	   // A one-octet number describing the hash algorithm used. (See RFC4880 9.4)
	this.publicKeyAlgorithm = null;	     // A one-octet number describing the public-key algorithm used. (See RFC4880 9.1)
	this.signingKeyId = null; // An eight-octet number holding the Key ID of the signing key.
	this.flags = null; 	//  A one-octet number holding a flag showing whether the signature is nested.  A zero value indicates that the next packet is another One-Pass Signature packet that describes another signature to be applied to the same message data.

	/**
	 * parsing function for a one-pass signature packet (tag 4).
	 * @param {string} input payload of a tag 4 packet
	 * @param {integer} position position to start reading from the input string
	 * @param {integer} len length of the packet or the remaining length of input at position
	 * @return {openpgp_packet_encrypteddata} object representation
	 */
	function read_packet(input, position, len) {
		this.packetLength = len;
		var mypos = position;
		// A one-octet version number.  The current version is 3.
		this.version = input.charCodeAt(mypos++);

	     // A one-octet signature type.  Signature types are described in
	     //   Section 5.2.1.
		this.type = input.charCodeAt(mypos++);

	     // A one-octet number describing the hash algorithm used.
		this.hashAlgorithm = input.charCodeAt(mypos++);

	     // A one-octet number describing the public-key algorithm used.
		this.publicKeyAlgorithm = input.charCodeAt(mypos++);
	     // An eight-octet number holding the Key ID of the signing key.
		this.signingKeyId = new openpgp_type_keyid();
		this.signingKeyId.read_packet(input,mypos);
		mypos += 8;
		
	     // A one-octet number holding a flag showing whether the signature
	     //   is nested.  A zero value indicates that the next packet is
	     //   another One-Pass Signature packet that describes another
	     //   signature to be applied to the same message data.
		this.flags = input.charCodeAt(mypos++);
		return this;
	}

	/**
	 * creates a string representation of a one-pass signature packet
	 * @param {integer} type Signature types as described in RFC4880 Section 5.2.1.
	 * @param {integer} hashalgorithm the hash algorithm used within the signature
	 * @param {openpgp_msg_privatekey} privatekey the private key used to generate the signature
	 * @param {integer} length length of data to be signed
	 * @param {boolean} nested boolean showing whether the signature is nested. 
	 *  "true" indicates that the next packet is another One-Pass Signature packet
	 *   that describes another signature to be applied to the same message data. 
	 * @return {String} a string representation of a one-pass signature packet
	 */
	function write_packet(type, hashalgorithm, privatekey,length, nested) {
		var result =""; 
		
		result += openpgp_packet.write_packet_header(4,13);
		result += String.fromCharCode(3);
		result += String.fromCharCode(type);
		result += String.fromCharCode(hashalgorithm);
		result += String.fromCharCode(privatekey.privateKeyPacket.publicKey.publicKeyAlgorithm);
		result += privatekey.getKeyId();
		if (nested)
			result += String.fromCharCode(0);
		else
			result += String.fromCharCode(1);
		
		return result;
	}
	
	/**
	 * generates debug output (pretty print)
	 * @return {string} String which gives some information about the one-pass signature packet
	 */
	function toString() {
		return '5.4.  One-Pass Signature Packets (Tag 4)\n'+
			   '    length: '+this.packetLength+'\n'+
			   '    type:   '+this.type+'\n'+
			   '    keyID:  '+this.signingKeyId.toString()+'\n'+
			   '    hashA:  '+this.hashAlgorithm+'\n'+
			   '    pubKeyA:'+this.publicKeyAlgorithm+'\n'+
			   '    flags:  '+this.flags+'\n'+
			   '    version:'+this.version+'\n';
	}
	
	this.read_packet = read_packet;
	this.toString = toString;
	this.write_packet = write_packet;
};
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
function openpgp_packet_marker() {
	this.tagType = 10;
	/**
	 * parsing function for a literal data packet (tag 10).
	 * 
	 * @param {string} input payload of a tag 10 packet
	 * @param {integer} position
	 *            position to start reading from the input string
	 * @param {integer} len
	 *            length of the packet or the remaining length of
	 *            input at position
	 * @return {openpgp_packet_encrypteddata} object representation
	 */
	function read_packet(input, position, len) {
		this.packetLength = 3;
		if (input[position].charCodeAt() == 0x50 && // P
				input[position + 1].charCodeAt() == 0x47 && // G
				input[position + 2].charCodeAt() == 0x50) // P
			return this;
		// marker packet does not contain "PGP"
		return null;
	}

	/**
	 * Generates Debug output
	 * 
	 * @return {string} String which gives some information about the keymaterial
	 */
	function toString() {
		return "5.8.  Marker Packet (Obsolete Literal Packet) (Tag 10)\n"
				+ "     packet reads: \"PGP\"\n";
	}

	this.read_packet = read_packet;
	this.toString = toString;
}
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
	this.tagType = 2;
	this.signatureType = null;
	this.creationTime = null;
	this.keyId = null;
	this.signatureData = null;
	this.signatureExpirationTime = null;
	this.signatureNeverExpires = null;
	this.signedHashValue = null;
	this.MPIs = null;
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
	 * @param {string} input payload of a tag 2 packet
	 * @param {integer} position position to start reading from the input string
	 * @param {integer} len length of the packet or the remaining length of input at position
	 * @return {openpgp_packet_encrypteddata} object representation
	 */
	function read_packet(input, position, len) {
		this.data = input.substring	(position, position+len);
		if (len < 0) {
			util.print_debug("openpgp.packet.signature.js\n"+"openpgp_packet_signature read_packet length < 0 @:"+position);
			return null;
		}
		var mypos = position;
		this.packetLength = len;
		// alert('starting parsing signature: '+position+' '+this.packetLength);
		this.version = input[mypos++].charCodeAt();
		// switch on version (3 and 4)
		switch (this.version) {
		case 3:
			// One-octet length of following hashed material. MUST be 5.
			if (input[mypos++].charCodeAt() != 5)
				util.print_debug("openpgp.packet.signature.js\n"+'invalid One-octet length of following hashed material.  MUST be 5. @:'+(mypos-1));
			var sigpos = mypos;
			// One-octet signature type.
			this.signatureType = input[mypos++].charCodeAt();

			// Four-octet creation time.
			this.creationTime = new Date(((input[mypos++].charCodeAt()) << 24 |
					(input[mypos++].charCodeAt() << 16) | (input[mypos++].charCodeAt() << 8) |
					input[mypos++].charCodeAt())* 1000);
			
			// storing data appended to data which gets verified
			this.signatureData = input.substring(position, mypos);
			
			// Eight-octet Key ID of signer.
			this.keyId = input.substring(mypos, mypos +8);
			mypos += 8;

			// One-octet public-key algorithm.
			this.publicKeyAlgorithm = input[mypos++].charCodeAt();

			// One-octet hash algorithm.
			this.hashAlgorithm = input[mypos++].charCodeAt();

			// Two-octet field holding left 16 bits of signed hash value.
			this.signedHashValue = (input[mypos++].charCodeAt() << 8) | input[mypos++].charCodeAt();
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
			
			this.MPIs = new Array();
			for (var i = 0; i < mpicount; i++) {
				this.MPIs[i] = new openpgp_type_mpi();
				if (this.MPIs[i].read(input, mypos, (mypos-position)) != null && 
						!this.packetLength < (mypos-position)) {
					mypos += this.MPIs[i].packetLength;
				} else {
			 		util.print_error('signature contains invalid MPI @:'+mypos);
				}
			}
		break;
		case 4:
			this.signatureType = input[mypos++].charCodeAt();
			this.publicKeyAlgorithm = input[mypos++].charCodeAt();
			this.hashAlgorithm = input[mypos++].charCodeAt();

			// Two-octet scalar octet count for following hashed subpacket
			// data.
			var hashed_subpacket_count = (input[mypos++].charCodeAt() << 8) + input[mypos++].charCodeAt();

			// Hashed subpacket data set (zero or more subpackets)
			var subpacket_length = 0;
			while (hashed_subpacket_count != subpacket_length) {
				if (hashed_subpacket_count < subpacket_length) {
					util.print_debug("openpgp.packet.signature.js\n"+"hashed missed something: "+mypos+" c:"+hashed_subpacket_count+" l:"+subpacket_length);
				}

				subpacket_length += this._raw_read_signature_sub_packet(input,
						mypos + subpacket_length, hashed_subpacket_count
								- subpacket_length);
			}
			
			mypos += hashed_subpacket_count;
			this.signatureData = input.substring(position, mypos);

			// alert("signatureData: "+util.hexstrdump(this.signatureData));
			
			// Two-octet scalar octet count for the following unhashed subpacket
			var subpacket_count = (input[mypos++].charCodeAt() << 8) + input[mypos++].charCodeAt();
				
			// Unhashed subpacket data set (zero or more subpackets).
			subpacket_length = 0;
			while (subpacket_count != subpacket_length) {
				if (subpacket_count < subpacket_length) {
					util.print_debug("openpgp.packet.signature.js\n"+"missed something: "+subpacket_length+" c:"+subpacket_count+" "+" l:"+subpacket_length);
				}
				subpacket_length += this._raw_read_signature_sub_packet(input,
						mypos + subpacket_length, subpacket_count
								- subpacket_length);

			}
			mypos += subpacket_count;
			// Two-octet field holding the left 16 bits of the signed hash
			// value.
			this.signedHashValue = (input[mypos++].charCodeAt() << 8) | input[mypos++].charCodeAt();
			// One or more multiprecision integers comprising the signature.
			// This portion is algorithm specific, as described above.
			var mpicount = 0;
			if (this.publicKeyAlgorithm > 0 && this.publicKeyAlgorithm < 4)
				mpicount = 1;
			else if (this.publicKeyAlgorithm == 17)
				mpicount = 2;
			
			this.MPIs = new Array();
			for (var i = 0; i < mpicount; i++) {
				this.MPIs[i] = new openpgp_type_mpi();
				if (this.MPIs[i].read(input, mypos, (mypos-position)) != null && 
						!this.packetLength < (mypos-position)) {
					mypos += this.MPIs[i].packetLength;
				} else {
			 		util.print_error('signature contains invalid MPI @:'+mypos);
				}
			}
			break;
		default:
			util.print_error("openpgp.packet.signature.js\n"+'unknown signature packet version'+this.version);
			break;
		}
		// util.print_message("openpgp.packet.signature.js\n"+"end signature: l: "+this.packetLength+"m: "+mypos+" m-p: "+(mypos-position));
		return this;
	}
	/**
	 * creates a string representation of a message signature packet (tag 2).
	 * This can be only used on text data
	 * @param {integer} signature_type should be 1 (one) 
	 * @param {String} data data to be signed
	 * @param {openpgp_msg_privatekey} privatekey private key used to sign the message. (secMPIs MUST be unlocked)
	 * @return {string} string representation of a signature packet
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
				publickey.MPIs,
				privatekey.privateKeyPacket.secMPIs,
				data+result+trailer);
		return {openpgp: (openpgp_packet.write_packet_header(2, (result+result2).length)+result + result2), 
				hash: util.get_hashAlgorithmString(hash_algo)};
	}
	/**
	 * creates a string representation of a sub signature packet (See RFC 4880 5.2.3.1)
	 * @param {integer} type subpacket signature type. Signature types as described in RFC4880 Section 5.2.3.2
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
	
	this._raw_read_signature_sub_packet = function(input, position, len) {
		if (len < 0)
			util.print_debug("openpgp.packet.signature.js\n"+"_raw_read_signature_sub_packet length < 0 @:"+position);
		var mypos = position;
		var subplen = 0;
		// alert('starting signature subpackage read at position:'+position+' length:'+len);
		if (input[mypos].charCodeAt() < 192) {
			subplen = input[mypos++].charCodeAt();
		} else if (input[mypos].charCodeAt() >= 192 && input[mypos].charCodeAt() < 224) {
			subplen = ((input[mypos++].charCodeAt() - 192) << 8) + (input[mypos++].charCodeAt()) + 192;
		} else if (input[mypos].charCodeAt() > 223 && input[mypos].charCodeAt() < 255) {
			subplen = 1 << (input[mypos++].charCodeAt() & 0x1F);
		} else if (input[mypos].charCodeAt() < 255) {
			mypos++;
			subplen = (input[mypos++].charCodeAt() << 24) | (input[mypos++].charCodeAt() << 16)
					|  (input[mypos++].charCodeAt() << 8) |  input[mypos++].charCodeAt();
		}
		
		var type = input[mypos++].charCodeAt() & 0x7F;
		// alert('signature subpacket type '+type+" with length: "+subplen);
		// subpacket type
		switch (type) {
		case 2: // Signature Creation Time
			this.creationTime = new Date(((input[mypos++].charCodeAt() << 24) | (input[mypos++].charCodeAt() << 16)
					| (input[mypos++].charCodeAt() << 8) | input[mypos++].charCodeAt())*1000);
			break;
		case 3: // Signature Expiration Time
			this.signatureExpirationTime =  (input[mypos++].charCodeAt() << 24)
					| (input[mypos++].charCodeAt() << 16) | (input[mypos++].charCodeAt() << 8)
					| input[mypos++].charCodeAt();
			this.signatureNeverExpires = (this.signature_expiration_time == 0);
			
			break;
		case 4: // Exportable Certification
			this.exportable = input[mypos++].charCodeAt() == 1;
			break;
		case 5: // Trust Signature
			this.trustLevel = input[mypos++].charCodeAt();
			this.trustAmount = input[mypos++].charCodeAt();
			break;
		case 6: // Regular Expression
			this.regular_expression = new String();
			for (var i = 0; i < subplen - 1; i++)
				this.regular_expression += (input[mypos++]);
			break;
		case 7: // Revocable
			this.revocable = input[mypos++].charCodeAt() == 1;
			break;
		case 9: // Key Expiration Time
			this.keyExpirationTime = (input[mypos++].charCodeAt() << 24)
					| (input[mypos++].charCodeAt() << 16) | (input[mypos++].charCodeAt() << 8)
					| input[mypos++].charCodeAt();
			this.keyNeverExpires = (this.keyExpirationTime == 0);
			break;
		case 11: // Preferred Symmetric Algorithms
			this.preferredSymmetricAlgorithms = new Array();
			for (var i = 0; i < subplen-1; i++) {
				this.preferredSymmetricAlgorithms = input[mypos++].charCodeAt();
			}
			break;
		case 12: // Revocation Key
			// (1 octet of class, 1 octet of public-key algorithm ID, 20
			// octets of
			// fingerprint)
			this.revocationKeyClass = input[mypos++].charCodeAt();
			this.revocationKeyAlgorithm = input[mypos++].charCodeAt();
			this.revocationKeyFingerprint = new Array();
			for ( var i = 0; i < 20; i++) {
				this.revocationKeyFingerprint = input[mypos++].charCodeAt();
			}
			break;
		case 16: // Issuer
			this.issuerKeyId = input.substring(mypos,mypos+8);
			mypos += 8;
			break;
		case 20: // Notation Data
			this.notationFlags = (input[mypos++].charCodeAt() << 24) | 
								 (input[mypos++].charCodeAt() << 16) |
								 (input[mypos++].charCodeAt() <<  8) | 
								 (input[mypos++].charCodeAt());
			var nameLength = (input[mypos++].charCodeAt() <<  8) | (input[mypos++].charCodeAt());
			var valueLength = (input[mypos++].charCodeAt() <<  8) | (input[mypos++].charCodeAt());
			this.notationName = "";
			for (var i = 0; i < nameLength; i++) {
				this.notationName += input[mypos++];
			}
			this.notationValue = "";
			for (var i = 0; i < valueLength; i++) {
				this.notationValue += input[mypos++];
			}
			break;
		case 21: // Preferred Hash Algorithms
			this.preferredHashAlgorithms = new Array();
			for (var i = 0; i < subplen-1; i++) {
				this.preferredHashAlgorithms = input[mypos++].charCodeAt();
			}
			break;
		case 22: // Preferred Compression Algorithms
			this.preferredCompressionAlgorithms = new Array();
			for ( var i = 0; i < subplen-1; i++) {
				this.preferredCompressionAlgorithms = input[mypos++].charCodeAt();
			}
			break;
		case 23: // Key Server Preferences
			this.keyServerPreferences = new Array();
			for ( var i = 0; i < subplen-1; i++) {
				this.keyServerPreferences = input[mypos++].charCodeAt();
			}
			break;
		case 24: // Preferred Key Server
			this.preferredKeyServer = new String();
			for ( var i = 0; i < subplen-1; i++) {
				this.preferredKeyServer += input[mypos++];
			}
			break;
		case 25: // Primary User ID
			this.isPrimaryUserID = input[mypos++] != 0;
			break;
		case 26: // Policy URI
			this.policyURI = new String();
			for ( var i = 0; i < subplen-1; i++) {
				this.policyURI += input[mypos++];
			}
			break;
		case 27: // Key Flags
			this.keyFlags = new Array();
			for ( var i = 0; i < subplen-1; i++) {
				this.keyFlags = input[mypos++].charCodeAt();
			}
			break;
		case 28: // Signer's User ID
			this.signersUserId = new String();
			for ( var i = 0; i < subplen-1; i++) {
				this.signersUserId += input[mypos++];
			}
			break;
		case 29: // Reason for Revocation
			this.reasonForRevocationFlag = input[mypos++].charCodeAt();
			this.reasonForRevocationString = new String();
			for ( var i = 0; i < subplen -2; i++) {
				this.reasonForRevocationString += input[mypos++];
			}
			break;
		case 30: // Features
			// TODO: to be implemented
			return subplen+1;
		case 31: // Signature Target
			// (1 octet public-key algorithm, 1 octet hash algorithm, N octets hash)
			this.signatureTargetPublicKeyAlgorithm = input[mypos++].charCodeAt();
			this.signatureTargetHashAlgorithm = input[mypos++].charCodeAt();
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
				this.signatureTargetHash[i] = input[mypos++]; 
			}
		case 32: // Embedded Signature
			this.embeddedSignature = new openpgp_packet_signature();
			this.embeddedSignature.read_packet(input, mypos, len -(mypos-position));
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
					this.MPIs, key.obj.publicKeyPacket.MPIs, data.substring(i)+this.signatureData+trailer);
			}
			break;

		case 1: // 0x01: Signature of a canonical text document.
			if (this.version == 4) {
				this.verified = openpgp_crypto_verifySignature(this.publicKeyAlgorithm, this.hashAlgorithm, 
					this.MPIs, key.obj.publicKeyPacket.MPIs, data+this.signatureData+trailer);
				return this.verified;
			}
			break;
				
		case 2: // 0x02: Standalone signature.
			// This signature is a signature of only its own subpacket contents.
			// It is calculated identically to a signature over a zero-length
			// binary document.  Note that it doesn't make sense to have a V3
			// standalone signature.
			if (this.version == 3) {
				this.verified = false;
				break;
				}
			
			this.verified = openpgp_crypto_verifySignature(this.publicKeyAlgorithm, this.hashAlgorithm, 
					this.MPIs, key.obj.publicKeyPacket.MPIs, this.signatureData+trailer);
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
					this.MPIs, key.MPIs, data+this.signatureData+trailer);
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
					this.MPIs, key.MPIs, data+this.signatureData+trailer);
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
					this.MPIs, key.MPIs, data+this.signatureData+trailer);
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
	 * @return {string} String which gives some information about the signature packet
	 */

	function toString () {
		if (this.version == 3) {
			var result = '5.2. Signature Packet (Tag 2)\n'+
	          "Packet Length:                     :"+this.packetLength+'\n'+
	          "Packet version:                    :"+this.version+'\n'+
	          "One-octet signature type           :"+this.signatureType+'\n'+
	          "Four-octet creation time.          :"+this.creationTime+'\n'+
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
          "Signature Creation Time            :"+this.creationTime+'\n'+
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
          for (var i = 0; i < this.MPIs.length; i++) {
        	  result += this.MPIs[i].toString();
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
	 * @return {obj: [openpgp_msg_publickey], text: [String]} if found the public key will be returned. null otherwise
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
 * @classdesc Implementation of the Sym. Encrypted Integrity Protected Data Packet (Tag 18)
 * 
 * RFC4880 5.13: The Symmetrically Encrypted Integrity Protected Data packet is
 * a variant of the Symmetrically Encrypted Data packet. It is a new feature
 * created for OpenPGP that addresses the problem of detecting a modification to
 * encrypted data. It is used in combination with a Modification Detection Code
 * packet.
 */

function openpgp_packet_encryptedintegrityprotecteddata() {
	this.tagType = 18;
	this.version = null; // integer == 1
	this.packetLength = null; // integer
	this.encryptedData = null; // string
	this.decrytpedData = null; // string
	this.hash = null; // string
	/**
	 * parsing function for the packet.
	 * 
	 * @param {string} input payload of a tag 18 packet
	 * @param {integer} position
	 *             position to start reading from the input string
	 * @param {integer} len length of the packet or the remaining length of
	 *            input at position
	 * @return {openpgp_packet_encryptedintegrityprotecteddata} object
	 *         representation
	 */
	function read_packet(input, position, len) {
		this.packetLength = len;
		// - A one-octet version number. The only currently defined value is
		// 1.
		this.version = input[position].charCodeAt();
		if (this.version != 1) {
			util
					.print_error('openpgp.packet.encryptedintegrityprotecteddata.js\nunknown encrypted integrity protected data packet version: '
							+ this.version
							+ " , @ "
							+ position
							+ "hex:"
							+ util.hexstrdump(input));
			return null;
		}
		// - Encrypted data, the output of the selected symmetric-key cipher
		//   operating in Cipher Feedback mode with shift amount equal to the
		//   block size of the cipher (CFB-n where n is the block size).
		this.encryptedData = input.substring(position + 1, position + 1 + len);
		util.print_debug("openpgp.packet.encryptedintegrityprotecteddata.js\n"
				+ this.toString());
		return this;
	}

	/**
	 * Creates a string representation of a Sym. Encrypted Integrity Protected
	 * Data Packet (tag 18) (see RFC4880 5.13)
	 * 
	 * @param {integer} symmetric_algorithm
	 *            the selected symmetric encryption algorithm to be used
	 * @param {String} key the key of cipher blocksize length to be used
	 * @param data
	 *            plaintext data to be encrypted within the packet
	 * @return a string representation of the packet
	 */
	function write_packet(symmetric_algorithm, key, data) {

		var prefixrandom = openpgp_crypto_getPrefixRandom(symmetric_algorithm);
		var prefix = prefixrandom
				+ prefixrandom.charAt(prefixrandom.length - 2)
				+ prefixrandom.charAt(prefixrandom.length - 1);
		var tohash = data;
		tohash += String.fromCharCode(0xD3);
		tohash += String.fromCharCode(0x14);
		util.print_debug_hexstr_dump("data to be hashed:"
				, prefix + tohash);
		tohash += str_sha1(prefix + tohash);
		util.print_debug_hexstr_dump("hash:"
				, tohash.substring(tohash.length - 20,
						tohash.length));
		var result = openpgp_crypto_symmetricEncrypt(prefixrandom,
				symmetric_algorithm, key, tohash, false).substring(0,
				prefix.length + tohash.length);
		var header = openpgp_packet.write_packet_header(18, result.length + 1)
				+ String.fromCharCode(1);
		this.encryptedData = result;
		return header + result;
	}

	/**
	 * Decrypts the encrypted data contained in this object read_packet must
	 * have been called before
	 * 
	 * @param {integer} symmetric_algorithm_type
	 *            the selected symmetric encryption algorithm to be used
	 * @param {String} key the key of cipher blocksize length to be used
	 * @return the decrypted data of this packet
	 */
	function decrypt(symmetric_algorithm_type, key) {
		this.decryptedData = openpgp_crypto_symmetricDecrypt(
				symmetric_algorithm_type, key, this.encryptedData, false);
		// there must be a modification detection code packet as the
		// last packet and everything gets hashed except the hash itself
		this.hash = str_sha1(openpgp_crypto_MDCSystemBytes(
				symmetric_algorithm_type, key, this.encryptedData)
				+ this.decryptedData.substring(0,
						this.decryptedData.length - 20));
		util.print_debug_hexstr_dump("calc hash = ", this.hash);
		if (this.hash == this.decryptedData.substring(
				this.decryptedData.length - 20, this.decryptedData.length))
			return this.decryptedData;
		else
			util
					.print_error("Decryption stopped: discovered a modification of encrypted data.");
		return null;
	}

	function toString() {
	    var data = '';
	    if(openpgp.config.debug)
	        data = '    data: Bytes ['
				+ util.hexstrdump(this.encryptedData) + ']';
	    
		return '5.13.  Sym. Encrypted Integrity Protected Data Packet (Tag 18)\n'
				+ '    length:  '
				+ this.packetLength
				+ '\n'
				+ '    version: '
				+ this.version
				+ '\n'
				+ data;
	}

	this.write_packet = write_packet;
	this.read_packet = read_packet;
	this.toString = toString;
	this.decrypt = decrypt;
};
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
 * @classdesc Implementation of the Modification Detection Code Packet (Tag 19)
 * 
 * RFC4880 5.14: The Modification Detection Code packet contains a SHA-1 hash of
 * plaintext data, which is used to detect message modification. It is only used
 * with a Symmetrically Encrypted Integrity Protected Data packet. The
 * Modification Detection Code packet MUST be the last packet in the plaintext
 * data that is encrypted in the Symmetrically Encrypted Integrity Protected
 * Data packet, and MUST appear in no other place.
 */

function openpgp_packet_modificationdetectioncode() {
	this.tagType = 19;
	this.hash = null;
	/**
	 * parsing function for a modification detection code packet (tag 19).
	 * 
	 * @param {String} input payload of a tag 19 packet
	 * @param {Integer} position
	 *            position to start reading from the input string
	 * @param {Integer} len
	 *            length of the packet or the remaining length of
	 *            input at position
	 * @return {openpgp_packet_encrypteddata} object representation
	 */
	function read_packet(input, position, len) {
		this.packetLength = len;

		if (len != 20) {
			util
					.print_error("openpgp.packet.modificationdetectioncode.js\n"
							+ 'invalid length for a modification detection code packet!'
							+ len);
			return null;
		}
		// - A 20-octet SHA-1 hash of the preceding plaintext data of the
		// Symmetrically Encrypted Integrity Protected Data packet,
		// including prefix data, the tag octet, and length octet of the
		// Modification Detection Code packet.
		this.hash = input.substring(position, position + 20);
		return this;
	}

	/*
	 * this packet is created within the encryptedintegrityprotected packet
	 * function write_packet(data) { }
	 */

	/**
	 * generates debug output (pretty print)
	 * 
	 * @return {string} String which gives some information about the modification
	 *         detection code
	 */
	function toString() {
		return '5.14 Modification detection code packet\n' + '    bytes ('
				+ this.hash.length + '): [' + util.hexstrdump(this.hash) + ']';
	}
	this.read_packet = read_packet;
	this.toString = toString;
};
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
 * @classdesc Implementation of the User ID Packet (Tag 13)
 * A User ID packet consists of UTF-8 text that is intended to represent
 * the name and email address of the key holder.  By convention, it
 * includes an RFC 2822 [RFC2822] mail name-addr, but there are no
 * restrictions on its content.  The packet length in the header
 * specifies the length of the User ID. 
 */

function openpgp_packet_userid() {
	this.tagType = 13;
	this.certificationSignatures = new Array();
	this.certificationRevocationSignatures = new Array();
	this.revocationSignatures = new Array();
	this.parentNode = null;

	/**
	 * parsing function for a user id packet (tag 13).
	 * @param {string} input payload of a tag 13 packet
	 * @param {integer} position position to start reading from the input string
	 * @param {integer} len length of the packet or the remaining length of input at position
	 * @return {openpgp_packet_encrypteddata} object representation
	 */
	function read_packet(input, position, len) {
		this.text = '';
		this.packetLength = len;

		for ( var i = 0; i < len; i++) {
			this.text += input[position + i];
		}
		return this;
	}

	/**
	 * creates a string representation of the user id packet
	 * @param {String} user_id the user id as string ("John Doe <john.doe@mail.us")
	 * @return {String} string representation
	 */
	function write_packet(user_id) {
		this.text = user_id;
		var result = openpgp_packet.write_packet_header(13,this.text.length);
		result += this.text;
		return result;
	}

	/**
	 * Continue parsing packets belonging to the userid packet such as signatures
	 * @param {openpgp_*} parent_node the parent object
	 * @param {String} input input string to read the packet(s) from
	 * @param {integer} position start position for the parser
	 * @param {integer} len length of the packet(s) or remaining length of input
	 * @return {integer} length of nodes read
	 */
	function read_nodes(parent_node, input, position, len) {
		if (parent_node.tagType == 6) { // public key
			this.parentNode = parent_node;
			var pos = position;
			var l = len;
			while (input.length != pos) {
				var result = openpgp_packet.read_packet(input, pos, l - (pos - position));
				if (result == null) {
					util.print_error('[user_id] parsing ends here @:' + pos + " l:" + l);
					break;
				} else {
					
					pos += result.packetLength + result.headerLength;
					l = input.length - pos;
					switch (result.tagType) {
					case 2: // Signature Packet
						if (result.signatureType > 15
								&& result.signatureType < 20) { // certification
							// //
							// signature
							this.certificationSignatures[this.certificationSignatures.length] = result;
							break;
						} else if (result.signatureType == 48) {// certification revocation signature
							this.certificationRevocationSignatures[this.certificationRevocationSignatures.length] = result;
							break;
						} else if (result.signatureType == 24) { // omg. standalone signature 
							this.certificationSignatures[this.certificationSignatures.length] = result;
							break;
						} else {
							util.debug("unknown sig t: "+result.signatureType+"@"+(pos - (result.packetLength + result.headerLength)));
						}
					default:
						this.data = input;
						this.position = position - parent_node.packetLength;
						this.len = pos - position -(result.headerLength + result.packetLength);
						return this.len;
					}
				}
			}
			this.data = input;
			this.position = position - parent_node.packetLength;
			this.len = pos - position -(result.headerLength + result.packetLength);
			return this.len;
		} else if (parent_node.tagType == 5) { // secret Key
			this.parentNode = parent_node;
			var exit = false;
			var pos = position;
			while (input.length != pos) {
				var result = openpgp_packet.read_packet(input, pos, l - (pos - position));
				if (result == null) {
					util.print_error('parsing ends here @:' + pos + " l:" + l);
					break;
				} else {
					pos += result.packetLength + result.headerLength;
					l = input.length - pos;
					switch (result.tagType) {
					case 2: // Signature Packet certification signature
						if (result.signatureType > 15
								&& result.signatureType < 20)
							this.certificationSignatures[this.certificationSignatures.length] = result;
						// certification revocation signature
						else if (result.signatureType == 48)
							this.certificationRevocationSignatures[this.certificationRevocationSignatures.length] = result;
					default:
						this.data = input;
						this.position = position - parent_node.packetLength;
						this.len = pos - position -(result.headerLength + result.packetLength);
						return this.len;
					}
				}
			}
		} else {
			util.print_error("unknown parent node for a userId packet "+parent_node.tagType);
		}
	}
	
	/**
	 * generates debug output (pretty print)
	 * @return {string} String which gives some information about the user id packet
	 */
	function toString() {
		var result = '     5.11.  User ID Packet (Tag 13)\n' + '    text ('
				+ this.text.length + '): "' + this.text.replace("<", "&lt;")
				+ '"\n';
		result +="certification signatures:\n";
		for (var i = 0; i < this.certificationSignatures.length; i++) {
			result += "        "+this.certificationSignatures[i].toString();
		}
		result +="certification revocation signatures:\n";
		for (var i = 0; i < this.certificationRevocationSignatures.length; i++) {
			result += "        "+this.certificationRevocationSignatures[i].toString();
		}
		return result;
	}

	/**
	 * lookup function to find certification revocation signatures
	 * @param {string} keyId string containing the key id of the issuer of this signature
	 * @return a CertificationRevocationSignature if found; otherwise null
	 */
	function hasCertificationRevocationSignature(keyId) {
		for (var i = 0; i < this.certificationRevocationSignatures.length; i++) {
			if ((this.certificationRevocationSignatures[i].version == 3 &&
				 this.certificationRevocationSignatures[i].keyId == keyId) ||
				(this.certificationRevocationSignatures[i].version == 4 &&
				 this.certificationRevocationSignatures[i].issuerKeyId == keyId))
				return this.certificationRevocationSignatures[i];
		}
		return null;
	}

	/**
	 * Verifies all certification signatures. This method does not consider possible revocation signatures.
	 * @param publicKeyPacket the top level key material
	 * @return an array of integers corresponding to the array of certification signatures. The meaning of each integer is the following:
	 * 0 = bad signature
	 * 1 = signature expired
	 * 2 = issuer key not available
	 * 3 = revoked
	 * 4 = signature valid
	 * 5 = signature by key owner expired
	 * 6 = signature by key owner revoked
	 */
	function verifyCertificationSignatures(publicKeyPacket) {
		result = new Array();
		for (var i = 0 ; i < this.certificationSignatures.length; i++) {
			// A certification signature (type 0x10 through 0x13) hashes the User
			// ID being bound to the key into the hash context after the above
			// data.  A V3 certification hashes the contents of the User ID or
			// attribute packet packet, without any header.  A V4 certification
			// hashes the constant 0xB4 for User ID certifications or the constant
			// 0xD1 for User Attribute certifications, followed by a four-octet
			// number giving the length of the User ID or User Attribute data, and
			// then the User ID or User Attribute data.

			if (this.certificationSignatures[i].version == 4) {
				if (this.certificationSignatures[i].signatureExpirationTime != null &&
						this.certificationSignatures[i].signatureExpirationTime != null &&
						this.certificationSignatures[i].signatureExpirationTime != 0 &&
						!this.certificationSignatures[i].signatureNeverExpires &&
						new Date(this.certificationSignatures[i].creationTime.getTime() +(this.certificationSignatures[i].signatureExpirationTime*1000)) < new Date()) {
					if (this.certificationSignatures[i].issuerKeyId == publicKeyPacket.getKeyId())
						result[i] = 5;
					else
						result[i] = 1;
					continue;
				}
				if (this.certificationSignatures[i].issuerKeyId == null) {
					result[i] = 0;
					continue;
				}
				var issuerPublicKey = openpgp.keyring.getPublicKeysForKeyId(this.certificationSignatures[i].issuerKeyId);
				if (issuerPublicKey == null || issuerPublicKey.length == 0) {
					result[i] = 2;
					continue;
				}
				// TODO: try to verify all returned issuer public keys (key ids are not unique!)
				var issuerPublicKey = issuerPublicKey[0];
				var signingKey = issuerPublicKey.obj.getSigningKey();
				if (signingKey == null) {
					result[i] = 0;
					continue;
				}
				var revocation = this.hasCertificationRevocationSignature(this.certificationSignatures[i].issuerKeyId);
				if (revocation != null && revocation.creationTime > 
					this.certificationSignatures[i].creationTime) {
					var signaturedata = String.fromCharCode(0x99)+ publicKeyPacket.header.substring(1)+
					publicKeyPacket.data+String.fromCharCode(0xB4)+
					String.fromCharCode((this.text.length >> 24) & 0xFF)+
					String.fromCharCode((this.text.length >> 16) & 0xFF)+
					String.fromCharCode((this.text.length >>  8) & 0xFF)+
					String.fromCharCode((this.text.length) & 0xFF)+
					this.text;
					if (revocation.verify(signaturedata, signingKey)) {
						if (this.certificationSignatures[i].issuerKeyId == publicKeyPacket.getKeyId())
							result[i] = 6;
						else
							result[i] = 3;
						continue;
					}
				}
				var signaturedata = String.fromCharCode(0x99)+ publicKeyPacket.header.substring(1)+
						publicKeyPacket.data+String.fromCharCode(0xB4)+
						String.fromCharCode((this.text.length >> 24) & 0xFF)+
						String.fromCharCode((this.text.length >> 16) & 0xFF)+
						String.fromCharCode((this.text.length >>  8) & 0xFF)+
						String.fromCharCode((this.text.length) & 0xFF)+
						this.text;
				if (this.certificationSignatures[i].verify(signaturedata, signingKey)) {
					result[i] = 4;
				} else
				result[i] = 0;
			} else if (this.certificationSignatures[i].version == 3) {
				if (this.certificationSignatures[i].keyId == null) {
					result[i] = 0;
					continue;
				}
				var issuerPublicKey = openpgp.keyring.getPublicKeysForKeyId(this.certificationSignatures[i].keyId);
				if (issuerPublicKey == null || issuerPublicKey.length == 0) {
					result[i] = 2;
					continue;
				}
				issuerPublicKey = issuerPublicKey[0];
				var signingKey = publicKey.obj.getSigningKey();
				if (signingKey == null) {
					result[i] = 0;
					continue;
				}
				var revocation = this.hasCertificationRevocationSignature(this.certificationSignatures[i].keyId);
				if (revocation != null && revocation.creationTime > 
					this.certificationSignatures[i].creationTime) {
					var signaturedata = String.fromCharCode(0x99)+ this.publicKeyPacket.header.substring(1)+
					this.publicKeyPacket.data+this.text;
					if (revocation.verify(signaturedata, signingKey)) {
						if (revocation.keyId == publicKeyPacket.getKeyId())
							result[i] = 6;
						else
							result[i] = 3;
						continue;
					}
				}
				var signaturedata = String.fromCharCode(0x99)+ publicKeyPacket.header.substring(1)+
					publicKeyPacket.data+this.text;
				if (this.certificationSignatures[i].verify(signaturedata, signingKey)) {
					result[i] = 4;
				} else 
				result[i] = 0;
			} else {
				result[i] = 0;
			}
		}
		return result;
	}

	/**
	 * verifies the signatures of the user id
	 * @return 0 if the userid is valid; 1 = userid expired; 2 = userid revoked
	 */
	function verify(publicKeyPacket) {
		var result = this.verifyCertificationSignatures(publicKeyPacket);
		if (result.indexOf(6) != -1)
			return 2;
		if (result.indexOf(5) != -1)
			return 1;
		return 0;
	}

	// TODO: implementation missing
	function addCertification(publicKeyPacket, privateKeyPacket) {
		
	}

	// TODO: implementation missing
	function revokeCertification(publicKeyPacket, privateKeyPacket) {
		
	}

	this.hasCertificationRevocationSignature = hasCertificationRevocationSignature;
	this.verifyCertificationSignatures = verifyCertificationSignatures;
	this.verify = verify;
	this.read_packet = read_packet;
	this.write_packet = write_packet;
	this.toString = toString;
	this.read_nodes = read_nodes;
}
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
function openpgp_packet_encryptedsessionkey() {

	/**
	 * parsing function for a publickey encrypted session key packet (tag 1).
	 * 
	 * @param {string} input payload of a tag 1 packet
	 * @param {integer} position position to start reading from the input string
	 * @param {integer} len length of the packet or the remaining length of
	 *            input at position
	 * @return {openpgp_packet_encrypteddata} object representation
	 */
	function read_pub_key_packet(input, position, len) {
		this.tagType = 1;
		this.packetLength = len;
		var mypos = position;
		if (len < 10) {
			util
					.print_error("openpgp.packet.encryptedsessionkey.js\n" + 'invalid length');
			return null;
		}

		this.version = input[mypos++].charCodeAt();
		this.keyId = new openpgp_type_keyid();
		this.keyId.read_packet(input, mypos);
		mypos += 8;
		this.publicKeyAlgorithmUsed = input[mypos++].charCodeAt();

		switch (this.publicKeyAlgorithmUsed) {
		case 1:
		case 2: // RSA
			this.MPIs = new Array();
			this.MPIs[0] = new openpgp_type_mpi();
			this.MPIs[0].read(input, mypos, mypos - position);
			break;
		case 16: // Elgamal
			this.MPIs = new Array();
			this.MPIs[0] = new openpgp_type_mpi();
			this.MPIs[0].read(input, mypos, mypos - position);
			mypos += this.MPIs[0].packetLength;
			this.MPIs[1] = new openpgp_type_mpi();
			this.MPIs[1].read(input, mypos, mypos - position);
			break;
		default:
			util.print_error("openpgp.packet.encryptedsessionkey.js\n"
					+ "unknown public key packet algorithm type "
					+ this.publicKeyAlgorithmType);
			break;
		}
		return this;
	}

	/**
	 * create a string representation of a tag 1 packet
	 * 
	 * @param {String} publicKeyId
	 *             the public key id corresponding to publicMPIs key as string
	 * @param {Array[openpgp_type_mpi]} publicMPIs
	 *            multiprecision integer objects describing the public key
	 * @param {integer} pubalgo
	 *            the corresponding public key algorithm // See RFC4880 9.1
	 * @param {integer} symmalgo
	 *            the symmetric cipher algorithm used to encrypt the data within 
	 *            an encrypteddatapacket or encryptedintegrityprotecteddatapacket 
	 *            following this packet //See RFC4880 9.2
	 * @param {String} sessionkey
	 *            a string of randombytes representing the session key
	 * @return {String} the string representation
	 */
	function write_pub_key_packet(publicKeyId, publicMPIs, pubalgo, symmalgo,
			sessionkey) {
		var result = String.fromCharCode(3);
		var data = String.fromCharCode(symmalgo);
		data += sessionkey;
		var checksum = util.calc_checksum(sessionkey);
		data += String.fromCharCode((checksum >> 8) & 0xFF);
		data += String.fromCharCode((checksum) & 0xFF);
		result += publicKeyId;
		result += String.fromCharCode(pubalgo);
		var mpi = new openpgp_type_mpi();
		var mpiresult = openpgp_crypto_asymetricEncrypt(pubalgo, publicMPIs,
				mpi.create(openpgp_encoding_eme_pkcs1_encode(data,
						publicMPIs[0].mpiByteLength)));
		for ( var i = 0; i < mpiresult.length; i++) {
			result += mpiresult[i];
		}
		result = openpgp_packet.write_packet_header(1, result.length) + result;
		return result;
	}

	/**
	 * parsing function for a symmetric encrypted session key packet (tag 3).
	 * 
	 * @param {string} input payload of a tag 1 packet
	 * @param {integer} position position to start reading from the input string
	 * @param {integer} len
	 *            length of the packet or the remaining length of
	 *            input at position
	 * @return {openpgp_packet_encrypteddata} object representation
	 */
	function read_symmetric_key_packet(input, position, len) {
		this.tagType = 3;
		var mypos = position;
		// A one-octet version number. The only currently defined version is 4.
		this.version = input[mypos++];

		// A one-octet number describing the symmetric algorithm used.
		this.symmetricKeyAlgorithmUsed = input[mypos++];
		// A string-to-key (S2K) specifier, length as defined above.
		this.s2k = new openpgp_type_s2k();
		this.s2k.read(input, mypos);

		// Optionally, the encrypted session key itself, which is decrypted
		// with the string-to-key object.
		if ((s2k.s2kLength + mypos) < len) {
			this.encryptedSessionKey = new Array();
			for ( var i = (mypos - position); i < len; i++) {
				this.encryptedSessionKey[i] = input[mypos++];
			}
		}
		return this;
	}
	/**
	 * Decrypts the session key (only for public key encrypted session key
	 * packets (tag 1)
	 * 
	 * @param {openpgp_msg_message} msg
	 *            the message object (with member encryptedData
	 * @param {openpgp_msg_privatekey} key
	 *            private key with secMPIs unlocked
	 * @return {String} the unencrypted session key
	 */
	function decrypt(msg, key) {
		if (this.tagType == 1) {
			var result = openpgp_crypto_asymetricDecrypt(
					this.publicKeyAlgorithmUsed, key.publicKey.MPIs,
					key.secMPIs, this.MPIs).toMPI();
			var checksum = ((result.charCodeAt(result.length - 2) << 8) + result
					.charCodeAt(result.length - 1));
			var decoded = openpgp_encoding_eme_pkcs1_decode(result.substring(2, result.length - 2), key.publicKey.MPIs[0].getByteLength());
			var sesskey = decoded.substring(1);
			var algo = decoded.charCodeAt(0);
			if (msg.encryptedData.tagType == 18)
				return msg.encryptedData.decrypt(algo, sesskey);
			else
				return msg.encryptedData.decrypt_sym(algo, sesskey);
		} else if (this.tagType == 3) {
			util
					.print_error("Symmetric encrypted sessionkey is not supported!");
			return null;
		}
	}

	/**
	 * Creates a string representation of this object (useful for debug
	 * purposes)
	 * 
	 * @return the string containing a openpgp description
	 */
	function toString() {
		if (this.tagType == 1) {
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
			for ( var i = 0; i < this.MPIs.length; i++) {
				result += this.MPIs[i].toString();
			}
			return result;
		} else
			return '5.3 Symmetric-Key Encrypted Session Key Packets (Tag 3)\n'
					+ '    KeyId:  ' + this.keyId.toString() + '\n'
					+ '    length: ' + this.packetLength + '\n'
					+ '    version:' + this.version + '\n' + '    symKeyA:'
					+ this.symmetricKeyAlgorithmUsed + '\n' + '    s2k:    '
					+ this.s2k + '\n';
	}

	this.read_pub_key_packet = read_pub_key_packet;
	this.read_symmetric_key_packet = read_symmetric_key_packet;
	this.write_pub_key_packet = write_pub_key_packet;
	this.toString = toString;
	this.decrypt = decrypt;
};

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
 * @classdesc Implementation of the Literal Data Packet (Tag 11)
 * 
 * RFC4880 5.9: A Literal Data packet contains the body of a message; data that
 * is not to be further interpreted.
 */
function openpgp_packet_literaldata() {
	this.tagType = 11;

	/**
	 * parsing function for a literal data packet (tag 11).
	 * 
	 * @param {string} input payload of a tag 11 packet
	 * @param {integer} position
	 *            position to start reading from the input string
	 * @param {integer} len
	 *            length of the packet or the remaining length of
	 *            input at position
	 * @return {openpgp_packet_encrypteddata} object representation
	 */
	function read_packet(input, position, len) {
		this.packetLength = len;
		// - A one-octet field that describes how the data is formatted.

		this.format = input[position];
		this.filename = input.substr(position + 2, input
				.charCodeAt(position + 1));
		this.date = new Date(parseInt(input.substr(position + 2
				+ input.charCodeAt(position + 1), 4)) * 1000);
		this.data = input.substring(position + 6
				+ input.charCodeAt(position + 1));
		return this;
	}

	/**
	 * Creates a string representation of the packet
	 * 
	 * @param {String} data the data to be inserted as body
	 * @return {String} string-representation of the packet
	 */
	function write_packet(data) {
		data = data.replace(/\r\n/g, "\n").replace(/\n/g, "\r\n");
		this.filename = "msg.txt";
		this.date = new Date();
		this.format = 't';
		var result = openpgp_packet.write_packet_header(11, data.length + 6
				+ this.filename.length);
		result += this.format;
		result += String.fromCharCode(this.filename.length);
		result += this.filename;
		result += String
				.fromCharCode((Math.round(this.date.getTime() / 1000) >> 24) & 0xFF);
		result += String
				.fromCharCode((Math.round(this.date.getTime() / 1000) >> 16) & 0xFF);
		result += String
				.fromCharCode((Math.round(this.date.getTime() / 1000) >> 8) & 0xFF);
		result += String
				.fromCharCode(Math.round(this.date.getTime() / 1000) & 0xFF);
		result += data;
		this.data = data;
		return result;
	}

	/**
	 * generates debug output (pretty print)
	 * 
	 * @return {string} String which gives some information about the keymaterial
	 */
	function toString() {
		return '5.9.  Literal Data Packet (Tag 11)\n' + '    length: '
				+ this.packetLength + '\n' + '    format: ' + this.format
				+ '\n' + '    filename:' + this.filename + '\n'
				+ '    date:   ' + this.date + '\n' + '    data:  |'
				+ this.data + '|\n' + '    rdata: |' + this.real_data + '|\n';
	}

	this.read_packet = read_packet;
	this.toString = toString;
	this.write_packet = write_packet;
}
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

function openpgp_packet_encrypteddata() {
	this.tagType = 9;
	this.packetLength = null;
	this.encryptedData = null;
	this.decryptedData = null;

	/**
	 * parsing function for the packet.
	 * 
	 * @param {string} input payload of a tag 9 packet
	 * @param {integer} position position to start reading from the input string
	 * @param {integer} len length of the packet or the remaining length of
	 *            input at position
	 * @return {openpgp_packet_encrypteddata} object representation
	 */
	function read_packet(input, position, len) {
		var mypos = position;
		this.packetLength = len;
		// - Encrypted data, the output of the selected symmetric-key cipher
		// operating in OpenPGP's variant of Cipher Feedback (CFB) mode.
		this.encryptedData = input.substring(position, position + len);
		return this;
	}

	/**
	 * symmetrically decrypt the packet data
	 * 
	 * @param {integer} symmetric_algorithm_type
	 *             symmetric key algorithm to use // See RFC4880 9.2
	 * @param {String} key
	 *             key as string with the corresponding length to the
	 *            algorithm
	 * @return the decrypted data;
	 */
	function decrypt_sym(symmetric_algorithm_type, key) {
		this.decryptedData = openpgp_crypto_symmetricDecrypt(
				symmetric_algorithm_type, key, this.encryptedData, true);
		util.print_debug("openpgp.packet.encryptedintegrityprotecteddata.js\n"+
				"data: "+util.hexstrdump(this.decryptedData));
		return this.decryptedData;
	}

	/**
	 * Creates a string representation of the packet
	 * 
	 * @param {Integer} algo symmetric key algorithm to use // See RFC4880 9.2
	 * @param {String} key key as string with the corresponding length to the
	 *            algorithm
	 * @param {String} data data to be
	 * @return {String} string-representation of the packet
	 */
	function write_packet(algo, key, data) {
		var result = "";
		result += openpgp_crypto_symmetricEncrypt(
				openpgp_crypto_getPrefixRandom(algo), algo, key, data, true);
		result = openpgp_packet.write_packet_header(9, result.length) + result;
		return result;
	}

	function toString() {
		return '5.7.  Symmetrically Encrypted Data Packet (Tag 9)\n'
				+ '    length:  ' + this.packetLength + '\n'
				+ '    Used symmetric algorithm: ' + this.algorithmType + '\n'
				+ '    encrypted data: Bytes ['
				+ util.hexstrdump(this.encryptedData) + ']\n';
	}
	this.decrypt_sym = decrypt_sym;
	this.toString = toString;
	this.read_packet = read_packet;
	this.write_packet = write_packet;
};
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
function openpgp_packet_userattribute() {
	this.tagType = 17;
	this.certificationSignatures = new Array();
	this.certificationRevocationSignatures = new Array();
	this.revocationSignatures = new Array();
	this.parentNode = null;

	/**
	 * parsing function for a user attribute packet (tag 17).
	 * @param {string} input payload of a tag 17 packet
	 * @param {integer} position position to start reading from the input string
	 * @param {integer} len length of the packet or the remaining length of input at position
	 * @return {openpgp_packet_encrypteddata} object representation
	 */
	function read_packet (input, position, len) {
		var total_len = 0;
		this.packetLength = len;
		this.userattributes = new Array();
		var count = 0;
		var mypos = position;
		while (len != total_len) {
			var current_len = 0;
			// 4.2.2.1. One-Octet Lengths
			if (input[mypos].charCodeAt() < 192) {
				packet_length = input[mypos++].charCodeAt();
				current_len = 1;
			// 4.2.2.2. Two-Octet Lengths
			} else if (input[mypos].charCodeAt() >= 192 && input[mypos].charCodeAt() < 224) {
				packet_length = ((input[mypos++].charCodeAt() - 192) << 8)
					+ (input[mypos++].charCodeAt()) + 192;
				current_len = 2;
			// 4.2.2.4. Partial Body Lengths
			} else if (input[mypos].charCodeAt() > 223 && input[mypos].charCodeAt() < 255) {
				packet_length = 1 << (input[mypos++].charCodeAt() & 0x1F);
				current_len = 1;
			// 4.2.2.3. Five-Octet Lengths
			} else {
				current_len = 5;
				mypos++;
				packet_length = (input[mypos++].charCodeAt() << 24) | (input[mypos++].charCodeAt() << 16)
					| (input[mypos++].charCodeAt() << 8) | input[mypos++].charCodeAt();
			}
			
			var subpackettype = input[mypos++].charCodeAt();
			packet_length--;
			current_len++;
			this.userattributes[count] = new Array();
			this.userattributes[count] = input.substring(mypos, mypos + packet_length);
			mypos += packet_length;
			total_len += current_len+packet_length;
		}
		this.packetLength = mypos - position;
		return this;
	}
	
	/**
	 * generates debug output (pretty print)
	 * @return {string} String which gives some information about the user attribute packet
	 */
	function toString() {
		var result = '5.12.  User Attribute Packet (Tag 17)\n'+
		             '    AttributePackets: (count = '+this.userattributes.length+')\n';
		for (var i = 0; i < this.userattributes.length; i++) {
			result += '    ('+this.userattributes[i].length+') bytes: ['+util.hexidump(this.userattributes[i])+']\n'; 
		}
		return result;
	}
	
	/**
	 * Continue parsing packets belonging to the user attribute packet such as signatures
	 * @param {openpgp_*} parent_node the parent object
	 * @param {String} input input string to read the packet(s) from
	 * @param {integer} position start position for the parser
	 * @param {integer} len length of the packet(s) or remaining length of input
	 * @return {integer} length of nodes read
	 */
	function read_nodes(parent_node, input, position, len) {
		
		this.parentNode = parent_node;
		var exit = false;
		var pos = position;
		var l = len;
		while (input.length != pos) {
			var result = openpgp_packet.read_packet(input, pos, l);
			if (result == null) {
				util.print_error("openpgp.packet.userattribute.js\n"+'[user_attr] parsing ends here @:' + pos + " l:" + l);
				break;
			} else {
				switch (result.tagType) {
				case 2: // Signature Packet
					if (result.signatureType > 15
							&& result.signatureType < 20) // certification
						// //
						// signature
						this.certificationSignatures[this.certificationSignatures.length] = result;
					else if (result.signatureType == 32) // certification revocation signature
						this.certificationRevocationSignatures[this.certificationRevocationSignatures.length] = result;
					pos += result.packetLength + result.headerLength;
					l = len - (pos - position);
					break;
				default:
					this.data = input;
					this.position = position - parent_node.packetLength;
					this.len = pos - position;
					return this.len;
					break;
				}
			}
		}
		this.data = input;
		this.position = position - parent_node.packetLength;
		this.len = pos - position;
		return this.len;

	}
	
	this.read_packet = read_packet;
	this.read_nodes = read_nodes;
	this.toString = toString;
	
};
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
 * @classdesc Parent openpgp packet class. Operations focus on determining packet types
 *     and packet header.
 */
function _openpgp_packet() {
	/**
	 * Encodes a given integer of length to the openpgp length specifier to a
	 * string
	 * 
	 * @param {Integer} length of the length to encode
	 * @return {string} string with openpgp length representation
	 */
	function encode_length(length) {
		result = "";
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
			result += String.fromCharCode((length >> 24) & 0xFF);
			result += String.fromCharCode((length >> 16) & 0xFF);
			result += String.fromCharCode((length >> 8) & 0xFF);
			result += String.fromCharCode(length & 0xFF);
		}
		return result;
	}
	this.encode_length = encode_length;

	/**
	 * Writes a packet header version 4 with the given tag_type and length to a
	 * string
	 * 
	 * @param {integer} tag_type tag type
	 * @param {integer} length length of the payload
	 * @return {string} string of the header
	 */
	function write_packet_header(tag_type, length) {
		/* we're only generating v4 packet headers here */
		var result = "";
		result += String.fromCharCode(0xC0 | tag_type);
		result += encode_length(length);
		return result;
	}

	/**
	 * Writes a packet header Version 3 with the given tag_type and length to a
	 * string
	 * 
	 * @param {integer} tag_type tag type
	 * @param {integer} length length of the payload
	 * @return {string} string of the header
	 */
	function write_old_packet_header(tag_type, length) {
		var result = "";
		if (length < 256) {
			result += String.fromCharCode(0x80 | (tag_type << 2));
			result += String.fromCharCode(length);
		} else if (length < 65536) {
			result += String.fromCharCode(0x80 | (tag_type << 2) | 1);
			result += String.fromCharCode(length >> 8);
			result += String.fromCharCode(length & 0xFF);
		} else {
			result += String.fromCharCode(0x80 | (tag_type << 2) | 2);
			result += String.fromCharCode((length >> 24) & 0xFF);
			result += String.fromCharCode((length >> 16) & 0xFF);
			result += String.fromCharCode((length >> 8) & 0xFF);
			result += String.fromCharCode(length & 0xFF);
		}
		return result;
	}
	this.write_old_packet_header = write_old_packet_header;
	this.write_packet_header = write_packet_header;
	/**
	 * Generic static Packet Parser function
	 * 
	 * @param {String} input input stream as string
	 * @param {integer} position position to start parsing
	 * @param {integer} len length of the input from position on
	 * @return {openpgp_packet_*} returns a parsed openpgp_packet
	 */
	function read_packet(input, position, len) {
		// some sanity checks
		if (input == null || input.length <= position
				|| input.substring(position).length < 2
				|| (input[position].charCodeAt() & 0x80) == 0) {
			util
					.print_error("Error during parsing. This message / key is propably not containing a valid OpenPGP format.");
			return null;
		}
		var mypos = position;
		var tag = -1;
		var format = -1;

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

		// alert('tag type: '+this.tag+' length: '+packet_length);
		var version = 1; // (old format; 2= new format)
		// if (input[mypos++].charCodeAt() > 15)
		// version = 2;

		switch (tag) {
		case 0: // Reserved - a packet tag MUST NOT have this value
			break;
		case 1: // Public-Key Encrypted Session Key Packet
			var result = new openpgp_packet_encryptedsessionkey();
			if (result.read_pub_key_packet(bodydata, 0, packet_length) != null) {
				result.headerLength = mypos - position;
				result.packetLength = real_packet_length;
				return result;
			}
			break;
		case 2: // Signature Packet
			var result = new openpgp_packet_signature();
			if (result.read_packet(bodydata, 0, packet_length) != null) {
				result.headerLength = mypos - position;
				result.packetLength = real_packet_length;
				return result;
			}
			break;
		case 3: // Symmetric-Key Encrypted Session Key Packet
			var result = new openpgp_packet_encryptedsessionkey();
			if (result.read_symmetric_key_packet(bodydata, 0, packet_length) != null) {
				result.headerLength = mypos - position;
				result.packetLength = real_packet_length;
				return result;
			}
			break;
		case 4: // One-Pass Signature Packet
			var result = new openpgp_packet_onepasssignature();
			if (result.read_packet(bodydata, 0, packet_length)) {
				result.headerLength = mypos - position;
				result.packetLength = real_packet_length;
				return result;
			}
			break;
		case 5: // Secret-Key Packet
			var result = new openpgp_packet_keymaterial();
			result.header = input.substring(position, mypos);
			if (result.read_tag5(bodydata, 0, packet_length) != null) {
				result.headerLength = mypos - position;
				result.packetLength = real_packet_length;
				return result;
			}
			break;
		case 6: // Public-Key Packet
			var result = new openpgp_packet_keymaterial();
			result.header = input.substring(position, mypos);
			if (result.read_tag6(bodydata, 0, packet_length) != null) {
				result.headerLength = mypos - position;
				result.packetLength = real_packet_length;
				return result;
			}
			break;
		case 7: // Secret-Subkey Packet
			var result = new openpgp_packet_keymaterial();
			if (result.read_tag7(bodydata, 0, packet_length) != null) {
				result.headerLength = mypos - position;
				result.packetLength = real_packet_length;
				return result;
			}
			break;
		case 8: // Compressed Data Packet
			var result = new openpgp_packet_compressed();
			if (result.read_packet(bodydata, 0, packet_length) != null) {
				result.headerLength = mypos - position;
				result.packetLength = real_packet_length;
				return result;
			}
			break;
		case 9: // Symmetrically Encrypted Data Packet
			var result = new openpgp_packet_encrypteddata();
			if (result.read_packet(bodydata, 0, packet_length) != null) {
				result.headerLength = mypos - position;
				result.packetLength = real_packet_length;
				return result;
			}
			break;
		case 10: // Marker Packet = PGP (0x50, 0x47, 0x50)
			var result = new openpgp_packet_marker();
			if (result.read_packet(bodydata, 0, packet_length) != null) {
				result.headerLength = mypos - position;
				result.packetLength = real_packet_length;
				return result;
			}
			break;
		case 11: // Literal Data Packet
			var result = new openpgp_packet_literaldata();
			if (result.read_packet(bodydata, 0, packet_length) != null) {
				result.headerLength = mypos - position;
				result.header = input.substring(position, mypos);
				result.packetLength = real_packet_length;
				return result;
			}
			break;
		case 12: // Trust Packet
			// TODO: to be implemented
			break;
		case 13: // User ID Packet
			var result = new openpgp_packet_userid();
			if (result.read_packet(bodydata, 0, packet_length) != null) {
				result.headerLength = mypos - position;
				result.packetLength = real_packet_length;
				return result;
			}
			break;
		case 14: // Public-Subkey Packet
			var result = new openpgp_packet_keymaterial();
			result.header = input.substring(position, mypos);
			if (result.read_tag14(bodydata, 0, packet_length) != null) {
				result.headerLength = mypos - position;
				result.packetLength = real_packet_length;
				return result;
			}
			break;
		case 17: // User Attribute Packet
			var result = new openpgp_packet_userattribute();
			if (result.read_packet(bodydata, 0, packet_length) != null) {
				result.headerLength = mypos - position;
				result.packetLength = real_packet_length;
				return result;
			}
			break;
		case 18: // Sym. Encrypted and Integrity Protected Data Packet
			var result = new openpgp_packet_encryptedintegrityprotecteddata();
			if (result.read_packet(bodydata, 0, packet_length) != null) {
				result.headerLength = mypos - position;
				result.packetLength = real_packet_length;
				return result;
			}
			break;
		case 19: // Modification Detection Code Packet
			var result = new openpgp_packet_modificationdetectioncode();
			if (result.read_packet(bodydata, 0, packet_length) != null) {
				result.headerLength = mypos - position;
				result.packetLength = real_packet_length;
				return result;
			}
			break;
		default:
			util.print_error("openpgp.packet.js\n"
					+ "[ERROR] openpgp_packet: failed to parse packet @:"
					+ mypos + "\nchar:'"
					+ util.hexstrdump(input.substring(mypos)) + "'\ninput:"
					+ util.hexstrdump(input));
			return null;
			break;
		}
	}

	this.read_packet = read_packet;
}

var openpgp_packet = new _openpgp_packet();
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
 * @classdesc Implementation of the Compressed Data Packet (Tag 8)
 * 
 * RFC4880 5.6:
 * The Compressed Data packet contains compressed data.  Typically, this
 * packet is found as the contents of an encrypted packet, or following
 * a Signature or One-Pass Signature packet, and contains a literal data
 * packet.
 */   
function openpgp_packet_compressed() {
	this.tagType = 8;
	this.decompressedData = null;
	
	/**
	 * parsing function for the packet.
	 * @param {string} input payload of a tag 8 packet
	 * @param {integer} position position to start reading from the input string
	 * @param {integer} len length of the packet or the remaining length of input at position
	 * @return {openpgp_packet_compressed} object representation
	 */
	function read_packet (input, position, len) {
		this.packetLength = len;
		var mypos = position;
		// One octet that gives the algorithm used to compress the packet.
		this.type = input.charCodeAt(mypos++);
		// Compressed data, which makes up the remainder of the packet.
		this.compressedData = input.substring(position+1, position+len);
		return this;
	}
	/**
	 * decompression method for decompressing the compressed data
	 * read by read_packet
	 * @return {String} the decompressed data
	 */
	function decompress() {
		if (this.decompressedData != null)
			return this.decompressedData;

		if (this.type == null)
			return null;

		switch (this.type) {
		case 0: // - Uncompressed
			this.decompressedData = this.compressedData;
			break;
		case 1: // - ZIP [RFC1951]
			util.print_info('Decompressed packet [Type 1-ZIP]: ' + this.toString());
			var compData = this.compressedData;
			var radix = s2r(compData).replace(/\n/g,"");
			// no header in this case, directly call deflate
			var jxg_obj = new JXG.Util.Unzip(JXG.Util.Base64.decodeAsArray(radix));
			this.decompressedData = unescape(jxg_obj.deflate()[0][0]);
			break;
		case 2: // - ZLIB [RFC1950]
			util.print_info('Decompressed packet [Type 2-ZLIB]: ' + this.toString());
			var compressionMethod = this.compressedData.charCodeAt(0) % 0x10; //RFC 1950. Bits 0-3 Compression Method
			//Bits 4-7 RFC 1950 are LZ77 Window. Generally this value is 7 == 32k window size.
			//2nd Byte in RFC 1950 is for "FLAGs" Allows for a Dictionary (how is this defined). Basic checksum, and compression level.
			if (compressionMethod == 8) { //CM 8 is for DEFLATE, RFC 1951
				// remove 4 bytes ADLER32 checksum from the end
				var compData = this.compressedData.substring(0, this.compressedData.length - 4);
				var radix = s2r(compData).replace(/\n/g,"");
				//TODO check ADLER32 checksum
				this.decompressedData = JXG.decompress(radix);
				break;
			} else {
				util.print_error("Compression algorithm ZLIB only supports DEFLATE compression method.");
			}
			break;
		case 3: //  - BZip2 [BZ2]
			// TODO: need to implement this
			util.print_error("Compression algorithm BZip2 [BZ2] is not implemented.");
			break;
		default:
			util.print_error("Compression algorithm unknown :"+this.type);
			break;
		}
		util.print_debug("decompressed:"+util.hexstrdump(this.decompressedData));
		return this.decompressedData; 
	}

	/**
	 * Compress the packet data (member decompressedData)
	 * @param {integer} type algorithm to be used // See RFC 4880 9.3
	 * @param {String} data data to be compressed
	 * @return {String} The compressed data stored in attribute compressedData
	 */
	function compress(type, data) {
		this.type = type;
		this.decompressedData = data;
		switch (this.type) {
		case 0: // - Uncompressed
			this.compressedData = this.decompressedData;
			break;
		case 1: // - ZIP [RFC1951]
			util.print_error("Compression algorithm ZIP [RFC1951] is not implemented.");
			break;
		case 2: // - ZLIB [RFC1950]
			// TODO: need to implement this
			util.print_error("Compression algorithm ZLIB [RFC1950] is not implemented.");
			break;
		case 3: //  - BZip2 [BZ2]
			// TODO: need to implement this
			util.print_error("Compression algorithm BZip2 [BZ2] is not implemented.");
			break;
		default:
			util.print_error("Compression algorithm unknown :"+this.type);
			break;
		}
		this.packetLength = this.compressedData.length +1;
		return this.compressedData; 
	}
	
	/**
	 * creates a string representation of the packet
	 * @param {integer} algorithm algorithm to be used // See RFC 4880 9.3
	 * @param {String} data data to be compressed
	 * @return {String} string-representation of the packet
	 */
	function write_packet(algorithm, data) {
		this.decompressedData = data;
		if (algorithm == null) {
			this.type = 1;
		}
		var result = String.fromCharCode(this.type)+this.compress(this.type);
		return openpgp_packet.write_packet_header(8, result.length)+result;
	}
	
	/**
	 * pretty printing the packet (useful for debug purposes)
	 * @return {String}
	 */
	function toString() {
		return '5.6.  Compressed Data Packet (Tag 8)\n'+
		   '    length:  '+this.packetLength+'\n'+
			   '    Compression Algorithm = '+this.type+'\n'+
		       '    Compressed Data: Byte ['+util.hexstrdump(this.compressedData)+']\n';
	}
	
	this.read_packet = read_packet;
	this.toString = toString;
	this.compress = compress;
	this.decompress = decompress;
	this.write_packet = write_packet;
};
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
function openpgp_packet_keymaterial() {
	// members:
	this.publicKeyAlgorithm = null;
	this.tagType = null;
	this.creationTime = null;
	this.version = null;
	this.expiration  = null;// V3
	this.MPIs = null;
	this.secMPIs = null;
	this.publicKey = null;
	this.symmetricEncryptionAlgorithm = null;
	this.s2kUsageConventions = null;
	this.IVLength  = null;
    this.encryptedMPIData = null;
    this.hasUnencryptedSecretKeyData = null;
    this.checksum = null;
    this.parentNode = null;
	this.subKeySignature = null;
	this.subKeyRevocationSignature = null;

	// 5.5.1. Key Packet Variants
	
	// 5.5.1.3. Secret-Key Packet (Tag 5)
	/**
	 * This function reads the payload of a secret key packet (Tag 5)
	 * and initializes the openpgp_packet_keymaterial
	 * @param input input string to read the packet from
	 * @param position start position for the parser
	 * @param len length of the packet or remaining length of input
	 * @return openpgp_packet_keymaterial object
	 */
	function read_tag5(input, position, len) {
		this.tagType = 5;
		this.read_priv_key(input, position, len);
		return this;
	}

	// 5.5.1.1. Public-Key Packet (Tag 6)
	/**
	 * This function reads the payload of a public key packet (Tag 6)
	 * and initializes the openpgp_packet_keymaterial
	 * @param input input string to read the packet from
	 * @param position start position for the parser
	 * @param len length of the packet or remaining length of input
	 * @return openpgp_packet_keymaterial object
	 */
	function read_tag6(input, position, len) {
		// A Public-Key packet starts a series of packets that forms an OpenPGP
		// key (sometimes called an OpenPGP certificate).
		this.tagType = 6;
		this.packetLength = len;
		this.read_pub_key(input, position,len);
		
		return this;
	}

	// 5.5.1.4. Secret-Subkey Packet (Tag 7)
	/**
	 * This function reads the payload of a secret key sub packet (Tag 7)
	 * and initializes the openpgp_packet_keymaterial
	 * @param input input string to read the packet from
	 * @param position start position for the parser
	 * @param len length of the packet or remaining length of input
	 * @return openpgp_packet_keymaterial object
	 */
	function read_tag7(input, position, len) {
		this.tagType = 7;
		this.packetLength = len;
		return this.read_priv_key(input, position, len);
	}

	// 5.5.1.2. Public-Subkey Packet (Tag 14)
	/**
	 * This function reads the payload of a public key sub packet (Tag 14)
	 * and initializes the openpgp_packet_keymaterial
	 * @param input input string to read the packet from
	 * @param position start position for the parser
	 * @param len length of the packet or remaining length of input
	 * @return openpgp_packet_keymaterial object
	 */
	function read_tag14(input, position, len) {
		this.subKeySignature = null;
		this.subKeyRevocationSignature = new Array();
		this.tagType = 14;
		this.packetLength = len;
		this.read_pub_key(input, position,len);
		return this;
	}
	
	/**
	 * Internal Parser for public keys as specified in RFC 4880 section 5.5.2 Public-Key Packet Formats
	 * called by read_tag&lt;num&gt;
	 * @param input input string to read the packet from
	 * @param position start position for the parser
	 * @param len length of the packet or remaining length of input
	 * @return this object with attributes set by the parser
	 */  
	function read_pub_key(input, position, len) {
		var mypos = position;
		// A one-octet version number (3 or 4).
		this.version = input[mypos++].charCodeAt();
		if (this.version == 3) {
			// A four-octet number denoting the time that the key was created.
			this.creationTime = new Date(((input[mypos++].charCodeAt() << 24) |
				(input[mypos++].charCodeAt() << 16) |
				(input[mypos++].charCodeAt() <<  8) |
				(input[mypos++].charCodeAt()))*1000);
			
		    // - A two-octet number denoting the time in days that this key is
		    //   valid.  If this number is zero, then it does not expire.
			this.expiration = (input[mypos++].charCodeAt() << 8) & input[mypos++].charCodeAt();
	
		    // - A one-octet number denoting the public-key algorithm of this key.
			this.publicKeyAlgorithm = input[mypos++].charCodeAt();
			var mpicount = 0;
		    // - A series of multiprecision integers comprising the key material:
			//   Algorithm-Specific Fields for RSA public keys:
		    //       - a multiprecision integer (MPI) of RSA public modulus n;
		    //       - an MPI of RSA public encryption exponent e.
			if (this.publicKeyAlgorithm > 0 && this.publicKeyAlgorithm < 4)
				mpicount = 2;
			//   Algorithm-Specific Fields for Elgamal public keys:
			//     - MPI of Elgamal prime p;
			//     - MPI of Elgamal group generator g;
			//     - MPI of Elgamal public key value y (= g**x mod p where x  is secret).

			else if (this.publicKeyAlgorithm == 16)
				mpicount = 3;
			//   Algorithm-Specific Fields for DSA public keys:
			//       - MPI of DSA prime p;
			//       - MPI of DSA group order q (q is a prime divisor of p-1);
			//       - MPI of DSA group generator g;
			//       - MPI of DSA public-key value y (= g**x mod p where x  is secret).
			else if (this.publicKeyAlgorithm == 17)
				mpicount = 4;

			this.MPIs = new Array();
			for (var i = 0; i < mpicount; i++) {
				this.MPIs[i] = new openpgp_type_mpi();
				if (this.MPIs[i].read(input, mypos, (mypos-position)) != null && 
						!this.packetLength < (mypos-position)) {
					mypos += this.MPIs[i].packetLength;
				} else {
					util.print_error("openpgp.packet.keymaterial.js\n"+'error reading MPI @:'+mypos);
				}
			}
			this.packetLength = mypos-position;
		} else if (this.version == 4) {
			// - A four-octet number denoting the time that the key was created.
			this.creationTime = new Date(((input[mypos++].charCodeAt() << 24) |
			(input[mypos++].charCodeAt() << 16) |
			(input[mypos++].charCodeAt() <<  8) |
			(input[mypos++].charCodeAt()))*1000);
			
			// - A one-octet number denoting the public-key algorithm of this key.
			this.publicKeyAlgorithm = input[mypos++].charCodeAt();
			var mpicount = 0;
		    // - A series of multiprecision integers comprising the key material:
			//   Algorithm-Specific Fields for RSA public keys:
		    //       - a multiprecision integer (MPI) of RSA public modulus n;
		    //       - an MPI of RSA public encryption exponent e.
			if (this.publicKeyAlgorithm > 0 && this.publicKeyAlgorithm < 4)
					mpicount = 2;
			//   Algorithm-Specific Fields for Elgamal public keys:
			//     - MPI of Elgamal prime p;
			//     - MPI of Elgamal group generator g;
			//     - MPI of Elgamal public key value y (= g**x mod p where x  is secret).
			else if (this.publicKeyAlgorithm == 16)
				mpicount = 3;

			//   Algorithm-Specific Fields for DSA public keys:
			//       - MPI of DSA prime p;
			//       - MPI of DSA group order q (q is a prime divisor of p-1);
			//       - MPI of DSA group generator g;
			//       - MPI of DSA public-key value y (= g**x mod p where x  is secret).
			else if (this.publicKeyAlgorithm == 17)
				mpicount = 4;

			this.MPIs = new Array();
			var i = 0;
			for (var i = 0; i < mpicount; i++) {
				this.MPIs[i] = new openpgp_type_mpi();
				if (this.MPIs[i].read(input, mypos, (mypos-position)) != null &&
						!this.packetLength < (mypos-position)) {
					mypos += this.MPIs[i].packetLength;
				} else {
					util.print_error("openpgp.packet.keymaterial.js\n"+'error reading MPI @:'+mypos);
				}
			}
			this.packetLength = mypos-position;
		} else {
			return null;
		}
		this.data = input.substring(position, mypos);
		this.packetdata = input.substring(position, mypos);
		return this;
	}
	
	// 5.5.3.  Secret-Key Packet Formats
	
	/**
	 * Internal parser for private keys as specified in RFC 4880 section 5.5.3
	 * @param input input string to read the packet from
	 * @param position start position for the parser
	 * @param len length of the packet or remaining length of input
	 * @return this object with attributes set by the parser
	 */
	function read_priv_key(input,position, len) {
	    // - A Public-Key or Public-Subkey packet, as described above.
	    this.publicKey = new openpgp_packet_keymaterial();
		if (this.publicKey.read_pub_key(input,position, len) == null) {
			util.print_error("openpgp.packet.keymaterial.js\n"+"Failed reading public key portion of a private key: "+input[position].charCodeAt()+" "+position+" "+len+"\n Aborting here...");
			return null;
		}
		this.publicKey.header = openpgp_packet.write_old_packet_header(6,this.publicKey.packetLength);
		// this.publicKey.header = String.fromCharCode(0x99) + String.fromCharCode(this.publicKey.packetLength >> 8 & 0xFF)+String.fromCharCode(this.publicKey.packetLength & 0xFF);
		var mypos = position + this.publicKey.data.length;
		this.packetLength = len;
		
	    // - One octet indicating string-to-key usage conventions.  Zero
	    //   indicates that the secret-key data is not encrypted.  255 or 254
	    //   indicates that a string-to-key specifier is being given.  Any
	    //   other value is a symmetric-key encryption algorithm identifier.
	    this.s2kUsageConventions = input[mypos++].charCodeAt();
	    
	    if (this.s2kUsageConventions == 0)
	    	this.hasUnencryptedSecretKeyData = true;
	   
	    // - [Optional] If string-to-key usage octet was 255 or 254, a one-
	    //   octet symmetric encryption algorithm.
	    if (this.s2kUsageConventions == 255 || this.s2kUsageConventions == 254) {
	    	this.symmetricEncryptionAlgorithm = input[mypos++].charCodeAt();
	    }
	     
	    // - [Optional] If string-to-key usage octet was 255 or 254, a
	    //   string-to-key specifier.  The length of the string-to-key
	    //   specifier is implied by its type, as described above.
	    if (this.s2kUsageConventions == 255 || this.s2kUsageConventions == 254) {
	    	this.s2k = new openpgp_type_s2k();
	    	this.s2k.read(input, mypos);
	    	mypos +=this.s2k.s2kLength;
	    }
	    
	    // - [Optional] If secret data is encrypted (string-to-key usage octet
	    //   not zero), an Initial Vector (IV) of the same length as the
	    //   cipher's block size.
	    this.symkeylength = 0;
	    if (this.s2kUsageConventions != 0 && this.s2kUsageConventions != 255 &&
	    		this.s2kUsageConventions != 254) {
	    	this.symmetricEncryptionAlgorithm = this.s2kUsageConventions;
	    }
	    if (this.s2kUsageConventions != 0) {
	    	this.hasIV = true;
	    	switch (this.symmetricEncryptionAlgorithm) {
		    case  1: // - IDEA [IDEA]
		    	util.print_error("openpgp.packet.keymaterial.js\n"+"symmetric encrytryption algorithim: IDEA is not implemented");
		    	return null;
	    	case  2: // - TripleDES (DES-EDE, [SCHNEIER] [HAC] - 168 bit key derived from 192)
	    	case  3: // - CAST5 (128 bit key, as per [RFC2144])
	    		this.IVLength = 8;
		    	break;
		    case  4: // - Blowfish (128 bit key, 16 rounds) [BLOWFISH]
		    case  7: // - AES with 128-bit key [AES]
	    	case  8: // - AES with 192-bit key
	    	case  9: // - AES with 256-bit key
	    		this.IVLength = 16;
		    	break;
	    	case 10: // - Twofish with 256-bit key [TWOFISH]
	    		this.IVLength = 32;	    		
		    	break;
	    	case  5: // - Reserved
	    	case  6: // - Reserved
	    	default:
	    		util.print_error("openpgp.packet.keymaterial.js\n"+"unknown encryption algorithm for secret key :"+this.symmetricEncryptionAlgorithm);
	    		return null;
	    	}
	    	mypos++; 
	    	this.IV = input.substring(mypos, mypos+this.IVLength);
	    	mypos += this.IVLength;
	    }
	    // - Plain or encrypted multiprecision integers comprising the secret
	    //   key data.  These algorithm-specific fields are as described
	    //   below.

	    //
	    //
	    if (!this.hasUnencryptedSecretKeyData) {
	    	this.encryptedMPIData = input.substring(mypos, len);
	    	mypos += this.encryptedMPIData.length;
	    } else {
	    	if (this.publicKey.publicKeyAlgorithm > 0 && this.publicKey.publicKeyAlgorithm < 4) {
	    		//   Algorithm-Specific Fields for RSA secret keys:
	    		//   - multiprecision integer (MPI) of RSA secret exponent d.
	    		//   - MPI of RSA secret prime value p.
	    		//   - MPI of RSA secret prime value q (p < q).
	    		//   - MPI of u, the multiplicative inverse of p, mod q.
	    		this.secMPIs = new Array();
	    		this.secMPIs[0] = new openpgp_type_mpi();
	    		this.secMPIs[0].read(input, mypos, len-2- (mypos - position));
	    		mypos += this.secMPIs[0].packetLength;
	    		this.secMPIs[1] = new openpgp_type_mpi();
	    		this.secMPIs[1].read(input, mypos, len-2- (mypos - position));
	    		mypos += this.secMPIs[1].packetLength;
	    		this.secMPIs[2] = new openpgp_type_mpi();
	    		this.secMPIs[2].read(input, mypos, len-2- (mypos - position));
	    		mypos += this.secMPIs[2].packetLength;
	    		this.secMPIs[3] = new openpgp_type_mpi();
	    		this.secMPIs[3].read(input, mypos, len-2- (mypos - position));
	    		mypos += this.secMPIs[3].packetLength;
	    	} else if (this.publicKey.publicKeyAlgorithm == 16) {
	    		// Algorithm-Specific Fields for Elgamal secret keys:
	    		//   - MPI of Elgamal secret exponent x.
	    		this.secMPIs = new Array();
	    		this.secMPIs[0] = new openpgp_type_mpi();
	    		this.secMPIs[0].read(input, mypos, len-2- (mypos - position));
	    		mypos += this.secMPIs[0].packetLength;
	    	} else if (this.publicKey.publicKeyAlgorithm == 17) {
	    		// Algorithm-Specific Fields for DSA secret keys:
	    		//   - MPI of DSA secret exponent x.
	    		this.secMPIs = new Array();
	    		this.secMPIs[0] = new openpgp_type_mpi();
	    		this.secMPIs[0].read(input, mypos, len-2- (mypos - position));
	    		mypos += this.secMPIs[0].packetLength;
	    	}
	    	// checksum because s2k usage convention is 0
	        this.checksum = new Array(); 
		    this.checksum[0] = input[mypos++].charCodeAt();
		    this.checksum[1] = input[mypos++].charCodeAt();
	    }
	    return this;
	}
	

	/**
	 * Decrypts the private key MPIs which are needed to use the key.
	 * openpgp_packet_keymaterial.hasUnencryptedSecretKeyData should be false otherwise
	 * a call to this function is not needed
	 * 
	 * @param str_passphrase the passphrase for this private key as string
	 * @return true if the passphrase was correct; false if not
	 */
	function decryptSecretMPIs(str_passphrase) {
		if (this.hasUnencryptedSecretKeyData)
			return this.secMPIs;
		// creating a key out of the passphrase
		var key = this.s2k.produce_key(str_passphrase);
		var cleartextMPIs = "";
    	switch (this.symmetricEncryptionAlgorithm) {
	    case  1: // - IDEA [IDEA]
	    	util.print_error("openpgp.packet.keymaterial.js\n"+"symmetric encryption algorithim: IDEA is not implemented");
	    	return false;
    	case  2: // - TripleDES (DES-EDE, [SCHNEIER] [HAC] - 168 bit key derived from 192)
    		cleartextMPIs = normal_cfb_decrypt(function(block, key) {
    			return des(key, block,1,null,0);
    		}, this.IVLength, key, this.encryptedMPIData, this.IV);
    		break;
    	case  3: // - CAST5 (128 bit key, as per [RFC2144])
    		cleartextMPIs = normal_cfb_decrypt(function(block, key) {
        		var cast5 = new openpgp_symenc_cast5();
        		cast5.setKey(key);
        		return cast5.encrypt(util.str2bin(block)); 
    		}, this.IVLength, util.str2bin(key.substring(0,16)), this.encryptedMPIData, this.IV);
    		break;
	    case  4: // - Blowfish (128 bit key, 16 rounds) [BLOWFISH]
	    	cleartextMPIs = normal_cfb_decrypt(function(block, key) {
    			var blowfish = new Blowfish(key);
        		return blowfish.encrypt(block); 
    		}, this.IVLength, key, this.encryptedMPIData, this.IV);
    		break;
	    case  7: // - AES with 128-bit key [AES]
    	case  8: // - AES with 192-bit key
    	case  9: // - AES with 256-bit key
    	    var numBytes = 16;
            //This is a weird way to achieve this. If's within a switch is probably not ideal.
    	    if(this.symmetricEncryptionAlgorithm == 8){
    	        numBytes = 24;
    	        key = this.s2k.produce_key(str_passphrase,numBytes);
    	    }
    	    if(this.symmetricEncryptionAlgorithm == 9){
    	        numBytes = 32;
    	        key = this.s2k.produce_key(str_passphrase,numBytes);
    	    }
    		cleartextMPIs = normal_cfb_decrypt(function(block,key){
    		    return AESencrypt(util.str2bin(block),key);
    		},
    				this.IVLength, keyExpansion(key.substring(0,numBytes)), this.encryptedMPIData, this.IV);
	    	break;
    	case 10: // - Twofish with 256-bit key [TWOFISH]
    		util.print_error("openpgp.packet.keymaterial.js\n"+"Key material is encrypted with twofish: not implemented");   		
	    	return false;
    	case  5: // - Reserved
    	case  6: // - Reserved
    	default:
    		util.print_error("openpgp.packet.keymaterial.js\n"+"unknown encryption algorithm for secret key :"+this.symmetricEncryptionAlgorithm);
    		return false;
    	}
    	
    	if (cleartextMPIs == null) {
    		util.print_error("openpgp.packet.keymaterial.js\n"+"cleartextMPIs was null");
    		return false;
    	}
    	
    	var cleartextMPIslength = cleartextMPIs.length;

    	if (this.s2kUsageConventions == 254 &&
    			str_sha1(cleartextMPIs.substring(0,cleartextMPIs.length - 20)) == 
    				cleartextMPIs.substring(cleartextMPIs.length - 20)) {
    		cleartextMPIslength -= 20;
    	} else if (this.s2kUsageConventions != 254 && util.calc_checksum(cleartextMPIs.substring(0,cleartextMPIs.length - 2)) == 
    			(cleartextMPIs.charCodeAt(cleartextMPIs.length -2) << 8 | cleartextMPIs.charCodeAt(cleartextMPIs.length -1))) {
    		cleartextMPIslength -= 2;
    	} else {
    		return false;
    	}

    	if (this.publicKey.publicKeyAlgorithm > 0 && this.publicKey.publicKeyAlgorithm < 4) {
    		//   Algorithm-Specific Fields for RSA secret keys:
    		//   - multiprecision integer (MPI) of RSA secret exponent d.
    		//   - MPI of RSA secret prime value p.
    		//   - MPI of RSA secret prime value q (p < q).
    		//   - MPI of u, the multiplicative inverse of p, mod q.
    		var mypos = 0;
    		this.secMPIs = new Array();
    		this.secMPIs[0] = new openpgp_type_mpi();
    		this.secMPIs[0].read(cleartextMPIs, 0, cleartextMPIslength);
    		mypos += this.secMPIs[0].packetLength;
    		this.secMPIs[1] = new openpgp_type_mpi();
    		this.secMPIs[1].read(cleartextMPIs, mypos, cleartextMPIslength-mypos);
    		mypos += this.secMPIs[1].packetLength;
    		this.secMPIs[2] = new openpgp_type_mpi();
    		this.secMPIs[2].read(cleartextMPIs, mypos, cleartextMPIslength-mypos);
    		mypos += this.secMPIs[2].packetLength;
    		this.secMPIs[3] = new openpgp_type_mpi();
    		this.secMPIs[3].read(cleartextMPIs, mypos, cleartextMPIslength-mypos);
    		mypos += this.secMPIs[3].packetLength;
    	} else if (this.publicKey.publicKeyAlgorithm == 16) {
    		// Algorithm-Specific Fields for Elgamal secret keys:
    		//   - MPI of Elgamal secret exponent x.
    		this.secMPIs = new Array();
    		this.secMPIs[0] = new openpgp_type_mpi();
    		this.secMPIs[0].read(cleartextMPIs, 0, cleartextMPIs);
    	} else if (this.publicKey.publicKeyAlgorithm == 17) {
    		// Algorithm-Specific Fields for DSA secret keys:
    		//   - MPI of DSA secret exponent x.
    		this.secMPIs = new Array();
    		this.secMPIs[0] = new openpgp_type_mpi();
    		this.secMPIs[0].read(cleartextMPIs, 0, cleartextMPIslength);
    	}
    	return true;
	}
	
	/**
	 * Generates Debug output
	 * @return String which gives some information about the keymaterial
	 */
	function toString() {
		var result = "";
		switch (this.tagType) {
		case 6:
			 result += '5.5.1.1. Public-Key Packet (Tag 6)\n'+
			   '    length:             '+this.packetLength+'\n'+
			   '    version:            '+this.version+'\n'+
			   '    creation time:      '+this.creationTime+'\n'+
			   '    expiration time:    '+this.expiration+'\n'+
			   '    publicKeyAlgorithm: '+this.publicKeyAlgorithm+'\n';
			break;
		case 14:
			result += '5.5.1.2. Public-Subkey Packet (Tag 14)\n'+
			   '    length:             '+this.packetLength+'\n'+
			   '    version:            '+this.version+'\n'+
			   '    creation time:      '+this.creationTime+'\n'+
			   '    expiration time:    '+this.expiration+'\n'+
			   '    publicKeyAlgorithm: '+this.publicKeyAlgorithm+'\n';
			break;
		case 5:
			result +='5.5.1.3. Secret-Key Packet (Tag 5)\n'+
			   '    length:             '+this.packetLength+'\n'+
			   '    version:            '+this.publicKey.version+'\n'+
			   '    creation time:      '+this.publicKey.creationTime+'\n'+
			   '    expiration time:    '+this.publicKey.expiration+'\n'+
			   '    publicKeyAlgorithm: '+this.publicKey.publicKeyAlgorithm+'\n';
			break;
		case 7:
			result += '5.5.1.4. Secret-Subkey Packet (Tag 7)\n'+
			   '    length:             '+this.packetLength+'\n'+
			   '    version[1]:         '+(this.version == 4)+'\n'+
			   '    creationtime[4]:    '+this.creationTime+'\n'+
			   '    expiration[2]:      '+this.expiration+'\n'+
			   '    publicKeyAlgorithm: '+this.publicKeyAlgorithm+'\n';
			break;
		default:
			result += 'unknown key material packet\n';
		}
		if (this.MPIs != null) {
			result += "Public Key MPIs:\n";
			for (var i = 0; i < this.MPIs.length; i++) {
      	  	result += this.MPIs[i].toString();
        	}
		}
		if (this.publicKey != null && this.publicKey.MPIs != null) {
			result += "Public Key MPIs:\n";
			for (var i = 0; i < this.publicKey.MPIs.length; i++) {
	      	  	result += this.publicKey.MPIs[i].toString();
        	}
		}
		if (this.secMPIs != null) {
			result += "Secret Key MPIs:\n";
			for (var i = 0; i < this.secMPIs.length; i++) {
		      	  result += this.secMPIs[i].toString();
		        }
		}
		
		if (this.subKeySignature != null)
			result += "subKey Signature:\n"+this.subKeySignature.toString();
		
		if (this.subKeyRevocationSignature != null )
			result += "subKey Revocation Signature:\n"+this.subKeyRevocationSignature.toString();
        return result;
	}
	
	/**
	 * Continue parsing packets belonging to the key material such as signatures
	 * @param {openpgp_*} parent_node the parent object
	 * @param {String} input input string to read the packet(s) from
	 * @param {integer} position start position for the parser
	 * @param {integer} len length of the packet(s) or remaining length of input
	 * @return {integer} length of nodes read
	 */
	function read_nodes(parent_node, input, position, len) {
		this.parentNode = parent_node;
		if (this.tagType == 14) { // public sub-key packet
			var pos = position;
			var result = null;
			while (input.length != pos) {
				var l = input.length - pos;
				result = openpgp_packet.read_packet(input, pos, l);
				if (result == null) {
					util.print_error("openpgp.packet.keymaterial.js\n"+'[user_keymat_pub]parsing ends here @:' + pos + " l:" + l);
					break;
				} else {
					
					switch (result.tagType) {
					case 2: // Signature Packet certification signature
						if (result.signatureType == 24)  { // subkey binding signature
							this.subKeySignature = result;
							pos += result.packetLength + result.headerLength;
							break;
						} else if (result.signatureType == 40) { // subkey revocation signature
							this.subKeyRevocationSignature[this.subKeyRevocationSignature.length] = result;
							pos += result.packetLength + result.headerLength;
							break;
						} else {
							util.print_error("openpgp.packet.keymaterial.js\nunknown signature:"+result.toString());
						}
						
					default:
						this.data = input;
						this.position = position - this.parentNode.packetLength;
						this.len = pos - position;
						return this.len;
						break;
					}
				}
			}
			this.data = input;
			this.position = position - this.parentNode.packetLength;
			this.len = pos - position;
			return this.len;
		} else if (this.tagType == 7) { // private sub-key packet
			var pos = position;
			while (input.length != pos) {
				var result = openpgp_packet.read_packet(input, pos, len - (pos - position));
				if (result == null) {
					util.print_error("openpgp.packet.keymaterial.js\n"+'[user_keymat_priv] parsing ends here @:' + pos);
					break;
				} else {
					switch (result.tagType) {
					case 2: // Signature Packet certification signature
						if (result.signatureType == 24) // subkey embedded signature
							this.subKeySignature = result; 
						else if (result.signatureType == 40) // subkey revocation signature
							this.subKeyRevocationSignature[this.subKeyRevocationSignature.length] = result;
						pos += result.packetLength + result.headerLength;
						break;
					default:
						this.data = input;
						this.position = position - this.parentNode.packetLength;
						this.len = pos - position;
						return this.len;
					}
				}
			}
			this.data = input;
			this.position = position - this.parentNode.packetLength;
			this.len = pos - position;
			return this.len;
		} else {
			util.print_error("openpgp.packet.keymaterial.js\n"+"unknown parent node for a key material packet "+parent_node.tagType);
		}
	}

	/**
	 * Checks the validity for usage of this (sub)key
	 * @return 0 = bad key, 1 = expired, 2 = revoked, 3 = valid
	 */
	function verifyKey() {
		if (this.tagType == 14) {
			if (this.subKeySignature == null) {
				return 0;
			}
			if (this.subKeySignature.version == 4 &&
				this.subKeySignature.keyNeverExpires != null &&
				!this.subKeySignature.keyNeverExpires &&
				new Date((this.subKeySignature.keyExpirationTime*1000)+ this.creationTime.getTime()) < new Date()) {
				    return 1;
				}
			var hashdata = String.fromCharCode(0x99)+this.parentNode.header.substring(1)+this.parentNode.data+
			String.fromCharCode(0x99)+this.header.substring(1)+this.packetdata;
			if (!this.subKeySignature.verify(hashdata,this.parentNode)) {
				return 0;
			}
			for (var i = 0; i < this.subKeyRevocationSignature.length; i++) {
			    if (this.getKeyId() == this.subKeyRevocationSignature[i].keyId){
			        return 2;
			    }
			}
		}
		return 3;
	}

	/**
	 * calculates the key id of they key 
	 * @return {String} a 8 byte key id
	 */
	function getKeyId() {
		if (this.version == 4) {
			var f = this.getFingerprint();
			return f.substring(12,20);
		} else if (this.version == 3 && this.publicKeyAlgorithm > 0 && this.publicKeyAlgorithm < 4) {
			var key_id = this.MPIs[0].substring((this.MPIs[0].mpiByteLength-8));
			util.print_debug("openpgp.msg.publickey read_nodes:\n"+"V3 key ID: "+key_id);
			return key_id;
		}
	}
	
	/**
	 * calculates the fingerprint of the key
	 * @return {String} a string containing the fingerprint
	 */
	function getFingerprint() {
		if (this.version == 4) {
			tohash = String.fromCharCode(0x99)+ String.fromCharCode(((this.packetdata.length) >> 8) & 0xFF) 
				+ String.fromCharCode((this.packetdata.length) & 0xFF)+this.packetdata;
			util.print_debug("openpgp.msg.publickey creating subkey fingerprint by hashing:"+util.hexstrdump(tohash)+"\npublickeyalgorithm: "+this.publicKeyAlgorithm);
			return str_sha1(tohash, tohash.length);
		} else if (this.version == 3 && this.publicKeyAlgorithm > 0 && this.publicKeyAlgorithm < 4) {
			return MD5(this.MPIs[0].MPI);
		}
	}
	
	/*
     * creates an OpenPGP key packet for the given key. much TODO in regards to s2k, subkeys.
     * @param {int} keyType follows the OpenPGP algorithm standard, IE 1 corresponds to RSA.
     * @param {RSA.keyObject} key
     * @param password
     * @param s2kHash
     * @param symmetricEncryptionAlgorithm
     * @param timePacket
     * @return {body: [string]OpenPGP packet body contents, header: [string] OpenPGP packet header, string: [string] header+body}
     */
    function write_private_key(keyType, key, password, s2kHash, symmetricEncryptionAlgorithm, timePacket){
        this.symmetricEncryptionAlgorithm = symmetricEncryptionAlgorithm;
		var tag = 5;
		var body = String.fromCharCode(4);
		body += timePacket;
		switch(keyType){
		case 1:
		    body += String.fromCharCode(keyType);//public key algo
		    body += key.n.toMPI();
		    body += key.ee.toMPI();
		    var algorithmStart = body.length;
		    //below shows ske/s2k
		    if(password){
		        body += String.fromCharCode(254); //octet of 254 indicates s2k with SHA1
		        //if s2k == 255,254 then 1 octet symmetric encryption algo
		        body += String.fromCharCode(this.symmetricEncryptionAlgorithm);
		        //if s2k == 255,254 then s2k specifier
		        body += String.fromCharCode(3); //s2k salt+iter
		        body += String.fromCharCode(s2kHash);
		        //8 octet salt value
		        //1 octet count
		        var cleartextMPIs = key.d.toMPI() + key.p.toMPI() + key.q.toMPI() + key.u.toMPI();
		        var sha1Hash = str_sha1(cleartextMPIs);
   		        util.print_debug_hexstr_dump('write_private_key sha1: ',sha1Hash);
		        var salt = openpgp_crypto_getRandomBytes(8);
		        util.print_debug_hexstr_dump('write_private_key Salt: ',salt);
		        body += salt;
		        var c = 96; //c of 96 translates to count of 65536
		        body += String.fromCharCode(c);
		        util.print_debug('write_private_key c: '+ c);
		        var s2k = new openpgp_type_s2k();
		        var hashKey = s2k.write(3, s2kHash, password, salt, c);
		        //if s2k, IV of same length as cipher's block
		        switch(this.symmetricEncryptionAlgorithm){
		        case 3:
		            this.IVLength = 8;
		            this.IV = openpgp_crypto_getRandomBytes(this.IVLength);
            		ciphertextMPIs = normal_cfb_encrypt(function(block, key) {
                		var cast5 = new openpgp_symenc_cast5();
                		cast5.setKey(key);
                		return cast5.encrypt(util.str2bin(block)); 
            		}, this.IVLength, util.str2bin(hashKey.substring(0,16)), cleartextMPIs + sha1Hash, this.IV);
            		body += this.IV + ciphertextMPIs;
		            break;
		        case 7:
		        case 8:
		        case 9:
		            this.IVLength = 16;
		            this.IV = openpgp_crypto_getRandomBytes(this.IVLength);
		            ciphertextMPIs = normal_cfb_encrypt(AESencrypt,
            				this.IVLength, hashKey, cleartextMPIs + sha1Hash, this.IV);
            		body += this.IV + ciphertextMPIs;
	            	break;
		        }
		    }
		    else{
		        body += String.fromCharCode(0);//1 octet -- s2k, 0 for no s2k
		        body += key.d.toMPI() + key.p.toMPI() + key.q.toMPI() + key.u.toMPI();
		        var checksum = util.calc_checksum(key.d.toMPI() + key.p.toMPI() + key.q.toMPI() + key.u.toMPI());
        		body += String.fromCharCode(checksum/0x100) + String.fromCharCode(checksum%0x100);//DEPRECATED:s2k == 0, 255: 2 octet checksum, sum all octets%65536
        		util.print_debug_hexstr_dump('write_private_key basic checksum: '+ checksum);
		    }
		    break;
		default :
			body = "";
			util.print_error("openpgp.packet.keymaterial.js\n"+'error writing private key, unknown type :'+keyType);
        }
		var header = openpgp_packet.write_packet_header(tag,body.length);
		return {string: header+body , header: header, body: body};
    }
	
	/*
     * same as write_private_key, but has less information because of public key.
     * @param {int} keyType follows the OpenPGP algorithm standard, IE 1 corresponds to RSA.
     * @param {RSA.keyObject} key
     * @param timePacket
     * @return {body: [string]OpenPGP packet body contents, header: [string] OpenPGP packet header, string: [string] header+body}
     */
    function write_public_key(keyType, key, timePacket){
        var tag = 6;
        var body = String.fromCharCode(4);
        body += timePacket;
		switch(keyType){
		case 1:
		    body += String.fromCharCode(1);//public key algo
		    body += key.n.toMPI();
		    body += key.ee.toMPI();
		    break;
	    default:
	    	util.print_error("openpgp.packet.keymaterial.js\n"+'error writing private key, unknown type :'+keyType);
	    }
        var header = openpgp_packet.write_packet_header(tag,body.length);
        return {string: header+body , header: header, body: body};
        }

	
	this.read_tag5 = read_tag5;
	this.read_tag6 = read_tag6;
	this.read_tag7 = read_tag7;
	this.read_tag14 = read_tag14;
	this.toString = toString;
	this.read_pub_key = read_pub_key;
	this.read_priv_key = read_priv_key;
	this.decryptSecretMPIs = decryptSecretMPIs;
	this.read_nodes = read_nodes;
	this.verifyKey = verifyKey;
	this.getKeyId = getKeyId;
	this.getFingerprint = getFingerprint;
	this.write_private_key = write_private_key;
	this.write_public_key = write_public_key;
}
/**
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

function str_sha1(str) {
	var shaObj = new jsSHA(str, "ASCII");
	return shaObj.getHash("SHA-1", "ASCII");
}

function str_sha224(str) {
	var shaObj = new jsSHA(str, "ASCII");
	return shaObj.getHash("SHA-224", "ASCII");
}

function str_sha256(str) {
	var shaObj = new jsSHA(str, "ASCII");
	return shaObj.getHash("SHA-256", "ASCII");
}


function str_sha384(str) {
	var shaObj = new jsSHA(str, "ASCII");
	return shaObj.getHash("SHA-384", "ASCII");

}

function str_sha512(str) {
	var shaObj = new jsSHA(str, "ASCII");
	return shaObj.getHash("SHA-512", "ASCII");
}
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
}/* Modified by Recurity Labs GmbH 
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

		 for(i = 0; i < src.length; i+=8)
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

		 for(i = 0; i < src.length; i+=8)
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

function SecureRandom(){
    function nextBytes(byteArray){
        for(var n = 0; n < byteArray.length;n++){
            byteArray[n] = openpgp_crypto_getSecureRandomOctet();
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
}/*
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

// The GPG4Browsers symmetric crypto interface

/**
 * Symmetrically encrypts data using prefixedrandom, a key with length 
 * depending on the algorithm in openpgp_cfb mode with or without resync
 * (MDC style)
 * @param prefixrandom secure random bytes as string in length equal to the
 * block size of the algorithm used (use openpgp_crypto_getPrefixRandom(algo)
 * to retrieve that string
 * @param algo [Integer] algorithm to use (see RFC4880 9.2)
 * @param key [String] key as string. length is depending on the algorithm used
 * @param data [String] data to encrypt
 * @param openpgp_cfb [boolean]
 * @return [String] encrypted data
 */
function openpgp_crypto_symmetricEncrypt(prefixrandom, algo, key, data, openpgp_cfb) {
	switch(algo) {
		case 0: // Plaintext or unencrypted data
			return data; // blockcipherencryptfn, plaintext, block_size, key
		case 2: // TripleDES (DES-EDE, [SCHNEIER] [HAC] - 168 bit key derived from 192)
			return openpgp_cfb_encrypt(prefixrandom, desede, data,8,key, openpgp_cfb).substring(0, data.length + 10);
		case 3: // CAST5 (128 bit key, as per [RFC2144])
			return openpgp_cfb_encrypt(prefixrandom, cast5_encrypt, data,8,key, openpgp_cfb).substring(0, data.length + 10);
		case 4: // Blowfish (128 bit key, 16 rounds) [BLOWFISH]
			return openpgp_cfb_encrypt(prefixrandom, BFencrypt, data,8,key, openpgp_cfb).substring(0, data.length + 10);
		case 7: // AES with 128-bit key [AES]
		case 8: // AES with 192-bit key
		case 9: // AES with 256-bit key
			return openpgp_cfb_encrypt(prefixrandom, AESencrypt, data, 16, keyExpansion(key), openpgp_cfb).substring(0, data.length + 18);
		case 10: // Twofish with 256-bit key [TWOFISH]
			return openpgp_cfb_encrypt(prefixrandom, TFencrypt, data,16, key, openpgp_cfb).substring(0, data.length + 18);
		case 1: // IDEA [IDEA]
			util.print_error("IDEA Algorithm not implemented");
			return null;
		default:
			return null;
	}
}

/**
 * Symmetrically decrypts data using a key with length depending on the
 * algorithm in openpgp_cfb mode with or without resync (MDC style)
 * @param algo [Integer] algorithm to use (see RFC4880 9.2)
 * @param key [String] key as string. length is depending on the algorithm used
 * @param data [String] data to be decrypted
 * @param openpgp_cfb [boolean] if true use the resync (for encrypteddata); 
 * otherwise use without the resync (for MDC encrypted data)
 * @return [String] plaintext data
 */
function openpgp_crypto_symmetricDecrypt(algo, key, data, openpgp_cfb) {
	util.print_debug_hexstr_dump("openpgp_crypto_symmetricDecrypt:\nalgo:"+algo+"\nencrypteddata:",data);
	var n = 0;
	if (!openpgp_cfb)
		n = 2;
	switch(algo) {
	case 0: // Plaintext or unencrypted data
		return data;
	case 2: // TripleDES (DES-EDE, [SCHNEIER] [HAC] - 168 bit key derived from 192)
		return openpgp_cfb_decrypt(desede, 8, key, data, openpgp_cfb).substring(n, (data.length+n)-10);
	case 3: // CAST5 (128 bit key, as per [RFC2144])
		return openpgp_cfb_decrypt(cast5_encrypt, 8, key, data, openpgp_cfb).substring(n, (data.length+n)-10);
	case 4: // Blowfish (128 bit key, 16 rounds) [BLOWFISH]
		return openpgp_cfb_decrypt(BFencrypt, 8, key, data, openpgp_cfb).substring(n, (data.length+n)-10);
	case 7: // AES with 128-bit key [AES]
	case 8: // AES with 192-bit key
	case 9: // AES with 256-bit key
		return openpgp_cfb_decrypt(AESencrypt, 16, keyExpansion(key), data, openpgp_cfb).substring(n, (data.length+n)-18);
	case 10: // Twofish with 256-bit key [TWOFISH]
		var result = openpgp_cfb_decrypt(TFencrypt, 16, key, data, openpgp_cfb).substring(n, (data.length+n)-18);
		return result;
	case 1: // IDEA [IDEA]
		util.print_error(""+ (algo == 1 ? "IDEA Algorithm not implemented" : "Twofish Algorithm not implemented"));
		return null;
	default:
	}
	return null;
}// Modified by Recurity Labs GmbH 

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

// --------------------------------------
/**
 * This function encrypts a given with the specified prefixrandom 
 * using the specified blockcipher to encrypt a message
 * @param prefixrandom random bytes of block_size length provided 
 *  as a string to be used in prefixing the data
 * @param blockcipherfn the algorithm encrypt function to encrypt
 *  data in one block_size encryption. The function must be 
 *  specified as blockcipherfn([integer_array(integers 0..255)] 
 *  block,[integer_array(integers 0..255)] key) returning an 
 *  array of bytes (integers 0..255)
 * @param block_size the block size in bytes of the algorithm used
 * @param plaintext data to be encrypted provided as a string
 * @param key key to be used to encrypt the data as 
 *  integer_array(integers 0..255)]. This will be passed to the 
 *  blockcipherfn
 * @param resync a boolean value specifying if a resync of the 
 *  IV should be used or not. The encrypteddatapacket uses the 
 *  "old" style with a resync. Encryption within an 
 *  encryptedintegrityprotecteddata packet is not resyncing the IV.
 * @return a string with the encrypted data
 */
function openpgp_cfb_encrypt(prefixrandom, blockcipherencryptfn, plaintext, block_size, key, resync) {
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
}

/**
 * decrypts the prefixed data for the Modification Detection Code (MDC) computation
 * @param blockcipherencryptfn cipher function to use
 * @param block_size blocksize of the algorithm
 * @param key the key for encryption
 * @param ciphertext the encrypted data
 * @return plaintext data of D(ciphertext) with blocksize length +2
 */
function openpgp_cfb_mdc(blockcipherencryptfn, block_size, key, ciphertext) {
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
}
/**
 * This function decrypts a given plaintext using the specified
 * blockcipher to decrypt a message
 * @param blockcipherfn the algorithm _encrypt_ function to encrypt
 *  data in one block_size encryption. The function must be 
 *  specified as blockcipherfn([integer_array(integers 0..255)] 
 *  block,[integer_array(integers 0..255)] key) returning an 
 *  array of bytes (integers 0..255)
 * @param block_size the block size in bytes of the algorithm used
 * @param plaintext ciphertext to be decrypted provided as a string
 * @param key key to be used to decrypt the ciphertext as 
 *  integer_array(integers 0..255)]. This will be passed to the 
 *  blockcipherfn
 * @param resync a boolean value specifying if a resync of the 
 *  IV should be used or not. The encrypteddatapacket uses the 
 *  "old" style with a resync. Decryption within an 
 *  encryptedintegrityprotecteddata packet is not resyncing the IV.
 * @return a string with the plaintext data
 */

function openpgp_cfb_decrypt(blockcipherencryptfn, block_size, key, ciphertext, resync)
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
}


function normal_cfb_encrypt(blockcipherencryptfn, block_size, key, plaintext, iv) {
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
}

function normal_cfb_decrypt(blockcipherencryptfn, block_size, key, ciphertext, iv) { 
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

/**
 * Encrypts data using the specified public key multiprecision integers 
 * and the specified algorithm.
 * @param algo [Integer] Algorithm to be used (See RFC4880 9.1)
 * @param publicMPIs [Array[openpgp_type_mpi]] algorithm dependent multiprecision integers
 * @param data [openpgp_type_mpi] data to be encrypted as MPI
 * @return [Object] if RSA an openpgp_type_mpi; if elgamal encryption an array of two
 * openpgp_type_mpi is returned; otherwise null
 */
function openpgp_crypto_asymetricEncrypt(algo, publicMPIs, data) {
	switch(algo) {
	case 1: // RSA (Encrypt or Sign) [HAC]
	case 2: // RSA Encrypt-Only [HAC]
	case 3: // RSA Sign-Only [HAC]
		var rsa = new RSA();
		var n = publicMPIs[0].toBigInteger();
		var e = publicMPIs[1].toBigInteger();
		var m = data.toBigInteger();
		return rsa.encrypt(m,e,n).toMPI();
	case 16: // Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
		var elgamal = new Elgamal();
		var p = publicMPIs[0].toBigInteger();
		var g = publicMPIs[1].toBigInteger();
		var y = publicMPIs[2].toBigInteger();
		var m = data.toBigInteger();
		return elgamal.encrypt(m,g,p,y);
	default:
		return null;
	}
}

/**
 * Decrypts data using the specified public key multiprecision integers of the private key,
 * the specified secretMPIs of the private key and the specified algorithm.
 * @param algo [Integer] Algorithm to be used (See RFC4880 9.1)
 * @param publicMPIs [Array[openpgp_type_mpi]] algorithm dependent multiprecision integers of the public key part of the private key
 * @param secretMPIs [Array[openpgp_type_mpi]] algorithm dependent multiprecision integers of the private key used
 * @param data [openpgp_type_mpi] data to be encrypted as MPI
 * @return [BigInteger] returns a big integer containing the decrypted data; otherwise null
 */

function openpgp_crypto_asymetricDecrypt(algo, publicMPIs, secretMPIs, dataMPIs) {
	switch(algo) {
	case 1: // RSA (Encrypt or Sign) [HAC]  
	case 2: // RSA Encrypt-Only [HAC]
	case 3: // RSA Sign-Only [HAC]
		var rsa = new RSA();
		var d = secretMPIs[0].toBigInteger();
		var p = secretMPIs[1].toBigInteger();
		var q = secretMPIs[2].toBigInteger();
		var u = secretMPIs[3].toBigInteger();
		var m = dataMPIs[0].toBigInteger();
		return rsa.decrypt(m, d, p, q, u);
	case 16: // Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
		var elgamal = new Elgamal();
		var x = secretMPIs[0].toBigInteger();
		var c1 = dataMPIs[0].toBigInteger();
		var c2 = dataMPIs[1].toBigInteger();
		var p = publicMPIs[0].toBigInteger();
		return elgamal.decrypt(c1,c2,p,x);
	default:
		return null;
	}
	
}

/**
 * generate random byte prefix as string for the specified algorithm
 * @param algo [Integer] algorithm to use (see RFC4880 9.2)
 * @return [String] random bytes with length equal to the block
 * size of the cipher
 */
function openpgp_crypto_getPrefixRandom(algo) {
	switch(algo) {
	case 2:
	case 3:
	case 4:
		return openpgp_crypto_getRandomBytes(8);
	case 7:
	case 8:
	case 9:
	case 10:
		return openpgp_crypto_getRandomBytes(16);
	default:
		return null;
	}
}

/**
 * retrieve the MDC prefixed bytes by decrypting them
 * @param algo [Integer] algorithm to use (see RFC4880 9.2)
 * @param key [String] key as string. length is depending on the algorithm used
 * @param data [String] encrypted data where the prefix is decrypted from
 * @return [String] plain text data of the prefixed data
 */
function openpgp_crypto_MDCSystemBytes(algo, key, data) {
	util.print_debug_hexstr_dump("openpgp_crypto_symmetricDecrypt:\nencrypteddata:",data);
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
		util.print_error(""+ (algo == 1 ? "IDEA Algorithm not implemented" : "Twofish Algorithm not implemented"));
		return null;
	default:
	}
	return null;
}
/**
 * Generating a session key for the specified symmetric algorithm
 * @param algo [Integer] algorithm to use (see RFC4880 9.2)
 * @return [String] random bytes as a string to be used as a key
 */
function openpgp_crypto_generateSessionKey(algo) {
	switch (algo) {
	case 2: // TripleDES (DES-EDE, [SCHNEIER] [HAC] - 168 bit key derived from 192)
	case 8: // AES with 192-bit key
		return openpgp_crypto_getRandomBytes(24); 
	case 3: // CAST5 (128 bit key, as per [RFC2144])
	case 4: // Blowfish (128 bit key, 16 rounds) [BLOWFISH]
	case 7: // AES with 128-bit key [AES]
		util.print_debug("length = 16:\n"+util.hexstrdump(openpgp_crypto_getRandomBytes(16)));
		return openpgp_crypto_getRandomBytes(16);
	case 9: // AES with 256-bit key
	case 10:// Twofish with 256-bit key [TWOFISH]
		return openpgp_crypto_getRandomBytes(32);
	}
	return null;
}

/**
 * 
 * @param algo [Integer] public key algorithm
 * @param hash_algo [Integer] hash algorithm
 * @param msg_MPIs [Array[openpgp_type_mpi]] signature multiprecision integers
 * @param publickey_MPIs [Array[openpgp_type_mpi]] public key multiprecision integers 
 * @param data [String] data on where the signature was computed on.
 * @return true if signature (sig_data was equal to data over hash)
 */
function openpgp_crypto_verifySignature(algo, hash_algo, msg_MPIs, publickey_MPIs, data) {
	var calc_hash = openpgp_crypto_hashData(hash_algo, data);
	switch(algo) {
	case 1: // RSA (Encrypt or Sign) [HAC]  
	case 2: // RSA Encrypt-Only [HAC]
	case 3: // RSA Sign-Only [HAC]
		var rsa = new RSA();
		var n = publickey_MPIs[0].toBigInteger();
		var e = publickey_MPIs[1].toBigInteger();
		var x = msg_MPIs[0].toBigInteger();
		var dopublic = rsa.verify(x,e,n);
		var hash  = openpgp_encoding_emsa_pkcs1_decode(hash_algo,dopublic.toMPI().substring(2));
		if (hash == -1) {
			util.print_error("PKCS1 padding in message or key incorrect. Aborting...");
			return false;
		}
		return hash == calc_hash;
		
	case 16: // Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
		util.print_error("signing with Elgamal is not defined in the OpenPGP standard.");
		return null;
	case 17: // DSA (Digital Signature Algorithm) [FIPS186] [HAC]
		var dsa = new DSA();
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
		return null;
	}
	
}
   
/**
 * Create a signature on data using the specified algorithm
 * @param hash_algo [Integer] hash algorithm to use (See RFC4880 9.4)
 * @param algo [Integer] asymmetric cipher algorithm to use (See RFC4880 9.1)
 * @param publicMPIs [Array[openpgp_type_mpi]] public key multiprecision integers of the private key 
 * @param secretMPIs [Array[openpgp_type_mpi]] private key multiprecision integers which is used to sign the data
 * @param data [String] data to be signed
 * @return [String or openpgp_type_mpi] 
 */
function openpgp_crypto_signData(hash_algo, algo, publicMPIs, secretMPIs, data) {
	
	switch(algo) {
	case 1: // RSA (Encrypt or Sign) [HAC]  
	case 2: // RSA Encrypt-Only [HAC]
	case 3: // RSA Sign-Only [HAC]
		var rsa = new RSA();
		var d = secretMPIs[0].toBigInteger();
		var n = publicMPIs[0].toBigInteger();
		var m = openpgp_encoding_emsa_pkcs1_encode(hash_algo, data,publicMPIs[0].mpiByteLength);
		util.print_debug("signing using RSA");
		return rsa.sign(m, d, n).toMPI();
	case 17: // DSA (Digital Signature Algorithm) [FIPS186] [HAC]
		var dsa = new DSA();
		util.print_debug("DSA Sign: q size in Bytes:"+publicMPIs[1].getByteLength());
		var p = publicMPIs[0].toBigInteger();
		var q = publicMPIs[1].toBigInteger();
		var g = publicMPIs[2].toBigInteger();
		var y = publicMPIs[3].toBigInteger();
		var x = secretMPIs[0].toBigInteger();
		var m = data;
		var result = dsa.sign(hash_algo,m, g, p, q, x);
		util.print_debug("signing using DSA\n result:"+util.hexstrdump(result[0])+"|"+util.hexstrdump(result[1]));
		return result[0]+result[1];
	case 16: // Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
			util.print_debug("signing with Elgamal is not defined in the OpenPGP standard.");
			return null;
	default:
		return null;
	}	
}

/**
 * create a hash on the specified data using the specified algorithm
 * @param algo [Integer] hash algorithm type (see RFC4880 9.4)
 * @param data [String] data to be hashed
 * @return [String] hash value
 */
function openpgp_crypto_hashData(algo, data) {
	var hash = null;
	switch(algo) {
	case 1: // - MD5 [HAC]
		hash = MD5(data);
		break;
	case 2: // - SHA-1 [FIPS180]
		hash = str_sha1(data);
		break;
	case 3: // - RIPE-MD/160 [HAC]
		hash = RMDstring(data);
		break;
	case 8: // - SHA256 [FIPS180]
		hash = str_sha256(data);
		break;
	case 9: // - SHA384 [FIPS180]
		hash = str_sha384(data);
		break;
	case 10:// - SHA512 [FIPS180]
		hash = str_sha512(data);
		break;
	case 11:// - SHA224 [FIPS180]
		hash = str_sha224(data);
	default:
		break;
	}
	return hash;
}

/**
 * returns the hash size in bytes of the specified hash algorithm type
 * @param algo [Integer] hash algorithm type (See RFC4880 9.4)
 * @return [Integer] size in bytes of the resulting hash
 */
function openpgp_crypto_getHashByteLength(algo) {
	var hash = null;
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
	}
	return null;
}

/**
 * retrieve secure random byte string of the specified length
 * @param length [Integer] length in bytes to generate
 * @return [String] random byte string
 */
function openpgp_crypto_getRandomBytes(length) {
	var result = '';
	for (var i = 0; i < length; i++) {
		result += String.fromCharCode(openpgp_crypto_getSecureRandomOctet());
	}
	return result;
}

/**
 * return a pseudo-random number in the specified range
 * @param from [Integer] min of the random number
 * @param to [Integer] max of the random number (max 32bit)
 * @return [Integer] a pseudo random number
 */
function openpgp_crypto_getPseudoRandom(from, to) {
	return Math.round(Math.random()*(to-from))+from;
}

/**
 * return a secure random number in the specified range
 * @param from [Integer] min of the random number
 * @param to [Integer] max of the random number (max 32bit)
 * @return [Integer] a secure random number
 */
function openpgp_crypto_getSecureRandom(from, to) {
	var buf = new Uint32Array(1);
	window.crypto.getRandomValues(buf);
	var bits = ((to-from)).toString(2).length;
	while ((buf[0] & (Math.pow(2, bits) -1)) > (to-from))
		window.crypto.getRandomValues(buf);
	return from+(Math.abs(buf[0] & (Math.pow(2, bits) -1)));
}

function openpgp_crypto_getSecureRandomOctet() {
	var buf = new Uint32Array(1);
	window.crypto.getRandomValues(buf);
	return buf[0] & 0xFF;
}

/**
 * create a secure random big integer of bits length
 * @param bits [Integer] bit length of the MPI to create
 * @return [BigInteger] resulting big integer
 */
function openpgp_crypto_getRandomBigInteger(bits) {
	if (bits < 0)
	   return null;
	var numBytes = Math.floor((bits+7)/8);

	var randomBits = openpgp_crypto_getRandomBytes(numBytes);
	if (bits % 8 > 0) {
		
		randomBits = String.fromCharCode(
						(Math.pow(2,bits % 8)-1) &
						randomBits.charCodeAt(0)) +
			randomBits.substring(1);
	}
	return new openpgp_type_mpi().create(randomBits).toBigInteger();
}

function openpgp_crypto_getRandomBigIntegerInRange(min, max) {
	if (max.compareTo(min) <= 0)
		return;
	var range = max.subtract(min);
	var r = openpgp_crypto_getRandomBigInteger(range.bitLength());
	while (r > range) {
		r = openpgp_crypto_getRandomBigInteger(range.bitLength());
	}
	return min.add(r);
}


//This is a test method to ensure that encryption/decryption with a given 1024bit RSAKey object functions as intended
function openpgp_crypto_testRSA(key){
	debugger;
    var rsa = new RSA();
	var mpi = new openpgp_type_mpi();
	mpi.create(openpgp_encoding_eme_pkcs1_encode('ABABABAB', 128));
	var msg = rsa.encrypt(mpi.toBigInteger(),key.ee,key.n);
	var result = rsa.decrypt(msg, key.d, key.p, key.q, key.u);
}
/**
 * calls the necessary crypto functions to generate a keypair. Called directly by openpgp.js
 * @keyType [int] follows OpenPGP algorithm convention.
 * @numBits [int] number of bits to make the key to be generated
 * @return {privateKey: [openpgp_packet_keymaterial] , publicKey: [openpgp_packet_keymaterial]}
 */
function openpgp_crypto_generateKeyPair(keyType, numBits, passphrase, s2kHash, symmetricEncryptionAlgorithm){
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
	 * @return [void]
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
	 * @return {Array[openpgp_msg_publickey]} on error the function
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
	 * @return {Array[openpgp_msg_privatekey]} on error the function
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
	 * @return {Array[openpgp_msg_message]} on error the function
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
	 * @return {Array[openpgp_msg_message]} on error the function
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
	 * @param {obj: [openpgp_msg_privatekey]} privatekey private key to be used to sign the message
	 * @param {Array {obj: [openpgp_msg_publickey]}} publickeys  public keys to be used to encrypt the message 
	 * @param {String} messagetext message text to encrypt and sign
	 * @return {String} a binary string representation of the message which can be OpenPGP armored
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
	 * @param {Array {obj: [openpgp_msg_publickey]}} publickeys public
	 * keys to be used to encrypt the message 
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
	 * @param {obj: [openpgp_msg_privatekey]} privatekey private
	 * key to be used to sign the message 
	 * @param {String} messagetext message text to sign
	 * @return {Object: text [String]}, openpgp: {String} a binary
	 *  string representation of the message which can be OpenPGP
	 *   armored(openpgp) and a text representation of the message (text). This can be directly used to OpenPGP armor the message
	 */
	function write_signed_message(privatekey, messagetext) {
		var sig = new openpgp_packet_signature().write_message_signature(1, messagetext.replace(/\r\n/g,"\n").replace(/\n/,"\r\n"), privatekey);
		var result = {text: messagetext.replace(/\r\n/g,"\n").replace(/\n/,"\r\n"), openpgp: sig.openpgp, hash: sig.hash};
		return openpgp_encoding_armor(2,result, null, null)
	}
	
	/**
	 * generates a new key pair for openpgp. Beta stage. Currently only supports RSA keys, and no subkeys.
	 * @param {int} keyType to indicate what type of key to make. RSA is 1. Follows algorithms outlined in OpenPGP.
	 * @param {int} numBits number of bits for the key creation. (should be 1024+, generally)
	 * @param {string} userId assumes already in form of "User Name <username@email.com>"
	 * @return {privateKey: [openpgp_msg_privatekey], privateKeyArmored: [string], publicKeyArmored: [string]}
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
 * @classdesc Decoded public key object for internal openpgp.js use
 */
function openpgp_msg_publickey() {
	this.data;
	this.position;
	this.len;
	this.tostring = "OPENPGP PUBLIC KEY\n";
	this.bindingSignature = null;
	this.publicKeyPacket = null;
	this.userIds = new Array();
	this.userAttributes = new Array();
	this.revocationSignatures = new Array();
	this.subKeys = new Array();
	this.arbitraryPacket = new Array();
	this.directSignatures = new Array();
	/**
	 * 
	 * @return last position
	 */
	function read_nodes(parent_node, input, position, len) {
		this.publicKeyPacket = parent_node;
		var exit = false;
		var pos = position;
		var l = len;
		while (input.length != pos) {
			var result = openpgp_packet.read_packet(input, pos, input.length - pos);
			if (result == null) {
				util.print_error("openpgp.msg.publickey read_nodes:\n"+'[pub_key]parsing ends here @:' + pos + " l:" + l);
				break;
			} else {
				switch (result.tagType) {
				case 2: // public key revocation signature
					if (result.signatureType == 32)
						this.revocationSignatures[this.revocationSignatures.length] = result;
					else if (result.signatureType == 16 || result.signatureType == 17 || result.signatureType == 18  || result.signatureType == 19)
						this.certificationSignature = result;
					else if (result.signatureType == 25) {
						this.bindingSignature = result;
					} else if (result.signatureType == 31) {
						this.directSignatures[this.directSignatures.length] = result;
					} else
						util.print_error("openpgp.msg.publickey read_nodes:\n"+"unknown signature type directly on key "+result.signatureType);
					pos += result.packetLength + result.headerLength;
					break;
				case 14: // Public-Subkey Packet
					this.subKeys[this.subKeys.length] = result;
					pos += result.packetLength + result.headerLength;
					pos += result.read_nodes(this.publicKeyPacket,input, pos, input.length - pos);
					break;
				case 17: // User Attribute Packet
					this.userAttributes[this.userAttributes.length] = result;
					pos += result.packetLength + result.headerLength;
					pos += result.read_nodes(this.publicKeyPacket,input, pos, input.length - pos);
					break;
				case 13: // User ID Packet
					this.userIds[this.userIds.length] = result;
					pos += result.packetLength + result.headerLength;
					pos += result.read_nodes(this.publicKeyPacket, input, pos, input.length - pos);
					break;
				default:
					this.data = input;
					this.position = position - this.publicKeyPacket.packetLength - this.publicKeyPacket.headerLength;
					this.len = pos - position;
					return this.len;
				}
			}
		}
		this.data = input;
		this.position = position - (this.publicKeyPacket.packetLength - this.publicKeyPacket.headerLength);
		this.len = pos - position;
		return this.len;
	}

	function write() {

	}

	function getKeyId() {
		return this.publicKeyPacket.getKeyId();
	}
	
	function getFingerprint() {
		return this.publicKeyPacket.getFingerprint();
	}


	
	function validate() {
		// check revocation keys
		for (var i = 0; i < this.revocationSignatures.length; i++) {
			var tohash = this.publicKeyPacket.header+this.publicKeyPacket.data;
			if (this.revocationSignatures[i].verify(tohash, this.publicKeyPacket))
				return false;
		}
		
		if (this.subKeys.length != 0) {
			// search for a valid subkey
			var found = false;
			for (var i = 0; i < this.subKeys.length; i++)
				if (this.subKeys[i].verifyKey() == 3) {
					found = true;
					break;
				}
			if (!found)
				return false;
		}
		// search for one valid userid
		found = false;
		for (var i = 0; i < this.userIds.length; i++)
			if (this.userIds[i].verify(this.publicKeyPacket) == 0) {
				found = true;
				break;
			}
		if (!found)
			return false;
		return true;
	}
	
	/**
	 * verifies all signatures
	 * @return a 2 dimensional array. the first dimension corresponds to the userids available
	 */
	function verifyCertificationSignatures() {
		var result = new Array();
		for (var i = 0; i < this.userIds.length; i++) {
			result[i] = this.userIds[i].verifyCertificationSignatures(this.publicKeyPacket);
		}
		return result;
	}
	this.verifyCertificationSignatures = verifyCertificationSignatures;
	
	/**
	 * verifies:
	 *  - revocation certificates directly on key
	 *  - self signatures
	 *  - subkey binding and revocation certificates
	 *  
	 *  This is useful for validating the key
	 *  @returns true if the basic signatures are all valid
	 */
	function verifyBasicSignatures() {
		for (var i = 0; i < this.revocationSignatures.length; i++) {
			var tohash = this.publicKeyPacket.header+this.publicKeyPacket.data;
			if (this.revocationSignatures[i].verify(tohash, this.publicKeyPacket))
				return false;
		}
		
		if (this.subKeys.length != 0) {
			// search for a valid subkey
			var found = false;
			for (var i = 0; i < this.subKeys.length; i++) {
				if (this.subKeys[i] == null)
					continue;
				var result = this.subKeys[i].verifyKey();
				if (result == 3) {
					found = true;
					break;
				} 
			}
			if (!found)
				return false;
		}
		var keyId = this.getKeyId();
		for (var i = 0; i < this.userIds.length; i++) {
			for (var j = 0; j < this.userIds[i].certificationRevocationSignatures.length; j++) {
				if (this.userIds[i].certificationSignatures[j].getIssuer == keyId &&
					this.userIds[i].certificationSignatures[j].verifyBasic(this.publicKeyPacket) != 4)
					return false;
			}
		}
		return true;
	}
	
	function toString() {
		var result = " OPENPGP Public Key\n    length: "+this.len+"\n";
		result += "    Revocation Signatures:\n"
		for (var i=0; i < this.revocationSignatures.length; i++) {
			result += "    "+this.revocationSignatures[i].toString(); 
		}
		result += "    User Ids:\n";
		for (var i=0; i < this.userIds.length; i++) {
			result += "    "+this.userIds[i].toString(); 
		}
		result += "    User Attributes:\n";
		for (var i=0; i < this.userAttributes.length; i++) {
			result += "    "+this.userAttributes[i].toString(); 
		}
		result += "    Public Key SubKeys:\n";
		for (var i=0; i < this.subKeys.length; i++) {
			result += "    "+this.subKeys[i].toString(); 
		}
		return result;
	}
	
	/**
	 * finds an encryption key for this public key
	 * @returns null if no encryption key has been found
	 */
	function getEncryptionKey() {
		if (this.publicKeyPacket.publicKeyAlgorithm != 17 && this.publicKeyPacket.publicKeyAlgorithm != 3
				&& this.publicKeyPacket.verifyKey())
			return this.publicKeyPacket;
		else if (this.publicKeyPacket.version == 4) // V3 keys MUST NOT have subkeys.
			for (var j = 0; j < this.subKeys.length; j++)
				if (this.subKeys[j].publicKeyAlgorithm != 17 &&
						this.subKeys[j].publicKeyAlgorithm != 3 &&
						this.subKeys[j].verifyKey()) {
					return this.subKeys[j];
				}
		return null;
	}
	
	function getSigningKey() {
		if ((this.publicKeyPacket.publicKeyAlgorithm == 17 ||
			 this.publicKeyPacket.publicKeyAlgorithm != 2))
			return this.publicKeyPacket;
		else if (this.publicKeyPacket.version == 4) // V3 keys MUST NOT have subkeys.
			for (var j = 0; j < this.subKeys.length; j++) {
				if ((this.subKeys[j].publicKeyAlgorithm == 17 ||
					 this.subKeys[j].publicKeyAlgorithm != 2) &&
					 this.subKeys[j].verifyKey())
					return this.subKeys[j];
			}
		return null;
	}

	this.getEncryptionKey = getEncryptionKey;
	this.getSigningKey = getSigningKey;
	this.read_nodes = read_nodes;
	this.write = write;
	this.toString = toString;
	this.validate = validate;
	this.getFingerprint = getFingerprint;
	this.getKeyId = getKeyId;
	this.verifyBasicSignatures = verifyBasicSignatures;
}
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
 *
 * This object contains configuration values and implements
 * storing and retrieving configuration them from HTML5 local storage.
 *
 * This object can be accessed after calling openpgp.init()
 * using openpgp.config
 * Stored config parameters can be accessed using
 * openpgp.config.config
 * @class
 * @classdesc Implementation of the GPG4Browsers config object
 */
function openpgp_config() {
	this.config = null;

	/**
	 * the default config object which is used if no
	 * configuration was in place
	 */
	this.default_config = {
			prefer_hash_algorithm: 2,
			encryption_cipher: 9,
			compression: 1,
			show_version: true,
			show_comment: true,
			integrity_protect: true,
			composition_behavior: 0,
			keyserver: "keyserver.linux.it" // "pgp.mit.edu:11371"
	};

	this.versionstring ="OpenPGP.js v.1.20121007";
	this.commentstring ="http://openpgpjs.org";
	/**
	 * reads the config out of the HTML5 local storage
	 * and initializes the object config.
	 * if config is null the default config will be used
	 * @return [void]
	 */
	function read() {
		var cf = JSON.parse(window.localStorage.getItem("config"));
		if (cf == null) {
			this.config = this.default_config;
			this.write();
		}
		else
			this.config = cf;
	}

	/**
	 * if enabled, debug messages will be printed
	 */
	this.debug = false;

	/**
	 * writes the config to HTML5 local storage
	 * @return [void]
	 */
	function write() {
		window.localStorage.setItem("config",JSON.stringify(this.config));
	}

	this.read = read;
	this.write = write;
}
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
 * @classdesc Class that represents a decoded private key for internal openpgp.js use
 */

function openpgp_msg_privatekey() {
	this.subKeys = new Array();
	this.privateKeyPacket = null;
	this.userIds = new Array();
	this.userAttributes = new Array();
	this.revocationSignatures = new Array();
	this.subKeys = new Array();

	/**
	 * 
	 * @return last position
	 */
	function read_nodes(parent_node, input, position, len) {
		this.privateKeyPacket = parent_node;
		
		var pos = position;
		while (input.length > pos) {
			var result = openpgp_packet.read_packet(input, pos, input.length - pos);
			if (result == null) {
				util.print_error("openpgp.msg.messge decrypt:\n"+'[pub/priv_key]parsing ends here @:' + pos + " l:" + len);
				break;
			} else {
				switch (result.tagType) {
				case 2: // public key revocation signature
					if (result.signatureType == 32)
						this.revocationSignatures[this.revocationSignatures.length] = result;
					else if (result.signatureType > 15 && result.signatureType < 20) {
						if (this.certificationsignatures == null)
							this.certificationSignatures = new Array();
						this.certificationSignatures[this.certificationSignatures.length] = result;
					} else
						util.print_error("openpgp.msg.messge decrypt:\n"+"unknown signature type directly on key "+result.signatureType+" @"+pos);
					pos += result.packetLength + result.headerLength;
					break;
				case 7: // PrivateSubkey Packet
					this.subKeys[this.subKeys.length] = result;
					pos += result.packetLength + result.headerLength;
					pos += result.read_nodes(this.privateKeyPacket,input, pos, input.length - pos);
					break;
				case 17: // User Attribute Packet
					this.userAttributes[this.userAttributes.length] = result;
					pos += result.packetLength + result.headerLength;
					pos += result.read_nodes(this.privateKeyPacket,input, pos, input.length - pos);
					break;
				case 13: // User ID Packet
					this.userIds[this.userIds.length] = result;
					pos += result.packetLength + result.headerLength;
					pos += result.read_nodes(this.privateKeyPacket, input, pos, input.length - pos);
					break;
				default:
					this.position = position - this.privateKeyPacket.packetLength - this.privateKeyPacket.headerLength;
					this.len = pos - position;
					return this.len;
				}
			}
		}
		this.position = position - this.privateKeyPacket.packetLength - this.privateKeyPacket.headerLength;
		this.len = pos - position;
		
		return this.len;
	}
	
	function getKeyId() {
		return this.privateKeyPacket.publicKey.getKeyId();
	}
	
	
	function getSubKeyIds() {
		if (this.privateKeyPacket.publicKey.version == 4) // V3 keys MUST NOT have subkeys.
		var result = new Array();
		for (var i = 0; i < this.subKeys.length; i++) {
			result[i] = str_sha1(this.subKeys[i].publicKey.header+this.subKeys[i].publicKey.data).substring(12,20);
		}
		return result;
	}
	
	
	function getSigningKey() {
		if ((this.privateKeyPacket.publicKey.publicKeyAlgorithm == 17 ||
			 this.privateKeyPacket.publicKey.publicKeyAlgorithm != 2)
			&& this.privateKeyPacket.publicKey.verifyKey() == 3)
			return this.privateKeyPacket;
		else if (this.privateKeyPacket.publicKey.version == 4) // V3 keys MUST NOT have subkeys.
			for (var j = 0; j < this.privateKeyPacket.subKeys.length; j++) {
				if ((this.privateKeyPacket.subKeys[j].publicKey.publicKeyAlgorithm == 17 ||
					 this.privateKeyPacket.subKeys[j].publicKey.publicKeyAlgorithm != 2) &&
					 this.privateKeyPacket.subKeys[j].publicKey.verifyKey() == 3)
					return this.privateKeyPacket.subKeys[j];
			}
		return null;
	}
	
	function getPreferredSignatureHashAlgorithm() {
		var pkey = this.getSigningKey();
		if (pkey == null) {
			util.print_error("private key is for encryption only! Cannot create a signature.")
			return null;
		}
		if (pkey.publicKey.publicKeyAlgorithm == 17) {
			var dsa = new DSA();
			return dsa.select_hash_algorithm(pkey.publicKey.MPIs[1].toBigInteger()); // q
		}
		return openpgp.config.config.prefer_hash_algorithm;
			
	}

	function decryptSecretMPIs(str_passphrase) {
		return this.privateKeyPacket.decryptSecretMPIs(str_passphrase);
	}
	
	function getFingerprint() {
		return this.privateKeyPacket.publicKey.getFingerprint();
	}

	// TODO need to implement this
	function revoke() {
		
	}

	/**
	 * extracts the public key part
	 * @return {String} OpenPGP armored text containing the public key
	 *                  returns null if no sufficient data to extract public key
	 */
	function extractPublicKey() {
		// add public key
		var key = this.privateKeyPacket.publicKey.header + this.privateKeyPacket.publicKey.data;
		for (var i = 0; i < this.userIds.length; i++) {
			// verify userids
			if (this.userIds[i].certificationSignatures.length === 0) {
				util.print_error("extractPublicKey - missing certification signatures");
				return null;
			}
			var userIdPacket = new openpgp_packet_userid();
			// add userids
			key += userIdPacket.write_packet(this.userIds[i].text);
			for (var j = 0; j < this.userIds[i].certificationSignatures.length; j++) {
				var certSig = this.userIds[i].certificationSignatures[j];
				// add signatures
				key += openpgp_packet.write_packet_header(2, certSig.data.length) + certSig.data;
			}
		}
		for (var k = 0; k < this.subKeys.length; k++) {
			var pubSubKey = this.subKeys[k].publicKey;
			// add public subkey package
			key += openpgp_packet.write_old_packet_header(14, pubSubKey.data.length) + pubSubKey.data;
			var subKeySig = this.subKeys[k].subKeySignature;
			if (subKeySig !== null) {
				// add subkey signature
				key += openpgp_packet.write_packet_header(2, subKeySig.data.length) + subKeySig.data;
			} else {
				util.print_error("extractPublicKey - missing subkey signature");
				return null;
			}
		}
		var publicArmored = openpgp_encoding_armor(4, key);
		return publicArmored;
	}

	this.extractPublicKey = extractPublicKey;
	this.getSigningKey = getSigningKey;
	this.getFingerprint = getFingerprint;
	this.getPreferredSignatureHashAlgorithm = getPreferredSignatureHashAlgorithm;
	this.read_nodes = read_nodes;
	this.decryptSecretMPIs = decryptSecretMPIs;
	this.getSubKeyIds = getSubKeyIds;
	this.getKeyId = getKeyId;
	
}
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
 * Wrapper function for the base64 codec. 
 * This function encodes a String (message) in base64 (radix-64)
 * @param message [String] the message to encode
 * @return [String] the base64 encoded data
 */
function openpgp_encoding_base64_encode(message) {
	return s2r(message);
}


/**
 * Wrapper function for the base64 codec.
 * This function decodes a String(message) in base64 (radix-64)
 * @param message [String] base64 encoded data
 * @return [String] raw data after decoding
 */
function openpgp_encoding_base64_decode(message) {
	return r2s(message);
}

/**
 * Wrapper function for jquery library.
 * This function escapes HTML characters within a string. This is used to prevent XSS.
 * @param message [String] message to escape
 * @return [String] html encoded string
 */
function openpgp_encoding_html_encode(message) {
	if (message == null)
		return "";
	return $('<div/>').text(message).html();
}

/**
 * create a EME-PKCS1-v1_5 padding (See RFC4880 13.1.1)
 * @param message [String] message to be padded
 * @param length [Integer] length to the resulting message
 * @return [String] EME-PKCS1 padded message
 */
function openpgp_encoding_eme_pkcs1_encode(message, length) {
	if (message.length > length-11)
		return -1;
	var result = "";
	result += String.fromCharCode(0);
	result += String.fromCharCode(2);
	for (var i = 0; i < length - message.length - 3; i++) {
		result += String.fromCharCode(openpgp_crypto_getPseudoRandom(1,255));
	}
	result += String.fromCharCode(0);
	result += message;
	return result;
}

/**
 * decodes a EME-PKCS1-v1_5 padding (See RFC4880 13.1.2)
 * @param message [String] EME-PKCS1 padded message
 * @return [String] decoded message 
 */
function openpgp_encoding_eme_pkcs1_decode(message, len) {
	if (message.length < len)
	    message = String.fromCharCode(0)+message;
	if (message.length < 12 || message.charCodeAt(0) != 0 || message.charCodeAt(1) != 2)
		return -1;
	var i = 2;
	while (message.charCodeAt(i) != 0 && message.length > i)
	    i++;
	return message.substring(i+1, message.length);
}
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

/**
 * create a EMSA-PKCS1-v1_5 padding (See RFC4880 13.1.3)
 * @param algo [Integer] hash algorithm type used
 * @param data [String] data to be hashed
 * @param keylength [Integer] key size of the public mpi in bytes
 * @return the [String] hashcode with pkcs1padding as string
 */
function openpgp_encoding_emsa_pkcs1_encode(algo, data, keylength) {
	var data2 = "";
	data2 += String.fromCharCode(0x00);
	data2 += String.fromCharCode(0x01);
	for (var i = 0; i < (keylength - hash_headers[algo].length - 3 - openpgp_crypto_getHashByteLength(algo)); i++)
		data2 += String.fromCharCode(0xff);
	data2 += String.fromCharCode(0x00);
	
	for (var i = 0; i < hash_headers[algo].length; i++)
		data2 += String.fromCharCode(hash_headers[algo][i]);
	
	data2 += openpgp_crypto_hashData(algo, data);
	return new BigInteger(util.hexstrdump(data2),16);
}

/**
 * extract the hash out of an EMSA-PKCS1-v1.5 padding (See RFC4880 13.1.3) 
 * @param data [String] hash in pkcs1 encoding
 * @return the hash as string
 */
function openpgp_encoding_emsa_pkcs1_decode(algo, data) { 
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
	if (data.substring(i).length < openpgp_crypto_getHashByteLength(algo)) return -1;
	return data.substring(i);
}/* OpenPGP radix-64/base64 string encoding/decoding
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
 * DeArmor an OpenPGP armored message; verify the checksum and return the encoded bytes
 * @text [String] OpenPGP armored message
 * @return either the bytes of the decoded message or an object with attribute "text" containing the message text
 * and an attribute "openpgp" containing the bytes.
 */
function openpgp_encoding_deArmor(text) {
	var type = getPGPMessageType(text);
	if (type != 2) {
	var splittedtext = text.split('-----');
	data = { openpgp: openpgp_encoding_base64_decode(splittedtext[2].split('\n\n')[1].split("\n=")[0].replace(/\n- /g,"\n")),
			type: type};
	if (verifyCheckSum(data.openpgp, splittedtext[2].split('\n\n')[1].split("\n=")[1].split('\n')[0]))
		return data;
	else
		util.print_error("Ascii armor integrity check on message failed: '"+splittedtext[2].split('\n\n')[1].split("\n=")[1].split('\n')[0]+"' should be '"+getCheckSum(data))+"'";
	} else {
		var splittedtext = text.split('-----');
		var result = { text: splittedtext[2].replace(/\n- /g,"\n").split("\n\n")[1],
		               openpgp: openpgp_encoding_base64_decode(splittedtext[4].split("\n\n")[1].split("\n=")[0]),
		               type: type};
		if (verifyCheckSum(result.openpgp, splittedtext[4].split("\n\n")[1].split("\n=")[1]))
				return result;
		else
			util.print_error("Ascii armor integrity check on message failed");
	}
}

/**
 * Finds out which Ascii Armoring type is used. This is an internal function
 * @param text [String] ascii armored text
 * @return 0 = MESSAGE PART n of m
 *         1 = MESSAGE PART n
 *         2 = SIGNED MESSAGE
 *         3 = PGP MESSAGE
 *         4 = PUBLIC KEY BLOCK
 *         5 = PRIVATE KEY BLOCK
 *         null = unknown
 */
function getPGPMessageType(text) {
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
 * @return  The header information
 */
function openpgp_encoding_armor_addheader() {
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
 * Armor an OpenPGP binary packet block
 * @param messagetype type of the message
 * @param data
 * @param partindex
 * @param parttotal
 * @return {string} Armored text
 */
function openpgp_encoding_armor(messagetype, data, partindex, parttotal) {
	var result = "";
	switch(messagetype) {
	case 0:
		result += "-----BEGIN PGP MESSAGE, PART "+partindex+"/"+parttotal+"-----\r\n";
		result += openpgp_encoding_armor_addheader();
		result += openpgp_encoding_base64_encode(data);
		result += "\r\n="+getCheckSum(data)+"\r\n";
		result += "-----END PGP MESSAGE, PART "+partindex+"/"+parttotal+"-----\r\n";
		break;
	case 1:
		result += "-----BEGIN PGP MESSAGE, PART "+partindex+"-----\r\n";
		result += openpgp_encoding_armor_addheader();
		result += openpgp_encoding_base64_encode(data);
		result += "\r\n="+getCheckSum(data)+"\r\n";
		result += "-----END PGP MESSAGE, PART "+partindex+"-----\r\n";
		break;
	case 2:
		result += "\r\n-----BEGIN PGP SIGNED MESSAGE-----\r\nHash: "+data.hash+"\r\n\r\n";
		result += data.text.replace(/\n-/g,"\n- -");
		result += "\r\n-----BEGIN PGP SIGNATURE-----\r\n";
		result += openpgp_encoding_armor_addheader();
		result += openpgp_encoding_base64_encode(data.openpgp);
		result += "\r\n="+getCheckSum(data.openpgp)+"\r\n";
		result += "-----END PGP SIGNATURE-----\r\n";
		break;
	case 3:
		result += "-----BEGIN PGP MESSAGE-----\r\n";
		result += openpgp_encoding_armor_addheader();
		result += openpgp_encoding_base64_encode(data);
		result += "\r\n="+getCheckSum(data)+"\r\n";
		result += "-----END PGP MESSAGE-----\r\n";
		break;
	case 4:
		result += "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n";
		result += openpgp_encoding_armor_addheader();
		result += openpgp_encoding_base64_encode(data);
		result += "\r\n="+getCheckSum(data)+"\r\n";
		result += "-----END PGP PUBLIC KEY BLOCK-----\r\n\r\n";
		break;
	case 5:
		result += "-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n";
		result += openpgp_encoding_armor_addheader();
		result += openpgp_encoding_base64_encode(data);
		result += "\r\n="+getCheckSum(data)+"\r\n";
		result += "-----END PGP PRIVATE KEY BLOCK-----\r\n";
		break;
	}

	return result;
}

/**
 * Calculates a checksum over the given data and returns it base64 encoded
 * @param data [String] data to create a CRC-24 checksum for
 * @return [String] base64 encoded checksum
 */
function getCheckSum(data) {
	var c = createcrc24(data);
	var str = "" + String.fromCharCode(c >> 16)+
				   String.fromCharCode((c >> 8) & 0xFF)+
				   String.fromCharCode(c & 0xFF);
	return openpgp_encoding_base64_encode(str);
}

/**
 * Calculates the checksum over the given data and compares it with the given base64 encoded checksum
 * @param data [String] data to create a CRC-24 checksum for
 * @param checksum [String] base64 encoded checksum
 * @return true if the given checksum is correct; otherwise false
 */
function verifyCheckSum(data, checksum) {
	var c = getCheckSum(data);
	var d = checksum;
	return c[0] == d[0] && c[1] == d[1] && c[2] == d[2];
}
/**
 * Internal function to calculate a CRC-24 checksum over a given string (data)
 * @param data [String] data to create a CRC-24 checksum for
 * @return [Integer] the CRC-24 checksum as number
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

JXG = {exists: (function(undefined){return function(v){return !(v===undefined || v===null);}})()};
JXG.decompress = function(str) {return unescape((new JXG.Util.Unzip(JXG.Util.Base64.decodeAsArray(str))).unzip()[0][0]);};
/*
    Copyright 2008-2012
        Matthias Ehmann,
        Michael Gerhaeuser,
        Carsten Miller,
        Bianca Valentin,
        Alfred Wassermann,
        Peter Wilfahrt

    This file is part of JSXGraph.
    
    Dual licensed under the Apache License Version 2.0, or LGPL Version 3 licenses.

    You should have received a copy of the GNU Lesser General Public License
    along with JSXCompressor.  If not, see <http://www.gnu.org/licenses/>.
    
    You should have received a copy of the Apache License along with JSXCompressor.  
    If not, see <http://www.apache.org/licenses/>.

*/

/**
  * @class Util class
  * @classdesc Utilities for uncompressing and base64 decoding
  * Class for gunzipping, unzipping and base64 decoding of files.
  * It is used for reading GEONExT, Geogebra and Intergeo files.
  *
  * Only Huffman codes are decoded in gunzip.
  * The code is based on the source code for gunzip.c by Pasi Ojala 
  * @see <a href="http://www.cs.tut.fi/~albert/Dev/gunzip/gunzip.c">http://www.cs.tut.fi/~albert/Dev/gunzip/gunzip.c</a>
  * @see <a href="http://www.cs.tut.fi/~albert">http://www.cs.tut.fi/~albert</a>
  */
JXG.Util = {};
                                 
/**
 * Unzip zip files
 */
JXG.Util.Unzip = function (barray){
    var outputArr = [],
        output = "",
        debug = false,
        gpflags,
        files = 0,
        unzipped = [],
        crc,
        buf32k = new Array(32768),
        bIdx = 0,
        modeZIP=false,

        CRC, SIZE,
    
        bitReverse = [
        0x00, 0x80, 0x40, 0xc0, 0x20, 0xa0, 0x60, 0xe0,
        0x10, 0x90, 0x50, 0xd0, 0x30, 0xb0, 0x70, 0xf0,
        0x08, 0x88, 0x48, 0xc8, 0x28, 0xa8, 0x68, 0xe8,
        0x18, 0x98, 0x58, 0xd8, 0x38, 0xb8, 0x78, 0xf8,
        0x04, 0x84, 0x44, 0xc4, 0x24, 0xa4, 0x64, 0xe4,
        0x14, 0x94, 0x54, 0xd4, 0x34, 0xb4, 0x74, 0xf4,
        0x0c, 0x8c, 0x4c, 0xcc, 0x2c, 0xac, 0x6c, 0xec,
        0x1c, 0x9c, 0x5c, 0xdc, 0x3c, 0xbc, 0x7c, 0xfc,
        0x02, 0x82, 0x42, 0xc2, 0x22, 0xa2, 0x62, 0xe2,
        0x12, 0x92, 0x52, 0xd2, 0x32, 0xb2, 0x72, 0xf2,
        0x0a, 0x8a, 0x4a, 0xca, 0x2a, 0xaa, 0x6a, 0xea,
        0x1a, 0x9a, 0x5a, 0xda, 0x3a, 0xba, 0x7a, 0xfa,
        0x06, 0x86, 0x46, 0xc6, 0x26, 0xa6, 0x66, 0xe6,
        0x16, 0x96, 0x56, 0xd6, 0x36, 0xb6, 0x76, 0xf6,
        0x0e, 0x8e, 0x4e, 0xce, 0x2e, 0xae, 0x6e, 0xee,
        0x1e, 0x9e, 0x5e, 0xde, 0x3e, 0xbe, 0x7e, 0xfe,
        0x01, 0x81, 0x41, 0xc1, 0x21, 0xa1, 0x61, 0xe1,
        0x11, 0x91, 0x51, 0xd1, 0x31, 0xb1, 0x71, 0xf1,
        0x09, 0x89, 0x49, 0xc9, 0x29, 0xa9, 0x69, 0xe9,
        0x19, 0x99, 0x59, 0xd9, 0x39, 0xb9, 0x79, 0xf9,
        0x05, 0x85, 0x45, 0xc5, 0x25, 0xa5, 0x65, 0xe5,
        0x15, 0x95, 0x55, 0xd5, 0x35, 0xb5, 0x75, 0xf5,
        0x0d, 0x8d, 0x4d, 0xcd, 0x2d, 0xad, 0x6d, 0xed,
        0x1d, 0x9d, 0x5d, 0xdd, 0x3d, 0xbd, 0x7d, 0xfd,
        0x03, 0x83, 0x43, 0xc3, 0x23, 0xa3, 0x63, 0xe3,
        0x13, 0x93, 0x53, 0xd3, 0x33, 0xb3, 0x73, 0xf3,
        0x0b, 0x8b, 0x4b, 0xcb, 0x2b, 0xab, 0x6b, 0xeb,
        0x1b, 0x9b, 0x5b, 0xdb, 0x3b, 0xbb, 0x7b, 0xfb,
        0x07, 0x87, 0x47, 0xc7, 0x27, 0xa7, 0x67, 0xe7,
        0x17, 0x97, 0x57, 0xd7, 0x37, 0xb7, 0x77, 0xf7,
        0x0f, 0x8f, 0x4f, 0xcf, 0x2f, 0xaf, 0x6f, 0xef,
        0x1f, 0x9f, 0x5f, 0xdf, 0x3f, 0xbf, 0x7f, 0xff
    ],
    
    cplens = [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
        35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258, 0, 0
    ],

    cplext = [
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
        3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0, 99, 99
    ], /* 99==invalid */

    cpdist = [
        0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0007, 0x0009, 0x000d,
        0x0011, 0x0019, 0x0021, 0x0031, 0x0041, 0x0061, 0x0081, 0x00c1,
        0x0101, 0x0181, 0x0201, 0x0301, 0x0401, 0x0601, 0x0801, 0x0c01,
        0x1001, 0x1801, 0x2001, 0x3001, 0x4001, 0x6001
    ],

    cpdext = [
        0,  0,  0,  0,  1,  1,  2,  2,
        3,  3,  4,  4,  5,  5,  6,  6,
        7,  7,  8,  8,  9,  9, 10, 10,
        11, 11, 12, 12, 13, 13
    ],
    
    border = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15],
    
    bA = barray,

    bytepos=0,
    bitpos=0,
    bb = 1,
    bits=0,
    
    NAMEMAX = 256,
    
    nameBuf = [],
    
    fileout;
    
    function readByte(){
        bits+=8;
        if (bytepos<bA.length){
            //if (debug)
            //    document.write(bytepos+": "+bA[bytepos]+"<br>");
            return bA[bytepos++];
        } else
            return -1;
    };

    function byteAlign(){
        bb = 1;
    };
    
    function readBit(){
        var carry;
        bits++;
        carry = (bb & 1);
        bb >>= 1;
        if (bb==0){
            bb = readByte();
            carry = (bb & 1);
            bb = (bb>>1) | 0x80;
        }
        return carry;
    };

    function readBits(a) {
        var res = 0,
            i = a;
    
        while(i--) {
            res = (res<<1) | readBit();
        }
        if(a) {
            res = bitReverse[res]>>(8-a);
        }
        return res;
    };
        
    function flushBuffer(){
        //document.write('FLUSHBUFFER:'+buf32k);
        bIdx = 0;
    };
    function addBuffer(a){
        SIZE++;
        //CRC=updcrc(a,crc);
        buf32k[bIdx++] = a;
        outputArr.push(String.fromCharCode(a));
        //output+=String.fromCharCode(a);
        if(bIdx==0x8000){
            //document.write('ADDBUFFER:'+buf32k);
            bIdx=0;
        }
    };
    
    function HufNode() {
        this.b0=0;
        this.b1=0;
        this.jump = null;
        this.jumppos = -1;
    };

    var LITERALS = 288;
    
    var literalTree = new Array(LITERALS);
    var distanceTree = new Array(32);
    var treepos=0;
    var Places = null;
    var Places2 = null;
    
    var impDistanceTree = new Array(64);
    var impLengthTree = new Array(64);
    
    var len = 0;
    var fpos = new Array(17);
    fpos[0]=0;
    var flens;
    var fmax;
    
    function IsPat() {
        while (1) {
            if (fpos[len] >= fmax)
                return -1;
            if (flens[fpos[len]] == len)
                return fpos[len]++;
            fpos[len]++;
        }
    };

    function Rec() {
        var curplace = Places[treepos];
        var tmp;
        if (debug)
    		document.write("<br>len:"+len+" treepos:"+treepos);
        if(len==17) { //war 17
            return -1;
        }
        treepos++;
        len++;
    	
        tmp = IsPat();
        if (debug)
        	document.write("<br>IsPat "+tmp);
        if(tmp >= 0) {
            curplace.b0 = tmp;    /* leaf cell for 0-bit */
            if (debug)
            	document.write("<br>b0 "+curplace.b0);
        } else {
        /* Not a Leaf cell */
        curplace.b0 = 0x8000;
        if (debug)
        	document.write("<br>b0 "+curplace.b0);
        if(Rec())
            return -1;
        }
        tmp = IsPat();
        if(tmp >= 0) {
            curplace.b1 = tmp;    /* leaf cell for 1-bit */
            if (debug)
            	document.write("<br>b1 "+curplace.b1);
            curplace.jump = null;    /* Just for the display routine */
        } else {
            /* Not a Leaf cell */
            curplace.b1 = 0x8000;
            if (debug)
            	document.write("<br>b1 "+curplace.b1);
            curplace.jump = Places[treepos];
            curplace.jumppos = treepos;
            if(Rec())
                return -1;
        }
        len--;
        return 0;
    };

    function CreateTree(currentTree, numval, lengths, show) {
        var i;
        /* Create the Huffman decode tree/table */
        //document.write("<br>createtree<br>");
        if (debug)
        	document.write("currentTree "+currentTree+" numval "+numval+" lengths "+lengths+" show "+show);
        Places = currentTree;
        treepos=0;
        flens = lengths;
        fmax  = numval;
        for (i=0;i<17;i++)
            fpos[i] = 0;
        len = 0;
        if(Rec()) {
            //fprintf(stderr, "invalid huffman tree\n");
            if (debug)
            	alert("invalid huffman tree\n");
            return -1;
        }
        if (debug){
        	document.write('<br>Tree: '+Places.length);
        	for (var a=0;a<32;a++){
            	document.write("Places["+a+"].b0="+Places[a].b0+"<br>");
            	document.write("Places["+a+"].b1="+Places[a].b1+"<br>");
        	}
        }
    
        /*if(show) {
            var tmp;
            for(tmp=currentTree;tmp<Places;tmp++) {
                fprintf(stdout, "0x%03x  0x%03x (0x%04x)",tmp-currentTree, tmp->jump?tmp->jump-currentTree:0,(tmp->jump?tmp->jump-currentTree:0)*6+0xcf0);
                if(!(tmp.b0 & 0x8000)) {
                    //fprintf(stdout, "  0x%03x (%c)", tmp->b0,(tmp->b0<256 && isprint(tmp->b0))?tmp->b0:'�');
                }
                if(!(tmp.b1 & 0x8000)) {
                    if((tmp.b0 & 0x8000))
                        fprintf(stdout, "           ");
                    fprintf(stdout, "  0x%03x (%c)", tmp->b1,(tmp->b1<256 && isprint(tmp->b1))?tmp->b1:'�');
                }
                fprintf(stdout, "\n");
            }
        }*/
        return 0;
    };
    
    function DecodeValue(currentTree) {
        var len, i,
            xtreepos=0,
            X = currentTree[xtreepos],
            b;

        /* decode one symbol of the data */
        while(1) {
            b=readBit();
            if (debug)
            	document.write("b="+b);
            if(b) {
                if(!(X.b1 & 0x8000)){
                	if (debug)
                    	document.write("ret1");
                    return X.b1;    /* If leaf node, return data */
                }
                X = X.jump;
                len = currentTree.length;
                for (i=0;i<len;i++){
                    if (currentTree[i]===X){
                        xtreepos=i;
                        break;
                    }
                }
                //xtreepos++;
            } else {
                if(!(X.b0 & 0x8000)){
                	if (debug)
                    	document.write("ret2");
                    return X.b0;    /* If leaf node, return data */
                }
                //X++; //??????????????????
                xtreepos++;
                X = currentTree[xtreepos];
            }
        }
        if (debug)
        	document.write("ret3");
        return -1;
    };
    
    function DeflateLoop() {
    var last, c, type, i, len;

    do {
        /*if((last = readBit())){
            fprintf(errfp, "Last Block: ");
        } else {
            fprintf(errfp, "Not Last Block: ");
        }*/
        last = readBit();
        type = readBits(2);
        switch(type) {
            case 0:
            	if (debug)
                	alert("Stored\n");
                break;
            case 1:
            	if (debug)
                	alert("Fixed Huffman codes\n");
                break;
            case 2:
            	if (debug)
                	alert("Dynamic Huffman codes\n");
                break;
            case 3:
            	if (debug)
                	alert("Reserved block type!!\n");
                break;
            default:
            	if (debug)
                	alert("Unexpected value %d!\n", type);
                break;
        }

        if(type==0) {
            var blockLen, cSum;

            // Stored 
            byteAlign();
            blockLen = readByte();
            blockLen |= (readByte()<<8);

            cSum = readByte();
            cSum |= (readByte()<<8);

            if(((blockLen ^ ~cSum) & 0xffff)) {
                document.write("BlockLen checksum mismatch\n");
            }
            while(blockLen--) {
                c = readByte();
                addBuffer(c);
            }
        } else if(type==1) {
            var j;

            /* Fixed Huffman tables -- fixed decode routine */
            while(1) {
            /*
                256    0000000        0
                :   :     :
                279    0010111        23
                0   00110000    48
                :    :      :
                143    10111111    191
                280 11000000    192
                :    :      :
                287 11000111    199
                144    110010000    400
                :    :       :
                255    111111111    511
    
                Note the bit order!
                */

            j = (bitReverse[readBits(7)]>>1);
            if(j > 23) {
                j = (j<<1) | readBit();    /* 48..255 */

                if(j > 199) {    /* 200..255 */
                    j -= 128;    /*  72..127 */
                    j = (j<<1) | readBit();        /* 144..255 << */
                } else {        /*  48..199 */
                    j -= 48;    /*   0..151 */
                    if(j > 143) {
                        j = j+136;    /* 280..287 << */
                        /*   0..143 << */
                    }
                }
            } else {    /*   0..23 */
                j += 256;    /* 256..279 << */
            }
            if(j < 256) {
                addBuffer(j);
                //document.write("out:"+String.fromCharCode(j));
                /*fprintf(errfp, "@%d %02x\n", SIZE, j);*/
            } else if(j == 256) {
                /* EOF */
                break;
            } else {
                var len, dist;

                j -= 256 + 1;    /* bytes + EOF */
                len = readBits(cplext[j]) + cplens[j];

                j = bitReverse[readBits(5)]>>3;
                if(cpdext[j] > 8) {
                    dist = readBits(8);
                    dist |= (readBits(cpdext[j]-8)<<8);
                } else {
                    dist = readBits(cpdext[j]);
                }
                dist += cpdist[j];

                /*fprintf(errfp, "@%d (l%02x,d%04x)\n", SIZE, len, dist);*/
                for(j=0;j<len;j++) {
                    var c = buf32k[(bIdx - dist) & 0x7fff];
                    addBuffer(c);
                }
            }
            } // while
        } else if(type==2) {
            var j, n, literalCodes, distCodes, lenCodes;
            var ll = new Array(288+32);    // "static" just to preserve stack
    
            // Dynamic Huffman tables 
    
            literalCodes = 257 + readBits(5);
            distCodes = 1 + readBits(5);
            lenCodes = 4 + readBits(4);
            //document.write("<br>param: "+literalCodes+" "+distCodes+" "+lenCodes+"<br>");
            for(j=0; j<19; j++) {
                ll[j] = 0;
            }
    
            // Get the decode tree code lengths
    
            //document.write("<br>");
            for(j=0; j<lenCodes; j++) {
                ll[border[j]] = readBits(3);
                //document.write(ll[border[j]]+" ");
            }
            //fprintf(errfp, "\n");
            //document.write('<br>ll:'+ll);
            len = distanceTree.length;
            for (i=0; i<len; i++)
                distanceTree[i]=new HufNode();
            if(CreateTree(distanceTree, 19, ll, 0)) {
                flushBuffer();
                return 1;
            }
            if (debug){
            	document.write("<br>distanceTree");
            	for(var a=0;a<distanceTree.length;a++){
                	document.write("<br>"+distanceTree[a].b0+" "+distanceTree[a].b1+" "+distanceTree[a].jump+" "+distanceTree[a].jumppos);
                	/*if (distanceTree[a].jumppos!=-1)
                    	document.write(" "+distanceTree[a].jump.b0+" "+distanceTree[a].jump.b1);
                	*/
            	}
            }
            //document.write('<BR>tree created');
    
            //read in literal and distance code lengths
            n = literalCodes + distCodes;
            i = 0;
            var z=-1;
            if (debug)
            	document.write("<br>n="+n+" bits: "+bits+"<br>");
            while(i < n) {
                z++;
                j = DecodeValue(distanceTree);
                if (debug)
                	document.write("<br>"+z+" i:"+i+" decode: "+j+"    bits "+bits+"<br>");
                if(j<16) {    // length of code in bits (0..15)
                       ll[i++] = j;
                } else if(j==16) {    // repeat last length 3 to 6 times 
                       var l;
                    j = 3 + readBits(2);
                    if(i+j > n) {
                        flushBuffer();
                        return 1;
                    }
                    l = i ? ll[i-1] : 0;
                    while(j--) {
                        ll[i++] = l;
                    }
                } else {
                    if(j==17) {        // 3 to 10 zero length codes
                        j = 3 + readBits(3);
                    } else {        // j == 18: 11 to 138 zero length codes 
                        j = 11 + readBits(7);
                    }
                    if(i+j > n) {
                        flushBuffer();
                        return 1;
                    }
                    while(j--) {
                        ll[i++] = 0;
                    }
                }
            }
            /*for(j=0; j<literalCodes+distCodes; j++) {
                //fprintf(errfp, "%d ", ll[j]);
                if ((j&7)==7)
                    fprintf(errfp, "\n");
            }
            fprintf(errfp, "\n");*/
            // Can overwrite tree decode tree as it is not used anymore
            len = literalTree.length;
            for (i=0; i<len; i++)
                literalTree[i]=new HufNode();
            if(CreateTree(literalTree, literalCodes, ll, 0)) {
                flushBuffer();
                return 1;
            }
            len = literalTree.length;
            for (i=0; i<len; i++)
                distanceTree[i]=new HufNode();
            var ll2 = new Array();
            for (i=literalCodes; i <ll.length; i++){
                ll2[i-literalCodes]=ll[i];
            }    
            if(CreateTree(distanceTree, distCodes, ll2, 0)) {
                flushBuffer();
                return 1;
            }
            if (debug)
           		document.write("<br>literalTree");
            outer:
            while(1) {
                j = DecodeValue(literalTree);
                if(j >= 256) {        // In C64: if carry set
                    var len, dist;
                    j -= 256;
                    if(j == 0) {
                        // EOF
                        break;
                    }
                    j--;
                    len = readBits(cplext[j]) + cplens[j];
    
                    j = DecodeValue(distanceTree);
                    if(cpdext[j] > 8) {
                        dist = readBits(8);
                        dist |= (readBits(cpdext[j]-8)<<8);
                    } else {
                        dist = readBits(cpdext[j]);
                    }
                    dist += cpdist[j];
                    while(len--) {
                        if(bIdx - dist < 0) {
                            break outer;
                        }
                        var c = buf32k[(bIdx - dist) & 0x7fff];
                        addBuffer(c);
                    }
                } else {
                    addBuffer(j);
                }
            }
        }
    } while(!last);
    flushBuffer();

    byteAlign();
    return 0;
};

JXG.Util.Unzip.prototype.unzipFile = function(name) {
    var i;
	this.unzip();
	//alert(unzipped[0][1]);
	for (i=0;i<unzipped.length;i++){
		if(unzipped[i][1]==name) {
			return unzipped[i][0];
		}
	}
	
  };

JXG.Util.Unzip.prototype.deflate = function() {
    outputArr = [];
    var tmp = [];
    modeZIP = false;
    DeflateLoop();
    if (debug)
        alert(outputArr.join(''));
    unzipped[files] = new Array(2);
    unzipped[files][0] = outputArr.join('');
    unzipped[files][1] = "DEFLATE";
    files++;
    return unzipped;
}    
    
JXG.Util.Unzip.prototype.unzip = function() {
	//convertToByteArray(input);
	if (debug)
		alert(bA);
	/*for (i=0;i<bA.length*8;i++){
		document.write(readBit());
		if ((i+1)%8==0)
			document.write(" ");
	}*/
	/*for (i=0;i<bA.length;i++){
		document.write(readByte()+" ");
		if ((i+1)%8==0)
			document.write(" ");
	}
	for (i=0;i<bA.length;i++){
		document.write(bA[i]+" ");
		if ((i+1)%16==0)
			document.write("<br>");
	}	
	*/
	//alert(bA);
	nextFile();
	return unzipped;
  };
    
 function nextFile(){
 	if (debug)
 		alert("NEXTFILE");
 	outputArr = [];
 	var tmp = [];
 	modeZIP = false;
	tmp[0] = readByte();
	tmp[1] = readByte();
	if (debug)
		alert("type: "+tmp[0]+" "+tmp[1]);
	if (tmp[0] == parseInt("78",16) && tmp[1] == parseInt("da",16)){ //GZIP
		if (debug)
			alert("GEONExT-GZIP");
		DeflateLoop();
		if (debug)
			alert(outputArr.join(''));
		unzipped[files] = new Array(2);
    	unzipped[files][0] = outputArr.join('');
    	unzipped[files][1] = "geonext.gxt";
    	files++;
	}
	if (tmp[0] == parseInt("78",16) && tmp[1] == parseInt("9c",16)){ //ZLIB
		if (debug)
			alert("ZLIB");
		DeflateLoop();
		if (debug)
			alert(outputArr.join(''));
		unzipped[files] = new Array(2);
    	unzipped[files][0] = outputArr.join('');
    	unzipped[files][1] = "ZLIB";
    	files++;
	}
	if (tmp[0] == parseInt("1f",16) && tmp[1] == parseInt("8b",16)){ //GZIP
		if (debug)
			alert("GZIP");
		//DeflateLoop();
		skipdir();
		if (debug)
			alert(outputArr.join(''));
		unzipped[files] = new Array(2);
    	unzipped[files][0] = outputArr.join('');
    	unzipped[files][1] = "file";
    	files++;
	}
	if (tmp[0] == parseInt("50",16) && tmp[1] == parseInt("4b",16)){ //ZIP
		modeZIP = true;
		tmp[2] = readByte();
		tmp[3] = readByte();
		if (tmp[2] == parseInt("3",16) && tmp[3] == parseInt("4",16)){
			//MODE_ZIP
			tmp[0] = readByte();
			tmp[1] = readByte();
			if (debug)
				alert("ZIP-Version: "+tmp[1]+" "+tmp[0]/10+"."+tmp[0]%10);
			
			gpflags = readByte();
			gpflags |= (readByte()<<8);
			if (debug)
				alert("gpflags: "+gpflags);
			
			var method = readByte();
			method |= (readByte()<<8);
			if (debug)
				alert("method: "+method);
			
			readByte();
			readByte();
			readByte();
			readByte();
			
			var crc = readByte();
			crc |= (readByte()<<8);
			crc |= (readByte()<<16);
			crc |= (readByte()<<24);
			
			var compSize = readByte();
			compSize |= (readByte()<<8);
			compSize |= (readByte()<<16);
			compSize |= (readByte()<<24);
			
			var size = readByte();
			size |= (readByte()<<8);
			size |= (readByte()<<16);
			size |= (readByte()<<24);
			
			if (debug)
				alert("local CRC: "+crc+"\nlocal Size: "+size+"\nlocal CompSize: "+compSize);
			
			var filelen = readByte();
			filelen |= (readByte()<<8);
			
			var extralen = readByte();
			extralen |= (readByte()<<8);
			
			if (debug)
				alert("filelen "+filelen);
			i = 0;
			nameBuf = [];
			while (filelen--){ 
				var c = readByte();
				if (c == "/" | c ==":"){
					i = 0;
				} else if (i < NAMEMAX-1)
					nameBuf[i++] = String.fromCharCode(c);
			}
			if (debug)
				alert("nameBuf: "+nameBuf);
			
			//nameBuf[i] = "\0";
			if (!fileout)
				fileout = nameBuf;
			
			var i = 0;
			while (i < extralen){
				c = readByte();
				i++;
			}
				
			CRC = 0xffffffff;
			SIZE = 0;
			
			if (size = 0 && fileOut.charAt(fileout.length-1)=="/"){
				//skipdir
				if (debug)
					alert("skipdir");
			}
			if (method == 8){
				DeflateLoop();
				if (debug)
					alert(outputArr.join(''));
				unzipped[files] = new Array(2);
				unzipped[files][0] = outputArr.join('');
    			unzipped[files][1] = nameBuf.join('');
    			files++;
				//return outputArr.join('');
			}
			skipdir();
		}
	}
 };
	
function skipdir(){
    var crc, 
        tmp = [],
        compSize, size, os, i, c;
    
	if ((gpflags & 8)) {
		tmp[0] = readByte();
		tmp[1] = readByte();
		tmp[2] = readByte();
		tmp[3] = readByte();
		
		if (tmp[0] == parseInt("50",16) && 
            tmp[1] == parseInt("4b",16) && 
            tmp[2] == parseInt("07",16) && 
            tmp[3] == parseInt("08",16))
        {
            crc = readByte();
            crc |= (readByte()<<8);
            crc |= (readByte()<<16);
            crc |= (readByte()<<24);
		} else {
			crc = tmp[0] | (tmp[1]<<8) | (tmp[2]<<16) | (tmp[3]<<24);
		}
		
		compSize = readByte();
		compSize |= (readByte()<<8);
		compSize |= (readByte()<<16);
		compSize |= (readByte()<<24);
		
		size = readByte();
		size |= (readByte()<<8);
		size |= (readByte()<<16);
		size |= (readByte()<<24);
		
		if (debug)
			alert("CRC:");
	}

	if (modeZIP)
		nextFile();
	
	tmp[0] = readByte();
	if (tmp[0] != 8) {
		if (debug)
			alert("Unknown compression method!");
        return 0;	
	}
	
	gpflags = readByte();
	if (debug){
		if ((gpflags & ~(parseInt("1f",16))))
			alert("Unknown flags set!");
	}
	
	readByte();
	readByte();
	readByte();
	readByte();
	
	readByte();
	os = readByte();
	
	if ((gpflags & 4)){
		tmp[0] = readByte();
		tmp[2] = readByte();
		len = tmp[0] + 256*tmp[1];
		if (debug)
			alert("Extra field size: "+len);
		for (i=0;i<len;i++)
			readByte();
	}
	
	if ((gpflags & 8)){
		i=0;
		nameBuf=[];
		while (c=readByte()){
			if(c == "7" || c == ":")
				i=0;
			if (i<NAMEMAX-1)
				nameBuf[i++] = c;
		}
		//nameBuf[i] = "\0";
		if (debug)
			alert("original file name: "+nameBuf);
	}
		
	if ((gpflags & 16)){
		while (c=readByte()){
			//FILE COMMENT
		}
	}
	
	if ((gpflags & 2)){
		readByte();
		readByte();
	}
	
	DeflateLoop();
	
	crc = readByte();
	crc |= (readByte()<<8);
	crc |= (readByte()<<16);
	crc |= (readByte()<<24);
	
	size = readByte();
	size |= (readByte()<<8);
	size |= (readByte()<<16);
	size |= (readByte()<<24);
	
	if (modeZIP)
		nextFile();
	
};

};

/**
*  Base64 encoding / decoding
*  @see <a href="http://www.webtoolkit.info/">http://www.webtoolkit.info/</A>
*/
JXG.Util.Base64 = {

    // private property
    _keyStr : "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",

    // public method for encoding
    encode : function (input) {
        var output = [],
            chr1, chr2, chr3, enc1, enc2, enc3, enc4,
            i = 0;

        input = JXG.Util.Base64._utf8_encode(input);

        while (i < input.length) {

            chr1 = input.charCodeAt(i++);
            chr2 = input.charCodeAt(i++);
            chr3 = input.charCodeAt(i++);

            enc1 = chr1 >> 2;
            enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
            enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
            enc4 = chr3 & 63;

            if (isNaN(chr2)) {
                enc3 = enc4 = 64;
            } else if (isNaN(chr3)) {
                enc4 = 64;
            }

            output.push([this._keyStr.charAt(enc1),
                         this._keyStr.charAt(enc2),
                         this._keyStr.charAt(enc3),
                         this._keyStr.charAt(enc4)].join(''));
        }

        return output.join('');
    },

    // public method for decoding
    decode : function (input, utf8) {
        var output = [],
            chr1, chr2, chr3,
            enc1, enc2, enc3, enc4,
            i = 0;

        input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");

        while (i < input.length) {

            enc1 = this._keyStr.indexOf(input.charAt(i++));
            enc2 = this._keyStr.indexOf(input.charAt(i++));
            enc3 = this._keyStr.indexOf(input.charAt(i++));
            enc4 = this._keyStr.indexOf(input.charAt(i++));

            chr1 = (enc1 << 2) | (enc2 >> 4);
            chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
            chr3 = ((enc3 & 3) << 6) | enc4;

            output.push(String.fromCharCode(chr1));

            if (enc3 != 64) {
                output.push(String.fromCharCode(chr2));
            }
            if (enc4 != 64) {
                output.push(String.fromCharCode(chr3));
            }
        }
        
        output = output.join(''); 
        
        if (utf8) {
            output = JXG.Util.Base64._utf8_decode(output);
        }
        return output;

    },

    // private method for UTF-8 encoding
    _utf8_encode : function (string) {
        string = string.replace(/\r\n/g,"\n");
        var utftext = "";

        for (var n = 0; n < string.length; n++) {

            var c = string.charCodeAt(n);

            if (c < 128) {
                utftext += String.fromCharCode(c);
            }
            else if((c > 127) && (c < 2048)) {
                utftext += String.fromCharCode((c >> 6) | 192);
                utftext += String.fromCharCode((c & 63) | 128);
            }
            else {
                utftext += String.fromCharCode((c >> 12) | 224);
                utftext += String.fromCharCode(((c >> 6) & 63) | 128);
                utftext += String.fromCharCode((c & 63) | 128);
            }

        }

        return utftext;
    },

    // private method for UTF-8 decoding
    _utf8_decode : function (utftext) {
        var string = [],
            i = 0,
            c = 0, c2 = 0, c3 = 0;

        while ( i < utftext.length ) {
            c = utftext.charCodeAt(i);
            if (c < 128) {
                string.push(String.fromCharCode(c));
                i++;
            }
            else if((c > 191) && (c < 224)) {
                c2 = utftext.charCodeAt(i+1);
                string.push(String.fromCharCode(((c & 31) << 6) | (c2 & 63)));
                i += 2;
            }
            else {
                c2 = utftext.charCodeAt(i+1);
                c3 = utftext.charCodeAt(i+2);
                string.push(String.fromCharCode(((c & 15) << 12) | ((c2 & 63) << 6) | (c3 & 63)));
                i += 3;
            }
        }
        return string.join('');
    },
    
    _destrip: function (stripped, wrap){
        var lines = [], lineno, i,
            destripped = [];
        
        if (wrap==null) 
            wrap = 76;
            
        stripped.replace(/ /g, "");
        lineno = stripped.length / wrap;
        for (i = 0; i < lineno; i++)
            lines[i]=stripped.substr(i * wrap, wrap);
        if (lineno != stripped.length / wrap)
            lines[lines.length]=stripped.substr(lineno * wrap, stripped.length-(lineno * wrap));
            
        for (i = 0; i < lines.length; i++)
            destripped.push(lines[i]);
        return destripped.join('\n');
    },
    
    decodeAsArray: function (input){
        var dec = this.decode(input),
            ar = [], i;
        for (i=0;i<dec.length;i++){
            ar[i]=dec.charCodeAt(i);
        }
        return ar;
    },
    
    decodeGEONExT : function (input) {
        return decodeAsArray(destrip(input),false);
    }
};

/**
 * @private
 */
JXG.Util.asciiCharCodeAt = function(str,i){
	var c = str.charCodeAt(i);
	if (c>255){
    	switch (c) {
			case 8364: c=128;
	    	break;
	    	case 8218: c=130;
	    	break;
	    	case 402: c=131;
	    	break;
	    	case 8222: c=132;
	    	break;
	    	case 8230: c=133;
	    	break;
	    	case 8224: c=134;
	    	break;
	    	case 8225: c=135;
	    	break;
	    	case 710: c=136;
	    	break;
	    	case 8240: c=137;
	    	break;
	    	case 352: c=138;
	    	break;
	    	case 8249: c=139;
	    	break;
	    	case 338: c=140;
	    	break;
	    	case 381: c=142;
	    	break;
	    	case 8216: c=145;
	    	break;
	    	case 8217: c=146;
	    	break;
	    	case 8220: c=147;
	    	break;
	    	case 8221: c=148;
	    	break;
	    	case 8226: c=149;
	    	break;
	    	case 8211: c=150;
	    	break;
	    	case 8212: c=151;
	    	break;
	    	case 732: c=152;
	    	break;
	    	case 8482: c=153;
	    	break;
	    	case 353: c=154;
	    	break;
	    	case 8250: c=155;
	    	break;
	    	case 339: c=156;
	    	break;
	    	case 382: c=158;
	    	break;
	    	case 376: c=159;
	    	break;
	    	default:
	    	break;
	    }
	}
	return c;
};

/**
 * Decoding string into utf-8
 * @param {String} string to decode
 * @return {String} utf8 decoded string
 */
JXG.Util.utf8Decode = function(utftext) {
  var string = [];
  var i = 0;
  var c = 0, c1 = 0, c2 = 0, c3;
  if (!JXG.exists(utftext)) return '';
  
  while ( i < utftext.length ) {
    c = utftext.charCodeAt(i);

    if (c < 128) {
      string.push(String.fromCharCode(c));
      i++;
    } else if((c > 191) && (c < 224)) {
      c2 = utftext.charCodeAt(i+1);
      string.push(String.fromCharCode(((c & 31) << 6) | (c2 & 63)));
      i += 2;
    } else {
      c2 = utftext.charCodeAt(i+1);
      c3 = utftext.charCodeAt(i+2);
      string.push(String.fromCharCode(((c & 15) << 12) | ((c2 & 63) << 6) | (c3 & 63)));
      i += 3;
    }
  };
  return string.join('');
};

/**
 * Generate a random uuid.
 * http://www.broofa.com
 * mailto:robert@broofa.com
 *
 * Copyright (c) 2010 Robert Kieffer
 * Dual licensed under the MIT and GPL licenses.
 *
 * EXAMPLES:
 *   >>> Math.uuid()
 *   "92329D39-6F5C-4520-ABFC-AAB64544E172"
 */
JXG.Util.genUUID = function() {
    // Private array of chars to use
    var chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.split(''),
        uuid = new Array(36), rnd=0, r;

    for (var i = 0; i < 36; i++) {
      if (i==8 || i==13 ||  i==18 || i==23) {
        uuid[i] = '-';
      } else if (i==14) {
        uuid[i] = '4';
      } else {
        if (rnd <= 0x02) rnd = 0x2000000 + (Math.random()*0x1000000)|0;
        r = rnd & 0xf;
        rnd = rnd >> 4;
        uuid[i] = chars[(i == 19) ? (r & 0x3) | 0x8 : r];
      }
    }

    return uuid.join('');
};

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
 * @protected
 * @class
 * @classdesc Top-level message object. Contains information from one or more packets
 */

function openpgp_msg_message() {
	
	// -1 = no valid passphrase submitted
	// -2 = no private key found
	// -3 = decryption error
	// text = valid decryption
	this.text = "";
	this.messagePacket = null;
	this.type = null;
	
	/**
	 * Decrypts a message and generates user interface message out of the found.
	 * MDC will be verified as well as message signatures
	 * @param {openpgp_msg_privatekey} private_key the private the message is encrypted with (corresponding to the session key)
	 * @param {openpgp_packet_encryptedsessionkey} sessionkey the session key to be used to decrypt the message
	 * @return {String} plaintext of the message or null on error
	 */
	function decrypt(private_key, sessionkey) {
        return this.decryptAndVerifySignature(private_key, sessionkey).text;
	}

	/**
	 * Decrypts a message and generates user interface message out of the found.
	 * MDC will be verified as well as message signatures
	 * @param {openpgp_msg_privatekey} private_key the private the message is encrypted with (corresponding to the session key)
	 * @param {openpgp_packet_encryptedsessionkey} sessionkey the session key to be used to decrypt the message
	 * @param {openpgp_msg_publickey} pubkey Array of public keys to check signature against. If not provided, checks local keystore.
	 * @return {String} plaintext of the message or null on error
	 */
	function decryptAndVerifySignature(private_key, sessionkey, pubkey) {
		if (private_key == null || sessionkey == null || sessionkey == "")
			return null;
		var decrypted = sessionkey.decrypt(this, private_key.keymaterial);
		if (decrypted == null)
			return null;
		var packet;
		var position = 0;
		var len = decrypted.length;
		var validSignatures = new Array();
		util.print_debug_hexstr_dump("openpgp.msg.messge decrypt:\n",decrypted);
		
		var messages = openpgp.read_messages_dearmored({text: decrypted, openpgp: decrypted});
		for(var m in messages){
			if(messages[m].data){
				this.text = messages[m].data;
			}
			if(messages[m].signature){
			    validSignatures.push(messages[m].verifySignature(pubkey));
			}
		}
		return {text:this.text, validSignatures:validSignatures};
	}
	
	/**
	 * Verifies a message signature. This function can be called after read_message if the message was signed only.
	 * @param {openpgp_msg_publickey} pubkey Array of public keys to check signature against. If not provided, checks local keystore.
	 * @return {boolean} true if the signature was correct; otherwise false
	 */
	function verifySignature(pubkey) {
		var result = false;
		if (this.signature.tagType == 2) {
		    if(!pubkey || pubkey.length == 0){
			    var pubkey;
			    if (this.signature.version == 4) {
				    pubkey = openpgp.keyring.getPublicKeysForKeyId(this.signature.issuerKeyId);
			    } else if (this.signature.version == 3) {
				    pubkey = openpgp.keyring.getPublicKeysForKeyId(this.signature.keyId);
			    } else {
				    util.print_error("unknown signature type on message!");
				    return false;
			    }
			}
			if (pubkey.length == 0)
				util.print_warning("Unable to verify signature of issuer: "+util.hexstrdump(this.signature.issuerKeyId)+". Public key not found in keyring.");
			else {
				for (var i = 0 ; i < pubkey.length; i++) {
					var tohash = this.text.replace(/\r\n/g,"\n").replace(/\n/g,"\r\n");
					if (this.signature.verify(tohash, pubkey[i])) {
						util.print_info("Found Good Signature from "+pubkey[i].obj.userIds[i].text+" (0x"+util.hexstrdump(pubkey[i].obj.getKeyId()).substring(8)+")");
						result = true;
					} else {
						util.print_error("Signature verification failed: Bad Signature from "+pubkey[i].obj.userIds[0].text+" (0x"+util.hexstrdump(pubkey[0].obj.getKeyId()).substring(8)+")");
					}
				}
			}
		}
		return result;
	}
	
	function toString() {
		var result = "Session Keys:\n";
		if (this.sessionKeys !=null)
		for (var i = 0; i < this.sessionKeys.length; i++) {
			result += this.sessionKeys[i].toString();
		}
		result += "\n\n EncryptedData:\n";
		if(this.encryptedData != null)
		result += this.encryptedData.toString();
		
		result += "\n\n Signature:\n";
		if(this.signature != null)
		result += this.signature.toString();
		
		result += "\n\n Text:\n"
		if(this.signature != null)
			result += this.text;
		return result;
	}
	this.decrypt = decrypt;
	this.decryptAndVerifySignature = decryptAndVerifySignature;
	this.verifySignature = verifySignature;
	this.toString = toString;
}
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
function openpgp_type_mpi() {
	this.MPI = null;
	this.mpiBitLength = null;
	this.mpiByteLength = null;
	this.data = null;
	/**
	 * parsing function for a mpi (RFC 4880 3.2).
	 * @param {string} input payload of mpi data
	 * @param {integer} position position to start reading from the input string
	 * @param {integer} len length of the packet or the remaining length of input at position
	 * @return {openpgp_type_mpi} object representation
	 */
	function read(input, position, len) {
		var mypos = position;
		
		this.mpiBitLength = (input[mypos++].charCodeAt() << 8) | input[mypos++].charCodeAt();
		
		// Additional rules:
		//
		//    The size of an MPI is ((MPI.length + 7) / 8) + 2 octets.
		//
		//    The length field of an MPI describes the length starting from its
		//	  most significant non-zero bit.  Thus, the MPI [00 02 01] is not
		//    formed correctly.  It should be [00 01 01].

		// TODO: Verification of this size method! This size calculation as
		// 		 specified above is not applicable in JavaScript
		this.mpiByteLength = (this.mpiBitLength - (this.mpiBitLength % 8)) / 8;
		if (this.mpiBitLength % 8 != 0)
			this.mpiByteLength++;
		
		this.MPI = input.substring(mypos,mypos+this.mpiByteLength);
		this.data = input.substring(position, position+2+this.mpiByteLength);
		this.packetLength = this.mpiByteLength +2;
		return this;
	}
	
	/**
	 * generates debug output (pretty print)
	 * @return {string} String which gives some information about the mpi
	 */
	function toString() {
		var r = "    MPI("+this.mpiBitLength+"b/"+this.mpiByteLength+"B) : 0x";
		r+=util.hexstrdump(this.MPI);
		return r+'\n';
	}
	
	/**
	 * converts the mpi to an BigInteger object
	 * @return {BigInteger}
	 */
	function getBigInteger() {
		return new BigInteger(util.hexstrdump(this.MPI),16); 
	}

	
	function getBits(num) {
		for (var i = 0; i < 9; i++)
		if (num >> i == 0)
		return i;
	}
	
	/**
	 * gets the length of the mpi in bytes
	 * @return {integer} mpi byte length
	 */
	function getByteLength() {
		return this.mpiByteLength;
	}
	
	/**
	 * creates an mpi from the specified string
	 * @param {String} data data to read the mpi from
	 * @return {openpgp_type_mpi} 
	 */
	function create(data) {
		this.MPI = data;
		this.mpiBitLength = (data.length -1) *8 + getBits(data.charCodeAt(0));
		this.mpiByteLength = data.length;
		return this;
	}
	
	/**
	 * converts the mpi object to a string as specified in RFC4880 3.2
	 * @return {String} mpi byte representation
	 */
	function toBin() {
		var result = String.fromCharCode((this.mpiBitLength >> 8) & 0xFF);
		result += String.fromCharCode(this.mpiBitLength & 0xFF);
		result += this.MPI;
		return result;
	}
	
	this.read = read;
	this.toBigInteger = getBigInteger;
	this.toString = toString;
	this.create = create;
	this.toBin = toBin;
	this.getByteLength = getByteLength;
}

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
	/**
	 * parsing method for a key id
	 * @param {String} input input to read the key id from 
	 * @param {integer} position position where to start reading the key id from input
	 * @return this object
	 */
	function read_packet(input, position) {
		this.bytes = input.substring(position, position+8);
		return this;
	}
	
	/**
	 * generates debug output (pretty print)
	 * @return {String} Key Id as hexadecimal string
	 */
	function toString() {
		return util.hexstrdump(this.bytes);
	}
	
	this.read_packet = read_packet;
	this.toString = toString;
};
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
	/**
	 * parsing function for a string-to-key specifier (RFC 4880 3.7).
	 * @param {string} input payload of string-to-key specifier
	 * @param {integer} position position to start reading from the input string
	 * @return {openpgp_type_s2k} object representation
	 */
	function read(input, position) {
		var mypos = position;
		this.type = input[mypos++].charCodeAt();
		switch (this.type) {
		case 0: // Simple S2K
			// Octet 1: hash algorithm
			this.hashAlgorithm = input[mypos++].charCodeAt();
			this.s2kLength = 1;
			break;

		case 1: // Salted S2K
			// Octet 1: hash algorithm
			this.hashAlgorithm = input[mypos++].charCodeAt();

			// Octets 2-9: 8-octet salt value
			this.saltValue = input.substring(mypos, mypos+8);
			mypos += 8;
			this.s2kLength = 9;
			break;

		case 3: // Iterated and Salted S2K
			// Octet 1: hash algorithm
			this.hashAlgorithm = input[mypos++].charCodeAt();

			// Octets 2-9: 8-octet salt value
			this.saltValue = input.substring(mypos, mypos+8);
			mypos += 8;

			// Octet 10: count, a one-octet, coded value
			this.EXPBIAS = 6;
			var c = input[mypos++].charCodeAt();
			this.count = (16 + (c & 15)) << ((c >> 4) + this.EXPBIAS);
			this.s2kLength = 10;
			break;

		case 2: // Reserved value
		default:
			util.print_error("unknown s2k type! "+this.type);
			break;
		}
		return this;
	}
	
	
	/**
	 * writes an s2k hash based on the inputs.
	 * @return {String} produced key of hashAlgorithm hash length
	 */
	function write(type, hash, passphrase, salt, c){
	    this.type = type;
	    if(this.type == 3){this.saltValue = salt;
	        this.hashAlgorithm = hash;
	        this.count = (16 + (c & 15)) << ((c >> 4) + 6);
	        this.s2kLength = 10;
	    }
	    return this.produce_key(passphrase);
	}

	/**
	 * produces a key using the specified passphrase and the defined hashAlgorithm 
	 * @param passphrase {String} passphrase containing user input
	 * @return {String} produced key with a length corresponding to hashAlgorithm hash length
	 */
	function produce_key(passphrase, numBytes) {
		if (this.type == 0) {
			return openpgp_crypto_hashData(this.hashAlgorithm,passphrase);
		} else if (this.type == 1) {
			return openpgp_crypto_hashData(this.hashAlgorithm,this.saltValue+passphrase);
		} else if (this.type == 3) {
			var isp = [];
			isp[0] = this.saltValue+passphrase;
			while (isp.length*(this.saltValue+passphrase).length < this.count)
				isp.push(this.saltValue+passphrase);
			isp = isp.join('');			
			if (isp.length > this.count)
				isp = isp.substr(0, this.count);
			if(numBytes && (numBytes == 24 || numBytes == 32)){ //This if accounts for RFC 4880 3.7.1.1 -- If hash size is greater than block size, use leftmost bits.  If blocksize larger than hash size, we need to rehash isp and prepend with 0.
			    var key = openpgp_crypto_hashData(this.hashAlgorithm,isp);
			    return key + openpgp_crypto_hashData(this.hashAlgorithm,String.fromCharCode(0)+isp);
			}
			return openpgp_crypto_hashData(this.hashAlgorithm,isp);
		} else return null;
	}
	
	this.read = read;
	this.write = write;
	this.produce_key = produce_key;
}
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
 * @classdesc The class that deals with storage of the keyring. Currently the only option is to use HTML5 local storage.
 */
function openpgp_keyring() {
		
	/**
	 * Initialization routine for the keyring. This method reads the 
	 * keyring from HTML5 local storage and initializes this instance.
	 * This method is called by openpgp.init().
	 * @return {null} undefined
	 */
	function init() {
		var sprivatekeys = JSON.parse(window.localStorage.getItem("privatekeys"));
		var spublickeys = JSON.parse(window.localStorage.getItem("publickeys"));
		if (sprivatekeys == null || sprivatekeys.length == 0) {
			sprivatekeys = new Array();
		}

		if (spublickeys == null || spublickeys.length == 0) {
			spublickeys = new Array();
		}
		this.publicKeys = new Array();
		this.privateKeys = new Array();
		var k = 0;
		for (var i =0; i < sprivatekeys.length; i++) {
			var r = openpgp.read_privateKey(sprivatekeys[i]);
			this.privateKeys[k] = { armored: sprivatekeys[i], obj: r[0], keyId: r[0].getKeyId()};
			k++;
		}
		k = 0;
		for (var i =0; i < spublickeys.length; i++) {
			var r = openpgp.read_publicKey(spublickeys[i]);
			if (r[0] != null) {
				this.publicKeys[k] = { armored: spublickeys[i], obj: r[0], keyId: r[0].getKeyId()};
				k++;
			}
		}
	}
	this.init = init;

	/**
	 * Checks if at least one private key is in the keyring
	 * @return {boolean} True if there are private keys, else false.
	 */
	function hasPrivateKey() {
		return this.privateKeys.length > 0;
	}
	this.hasPrivateKey = hasPrivateKey;

	/**
	 * Saves the current state of the keyring to HTML5 local storage.
	 * The privateKeys array and publicKeys array gets Stringified using JSON
	 * @return {null} undefined
	 */
	function store() { 
		var priv = new Array();
		for (var i = 0; i < this.privateKeys.length; i++) {
			priv[i] = this.privateKeys[i].armored;
		}
		var pub = new Array();
		for (var i = 0; i < this.publicKeys.length; i++) {
			pub[i] = this.publicKeys[i].armored;
		}
		window.localStorage.setItem("privatekeys",JSON.stringify(priv));
		window.localStorage.setItem("publickeys",JSON.stringify(pub));
	}
	this.store = store;
	/**
	 * searches all public keys in the keyring matching the address or address part of the user ids
	 * @param email_address
	 * @return {array[openpgp_msg_publickey]} the public keys associated with provided email address.
	 */
	function getPublicKeyForAddress(email_address) {
		var results = new Array();
		var spl = email_address.split("<");
		var email = "";
		if (spl.length > 1) {
			email = spl[1].split(">")[0];
		} else {
			email = email_address.trim();
		}
		email = email.toLowerCase();
		if(!util.emailRegEx.test(email)){
		    return results;
		}
		for (var i =0; i < this.publicKeys.length; i++) {
			for (var j = 0; j < this.publicKeys[i].obj.userIds.length; j++) {
				if (this.publicKeys[i].obj.userIds[j].text.toLowerCase().indexOf(email) >= 0)
					results[results.length] = this.publicKeys[i];
			}
		}
		return results;
	}
	this.getPublicKeyForAddress = getPublicKeyForAddress;

	/**
	 * Searches the keyring for a private key containing the specified email address
	 * @param {String} email_address email address to search for
	 * @return {Array[openpgp_msg_privatekey} private keys found
	 */
	function getPrivateKeyForAddress(email_address) {
		var results = new Array();
		var spl = email_address.split("<");
		var email = "";
		if (spl.length > 1) {
			email = spl[1].split(">")[0];
		} else {
			email = email_address.trim();
		}
		email = email.toLowerCase();
		if(!util.emailRegEx.test(email)){
		    return results;
		}
		for (var i =0; i < this.privateKeys.length; i++) {
			for (var j = 0; j < this.privateKeys[i].obj.userIds.length; j++) {
				if (this.privateKeys[i].obj.userIds[j].text.toLowerCase().indexOf(email) >= 0)
					results[results.length] = this.privateKeys[i];
			}
		}
		return results;
	}

	this.getPrivateKeyForAddress = getPrivateKeyForAddress;
	/**
	 * Searches the keyring for public keys having the specified key id
	 * @param keyId provided as string of hex number (lowercase)
	 * @return {Array[openpgp_msg_privatekey]} public keys found
	 */
	function getPublicKeysForKeyId(keyId) {
		var result = new Array();
		for (var i=0; i < this.publicKeys.length; i++)
			if (keyId == this.publicKeys[i].obj.getKeyId())
				result[result.length] = this.publicKeys[i];
		return result;
	}
	this.getPublicKeysForKeyId = getPublicKeysForKeyId;
	
	/**
	 * Searches the keyring for private keys having the specified key id
	 * @param {String} keyId 8 bytes as string containing the key id to look for
	 * @return {Array[openpgp_msg_privatekey]} private keys found
	 */
	function getPrivateKeyForKeyId(keyId) {
		var result = new Array();
		for (var i=0; i < this.privateKeys.length; i++) {
			if (keyId == this.privateKeys[i].obj.getKeyId()) {
				result[result.length] = { key: this.privateKeys[i], keymaterial: this.privateKeys[i].obj.privateKeyPacket};
			}
			if (this.privateKeys[i].obj.subKeys != null) {
				var subkeyids = this.privateKeys[i].obj.getSubKeyIds();
				for (var j=0; j < subkeyids.length; j++)
					if (keyId == util.hexstrdump(subkeyids[j])) {
						result[result.length] = { key: this.privateKeys[i], keymaterial: this.privateKeys[i].obj.subKeys[j]};
					}
			}
		}
		return result;
	}
	this.getPrivateKeyForKeyId = getPrivateKeyForKeyId;
	
	/**
	 * Imports a public key from an exported ascii armored message 
	 * @param {String} armored_text PUBLIC KEY BLOCK message to read the public key from
	 * @return {null} nothing
	 */
	function importPublicKey (armored_text) {
		var result = openpgp.read_publicKey(armored_text);
		for (var i = 0; i < result.length; i++) {
			this.publicKeys[this.publicKeys.length] = {armored: armored_text, obj: result[i], keyId: result[i].getKeyId()};
		}
		return true;
	}

	/**
	 * Imports a private key from an exported ascii armored message 
	 * @param {String} armored_text PRIVATE KEY BLOCK message to read the private key from
	 * @return {null} nothing
	 */
	function importPrivateKey (armored_text, password) {
		var result = openpgp.read_privateKey(armored_text);
		if(!result[0].decryptSecretMPIs(password))
		    return false;
		for (var i = 0; i < result.length; i++) {
			this.privateKeys[this.privateKeys.length] = {armored: armored_text, obj: result[i], keyId: result[i].getKeyId()};
		}
		return true;
	}

	this.importPublicKey = importPublicKey;
	this.importPrivateKey = importPrivateKey;
	
	/**
	 * returns the openpgp_msg_privatekey representation of the public key at public key ring index  
	 * @param {Integer} index the index of the public key within the publicKeys array
	 * @return {openpgp_msg_privatekey} the public key object
	 */
	function exportPublicKey(index) {
		return this.publicKey[index];
	}
	this.exportPublicKey = exportPublicKey;
		
	
	/**
	 * Removes a public key from the public key keyring at the specified index 
	 * @param {Integer} index the index of the public key within the publicKeys array
	 * @return {openpgp_msg_privatekey} The public key object which has been removed
	 */
	function removePublicKey(index) {
		var removed = this.publicKeys.splice(index,1);
		this.store();
		return removed;
	}
	this.removePublicKey = removePublicKey;

	/**
	 * returns the openpgp_msg_privatekey representation of the private key at private key ring index  
	 * @param {Integer} index the index of the private key within the privateKeys array
	 * @return {openpgp_msg_privatekey} the private key object
	 */	
	function exportPrivateKey(index) {
		return this.privateKeys[index];
	}
	this.exportPrivateKey = exportPrivateKey;

	/**
	 * Removes a private key from the private key keyring at the specified index 
	 * @param {Integer} index the index of the private key within the privateKeys array
	 * @return {openpgp_msg_privatekey} The private key object which has been removed
	 */
	function removePrivateKey(index) {
		var removed = this.privateKeys.splice(index,1);
		this.store();
		return removed;
	}
	this.removePrivateKey = removePrivateKey;

}
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
	 * create hexstring from a binary
	 * @param str [String] string to convert
	 * @return [String] string containing the hexadecimal values
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
	 * create binary string from a hex encoded string
	 * @param str [String] hex string to convert
	 * @return [String] string containing the binary values
	 */
	this.hex2bin = function(hex) {
	    var str = '';
	    for (var i = 0; i < hex.length; i += 2)
	        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
	    return str;
	};
	
	/**
	 * creating a hex string from an binary array of integers (0..255)
	 * @param [Array[integer 0..255]] array to convert
	 * @return [String] hexadecimal representation of the array
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
	 * convert a string to an array of integers(0.255)
	 * @param [String] string to convert
	 * @return [Array [Integer 0..255]] array of (binary) integers
	 */
	this.str2bin = function(str) {
		var result = new Array();
		for (var i = 0; i < str.length; i++) {
			result[i] = str.charCodeAt(i);
		}
		
		return result;
	};

	/**
	 * convert an array of integers(0.255) to a string 
	 * @param [Array [Integer 0..255]] array of (binary) integers to convert
	 * @return [String] string representation of the array
	 */
	this.bin2str = function(bin) {
		var result = [];
		for (var i = 0; i < bin.length; i++) {
			result.push(String.fromCharCode(bin[i]));
		}
		return result.join('');
	};
	
	/**
	 * convert a string to a Uint8Array
	 * @param [String] string to convert
	 * @return [Uint8Array] array of (binary) integers
	 */
	this.str2Uint8Array = function(str){
        var uintArray = new Uint8Array(new ArrayBuffer(str.length));
        for(var n = 0; n < str.length; n++){
            uintArray[n] = str.charCodeAt(n);
        }
        return uintArray;
	};
	
	/**
	 * convert a Uint8Array to a string. This currently functions the same as bin2str. 
	 * @param [Uint8Array] array of (binary) integers to convert
	 * @return [String] string representation of the array
	 */
	this.Uint8Array2str = function(bin) {
        var result = [];
        for(n = 0; n< bin.length; n++){
            result[n] = String.fromCharCode(bin[n]);
        }
        return result.join('');
	};
	
	/**
	 * calculates a 16bit sum of a string by adding each character codes modulus 65535
	 * @param text [String] string to create a sum of
	 * @return [Integer] an integer containing the sum of all character codes % 65535
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
	 * @param str [String] string of the debug message
	 * @return [String] an HTML tt entity containing a paragraph with a style attribute where the debug message is HTMLencoded in. 
	 */
	this.print_debug = function(str) {
		if (openpgp.config.debug) {
			str = openpgp_encoding_html_encode(str);
			showMessages("<tt><p style=\"background-color: #ffffff; width: 652px; word-break: break-word; padding: 5px; border-bottom: 1px solid black;\">"+str.replace(/\n/g,"<br>")+"</p></tt>");
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
	 * @param str [String] string of the debug message
	 * @return [String] an HTML tt entity containing a paragraph with a style attribute where the debug message is HTMLencoded in. 
	 */
	this.print_debug_hexstr_dump = function(str,strToHex) {
		if (openpgp.config.debug) {
			str = str + this.hexstrdump(strToHex);
			str = openpgp_encoding_html_encode(str);
			showMessages("<tt><p style=\"background-color: #ffffff; width: 652px; word-break: break-word; padding: 5px; border-bottom: 1px solid black;\">"+str.replace(/\n/g,"<br>")+"</p></tt>");
		}
	};
	
	/**
	 * Helper function to print an error message. 
	 * The calling Javascript context MUST define
	 * a "showMessages(text)" function. Line feeds ('\n')
	 * are automatically converted to HTML line feeds '<br/>'
	 * @param str [String] string of the error message
	 * @return [String] a HTML paragraph entity with a style attribute containing the HTML encoded error message
	 */
	this.print_error = function(str) {
		str = openpgp_encoding_html_encode(str);
		showMessages("<p style=\"font-size: 80%; background-color: #FF8888; margin:0; width: 652px; word-break: break-word; padding: 5px; border-bottom: 1px solid black;\"><span style=\"color: #888;\"><b>ERROR:</b></span>	"+str.replace(/\n/g,"<br>")+"</p>");
	};
	
	/**
	 * Helper function to print an info message. 
	 * The calling Javascript context MUST define
	 * a "showMessages(text)" function. Line feeds ('\n')
	 * are automatically converted to HTML line feeds '<br/>'.
	 * @param str [String] string of the info message
	 * @return [String] a HTML paragraph entity with a style attribute containing the HTML encoded info message
	 */
	this.print_info = function(str) {
		str = openpgp_encoding_html_encode(str);
		showMessages("<p style=\"font-size: 80%; background-color: #88FF88; margin:0; width: 652px; word-break: break-word; padding: 5px; border-bottom: 1px solid black;\"><span style=\"color: #888;\"><b>INFO:</b></span>	"+str.replace(/\n/g,"<br>")+"</p>");
	};
	
	this.print_warning = function(str) {
		str = openpgp_encoding_html_encode(str);
		showMessages("<p style=\"font-size: 80%; background-color: #FFAA88; margin:0; width: 652px; word-break: break-word; padding: 5px; border-bottom: 1px solid black;\"><span style=\"color: #888;\"><b>WARNING:</b></span>	"+str.replace(/\n/g,"<br>")+"</p>");
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
	 * @param value [String] the string to shift
	 * @param bitcount [Integer] amount of bits to shift (MUST be smaller than 9)
	 * @return [String] resulting string. 
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
	 * @return [String] String representing the message type
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
var util = new Util();
