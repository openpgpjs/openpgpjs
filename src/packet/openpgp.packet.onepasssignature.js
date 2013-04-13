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
	this.type = null; 	 // A one-octet signature type.  Signature types are described in RFC4880 Section 5.2.1.
	this.hashAlgorithm = null; 	   // A one-octet number describing the hash algorithm used. (See RFC4880 9.4)
	this.publicKeyAlgorithm = null;	     // A one-octet number describing the public-key algorithm used. (See RFC4880 9.1)
	this.signingKeyId = null; // An eight-octet number holding the Key ID of the signing key.
	this.flags = null; 	//  A one-octet number holding a flag showing whether the signature is nested.  A zero value indicates that the next packet is another One-Pass Signature packet that describes another signature to be applied to the same message data.

	/**
	 * parsing function for a one-pass signature packet (tag 4).
	 * @param {String} input payload of a tag 4 packet
	 * @param {Integer} position position to start reading from the input string
	 * @param {Integer} len length of the packet or the remaining length of input at position
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
	 * @param {Integer} type Signature types as described in RFC4880 Section 5.2.1.
	 * @param {Integer} hashalgorithm the hash algorithm used within the signature
	 * @param {openpgp_msg_privatekey} privatekey the private key used to generate the signature
	 * @param {Integer} length length of data to be signed
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
	 * @return {String} String which gives some information about the one-pass signature packet
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
