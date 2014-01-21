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
 * Implementation of the One-Pass Signature Packets (Tag 4)<br/>
 * <br/>
 * {@link http://tools.ietf.org/html/rfc4880#section-5.4|RFC4880 5.4}: The One-Pass Signature packet precedes the signed data and contains
 * enough information to allow the receiver to begin calculating any
 * hashes needed to verify the signature.  It allows the Signature
 * packet to be placed at the end of the message, so that the signer
 * can compute the entire signed message in one pass.
 * @requires enums
 * @requires type/keyid
 * @module packet/one_pass_signature
*/

module.exports = OnePassSignature;

var enums = require('../enums.js'),
  type_keyid = require('../type/keyid.js');

/**
 * @constructor
 */
function OnePassSignature() {
  this.tag = enums.packet.onePassSignature; // The packet type
  this.version = null; // A one-octet version number.  The current version is 3.
  this.type = null; // A one-octet signature type.  Signature types are described in {@link http://tools.ietf.org/html/rfc4880#section-5.2.1|RFC4880 Section 5.2.1}.
  this.hashAlgorithm = null; // A one-octet number describing the hash algorithm used. (See {@link http://tools.ietf.org/html/rfc4880#section-9.4|RFC4880 9.4})
  this.publicKeyAlgorithm = null; // A one-octet number describing the public-key algorithm used. (See {@link http://tools.ietf.org/html/rfc4880#section-9.1|RFC4880 9.1})
  this.signingKeyId = null; // An eight-octet number holding the Key ID of the signing key.
  this.flags = null; //  A one-octet number holding a flag showing whether the signature is nested.  A zero value indicates that the next packet is another One-Pass Signature packet that describes another signature to be applied to the same message data.
}

/**
 * parsing function for a one-pass signature packet (tag 4).
 * @param {String} bytes payload of a tag 4 packet
 * @return {module:packet/one_pass_signature} object representation
 */
OnePassSignature.prototype.read = function (bytes) {
  var mypos = 0;
  // A one-octet version number.  The current version is 3.
  this.version = bytes.charCodeAt(mypos++);

  // A one-octet signature type.  Signature types are described in
  //   Section 5.2.1.
  this.type = enums.read(enums.signature, bytes.charCodeAt(mypos++));

  // A one-octet number describing the hash algorithm used.
  this.hashAlgorithm = enums.read(enums.hash, bytes.charCodeAt(mypos++));

  // A one-octet number describing the public-key algorithm used.
  this.publicKeyAlgorithm = enums.read(enums.publicKey, bytes.charCodeAt(mypos++));

  // An eight-octet number holding the Key ID of the signing key.
  this.signingKeyId = new type_keyid();
  this.signingKeyId.read(bytes.substr(mypos));
  mypos += 8;

  // A one-octet number holding a flag showing whether the signature
  //   is nested.  A zero value indicates that the next packet is
  //   another One-Pass Signature packet that describes another
  //   signature to be applied to the same message data.
  this.flags = bytes.charCodeAt(mypos++);
  return this;
};

/**
 * creates a string representation of a one-pass signature packet
 * @return {String} a string representation of a one-pass signature packet
 */
OnePassSignature.prototype.write = function () {
  var result = "";

  result += String.fromCharCode(3);
  result += String.fromCharCode(enums.write(enums.signature, this.type));
  result += String.fromCharCode(enums.write(enums.hash, this.hashAlgorithm));
  result += String.fromCharCode(enums.write(enums.publicKey, this.publicKeyAlgorithm));
  result += this.signingKeyId.write();
  result += String.fromCharCode(this.flags);

  return result;
};

/**
 * Fix custom types after cloning
 */
OnePassSignature.prototype.postCloneTypeFix = function() {
  this.signingKeyId = type_keyid.fromClone(this.signingKeyId);
};
