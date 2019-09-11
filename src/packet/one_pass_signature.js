// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
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
 * @requires web-stream-tools
 * @requires packet/signature
 * @requires type/keyid
 * @requires enums
 * @requires util
 */

import stream from 'web-stream-tools';
import Signature from './signature';
import type_keyid from '../type/keyid';
import enums from '../enums';
import util from '../util';

/**
 * Implementation of the One-Pass Signature Packets (Tag 4)
 *
 * {@link https://tools.ietf.org/html/rfc4880#section-5.4|RFC4880 5.4}:
 * The One-Pass Signature packet precedes the signed data and contains
 * enough information to allow the receiver to begin calculating any
 * hashes needed to verify the signature.  It allows the Signature
 * packet to be placed at the end of the message, so that the signer
 * can compute the entire signed message in one pass.
 * @memberof module:packet
 * @constructor
 */
function OnePassSignature() {
  /**
   * Packet type
   * @type {module:enums.packet}
   */
  this.tag = enums.packet.onePassSignature;
  /** A one-octet version number.  The current version is 3. */
  this.version = null;
  /**
   * A one-octet signature type.
   * Signature types are described in
   * {@link https://tools.ietf.org/html/rfc4880#section-5.2.1|RFC4880 Section 5.2.1}.
   */
  this.signatureType = null;
  /**
   * A one-octet number describing the hash algorithm used.
   * @see {@link https://tools.ietf.org/html/rfc4880#section-9.4|RFC4880 9.4}
   */
  this.hashAlgorithm = null;
  /**
   * A one-octet number describing the public-key algorithm used.
   * @see {@link https://tools.ietf.org/html/rfc4880#section-9.1|RFC4880 9.1}
   */
  this.publicKeyAlgorithm = null;
  /** An eight-octet number holding the Key ID of the signing key. */
  this.issuerKeyId = null;
  /**
   * A one-octet number holding a flag showing whether the signature is nested.
   * A zero value indicates that the next packet is another One-Pass Signature packet
   * that describes another signature to be applied to the same message data.
   */
  this.flags = null;
}

/**
 * parsing function for a one-pass signature packet (tag 4).
 * @param {Uint8Array} bytes payload of a tag 4 packet
 * @returns {module:packet.OnePassSignature} object representation
 */
OnePassSignature.prototype.read = function (bytes) {
  let mypos = 0;
  // A one-octet version number.  The current version is 3.
  this.version = bytes[mypos++];

  // A one-octet signature type.  Signature types are described in
  //   Section 5.2.1.
  this.signatureType = bytes[mypos++];

  // A one-octet number describing the hash algorithm used.
  this.hashAlgorithm = bytes[mypos++];

  // A one-octet number describing the public-key algorithm used.
  this.publicKeyAlgorithm = bytes[mypos++];

  // An eight-octet number holding the Key ID of the signing key.
  this.issuerKeyId = new type_keyid();
  this.issuerKeyId.read(bytes.subarray(mypos, mypos + 8));
  mypos += 8;

  // A one-octet number holding a flag showing whether the signature
  //   is nested.  A zero value indicates that the next packet is
  //   another One-Pass Signature packet that describes another
  //   signature to be applied to the same message data.
  this.flags = bytes[mypos++];
  return this;
};

/**
 * creates a string representation of a one-pass signature packet
 * @returns {Uint8Array} a Uint8Array representation of a one-pass signature packet
 */
OnePassSignature.prototype.write = function () {
  const start = new Uint8Array([3, enums.write(enums.signature, this.signatureType),
    enums.write(enums.hash, this.hashAlgorithm),
    enums.write(enums.publicKey, this.publicKeyAlgorithm)]);

  const end = new Uint8Array([this.flags]);

  return util.concatUint8Array([start, this.issuerKeyId.write(), end]);
};

/**
 * Fix custom types after cloning
 */
OnePassSignature.prototype.postCloneTypeFix = function() {
  this.issuerKeyId = type_keyid.fromClone(this.issuerKeyId);
};

OnePassSignature.prototype.hash = Signature.prototype.hash;
OnePassSignature.prototype.toHash = Signature.prototype.toHash;
OnePassSignature.prototype.toSign = Signature.prototype.toSign;
OnePassSignature.prototype.calculateTrailer = function(...args) {
  return stream.fromAsync(async () => Signature.prototype.calculateTrailer.apply(await this.correspondingSig, args));
};

OnePassSignature.prototype.verify = async function() {
  const correspondingSig = await this.correspondingSig;
  if (!correspondingSig || correspondingSig.tag !== enums.packet.signature) {
    throw new Error('Corresponding signature packet missing');
  }
  if (
    correspondingSig.signatureType !== this.signatureType ||
    correspondingSig.hashAlgorithm !== this.hashAlgorithm ||
    correspondingSig.publicKeyAlgorithm !== this.publicKeyAlgorithm ||
    !correspondingSig.issuerKeyId.equals(this.issuerKeyId)
  ) {
    throw new Error('Corresponding signature packet does not match one-pass signature packet');
  }
  correspondingSig.hashed = this.hashed;
  return correspondingSig.verify.apply(correspondingSig, arguments);
};

export default OnePassSignature;
