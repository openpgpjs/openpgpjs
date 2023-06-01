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

import * as stream from '@openpgp/web-stream-tools';
import SignaturePacket, { saltLengthForHash } from './signature';
import KeyID from '../type/keyid';
import enums from '../enums';
import util from '../util';
import { UnsupportedError } from './packet';

/**
 * Implementation of the One-Pass Signature Packets (Tag 4)
 *
 * {@link https://tools.ietf.org/html/rfc4880#section-5.4|RFC4880 5.4}:
 * The One-Pass Signature packet precedes the signed data and contains
 * enough information to allow the receiver to begin calculating any
 * hashes needed to verify the signature.  It allows the Signature
 * packet to be placed at the end of the message, so that the signer
 * can compute the entire signed message in one pass.
 */
class OnePassSignaturePacket {
  static get tag() {
    return enums.packet.onePassSignature;
  }

  static fromSignaturePacket(signaturePacket, isLast) {
    const onePassSig = new OnePassSignaturePacket();
    onePassSig.version = signaturePacket.version === 6 ? 6 : 3;
    onePassSig.signatureType = signaturePacket.signatureType;
    onePassSig.hashAlgorithm = signaturePacket.hashAlgorithm;
    onePassSig.publicKeyAlgorithm = signaturePacket.publicKeyAlgorithm;
    onePassSig.issuerKeyID = signaturePacket.issuerKeyID;
    onePassSig.salt = signaturePacket.salt; // v6 only
    onePassSig.issuerFingerprint = signaturePacket.issuerFingerprint; // v6 only

    onePassSig.flags = isLast ? 1 : 0;
    return onePassSig;
  }

  constructor() {
    /** A one-octet version number.  The current versions are 3 and 6. */
    this.version = null;
    /**
     * A one-octet signature type.
     * Signature types are described in
     * {@link https://tools.ietf.org/html/rfc4880#section-5.2.1|RFC4880 Section 5.2.1}.
     * @type {enums.signature}

     */
    this.signatureType = null;
    /**
     * A one-octet number describing the hash algorithm used.
     * @see {@link https://tools.ietf.org/html/rfc4880#section-9.4|RFC4880 9.4}
     * @type {enums.hash}
     */
    this.hashAlgorithm = null;
    /**
     * A one-octet number describing the public-key algorithm used.
     * @see {@link https://tools.ietf.org/html/rfc4880#section-9.1|RFC4880 9.1}
     * @type {enums.publicKey}
     */
    this.publicKeyAlgorithm = null;
    /** Only for v6, a variable-length field containing the salt. */
    this.salt = null;
    /** Only for v3 packets, an eight-octet number holding the Key ID of the signing key. */
    this.issuerKeyID = null;
    /** Only for v6 packets, 32 octets of the fingerprint of the signing key. */
    this.issuerFingerprint = null;
    /**
     * A one-octet number holding a flag showing whether the signature is nested.
     * A zero value indicates that the next packet is another One-Pass Signature packet
     * that describes another signature to be applied to the same message data.
     */
    this.flags = null;
  }

  /**
   * parsing function for a one-pass signature packet (tag 4).
   * @param {Uint8Array} bytes - Payload of a tag 4 packet
   * @returns {OnePassSignaturePacket} Object representation.
   */
  read(bytes) {
    let mypos = 0;
    // A one-octet version number.  The current versions are 3 or 6.
    this.version = bytes[mypos++];
    if (this.version !== 3 && this.version !== 6) {
      throw new UnsupportedError(`Version ${this.version} of the one-pass signature packet is unsupported.`);
    }

    // A one-octet signature type.  Signature types are described in
    //   Section 5.2.1.
    this.signatureType = bytes[mypos++];

    // A one-octet number describing the hash algorithm used.
    this.hashAlgorithm = bytes[mypos++];

    // A one-octet number describing the public-key algorithm used.
    this.publicKeyAlgorithm = bytes[mypos++];

    if (this.version === 6) {
      // Only for v6 signatures, a variable-length field containing:

      // A one-octet salt size. The value MUST match the value defined
      // for the hash algorithm as specified in Table 23 (Hash algorithm registry).
      const saltLength = bytes[mypos++];
      if (saltLength !== saltLengthForHash(this.hashAlgorithm)) {
        throw new Error('Unexpected salt size for the hash algorithm');
      }

      // The salt; a random value value of the specified size.
      this.salt = bytes.subarray(mypos, mypos + saltLength);
      mypos += saltLength;

      // Only for v6 packets, 32 octets of the fingerprint of the signing key.
      this.issuerFingerprint = bytes.subarray(mypos, mypos + 32);
      mypos += 32;
      this.issuerKeyID = new KeyID();
      // For v6 the Key ID is the high-order 64 bits of the fingerprint.
      this.issuerKeyID.read(this.issuerFingerprint);
    } else {
      // Only for v3 packets, an eight-octet number holding the Key ID of the signing key.
      this.issuerKeyID = new KeyID();
      this.issuerKeyID.read(bytes.subarray(mypos, mypos + 8));
      mypos += 8;
    }

    // A one-octet number holding a flag showing whether the signature
    //   is nested.  A zero value indicates that the next packet is
    //   another One-Pass Signature packet that describes another
    //   signature to be applied to the same message data.
    this.flags = bytes[mypos++];
    return this;
  }

  /**
   * creates a string representation of a one-pass signature packet
   * @returns {Uint8Array} A Uint8Array representation of a one-pass signature packet.
   */
  write() {
    const arr = [new Uint8Array([
      this.version,
      this.signatureType,
      this.hashAlgorithm,
      this.publicKeyAlgorithm
    ])];
    if (this.version === 6) {
      arr.push(
        new Uint8Array([this.salt.length]),
        this.salt,
        this.issuerFingerprint
      );
    } else {
      arr.push(this.issuerKeyID.write());
    }
    arr.push(new Uint8Array([this.flags]));
    return util.concatUint8Array(arr);
  }

  calculateTrailer(...args) {
    return stream.fromAsync(async () => SignaturePacket.prototype.calculateTrailer.apply(await this.correspondingSig, args));
  }

  async verify() {
    const correspondingSig = await this.correspondingSig;
    if (!correspondingSig || correspondingSig.constructor.tag !== enums.packet.signature) {
      throw new Error('Corresponding signature packet missing');
    }
    if (
      correspondingSig.signatureType !== this.signatureType ||
      correspondingSig.hashAlgorithm !== this.hashAlgorithm ||
      correspondingSig.publicKeyAlgorithm !== this.publicKeyAlgorithm ||
      !correspondingSig.issuerKeyID.equals(this.issuerKeyID) ||
      (this.version === 3 && correspondingSig.version === 6) ||
      (this.version === 6 && correspondingSig.version !== 6) ||
      (this.version === 6 && !util.equalsUint8Array(correspondingSig.issuerFingerprint, this.issuerFingerprint)) ||
      (this.version === 6 && !util.equalsUint8Array(correspondingSig.salt, this.salt))
    ) {
      throw new Error('Corresponding signature packet does not match one-pass signature packet');
    }
    correspondingSig.hashed = this.hashed;
    return correspondingSig.verify.apply(correspondingSig, arguments);
  }
}

OnePassSignaturePacket.prototype.hash = SignaturePacket.prototype.hash;
OnePassSignaturePacket.prototype.toHash = SignaturePacket.prototype.toHash;
OnePassSignaturePacket.prototype.toSign = SignaturePacket.prototype.toSign;

export default OnePassSignaturePacket;
