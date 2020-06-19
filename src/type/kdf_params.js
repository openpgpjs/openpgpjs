// OpenPGP.js - An OpenPGP implementation in javascript
// Copyright (C) 2015-2016 Decentral
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

import { UnsupportedError } from '../packet/packet';

/**
 * Implementation of type KDF parameters
 *
 * {@link https://tools.ietf.org/html/rfc6637#section-7|RFC 6637 7}:
 * A key derivation function (KDF) is necessary to implement the EC
 * encryption.  The Concatenation Key Derivation Function (Approved
 * Alternative 1) [NIST-SP800-56A] with the KDF hash function that is
 * SHA2-256 [FIPS-180-3] or stronger is REQUIRED.
 * @module type/kdf_params
 */
import util from '../util';
import enums from '../enums';

class KDFParams {
  /**
   * @param  {Integer}          version                 Version, defaults to 1
   * @param  {enums.hash}       hash                    Hash algorithm
   * @param  {enums.symmetric}  cipher                  Symmetric algorithm
   * @param  {enums.kdfFlags}   flags                   (v2 only) flags
   * @param  {Uint8Array}       replacementFingerprint  (v2 only) fingerprint to use instead of recipient one (v5 keys, the 20 leftmost bytes of the fingerprint)
   * @param  {Uint8Array}       replacementKDFParams    (v2 only) serialized KDF params to use in KDF digest computation
   */
  constructor(data) {
    if (data) {
      const { version, hash, cipher, flags, replacementFingerprint, replacementKDFParams } = data;
      this.version = version || 1;
      this.hash = hash;
      this.cipher = cipher;

      this.flags = flags;
      this.replacementFingerprint = replacementFingerprint;
      this.replacementKDFParams = replacementKDFParams;
    } else {
      this.version = null;
      this.hash = null;
      this.cipher = null;
      this.flags = null;
      this.replacementFingerprint = null;
      this.replacementKDFParams = null;
    }
  }

  /**
   * Read KDFParams from an Uint8Array
   * @param {Uint8Array} input - Where to read the KDFParams from
   * @returns {Number} Number of read bytes.
   */
  read(input) {
    if (input.length < 4 || (input[1] !== 1 && input[1] !== 2)) {
      throw new UnsupportedError('Cannot read KDFParams');
    }
    this.version = input[1];
    this.hash = input[2];
    this.cipher = input[3];
    let readBytes = 4;

    if (this.version === 2) {
      this.flags = input[readBytes++];
      if (this.flags & enums.kdfFlags.replace_fingerprint) {
        this.replacementFingerprint = input.slice(readBytes, readBytes + 20);
        readBytes += 20;
      }
      if (this.flags & enums.kdfFlags.replace_kdf_params) {
        const fieldLength = input[readBytes] + 1; // account for length
        this.replacementKDFParams = input.slice(readBytes, readBytes + fieldLength);
        readBytes += fieldLength;
      }
    }
    return readBytes;
  }

  /**
   * Write KDFParams to an Uint8Array
   * @returns  {Uint8Array}  Array with the KDFParams value
   */
  write() {
    if (!this.version || this.version === 1) {
      return new Uint8Array([3, 1, this.hash, this.cipher]);
    }

    const v2Fields = util.concatUint8Array([
      new Uint8Array([4, 2, this.hash, this.cipher, this.flags]),
      this.replacementFingerprint || new Uint8Array(),
      this.replacementKDFParams || new Uint8Array()
    ]);

    // update length field
    v2Fields[0] = v2Fields.length - 1;
    return new Uint8Array(v2Fields);
  }
}

export default KDFParams;
