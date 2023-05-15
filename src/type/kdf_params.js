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

const VERSION_FORWARDING = 0xFF;

class KDFParams {
  /**
   * @param  {Integer}          version                 Version, defaults to 1
   * @param  {enums.hash}       hash                    Hash algorithm
   * @param  {enums.symmetric}  cipher                  Symmetric algorithm
   * @param  {Uint8Array}       replacementFingerprint  (forwarding only) fingerprint to use instead of recipient one (v5 keys, the 20 leftmost bytes of the fingerprint)
   */
  constructor(data) {
    if (data) {
      const { version, hash, cipher, replacementFingerprint } = data;
      this.version = version || 1;
      this.hash = hash;
      this.cipher = cipher;

      this.replacementFingerprint = replacementFingerprint;
    } else {
      this.version = null;
      this.hash = null;
      this.cipher = null;
      this.replacementFingerprint = null;
    }
  }

  /**
   * Read KDFParams from an Uint8Array
   * @param {Uint8Array} input - Where to read the KDFParams from
   * @returns {Number} Number of read bytes.
   */
  read(input) {
    if (input.length < 4 || (input[1] !== 1 && input[1] !== VERSION_FORWARDING)) {
      throw new UnsupportedError('Cannot read KDFParams');
    }
    const totalBytes = input[0];
    this.version = input[1];
    this.hash = input[2];
    this.cipher = input[3];
    let readBytes = 4;

    if (this.version === VERSION_FORWARDING) {
      const fingerprintLength = totalBytes - readBytes + 1; // acount for length byte
      this.replacementFingerprint = input.slice(readBytes, readBytes + fingerprintLength);
      readBytes += fingerprintLength;
    }
    return readBytes;
  }

  /**
   * Write KDFParams to an Uint8Array
   * @param {Boolean} [forReplacementParams] - forwarding only: whether to serialize data to use for replacement params
   * @returns  {Uint8Array}  Array with the KDFParams value
   */
  write(forReplacementParams) {
    if (!this.version || this.version === 1 || forReplacementParams) {
      return new Uint8Array([3, 1, this.hash, this.cipher]);
    }

    const forwardingFields = util.concatUint8Array([
      new Uint8Array([
        3 + this.replacementFingerprint.length,
        this.version,
        this.hash,
        this.cipher
      ]),
      this.replacementFingerprint
    ]);

    return forwardingFields;
  }
}

export default KDFParams;
