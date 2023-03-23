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

/**
 * Encoded symmetric key for ECDH (incl. legacy x25519)
 *
 * @module type/ecdh_symkey
 * @private
 */

import util from '../util';

class ECDHSymmetricKey {
  constructor(data) {
    if (data) {
      this.data = data;
    }
  }

  /**
   * Read an ECDHSymmetricKey from an Uint8Array:
   * - 1 octect for the length `l`
   * - `l` octects of encoded session key data
   * @param {Uint8Array} bytes
   * @returns {Number} Number of read bytes.
   */
  read(bytes) {
    if (bytes.length >= 1) {
      const length = bytes[0];
      if (bytes.length >= 1 + length) {
        this.data = bytes.subarray(1, 1 + length);
        return 1 + this.data.length;
      }
    }
    throw new Error('Invalid symmetric key');
  }

  /**
   * Write an ECDHSymmetricKey as an Uint8Array
   * @returns  {Uint8Array} Serialised data
   */
  write() {
    return util.concatUint8Array([new Uint8Array([this.data.length]), this.data]);
  }
}

export default ECDHSymmetricKey;
