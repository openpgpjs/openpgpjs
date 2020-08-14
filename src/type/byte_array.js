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
 * Wrapper for Uint8Array
 *
 * @requires util
 * @module type/byte_array.js
 */

import util from '../util';

class ByteArray {
  constructor(data) {
    if (typeof data === 'undefined') {
      data = new Uint8Array([]);
    } else if (util.isString(data)) {
      data = util.strToUint8Array(data);
    } else {
      data = new Uint8Array(data);
    }
    this.data = data;
  }

  /**
   * Exposes the length of the underlying data
   * @returns {number}
   */
  get length() {
    return this.data.length;
  }

  /**
   * Read from an Uint8Array
   * @param  {Uint8Array}  input  Where to read the symmetric key from
   */
  read(input) {
    if (input.length >= 1) {
      const length = input[0];
      if (input.length >= 1 + length) {
        this.data = input.subarray(1, 1 + length);
        return 1 + this.data.length;
      }
    }
    throw new Error('Invalid symmetric key');
  }

  /**
   * Write as an Uint8Array
   * @returns  {Uint8Array}  An array containing the value
   */
  write() {
    return util.concatUint8Array([new Uint8Array([this.data.length]), this.data]);
  }
}

export default ByteArray;
