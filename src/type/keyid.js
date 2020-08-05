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
 * Implementation of type key id
 *
 * {@link https://tools.ietf.org/html/rfc4880#section-3.3|RFC4880 3.3}:
 * A Key ID is an eight-octet scalar that identifies a key.
 * Implementations SHOULD NOT assume that Key IDs are unique.  The
 * section "Enhanced Key Formats" below describes how Key IDs are
 * formed.
 * @requires util
 * @module type/keyid
 */

import util from '../util.js';

class Keyid {
  constructor() {
    this.bytes = '';
  }

  /**
   * Parsing method for a key id
   * @param {Uint8Array} bytes Input to read the key id from
   */
  read(bytes) {
    this.bytes = util.uint8ArrayToStr(bytes.subarray(0, 8));
  }

  /**
   * Serializes the Key ID
   * @returns {Uint8Array} Key ID as a Uint8Array
   */
  write() {
    return util.strToUint8Array(this.bytes);
  }

  /**
   * Returns the Key ID represented as a hexadecimal string
   * @returns {String} Key ID as a hexadecimal string
   */
  toHex() {
    return util.strToHex(this.bytes);
  }

  /**
   * Checks equality of Key ID's
   * @param {Keyid} keyid
   * @param {Boolean} matchWildcard Indicates whether to check if either keyid is a wildcard
   */
  equals(keyid, matchWildcard = false) {
    return (matchWildcard && (keyid.isWildcard() || this.isWildcard())) || this.bytes === keyid.bytes;
  }

  /**
   * Checks to see if the Key ID is unset
   * @returns {Boolean} true if the Key ID is null
   */
  isNull() {
    return this.bytes === '';
  }

  /**
   * Checks to see if the Key ID is a "wildcard" Key ID (all zeros)
   * @returns {Boolean} true if this is a wildcard Key ID
   */
  isWildcard() {
    return /^0+$/.test(this.toHex());
  }

  static mapToHex(keyId) {
    return keyId.toHex();
  }

  static fromId(hex) {
    const keyid = new Keyid();
    keyid.read(util.hexToUint8Array(hex));
    return keyid;
  }

  static wildcard() {
    const keyid = new Keyid();
    keyid.read(new Uint8Array(8));
    return keyid;
  }
}

export default Keyid;
