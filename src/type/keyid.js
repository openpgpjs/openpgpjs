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
 * @module type/keyid
 * @private
 */

import util from '../util';

/**
 * Implementation of type key id
 *
 * {@link https://tools.ietf.org/html/rfc4880#section-3.3|RFC4880 3.3}:
 * A Key ID is an eight-octet scalar that identifies a key.
 * Implementations SHOULD NOT assume that Key IDs are unique.  The
 * section "Enhanced Key Formats" below describes how Key IDs are
 * formed.
 */
class KeyID {
  constructor() {
    this.bytes = '';
  }

  /**
   * Parsing method for a key id
   * @param {Uint8Array} bytes - Input to read the key id from
   */
  read(bytes) {
    this.bytes = util.uint8ArrayToString(bytes.subarray(0, 8));
    return this.bytes.length;
  }

  /**
   * Serializes the Key ID
   * @returns {Uint8Array} Key ID as a Uint8Array.
   */
  write() {
    return util.stringToUint8Array(this.bytes);
  }

  /**
   * Returns the Key ID represented as a hexadecimal string
   * @returns {String} Key ID as a hexadecimal string.
   */
  toHex() {
    return util.uint8ArrayToHex(util.stringToUint8Array(this.bytes));
  }

  /**
   * Checks equality of Key ID's
   * @param {KeyID} keyID
   * @param {Boolean} matchWildcard - Indicates whether to check if either keyID is a wildcard
   */
  equals(keyID, matchWildcard = false) {
    return (matchWildcard && (keyID.isWildcard() || this.isWildcard())) || this.bytes === keyID.bytes;
  }

  /**
   * Checks to see if the Key ID is unset
   * @returns {Boolean} True if the Key ID is null.
   */
  isNull() {
    return this.bytes === '';
  }

  /**
   * Checks to see if the Key ID is a "wildcard" Key ID (all zeros)
   * @returns {Boolean} True if this is a wildcard Key ID.
   */
  isWildcard() {
    return /^0+$/.test(this.toHex());
  }

  static mapToHex(keyID) {
    return keyID.toHex();
  }

  static fromID(hex) {
    const keyID = new KeyID();
    keyID.read(util.hexToUint8Array(hex));
    return keyID;
  }

  static wildcard() {
    const keyID = new KeyID();
    keyID.read(new Uint8Array(8));
    return keyID;
  }
}

export default KeyID;
