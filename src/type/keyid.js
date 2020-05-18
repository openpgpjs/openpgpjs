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

/**
 * @constructor
 */
function Keyid() {
  this.bytes = '';
}

/**
 * Parsing method for a key id
 * @param {Uint8Array} input Input to read the key id from
 */
Keyid.prototype.read = function(bytes) {
  this.bytes = util.Uint8Array_to_str(bytes.subarray(0, 8));
};

/**
 * Serializes the Key ID
 * @returns {Uint8Array} Key ID as a Uint8Array
 */
Keyid.prototype.write = function() {
  return util.str_to_Uint8Array(this.bytes);
};

/**
 * Returns the Key ID represented as a hexadecimal string
 * @returns {String} Key ID as a hexadecimal string
 */
Keyid.prototype.toHex = function() {
  return util.str_to_hex(this.bytes);
};

/**
 * Checks equality of Key ID's
 * @param {Keyid} keyid
 * @param {Boolean} matchWildcard Indicates whether to check if either keyid is a wildcard
 */
Keyid.prototype.equals = function(keyid, matchWildcard = false) {
  return (matchWildcard && (keyid.isWildcard() || this.isWildcard())) || this.bytes === keyid.bytes;
};

/**
 * Checks to see if the Key ID is unset
 * @returns {Boolean} true if the Key ID is null
 */
Keyid.prototype.isNull = function() {
  return this.bytes === '';
};

/**
 * Checks to see if the Key ID is a "wildcard" Key ID (all zeros)
 * @returns {Boolean} true if this is a wildcard Key ID
 */
Keyid.prototype.isWildcard = function() {
  return /^0+$/.test(this.toHex());
};

Keyid.mapToHex = function (keyId) {
  return keyId.toHex();
};

Keyid.fromClone = function (clone) {
  const keyid = new Keyid();
  keyid.bytes = clone.bytes;
  return keyid;
};

Keyid.fromId = function (hex) {
  const keyid = new Keyid();
  keyid.read(util.hex_to_Uint8Array(hex));
  return keyid;
};

Keyid.wildcard = function () {
  const keyid = new Keyid();
  keyid.read(new Uint8Array(8));
  return keyid;
};

export default Keyid;
