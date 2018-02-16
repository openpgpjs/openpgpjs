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
 * Wrapper to an OID value<br/>
 * <br/>
 * An object identifier type from {@link https://tools.ietf.org/html/rfc6637#section-11|RFC6637, section 11}.
 * @requires util
 * @module type/oid
 */

import util from '../util.js';

module.exports = OID;

/**
 * @constructor
 */
function OID(oid) {
  if (oid instanceof OID) {
    oid = oid.oid;
  } else if (typeof oid === 'undefined') {
    oid = '';
  } else if (util.isArray(oid)) {
    oid = util.bin2str(oid);
  } else if (util.isUint8Array(oid)) {
    oid = util.Uint8Array2str(oid);
  }
  this.oid = oid;
}

/**
 * Method to read an OID object
 * @param  {Uint8Array}  input  Where to read the OID from
 * @return {Number}             Number of read bytes
 */
OID.prototype.read = function (input) {
  if (input.length >= 1) {
    const length = input[0];
    if (input.length >= 1+length) {
      this.oid = util.Uint8Array2str(input.subarray(1, 1+length));
      return 1+this.oid.length;
    }
  }
  throw new Error('Invalid oid');
};

/**
 * Serialize an OID object
 * @return {Uint8Array} Array with the serialized value the OID
 */
OID.prototype.write = function () {
  return util.str2Uint8Array(String.fromCharCode(this.oid.length)+this.oid);
};

/**
 * Serialize an OID object as a hex string
 * @return {string} String with the hex value of the OID
 */
OID.prototype.toHex = function() {
  return util.hexstrdump(this.oid);
};

OID.fromClone = function (clone) {
  const oid = new OID(clone.oid);
  return oid;
};
