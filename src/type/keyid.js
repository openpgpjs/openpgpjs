// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

var util = require('../util');

/**
 * @class
 * @classdesc Implementation of type key id (RFC4880 3.3)
 *  A Key ID is an eight-octet scalar that identifies a key.
   Implementations SHOULD NOT assume that Key IDs are unique.  The
   section "Enhanced Key Formats" below describes how Key IDs are
   formed.
 */
module.exports = function keyid() {

  this.bytes = '';

  for (var i = 0; i < 8; i++) {
    this.bytes += String.fromCharCode(0);
  }
  /**
   * Parsing method for a key id
   * @param {String} input Input to read the key id from 
   * @param {integer} position Position where to start reading the key 
   * id from input
   * @return {openpgp_type_keyid} This object
   */
  this.read = function(bytes) {
    this.bytes = bytes.substr(0, 8);
  }

  this.write = function() {
    return this.bytes;
  }

  this.toHex = function() {
    return util.hexstrdump(this.bytes);
  }

  this.equals = function(keyid) {
    return this.bytes == keyid.bytes;
  }
};
