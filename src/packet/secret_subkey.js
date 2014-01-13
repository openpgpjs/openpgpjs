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

/**
 * @requires packet/secret_key
 * @requires enums
 * @module packet/secret_subkey
 */

module.exports = SecretSubkey;

var secretKey = require('./secret_key.js'),
  enums = require('../enums.js');

/**
 * @constructor
 * @extends module:packet/secret_key
 */
function SecretSubkey() {
  secretKey.call(this);
  this.tag = enums.packet.secretSubkey;
}

SecretSubkey.prototype = new secretKey();
SecretSubkey.prototype.constructor = SecretSubkey;
