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
 * @fileoverview Wrapper for a KeyPair of an curve from indutny/elliptic library
 * @requires enums
 * @requires asn1.js
 * @module crypto/public_key/elliptic/indutnyKey
 */

/**
 * @constructor
 */
function KeyPair(indutnyCurve, options) {
  this.keyPair = indutnyCurve.keyPair(options);
  if (this.keyPair.validate().result !== true) {
    throw new Error('Invalid elliptic public key');
  }
}

export default KeyPair;