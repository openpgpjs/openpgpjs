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
 * @requires packet/public_key
 * @requires enums
 * @module packet/public_subkey
 */

import publicKey from './public_key.js';
import enums from '../enums.js';

/**
 * @constructor
 * @extends module:packet/public_key
 */
export default function PublicSubkey() {
  publicKey.call(this);
  this.tag = enums.packet.publicSubkey;
}

PublicSubkey.prototype = new publicKey();
PublicSubkey.prototype.constructor = PublicSubkey;
