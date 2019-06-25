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
 * @fileoverview Wrapper for a KeyPair of an Elliptic Curve
 * @requires enums
 * @requires asn1.js
 * @module crypto/public_key/elliptic/key
 */

import enums from '../../../enums';

/**
 * @constructor
 */
function KeyPair(curve, options) {
  this.curve = curve;
  if (this.curve.name !== 'ed25519') {
    this.keyType = curve.curve.type === 'edwards' ? enums.publicKey.eddsa : enums.publicKey.ecdsa;
    this.keyPair = this.curve.curve.keyPair(options);
  }
}

KeyPair.prototype.derive = function (pub) {
  if (this.keyType === enums.publicKey.eddsa) {
    throw new Error('Key can only be used for EdDSA');
  }
  return this.keyPair.derive(pub.keyPair.getPublic());
};

KeyPair.prototype.getPublic = function () {
  const compact = this.curve.curve.curve.type === 'edwards' ||
        this.curve.curve.curve.type === 'mont';
  return this.keyPair.getPublic('array', compact);
};

KeyPair.prototype.getPrivate = function () {
  if (this.curve.keyType === enums.publicKey.eddsa) {
    return this.keyPair.getSecret();
  }
  return this.keyPair.getPrivate().toArray();
};

export default KeyPair;
