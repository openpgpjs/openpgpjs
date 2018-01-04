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

// Wrapper for a KeyPair of an Elliptic Curve

/**
 * @requires crypto/hash
 * @requires util
 * @module crypto/public_key/elliptic/key
 */

'use strict';

import hash from '../../hash';
import util from '../../../util';
import enums from '../../../enums';

function KeyPair(curve, options) {
  this.curve = curve;
  this.keyType = curve.curve.type === 'edwards' ? enums.publicKey.eddsa : enums.publicKey.ecdsa;
  this.keyPair = this.curve.keyPair(options);
}

KeyPair.prototype.sign = function (message, hash_algo) {
  if (typeof message === 'string') {
    message = util.str2Uint8Array(message);
  }
  const digest = (typeof hash_algo === 'undefined') ? message : hash.digest(hash_algo, message);
  return this.keyPair.sign(digest);
};

KeyPair.prototype.verify = function (message, signature, hash_algo) {
  if (typeof message === 'string') {
    message = util.str2Uint8Array(message);
  }
  const digest = (typeof hash_algo === 'undefined') ? message : hash.digest(hash_algo, message);
  return this.keyPair.verify(digest, signature);
};

KeyPair.prototype.derive = function (pub) {
  if (this.keyType === enums.publicKey.eddsa) {
    throw new Error('Key can only be used for EdDSA');
  }
  return this.keyPair.derive(pub.keyPair.getPublic()).toArray();
};

KeyPair.prototype.getPublic = function () {
  return this.keyPair.getPublic('array');
};

KeyPair.prototype.getPrivate = function () {
  if (this.keyType === enums.publicKey.eddsa) {
    return this.keyPair.getSecret();
  } else {
    return this.keyPair.getPrivate().toArray();
  }
};

KeyPair.prototype.isValid = function () { // FIXME
  return this.keyPair.validate().result;
};

module.exports = {
  KeyPair: KeyPair
};
