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
import util from '../../../util.js';

function KeyPair(curve, options) {
  this.curve = curve;
  this.keyPair = this.curve.keyPair(options);
}

KeyPair.prototype.sign = function (message, hash_algo) {
  if (typeof message === 'string') {
    message = util.str2Uint8Array(message);
  }
  const digest = (typeof hash_algo === 'undefined') ? message : hash.digest(hash_algo, message);
  const signature = this.keyPair.sign(digest);
  return {
    r: signature.r.toArray(),
    s: signature.s.toArray()
  };
};

KeyPair.prototype.verify = function (message, signature, hash_algo) {
  if (typeof message === 'string') {
    message = util.str2Uint8Array(message);
  }
  const digest = (typeof hash_algo === 'undefined') ? message : hash.digest(hash_algo, message);
  return this.keyPair.verify(digest, signature);
};

KeyPair.prototype.derive = function (pub) {
  return this.keyPair.derive(pub.keyPair.getPublic()).toArray();
};

KeyPair.prototype.getPublic = function () {
  return this.keyPair.getPublic().encode();
};

KeyPair.prototype.getPrivate = function () {
  return this.keyPair.getPrivate().toArray();
};

KeyPair.prototype.isValid = function () {
  return this.keyPair.validate().result;
};

module.exports = {
  KeyPair: KeyPair
};
