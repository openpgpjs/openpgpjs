// OpenPGP.js - An OpenPGP implementation in javascript
// Copyright (C) 2016 Tankred Hase
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
 * Implementation of the Symmetrically Encrypted AEAD Protected Data Packet <br/>
 * <br/>
 * {@link https://tools.ietf.org/html/draft-ford-openpgp-format-00#section-2.1}: AEAD Protected Data Packet
 */

'use strict';

import util from '../util.js';
import crypto from '../crypto';
import enums from '../enums.js';

const IV_LEN = crypto.gcm.ivLength;

/**
 * @constructor
 */
export default function SymEncryptedAEADProtected() {
  this.tag = enums.packet.symEncryptedAEADProtected;
  this.iv = null;
  this.encrypted = null;
  /** Decrypted packets contained within.
   * @type {module:packet/packetlist} */
  this.packets =  null;
}

SymEncryptedAEADProtected.prototype.read = function (bytes) {
  this.iv = bytes.subarray(0, IV_LEN);
  this.encrypted = bytes.subarray(IV_LEN, bytes.length);
};

SymEncryptedAEADProtected.prototype.write = function () {
  return util.concatUint8Array([this.iv, this.encrypted]);
};

SymEncryptedAEADProtected.prototype.decrypt = function (sessionKeyAlgorithm, key) {
  return crypto.gcm.decrypt(sessionKeyAlgorithm, this.encrypted, key, this.iv).then(decrypted => {
    this.packets.read(decrypted);
  });
};

SymEncryptedAEADProtected.prototype.encrypt = function (sessionKeyAlgorithm, key) {
  var data = this.packets.write();
  this.iv = crypto.random.getRandomValues(new Uint8Array(IV_LEN));

  return crypto.gcm.encrypt(sessionKeyAlgorithm, data, key, this.iv).then(encrypted => {
    this.encrypted = encrypted;
  });
};
