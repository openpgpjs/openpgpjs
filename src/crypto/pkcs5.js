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

import util from '../util';

/**
 * @fileoverview Functions to add and remove PKCS5 padding
 * @see PublicKeyEncryptedSessionKeyPacket
 * @module crypto/pkcs5
 */

/**
 * Add pkcs5 padding to a message
 * @param  {Uint8Array}  message  message to pad
 * @returns {Uint8Array}  padded message
 */
function encode(message) {
  const c = 8 - (message.length % 8);
  const padded = new Uint8Array(message.length + c).fill(c);
  padded.set(message);
  return padded;
}

/**
 * Remove pkcs5 padding from a message
 * @param  {Uint8Array}  message  message to remove padding from
 * @returns {Uint8Array} message without padding
 */
function decode(message) {
  const len = message.length;
  if (len > 0) {
    const c = message[len - 1];
    if (c >= 1) {
      const provided = message.subarray(len - c);
      const computed = new Uint8Array(c).fill(c);
      if (util.equalsUint8Array(provided, computed)) {
        return message.subarray(0, len - c);
      }
    }
  }
  throw new Error('Invalid padding');
}

export default { encode, decode };
