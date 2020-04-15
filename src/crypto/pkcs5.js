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
 * @fileoverview Functions to add and remove PKCS5 padding
 * @see module:packet.PublicKeyEncryptedSessionKey
 * @module crypto/pkcs5
 */

/**
 * Add pkcs5 padding to a text.
 * @param  {String}  msg  Text to add padding
 * @returns {String}       Text with padding added
 */
function encode(msg) {
  const c = 8 - (msg.length % 8);
  const padding = String.fromCharCode(c).repeat(c);
  return msg + padding;
}

/**
 * Remove pkcs5 padding from a string.
 * @param  {String}  msg  Text to remove padding from
 * @returns {String}       Text with padding removed
 */
function decode(msg) {
  const len = msg.length;
  if (len > 0) {
    const c = msg.charCodeAt(len - 1);
    if (c >= 1) {
      const provided = msg.substr(len - c);
      const computed = String.fromCharCode(c).repeat(c);
      if (provided === computed) {
        return msg.substr(0, len - c);
      }
    }
  }
  throw new Error('Invalid padding');
}

export default { encode, decode };
