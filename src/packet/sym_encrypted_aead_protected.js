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
 * @requires crypto
 * @requires enums
 * @requires util
 */

import crypto from '../crypto';
import enums from '../enums';
import util from '../util';

const VERSION = 1; // A one-octet version number of the data packet.
const IV_LEN = crypto.gcm.ivLength; // currently only AES-GCM is supported

/**
 * Implementation of the Symmetrically Encrypted Authenticated Encryption with
 * Additional Data (AEAD) Protected Data Packet
 *
 * {@link https://tools.ietf.org/html/draft-ford-openpgp-format-00#section-2.1}:
 * AEAD Protected Data Packet
 * @memberof module:packet
 * @constructor
 */
function SymEncryptedAEADProtected() {
  this.tag = enums.packet.symEncryptedAEADProtected;
  this.version = VERSION;
  this.iv = null;
  this.encrypted = null;
  this.packets = null;
}

export default SymEncryptedAEADProtected;

/**
 * Parse an encrypted payload of bytes in the order: version, IV, ciphertext (see specification)
 */
SymEncryptedAEADProtected.prototype.read = function (bytes) {
  let offset = 0;
  if (bytes[offset] !== VERSION) { // The only currently defined value is 1.
    throw new Error('Invalid packet version.');
  }
  offset++;
  this.iv = bytes.subarray(offset, IV_LEN + offset);
  offset += IV_LEN;
  this.encrypted = bytes.subarray(offset, bytes.length);
};

/**
 * Write the encrypted payload of bytes in the order: version, IV, ciphertext (see specification)
 * @returns {Uint8Array} The encrypted payload
 */
SymEncryptedAEADProtected.prototype.write = function () {
  return util.concatUint8Array([new Uint8Array([this.version]), this.iv, this.encrypted]);
};

/**
 * Decrypt the encrypted payload.
 * @param  {String} sessionKeyAlgorithm   The session key's cipher algorithm e.g. 'aes128'
 * @param  {Uint8Array} key               The session key used to encrypt the payload
 * @returns {Promise<Boolean>}
 * @async
 */
SymEncryptedAEADProtected.prototype.decrypt = async function (sessionKeyAlgorithm, key) {
  this.packets.read(await crypto.gcm.decrypt(sessionKeyAlgorithm, this.encrypted, key, this.iv));
  return true;
};

/**
 * Encrypt the packet list payload.
 * @param  {String} sessionKeyAlgorithm   The session key's cipher algorithm e.g. 'aes128'
 * @param  {Uint8Array} key               The session key used to encrypt the payload
 * @returns {Promise<Boolean>}
 * @async
 */
SymEncryptedAEADProtected.prototype.encrypt = async function (sessionKeyAlgorithm, key) {
  this.iv = await crypto.random.getRandomBytes(IV_LEN); // generate new random IV
  this.encrypted = await crypto.gcm.encrypt(sessionKeyAlgorithm, this.packets.write(), key, this.iv);
  return true;
};
