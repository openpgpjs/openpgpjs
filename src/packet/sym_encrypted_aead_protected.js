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
 * @requires config
 * @requires crypto
 * @requires enums
 * @requires util
 */

import config from '../config';
import crypto from '../crypto';
import enums from '../enums';
import util from '../util';

const VERSION = 1; // A one-octet version number of the data packet.

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
  this.cipherAlgo = null;
  this.aeadAlgorithm = 'eax';
  this.aeadAlgo = null;
  this.chunkSizeByte = null;
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
  if (config.aead_protect_version === 4) {
    this.cipherAlgo = bytes[offset++];
    this.aeadAlgo = bytes[offset++];
    this.chunkSizeByte = bytes[offset++];
  } else {
    this.aeadAlgo = enums.aead.gcm;
  }
  const mode = crypto[enums.read(enums.aead, this.aeadAlgo)];
  this.iv = bytes.subarray(offset, mode.ivLength + offset);
  offset += mode.ivLength;
  this.encrypted = bytes.subarray(offset, bytes.length);
};

/**
 * Write the encrypted payload of bytes in the order: version, IV, ciphertext (see specification)
 * @returns {Uint8Array} The encrypted payload
 */
SymEncryptedAEADProtected.prototype.write = function () {
  if (config.aead_protect_version === 4) {
    return util.concatUint8Array([new Uint8Array([this.version, this.cipherAlgo, this.aeadAlgo, this.chunkSizeByte]), this.iv, this.encrypted]);
  }
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
  const mode = crypto[enums.read(enums.aead, this.aeadAlgo)];
  if (config.aead_protect_version === 4) {
    const cipher = enums.read(enums.symmetric, this.cipherAlgo);
    let data = this.encrypted.subarray(0, this.encrypted.length - mode.blockLength);
    const authTag = this.encrypted.subarray(this.encrypted.length - mode.blockLength);
    const chunkSize = 2 ** (this.chunkSizeByte + 6); // ((uint64_t)1 << (c + 6))
    const adataBuffer = new ArrayBuffer(21);
    const adataArray = new Uint8Array(adataBuffer, 0, 13);
    const adataTagArray = new Uint8Array(adataBuffer);
    const adataView = new DataView(adataBuffer);
    const chunkIndexArray = new Uint8Array(adataBuffer, 5, 8);
    adataArray.set([0xC0 | this.tag, this.version, this.cipherAlgo, this.aeadAlgo, this.chunkSizeByte], 0);
    adataView.setInt32(13 + 4, data.length - mode.blockLength); // Should be setInt64(13, ...)
    const decryptedPromises = [];
    const modeInstance = new mode(cipher, key);
    for (let chunkIndex = 0; chunkIndex === 0 || data.length;) {
      decryptedPromises.push(
        modeInstance.decrypt(data.subarray(0, chunkSize), mode.getNonce(this.iv, chunkIndexArray), adataArray)
      );
      data = data.subarray(chunkSize);
      adataView.setInt32(5 + 4, ++chunkIndex); // Should be setInt64(5, ...)
    }
    decryptedPromises.push(
      modeInstance.decrypt(authTag, mode.getNonce(this.iv, chunkIndexArray), adataTagArray)
    );
    this.packets.read(util.concatUint8Array(await Promise.all(decryptedPromises)));
  } else {
    this.packets.read(await mode.decrypt(sessionKeyAlgorithm, this.encrypted, key, this.iv));
  }
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
  this.aeadAlgo = config.aead_protect_version === 4 ? enums.write(enums.aead, this.aeadAlgorithm) : enums.aead.gcm;
  const mode = crypto[enums.read(enums.aead, this.aeadAlgo)];
  this.iv = await crypto.random.getRandomBytes(mode.ivLength); // generate new random IV
  let data = this.packets.write();
  if (config.aead_protect_version === 4) {
    this.cipherAlgo = enums.write(enums.symmetric, sessionKeyAlgorithm);
    this.chunkSizeByte = config.aead_chunk_size_byte;
    const chunkSize = 2 ** (this.chunkSizeByte + 6); // ((uint64_t)1 << (c + 6))
    const adataBuffer = new ArrayBuffer(21);
    const adataArray = new Uint8Array(adataBuffer, 0, 13);
    const adataTagArray = new Uint8Array(adataBuffer);
    const adataView = new DataView(adataBuffer);
    const chunkIndexArray = new Uint8Array(adataBuffer, 5, 8);
    adataArray.set([0xC0 | this.tag, this.version, this.cipherAlgo, this.aeadAlgo, this.chunkSizeByte], 0);
    adataView.setInt32(13 + 4, data.length); // Should be setInt64(13, ...)
    const encryptedPromises = [];
    const modeInstance = new mode(sessionKeyAlgorithm, key);
    for (let chunkIndex = 0; chunkIndex === 0 || data.length;) {
      encryptedPromises.push(
        modeInstance.encrypt(data.subarray(0, chunkSize), mode.getNonce(this.iv, chunkIndexArray), adataArray)
      );
      // We take a chunk of data, encrypt it, and shift `data` to the
      // next chunk. After the final chunk, we encrypt a final, empty
      // data chunk to get the final authentication tag.
      data = data.subarray(chunkSize);
      adataView.setInt32(5 + 4, ++chunkIndex); // Should be setInt64(5, ...)
    }
    encryptedPromises.push(
      modeInstance.encrypt(data, mode.getNonce(this.iv, chunkIndexArray), adataTagArray)
    );
    this.encrypted = util.concatUint8Array(await Promise.all(encryptedPromises));
  } else {
    this.encrypted = await mode.encrypt(sessionKeyAlgorithm, data, key, this.iv);
  }
  return true;
};
