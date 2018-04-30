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
    this.aeadAlgo = enums.aead.experimental_gcm;
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
    const data = this.encrypted.subarray(0, -mode.tagLength);
    const authTag = this.encrypted.subarray(-mode.tagLength);
    this.packets.read(await this.crypt('decrypt', key, data, authTag));
  } else {
    this.cipherAlgo = enums.write(enums.symmetric, sessionKeyAlgorithm);
    this.packets.read(await this.crypt('decrypt', key, this.encrypted));
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
  this.cipherAlgo = enums.write(enums.symmetric, sessionKeyAlgorithm);
  this.aeadAlgo = config.aead_protect_version === 4 ? enums.write(enums.aead, this.aeadAlgorithm) : enums.aead.experimental_gcm;
  const mode = crypto[enums.read(enums.aead, this.aeadAlgo)];
  this.iv = await crypto.random.getRandomBytes(mode.ivLength); // generate new random IV
  this.chunkSizeByte = config.aead_chunk_size_byte;
  const data = this.packets.write();
  this.encrypted = await this.crypt('encrypt', key, data, data.subarray(0, 0));
};

/**
 * En/decrypt the payload.
 * @param  {encrypt|decrypt} fn      Whether to encrypt or decrypt
 * @param  {Uint8Array} key          The session key used to en/decrypt the payload
 * @param  {Uint8Array} data         The data to en/decrypt
 * @param  {Uint8Array} finalChunk   For encryption: empty final chunk; for decryption: final authentication tag
 * @returns {Promise<Uint8Array>}
 * @async
 */
SymEncryptedAEADProtected.prototype.crypt = async function (fn, key, data, finalChunk) {
  const cipher = enums.read(enums.symmetric, this.cipherAlgo);
  const mode = crypto[enums.read(enums.aead, this.aeadAlgo)];
  const modeInstance = await mode(cipher, key);
  if (config.aead_protect_version === 4) {
    const tagLengthIfDecrypting = fn === 'decrypt' ? mode.tagLength : 0;
    const chunkSize = 2 ** (this.chunkSizeByte + 6) + tagLengthIfDecrypting; // ((uint64_t)1 << (c + 6))
    const adataBuffer = new ArrayBuffer(21);
    const adataArray = new Uint8Array(adataBuffer, 0, 13);
    const adataTagArray = new Uint8Array(adataBuffer);
    const adataView = new DataView(adataBuffer);
    const chunkIndexArray = new Uint8Array(adataBuffer, 5, 8);
    adataArray.set([0xC0 | this.tag, this.version, this.cipherAlgo, this.aeadAlgo, this.chunkSizeByte], 0);
    adataView.setInt32(13 + 4, data.length - tagLengthIfDecrypting * Math.ceil(data.length / chunkSize)); // Should be setInt64(13, ...)
    const cryptedPromises = [];
    for (let chunkIndex = 0; chunkIndex === 0 || data.length;) {
      cryptedPromises.push(
        modeInstance[fn](data.subarray(0, chunkSize), mode.getNonce(this.iv, chunkIndexArray), adataArray)
      );
      // We take a chunk of data, en/decrypt it, and shift `data` to the
      // next chunk.
      data = data.subarray(chunkSize);
      adataView.setInt32(5 + 4, ++chunkIndex); // Should be setInt64(5, ...)
    }
    // After the final chunk, we either encrypt a final, empty data
    // chunk to get the final authentication tag or validate that final
    // authentication tag.
    cryptedPromises.push(
      modeInstance[fn](finalChunk, mode.getNonce(this.iv, chunkIndexArray), adataTagArray)
    );
    return util.concatUint8Array(await Promise.all(cryptedPromises));
  } else {
    return modeInstance[fn](data, this.iv);
  }
};
