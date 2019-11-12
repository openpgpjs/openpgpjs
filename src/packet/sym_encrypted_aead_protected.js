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
 * @requires web-stream-tools
 * @requires config
 * @requires crypto
 * @requires enums
 * @requires util
 */

import stream from 'web-stream-tools';
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
 * @param {Uint8Array | ReadableStream<Uint8Array>} bytes
 */
SymEncryptedAEADProtected.prototype.read = async function (bytes) {
  await stream.parse(bytes, async reader => {
    if (await reader.readByte() !== VERSION) { // The only currently defined value is 1.
      throw new Error('Invalid packet version.');
    }
    this.cipherAlgo = await reader.readByte();
    this.aeadAlgo = await reader.readByte();
    this.chunkSizeByte = await reader.readByte();
    const mode = crypto[enums.read(enums.aead, this.aeadAlgo)];
    this.iv = await reader.readBytes(mode.ivLength);
    this.encrypted = reader.remainder();
  });
};

/**
 * Write the encrypted payload of bytes in the order: version, IV, ciphertext (see specification)
 * @returns {Uint8Array | ReadableStream<Uint8Array>} The encrypted payload
 */
SymEncryptedAEADProtected.prototype.write = function () {
  return util.concat([new Uint8Array([this.version, this.cipherAlgo, this.aeadAlgo, this.chunkSizeByte]), this.iv, this.encrypted]);
};

/**
 * Decrypt the encrypted payload.
 * @param  {String} sessionKeyAlgorithm   The session key's cipher algorithm e.g. 'aes128'
 * @param  {Uint8Array} key               The session key used to encrypt the payload
 * @param  {Boolean} streaming            Whether the top-level function will return a stream
 * @returns {Boolean}
 * @async
 */
SymEncryptedAEADProtected.prototype.decrypt = async function (sessionKeyAlgorithm, key, streaming) {
  await this.packets.read(await this.crypt('decrypt', key, stream.clone(this.encrypted), streaming), streaming);
  return true;
};

/**
 * Encrypt the packet list payload.
 * @param  {String} sessionKeyAlgorithm   The session key's cipher algorithm e.g. 'aes128'
 * @param  {Uint8Array} key               The session key used to encrypt the payload
 * @param  {Boolean} streaming            Whether the top-level function will return a stream
 * @async
 */
SymEncryptedAEADProtected.prototype.encrypt = async function (sessionKeyAlgorithm, key, streaming) {
  this.cipherAlgo = enums.write(enums.symmetric, sessionKeyAlgorithm);
  this.aeadAlgo = enums.write(enums.aead, this.aeadAlgorithm);
  const mode = crypto[enums.read(enums.aead, this.aeadAlgo)];
  this.iv = await crypto.random.getRandomBytes(mode.ivLength); // generate new random IV
  this.chunkSizeByte = config.aead_chunk_size_byte;
  const data = this.packets.write();
  this.encrypted = await this.crypt('encrypt', key, data, streaming);
};

/**
 * En/decrypt the payload.
 * @param  {encrypt|decrypt} fn      Whether to encrypt or decrypt
 * @param  {Uint8Array} key          The session key used to en/decrypt the payload
 * @param  {Uint8Array | ReadableStream<Uint8Array>} data         The data to en/decrypt
 * @param  {Boolean} streaming        Whether the top-level function will return a stream
 * @returns {Uint8Array | ReadableStream<Uint8Array>}
 * @async
 */
SymEncryptedAEADProtected.prototype.crypt = async function (fn, key, data, streaming) {
  const cipher = enums.read(enums.symmetric, this.cipherAlgo);
  const mode = crypto[enums.read(enums.aead, this.aeadAlgo)];
  const modeInstance = await mode(cipher, key);
  const tagLengthIfDecrypting = fn === 'decrypt' ? mode.tagLength : 0;
  const tagLengthIfEncrypting = fn === 'encrypt' ? mode.tagLength : 0;
  const chunkSize = 2 ** (this.chunkSizeByte + 6) + tagLengthIfDecrypting; // ((uint64_t)1 << (c + 6))
  const adataBuffer = new ArrayBuffer(21);
  const adataArray = new Uint8Array(adataBuffer, 0, 13);
  const adataTagArray = new Uint8Array(adataBuffer);
  const adataView = new DataView(adataBuffer);
  const chunkIndexArray = new Uint8Array(adataBuffer, 5, 8);
  adataArray.set([0xC0 | this.tag, this.version, this.cipherAlgo, this.aeadAlgo, this.chunkSizeByte], 0);
  let chunkIndex = 0;
  let latestPromise = Promise.resolve();
  let cryptedBytes = 0;
  let queuedBytes = 0;
  const iv = this.iv;
  return stream.transformPair(data, async (readable, writable) => {
    const reader = stream.getReader(readable);
    const buffer = new TransformStream({}, {
      highWaterMark: streaming ? util.getHardwareConcurrency() * 2 ** (this.chunkSizeByte + 6) : Infinity,
      size: array => array.length
    });
    stream.pipe(buffer.readable, writable);
    const writer = stream.getWriter(buffer.writable);
    try {
      while (true) {
        let chunk = await reader.readBytes(chunkSize + tagLengthIfDecrypting) || new Uint8Array();
        const finalChunk = chunk.subarray(chunk.length - tagLengthIfDecrypting);
        chunk = chunk.subarray(0, chunk.length - tagLengthIfDecrypting);
        let cryptedPromise;
        let done;
        if (!chunkIndex || chunk.length) {
          reader.unshift(finalChunk);
          cryptedPromise = modeInstance[fn](chunk, mode.getNonce(iv, chunkIndexArray), adataArray);
          queuedBytes += chunk.length - tagLengthIfDecrypting + tagLengthIfEncrypting;
        } else {
          // After the last chunk, we either encrypt a final, empty
          // data chunk to get the final authentication tag or
          // validate that final authentication tag.
          adataView.setInt32(13 + 4, cryptedBytes); // Should be setInt64(13, ...)
          cryptedPromise = modeInstance[fn](finalChunk, mode.getNonce(iv, chunkIndexArray), adataTagArray);
          queuedBytes += tagLengthIfEncrypting;
          done = true;
        }
        cryptedBytes += chunk.length - tagLengthIfDecrypting;
        // eslint-disable-next-line no-loop-func
        latestPromise = latestPromise.then(() => cryptedPromise).then(async crypted => {
          await writer.ready;
          await writer.write(crypted);
          queuedBytes -= crypted.length;
        }).catch(err => writer.abort(err));
        if (done || queuedBytes > writer.desiredSize) {
          await latestPromise; // Respect backpressure
        }
        if (!done) {
          adataView.setInt32(5 + 4, ++chunkIndex); // Should be setInt64(5, ...)
        } else {
          await writer.close();
          break;
        }
      }
    } catch (e) {
      await writer.abort(e);
    }
  });
};
