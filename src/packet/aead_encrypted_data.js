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

import * as stream from '@openpgp/web-stream-tools';
import crypto from '../crypto';
import enums from '../enums';
import util from '../util';
import defaultConfig from '../config';
import { UnsupportedError } from './packet';

import LiteralDataPacket from './literal_data';
import CompressedDataPacket from './compressed_data';
import OnePassSignaturePacket from './one_pass_signature';
import SignaturePacket from './signature';
import PacketList from './packetlist';

// An AEAD-encrypted Data packet can contain the following packet types
const allowedPackets = /*#__PURE__*/ util.constructAllowedPackets([
  LiteralDataPacket,
  CompressedDataPacket,
  OnePassSignaturePacket,
  SignaturePacket
]);

const VERSION = 1; // A one-octet version number of the data packet.

/**
 * Implementation of the Symmetrically Encrypted Authenticated Encryption with
 * Additional Data (AEAD) Protected Data Packet
 *
 * {@link https://tools.ietf.org/html/draft-ford-openpgp-format-00#section-2.1}:
 * AEAD Protected Data Packet
 */
class AEADEncryptedDataPacket {
  static get tag() {
    return enums.packet.aeadEncryptedData;
  }

  constructor() {
    this.version = VERSION;
    /** @type {enums.symmetric} */
    this.cipherAlgorithm = null;
    /** @type {enums.aead} */
    this.aeadAlgorithm = enums.aead.eax;
    this.chunkSizeByte = null;
    this.iv = null;
    this.encrypted = null;
    this.packets = null;
  }

  /**
   * Parse an encrypted payload of bytes in the order: version, IV, ciphertext (see specification)
   * @param {Uint8Array | ReadableStream<Uint8Array>} bytes
   * @throws {Error} on parsing failure
   */
  async read(bytes) {
    await stream.parse(bytes, async reader => {
      const version = await reader.readByte();
      if (version !== VERSION) { // The only currently defined value is 1.
        throw new UnsupportedError(`Version ${version} of the AEAD-encrypted data packet is not supported.`);
      }
      this.cipherAlgorithm = await reader.readByte();
      this.aeadAlgorithm = await reader.readByte();
      this.chunkSizeByte = await reader.readByte();

      const mode = crypto.getAEADMode(this.aeadAlgorithm);
      this.iv = await reader.readBytes(mode.ivLength);
      this.encrypted = reader.remainder();
    });
  }

  /**
   * Write the encrypted payload of bytes in the order: version, IV, ciphertext (see specification)
   * @returns {Uint8Array | ReadableStream<Uint8Array>} The encrypted payload.
   */
  write() {
    return util.concat([new Uint8Array([this.version, this.cipherAlgorithm, this.aeadAlgorithm, this.chunkSizeByte]), this.iv, this.encrypted]);
  }

  /**
   * Decrypt the encrypted payload.
   * @param {enums.symmetric} sessionKeyAlgorithm - The session key's cipher algorithm
   * @param {Uint8Array} key - The session key used to encrypt the payload
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @throws {Error} if decryption was not successful
   * @async
   */
  async decrypt(sessionKeyAlgorithm, key, config = defaultConfig) {
    this.packets = await PacketList.fromBinary(
      await this.crypt('decrypt', key, stream.clone(this.encrypted)),
      allowedPackets,
      config
    );
  }

  /**
   * Encrypt the packet payload.
   * @param {enums.symmetric} sessionKeyAlgorithm - The session key's cipher algorithm
   * @param {Uint8Array} key - The session key used to encrypt the payload
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @throws {Error} if encryption was not successful
   * @async
   */
  async encrypt(sessionKeyAlgorithm, key, config = defaultConfig) {
    this.cipherAlgorithm = sessionKeyAlgorithm;

    const { ivLength } = crypto.getAEADMode(this.aeadAlgorithm);
    this.iv = crypto.random.getRandomBytes(ivLength); // generate new random IV
    this.chunkSizeByte = config.aeadChunkSizeByte;
    const data = this.packets.write();
    this.encrypted = await this.crypt('encrypt', key, data);
  }

  /**
   * En/decrypt the payload.
   * @param {encrypt|decrypt} fn - Whether to encrypt or decrypt
   * @param {Uint8Array} key - The session key used to en/decrypt the payload
   * @param {Uint8Array | ReadableStream<Uint8Array>} data - The data to en/decrypt
   * @returns {Promise<Uint8Array | ReadableStream<Uint8Array>>}
   * @async
   */
  async crypt(fn, key, data) {
    const mode = crypto.getAEADMode(this.aeadAlgorithm);
    const modeInstance = await mode(this.cipherAlgorithm, key);
    const tagLengthIfDecrypting = fn === 'decrypt' ? mode.tagLength : 0;
    const tagLengthIfEncrypting = fn === 'encrypt' ? mode.tagLength : 0;
    const chunkSize = 2 ** (this.chunkSizeByte + 6) + tagLengthIfDecrypting; // ((uint64_t)1 << (c + 6))
    const adataBuffer = new ArrayBuffer(21);
    const adataArray = new Uint8Array(adataBuffer, 0, 13);
    const adataTagArray = new Uint8Array(adataBuffer);
    const adataView = new DataView(adataBuffer);
    const chunkIndexArray = new Uint8Array(adataBuffer, 5, 8);
    adataArray.set([0xC0 | AEADEncryptedDataPacket.tag, this.version, this.cipherAlgorithm, this.aeadAlgorithm, this.chunkSizeByte], 0);
    let chunkIndex = 0;
    let latestPromise = Promise.resolve();
    let cryptedBytes = 0;
    let queuedBytes = 0;
    const iv = this.iv;
    return stream.transformPair(data, async (readable, writable) => {
      if (util.isStream(readable) !== 'array') {
        const buffer = new stream.TransformStream({}, {
          highWaterMark: util.getHardwareConcurrency() * 2 ** (this.chunkSizeByte + 6),
          size: array => array.length
        });
        stream.pipe(buffer.readable, writable);
        writable = buffer.writable;
      }
      const reader = stream.getReader(readable);
      const writer = stream.getWriter(writable);
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
  }
}

export default AEADEncryptedDataPacket;
