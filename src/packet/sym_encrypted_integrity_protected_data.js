// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
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
import HKDF from '../crypto/hkdf';
import enums from '../enums';
import util from '../util';
import defaultConfig from '../config';

import LiteralDataPacket from './literal_data';
import CompressedDataPacket from './compressed_data';
import OnePassSignaturePacket from './one_pass_signature';
import SignaturePacket from './signature';
import PacketList from './packetlist';
import { UnsupportedError } from './packet';

// A SEIP packet can contain the following packet types
const allowedPackets = /*#__PURE__*/ util.constructAllowedPackets([
  LiteralDataPacket,
  CompressedDataPacket,
  OnePassSignaturePacket,
  SignaturePacket
]);

/**
 * Implementation of the Sym. Encrypted Integrity Protected Data Packet (Tag 18)
 *
 * {@link https://tools.ietf.org/html/rfc4880#section-5.13|RFC4880 5.13}:
 * The Symmetrically Encrypted Integrity Protected Data packet is
 * a variant of the Symmetrically Encrypted Data packet. It is a new feature
 * created for OpenPGP that addresses the problem of detecting a modification to
 * encrypted data. It is used in combination with a Modification Detection Code
 * packet.
 */
class SymEncryptedIntegrityProtectedDataPacket {
  static get tag() {
    return enums.packet.symEncryptedIntegrityProtectedData;
  }

  constructor() {
    this.version = 1;

    // The following 4 fields are for V2 only.
    // NOTE: these properties are also used by the AEADEncryptedDataPacket.
    // They need to be kept in sync there if changed. (Except `salt`, it uses `iv` instead.)
    /** @type {enums.symmetric} */
    this.cipherAlgorithm = null;
    /** @type {enums.aead} */
    this.aeadAlgorithm = null;
    this.chunkSizeByte = null;
    this.salt = null;

    this.encrypted = null;
    this.packets = null;
  }

  async read(bytes) {
    await stream.parse(bytes, async reader => {
      this.version = await reader.readByte();
      // - A one-octet version number with value 1 or 2.
      if (this.version !== 1 && this.version !== 2) {
        throw new UnsupportedError(`Version ${version} of the SEIP packet is unsupported.`);
      }

      if (this.version === 2) {
        // - A one-octet cipher algorithm.
        this.cipherAlgorithm = await reader.readByte();
        // - A one-octet AEAD algorithm.
        this.aeadAlgorithm = await reader.readByte();
        // - A one-octet chunk size.
        this.chunkSizeByte = await reader.readByte();
        // - Thirty-two octets of salt. The salt is used to derive the message key and must be unique.
        this.salt = await reader.readBytes(32);
      }

      // For V1:
      // - Encrypted data, the output of the selected symmetric-key cipher
      //   operating in Cipher Feedback mode with shift amount equal to the
      //   block size of the cipher (CFB-n where n is the block size).
      // For V2:
      // - Encrypted data, the output of the selected symmetric-key cipher operating in the given AEAD mode.
      // - A final, summary authentication tag for the AEAD mode.
      this.encrypted = reader.remainder();
    });
  }

  write() {
    if (this.version === 2) {
      return util.concat([new Uint8Array([this.version, this.cipherAlgorithm, this.aeadAlgorithm, this.chunkSizeByte]), this.salt, this.encrypted]);
    }
    return util.concat([new Uint8Array([this.version]), this.encrypted]);
  }

  /**
   * Encrypt the payload in the packet.
   * @param {enums.symmetric} sessionKeyAlgorithm - The symmetric encryption algorithm to use
   * @param {Uint8Array} key - The key of cipher blocksize length to be used
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Boolean>}
   * @throws {Error} on encryption failure
   * @async
   */
  async encrypt(sessionKeyAlgorithm, key, config = defaultConfig) {
    let bytes = this.packets.write();
    if (stream.isArrayStream(bytes)) bytes = await stream.readToEnd(bytes);

    if (this.version === 2) {
      this.cipherAlgorithm = sessionKeyAlgorithm;

      this.salt = await crypto.random.getRandomBytes(32);
      this.chunkSizeByte = config.aeadChunkSizeByte;
      this.encrypted = await this.aead('encrypt', key, bytes);
    } else {
      const { blockSize } = crypto.getCipher(sessionKeyAlgorithm);

      const prefix = await crypto.getPrefixRandom(sessionKeyAlgorithm);
      const mdc = new Uint8Array([0xD3, 0x14]); // modification detection code packet

      const tohash = util.concat([prefix, bytes, mdc]);
      const hash = await crypto.hash.sha1(stream.passiveClone(tohash));
      const plaintext = util.concat([tohash, hash]);

      this.encrypted = await crypto.mode.cfb.encrypt(sessionKeyAlgorithm, key, plaintext, new Uint8Array(blockSize), config);
    }
    return true;
  }

  /**
   * Decrypts the encrypted data contained in the packet.
   * @param {enums.symmetric} sessionKeyAlgorithm - The selected symmetric encryption algorithm to be used
   * @param {Uint8Array} key - The key of cipher blocksize length to be used
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Boolean>}
   * @throws {Error} on decryption failure
   * @async
   */
  async decrypt(sessionKeyAlgorithm, key, config = defaultConfig) {
    let encrypted = stream.clone(this.encrypted);
    if (stream.isArrayStream(encrypted)) encrypted = await stream.readToEnd(encrypted);

    let packetbytes;
    if (this.version === 2) {
      packetbytes = await this.aead('decrypt', key, encrypted);
    } else {
      const { blockSize } = crypto.getCipher(sessionKeyAlgorithm);
      const decrypted = await crypto.mode.cfb.decrypt(sessionKeyAlgorithm, key, encrypted, new Uint8Array(blockSize));

      // there must be a modification detection code packet as the
      // last packet and everything gets hashed except the hash itself
      const realHash = stream.slice(stream.passiveClone(decrypted), -20);
      const tohash = stream.slice(decrypted, 0, -20);
      const verifyHash = Promise.all([
        stream.readToEnd(await crypto.hash.sha1(stream.passiveClone(tohash))),
        stream.readToEnd(realHash)
      ]).then(([hash, mdc]) => {
        if (!util.equalsUint8Array(hash, mdc)) {
          throw new Error('Modification detected.');
        }
        return new Uint8Array();
      });
      const bytes = stream.slice(tohash, blockSize + 2); // Remove random prefix
      packetbytes = stream.slice(bytes, 0, -2); // Remove MDC packet
      packetbytes = stream.concat([packetbytes, stream.fromAsync(() => verifyHash)]);
      if (!util.isStream(encrypted) || !config.allowUnauthenticatedStream) {
        packetbytes = await stream.readToEnd(packetbytes);
      }
    }

    this.packets = await PacketList.fromBinary(packetbytes, allowedPackets, config);
    return true;
  }

  /**
   * En/decrypt the payload.
   * NOTE: this function is also used by the AEADEncryptedDataPacket.
   * @param {encrypt|decrypt} fn - Whether to encrypt or decrypt
   * @param {Uint8Array} key - The session key used to en/decrypt the payload
   * @param {Uint8Array | ReadableStream<Uint8Array>} data - The data to en/decrypt
   * @returns {Promise<Uint8Array | ReadableStream<Uint8Array>>}
   * @async
   */
  async aead(fn, key, data) {
    const mode = crypto.getAEADMode(this.aeadAlgorithm);
    const tagLengthIfDecrypting = fn === 'decrypt' ? mode.tagLength : 0;
    const tagLengthIfEncrypting = fn === 'encrypt' ? mode.tagLength : 0;
    const chunkSize = 2 ** (this.chunkSizeByte + 6) + tagLengthIfDecrypting; // ((uint64_t)1 << (c + 6))
    const chunkIndexSizeIfAEADEP = this.constructor === SymEncryptedIntegrityProtectedDataPacket ? 0 : 8;
    const adataBuffer = new ArrayBuffer(13 + chunkIndexSizeIfAEADEP);
    const adataArray = new Uint8Array(adataBuffer, 0, 5 + chunkIndexSizeIfAEADEP);
    const adataTagArray = new Uint8Array(adataBuffer);
    const adataView = new DataView(adataBuffer);
    const chunkIndexArray = new Uint8Array(adataBuffer, 5, 8);
    adataArray.set([0xC0 | this.constructor.tag, this.version, this.cipherAlgorithm, this.aeadAlgorithm, this.chunkSizeByte], 0);
    let chunkIndex = 0;
    let latestPromise = Promise.resolve();
    let cryptedBytes = 0;
    let queuedBytes = 0;
    let iv;
    let ivView;
    if (this.constructor === SymEncryptedIntegrityProtectedDataPacket) { // SEIPD V2
      const { keySize } = crypto.getCipher(this.cipherAlgorithm);
      const { ivLength } = crypto.getAEADMode(this.aeadAlgorithm);
      const info = new Uint8Array(adataBuffer, 0, 5);
      const derived = await HKDF(key, this.salt, info, keySize + ivLength);
      key = derived.subarray(0, keySize);
      iv = derived.subarray(keySize); // The last 8 bytes of HKDF output are unneeded, but this avoids one copy.
      iv.fill(0, iv.length - 8);
      ivView = new DataView(iv.buffer, iv.byteOffset, iv.byteLength);
    } else { // AEADEncryptedDataPacket
      iv = this.iv;
      // ivView is unused in this case
    }
    const modeInstance = await mode(this.cipherAlgorithm, key);
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
          let nonce;
          if (this.constructor === SymEncryptedIntegrityProtectedDataPacket) { // SEIPD V2
            nonce = iv;
          } else { // AEADEncryptedDataPacket
            nonce = iv.slice();
            for (let i = 0; i < 8; i++) {
              nonce[iv.length - 8 + i] ^= chunkIndexArray[i];
            }
          }
          if (!chunkIndex || chunk.length) {
            reader.unshift(finalChunk);
            cryptedPromise = modeInstance[fn](chunk, nonce, adataArray);
            queuedBytes += chunk.length - tagLengthIfDecrypting + tagLengthIfEncrypting;
          } else {
            // After the last chunk, we either encrypt a final, empty
            // data chunk to get the final authentication tag or
            // validate that final authentication tag.
            adataView.setInt32(5 + chunkIndexSizeIfAEADEP + 4, cryptedBytes); // Should be setInt64(5 + chunkIndexSizeIfAEADEP, ...)
            cryptedPromise = modeInstance[fn](finalChunk, nonce, adataTagArray);
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
            if (this.constructor === SymEncryptedIntegrityProtectedDataPacket) { // SEIPD V2
              ivView.setInt32(iv.length - 4, ++chunkIndex); // Should be setInt64(iv.length - 8, ...)
            } else { // AEADEncryptedDataPacket
              adataView.setInt32(5 + 4, ++chunkIndex); // Should be setInt64(5, ...)
            }
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

export default SymEncryptedIntegrityProtectedDataPacket;
