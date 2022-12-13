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

import SymEncryptedIntegrityProtectedDataPacket from './sym_encrypted_integrity_protected_data';
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

const aead = SymEncryptedIntegrityProtectedDataPacket.prototype.aead;

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
      await aead.call(this, 'decrypt', key, stream.clone(this.encrypted)),
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
    this.iv = await crypto.random.getRandomBytes(ivLength); // generate new random IV
    this.chunkSizeByte = config.aeadChunkSizeByte;
    const data = this.packets.write();
    this.encrypted = await aead.call(this, 'encrypt', key, data);
  }
}

export default AEADEncryptedDataPacket;
