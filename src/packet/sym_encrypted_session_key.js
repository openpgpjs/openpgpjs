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

import { newS2KFromConfig, newS2KFromType } from '../type/s2k';
import defaultConfig from '../config';
import crypto from '../crypto';
import computeHKDF from '../crypto/hkdf';
import enums from '../enums';
import util from '../util';
import { UnsupportedError } from './packet';

/**
 * Symmetric-Key Encrypted Session Key Packets (Tag 3)
 *
 * {@link https://tools.ietf.org/html/rfc4880#section-5.3|RFC4880 5.3}:
 * The Symmetric-Key Encrypted Session Key packet holds the
 * symmetric-key encryption of a session key used to encrypt a message.
 * Zero or more Public-Key Encrypted Session Key packets and/or
 * Symmetric-Key Encrypted Session Key packets may precede a
 * Symmetrically Encrypted Data packet that holds an encrypted message.
 * The message is encrypted with a session key, and the session key is
 * itself encrypted and stored in the Encrypted Session Key packet or
 * the Symmetric-Key Encrypted Session Key packet.
 */
class SymEncryptedSessionKeyPacket {
  static get tag() {
    return enums.packet.symEncryptedSessionKey;
  }

  /**
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   */
  constructor(config = defaultConfig) {
    this.version = config.aeadProtect ? 6 : 4;
    this.sessionKey = null;
    /**
     * Algorithm to encrypt the session key with
     * @type {enums.symmetric}
     */
    this.sessionKeyEncryptionAlgorithm = null;
    /**
     * Algorithm to encrypt the message with
     * @type {enums.symmetric}
     */
    this.sessionKeyAlgorithm = enums.symmetric.aes256;
    /**
     * AEAD mode to encrypt the session key with (if AEAD protection is enabled)
     * @type {enums.aead}
     */
    this.aeadAlgorithm = enums.write(enums.aead, config.preferredAEADAlgorithm);
    this.encrypted = null;
    this.s2k = null;
    this.iv = null;
  }

  /**
   * Parsing function for a symmetric encrypted session key packet (tag 3).
   *
   * @param {Uint8Array} bytes - Payload of a tag 3 packet
   */
  read(bytes) {
    let offset = 0;

    // A one-octet version number with value 4, 5 or 6.
    this.version = bytes[offset++];
    if (this.version !== 4 && this.version !== 5 && this.version !== 6) {
      throw new UnsupportedError(`Version ${this.version} of the SKESK packet is unsupported.`);
    }

    if (this.version === 6) {
      // A one-octet scalar octet count of the following 5 fields.
      offset++;
    }

    // A one-octet number describing the symmetric algorithm used.
    const algo = bytes[offset++];

    if (this.version >= 5) {
      // A one-octet AEAD algorithm.
      this.aeadAlgorithm = bytes[offset++];

      if (this.version === 6) {
        // A one-octet scalar octet count of the following field.
        offset++;
      }
    }

    // A string-to-key (S2K) specifier, length as defined above.
    const s2kType = bytes[offset++];
    this.s2k = newS2KFromType(s2kType);
    offset += this.s2k.read(bytes.subarray(offset, bytes.length));

    if (this.version >= 5) {
      const mode = crypto.getAEADMode(this.aeadAlgorithm);

      // A starting initialization vector of size specified by the AEAD
      // algorithm.
      this.iv = bytes.subarray(offset, offset += mode.ivLength);
    }

    // The encrypted session key itself, which is decrypted with the
    // string-to-key object. This is optional in version 4.
    if (this.version >= 5 || offset < bytes.length) {
      this.encrypted = bytes.subarray(offset, bytes.length);
      this.sessionKeyEncryptionAlgorithm = algo;
    } else {
      this.sessionKeyAlgorithm = algo;
    }
  }

  /**
   * Create a binary representation of a tag 3 packet
   *
   * @returns {Uint8Array} The Uint8Array representation.
  */
  write() {
    const algo = this.encrypted === null ?
      this.sessionKeyAlgorithm :
      this.sessionKeyEncryptionAlgorithm;

    let bytes;

    const s2k = this.s2k.write();
    if (this.version === 6) {
      const s2kLen = s2k.length;
      const fieldsLen = 3 + s2kLen + this.iv.length;
      bytes = util.concatUint8Array([new Uint8Array([this.version, fieldsLen, algo, this.aeadAlgorithm, s2kLen]), s2k, this.iv, this.encrypted]);
    } else if (this.version === 5) {
      bytes = util.concatUint8Array([new Uint8Array([this.version, algo, this.aeadAlgorithm]), s2k, this.iv, this.encrypted]);
    } else {
      bytes = util.concatUint8Array([new Uint8Array([this.version, algo]), s2k]);

      if (this.encrypted !== null) {
        bytes = util.concatUint8Array([bytes, this.encrypted]);
      }
    }

    return bytes;
  }

  /**
   * Decrypts the session key with the given passphrase
   * @param {String} passphrase - The passphrase in string form
   * @throws {Error} if decryption was not successful
   * @async
   */
  async decrypt(passphrase) {
    const algo = this.sessionKeyEncryptionAlgorithm !== null ?
      this.sessionKeyEncryptionAlgorithm :
      this.sessionKeyAlgorithm;

    const { blockSize, keySize } = crypto.getCipher(algo);
    const key = await this.s2k.produceKey(passphrase, keySize);

    if (this.version >= 5) {
      const mode = crypto.getAEADMode(this.aeadAlgorithm);
      const adata = new Uint8Array([0xC0 | SymEncryptedSessionKeyPacket.tag, this.version, this.sessionKeyEncryptionAlgorithm, this.aeadAlgorithm]);
      const encryptionKey = this.version === 6 ? await computeHKDF(enums.hash.sha256, key, new Uint8Array(), adata, keySize) : key;
      const modeInstance = await mode(algo, encryptionKey);
      this.sessionKey = await modeInstance.decrypt(this.encrypted, this.iv, adata);
    } else if (this.encrypted !== null) {
      const decrypted = await crypto.mode.cfb.decrypt(algo, key, this.encrypted, new Uint8Array(blockSize));

      this.sessionKeyAlgorithm = enums.write(enums.symmetric, decrypted[0]);
      this.sessionKey = decrypted.subarray(1, decrypted.length);
    } else {
      this.sessionKey = key;
    }
  }

  /**
   * Encrypts the session key with the given passphrase
   * @param {String} passphrase - The passphrase in string form
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @throws {Error} if encryption was not successful
   * @async
   */
  async encrypt(passphrase, config = defaultConfig) {
    const algo = this.sessionKeyEncryptionAlgorithm !== null ?
      this.sessionKeyEncryptionAlgorithm :
      this.sessionKeyAlgorithm;

    this.sessionKeyEncryptionAlgorithm = algo;

    this.s2k = newS2KFromConfig(config);
    this.s2k.generateSalt();

    const { blockSize, keySize } = crypto.getCipher(algo);
    const key = await this.s2k.produceKey(passphrase, keySize);

    if (this.sessionKey === null) {
      this.sessionKey = crypto.generateSessionKey(this.sessionKeyAlgorithm);
    }

    if (this.version >= 5) {
      const mode = crypto.getAEADMode(this.aeadAlgorithm);
      this.iv = crypto.random.getRandomBytes(mode.ivLength); // generate new random IV
      const adata = new Uint8Array([0xC0 | SymEncryptedSessionKeyPacket.tag, this.version, this.sessionKeyEncryptionAlgorithm, this.aeadAlgorithm]);
      const encryptionKey = this.version === 6 ? await computeHKDF(enums.hash.sha256, key, new Uint8Array(), adata, keySize) : key;
      const modeInstance = await mode(algo, encryptionKey);
      this.encrypted = await modeInstance.encrypt(this.sessionKey, this.iv, adata);
    } else {
      const toEncrypt = util.concatUint8Array([
        new Uint8Array([this.sessionKeyAlgorithm]),
        this.sessionKey
      ]);
      this.encrypted = await crypto.mode.cfb.encrypt(algo, key, toEncrypt, new Uint8Array(blockSize), config);
    }
  }
}

export default SymEncryptedSessionKeyPacket;
