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

import KeyID from '../type/keyid';
import crypto from '../crypto';
import enums from '../enums';
import util from '../util';
import { UnsupportedError } from './packet';
import defaultConfig from '../config';
import SecretKeyPacket from './secret_key';

const VERSION = 3;

/**
 * Public-Key Encrypted Session Key Packets (Tag 1)
 *
 * {@link https://tools.ietf.org/html/rfc4880#section-5.1|RFC4880 5.1}:
 * A Public-Key Encrypted Session Key packet holds the session key
 * used to encrypt a message. Zero or more Public-Key Encrypted Session Key
 * packets and/or Symmetric-Key Encrypted Session Key packets may precede a
 * Symmetrically Encrypted Data Packet, which holds an encrypted message. The
 * message is encrypted with the session key, and the session key is itself
 * encrypted and stored in the Encrypted Session Key packet(s). The
 * Symmetrically Encrypted Data Packet is preceded by one Public-Key Encrypted
 * Session Key packet for each OpenPGP key to which the message is encrypted.
 * The recipient of the message finds a session key that is encrypted to their
 * public key, decrypts the session key, and then uses the session key to
 * decrypt the message.
 */
class PublicKeyEncryptedSessionKeyPacket {
  static get tag() {
    return enums.packet.publicKeyEncryptedSessionKey;
  }

  constructor() {
    this.version = 3;

    this.publicKeyID = new KeyID();
    this.publicKeyAlgorithm = null;

    this.sessionKey = null;
    /**
     * Algorithm to encrypt the message with
     * @type {enums.symmetric}
     */
    this.sessionKeyAlgorithm = null;

    /** @type {Object} */
    this.encrypted = {};
  }

  /**
   * Parsing function for a publickey encrypted session key packet (tag 1).
   *
   * @param {Uint8Array} bytes - Payload of a tag 1 packet
   */
  read(bytes) {
    this.version = bytes[0];
    if (this.version !== VERSION) {
      throw new UnsupportedError(`Version ${this.version} of the PKESK packet is unsupported.`);
    }
    this.publicKeyID.read(bytes.subarray(1, bytes.length));
    this.publicKeyAlgorithm = bytes[9];
    this.encrypted = crypto.parseEncSessionKeyParams(this.publicKeyAlgorithm, bytes.subarray(10));
  }

  /**
   * Create a binary representation of a tag 1 packet
   *
   * @returns {Uint8Array} The Uint8Array representation.
   */
  write() {
    const arr = [
      new Uint8Array([this.version]),
      this.publicKeyID.write(),
      new Uint8Array([this.publicKeyAlgorithm]),
      crypto.serializeParams(this.publicKeyAlgorithm, this.encrypted)
    ];

    return util.concatUint8Array(arr);
  }

  /**
   * Encrypt session key packet
   * @param {PublicKeyPacket} key - Public key
   * @throws {Error} if encryption failed
   * @async
   */
  async encrypt(key) {
    const data = util.concatUint8Array([
      new Uint8Array([enums.write(enums.symmetric, this.sessionKeyAlgorithm)]),
      this.sessionKey,
      util.writeChecksum(this.sessionKey)
    ]);
    const algo = enums.write(enums.publicKey, this.publicKeyAlgorithm);
    this.encrypted = await crypto.publicKeyEncrypt(
      algo, key.publicParams, data, key.getFingerprintBytes());
  }

  /**
   * Decrypts the session key (only for public key encrypted session key packets (tag 1)
   * @param {SecretKeyPacket} key - decrypted private key
   * @param {Object} [randomSessionKey] - Bogus session key to use in case of sensitive decryption error, or if the decrypted session key is of a different type/size.
   *                                      This is needed for constant-time processing. Expected object of the form: { sessionKey: Uint8Array, sessionKeyAlgorithm: enums.symmetric }
   * @param {Object} [config] - Custom configuration settings to overwrite those in [config]{@link module:config}
   * @throws {Error} if decryption failed, unless `randomSessionKey` is given
   * @async
   */
  async decrypt(key, randomSessionKey, config = defaultConfig) {
    // check that session key algo matches the secret key algo
    if (this.publicKeyAlgorithm !== key.algorithm) {
      throw new Error('Decryption error');
    }
    if (key instanceof SecretKeyPacket && key.isStoredInHardware() && !(config.hardwareKeys)){
      throw new Error('Cannot use gnu-divert-to-card key without config.hardwareKeys set.');
    }

    const randomPayload = randomSessionKey ? util.concatUint8Array([
      new Uint8Array([randomSessionKey.sessionKeyAlgorithm]),
      randomSessionKey.sessionKey,
      util.writeChecksum(randomSessionKey.sessionKey)
    ]) : null;
    const decoded = await crypto.publicKeyDecrypt(this.publicKeyAlgorithm, key.publicParams, key.privateParams, this.encrypted, key.getFingerprintBytes(), randomPayload, config);
    const symmetricAlgoByte = decoded[0];
    const sessionKey = decoded.subarray(1, decoded.length - 2);
    const checksum = decoded.subarray(decoded.length - 2);
    const computedChecksum = util.writeChecksum(sessionKey);
    const isValidChecksum = computedChecksum[0] === checksum[0] & computedChecksum[1] === checksum[1];

    if (randomSessionKey) {
      // We must not leak info about the validity of the decrypted checksum or cipher algo.
      // The decrypted session key must be of the same algo and size as the random session key, otherwise we discard it and use the random data.
      const isValidPayload = isValidChecksum & symmetricAlgoByte === randomSessionKey.sessionKeyAlgorithm & sessionKey.length === randomSessionKey.sessionKey.length;
      this.sessionKeyAlgorithm = util.selectUint8(isValidPayload, symmetricAlgoByte, randomSessionKey.sessionKeyAlgorithm);
      this.sessionKey = util.selectUint8Array(isValidPayload, sessionKey, randomSessionKey.sessionKey);

    } else {
      const isValidPayload = isValidChecksum && enums.read(enums.symmetric, symmetricAlgoByte);
      if (isValidPayload) {
        this.sessionKey = sessionKey;
        this.sessionKeyAlgorithm = symmetricAlgoByte;
      } else {
        throw new Error('Decryption error');
      }
    }
  }
}

export default PublicKeyEncryptedSessionKeyPacket;
