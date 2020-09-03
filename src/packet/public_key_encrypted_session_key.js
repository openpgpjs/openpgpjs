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

/**
 * @requires type/keyid
 * @requires type/mpi
 * @requires crypto
 * @requires enums
 * @requires util
 */

import type_keyid from '../type/keyid';
import crypto from '../crypto';
import enums from '../enums';
import util from '../util';

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
 * @memberof module:packet
 */
class PublicKeyEncryptedSessionKeyPacket {
  constructor() {
    this.tag = enums.packet.publicKeyEncryptedSessionKey;
    this.version = 3;

    this.publicKeyId = new type_keyid();
    this.publicKeyAlgorithm = null;

    this.sessionKey = null;
    this.sessionKeyAlgorithm = null;

    /** @type {Array<module:type/mpi>} */
    this.encrypted = [];
  }

  /**
   * Parsing function for a publickey encrypted session key packet (tag 1).
   *
   * @param {Uint8Array} bytes Payload of a tag 1 packet
   */
  read(bytes) {
    this.version = bytes[0];
    this.publicKeyId.read(bytes.subarray(1, bytes.length));
    this.publicKeyAlgorithm = enums.read(enums.publicKey, bytes[9]);

    let i = 10;

    const algo = enums.write(enums.publicKey, this.publicKeyAlgorithm);
    const types = crypto.getEncSessionKeyParamTypes(algo);
    this.encrypted = crypto.constructParams(types);

    for (let j = 0; j < types.length; j++) {
      i += this.encrypted[j].read(bytes.subarray(i, bytes.length));
    }
  }

  /**
   * Create a binary representation of a tag 1 packet
   *
   * @returns {Uint8Array} The Uint8Array representation
   */
  write() {
    const arr = [new Uint8Array([this.version]), this.publicKeyId.write(), new Uint8Array([enums.write(enums.publicKey, this.publicKeyAlgorithm)])];

    for (let i = 0; i < this.encrypted.length; i++) {
      arr.push(this.encrypted[i].write());
    }

    return util.concatUint8Array(arr);
  }

  /**
   * Encrypt session key packet
   * @param {PublicKeyPacket} key Public key
   * @returns {Promise<Boolean>}
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
      algo, key.params, data, key.getFingerprintBytes());
    return true;
  }

  /**
   * Decrypts the session key (only for public key encrypted session key
   * packets (tag 1)
   *
   * @param {SecretKeyPacket} key
   *            Private key with secret params unlocked
   * @returns {Promise<Boolean>}
   * @async
   */
  async decrypt(key) {
    const algo = enums.write(enums.publicKey, this.publicKeyAlgorithm);
    const keyAlgo = enums.write(enums.publicKey, key.algorithm);
    // check that session key algo matches the secret key algo
    if (algo !== keyAlgo) {
      throw new Error('Decryption error');
    }
    const decoded = await crypto.publicKeyDecrypt(algo, key.params, this.encrypted, key.getFingerprintBytes());
    const checksum = decoded.subarray(decoded.length - 2);
    const sessionKey = decoded.subarray(1, decoded.length - 2);
    if (!util.equalsUint8Array(checksum, util.writeChecksum(sessionKey))) {
      throw new Error('Decryption error');
    } else {
      this.sessionKey = sessionKey;
      this.sessionKeyAlgorithm = enums.read(enums.symmetric, decoded[0]);
    }
    return true;
  }
}

export default PublicKeyEncryptedSessionKeyPacket;
