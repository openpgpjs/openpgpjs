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
 * @requires type/s2k
 * @requires crypto
 * @requires enums
 * @requires util
 */

import type_s2k from '../type/s2k';
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
 * @constructor
 */
function SymEncryptedSessionKey() {
  this.tag = enums.packet.symEncryptedSessionKey;
  this.version = 4;
  this.sessionKey = null;
  this.sessionKeyEncryptionAlgorithm = null;
  this.sessionKeyAlgorithm = 'aes256';
  this.encrypted = null;
  this.s2k = null;
}

/**
 * Parsing function for a symmetric encrypted session key packet (tag 3).
 *
 * @param {Uint8Array} input Payload of a tag 1 packet
 * @param {Integer} position Position to start reading from the input string
 * @param {Integer} len
 *            Length of the packet or the remaining length of
 *            input at position
 * @returns {module:packet.SymEncryptedSessionKey} Object representation
 */
SymEncryptedSessionKey.prototype.read = function(bytes) {
  // A one-octet version number. The only currently defined version is 4.
  [this.version] = bytes;

  // A one-octet number describing the symmetric algorithm used.
  const algo = enums.read(enums.symmetric, bytes[1]);

  // A string-to-key (S2K) specifier, length as defined above.
  this.s2k = new type_s2k();
  const s2klength = this.s2k.read(bytes.subarray(2, bytes.length));

  // Optionally, the encrypted session key itself, which is decrypted
  // with the string-to-key object.
  const done = s2klength + 2;

  if (done < bytes.length) {
    this.encrypted = bytes.subarray(done, bytes.length);
    this.sessionKeyEncryptionAlgorithm = algo;
  } else {
    this.sessionKeyAlgorithm = algo;
  }
};

SymEncryptedSessionKey.prototype.write = function() {
  const algo = this.encrypted === null ?
    this.sessionKeyAlgorithm :
    this.sessionKeyEncryptionAlgorithm;

  let bytes = util.concatUint8Array([new Uint8Array([this.version, enums.write(enums.symmetric, algo)]), this.s2k.write()]);

  if (this.encrypted !== null) {
    bytes = util.concatUint8Array([bytes, this.encrypted]);
  }
  return bytes;
};

/**
 * Decrypts the session key
 * @param {String} passphrase The passphrase in string form
 * @returns {Promise<Boolean>}
 * @async
 */
SymEncryptedSessionKey.prototype.decrypt = async function(passphrase) {
  const algo = this.sessionKeyEncryptionAlgorithm !== null ?
    this.sessionKeyEncryptionAlgorithm :
    this.sessionKeyAlgorithm;

  const length = crypto.cipher[algo].keySize;
  const key = this.s2k.produce_key(passphrase, length);

  if (this.encrypted === null) {
    this.sessionKey = key;
  } else {
    const decrypted = crypto.cfb.normalDecrypt(algo, key, this.encrypted, null);

    this.sessionKeyAlgorithm = enums.read(enums.symmetric, decrypted[0]);
    this.sessionKey = decrypted.subarray(1, decrypted.length);
  }
  return true;
};

/**
 * Encrypts the session key
 * @param {String} passphrase The passphrase in string form
 * @returns {Promise<Boolean>}
 * @async
 */
SymEncryptedSessionKey.prototype.encrypt = async function(passphrase) {
  const algo = this.sessionKeyEncryptionAlgorithm !== null ?
    this.sessionKeyEncryptionAlgorithm :
    this.sessionKeyAlgorithm;

  this.sessionKeyEncryptionAlgorithm = algo;

  this.s2k = new type_s2k();
  this.s2k.salt = await crypto.random.getRandomBytes(8);

  const length = crypto.cipher[algo].keySize;
  const key = this.s2k.produce_key(passphrase, length);

  const algo_enum = new Uint8Array([enums.write(enums.symmetric, this.sessionKeyAlgorithm)]);

  if (this.sessionKey === null) {
    this.sessionKey = await crypto.generateSessionKey(this.sessionKeyAlgorithm);
  }
  const private_key = util.concatUint8Array([algo_enum, this.sessionKey]);

  this.encrypted = crypto.cfb.normalEncrypt(algo, key, private_key, null);
  return true;
};

/**
 * Fix custom types after cloning
 */
SymEncryptedSessionKey.prototype.postCloneTypeFix = function() {
  this.s2k = type_s2k.fromClone(this.s2k);
};

export default SymEncryptedSessionKey;
