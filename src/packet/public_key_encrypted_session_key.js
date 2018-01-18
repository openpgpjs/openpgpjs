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
 * Public-Key Encrypted Session Key Packets (Tag 1)<br/>
 * <br/>
 * {@link http://tools.ietf.org/html/rfc4880#section-5.1|RFC4880 5.1}: A Public-Key Encrypted Session Key packet holds the session key
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
 * @requires crypto
 * @requires enums
 * @requires type/ecdh_symkey
 * @requires type/keyid
 * @requires type/mpi
 * @requires util
 * @module packet/public_key_encrypted_session_key
 */

'use strict';

import type_keyid from '../type/keyid.js';
import util from '../util.js';
import type_ecdh_symkey from '../type/ecdh_symkey.js';
import type_mpi from '../type/mpi.js';
import enums from '../enums.js';
import crypto from '../crypto';

/**
 * @constructor
 */
export default function PublicKeyEncryptedSessionKey() {
  this.tag = enums.packet.publicKeyEncryptedSessionKey;
  this.version = 3;

  this.publicKeyId = new type_keyid();
  this.sessionKey = null;

  /** @type {Array<module:type/mpi>} */
  this.encrypted = [];
}

/**
 * Parsing function for a publickey encrypted session key packet (tag 1).
 *
 * @param {Uint8Array} input Payload of a tag 1 packet
 * @param {Integer} position Position to start reading from the input string
 * @param {Integer} len Length of the packet or the remaining length of
 *            input at position
 * @return {module:packet/public_key_encrypted_session_key} Object representation
 */
PublicKeyEncryptedSessionKey.prototype.read = function (bytes) {

  this.version = bytes[0];
  this.publicKeyId.read(bytes.subarray(1,bytes.length));
  this.publicKeyAlgorithm = enums.read(enums.publicKey, bytes[9]);

  var i = 10;

  var types = crypto.getEncSessionKeyParamTypes(this.publicKeyAlgorithm);
  this.encrypted = crypto.constructParams(new Array(types.length), types);

  for (var j = 0; j < types.length; j++) {
    i += this.encrypted[j].read(bytes.subarray(i, bytes.length));
  }
};

/**
 * Create a string representation of a tag 1 packet
 *
 * @return {Uint8Array} The Uint8Array representation
 */
PublicKeyEncryptedSessionKey.prototype.write = function () {

  var arr = [new Uint8Array([this.version]), this.publicKeyId.write(), new Uint8Array([enums.write(enums.publicKey, this.publicKeyAlgorithm)])];

  for (var i = 0; i < this.encrypted.length; i++) {
    arr.push(this.encrypted[i].write());
  }

  return util.concatUint8Array(arr);
};

PublicKeyEncryptedSessionKey.prototype.encrypt = async function (key) {
  var data = String.fromCharCode(
    enums.write(enums.symmetric, this.sessionKeyAlgorithm));

  data += util.Uint8Array2str(this.sessionKey);
  var checksum = util.calc_checksum(this.sessionKey);
  data += util.Uint8Array2str(util.writeNumber(checksum, 2));

  var toEncrypt;
  if (this.publicKeyAlgorithm === 'ecdh') {
    toEncrypt = new type_mpi(crypto.pkcs5.encode(data));
  } else {
    toEncrypt = new type_mpi(crypto.pkcs1.eme.encode(data, key.params[0].byteLength()));
  }

  this.encrypted = await crypto.publicKeyEncrypt(
    this.publicKeyAlgorithm,
    key.params,
    toEncrypt,
    key.fingerprint);
};

/**
 * Decrypts the session key (only for public key encrypted session key
 * packets (tag 1)
 *
 * @param {module:packet/secret_key} key
 *            Private key with secMPIs unlocked
 * @return {String} The unencrypted session key
 */
PublicKeyEncryptedSessionKey.prototype.decrypt = async function (key) {
  var result = (await crypto.publicKeyDecrypt(
    this.publicKeyAlgorithm,
    key.params,
    this.encrypted,
    key.fingerprint)).toBytes();

  var checksum;
  var decoded;
  if (this.publicKeyAlgorithm === 'ecdh') {
    decoded = crypto.pkcs5.decode(result);
    checksum = util.readNumber(util.str2Uint8Array(decoded.substr(decoded.length - 2)));
  } else {
    decoded = crypto.pkcs1.eme.decode(result);
    checksum = util.readNumber(util.str2Uint8Array(result.substr(result.length - 2)));
  }

  key = util.str2Uint8Array(decoded.substring(1, decoded.length - 2));

  if (checksum !== util.calc_checksum(key)) {
    throw new Error('Checksum mismatch');
  } else {
    this.sessionKey = key;
    this.sessionKeyAlgorithm = enums.read(enums.symmetric, decoded.charCodeAt(0));
  }
};

/**
 * Fix custom types after cloning
 */
PublicKeyEncryptedSessionKey.prototype.postCloneTypeFix = function() {
  this.publicKeyId = type_keyid.fromClone(this.publicKeyId);
  for (var i = 0; i < this.encrypted.length; i++) {
    this.encrypted[i] = type_mpi.fromClone(this.encrypted[i]);
  }
};
