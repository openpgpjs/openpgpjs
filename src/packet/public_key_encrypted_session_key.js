// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

var type_keyid = require('../type/keyid.js'),
  util = require('../util'),
  type_mpi = require('../type/mpi.js'),
  enums = require('../enums.js'),
  crypto = require('../crypto');


/**
 * @class
 * @classdesc Public-Key Encrypted Session Key Packets (Tag 1)
 * 
 * RFC4880 5.1: A Public-Key Encrypted Session Key packet holds the session key
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
module.exports = function packet_public_key_encrypted_session_key() {
  this.version = 3;

  this.publicKeyId = new type_keyid();
  this.publicKeyAlgorithm = 'rsa_encrypt';

  this.sessionKey = null;
  this.sessionKeyAlgorithm = 'aes256';

  /** @type {openpgp_type_mpi[]} */
  this.encrypted = [];

  /**
   * Parsing function for a publickey encrypted session key packet (tag 1).
   * 
   * @param {String} input Payload of a tag 1 packet
   * @param {Integer} position Position to start reading from the input string
   * @param {Integer} len Length of the packet or the remaining length of
   *            input at position
   * @return {openpgp_packet_encrypteddata} Object representation
   */
  this.read = function(bytes) {

    this.version = bytes.charCodeAt(0);
    this.publicKeyId.read(bytes.substr(1));
    this.publicKeyAlgorithm = enums.read(enums.publicKey, bytes.charCodeAt(9));

    var i = 10;

    var integerCount = (function(algo) {
      switch (algo) {
        case 'rsa_encrypt':
        case 'rsa_encrypt_sign':
          return 1;

        case 'elgamal':
          return 2;

        default:
          throw new Error("Invalid algorithm.");
      }
    })(this.publicKeyAlgorithm);

    this.encrypted = [];

    for (var j = 0; j < integerCount; j++) {
      var mpi = new type_mpi();
      i += mpi.read(bytes.substr(i));
      this.encrypted.push(mpi);
    }
  }

  /**
   * Create a string representation of a tag 1 packet
   * 
   * @param {String} publicKeyId
   *             The public key id corresponding to publicMPIs key as string
   * @param {openpgp_type_mpi[]} publicMPIs
   *            Multiprecision integer objects describing the public key
   * @param {Integer} pubalgo
   *            The corresponding public key algorithm // See RFC4880 9.1
   * @param {Integer} symmalgo
   *            The symmetric cipher algorithm used to encrypt the data 
   *            within an encrypteddatapacket or encryptedintegrity-
   *            protecteddatapacket 
   *            following this packet //See RFC4880 9.2
   * @param {String} sessionkey
   *            A string of randombytes representing the session key
   * @return {String} The string representation
   */
  this.write = function() {

    var result = String.fromCharCode(this.version);
    result += this.publicKeyId.write();
    result += String.fromCharCode(
      enums.write(enums.publicKey, this.publicKeyAlgorithm));

    for (var i = 0; i < this.encrypted.length; i++) {
      result += this.encrypted[i].write()
    }

    return result;
  }

  this.encrypt = function(key) {
    var data = String.fromCharCode(
      enums.write(enums.symmetric, this.sessionKeyAlgorithm));

    data += this.sessionKey;
    var checksum = util.calc_checksum(this.sessionKey);
    data += util.writeNumber(checksum, 2);

    var mpi = new type_mpi();
    mpi.fromBytes(crypto.pkcs1.eme.encode(
      data,
      key.mpi[0].byteLength()));

    this.encrypted = crypto.publicKeyEncrypt(
      this.publicKeyAlgorithm,
      key.mpi,
      mpi);
  }

  /**
   * Decrypts the session key (only for public key encrypted session key
   * packets (tag 1)
   * 
   * @param {openpgp_msg_message} msg
   *            The message object (with member encryptedData
   * @param {openpgp_msg_privatekey} key
   *            Private key with secMPIs unlocked
   * @return {String} The unencrypted session key
   */
  this.decrypt = function(key) {
    var result = crypto.publicKeyDecrypt(
      this.publicKeyAlgorithm,
      key.mpi,
      this.encrypted).toBytes();

    var checksum = util.readNumber(result.substr(result.length - 2));

    var decoded = crypto.pkcs1.eme.decode(
      result,
      key.mpi[0].byteLength());

    var key = decoded.substring(1, decoded.length - 2);

    if (checksum != util.calc_checksum(key)) {
      throw new Error('Checksum mismatch');
    } else {
      this.sessionKey = key;
      this.sessionKeyAlgorithm =
        enums.read(enums.symmetric, decoded.charCodeAt(0));
    }
  }
};
