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

/**
 * @fileoverview The openpgp base class should provide all of the functionality 
 * to consume the openpgp.js library. All additional classes are documented 
 * for extending and developing on top of the base library.
 */

var armor = require('./encoding/armor.js');
var packet = require('./packet');
var util = require('./util');
var enums = require('./enums.js');

/**
 * GPG4Browsers Core interface. A single instance is hold
 * from the beginning. To use this library call "openpgp.init()"
 * @alias openpgp
 * @class
 * @classdesc Main Openpgp.js class. Use this to initiate and make all calls to this library.
 */
function _openpgp() {
  this.tostring = "";

  /**
   * reads message packets out of an OpenPGP armored text and
   * returns an array of message objects
   * @param {String} armoredText text to be parsed
   * @return {openpgp_msg_message[]} on error the function
   * returns null
   */
  function readArmoredPackets(armoredText) {
    //TODO how do we want to handle bad text? Exception throwing
    var input = armor.decode(armoredText.replace(/\r/g, '')).openpgp;
    return readDearmoredPackets(input);
  }

  /**
   * reads message packets out of an OpenPGP armored text and
   * returns an array of message objects. Can be called externally or internally.
   * External call will parse a de-armored messaged and return messages found.
   * Internal will be called to read packets wrapped in other packets (i.e. compressed)
   * @param {String} input dearmored text of OpenPGP packets, to be parsed
   * @return {openpgp_msg_message[]} on error the function
   * returns null
   */
  function readDearmoredPackets(input) {
    var packetList = new packet.list();
    packetList.read(input);
    return packetList;
  }

  function encryptMessage(publicKeyPacketlist, message) {

  }

  function encryptAndSignMessage(publicKeyPacketlist, privateKeyPacketlist, message) {

  }

  function decryptMessage(privateKeyPacketlist, messagePacketlist) {

  }

  function decryptAndVerifyMessage(privateKeyPacketlist, publicKeyPacketlist, messagePacketlist) {

  }

  function verifyMessage(publicKeyPacketlist, messagePacketlist) {

  }

  function signMessage(privateKeyPacketlist, messagePacketlist) {

  }

  function generateKeyPair(keyType, numBits, userId, passphrase) {
    debugger;
    var packetlist = new packet.list();

    var secretKeyPacket = new packet.secret_key();
    secretKeyPacket.algorithm = enums.read(enums.publicKey, keyType);
    secretKeyPacket.generate(numBits);
    secretKeyPacket.encrypt(passphrase);

    var userIdPacket = new packet.userid();
    userIdPacket.read(userId);

    var dataToSign = {};
    dataToSign.userid = userIdPacket;
    dataToSign.key = secretKeyPacket;
    var signaturePacket = new packet.signature();
    signaturePacket.signatureType = enums.signature.cert_casual;
    signaturePacket.publicKeyAlgorithm = keyType;
    //TODO we should load preferred hash from config, or as input to this function
    signaturePacket.hashAlgorithm = enums.hash.sha256;
    signaturePacket.sign(secretKeyPacket, dataToSign);

    var secretSubkeyPacket = new packet.secret_subkey();
    secretSubkeyPacket.algorithm = enums.read(enums.publicKey, keyType);
    secretSubkeyPacket.generate(numBits);
    secretSubkeyPacket.encrypt(passphrase);

    dataToSign = {};
    dataToSign.key = secretKeyPacket;
    dataToSign.bind = secretSubkeyPacket;
    var subkeySignaturePacket = new packet.signature();
    subkeySignaturePacket.signatureType = enums.signature.subkey_binding;
    subkeySignaturePacket.publicKeyAlgorithm = keyType;
    //TODO we should load preferred hash from config, or as input to this function
    subkeySignaturePacket.hashAlgorithm = enums.hash.sha256;
    subkeySignaturePacket.sign(secretSubkeyPacket, dataToSign);

    packetlist.push(secretKeyPacket);
    packetlist.push(userIdPacket);
    packetlist.push(signaturePacket);
    packetlist.push(secretSubkeyPacket);
    packetlist.push(subkeySignaturePacket);

    var armored = armor.encode(5, packetlist.write(), this.config);
  }

  /**
   * creates a binary string representation of an encrypted and signed message.
   * The message will be encrypted with the public keys specified and signed
   * with the specified private key.
   * @param {Object} privatekey {obj: [openpgp_msg_privatekey]} Private key 
   * to be used to sign the message
   * @param {Object[]} publickeys An arraf of {obj: [openpgp_msg_publickey]}
   * - public keys to be used to encrypt the message 
   * @param {String} messagetext message text to encrypt and sign
   * @return {String} a binary string representation of the message which 
   * can be OpenPGP armored
   */
  function write_signed_and_encrypted_message(privatekey, publickeys, messagetext) {
    var result = "";
    var i;
    var literal = new openpgp_packet_literaldata().write_packet(messagetext.replace(/\r\n/g, "\n").replace(/\n/g,
      "\r\n"));
    util.print_debug_hexstr_dump("literal_packet: |" + literal + "|\n", literal);
    for (i = 0; i < publickeys.length; i++) {
      var onepasssignature = new openpgp_packet_onepasssignature();
      var onepasssigstr = "";
      if (i === 0)
        onepasssigstr = onepasssignature.write_packet(1, openpgp.config.config.prefer_hash_algorithm, privatekey, false);
      else
        onepasssigstr = onepasssignature.write_packet(1, openpgp.config.config.prefer_hash_algorithm, privatekey, false);
      util.print_debug_hexstr_dump("onepasssigstr: |" + onepasssigstr + "|\n", onepasssigstr);
      var datasignature = new openpgp_packet_signature().write_message_signature(1, messagetext.replace(/\r\n/g, "\n").replace(
        /\n/g, "\r\n"), privatekey);
      util.print_debug_hexstr_dump("datasignature: |" + datasignature.openpgp + "|\n", datasignature.openpgp);
      if (i === 0) {
        result = onepasssigstr + literal + datasignature.openpgp;
      } else {
        result = onepasssigstr + result + datasignature.openpgp;
      }
    }

    util.print_debug_hexstr_dump("signed packet: |" + result + "|\n", result);
    // signatures done.. now encryption
    var sessionkey = openpgp_crypto_generateSessionKey(openpgp.config.config.encryption_cipher);
    var result2 = "";

    // creating session keys for each recipient
    for (i = 0; i < publickeys.length; i++) {
      var pkey = publickeys[i].getEncryptionKey();
      if (pkey === null) {
        util.print_error("no encryption key found! Key is for signing only.");
        return null;
      }
      result2 += new openpgp_packet_encryptedsessionkey().
      write_pub_key_packet(
        pkey.getKeyId(),
        pkey.MPIs,
        pkey.publicKeyAlgorithm,
        openpgp.config.config.encryption_cipher,
        sessionkey);
    }
    if (openpgp.config.config.integrity_protect) {
      result2 += new openpgp_packet_encryptedintegrityprotecteddata().write_packet(openpgp.config.config.encryption_cipher,
        sessionkey, result);
    } else {
      result2 += new openpgp_packet_encrypteddata().write_packet(openpgp.config.config.encryption_cipher, sessionkey,
        result);
    }
    return armor.encode(3, result2, null, null);
  }
  /**
   * creates a binary string representation of an encrypted message.
   * The message will be encrypted with the public keys specified 
   * @param {Object[]} publickeys An array of {obj: [openpgp_msg_publickey]}
   * -public keys to be used to encrypt the message 
   * @param {String} messagetext message text to encrypt
   * @return {String} a binary string representation of the message
   * which can be OpenPGP armored
   */
  function write_encrypted_message(publickeys, messagetext) {
    var result = "";
    var literal = new openpgp_packet_literaldata().write_packet(messagetext.replace(/\r\n/g, "\n").replace(/\n/g,
      "\r\n"));
    util.print_debug_hexstr_dump("literal_packet: |" + literal + "|\n", literal);
    result = literal;

    // signatures done.. now encryption
    var sessionkey = openpgp_crypto_generateSessionKey(openpgp.config.config.encryption_cipher);
    var result2 = "";

    // creating session keys for each recipient
    for (var i = 0; i < publickeys.length; i++) {
      var pkey = publickeys[i].getEncryptionKey();
      if (pkey === null) {
        util.print_error("no encryption key found! Key is for signing only.");
        return null;
      }
      result2 += new openpgp_packet_encryptedsessionkey().
      write_pub_key_packet(
        pkey.getKeyId(),
        pkey.MPIs,
        pkey.publicKeyAlgorithm,
        openpgp.config.config.encryption_cipher,
        sessionkey);
    }
    if (openpgp.config.config.integrity_protect) {
      result2 += new openpgp_packet_encryptedintegrityprotecteddata().write_packet(openpgp.config.config.encryption_cipher,
        sessionkey, result);
    } else {
      result2 += new openpgp_packet_encrypteddata().write_packet(openpgp.config.config.encryption_cipher, sessionkey,
        result);
    }
    return armor.encode(3, result2, null, null);
  }

  /**
   * creates a binary string representation a signed message.
   * The message will be signed with the specified private key.
   * @param {Object} privatekey {obj: [openpgp_msg_privatekey]}
   * - the private key to be used to sign the message 
   * @param {String} messagetext message text to sign
   * @return {Object} {Object: text [String]}, openpgp: {String} a binary
   *  string representation of the message which can be OpenPGP
   *   armored(openpgp) and a text representation of the message (text). 
   * This can be directly used to OpenPGP armor the message
   */
  function write_signed_message(privatekey, messagetext) {
    var sig = new openpgp_packet_signature().write_message_signature(1, messagetext.replace(/\r\n/g, "\n").replace(/\n/,
      "\r\n"), privatekey);
    var result = {
      text: messagetext.replace(/\r\n/g, "\n").replace(/\n/, "\r\n"),
      openpgp: sig.openpgp,
      hash: sig.hash
    };
    return armor.encode(2, result, null, null);
  }

  /**
   * generates a new key pair for openpgp. Beta stage. Currently only 
   * supports RSA keys, and no subkeys.
   * @param {Integer} keyType to indicate what type of key to make. 
   * RSA is 1. Follows algorithms outlined in OpenPGP.
   * @param {Integer} numBits number of bits for the key creation. (should 
   * be 1024+, generally)
   * @param {String} userId assumes already in form of "User Name 
   * <username@email.com>"
   * @param {String} passphrase The passphrase used to encrypt the resulting private key
   * @return {Object} {privateKey: [openpgp_msg_privatekey], 
   * privateKeyArmored: [string], publicKeyArmored: [string]}
   */
  function generate_key_pair(keyType, numBits, userId, passphrase) {
    var userIdPacket = new openpgp_packet_userid();
    var userIdString = userIdPacket.write_packet(userId);

    var keyPair = openpgp_crypto_generateKeyPair(keyType, numBits, passphrase, openpgp.config.config.prefer_hash_algorithm,
      3);
    var privKeyString = keyPair.privateKey;
    var privKeyPacket = new openpgp_packet_keymaterial().read_priv_key(privKeyString.string, 3, privKeyString.string.length);
    if (!privKeyPacket.decryptSecretMPIs(passphrase))
      util.print_error('Issue creating key. Unable to read resulting private key');
    var privKey = new openpgp_msg_privatekey();
    privKey.privateKeyPacket = privKeyPacket;
    privKey.getPreferredSignatureHashAlgorithm = function() {
      return openpgp.config.config.prefer_hash_algorithm
    }; //need to override this to solve catch 22 to generate signature. 8 is value for SHA256

    var publicKeyString = privKey.privateKeyPacket.publicKey.data;
    var hashData = String.fromCharCode(0x99) + String.fromCharCode(((publicKeyString.length) >> 8) & 0xFF) + String.fromCharCode((
      publicKeyString.length) & 0xFF) + publicKeyString + String.fromCharCode(0xB4) +
      String.fromCharCode((userId.length) >> 24) + String.fromCharCode(((userId.length) >> 16) & 0xFF) + String.fromCharCode(((
      userId.length) >> 8) & 0xFF) + String.fromCharCode((userId.length) & 0xFF) + userId;
    var signature = new openpgp_packet_signature();
    signature = signature.write_message_signature(16, hashData, privKey);
    var publicArmored = armor.encode(4, keyPair.publicKey.string + userIdString + signature.openpgp);

    var privArmored = armor.encode(5, privKeyString.string + userIdString + signature.openpgp);

    return {
      privateKey: privKey,
      privateKeyArmored: privArmored,
      publicKeyArmored: publicArmored
    };
  }

  this.generateKeyPair = generateKeyPair;
  this.write_signed_message = write_signed_message;
  this.write_signed_and_encrypted_message = write_signed_and_encrypted_message;
  this.write_encrypted_message = write_encrypted_message;
  this.readArmoredPackets = readArmoredPackets;
  this.readDearmoredPackets = readDearmoredPackets;
}

module.exports = new _openpgp();
