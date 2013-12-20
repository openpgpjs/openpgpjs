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

var packet = require('./packet');
var enums = require('./enums.js');
var armor = require('./encoding/armor.js');
var config = require('./config');
var crypto = require('./crypto');
var util = require('./util');

/**
 * @class
 * @classdesc Class that represents an OpenPGP message.
 * Can be an encrypted message, signed message, compressed message or literal message
 * @param  {packetlist} packetlist The packets that form this message
 * See http://tools.ietf.org/html/rfc4880#section-11.3
 */

function Message(packetlist) {
  if (!(this instanceof Message)) {
    return new Message(packetlist);
  }
  this.packets = packetlist || new packet.list();
}

/**
 * Returns the key IDs of the keys to which the session key is encrypted
 * @return {[keyId]} array of keyid objects
 */
Message.prototype.getEncryptionKeyIds = function() {
  var keyIds = [];
  var pkESKeyPacketlist = this.packets.filterByTag(enums.packet.public_key_encrypted_session_key);
  pkESKeyPacketlist.forEach(function(packet) {
    keyIds.push(packet.publicKeyId);
  });
  return keyIds;
};

/**
 * Returns the key IDs of the keys that signed the message
 * @return {[keyId]} array of keyid objects
 */
Message.prototype.getSigningKeyIds = function() {
  var keyIds = [];
  var msg = this.unwrapCompressed();
  // search for one pass signatures
  var onePassSigList = msg.packets.filterByTag(enums.packet.one_pass_signature);
  onePassSigList.forEach(function(packet) {
    keyIds.push(packet.signingKeyId);
  });
  // if nothing found look for signature packets
  if (!keyIds.length) {
    var signatureList = msg.packets.filterByTag(enums.packet.signature);
    signatureList.forEach(function(packet) {
      keyIds.push(packet.issuerKeyId);
    });
  }
  return keyIds;
};

/**
 * Decrypt the message
 * @param {key} privateKey private key with decrypted secret data           
 * @return {[message]} new message with decrypted content
 */
Message.prototype.decrypt = function(privateKey) {
  var encryptionKeyIds = this.getEncryptionKeyIds();
  if (!encryptionKeyIds.length) {
    // nothing to decrypt return unmodified message
    return this;
  }
  var privateKeyPacket = privateKey.getPrivateKeyPacket(encryptionKeyIds);
  if (!privateKeyPacket.isDecrypted) throw new Error('Private key is not decrypted.');
  var pkESKeyPacketlist = this.packets.filterByTag(enums.packet.public_key_encrypted_session_key);
  var pkESKeyPacket;
  for (var i = 0; i < pkESKeyPacketlist.length; i++) {
    if (pkESKeyPacketlist[i].publicKeyId.equals(privateKeyPacket.getKeyId())) {
      pkESKeyPacket = pkESKeyPacketlist[i];
      pkESKeyPacket.decrypt(privateKeyPacket);
      break;
    }
  }
  if (pkESKeyPacket) {
    var symEncryptedPacketlist = this.packets.filterByTag(enums.packet.symmetrically_encrypted, enums.packet.sym_encrypted_integrity_protected);
    if (symEncryptedPacketlist.length !== 0) {
      var symEncryptedPacket = symEncryptedPacketlist[0];
      symEncryptedPacket.decrypt(pkESKeyPacket.sessionKeyAlgorithm, pkESKeyPacket.sessionKey);
      return new Message(symEncryptedPacket.packets);
    }
  }
};

/**
 * Get literal data that is the body of the message
 * @return {String|null} literal body of the message as string
 */
Message.prototype.getLiteralData = function() {
  var literal = this.packets.findPacket(enums.packet.literal);
  return literal && literal.data || null;
};

/**
 * Get literal data as text
 * @return {String|null} literal body of the message interpreted as text
 */
Message.prototype.getText = function() {
  var literal = this.packets.findPacket(enums.packet.literal);
  if (literal) {
    return literal.getText();
  } else {
    return null;
  }
};

/**
 * Encrypt the message
 * @param  {[key]} keys array of keys, used to encrypt the message
 * @return {[message]} new message with encrypted content
 */
Message.prototype.encrypt = function(keys) {
  var packetlist = new packet.list();
  //TODO get preferred algo from signature
  var sessionKey = crypto.generateSessionKey(enums.read(enums.symmetric, config.encryption_cipher));
  keys.forEach(function(key) {
    var encryptionKeyPacket = key.getEncryptionKeyPacket();
    if (encryptionKeyPacket) {
      var pkESKeyPacket = new packet.public_key_encrypted_session_key();
      pkESKeyPacket.publicKeyId = encryptionKeyPacket.getKeyId();
      pkESKeyPacket.publicKeyAlgorithm = encryptionKeyPacket.algorithm;
      pkESKeyPacket.sessionKey = sessionKey;
      //TODO get preferred algo from signature
      pkESKeyPacket.sessionKeyAlgorithm = enums.read(enums.symmetric, config.encryption_cipher);
      pkESKeyPacket.encrypt(encryptionKeyPacket);
      packetlist.push(pkESKeyPacket);
    } else {
      throw new Error('Could not find valid key packet for encryption in key ' + key.primaryKey.getKeyId().toHex());
    }
  });
  var symEncryptedPacket;
  if (config.integrity_protect) {
    symEncryptedPacket = new packet.sym_encrypted_integrity_protected();
  } else {
    symEncryptedPacket = new packet.symmetrically_encrypted();
  }
  symEncryptedPacket.packets = this.packets;
  //TODO get preferred algo from signature
  symEncryptedPacket.encrypt(enums.read(enums.symmetric, config.encryption_cipher), sessionKey);
  packetlist.push(symEncryptedPacket);
  return new Message(packetlist);
};

/**
 * Sign the message (the literal data packet of the message)
 * @param  {[key]} privateKey private keys with decrypted secret key data for signing
 * @return {message}      new message with signed content
 */
Message.prototype.sign = function(privateKeys) {

  var packetlist = new packet.list();

  var literalDataPacket = this.packets.findPacket(enums.packet.literal);
  if (!literalDataPacket) throw new Error('No literal data packet to sign.');
  
  var literalFormat = enums.write(enums.literal, literalDataPacket.format);
  var signatureType = literalFormat == enums.literal.binary 
                      ? enums.signature.binary : enums.signature.text; 
  
  for (var i = 0; i < privateKeys.length; i++) {
    var onePassSig = new packet.one_pass_signature();
    onePassSig.type = signatureType;
    //TODO get preferred hashg algo from key signature
    onePassSig.hashAlgorithm = config.prefer_hash_algorithm;
    var signingKeyPacket = privateKeys[i].getSigningKeyPacket();
    if (!signingKeyPacket) {
      throw new Error('Could not find valid key packet for signing in key ' + privateKeys[i].primaryKey.getKeyId().toHex());
    }
    onePassSig.publicKeyAlgorithm = signingKeyPacket.algorithm;
    onePassSig.signingKeyId = signingKeyPacket.getKeyId();
    packetlist.push(onePassSig);
  }

  packetlist.push(literalDataPacket);
  
  for (var i = privateKeys.length - 1; i >= 0; i--) {
    var signaturePacket = new packet.signature();
    signaturePacket.signatureType = signatureType;
    signaturePacket.hashAlgorithm = config.prefer_hash_algorithm;
    signaturePacket.publicKeyAlgorithm = signingKeyPacket.algorithm;
    if (!signingKeyPacket.isDecrypted) throw new Error('Private key is not decrypted.');
    signaturePacket.sign(signingKeyPacket, literalDataPacket);
    packetlist.push(signaturePacket);
  }

  return new Message(packetlist);
};

/**
 * Verify message signatures
 * @param {[key]} publicKeys public keys to verify signatures
 * @return {[{'keyid': keyid, 'valid': Boolean}]} list of signer's keyid and validity of signature
 */
Message.prototype.verify = function(publicKeys) {
  var result = [];
  var msg = this.unwrapCompressed();
  var literalDataList = msg.packets.filterByTag(enums.packet.literal);
  if (literalDataList.length !== 1) throw new Error('Can only verify message with one literal data packet.');
  var signatureList = msg.packets.filterByTag(enums.packet.signature);
  publicKeys.forEach(function(pubKey) {
    for (var i = 0; i < signatureList.length; i++) {
      var publicKeyPacket = pubKey.getPublicKeyPacket([signatureList[i].issuerKeyId]);
      if (publicKeyPacket) {
        var verifiedSig = {};
        verifiedSig.keyid = signatureList[i].issuerKeyId;
        verifiedSig.valid = signatureList[i].verify(publicKeyPacket, literalDataList[0]);
        result.push(verifiedSig);
        break;
      }
    }
  });
  return result;
};

/**
 * Unwrap compressed message
 * @return {message} message Content of compressed message
 */
Message.prototype.unwrapCompressed = function() {
  var compressed = this.packets.filterByTag(enums.packet.compressed);
  if (compressed.length) {
    return new Message(compressed[0].packets);
  } else {
    return this;
  }
};

/**
 * Returns ASCII armored text of message
 * @return {String} ASCII armor
 */
Message.prototype.armor = function() {
  return armor.encode(enums.armor.message, this.packets.write());
};

/**
 * reads an OpenPGP armored message and returns a message object
 * @param {String} armoredText text to be parsed
 * @return {message} new message object
 */
function readArmored(armoredText) {
  //TODO how do we want to handle bad text? Exception throwing
  //TODO don't accept non-message armored texts
  var input = armor.decode(armoredText).data;
  var packetlist = new packet.list();
  packetlist.read(input);
  var newMessage = new Message(packetlist);
  return newMessage;
}

/**
 * creates new message object from text
 * @param {String} text
 * @return {message} new message object
 */
function fromText(text) {
  var literalDataPacket = new packet.literal();
  // text will be converted to UTF8
  literalDataPacket.setText(text);
  var literalDataPacketlist = new packet.list();
  literalDataPacketlist.push(literalDataPacket);
  var newMessage = new Message(literalDataPacketlist);
  return newMessage;
}

/**
 * creates new message object from binary data
 * @param {String} bytes
 * @return {message} new message object
 */
function fromBinary(bytes) {
  var literalDataPacket = new packet.literal();
  literalDataPacket.setBytes(bytes, enums.read(enums.literal, enums.literal.binary));
  var literalDataPacketlist = new packet.list();
  literalDataPacketlist.push(literalDataPacket);
  var newMessage = new Message(literalDataPacketlist);
  return newMessage;
}

exports.Message = Message;
exports.readArmored = readArmored;
exports.fromText = fromText;
exports.fromBinary = fromBinary;
