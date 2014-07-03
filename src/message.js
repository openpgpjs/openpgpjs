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
 * @requires config
 * @requires crypto
 * @requires encoding/armor
 * @requires enums
 * @requires packet
 * @module message
 */

var packet = require('./packet'),
  enums = require('./enums.js'),
  armor = require('./encoding/armor.js'),
  config = require('./config'),
  crypto = require('./crypto'),
  keyModule = require('./key.js');

/**
 * @class
 * @classdesc Class that represents an OpenPGP message.
 * Can be an encrypted message, signed message, compressed message or literal message
 * @param  {module:packet/packetlist} packetlist The packets that form this message
 * See {@link http://tools.ietf.org/html/rfc4880#section-11.3}
 */

function Message(packetlist) {
  if (!(this instanceof Message)) {
    return new Message(packetlist);
  }
  this.packets = packetlist || new packet.List();
}

/**
 * Returns the key IDs of the keys to which the session key is encrypted
 * @return {Array<module:type/keyid>} array of keyid objects
 */
Message.prototype.getEncryptionKeyIds = function() {
  var keyIds = [];
  var pkESKeyPacketlist = this.packets.filterByTag(enums.packet.publicKeyEncryptedSessionKey);
  pkESKeyPacketlist.forEach(function(packet) {
    keyIds.push(packet.publicKeyId);
  });
  return keyIds;
};

/**
 * Returns the key IDs of the keys that signed the message
 * @return {Array<module:type/keyid>} array of keyid objects
 */
Message.prototype.getSigningKeyIds = function() {
  var keyIds = [];
  var msg = this.unwrapCompressed();
  // search for one pass signatures
  var onePassSigList = msg.packets.filterByTag(enums.packet.onePassSignature);
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
 * @param {module:key~Key} privateKey private key with decrypted secret data           
 * @return {Array<module:message~Message>} new message with decrypted content
 */
Message.prototype.decrypt = function(privateKey) {
  var encryptionKeyIds = this.getEncryptionKeyIds();
  if (!encryptionKeyIds.length) {
    // nothing to decrypt return unmodified message
    return this;
  }
  var privateKeyPacket = privateKey.getKeyPacket(encryptionKeyIds);
  if (!privateKeyPacket.isDecrypted) throw new Error('Private key is not decrypted.');
  var pkESKeyPacketlist = this.packets.filterByTag(enums.packet.publicKeyEncryptedSessionKey);
  var pkESKeyPacket;
  for (var i = 0; i < pkESKeyPacketlist.length; i++) {
    if (pkESKeyPacketlist[i].publicKeyId.equals(privateKeyPacket.getKeyId())) {
      pkESKeyPacket = pkESKeyPacketlist[i];
      pkESKeyPacket.decrypt(privateKeyPacket);
      break;
    }
  }
  if (pkESKeyPacket) {
    var symEncryptedPacketlist = this.packets.filterByTag(enums.packet.symmetricallyEncrypted, enums.packet.symEncryptedIntegrityProtected);
    if (symEncryptedPacketlist.length !== 0) {
      var symEncryptedPacket = symEncryptedPacketlist[0];
      symEncryptedPacket.decrypt(pkESKeyPacket.sessionKeyAlgorithm, pkESKeyPacket.sessionKey);
      var resultMsg = new Message(symEncryptedPacket.packets);
      // remove packets after decryption
      symEncryptedPacket.packets = new packet.List();
      return resultMsg;
    }
  }
};

/**
 * Get literal data that is the body of the message
 * @return {(String|null)} literal body of the message as string
 */
Message.prototype.getLiteralData = function() {
  var literal = this.packets.findPacket(enums.packet.literal);
  return literal && literal.data || null;
};

/**
 * Get literal data as text
 * @return {(String|null)} literal body of the message interpreted as text
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
 * @param  {Array<module:key~Key>} keys array of keys, used to encrypt the message
 * @return {Array<module:message~Message>} new message with encrypted content
 */
Message.prototype.encrypt = function(keys) {
  var packetlist = new packet.List();
  var symAlgo = keyModule.getPreferredSymAlgo(keys);
  var sessionKey = crypto.generateSessionKey(enums.read(enums.symmetric, symAlgo));
  keys.forEach(function(key) {
    var encryptionKeyPacket = key.getEncryptionKeyPacket();
    if (encryptionKeyPacket) {
      var pkESKeyPacket = new packet.PublicKeyEncryptedSessionKey();
      pkESKeyPacket.publicKeyId = encryptionKeyPacket.getKeyId();
      pkESKeyPacket.publicKeyAlgorithm = encryptionKeyPacket.algorithm;
      pkESKeyPacket.sessionKey = sessionKey;
      pkESKeyPacket.sessionKeyAlgorithm = enums.read(enums.symmetric, symAlgo);
      pkESKeyPacket.encrypt(encryptionKeyPacket);
      packetlist.push(pkESKeyPacket);
    } else {
      throw new Error('Could not find valid key packet for encryption in key ' + key.primaryKey.getKeyId().toHex());
    }
  });
  var symEncryptedPacket;
  if (config.integrity_protect) {
    symEncryptedPacket = new packet.SymEncryptedIntegrityProtected();
  } else {
    symEncryptedPacket = new packet.SymmetricallyEncrypted();
  }
  symEncryptedPacket.packets = this.packets;
  symEncryptedPacket.encrypt(enums.read(enums.symmetric, symAlgo), sessionKey);
  packetlist.push(symEncryptedPacket);
  // remove packets after encryption
  symEncryptedPacket.packets = new packet.List();
  return new Message(packetlist);
};

/**
 * Sign the message (the literal data packet of the message)
 * @param  {Array<module:key~Key>} privateKey private keys with decrypted secret key data for signing
 * @return {module:message~Message}      new message with signed content
 */
Message.prototype.sign = function(privateKeys) {

  var packetlist = new packet.List();

  var literalDataPacket = this.packets.findPacket(enums.packet.literal);
  if (!literalDataPacket) throw new Error('No literal data packet to sign.');
  
  var literalFormat = enums.write(enums.literal, literalDataPacket.format);
  var signatureType = literalFormat == enums.literal.binary ?
                      enums.signature.binary : enums.signature.text;
  var i;
  for (i = 0; i < privateKeys.length; i++) {
    var onePassSig = new packet.OnePassSignature();
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
  
  for (i = privateKeys.length - 1; i >= 0; i--) {
    var signaturePacket = new packet.Signature();
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
 * @param {Array<module:key~Key>} keys array of keys to verify signatures
 * @return {Array<({keyid: module:type/keyid, valid: Boolean})>} list of signer's keyid and validity of signature
 */
Message.prototype.verify = function(keys) {
  var result = [];
  var msg = this.unwrapCompressed();
  var literalDataList = msg.packets.filterByTag(enums.packet.literal);
  if (literalDataList.length !== 1) throw new Error('Can only verify message with one literal data packet.');
  var signatureList = msg.packets.filterByTag(enums.packet.signature);
  for (var i = 0; i < signatureList.length; i++) {
    var keyPacket = null;
    for (var j = 0; j < keys.length; j++) {
      keyPacket = keys[j].getKeyPacket([signatureList[i].issuerKeyId]);
      if (keyPacket) {
        break;
      }
    }

    var verifiedSig = {};
    if (keyPacket) {
      verifiedSig.keyid = signatureList[i].issuerKeyId;
      verifiedSig.valid = signatureList[i].verify(keyPacket, literalDataList[0]);
    } else {
      verifiedSig.keyid = signatureList[i].issuerKeyId;
      verifiedSig.valid = null;
    }
    result.push(verifiedSig);
  }
  return result;
};

/**
 * Unwrap compressed message
 * @return {module:message~Message} message Content of compressed message
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
 * @return {module:message~Message} new message object
 * @static
 */
function readArmored(armoredText) {
  //TODO how do we want to handle bad text? Exception throwing
  //TODO don't accept non-message armored texts
  var input = armor.decode(armoredText).data;
  var packetlist = new packet.List();
  packetlist.read(input);
  var newMessage = new Message(packetlist);
  return newMessage;
}

/**
 * Create a message object from signed content and a detached armored signature.
 * @param {String} content An 8 bit ascii string containing e.g. a MIME subtree with text nodes or attachments
 * @param {String} detachedSignature The detached ascii armored PGP signarure
 */
function readSignedContent(content, detachedSignature) {
  var literalDataPacket = new packet.Literal();
  literalDataPacket.setBytes(content, enums.read(enums.literal, enums.literal.binary));
  var packetlist = new packet.List();
  packetlist.push(literalDataPacket);
  var input = armor.decode(detachedSignature).data;
  packetlist.read(input);
  var newMessage = new Message(packetlist);
  return newMessage;
}

/**
 * creates new message object from text
 * @param {String} text
 * @return {module:message~Message} new message object
 * @static
 */
function fromText(text) {
  var literalDataPacket = new packet.Literal();
  // text will be converted to UTF8
  literalDataPacket.setText(text);
  var literalDataPacketlist = new packet.List();
  literalDataPacketlist.push(literalDataPacket);
  var newMessage = new Message(literalDataPacketlist);
  return newMessage;
}

/**
 * creates new message object from binary data
 * @param {String} bytes
 * @return {module:message~Message} new message object
 * @static
 */
function fromBinary(bytes) {
  var literalDataPacket = new packet.Literal();
  literalDataPacket.setBytes(bytes, enums.read(enums.literal, enums.literal.binary));
  var literalDataPacketlist = new packet.List();
  literalDataPacketlist.push(literalDataPacket);
  var newMessage = new Message(literalDataPacketlist);
  return newMessage;
}

exports.Message = Message;
exports.readArmored = readArmored;
exports.readSignedContent = readSignedContent;
exports.fromText = fromText;
exports.fromBinary = fromBinary;
