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

var config = require('./config');
var packet = require('./packet');
var enums = require('./enums.js');
var armor = require('./encoding/armor.js');

/**
 * @class
 * @classdesc Class that represents an OpenPGP cleartext signed message.
 * See http://tools.ietf.org/html/rfc4880#section-7
 * @param  {String}     text       The cleartext of the signed message
 * @param  {packetlist} packetlist The packetlist with signature packets or undefined
 *                                 if message not yet signed
 */

function CleartextMessage(text, packetlist) {
  if (!(this instanceof CleartextMessage)) {
    return new CleartextMessage(packetlist);
  }
  this.text = text.replace(/\r/g, '').replace(/[\t ]+\n/g, "\n").replace(/\n/g,"\r\n");
  this.packets = packetlist || new packet.list();
}

/**
 * Returns the key IDs of the keys that signed the cleartext message
 * @return {[keyId]} array of keyid objects
 */
CleartextMessage.prototype.getSigningKeyIds = function() {
  var keyIds = [];
  var signatureList = this.packets.filterByTag(enums.packet.signature);
  signatureList.forEach(function(packet) {
    keyIds.push(packet.issuerKeyId);
  });
  return keyIds;
};

/**
 * Sign the cleartext message
 * @param  {[key]} privateKeys private keys with decrypted secret key data for signing
 */
CleartextMessage.prototype.sign = function(privateKeys) {
  var packetlist = new packet.list();  
  for (var i = 0; i < privateKeys.length; i++) {
    var signaturePacket = new packet.signature();
    signaturePacket.signatureType = enums.signature.text;
    signaturePacket.hashAlgorithm = config.prefer_hash_algorithm;
    var signingKeyPacket = privateKeys[i].getSigningKeyPacket();
    signaturePacket.publicKeyAlgorithm = signingKeyPacket.algorithm;
    if (!signingKeyPacket.isDecrypted) throw new Error('Private key is not decrypted.');
    var literalDataPacket = new packet.literal();
    literalDataPacket.setBytes(this.text, enums.read(enums.literal, enums.literal.text));
    signaturePacket.sign(signingKeyPacket, literalDataPacket);
    packetlist.push(signaturePacket);
  }
  this.packets = packetlist;
};

/**
 * Verify signatures of cleartext signed message
 * @param {[key]} publicKeys public keys to verify signatures
 * @return {[{'keyid': keyid, 'valid': Boolean}]} list of signer's keyid and validity of signature
 */
CleartextMessage.prototype.verify = function(publicKeys) {
  var result = [];
  var signatureList = this.packets.filterByTag(enums.packet.signature);
  var that = this;
  publicKeys.forEach(function(pubKey) {
    for (var i = 0; i < signatureList.length; i++) {
      var publicKeyPacket = pubKey.getPublicKeyPacket([signatureList[i].issuerKeyId]);
      if (publicKeyPacket) {
        var verifiedSig = {};
        verifiedSig.keyid = signatureList[i].issuerKeyId;
        var literalDataPacket = new packet.literal();
        literalDataPacket.setBytes(that.text, enums.read(enums.literal, enums.literal.text));
        verifiedSig.status = signatureList[i].verify(publicKeyPacket, literalDataPacket);
        result.push(verifiedSig);
        break;
      }
    }
  });
  return result;
};

/**
 * Get cleartext
 * @return {String} cleartext of message
 */
CleartextMessage.prototype.getText = function() {
  return this.text;
};

/**
 * Returns ASCII armored text of cleartext signed message
 * @return {String} ASCII armor
 */
CleartextMessage.prototype.armor = function() {
  var body = {
    hash: enums.read(enums.hash, config.prefer_hash_algorithm).toUpperCase(),
    text: this.text,
    data: this.packets.write()
  }
  return armor.encode(enums.armor.signed, body);
};


/**
 * reads an OpenPGP cleartext signed message and returns a CleartextMessage object
 * @param {String} armoredText text to be parsed
 * @return {CleartextMessage} new cleartext message object
 */
function readArmored(armoredText) {
  var input = armor.decode(armoredText);
  if (input.type !== enums.armor.signed) {
    throw new Error('No cleartext signed message.');
  }
  var packetlist = new packet.list();
  packetlist.read(input.data);
  var newMessage = new CleartextMessage(input.text, packetlist);
  return newMessage;
}

exports.CleartextMessage = CleartextMessage;
exports.readArmored = readArmored;
