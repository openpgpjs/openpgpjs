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
 * @requires config
 * @requires encoding/armor
 * @requires enums
 * @requires packet
 * @module cleartext
 */

'use strict';

var config = require('./config'),
  packet = require('./packet'),
  enums = require('./enums.js'),
  armor = require('./encoding/armor.js');

/**
 * @class
 * @classdesc Class that represents an OpenPGP cleartext signed message.
 * See {@link http://tools.ietf.org/html/rfc4880#section-7}
 * @param  {String}     text       The cleartext of the signed message
 * @param  {module:packet/packetlist} packetlist The packetlist with signature packets or undefined
 *                                 if message not yet signed
 */

function CleartextMessage(text, packetlist) {
  if (!(this instanceof CleartextMessage)) {
    return new CleartextMessage(text, packetlist);
  }
  // normalize EOL to canonical form <CR><LF>
  this.text = text.replace(/\r/g, '').replace(/[\t ]+\n/g, "\n").replace(/\n/g,"\r\n");
  this.packets = packetlist || new packet.List();
}

/**
 * Returns the key IDs of the keys that signed the cleartext message
 * @return {Array<module:type/keyid>} array of keyid objects
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
 * @param  {Array<module:key~Key>} privateKeys private keys with decrypted secret key data for signing
 */
CleartextMessage.prototype.sign = function(privateKeys) {
  var packetlist = new packet.List();
  var literalDataPacket = new packet.Literal();
  literalDataPacket.setText(this.text);
  for (var i = 0; i < privateKeys.length; i++) {
    if (privateKeys[i].isPublic()) {
      throw new Error('Need private key for signing');
    }
    var signaturePacket = new packet.Signature();
    signaturePacket.signatureType = enums.signature.text;
    signaturePacket.hashAlgorithm = config.prefer_hash_algorithm;
    var signingKeyPacket = privateKeys[i].getSigningKeyPacket();
    signaturePacket.publicKeyAlgorithm = signingKeyPacket.algorithm;
    if (!signingKeyPacket.isDecrypted) throw new Error('Private key is not decrypted.');
    signaturePacket.sign(signingKeyPacket, literalDataPacket);
    packetlist.push(signaturePacket);
  }
  this.packets = packetlist;
};

/**
 * Verify signatures of cleartext signed message
 * @param {Array<module:key~Key>} keys array of keys to verify signatures
 * @return {Array<{keyid: module:type/keyid, valid: Boolean}>} list of signer's keyid and validity of signature
 */
CleartextMessage.prototype.verify = function(keys) {
  var result = [];
  var signatureList = this.packets.filterByTag(enums.packet.signature);
  var literalDataPacket = new packet.Literal();
  // we assume that cleartext signature is generated based on UTF8 cleartext
  literalDataPacket.setText(this.text);
  for (var i = 0; i < signatureList.length; i++) {
    var keyPacket = null;
    for (var j = 0; j < keys.length; j++) {
      keyPacket = keys[j].getSigningKeyPacket(signatureList[i].issuerKeyId);
      if (keyPacket) {
        break;
      }
    }

    var verifiedSig = {};
    if (keyPacket) {
      verifiedSig.keyid = signatureList[i].issuerKeyId;
      verifiedSig.valid = signatureList[i].verify(keyPacket, literalDataPacket);
    } else {
      verifiedSig.keyid = signatureList[i].issuerKeyId;
      verifiedSig.valid = null;
    }
    result.push(verifiedSig);
  }
  return result;
};

/**
 * Get cleartext
 * @return {String} cleartext of message
 */
CleartextMessage.prototype.getText = function() {
  // normalize end of line to \n
  return this.text.replace(/\r\n/g,"\n");
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
  };
  return armor.encode(enums.armor.signed, body);
};


/**
 * reads an OpenPGP cleartext signed message and returns a CleartextMessage object
 * @param {String} armoredText text to be parsed
 * @return {module:cleartext~CleartextMessage} new cleartext message object
 * @static
 */
function readArmored(armoredText) {
  var input = armor.decode(armoredText);
  if (input.type !== enums.armor.signed) {
    throw new Error('No cleartext signed message.');
  }
  var packetlist = new packet.List();
  packetlist.read(input.data);
  verifyHeaders(input.headers, packetlist);
  var newMessage = new CleartextMessage(input.text, packetlist);
  return newMessage;
}

/**
 * Compare hash algorithm specified in the armor header with signatures
 * @private
 * @param  {Array<String>} headers    Armor headers
 * @param  {module:packet/packetlist} packetlist The packetlist with signature packets
 */
function verifyHeaders(headers, packetlist) {
  var checkHashAlgos = function(hashAlgos) {
    for (var i = 0; i < packetlist.length; i++) {
      if (packetlist[i].tag === enums.packet.signature &&
          !hashAlgos.some(function(algo) {
            return packetlist[i].hashAlgorithm === algo;
          })) {
        return false;
      }
    }
    return true;
  }
  var oneHeader = null;
  var hashAlgos = [];
  for (var i = 0; i < headers.length; i++) {
    oneHeader = headers[i].match(/Hash: (.+)/); // get header value
    if (oneHeader) {
      oneHeader = oneHeader[1].replace(/\s/g, '');  // remove whitespace
      oneHeader = oneHeader.split(',');
      oneHeader = oneHeader.map(function(hash) {
        hash = hash.toLowerCase();
        try {
          return enums.write(enums.hash, hash);
        } catch (e) {
          throw new Error('Unknown hash algorithm in armor header: ' + hash);
        }
      });
      hashAlgos = hashAlgos.concat(oneHeader);
    } else {
      throw new Error('Only "Hash" header allowed in cleartext signed message');
    }
  }
  if (!hashAlgos.length && !checkHashAlgos([enums.hash.md5])) {
    throw new Error('If no "Hash" header in cleartext signed message, then only MD5 signatures allowed');
  } else if (!checkHashAlgos(hashAlgos)) {
    throw new Error('Hash algorithm mismatch in armor header and signature');
  }
}

exports.CleartextMessage = CleartextMessage;
exports.readArmored = readArmored;
