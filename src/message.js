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
 * @classdesc A generic message containing one or more literal packets.
 */

function message(packetlist) {

  this.packets = packetlist || new packet.list();

  /**
   * Returns the key IDs of the keys to which the session key is encrypted
   * @return {[keyId]} array of keyid objects
   */
  this.getEncryptionKeyIds = function() {
    var keyIds = [];
    var pkESKeyPacketlist = this.packets.filterByTag(enums.packet.public_key_encrypted_session_key);
    pkESKeyPacketlist.forEach(function(packet) {
      keyIds.push(packet.publicKeyId);
    });
    return keyIds;
  }

  /**
   * Returns the key IDs of the keys that signed the message
   * @return {[keyId]} array of keyid objects
   */
  this.getSigningKeyIds = function() {
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
  }

  /**
   * Decrypt the message
   * @param {key} privateKey private key with decrypted secret data           
   * @return {[message]} new message with decrypted content
   */
  this.decrypt = function(privateKey) {
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
        return new message(symEncryptedPacket.packets);
      }
    }
  }

  /**
   * Get literal data that is the body of the message
   * @return {String|null} literal body of the message as string
   */
  this.getLiteralData = function() {
    var literal = this.packets.findPacket(enums.packet.literal);
    return literal && literal.data || null;
  }

  /**
   * Get literal data as text
   * @return {String|null} literal body of the message interpreted as text
   */
  this.getText = function() {
    var literal = this.packets.findPacket(enums.packet.literal);
    if (literal) {
      var data = literal.data;
      if (literal.format == enums.read(enums.literal, enums.literal.binary)
        || literal.format == enums.read(enums.literal, enums.literal.text)) {
        // text in a literal packet with format 'binary' or 'text' could be utf8, therefore decode
        data = util.decode_utf8(data);
      }
      return data;
    } else {
      return null;
    }
  }

  /**
   * Encrypt the message
   * @param  {[key]} keys array of keys, used to encrypt the message
   * @return {[message]} new message with encrypted content
   */
  this.encrypt = function(keys) {
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
    return new message(packetlist);
  }

  /**
   * Sign the message (the literal data packet of the message)
   * @param  {[key]} privateKey private keys with decrypted secret key data for signing
   * @return {message}      new message with signed content
   */
  this.sign = function(privateKeys) {

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

    return new message(packetlist);
  }

  /**
   * Verify message signatures
   * @param {[key]} publicKeys public keys to verify signatures
   * @return {[{'keyid': keyid, 'valid': Boolean}]} list of signer's keyid and validity of signature
   */
  this.verify = function(publicKeys) {
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
          verifiedSig.status = signatureList[i].verify(publicKeyPacket, literalDataList[0]);
          result.push(verifiedSig);
          break;
        }
      }
    });
    return result;
  }

  /**
   * Unwrap compressed message
   * @return {message} message Content of compressed message
   */
  this.unwrapCompressed = function() {
    var compressed = this.packets.filterByTag(enums.packet.compressed);
    if (compressed.length) {
      return new message(compressed[0].packets);
    } else {
      return this;
    }
  }

  /**
   * Returns ASCII armored text of message
   * @return {String} ASCII armor
   */
  this.armor = function() {
    return armor.encode(enums.armor.message, this.packets.write());
  }

  /**
   * Decrypts a message and generates user interface message out of the found.
   * MDC will be verified as well as message signatures
   * @param {openpgp_msg_privatekey} private_key the private the message is encrypted with (corresponding to the session key)
   * @param {openpgp_packet_encryptedsessionkey} sessionkey the session key to be used to decrypt the message
   * @param {openpgp_msg_publickey} pubkey Array of public keys to check signature against. If not provided, checks local keystore.
   * @return {String} plaintext of the message or null on error
   */
  function decryptAndVerifySignature(private_key, sessionkey, pubkey) {
    if (private_key == null || sessionkey == null || sessionkey == "")
      return null;
    var decrypted = sessionkey.decrypt(this, private_key.keymaterial);
    if (decrypted == null)
      return null;
    var packet;
    var position = 0;
    var len = decrypted.length;
    var validSignatures = new Array();
    util.print_debug_hexstr_dump("openpgp.msg.messge decrypt:\n", decrypted);

    var messages = openpgp.read_messages_dearmored({
      text: decrypted,
      openpgp: decrypted
    });
    for (var m in messages) {
      if (messages[m].data) {
        this.text = messages[m].data;
      }
      if (messages[m].signature) {
        validSignatures.push(messages[m].verifySignature(pubkey));
      }
    }
    return {
      text: this.text,
      validSignatures: validSignatures
    };
  }

  /**
   * Verifies a message signature. This function can be called after read_message if the message was signed only.
   * @param {openpgp_msg_publickey} pubkey Array of public keys to check signature against. If not provided, checks local keystore.
   * @return {boolean} true if the signature was correct; otherwise false
   */
  function verifySignature(pubkey) {
    var result = false;
    if (this.signature.tagType == 2) {
      if (!pubkey || pubkey.length == 0) {
        var pubkey;
        if (this.signature.version == 4) {
          pubkey = openpgp.keyring.getPublicKeysForKeyId(this.signature.issuerKeyId);
        } else if (this.signature.version == 3) {
          pubkey = openpgp.keyring.getPublicKeysForKeyId(this.signature.keyId);
        } else {
          util.print_error("unknown signature type on message!");
          return false;
        }
      }
      if (pubkey.length == 0)
        util.print_warning("Unable to verify signature of issuer: " + util.hexstrdump(this.signature.issuerKeyId) +
          ". Public key not found in keyring.");
      else {
        for (var i = 0; i < pubkey.length; i++) {
          var tohash = this.text.replace(/\r\n/g, "\n").replace(/\n/g, "\r\n");
          if (this.signature.verify(tohash, pubkey[i])) {
            util.print_info("Found Good Signature from " + pubkey[i].obj.userIds[0].text + " (0x" + util.hexstrdump(
              pubkey[i].obj.getKeyId()).substring(8) + ")");
            result = true;
          } else {
            util.print_error("Signature verification failed: Bad Signature from " + pubkey[i].obj.userIds[0].text +
              " (0x" + util.hexstrdump(pubkey[0].obj.getKeyId()).substring(8) + ")");
          }
        }
      }
    }
    return result;
  }
}

/**
 * reads an OpenPGP armored message and returns a message object
 * @param {String} armoredText text to be parsed
 * @return {message} new message object
 */
message.readArmored = function(armoredText) {
  //TODO how do we want to handle bad text? Exception throwing
  //TODO don't accept non-message armored texts
  var input = armor.decode(armoredText).data;
  var packetlist = new packet.list();
  packetlist.read(input);
  var newMessage = new message(packetlist);
  return newMessage;
}

/**
 * creates new message object from text
 * @param {String} text
 * @return {message} new message object
 */
message.fromText = function(text) {
  var literalDataPacket = new packet.literal();
  // text will be converted to UTF8
  literalDataPacket.set(text);
  var literalDataPacketlist = new packet.list();
  literalDataPacketlist.push(literalDataPacket);
  var newMessage = new message(literalDataPacketlist);
  return newMessage;
}

module.exports = message;