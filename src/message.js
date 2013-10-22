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

/**
 * @class
 * @classdesc A generic message containing one or more literal packets.
 */

function message(packetlist) {

  this.packets = packetlist || new packet.list();

  /**
   * Returns the key IDs of the public keys to which the session key is encrypted
   * @return {[keyId]} array of keyid objects
   */
  this.getKeyIds = function() {
    var keyIds = [];
    var pkESKeyPacketlist = this.packets.filterByType(enums.packet.public_key_encrypted_session_key);
    pkESKeyPacketlist.forEach(function(packet) {
      keyIds.push(packet.publicKeyId);
    });
    return keyIds;
  }

  /**
   * Returns the key IDs in hex of the public keys to which the session key is encrypted
   * @return {[String]} keyId provided as string of hex numbers (lowercase)
   */
  this.getKeyIdsHex = function() {
    return this.getKeyIds().map(function(keyId) {
      return keyId.toHex();
    });
  }

  /**
   * Decrypts the message
   * @param {secret_subkey|packet_secret_key} privateKeyPacket the private key packet (with decrypted secret part) the message is encrypted with (corresponding to the session key)
   * @return {[String]} array with plaintext of decrypted messages
   */
  this.decrypt = function(privateKeyPacket) {
    var decryptedMessages = [];
    var pkESKeyPacketlist = this.packets.filterByType(enums.packet.public_key_encrypted_session_key);
    for (var i = 0; i < pkESKeyPacketlist.length; i++) {
      var pkESKeyPacket = pkESKeyPacketlist[i];
      if (pkESKeyPacket.publicKeyId.equals(privateKeyPacket.getKeyId())) {
        pkESKeyPacket.decrypt(privateKeyPacket);
        var symEncryptedPacketlist = this.packets.filter(function(packet) {
          return packet.tag == enums.packet.symmetrically_encrypted || packet.tag == enums.packet.sym_encrypted_integrity_protected;
        });
        for (var k = 0; k < symEncryptedPacketlist.length; k++) {
          var symEncryptedPacket = symEncryptedPacketlist[k];
          symEncryptedPacket.decrypt(pkESKeyPacket.sessionKeyAlgorithm, pkESKeyPacket.sessionKey);
          for (var l = 0; l < symEncryptedPacket.packets.length; l++) {
            var dataPacket = symEncryptedPacket.packets[l];
            switch (dataPacket.tag) {
              case enums.packet.literal:
                decryptedMessages.push(dataPacket.getBytes());
                break;
              case enums.packet.compressed:
                //TODO
                break;
              default:
                //TODO
            }
          }
        }
        break;
      }
    }
    return decryptedMessages;
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
 * @return {key} new message object
 */
message.readArmored = function(armoredText) {
  //TODO how do we want to handle bad text? Exception throwing
  //TODO don't accept non-message armored texts
  var input = armor.decode(armoredText).openpgp;
  var packetlist = new packet.list();
  packetlist.read(input);
  var newMessage = new message(packetlist);
  return newMessage;
}

module.exports = message;