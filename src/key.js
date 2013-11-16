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

/**
 * @class
 * @classdesc Class that represents an OpenPGP key. Must contain a master key. 
 * @param  {packetlist} packetlist [description]
 * Can contain additional subkeys, signatures,
 * user ids, user attributes.
 */

 function key(packetlist) {

  this.packets = packetlist || new packet.list();

  this.passphrase = null;

  /** 
   * Returns the primary key packet (secret or public)
   * @returns {packet_secret_key|packet_public_key|null} 
   */
  this.getKeyPacket = function() {
    for (var i = 0; i < this.packets.length; i++) {
      if (this.packets[i].tag == enums.packet.public_key ||
        this.packets[i].tag == enums.packet.secret_key) {
        return this.packets[i];
      }
    }
    return null;
  }

  /** 
   * Returns all the private and public subkey packets
   * @returns {[public_subkey|secret_subkey]} 
   */
  this.getSubkeyPackets = function() {

    var subkeys = [];

    for (var i = 0; i < this.packets.length; i++) {
      if (this.packets[i].tag == enums.packet.public_subkey ||
        this.packets[i].tag == enums.packet.secret_subkey) {
        subkeys.push(this.packets[i]);
      }
    }

    return subkeys;
  }

  /** 
   * Returns all the private and public key and subkey packets
   * @returns {[public_subkey|secret_subkey|packet_secret_key|packet_public_key]} 
   */
  this.getAllKeyPackets = function() {
    return [this.getKeyPacket()].concat(this.getSubkeyPackets());
  }

  /** 
   * Returns key IDs of all key packets
   * @returns {[keyid]} 
   */
  this.getKeyIds = function() {
    var keyIds = [];
    var keys = this.getAllKeyPackets();
    for (var i = 0; i < keys.length; i++) {
      keyIds.push(keys[i].getKeyId());
    }
    return keyIds;
  }

  /**
   * Returns first key packet for given array of key IDs
   * @param  {[keyid]} keyIds 
   * @return {public_subkey|secret_subkey|packet_secret_key|packet_public_key|null}       
   */
  this.getKeyPacket = function(keyIds) {
    var keys = this.getAllKeyPackets();
    for (var i = 0; i < keys.length; i++) {
      var keyId = keys[i].getKeyId(); 
      for (var j = 0; j < keyIds.length; j++) {
        if (keyId.equals(keyIds[j])) {
          //TODO return only verified keys
          return keys[i];
        }
      }
    }
    return null;
  }

  /**
   * Returns first private key packet for given array of key IDs
   * @param  {[keyid]} keyIds
   * @param  {Boolean} decrypted decrypt private key packet
   * @return {secret_subkey|packet_secret_key|null}       
   */
  this.getPrivateKeyPacket = function(keyIds, decrypted) {
    var keys = this.packets.filterByTag(enums.packet.secret_key, enums.packet.secret_subkey);
    for (var i = 0; i < keys.length; i++) {
      var keyId = keys[i].getKeyId(); 
      for (var j = 0; j < keyIds.length; j++) {
        if (keyId.equals(keyIds[j])) {
          //TODO return only verified keys
          if (decrypted) {
            if (!this.passphrase) throw new Error('No passphrase to decrypt key.');
            keys[i].decrypt(this.passphrase);
          }
          return keys[i];
        }
      }
    }
    return null;
  }

  /**
   * Returns true if this is a public key
   * @return {Boolean}
   */
  this.isPublic = function() {
    var publicKeyPackets = this.packets.filterByTag(enums.packet.public_key);
    return publicKeyPackets.length ? true : false;
  }

  /**
   * Returns true if this is a private key
   * @return {Boolean}
   */
  this.isPrivate = function() {
    var privateKeyPackets = this.packets.filterByTag(enums.packet.private_key);
    return privateKeyPackets.length ? true : false;
  }

  /**
   * Returns first key packet that is available for signing
   * @return {public_subkey|secret_subkey|packet_secret_key|packet_public_key|null}
   */
  this.getSigningKeyPacket = function() {

    var signing = [ enums.publicKey.rsa_encrypt_sign, enums.publicKey.rsa_sign, enums.publicKey.dsa];

    signing = signing.map(function(s) {
      return enums.read(enums.publicKey, s);
    });

    var keys = this.getAllKeyPackets();

    for (var i = 0; i < keys.length; i++) {
      if (signing.indexOf(keys[i].algorithm) !== -1) {
        return keys[i];
      }
    }

    return null;
  }

  /**
   * Returns preferred signature hash algorithm of this key
   * @return {String}
   */
  function getPreferredSignatureHashAlgorithm() {
    //TODO implement: https://tools.ietf.org/html/rfc4880#section-5.2.3.8
    //separate private key preference from digest preferences
    return config.prefer_hash_algorithm;
  }

  /**
   * Returns the first valid encryption key packet for this key
   * @returns {public_subkey|secret_subkey|packet_secret_key|packet_public_key|null} key packet or null if no encryption key has been found
   */
  this.getEncryptionKeyPacket = function() {
    // V4: by convention subkeys are prefered for encryption service
    // V3: keys MUST NOT have subkeys
    var isValidEncryptionKey = function(key) {
      //TODO evaluate key flags: http://tools.ietf.org/html/rfc4880#section-5.2.3.21
      return key.algorithm != enums.read(enums.publicKey, enums.publicKey.dsa) && key.algorithm != enums.read(enums.publicKey,
        enums.publicKey.rsa_sign);
      //TODO verify key
      //&& keys.verifyKey()
    };

    var subkeys = this.getSubkeyPackets();

    for (var j = 0; j < subkeys.length; j++) {
      if (isValidEncryptionKey(subkeys[j])) {
        return subkeys[j];
      }
    }
    // if no valid subkey for encryption, use primary key
    var primaryKey = this.getKeyPacket();
    if (isValidEncryptionKey(primaryKey)) {
      return primaryKey;
    }
    return null;
  }

  /**
   * Decrypts all secret key and subkey packets
   * @param  {String} passphrase 
   * @return {undefined}
   */
  this.decrypt = function(passphrase) {
    //TODO return value
    var keys = this.getAllKeyPackets();
    for (var i in keys) {
      if (keys[i].tag == enums.packet.secret_subkey ||
        keys[i].tag == enums.packet.secret_key) {
          if (!passphrase && !this.passphrase) throw new Error('No passphrase to decrypt key.');
          keys[i].decrypt(passphrase || this.passphrase);
      }
    }
  }

  /**
   * Unlocks the key with passphrase, decryption of secret keys deferred. This allows to decrypt the required private key packets on demand
   * @param  {String} passphrase 
   * @return {undefined}
   */
  this.unlock = function(passphrase) {
    this.passphrase = passphrase;
  }

  // TODO
  this.verify = function() {

  }
  // TODO
  this.revoke = function() {

  }

}

/**
 * reads an OpenPGP armored text and returns a key object
 * @param {String} armoredText text to be parsed
 * @return {key} new key object
 */
key.readArmored = function(armoredText) {
  //TODO how do we want to handle bad text? Exception throwing
  //TODO don't accept non-key armored texts
  var input = armor.decode(armoredText).openpgp;
  var packetlist = new packet.list();
  packetlist.read(input);
  var newKey = new key(packetlist);
  return newKey;
}

module.exports = key;
