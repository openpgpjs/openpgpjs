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
 * @classdesc Class that represents an OpenPGP key. Must contain a master key. 
 * @param  {packetlist} packetlist [description]
 * Can contain additional subkeys, signatures,
 * user ids, user attributes.
 */

 function key(packetlist) {

  this.packets = packetlist || new packet.list();


  /** Returns the primary key (secret or public)
   * @returns {packet_secret_key|packet_public_key|null} */
  this.getKey = function() {
    for (var i = 0; i < this.packets.length; i++) {
      if (this.packets[i].tag == enums.packet.public_key ||
        this.packets[i].tag == enums.packet.secret_key) {
        return this.packets[i];
      }
    }
    return null;
  };

  /** Returns all the private and public subkeys 
   * @returns {[public_subkey|secret_subkey]} */
  this.getSubkeys = function() {

    var subkeys = [];

    for (var i = 0; i < this.packets.length; i++) {
      if (this.packets[i].tag == enums.packet.public_subkey ||
        this.packets[i].tag == enums.packet.secret_subkey) {
        subkeys.push(this.packets[i]);
      }
    }

    return subkeys;
  };

  this.getAllKeys = function() {
    return [this.getKey()].concat(this.getSubkeys());
  };

  this.getKeyids = function() {
    var keyids = [];
    var keys = this.getAllKeys();
    for (var i = 0; i < keys.length; i++) {
      keyids.push(keys[i].getKeyId());
    }
    return keyids;
  };

  this.getKeyById = function(keyid) {
    var keys = this.getAllKeys();
    for (var i = 0; i < keys.length; i++) {
      if (keys[i].getKeyId().equals(keyid)) {
        return keys[i];
      }
    }
  }

  this.getSigningKey = function() {

    var signing = [ enums.publicKey.rsa_encrypt_sign, enums.publicKey.rsa_sign, enums.publicKey.dsa];

    signing = signing.map(function(s) {
      return enums.read(enums.publicKey, s);
    });

    var keys = this.getAllKeys();

    for (var i = 0; i < keys.length; i++) {
      if (signing.indexOf(keys[i].algorithm) !== -1) {
        return keys[i];
      }
    }

    return null;
  };

  function getPreferredSignatureHashAlgorithm() {
    var pkey = this.getSigningKey();
    if (pkey === null) {
      util.print_error("private key is for encryption only! Cannot create a signature.");
      return null;
    }
    if (pkey.publicKey.publicKeyAlgorithm == 17) {
      var dsa = new DSA();
      return dsa.select_hash_algorithm(pkey.publicKey.MPIs[1].toBigInteger()); // q
    }
    //TODO implement: https://tools.ietf.org/html/rfc4880#section-5.2.3.8
    //separate private key preference from digest preferences
    return openpgp.config.config.prefer_hash_algorithm;
  }

  /**
   * Finds an encryption key for this key
   * @returns null if no encryption key has been found
   */
  this.getEncryptionKey = function() {
    // V4: by convention subkeys are prefered for encryption service
    // V3: keys MUST NOT have subkeys
    var isValidEncryptionKey = function(key) {
      return key.algorithm != enums.read(enums.publicKey, enums.publicKey.dsa) && key.algorithm != enums.read(enums.publicKey,
        enums.publicKey.rsa_sign);
      //TODO verify key
      //&& keys.verifyKey()
    };

    var subkeys = this.getSubkeys();

    for (var j = 0; j < subkeys.length; j++) {
      if (isValidEncryptionKey(subkeys[j])) {
        return subkeys[j];
      }
    }
    // if no valid subkey for encryption, use primary key
    var primaryKey = this.getKey();
    if (isValidEncryptionKey(primaryKey)) {
      return primaryKey;
    }
    return null;
  };

  this.decrypt = function(passphrase) {
    var keys = this.getAllKeys();

    for (var i in keys)
      if (keys[i].tag == enums.packet.secret_subkey ||
        keys[i].tag == enums.packet.secret_key) {
        keys[i].decrypt(passphrase);
      }
  };


  // TODO need to implement this

  function revoke() {

  }

};

/**
 * reads an OpenPGP armored text and returns a key object
 * @param {String} armoredText text to be parsed
 * @return {key} new key object
 */
key.readArmored = function(armoredText) {
  //TODO how do we want to handle bad text? Exception throwing
  var input = armor.decode(armoredText).openpgp;
  var packetlist = new packet.list();
  packetlist.read(input);
  var newKey = new key(packetlist);
  return newKey;
}

module.exports = key;
