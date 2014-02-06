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
 * The class that deals with storage of the keyring. Currently the only option is to use HTML5 local storage.
 * @requires enums
 * @requires key
 * @requires util
 * @module keyring/keyring
 */

var enums = require('../enums.js'),
  keyModule = require('../key.js'),
  util = require('../util.js');

/**
 * Callback to check if a key matches the input
 * @callback module:keyring/keyring.checkCallback
 * @param {String} input input to search for
 * @param {module:key~Key} key The key to be checked.
 * @return {Boolean} True if the input matches the specified key
 */

module.exports = Keyring;

  /**
 * Initialization routine for the keyring. This method reads the
 * keyring from HTML5 local storage and initializes this instance.
 * @constructor
 * @param {class} [storeHandler] class implementing load() and store() methods
 */
function Keyring(storeHandler) {
  this.storeHandler = storeHandler || new (require('./localstore.js'))();
  this.keys = this.storeHandler.load();
};

/**
 * Calls the storeHandler to save the keys
 */
Keyring.prototype.store = function () {
  this.storeHandler.store(this.keys);
};

/**
 * Clear the keyring - erase all the keys
 */
Keyring.prototype.clear = function() {
  this.keys = [];
};

/**
 * Checks a key to see if it matches the specified email address
 * @param {String} email email address to search for
 * @param {module:key~Key} key The key to be checked.
 * @return {Boolean} True if the email address is defined in the specified key
 */
function emailCheck(email, key) {
  email = email.toLowerCase();
  var keyEmails = key.getUserIds();
  for (var i = 0; i < keyEmails.length; i++) {
    //we need to get just the email from the userid key
    keyEmail = keyEmails[i].split('<')[1].split('>')[0].trim().toLowerCase();
    if (keyEmail == email) {
      return true;
    }
  }
  return false;
}

/**
 * Checks a key to see if it matches the specified keyid
 * @param {String} id hex string keyid to search for
 * @param {module:key~Key} key the key to be checked.
 * @return {Boolean} true if the email address is defined in the specified key
 * @inner
 */
function idCheck(id, key) {
  var keyids = key.getKeyIds();
  for (var i = 0; i < keyids.length; i++) {
    if (util.hexstrdump(keyids[i].write()) == id) {
      return true;
    }
  }
  return false;
}

/**
 * searches all public keys in the keyring matching the address or address part of the user ids
 * @param {Array<module:key~Key>} keys array of keys to search
 * @param {module:keyring/keyring.checkCallback} identityFunction callback function which checks for a match
 * @param {String} identityInput input to check against
 * @param {module:enums.packet} keyType packet types of keys to check
 * @return {Array<module:key~Key>} array of keys which match
 */
function checkForIdentityAndKeyTypeMatch(keys, identityFunction, identityInput, keyType) {
  var results = [];
  for (var p = 0; p < keys.length; p++) {
    var key = keys[p];
    switch (keyType) {
      case enums.packet.publicKey:
        if (key.isPublic() && identityFunction(identityInput, key)) {
          results.push(key);
        }
        break;
      case enums.packet.secretKey:
        if (key.isPrivate() && identityFunction(identityInput, key)) {
          results.push(key);
        }
        break;
    }
  }
  return results;
}

/**
 * searches all public keys in the keyring matching the address or address part of the user ids
 * @param {String} email email address to search for
 * @return {Array<module:key~Key>} The public keys associated with provided email address.
 */
Keyring.prototype.getPublicKeyForAddress = function (email) {
  return checkForIdentityAndKeyTypeMatch(this.keys, emailCheck, email, enums.packet.publicKey);
};

/**
 * Searches the keyring for a private key containing the specified email address
 * @param {String} email email address to search for
 * @return {Array<module:key~Key>} private keys found
 */
Keyring.prototype.getPrivateKeyForAddress = function (email) {
  return checkForIdentityAndKeyTypeMatch(this.keys, emailCheck, email, enums.packet.secretKey);
};

/**
 * Searches the keyring for public keys having the specified key id
 * @param {String} keyId provided as string of hex number (lowercase)
 * @return {Array<module:key~Key>} public keys found
 */
Keyring.prototype.getKeysForKeyId = function (keyId) {
  return checkForIdentityAndKeyTypeMatch(this.keys, idCheck, keyId, enums.packet.publicKey);
};

/**
 * Imports a key from an ascii armored message
 * @param {String} armored message to read the keys/key from
 */
Keyring.prototype.importKey = function (armored) {
  this.keys = this.keys.concat(keyModule.readArmored(armored).keys);

  return true;
};

/**
 * returns the armored message representation of the key at key ring index
 * @param {Integer} index the index of the key within the array
 * @return {String} armored message representing the key object
 */
Keyring.prototype.exportKey = function (index) {
  return this.keys[index].armor();
};

/**
 * Removes a public key from the public key keyring at the specified index
 * @param {Integer} index the index of the public key within the publicKeys array
 * @return {module:key~Key} The public key object which has been removed
 */
Keyring.prototype.removeKey = function (index) {
  var removed = this.keys.splice(index, 1);

  return removed;
};

/**
 * returns the armored message representation of the public key portion of the key at key ring index
 * @param {Integer} index the index of the key within the array
 * @return {String} armored message representing the public key object
 */
Keyring.prototype.exportPublicKey = function (index) {
  return this.keys[index].toPublic().armor();
};
