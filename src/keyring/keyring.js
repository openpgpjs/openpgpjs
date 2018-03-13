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
 * @fileoverview Provides the Keyring class
 * @requires key
 * @requires keyring/localstore
 * @module keyring/keyring
 */

import { readArmored } from '../key';
import LocalStore from './localstore';

/**
 * Initialization routine for the keyring.
 * This method reads the keyring from HTML5 local storage and initializes this instance.
 * @constructor
 * @param {keyring/localstore} [storeHandler] class implementing loadPublic(), loadPrivate(), storePublic(), and storePrivate() methods
 */
function Keyring(storeHandler) {
  this.storeHandler = storeHandler || new LocalStore();
  this.publicKeys = new KeyArray(this.storeHandler.loadPublic());
  this.privateKeys = new KeyArray(this.storeHandler.loadPrivate());
}

/**
 * Calls the storeHandler to save the keys
 */
Keyring.prototype.store = function () {
  this.storeHandler.storePublic(this.publicKeys.keys);
  this.storeHandler.storePrivate(this.privateKeys.keys);
};

/**
 * Clear the keyring - erase all the keys
 */
Keyring.prototype.clear = function() {
  this.publicKeys.keys = [];
  this.privateKeys.keys = [];
};

/**
 * Searches the keyring for keys having the specified key id
 * @param {String} keyId provided as string of lowercase hex number
 * withouth 0x prefix (can be 16-character key ID or fingerprint)
 * @param  {Boolean} deep if true search also in subkeys
 * @returns {Array<module:key.Key>|null} keys found or null
 */
Keyring.prototype.getKeysForId = function (keyId, deep) {
  let result = [];
  result = result.concat(this.publicKeys.getForId(keyId, deep) || []);
  result = result.concat(this.privateKeys.getForId(keyId, deep) || []);
  return result.length ? result : null;
};

/**
 * Removes keys having the specified key id from the keyring
 * @param {String} keyId provided as string of lowercase hex number
 * withouth 0x prefix (can be 16-character key ID or fingerprint)
 * @returns {Array<module:key.Key>|null} keys found or null
 */
Keyring.prototype.removeKeysForId = function (keyId) {
  let result = [];
  result = result.concat(this.publicKeys.removeForId(keyId) || []);
  result = result.concat(this.privateKeys.removeForId(keyId) || []);
  return result.length ? result : null;
};

/**
 * Get all public and private keys
 * @returns {Array<module:key.Key>} all keys
 */
Keyring.prototype.getAllKeys = function () {
  return this.publicKeys.keys.concat(this.privateKeys.keys);
};

/**
 * Array of keys
 * @param {Array<module:key.Key>} keys The keys to store in this array
 */
function KeyArray(keys) {
  this.keys = keys;
}

/**
 * Searches all keys in the KeyArray matching the address or address part of the user ids
 * @param {String} email email address to search for
 * @returns {Array<module:key.Key>} The public keys associated with provided email address.
 */
KeyArray.prototype.getForAddress = function(email) {
  const results = [];
  for (let i = 0; i < this.keys.length; i++) {
    if (emailCheck(email, this.keys[i])) {
      results.push(this.keys[i]);
    }
  }
  return results;
};

/**
 * Checks a key to see if it matches the specified email address
 * @private
 * @param {String} email email address to search for
 * @param {module:key.Key} key The key to be checked.
 * @returns {Boolean} True if the email address is defined in the specified key
 */
function emailCheck(email, key) {
  email = email.toLowerCase();
  // escape email before using in regular expression
  const emailEsc = email.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const emailRegex = new RegExp('<' + emailEsc + '>');
  const userIds = key.getUserIds();
  for (let i = 0; i < userIds.length; i++) {
    const userId = userIds[i].toLowerCase();
    if (email === userId || emailRegex.test(userId)) {
      return true;
    }
  }
  return false;
}

/**
 * Checks a key to see if it matches the specified keyid
 * @private
 * @param {String} keyId provided as string of lowercase hex number
 * withouth 0x prefix (can be 16-character key ID or fingerprint)
 * @param {module:packet.SecretKey|public_key|public_subkey|secret_subkey} keypacket The keypacket to be checked
 * @returns {Boolean} True if keypacket has the specified keyid
 */
function keyIdCheck(keyId, keypacket) {
  if (keyId.length === 16) {
    return keyId === keypacket.getKeyId().toHex();
  }
  return keyId === keypacket.getFingerprint();
}

/**
 * Searches the KeyArray for a key having the specified key id
 * @param {String} keyId provided as string of lowercase hex number
 * withouth 0x prefix (can be 16-character key ID or fingerprint)
 * @param  {Boolean} deep if true search also in subkeys
 * @returns {module:key.Key|null} key found or null
 */
KeyArray.prototype.getForId = function (keyId, deep) {
  for (let i = 0; i < this.keys.length; i++) {
    if (keyIdCheck(keyId, this.keys[i].primaryKey)) {
      return this.keys[i];
    }
    if (deep && this.keys[i].subKeys.length) {
      for (let j = 0; j < this.keys[i].subKeys.length; j++) {
        if (keyIdCheck(keyId, this.keys[i].subKeys[j].subKey)) {
          return this.keys[i];
        }
      }
    }
  }
  return null;
};

/**
 * Imports a key from an ascii armored message
 * @param {String} armored message to read the keys/key from
 * @returns {Promise<Array<Error>|null>} array of error objects or null
 * @async
 */
KeyArray.prototype.importKey = async function (armored) {
  const imported = readArmored(armored);
  const that = this;
  for (let i = 0; i < imported.keys.length; i++) {
    const key = imported.keys[i];
    // check if key already in key array
    const keyidHex = key.primaryKey.getKeyId().toHex();
    const keyFound = that.getForId(keyidHex);
    if (keyFound) {
      // eslint-disable-next-line no-await-in-loop
      await keyFound.update(key);
    } else {
      that.push(key);
    }
  }
  return imported.err ? imported.err : null;
};

/**
 * Add key to KeyArray
 * @param {module:key.Key} key The key that will be added to the keyring
 * @returns {Number} The new length of the KeyArray
 */
KeyArray.prototype.push = function (key) {
  return this.keys.push(key);
};

/**
 * Removes a key with the specified keyid from the keyring
 * @param {String} keyId provided as string of lowercase hex number
 * withouth 0x prefix (can be 16-character key ID or fingerprint)
 * @returns {module:key.Key|null} The key object which has been removed or null
 */
KeyArray.prototype.removeForId = function (keyId) {
  for (let i = 0; i < this.keys.length; i++) {
    if (keyIdCheck(keyId, this.keys[i].primaryKey)) {
      return this.keys.splice(i, 1)[0];
    }
  }
  return null;
};

export default Keyring;
