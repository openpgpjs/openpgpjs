require=(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);throw new Error("Cannot find module '"+o+"'")}var f=n[o]={exports:{}};t[o][0].call(f.exports,function(e){var n=t[o][1][e];return s(n?n:e)},f,f.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({"fjvtDg":[function(require,module,exports){

module.exports = require('./keyring.js');
module.exports.localstore = require('./localstore.js');

},{"./keyring.js":3,"./localstore.js":4}],"keyring":[function(require,module,exports){
module.exports=require('fjvtDg');
},{}],3:[function(require,module,exports){
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
 * @requires openpgp
 * @module keyring/keyring
 */

var openpgp = require('openpgp');

/**
 * Callback to check if a key matches the input
 * @callback module:keyring/keyring.checkCallback
 * @param {String} input input to search for
 * @param {module:key~Key} key The key to be checked.
 * @return {Boolean} True if the input matches the specified key
 */

/**
 * Initialization routine for the keyring. This method reads the
 * keyring from HTML5 local storage and initializes this instance.
 * @constructor
 * @param {class} [storeHandler] class implementing load() and store() methods
 */
module.exports = function(storeHandler) {
  if (!storeHandler) {
    storeHandler = new (require('./localstore.js'))();
  }
  this.storeHandler = storeHandler;
  this.keys = this.storeHandler.load();

  /**
   * Calls the storeHandler to save the keys
   */
  this.store = function () {
    this.storeHandler.store(this.keys);
  };

  /**
   * Clear the keyring - erase all the keys
   */
  this.clear = function() {
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
    for (var i; i < keyEmails.length; i++) {
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
      if (openpgp.util.hexstrdump(keyids[i].write()) == id) {
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
        case openpgp.enums.packet.public_key:
          if (key.isPublic() && identityFunction(identityInput, key)) {
            results.push(key);
          }
          break;
        case openpgp.enums.packet.private_key:
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
  this.getPublicKeyForAddress = function (email) {
    return checkForIdentityAndKeyTypeMatch(this.keys, emailCheck, email, openpgp.enums.packet.public_key);
  };

  /**
   * Searches the keyring for a private key containing the specified email address
   * @param {String} email email address to search for
   * @return {Array<module:key~Key>} private keys found
   */
  this.getPrivateKeyForAddress = function (email) {
    return checkForIdentityAndKeyTypeMatch(this.keys, emailCheck, email, openpgp.enums.packet.secret_key);
  };

  /**
   * Searches the keyring for public keys having the specified key id
   * @param {String} keyId provided as string of hex number (lowercase)
   * @return {Array<module:key~Key>} public keys found
   */
  this.getKeysForKeyId = function (keyId) {
    return checkForIdentityAndKeyTypeMatch(this.keys, idCheck, keyId, openpgp.enums.packet.public_key);
  };

  /**
   * Imports a key from an ascii armored message
   * @param {String} armored message to read the keys/key from
   */
  this.importKey = function (armored) {
    this.keys = this.keys.concat(openpgp.key.readArmored(armored).keys);

    return true;
  };

  /**
   * returns the armored message representation of the key at key ring index
   * @param {Integer} index the index of the key within the array
   * @return {String} armored message representing the key object
   */
  this.exportKey = function (index) {
    return this.keys[index].armor();
  };

  /**
   * Removes a public key from the public key keyring at the specified index
   * @param {Integer} index the index of the public key within the publicKeys array
   * @return {module:key~Key} The public key object which has been removed
   */
  this.removeKey = function (index) {
    var removed = this.keys.splice(index, 1);

    return removed;
  };

  /**
   * returns the armored message representation of the public key portion of the key at key ring index
   * @param {Integer} index the index of the key within the array
   * @return {String} armored message representing the public key object
   */
  this.exportPublicKey = function (index) {
    return this.keys[index].toPublic().armor();
  };
};

},{"./localstore.js":4}],4:[function(require,module,exports){
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
 * @requires openpgp
 * @module keyring/localstore
 */

var openpgp = require('openpgp');

module.exports = function () {
  /**
   * Load the keyring from HTML5 local storage and initializes this instance.
   * @return {Array<module:key~Key>} array of keys retrieved from localstore
   */
  this.load = function () {
    var armoredKeys = JSON.parse(window.localStorage.getItem("armoredKeys"));
    var keys = [];
    if (armoredKeys !== null && armoredKeys.length !== 0) {
      var key;
      for (var i = 0; i < armoredKeys.length; i++) {
        key = openpgp.key.readArmored(armoredKeys[i]);
        keys.push(key);
      }
    }
    return keys;
  }

  /**
   * Saves the current state of the keyring to HTML5 local storage.
   * The privateKeys array and publicKeys array gets Stringified using JSON
   * @param {Array<module:key~Key>} keys array of keys to save in localstore
   */
  this.store = function (keys) {
    var armoredKeys = [];
    for (var i = 0; i < keys.length; i++) {
      armoredKeys.push(keys[i].armor());
    }
    window.localStorage.setItem("armoredKeys", JSON.stringify(armoredKeys));
  }
};

},{}]},{},[])
//@ sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZ2VuZXJhdGVkLmpzIiwic291cmNlcyI6WyIvaG9tZS9yb2JlcnQvemltYnJhLXBncC9vcGVucGdwanMtZGV2ZWwvc3JjL2tleXJpbmcvaW5kZXguanMiLCIvaG9tZS9yb2JlcnQvemltYnJhLXBncC9vcGVucGdwanMtZGV2ZWwvc3JjL2tleXJpbmcva2V5cmluZy5qcyIsIi9ob21lL3JvYmVydC96aW1icmEtcGdwL29wZW5wZ3Bqcy1kZXZlbC9zcmMva2V5cmluZy9sb2NhbHN0b3JlLmpzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFBQTtBQUNBO0FBQ0E7QUFDQTs7OztBQ0hBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDOUxBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSIsInNvdXJjZXNDb250ZW50IjpbIlxubW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKCcuL2tleXJpbmcuanMnKTtcbm1vZHVsZS5leHBvcnRzLmxvY2Fsc3RvcmUgPSByZXF1aXJlKCcuL2xvY2Fsc3RvcmUuanMnKTtcbiIsIi8vIEdQRzRCcm93c2VycyAtIEFuIE9wZW5QR1AgaW1wbGVtZW50YXRpb24gaW4gamF2YXNjcmlwdFxuLy8gQ29weXJpZ2h0IChDKSAyMDExIFJlY3VyaXR5IExhYnMgR21iSFxuLy8gXG4vLyBUaGlzIGxpYnJhcnkgaXMgZnJlZSBzb2Z0d2FyZTsgeW91IGNhbiByZWRpc3RyaWJ1dGUgaXQgYW5kL29yXG4vLyBtb2RpZnkgaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgTGVzc2VyIEdlbmVyYWwgUHVibGljXG4vLyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieSB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uOyBlaXRoZXJcbi8vIHZlcnNpb24gMi4xIG9mIHRoZSBMaWNlbnNlLCBvciAoYXQgeW91ciBvcHRpb24pIGFueSBsYXRlciB2ZXJzaW9uLlxuLy8gXG4vLyBUaGlzIGxpYnJhcnkgaXMgZGlzdHJpYnV0ZWQgaW4gdGhlIGhvcGUgdGhhdCBpdCB3aWxsIGJlIHVzZWZ1bCxcbi8vIGJ1dCBXSVRIT1VUIEFOWSBXQVJSQU5UWTsgd2l0aG91dCBldmVuIHRoZSBpbXBsaWVkIHdhcnJhbnR5IG9mXG4vLyBNRVJDSEFOVEFCSUxJVFkgb3IgRklUTkVTUyBGT1IgQSBQQVJUSUNVTEFSIFBVUlBPU0UuICBTZWUgdGhlIEdOVVxuLy8gTGVzc2VyIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgZm9yIG1vcmUgZGV0YWlscy5cbi8vIFxuLy8gWW91IHNob3VsZCBoYXZlIHJlY2VpdmVkIGEgY29weSBvZiB0aGUgR05VIExlc3NlciBHZW5lcmFsIFB1YmxpY1xuLy8gTGljZW5zZSBhbG9uZyB3aXRoIHRoaXMgbGlicmFyeTsgaWYgbm90LCB3cml0ZSB0byB0aGUgRnJlZSBTb2Z0d2FyZVxuLy8gRm91bmRhdGlvbiwgSW5jLiwgNTEgRnJhbmtsaW4gU3RyZWV0LCBGaWZ0aCBGbG9vciwgQm9zdG9uLCBNQSAgMDIxMTAtMTMwMSAgVVNBXG5cbi8qKlxuICogVGhlIGNsYXNzIHRoYXQgZGVhbHMgd2l0aCBzdG9yYWdlIG9mIHRoZSBrZXlyaW5nLiBDdXJyZW50bHkgdGhlIG9ubHkgb3B0aW9uIGlzIHRvIHVzZSBIVE1MNSBsb2NhbCBzdG9yYWdlLlxuICogQHJlcXVpcmVzIG9wZW5wZ3BcbiAqIEBtb2R1bGUga2V5cmluZy9rZXlyaW5nXG4gKi9cblxudmFyIG9wZW5wZ3AgPSByZXF1aXJlKCdvcGVucGdwJyk7XG5cbi8qKlxuICogQ2FsbGJhY2sgdG8gY2hlY2sgaWYgYSBrZXkgbWF0Y2hlcyB0aGUgaW5wdXRcbiAqIEBjYWxsYmFjayBtb2R1bGU6a2V5cmluZy9rZXlyaW5nLmNoZWNrQ2FsbGJhY2tcbiAqIEBwYXJhbSB7U3RyaW5nfSBpbnB1dCBpbnB1dCB0byBzZWFyY2ggZm9yXG4gKiBAcGFyYW0ge21vZHVsZTprZXl+S2V5fSBrZXkgVGhlIGtleSB0byBiZSBjaGVja2VkLlxuICogQHJldHVybiB7Qm9vbGVhbn0gVHJ1ZSBpZiB0aGUgaW5wdXQgbWF0Y2hlcyB0aGUgc3BlY2lmaWVkIGtleVxuICovXG5cbi8qKlxuICogSW5pdGlhbGl6YXRpb24gcm91dGluZSBmb3IgdGhlIGtleXJpbmcuIFRoaXMgbWV0aG9kIHJlYWRzIHRoZVxuICoga2V5cmluZyBmcm9tIEhUTUw1IGxvY2FsIHN0b3JhZ2UgYW5kIGluaXRpYWxpemVzIHRoaXMgaW5zdGFuY2UuXG4gKiBAY29uc3RydWN0b3JcbiAqIEBwYXJhbSB7Y2xhc3N9IFtzdG9yZUhhbmRsZXJdIGNsYXNzIGltcGxlbWVudGluZyBsb2FkKCkgYW5kIHN0b3JlKCkgbWV0aG9kc1xuICovXG5tb2R1bGUuZXhwb3J0cyA9IGZ1bmN0aW9uKHN0b3JlSGFuZGxlcikge1xuICBpZiAoIXN0b3JlSGFuZGxlcikge1xuICAgIHN0b3JlSGFuZGxlciA9IG5ldyAocmVxdWlyZSgnLi9sb2NhbHN0b3JlLmpzJykpKCk7XG4gIH1cbiAgdGhpcy5zdG9yZUhhbmRsZXIgPSBzdG9yZUhhbmRsZXI7XG4gIHRoaXMua2V5cyA9IHRoaXMuc3RvcmVIYW5kbGVyLmxvYWQoKTtcblxuICAvKipcbiAgICogQ2FsbHMgdGhlIHN0b3JlSGFuZGxlciB0byBzYXZlIHRoZSBrZXlzXG4gICAqL1xuICB0aGlzLnN0b3JlID0gZnVuY3Rpb24gKCkge1xuICAgIHRoaXMuc3RvcmVIYW5kbGVyLnN0b3JlKHRoaXMua2V5cyk7XG4gIH07XG5cbiAgLyoqXG4gICAqIENsZWFyIHRoZSBrZXlyaW5nIC0gZXJhc2UgYWxsIHRoZSBrZXlzXG4gICAqL1xuICB0aGlzLmNsZWFyID0gZnVuY3Rpb24oKSB7XG4gICAgdGhpcy5rZXlzID0gW107XG4gIH07XG5cbiAgLyoqXG4gICAqIENoZWNrcyBhIGtleSB0byBzZWUgaWYgaXQgbWF0Y2hlcyB0aGUgc3BlY2lmaWVkIGVtYWlsIGFkZHJlc3NcbiAgICogQHBhcmFtIHtTdHJpbmd9IGVtYWlsIGVtYWlsIGFkZHJlc3MgdG8gc2VhcmNoIGZvclxuICAgKiBAcGFyYW0ge21vZHVsZTprZXl+S2V5fSBrZXkgVGhlIGtleSB0byBiZSBjaGVja2VkLlxuICAgKiBAcmV0dXJuIHtCb29sZWFufSBUcnVlIGlmIHRoZSBlbWFpbCBhZGRyZXNzIGlzIGRlZmluZWQgaW4gdGhlIHNwZWNpZmllZCBrZXlcbiAgICovXG4gIGZ1bmN0aW9uIGVtYWlsQ2hlY2soZW1haWwsIGtleSkge1xuICAgIGVtYWlsID0gZW1haWwudG9Mb3dlckNhc2UoKTtcbiAgICB2YXIga2V5RW1haWxzID0ga2V5LmdldFVzZXJJZHMoKTtcbiAgICBmb3IgKHZhciBpOyBpIDwga2V5RW1haWxzLmxlbmd0aDsgaSsrKSB7XG4gICAgICAvL3dlIG5lZWQgdG8gZ2V0IGp1c3QgdGhlIGVtYWlsIGZyb20gdGhlIHVzZXJpZCBrZXlcbiAgICAgIGtleUVtYWlsID0ga2V5RW1haWxzW2ldLnNwbGl0KCc8JylbMV0uc3BsaXQoJz4nKVswXS50cmltKCkudG9Mb3dlckNhc2UoKTtcbiAgICAgIGlmIChrZXlFbWFpbCA9PSBlbWFpbCkge1xuICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIGZhbHNlO1xuICB9XG5cbiAgLyoqXG4gICAqIENoZWNrcyBhIGtleSB0byBzZWUgaWYgaXQgbWF0Y2hlcyB0aGUgc3BlY2lmaWVkIGtleWlkXG4gICAqIEBwYXJhbSB7U3RyaW5nfSBpZCBoZXggc3RyaW5nIGtleWlkIHRvIHNlYXJjaCBmb3JcbiAgICogQHBhcmFtIHttb2R1bGU6a2V5fktleX0ga2V5IHRoZSBrZXkgdG8gYmUgY2hlY2tlZC5cbiAgICogQHJldHVybiB7Qm9vbGVhbn0gdHJ1ZSBpZiB0aGUgZW1haWwgYWRkcmVzcyBpcyBkZWZpbmVkIGluIHRoZSBzcGVjaWZpZWQga2V5XG4gICAqIEBpbm5lclxuICAgKi9cbiAgZnVuY3Rpb24gaWRDaGVjayhpZCwga2V5KSB7XG4gICAgdmFyIGtleWlkcyA9IGtleS5nZXRLZXlJZHMoKTtcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IGtleWlkcy5sZW5ndGg7IGkrKykge1xuICAgICAgaWYgKG9wZW5wZ3AudXRpbC5oZXhzdHJkdW1wKGtleWlkc1tpXS53cml0ZSgpKSA9PSBpZCkge1xuICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIGZhbHNlO1xuICB9XG5cbiAgLyoqXG4gICAqIHNlYXJjaGVzIGFsbCBwdWJsaWMga2V5cyBpbiB0aGUga2V5cmluZyBtYXRjaGluZyB0aGUgYWRkcmVzcyBvciBhZGRyZXNzIHBhcnQgb2YgdGhlIHVzZXIgaWRzXG4gICAqIEBwYXJhbSB7QXJyYXk8bW9kdWxlOmtleX5LZXk+fSBrZXlzIGFycmF5IG9mIGtleXMgdG8gc2VhcmNoXG4gICAqIEBwYXJhbSB7bW9kdWxlOmtleXJpbmcva2V5cmluZy5jaGVja0NhbGxiYWNrfSBpZGVudGl0eUZ1bmN0aW9uIGNhbGxiYWNrIGZ1bmN0aW9uIHdoaWNoIGNoZWNrcyBmb3IgYSBtYXRjaFxuICAgKiBAcGFyYW0ge1N0cmluZ30gaWRlbnRpdHlJbnB1dCBpbnB1dCB0byBjaGVjayBhZ2FpbnN0XG4gICAqIEBwYXJhbSB7bW9kdWxlOmVudW1zLnBhY2tldH0ga2V5VHlwZSBwYWNrZXQgdHlwZXMgb2Yga2V5cyB0byBjaGVja1xuICAgKiBAcmV0dXJuIHtBcnJheTxtb2R1bGU6a2V5fktleT59IGFycmF5IG9mIGtleXMgd2hpY2ggbWF0Y2hcbiAgICovXG4gIGZ1bmN0aW9uIGNoZWNrRm9ySWRlbnRpdHlBbmRLZXlUeXBlTWF0Y2goa2V5cywgaWRlbnRpdHlGdW5jdGlvbiwgaWRlbnRpdHlJbnB1dCwga2V5VHlwZSkge1xuICAgIHZhciByZXN1bHRzID0gW107XG4gICAgZm9yICh2YXIgcCA9IDA7IHAgPCBrZXlzLmxlbmd0aDsgcCsrKSB7XG4gICAgICB2YXIga2V5ID0ga2V5c1twXTtcbiAgICAgIHN3aXRjaCAoa2V5VHlwZSkge1xuICAgICAgICBjYXNlIG9wZW5wZ3AuZW51bXMucGFja2V0LnB1YmxpY19rZXk6XG4gICAgICAgICAgaWYgKGtleS5pc1B1YmxpYygpICYmIGlkZW50aXR5RnVuY3Rpb24oaWRlbnRpdHlJbnB1dCwga2V5KSkge1xuICAgICAgICAgICAgcmVzdWx0cy5wdXNoKGtleSk7XG4gICAgICAgICAgfVxuICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlIG9wZW5wZ3AuZW51bXMucGFja2V0LnByaXZhdGVfa2V5OlxuICAgICAgICAgIGlmIChrZXkuaXNQcml2YXRlKCkgJiYgaWRlbnRpdHlGdW5jdGlvbihpZGVudGl0eUlucHV0LCBrZXkpKSB7XG4gICAgICAgICAgICByZXN1bHRzLnB1c2goa2V5KTtcbiAgICAgICAgICB9XG4gICAgICAgICAgYnJlYWs7XG4gICAgICB9XG4gICAgfVxuICAgIHJldHVybiByZXN1bHRzO1xuICB9XG5cbiAgLyoqXG4gICAqIHNlYXJjaGVzIGFsbCBwdWJsaWMga2V5cyBpbiB0aGUga2V5cmluZyBtYXRjaGluZyB0aGUgYWRkcmVzcyBvciBhZGRyZXNzIHBhcnQgb2YgdGhlIHVzZXIgaWRzXG4gICAqIEBwYXJhbSB7U3RyaW5nfSBlbWFpbCBlbWFpbCBhZGRyZXNzIHRvIHNlYXJjaCBmb3JcbiAgICogQHJldHVybiB7QXJyYXk8bW9kdWxlOmtleX5LZXk+fSBUaGUgcHVibGljIGtleXMgYXNzb2NpYXRlZCB3aXRoIHByb3ZpZGVkIGVtYWlsIGFkZHJlc3MuXG4gICAqL1xuICB0aGlzLmdldFB1YmxpY0tleUZvckFkZHJlc3MgPSBmdW5jdGlvbiAoZW1haWwpIHtcbiAgICByZXR1cm4gY2hlY2tGb3JJZGVudGl0eUFuZEtleVR5cGVNYXRjaCh0aGlzLmtleXMsIGVtYWlsQ2hlY2ssIGVtYWlsLCBvcGVucGdwLmVudW1zLnBhY2tldC5wdWJsaWNfa2V5KTtcbiAgfTtcblxuICAvKipcbiAgICogU2VhcmNoZXMgdGhlIGtleXJpbmcgZm9yIGEgcHJpdmF0ZSBrZXkgY29udGFpbmluZyB0aGUgc3BlY2lmaWVkIGVtYWlsIGFkZHJlc3NcbiAgICogQHBhcmFtIHtTdHJpbmd9IGVtYWlsIGVtYWlsIGFkZHJlc3MgdG8gc2VhcmNoIGZvclxuICAgKiBAcmV0dXJuIHtBcnJheTxtb2R1bGU6a2V5fktleT59IHByaXZhdGUga2V5cyBmb3VuZFxuICAgKi9cbiAgdGhpcy5nZXRQcml2YXRlS2V5Rm9yQWRkcmVzcyA9IGZ1bmN0aW9uIChlbWFpbCkge1xuICAgIHJldHVybiBjaGVja0ZvcklkZW50aXR5QW5kS2V5VHlwZU1hdGNoKHRoaXMua2V5cywgZW1haWxDaGVjaywgZW1haWwsIG9wZW5wZ3AuZW51bXMucGFja2V0LnNlY3JldF9rZXkpO1xuICB9O1xuXG4gIC8qKlxuICAgKiBTZWFyY2hlcyB0aGUga2V5cmluZyBmb3IgcHVibGljIGtleXMgaGF2aW5nIHRoZSBzcGVjaWZpZWQga2V5IGlkXG4gICAqIEBwYXJhbSB7U3RyaW5nfSBrZXlJZCBwcm92aWRlZCBhcyBzdHJpbmcgb2YgaGV4IG51bWJlciAobG93ZXJjYXNlKVxuICAgKiBAcmV0dXJuIHtBcnJheTxtb2R1bGU6a2V5fktleT59IHB1YmxpYyBrZXlzIGZvdW5kXG4gICAqL1xuICB0aGlzLmdldEtleXNGb3JLZXlJZCA9IGZ1bmN0aW9uIChrZXlJZCkge1xuICAgIHJldHVybiBjaGVja0ZvcklkZW50aXR5QW5kS2V5VHlwZU1hdGNoKHRoaXMua2V5cywgaWRDaGVjaywga2V5SWQsIG9wZW5wZ3AuZW51bXMucGFja2V0LnB1YmxpY19rZXkpO1xuICB9O1xuXG4gIC8qKlxuICAgKiBJbXBvcnRzIGEga2V5IGZyb20gYW4gYXNjaWkgYXJtb3JlZCBtZXNzYWdlXG4gICAqIEBwYXJhbSB7U3RyaW5nfSBhcm1vcmVkIG1lc3NhZ2UgdG8gcmVhZCB0aGUga2V5cy9rZXkgZnJvbVxuICAgKi9cbiAgdGhpcy5pbXBvcnRLZXkgPSBmdW5jdGlvbiAoYXJtb3JlZCkge1xuICAgIHRoaXMua2V5cyA9IHRoaXMua2V5cy5jb25jYXQob3BlbnBncC5rZXkucmVhZEFybW9yZWQoYXJtb3JlZCkua2V5cyk7XG5cbiAgICByZXR1cm4gdHJ1ZTtcbiAgfTtcblxuICAvKipcbiAgICogcmV0dXJucyB0aGUgYXJtb3JlZCBtZXNzYWdlIHJlcHJlc2VudGF0aW9uIG9mIHRoZSBrZXkgYXQga2V5IHJpbmcgaW5kZXhcbiAgICogQHBhcmFtIHtJbnRlZ2VyfSBpbmRleCB0aGUgaW5kZXggb2YgdGhlIGtleSB3aXRoaW4gdGhlIGFycmF5XG4gICAqIEByZXR1cm4ge1N0cmluZ30gYXJtb3JlZCBtZXNzYWdlIHJlcHJlc2VudGluZyB0aGUga2V5IG9iamVjdFxuICAgKi9cbiAgdGhpcy5leHBvcnRLZXkgPSBmdW5jdGlvbiAoaW5kZXgpIHtcbiAgICByZXR1cm4gdGhpcy5rZXlzW2luZGV4XS5hcm1vcigpO1xuICB9O1xuXG4gIC8qKlxuICAgKiBSZW1vdmVzIGEgcHVibGljIGtleSBmcm9tIHRoZSBwdWJsaWMga2V5IGtleXJpbmcgYXQgdGhlIHNwZWNpZmllZCBpbmRleFxuICAgKiBAcGFyYW0ge0ludGVnZXJ9IGluZGV4IHRoZSBpbmRleCBvZiB0aGUgcHVibGljIGtleSB3aXRoaW4gdGhlIHB1YmxpY0tleXMgYXJyYXlcbiAgICogQHJldHVybiB7bW9kdWxlOmtleX5LZXl9IFRoZSBwdWJsaWMga2V5IG9iamVjdCB3aGljaCBoYXMgYmVlbiByZW1vdmVkXG4gICAqL1xuICB0aGlzLnJlbW92ZUtleSA9IGZ1bmN0aW9uIChpbmRleCkge1xuICAgIHZhciByZW1vdmVkID0gdGhpcy5rZXlzLnNwbGljZShpbmRleCwgMSk7XG5cbiAgICByZXR1cm4gcmVtb3ZlZDtcbiAgfTtcblxuICAvKipcbiAgICogcmV0dXJucyB0aGUgYXJtb3JlZCBtZXNzYWdlIHJlcHJlc2VudGF0aW9uIG9mIHRoZSBwdWJsaWMga2V5IHBvcnRpb24gb2YgdGhlIGtleSBhdCBrZXkgcmluZyBpbmRleFxuICAgKiBAcGFyYW0ge0ludGVnZXJ9IGluZGV4IHRoZSBpbmRleCBvZiB0aGUga2V5IHdpdGhpbiB0aGUgYXJyYXlcbiAgICogQHJldHVybiB7U3RyaW5nfSBhcm1vcmVkIG1lc3NhZ2UgcmVwcmVzZW50aW5nIHRoZSBwdWJsaWMga2V5IG9iamVjdFxuICAgKi9cbiAgdGhpcy5leHBvcnRQdWJsaWNLZXkgPSBmdW5jdGlvbiAoaW5kZXgpIHtcbiAgICByZXR1cm4gdGhpcy5rZXlzW2luZGV4XS50b1B1YmxpYygpLmFybW9yKCk7XG4gIH07XG59O1xuIiwiLy8gR1BHNEJyb3dzZXJzIC0gQW4gT3BlblBHUCBpbXBsZW1lbnRhdGlvbiBpbiBqYXZhc2NyaXB0XG4vLyBDb3B5cmlnaHQgKEMpIDIwMTEgUmVjdXJpdHkgTGFicyBHbWJIXG4vLyBcbi8vIFRoaXMgbGlicmFyeSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3Jcbi8vIG1vZGlmeSBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBMZXNzZXIgR2VuZXJhbCBQdWJsaWNcbi8vIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5IHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlclxuLy8gdmVyc2lvbiAyLjEgb2YgdGhlIExpY2Vuc2UsIG9yIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4vLyBcbi8vIFRoaXMgbGlicmFyeSBpcyBkaXN0cmlidXRlZCBpbiB0aGUgaG9wZSB0aGF0IGl0IHdpbGwgYmUgdXNlZnVsLFxuLy8gYnV0IFdJVEhPVVQgQU5ZIFdBUlJBTlRZOyB3aXRob3V0IGV2ZW4gdGhlIGltcGxpZWQgd2FycmFudHkgb2Zcbi8vIE1FUkNIQU5UQUJJTElUWSBvciBGSVRORVNTIEZPUiBBIFBBUlRJQ1VMQVIgUFVSUE9TRS4gIFNlZSB0aGUgR05VXG4vLyBMZXNzZXIgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBmb3IgbW9yZSBkZXRhaWxzLlxuLy8gXG4vLyBZb3Ugc2hvdWxkIGhhdmUgcmVjZWl2ZWQgYSBjb3B5IG9mIHRoZSBHTlUgTGVzc2VyIEdlbmVyYWwgUHVibGljXG4vLyBMaWNlbnNlIGFsb25nIHdpdGggdGhpcyBsaWJyYXJ5OyBpZiBub3QsIHdyaXRlIHRvIHRoZSBGcmVlIFNvZnR3YXJlXG4vLyBGb3VuZGF0aW9uLCBJbmMuLCA1MSBGcmFua2xpbiBTdHJlZXQsIEZpZnRoIEZsb29yLCBCb3N0b24sIE1BICAwMjExMC0xMzAxICBVU0FcblxuLyoqXG4gKiBUaGUgY2xhc3MgdGhhdCBkZWFscyB3aXRoIHN0b3JhZ2Ugb2YgdGhlIGtleXJpbmcuIEN1cnJlbnRseSB0aGUgb25seSBvcHRpb24gaXMgdG8gdXNlIEhUTUw1IGxvY2FsIHN0b3JhZ2UuXG4gKiBAcmVxdWlyZXMgb3BlbnBncFxuICogQG1vZHVsZSBrZXlyaW5nL2xvY2Fsc3RvcmVcbiAqL1xuXG52YXIgb3BlbnBncCA9IHJlcXVpcmUoJ29wZW5wZ3AnKTtcblxubW9kdWxlLmV4cG9ydHMgPSBmdW5jdGlvbiAoKSB7XG4gIC8qKlxuICAgKiBMb2FkIHRoZSBrZXlyaW5nIGZyb20gSFRNTDUgbG9jYWwgc3RvcmFnZSBhbmQgaW5pdGlhbGl6ZXMgdGhpcyBpbnN0YW5jZS5cbiAgICogQHJldHVybiB7QXJyYXk8bW9kdWxlOmtleX5LZXk+fSBhcnJheSBvZiBrZXlzIHJldHJpZXZlZCBmcm9tIGxvY2Fsc3RvcmVcbiAgICovXG4gIHRoaXMubG9hZCA9IGZ1bmN0aW9uICgpIHtcbiAgICB2YXIgYXJtb3JlZEtleXMgPSBKU09OLnBhcnNlKHdpbmRvdy5sb2NhbFN0b3JhZ2UuZ2V0SXRlbShcImFybW9yZWRLZXlzXCIpKTtcbiAgICB2YXIga2V5cyA9IFtdO1xuICAgIGlmIChhcm1vcmVkS2V5cyAhPT0gbnVsbCAmJiBhcm1vcmVkS2V5cy5sZW5ndGggIT09IDApIHtcbiAgICAgIHZhciBrZXk7XG4gICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGFybW9yZWRLZXlzLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgIGtleSA9IG9wZW5wZ3Aua2V5LnJlYWRBcm1vcmVkKGFybW9yZWRLZXlzW2ldKTtcbiAgICAgICAga2V5cy5wdXNoKGtleSk7XG4gICAgICB9XG4gICAgfVxuICAgIHJldHVybiBrZXlzO1xuICB9XG5cbiAgLyoqXG4gICAqIFNhdmVzIHRoZSBjdXJyZW50IHN0YXRlIG9mIHRoZSBrZXlyaW5nIHRvIEhUTUw1IGxvY2FsIHN0b3JhZ2UuXG4gICAqIFRoZSBwcml2YXRlS2V5cyBhcnJheSBhbmQgcHVibGljS2V5cyBhcnJheSBnZXRzIFN0cmluZ2lmaWVkIHVzaW5nIEpTT05cbiAgICogQHBhcmFtIHtBcnJheTxtb2R1bGU6a2V5fktleT59IGtleXMgYXJyYXkgb2Yga2V5cyB0byBzYXZlIGluIGxvY2Fsc3RvcmVcbiAgICovXG4gIHRoaXMuc3RvcmUgPSBmdW5jdGlvbiAoa2V5cykge1xuICAgIHZhciBhcm1vcmVkS2V5cyA9IFtdO1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwga2V5cy5sZW5ndGg7IGkrKykge1xuICAgICAgYXJtb3JlZEtleXMucHVzaChrZXlzW2ldLmFybW9yKCkpO1xuICAgIH1cbiAgICB3aW5kb3cubG9jYWxTdG9yYWdlLnNldEl0ZW0oXCJhcm1vcmVkS2V5c1wiLCBKU09OLnN0cmluZ2lmeShhcm1vcmVkS2V5cykpO1xuICB9XG59O1xuIl19
;