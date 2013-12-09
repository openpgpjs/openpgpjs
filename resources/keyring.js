require=(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);throw new Error("Cannot find module '"+o+"'")}var f=n[o]={exports:{}};t[o][0].call(f.exports,function(e){var n=t[o][1][e];return s(n?n:e)},f,f.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({"RRTcVk":[function(require,module,exports){

module.exports = require('./keyring.js');
module.exports.localstore = require('./localstore.js');

},{"./keyring.js":3,"./localstore.js":4}],"keyring":[function(require,module,exports){
module.exports=require('RRTcVk');
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

var openpgp = require('openpgp');

/**
 * @class
 * @classdesc The class that deals with storage of the keyring. Currently the only option is to use HTML5 local storage.
 */
var keyring = function() {
  this.keys = [];

  /**
   * Initialization routine for the keyring. This method reads the 
   * keyring from HTML5 local storage and initializes this instance.
   * This method is called by openpgp.init().
   */
  function init(storeHandler) {
    this.storeHandler = storeHandler ? storeHandler : require('./localstore');
    this.keys = [];
    this.storeHandler.init(this.keys);
  }
  this.init = init;

  this.store = function () {
    this.storeHandler.store(this.keys);
  }

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

  function idCheck(id, key) {
    var keyids = key.getKeyIds();
    for (var i = 0; i < keyids.length; i++) {
      if (openpgp.util.hexstrdump(keyids[i].write()) == id) {
        return true;
      }
      return false;
    }
  }

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
  this.checkForIdentityAndKeyTypeMatch = checkForIdentityAndKeyTypeMatch;

  /**
   * searches all public keys in the keyring matching the address or address part of the user ids
   * @param {String} email email address to search for
   * @return {openpgp.key.Key[]} The public keys associated with provided email address.
   */
  function getPublicKeyForAddress(email) {
    return checkForIdentityAndKeyTypeMatch(this.keys, emailCheck, email, openpgp.enums.packet.public_key);
  }
  this.getPublicKeyForAddress = getPublicKeyForAddress;

  /**
   * Searches the keyring for a private key containing the specified email address
   * @param {String} email email address to search for
   * @return {openpgp.key.Key[]} private keys found
   */
  function getPrivateKeyForAddress(email) {
    return checkForIdentityAndKeyTypeMatch(this.keys, emailCheck, email, openpgp.enums.packet.secret_key);
  }
  this.getPrivateKeyForAddress = getPrivateKeyForAddress;

  /**
   * Searches the keyring for public keys having the specified key id
   * @param {String} keyId provided as string of hex number (lowercase)
   * @return {openpgp.key.Key[]} public keys found
   */
  function getKeysForKeyId(keyId) {
    return this.checkForIdentityAndKeyTypeMatch(this.keys, idCheck, keyId, openpgp.enums.packet.public_key);
  }
  this.getKeysForKeyId = getKeysForKeyId;

  /**
   * Imports a key from an ascii armored message
   * @param {String} armored message to read the keys/key from
   */
  function importKey(armored) {
    this.keys.push(openpgp.key.readArmored(armored));

    return true;
  }
  this.importKey = importKey;

  /**
   * returns the armored message representation of the key at key ring index
   * @param {Integer} index the index of the key within the array
   * @return {String} armored message representing the key object
   */
  function exportKey(index) {
    return this.keys[index].armor();
  }
  this.exportKey = exportKey;

  /**
   * Removes a public key from the public key keyring at the specified index 
   * @param {Integer} index the index of the public key within the publicKeys array
   * @return {openpgp.key.Key} The public key object which has been removed
   */
  function removeKey(index) {
    var removed = this.keys.splice(index, 1);

    return removed;
  }
  this.removeKey = removeKey;

  /**
   * returns the armored message representation of the public key portion of the key at key ring index
   * @param {Integer} index the index of the key within the array
   * @return {String} armored message representing the public key object
   */
  function exportPublicKey(index) {
    return this.keys[index].toPublic().armor();
  }
  this.exportPublicKey = exportPublicKey;

};

module.exports = new keyring();

},{"./localstore":4}],4:[function(require,module,exports){
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

var openpgp = require('openpgp');

/**
 * @class
 * @classdesc The class that deals with storage of the keyring. Currently the only option is to use HTML5 local storage.
 */
var localstore = function() {
  /**
   * Initialization routine for the keyring. This method reads the 
   * keyring from HTML5 local storage and initializes this instance.
   * This method is called by openpgp.init().
   */
  function init(keys) {
    var armoredKeys = JSON.parse(window.localStorage.getItem("armoredKeys"));
    if (armoredKeys !== null && armoredKeys.length === 0) {
      var key;
      for (var i = 0; i < armoredKeys.length; i++) {
        key = openpgp.key.readArmored(armoredKeys[i]);
        keys.push(key);
      }
    } else {
      this.keys = [];
    }
  }
  this.init = init;

  /**
   * Saves the current state of the keyring to HTML5 local storage.
   * The privateKeys array and publicKeys array gets Stringified using JSON
   */
  function store(keys) {
    var armoredKeys = [];
    for (var i = 0; i < keys.length; i++) {
      armoredKeys.push(keys[i].armor());
    }
    window.localStorage.setItem("armoredKeys", JSON.stringify(armoredKeys));
  }
  this.store = store;
};

module.exports = new localstore();

},{}]},{},[])
//@ sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZ2VuZXJhdGVkLmpzIiwic291cmNlcyI6WyIvaG9tZS9yb2JlcnQvemltYnJhLXBncC9vcGVucGdwanMta2V5cmluZy9zcmMva2V5cmluZy9pbmRleC5qcyIsIi9ob21lL3JvYmVydC96aW1icmEtcGdwL29wZW5wZ3Bqcy1rZXlyaW5nL3NyYy9rZXlyaW5nL2tleXJpbmcuanMiLCIvaG9tZS9yb2JlcnQvemltYnJhLXBncC9vcGVucGdwanMta2V5cmluZy9zcmMva2V5cmluZy9sb2NhbHN0b3JlLmpzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFBQTtBQUNBO0FBQ0E7QUFDQTs7OztBQ0hBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ2xLQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBIiwic291cmNlc0NvbnRlbnQiOlsiXG5tb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoJy4va2V5cmluZy5qcycpO1xubW9kdWxlLmV4cG9ydHMubG9jYWxzdG9yZSA9IHJlcXVpcmUoJy4vbG9jYWxzdG9yZS5qcycpO1xuIiwiLy8gR1BHNEJyb3dzZXJzIC0gQW4gT3BlblBHUCBpbXBsZW1lbnRhdGlvbiBpbiBqYXZhc2NyaXB0XG4vLyBDb3B5cmlnaHQgKEMpIDIwMTEgUmVjdXJpdHkgTGFicyBHbWJIXG4vLyBcbi8vIFRoaXMgbGlicmFyeSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3Jcbi8vIG1vZGlmeSBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBMZXNzZXIgR2VuZXJhbCBQdWJsaWNcbi8vIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5IHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlclxuLy8gdmVyc2lvbiAyLjEgb2YgdGhlIExpY2Vuc2UsIG9yIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4vLyBcbi8vIFRoaXMgbGlicmFyeSBpcyBkaXN0cmlidXRlZCBpbiB0aGUgaG9wZSB0aGF0IGl0IHdpbGwgYmUgdXNlZnVsLFxuLy8gYnV0IFdJVEhPVVQgQU5ZIFdBUlJBTlRZOyB3aXRob3V0IGV2ZW4gdGhlIGltcGxpZWQgd2FycmFudHkgb2Zcbi8vIE1FUkNIQU5UQUJJTElUWSBvciBGSVRORVNTIEZPUiBBIFBBUlRJQ1VMQVIgUFVSUE9TRS4gIFNlZSB0aGUgR05VXG4vLyBMZXNzZXIgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBmb3IgbW9yZSBkZXRhaWxzLlxuLy8gXG4vLyBZb3Ugc2hvdWxkIGhhdmUgcmVjZWl2ZWQgYSBjb3B5IG9mIHRoZSBHTlUgTGVzc2VyIEdlbmVyYWwgUHVibGljXG4vLyBMaWNlbnNlIGFsb25nIHdpdGggdGhpcyBsaWJyYXJ5OyBpZiBub3QsIHdyaXRlIHRvIHRoZSBGcmVlIFNvZnR3YXJlXG4vLyBGb3VuZGF0aW9uLCBJbmMuLCA1MSBGcmFua2xpbiBTdHJlZXQsIEZpZnRoIEZsb29yLCBCb3N0b24sIE1BICAwMjExMC0xMzAxICBVU0FcblxudmFyIG9wZW5wZ3AgPSByZXF1aXJlKCdvcGVucGdwJyk7XG5cbi8qKlxuICogQGNsYXNzXG4gKiBAY2xhc3NkZXNjIFRoZSBjbGFzcyB0aGF0IGRlYWxzIHdpdGggc3RvcmFnZSBvZiB0aGUga2V5cmluZy4gQ3VycmVudGx5IHRoZSBvbmx5IG9wdGlvbiBpcyB0byB1c2UgSFRNTDUgbG9jYWwgc3RvcmFnZS5cbiAqL1xudmFyIGtleXJpbmcgPSBmdW5jdGlvbigpIHtcbiAgdGhpcy5rZXlzID0gW107XG5cbiAgLyoqXG4gICAqIEluaXRpYWxpemF0aW9uIHJvdXRpbmUgZm9yIHRoZSBrZXlyaW5nLiBUaGlzIG1ldGhvZCByZWFkcyB0aGUgXG4gICAqIGtleXJpbmcgZnJvbSBIVE1MNSBsb2NhbCBzdG9yYWdlIGFuZCBpbml0aWFsaXplcyB0aGlzIGluc3RhbmNlLlxuICAgKiBUaGlzIG1ldGhvZCBpcyBjYWxsZWQgYnkgb3BlbnBncC5pbml0KCkuXG4gICAqL1xuICBmdW5jdGlvbiBpbml0KHN0b3JlSGFuZGxlcikge1xuICAgIHRoaXMuc3RvcmVIYW5kbGVyID0gc3RvcmVIYW5kbGVyID8gc3RvcmVIYW5kbGVyIDogcmVxdWlyZSgnLi9sb2NhbHN0b3JlJyk7XG4gICAgdGhpcy5rZXlzID0gW107XG4gICAgdGhpcy5zdG9yZUhhbmRsZXIuaW5pdCh0aGlzLmtleXMpO1xuICB9XG4gIHRoaXMuaW5pdCA9IGluaXQ7XG5cbiAgdGhpcy5zdG9yZSA9IGZ1bmN0aW9uICgpIHtcbiAgICB0aGlzLnN0b3JlSGFuZGxlci5zdG9yZSh0aGlzLmtleXMpO1xuICB9XG5cbiAgZnVuY3Rpb24gZW1haWxDaGVjayhlbWFpbCwga2V5KSB7XG4gICAgZW1haWwgPSBlbWFpbC50b0xvd2VyQ2FzZSgpO1xuICAgIHZhciBrZXlFbWFpbHMgPSBrZXkuZ2V0VXNlcklkcygpO1xuICAgIGZvciAodmFyIGk7IGkgPCBrZXlFbWFpbHMubGVuZ3RoOyBpKyspIHtcbiAgICAgIC8vd2UgbmVlZCB0byBnZXQganVzdCB0aGUgZW1haWwgZnJvbSB0aGUgdXNlcmlkIGtleVxuICAgICAga2V5RW1haWwgPSBrZXlFbWFpbHNbaV0uc3BsaXQoJzwnKVsxXS5zcGxpdCgnPicpWzBdLnRyaW0oKS50b0xvd2VyQ2FzZSgpO1xuICAgICAgaWYgKGtleUVtYWlsID09IGVtYWlsKSB7XG4gICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cblxuICBmdW5jdGlvbiBpZENoZWNrKGlkLCBrZXkpIHtcbiAgICB2YXIga2V5aWRzID0ga2V5LmdldEtleUlkcygpO1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwga2V5aWRzLmxlbmd0aDsgaSsrKSB7XG4gICAgICBpZiAob3BlbnBncC51dGlsLmhleHN0cmR1bXAoa2V5aWRzW2ldLndyaXRlKCkpID09IGlkKSB7XG4gICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgfVxuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cbiAgfVxuXG4gIGZ1bmN0aW9uIGNoZWNrRm9ySWRlbnRpdHlBbmRLZXlUeXBlTWF0Y2goa2V5cywgaWRlbnRpdHlGdW5jdGlvbiwgaWRlbnRpdHlJbnB1dCwga2V5VHlwZSkge1xuICAgIHZhciByZXN1bHRzID0gW107XG4gICAgZm9yICh2YXIgcCA9IDA7IHAgPCBrZXlzLmxlbmd0aDsgcCsrKSB7XG4gICAgICB2YXIga2V5ID0ga2V5c1twXTtcbiAgICAgIHN3aXRjaCAoa2V5VHlwZSkge1xuICAgICAgICBjYXNlIG9wZW5wZ3AuZW51bXMucGFja2V0LnB1YmxpY19rZXk6XG4gICAgICAgICAgaWYgKGtleS5pc1B1YmxpYygpICYmIGlkZW50aXR5RnVuY3Rpb24oaWRlbnRpdHlJbnB1dCwga2V5KSkge1xuICAgICAgICAgICAgcmVzdWx0cy5wdXNoKGtleSk7XG4gICAgICAgICAgfVxuICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlIG9wZW5wZ3AuZW51bXMucGFja2V0LnByaXZhdGVfa2V5OlxuICAgICAgICAgIGlmIChrZXkuaXNQcml2YXRlKCkgJiYgaWRlbnRpdHlGdW5jdGlvbihpZGVudGl0eUlucHV0LCBrZXkpKSB7XG4gICAgICAgICAgICByZXN1bHRzLnB1c2goa2V5KTtcbiAgICAgICAgICB9XG4gICAgICAgICAgYnJlYWs7XG4gICAgICB9XG4gICAgfVxuICAgIHJldHVybiByZXN1bHRzO1xuICB9XG4gIHRoaXMuY2hlY2tGb3JJZGVudGl0eUFuZEtleVR5cGVNYXRjaCA9IGNoZWNrRm9ySWRlbnRpdHlBbmRLZXlUeXBlTWF0Y2g7XG5cbiAgLyoqXG4gICAqIHNlYXJjaGVzIGFsbCBwdWJsaWMga2V5cyBpbiB0aGUga2V5cmluZyBtYXRjaGluZyB0aGUgYWRkcmVzcyBvciBhZGRyZXNzIHBhcnQgb2YgdGhlIHVzZXIgaWRzXG4gICAqIEBwYXJhbSB7U3RyaW5nfSBlbWFpbCBlbWFpbCBhZGRyZXNzIHRvIHNlYXJjaCBmb3JcbiAgICogQHJldHVybiB7b3BlbnBncC5rZXkuS2V5W119IFRoZSBwdWJsaWMga2V5cyBhc3NvY2lhdGVkIHdpdGggcHJvdmlkZWQgZW1haWwgYWRkcmVzcy5cbiAgICovXG4gIGZ1bmN0aW9uIGdldFB1YmxpY0tleUZvckFkZHJlc3MoZW1haWwpIHtcbiAgICByZXR1cm4gY2hlY2tGb3JJZGVudGl0eUFuZEtleVR5cGVNYXRjaCh0aGlzLmtleXMsIGVtYWlsQ2hlY2ssIGVtYWlsLCBvcGVucGdwLmVudW1zLnBhY2tldC5wdWJsaWNfa2V5KTtcbiAgfVxuICB0aGlzLmdldFB1YmxpY0tleUZvckFkZHJlc3MgPSBnZXRQdWJsaWNLZXlGb3JBZGRyZXNzO1xuXG4gIC8qKlxuICAgKiBTZWFyY2hlcyB0aGUga2V5cmluZyBmb3IgYSBwcml2YXRlIGtleSBjb250YWluaW5nIHRoZSBzcGVjaWZpZWQgZW1haWwgYWRkcmVzc1xuICAgKiBAcGFyYW0ge1N0cmluZ30gZW1haWwgZW1haWwgYWRkcmVzcyB0byBzZWFyY2ggZm9yXG4gICAqIEByZXR1cm4ge29wZW5wZ3Aua2V5LktleVtdfSBwcml2YXRlIGtleXMgZm91bmRcbiAgICovXG4gIGZ1bmN0aW9uIGdldFByaXZhdGVLZXlGb3JBZGRyZXNzKGVtYWlsKSB7XG4gICAgcmV0dXJuIGNoZWNrRm9ySWRlbnRpdHlBbmRLZXlUeXBlTWF0Y2godGhpcy5rZXlzLCBlbWFpbENoZWNrLCBlbWFpbCwgb3BlbnBncC5lbnVtcy5wYWNrZXQuc2VjcmV0X2tleSk7XG4gIH1cbiAgdGhpcy5nZXRQcml2YXRlS2V5Rm9yQWRkcmVzcyA9IGdldFByaXZhdGVLZXlGb3JBZGRyZXNzO1xuXG4gIC8qKlxuICAgKiBTZWFyY2hlcyB0aGUga2V5cmluZyBmb3IgcHVibGljIGtleXMgaGF2aW5nIHRoZSBzcGVjaWZpZWQga2V5IGlkXG4gICAqIEBwYXJhbSB7U3RyaW5nfSBrZXlJZCBwcm92aWRlZCBhcyBzdHJpbmcgb2YgaGV4IG51bWJlciAobG93ZXJjYXNlKVxuICAgKiBAcmV0dXJuIHtvcGVucGdwLmtleS5LZXlbXX0gcHVibGljIGtleXMgZm91bmRcbiAgICovXG4gIGZ1bmN0aW9uIGdldEtleXNGb3JLZXlJZChrZXlJZCkge1xuICAgIHJldHVybiB0aGlzLmNoZWNrRm9ySWRlbnRpdHlBbmRLZXlUeXBlTWF0Y2godGhpcy5rZXlzLCBpZENoZWNrLCBrZXlJZCwgb3BlbnBncC5lbnVtcy5wYWNrZXQucHVibGljX2tleSk7XG4gIH1cbiAgdGhpcy5nZXRLZXlzRm9yS2V5SWQgPSBnZXRLZXlzRm9yS2V5SWQ7XG5cbiAgLyoqXG4gICAqIEltcG9ydHMgYSBrZXkgZnJvbSBhbiBhc2NpaSBhcm1vcmVkIG1lc3NhZ2VcbiAgICogQHBhcmFtIHtTdHJpbmd9IGFybW9yZWQgbWVzc2FnZSB0byByZWFkIHRoZSBrZXlzL2tleSBmcm9tXG4gICAqL1xuICBmdW5jdGlvbiBpbXBvcnRLZXkoYXJtb3JlZCkge1xuICAgIHRoaXMua2V5cy5wdXNoKG9wZW5wZ3Aua2V5LnJlYWRBcm1vcmVkKGFybW9yZWQpKTtcblxuICAgIHJldHVybiB0cnVlO1xuICB9XG4gIHRoaXMuaW1wb3J0S2V5ID0gaW1wb3J0S2V5O1xuXG4gIC8qKlxuICAgKiByZXR1cm5zIHRoZSBhcm1vcmVkIG1lc3NhZ2UgcmVwcmVzZW50YXRpb24gb2YgdGhlIGtleSBhdCBrZXkgcmluZyBpbmRleFxuICAgKiBAcGFyYW0ge0ludGVnZXJ9IGluZGV4IHRoZSBpbmRleCBvZiB0aGUga2V5IHdpdGhpbiB0aGUgYXJyYXlcbiAgICogQHJldHVybiB7U3RyaW5nfSBhcm1vcmVkIG1lc3NhZ2UgcmVwcmVzZW50aW5nIHRoZSBrZXkgb2JqZWN0XG4gICAqL1xuICBmdW5jdGlvbiBleHBvcnRLZXkoaW5kZXgpIHtcbiAgICByZXR1cm4gdGhpcy5rZXlzW2luZGV4XS5hcm1vcigpO1xuICB9XG4gIHRoaXMuZXhwb3J0S2V5ID0gZXhwb3J0S2V5O1xuXG4gIC8qKlxuICAgKiBSZW1vdmVzIGEgcHVibGljIGtleSBmcm9tIHRoZSBwdWJsaWMga2V5IGtleXJpbmcgYXQgdGhlIHNwZWNpZmllZCBpbmRleCBcbiAgICogQHBhcmFtIHtJbnRlZ2VyfSBpbmRleCB0aGUgaW5kZXggb2YgdGhlIHB1YmxpYyBrZXkgd2l0aGluIHRoZSBwdWJsaWNLZXlzIGFycmF5XG4gICAqIEByZXR1cm4ge29wZW5wZ3Aua2V5LktleX0gVGhlIHB1YmxpYyBrZXkgb2JqZWN0IHdoaWNoIGhhcyBiZWVuIHJlbW92ZWRcbiAgICovXG4gIGZ1bmN0aW9uIHJlbW92ZUtleShpbmRleCkge1xuICAgIHZhciByZW1vdmVkID0gdGhpcy5rZXlzLnNwbGljZShpbmRleCwgMSk7XG5cbiAgICByZXR1cm4gcmVtb3ZlZDtcbiAgfVxuICB0aGlzLnJlbW92ZUtleSA9IHJlbW92ZUtleTtcblxuICAvKipcbiAgICogcmV0dXJucyB0aGUgYXJtb3JlZCBtZXNzYWdlIHJlcHJlc2VudGF0aW9uIG9mIHRoZSBwdWJsaWMga2V5IHBvcnRpb24gb2YgdGhlIGtleSBhdCBrZXkgcmluZyBpbmRleFxuICAgKiBAcGFyYW0ge0ludGVnZXJ9IGluZGV4IHRoZSBpbmRleCBvZiB0aGUga2V5IHdpdGhpbiB0aGUgYXJyYXlcbiAgICogQHJldHVybiB7U3RyaW5nfSBhcm1vcmVkIG1lc3NhZ2UgcmVwcmVzZW50aW5nIHRoZSBwdWJsaWMga2V5IG9iamVjdFxuICAgKi9cbiAgZnVuY3Rpb24gZXhwb3J0UHVibGljS2V5KGluZGV4KSB7XG4gICAgcmV0dXJuIHRoaXMua2V5c1tpbmRleF0udG9QdWJsaWMoKS5hcm1vcigpO1xuICB9XG4gIHRoaXMuZXhwb3J0UHVibGljS2V5ID0gZXhwb3J0UHVibGljS2V5O1xuXG59O1xuXG5tb2R1bGUuZXhwb3J0cyA9IG5ldyBrZXlyaW5nKCk7XG4iLCIvLyBHUEc0QnJvd3NlcnMgLSBBbiBPcGVuUEdQIGltcGxlbWVudGF0aW9uIGluIGphdmFzY3JpcHRcbi8vIENvcHlyaWdodCAoQykgMjAxMSBSZWN1cml0eSBMYWJzIEdtYkhcbi8vIFxuLy8gVGhpcyBsaWJyYXJ5IGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vclxuLy8gbW9kaWZ5IGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIExlc3NlciBHZW5lcmFsIFB1YmxpY1xuLy8gTGljZW5zZSBhcyBwdWJsaXNoZWQgYnkgdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyXG4vLyB2ZXJzaW9uIDIuMSBvZiB0aGUgTGljZW5zZSwgb3IgKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbi8vIFxuLy8gVGhpcyBsaWJyYXJ5IGlzIGRpc3RyaWJ1dGVkIGluIHRoZSBob3BlIHRoYXQgaXQgd2lsbCBiZSB1c2VmdWwsXG4vLyBidXQgV0lUSE9VVCBBTlkgV0FSUkFOVFk7IHdpdGhvdXQgZXZlbiB0aGUgaW1wbGllZCB3YXJyYW50eSBvZlxuLy8gTUVSQ0hBTlRBQklMSVRZIG9yIEZJVE5FU1MgRk9SIEEgUEFSVElDVUxBUiBQVVJQT1NFLiAgU2VlIHRoZSBHTlVcbi8vIExlc3NlciBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGZvciBtb3JlIGRldGFpbHMuXG4vLyBcbi8vIFlvdSBzaG91bGQgaGF2ZSByZWNlaXZlZCBhIGNvcHkgb2YgdGhlIEdOVSBMZXNzZXIgR2VuZXJhbCBQdWJsaWNcbi8vIExpY2Vuc2UgYWxvbmcgd2l0aCB0aGlzIGxpYnJhcnk7IGlmIG5vdCwgd3JpdGUgdG8gdGhlIEZyZWUgU29mdHdhcmVcbi8vIEZvdW5kYXRpb24sIEluYy4sIDUxIEZyYW5rbGluIFN0cmVldCwgRmlmdGggRmxvb3IsIEJvc3RvbiwgTUEgIDAyMTEwLTEzMDEgIFVTQVxuXG52YXIgb3BlbnBncCA9IHJlcXVpcmUoJ29wZW5wZ3AnKTtcblxuLyoqXG4gKiBAY2xhc3NcbiAqIEBjbGFzc2Rlc2MgVGhlIGNsYXNzIHRoYXQgZGVhbHMgd2l0aCBzdG9yYWdlIG9mIHRoZSBrZXlyaW5nLiBDdXJyZW50bHkgdGhlIG9ubHkgb3B0aW9uIGlzIHRvIHVzZSBIVE1MNSBsb2NhbCBzdG9yYWdlLlxuICovXG52YXIgbG9jYWxzdG9yZSA9IGZ1bmN0aW9uKCkge1xuICAvKipcbiAgICogSW5pdGlhbGl6YXRpb24gcm91dGluZSBmb3IgdGhlIGtleXJpbmcuIFRoaXMgbWV0aG9kIHJlYWRzIHRoZSBcbiAgICoga2V5cmluZyBmcm9tIEhUTUw1IGxvY2FsIHN0b3JhZ2UgYW5kIGluaXRpYWxpemVzIHRoaXMgaW5zdGFuY2UuXG4gICAqIFRoaXMgbWV0aG9kIGlzIGNhbGxlZCBieSBvcGVucGdwLmluaXQoKS5cbiAgICovXG4gIGZ1bmN0aW9uIGluaXQoa2V5cykge1xuICAgIHZhciBhcm1vcmVkS2V5cyA9IEpTT04ucGFyc2Uod2luZG93LmxvY2FsU3RvcmFnZS5nZXRJdGVtKFwiYXJtb3JlZEtleXNcIikpO1xuICAgIGlmIChhcm1vcmVkS2V5cyAhPT0gbnVsbCAmJiBhcm1vcmVkS2V5cy5sZW5ndGggPT09IDApIHtcbiAgICAgIHZhciBrZXk7XG4gICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGFybW9yZWRLZXlzLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgIGtleSA9IG9wZW5wZ3Aua2V5LnJlYWRBcm1vcmVkKGFybW9yZWRLZXlzW2ldKTtcbiAgICAgICAga2V5cy5wdXNoKGtleSk7XG4gICAgICB9XG4gICAgfSBlbHNlIHtcbiAgICAgIHRoaXMua2V5cyA9IFtdO1xuICAgIH1cbiAgfVxuICB0aGlzLmluaXQgPSBpbml0O1xuXG4gIC8qKlxuICAgKiBTYXZlcyB0aGUgY3VycmVudCBzdGF0ZSBvZiB0aGUga2V5cmluZyB0byBIVE1MNSBsb2NhbCBzdG9yYWdlLlxuICAgKiBUaGUgcHJpdmF0ZUtleXMgYXJyYXkgYW5kIHB1YmxpY0tleXMgYXJyYXkgZ2V0cyBTdHJpbmdpZmllZCB1c2luZyBKU09OXG4gICAqL1xuICBmdW5jdGlvbiBzdG9yZShrZXlzKSB7XG4gICAgdmFyIGFybW9yZWRLZXlzID0gW107XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBrZXlzLmxlbmd0aDsgaSsrKSB7XG4gICAgICBhcm1vcmVkS2V5cy5wdXNoKGtleXNbaV0uYXJtb3IoKSk7XG4gICAgfVxuICAgIHdpbmRvdy5sb2NhbFN0b3JhZ2Uuc2V0SXRlbShcImFybW9yZWRLZXlzXCIsIEpTT04uc3RyaW5naWZ5KGFybW9yZWRLZXlzKSk7XG4gIH1cbiAgdGhpcy5zdG9yZSA9IHN0b3JlO1xufTtcblxubW9kdWxlLmV4cG9ydHMgPSBuZXcgbG9jYWxzdG9yZSgpO1xuIl19
;