require=(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);throw new Error("Cannot find module '"+o+"'")}var f=n[o]={exports:{}};t[o][0].call(f.exports,function(e){var n=t[o][1][e];return s(n?n:e)},f,f.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({"vHAI4A":[function(require,module,exports){

module.exports = require('./keyring.js');
module.exports.localstore = require('./localstore.js');

},{"./keyring.js":3,"./localstore.js":4}],"keyring":[function(require,module,exports){
module.exports=require('vHAI4A');
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
    }
    return false;
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
    this.keys = this.keys.concat(openpgp.key.readArmored(armored).keys);

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
//@ sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZ2VuZXJhdGVkLmpzIiwic291cmNlcyI6WyIvaG9tZS90b2Jlcm5kby9kZXYvb3BlbnBncGpzLWRldmVsL3NyYy9rZXlyaW5nL2luZGV4LmpzIiwiL2hvbWUvdG9iZXJuZG8vZGV2L29wZW5wZ3Bqcy1kZXZlbC9zcmMva2V5cmluZy9rZXlyaW5nLmpzIiwiL2hvbWUvdG9iZXJuZG8vZGV2L29wZW5wZ3Bqcy1kZXZlbC9zcmMva2V5cmluZy9sb2NhbHN0b3JlLmpzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFBQTtBQUNBO0FBQ0E7QUFDQTs7OztBQ0hBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ2xLQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBIiwic291cmNlc0NvbnRlbnQiOlsiXG5tb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoJy4va2V5cmluZy5qcycpO1xubW9kdWxlLmV4cG9ydHMubG9jYWxzdG9yZSA9IHJlcXVpcmUoJy4vbG9jYWxzdG9yZS5qcycpO1xuIiwiLy8gR1BHNEJyb3dzZXJzIC0gQW4gT3BlblBHUCBpbXBsZW1lbnRhdGlvbiBpbiBqYXZhc2NyaXB0XG4vLyBDb3B5cmlnaHQgKEMpIDIwMTEgUmVjdXJpdHkgTGFicyBHbWJIXG4vLyBcbi8vIFRoaXMgbGlicmFyeSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3Jcbi8vIG1vZGlmeSBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBMZXNzZXIgR2VuZXJhbCBQdWJsaWNcbi8vIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5IHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlclxuLy8gdmVyc2lvbiAyLjEgb2YgdGhlIExpY2Vuc2UsIG9yIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4vLyBcbi8vIFRoaXMgbGlicmFyeSBpcyBkaXN0cmlidXRlZCBpbiB0aGUgaG9wZSB0aGF0IGl0IHdpbGwgYmUgdXNlZnVsLFxuLy8gYnV0IFdJVEhPVVQgQU5ZIFdBUlJBTlRZOyB3aXRob3V0IGV2ZW4gdGhlIGltcGxpZWQgd2FycmFudHkgb2Zcbi8vIE1FUkNIQU5UQUJJTElUWSBvciBGSVRORVNTIEZPUiBBIFBBUlRJQ1VMQVIgUFVSUE9TRS4gIFNlZSB0aGUgR05VXG4vLyBMZXNzZXIgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBmb3IgbW9yZSBkZXRhaWxzLlxuLy8gXG4vLyBZb3Ugc2hvdWxkIGhhdmUgcmVjZWl2ZWQgYSBjb3B5IG9mIHRoZSBHTlUgTGVzc2VyIEdlbmVyYWwgUHVibGljXG4vLyBMaWNlbnNlIGFsb25nIHdpdGggdGhpcyBsaWJyYXJ5OyBpZiBub3QsIHdyaXRlIHRvIHRoZSBGcmVlIFNvZnR3YXJlXG4vLyBGb3VuZGF0aW9uLCBJbmMuLCA1MSBGcmFua2xpbiBTdHJlZXQsIEZpZnRoIEZsb29yLCBCb3N0b24sIE1BICAwMjExMC0xMzAxICBVU0FcblxudmFyIG9wZW5wZ3AgPSByZXF1aXJlKCdvcGVucGdwJyk7XG5cbi8qKlxuICogQGNsYXNzXG4gKiBAY2xhc3NkZXNjIFRoZSBjbGFzcyB0aGF0IGRlYWxzIHdpdGggc3RvcmFnZSBvZiB0aGUga2V5cmluZy4gQ3VycmVudGx5IHRoZSBvbmx5IG9wdGlvbiBpcyB0byB1c2UgSFRNTDUgbG9jYWwgc3RvcmFnZS5cbiAqL1xudmFyIGtleXJpbmcgPSBmdW5jdGlvbigpIHtcbiAgdGhpcy5rZXlzID0gW107XG5cbiAgLyoqXG4gICAqIEluaXRpYWxpemF0aW9uIHJvdXRpbmUgZm9yIHRoZSBrZXlyaW5nLiBUaGlzIG1ldGhvZCByZWFkcyB0aGUgXG4gICAqIGtleXJpbmcgZnJvbSBIVE1MNSBsb2NhbCBzdG9yYWdlIGFuZCBpbml0aWFsaXplcyB0aGlzIGluc3RhbmNlLlxuICAgKiBUaGlzIG1ldGhvZCBpcyBjYWxsZWQgYnkgb3BlbnBncC5pbml0KCkuXG4gICAqL1xuICBmdW5jdGlvbiBpbml0KHN0b3JlSGFuZGxlcikge1xuICAgIHRoaXMuc3RvcmVIYW5kbGVyID0gc3RvcmVIYW5kbGVyID8gc3RvcmVIYW5kbGVyIDogcmVxdWlyZSgnLi9sb2NhbHN0b3JlJyk7XG4gICAgdGhpcy5rZXlzID0gW107XG4gICAgdGhpcy5zdG9yZUhhbmRsZXIuaW5pdCh0aGlzLmtleXMpO1xuICB9XG4gIHRoaXMuaW5pdCA9IGluaXQ7XG5cbiAgdGhpcy5zdG9yZSA9IGZ1bmN0aW9uICgpIHtcbiAgICB0aGlzLnN0b3JlSGFuZGxlci5zdG9yZSh0aGlzLmtleXMpO1xuICB9XG5cbiAgZnVuY3Rpb24gZW1haWxDaGVjayhlbWFpbCwga2V5KSB7XG4gICAgZW1haWwgPSBlbWFpbC50b0xvd2VyQ2FzZSgpO1xuICAgIHZhciBrZXlFbWFpbHMgPSBrZXkuZ2V0VXNlcklkcygpO1xuICAgIGZvciAodmFyIGk7IGkgPCBrZXlFbWFpbHMubGVuZ3RoOyBpKyspIHtcbiAgICAgIC8vd2UgbmVlZCB0byBnZXQganVzdCB0aGUgZW1haWwgZnJvbSB0aGUgdXNlcmlkIGtleVxuICAgICAga2V5RW1haWwgPSBrZXlFbWFpbHNbaV0uc3BsaXQoJzwnKVsxXS5zcGxpdCgnPicpWzBdLnRyaW0oKS50b0xvd2VyQ2FzZSgpO1xuICAgICAgaWYgKGtleUVtYWlsID09IGVtYWlsKSB7XG4gICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cblxuICBmdW5jdGlvbiBpZENoZWNrKGlkLCBrZXkpIHtcbiAgICB2YXIga2V5aWRzID0ga2V5LmdldEtleUlkcygpO1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwga2V5aWRzLmxlbmd0aDsgaSsrKSB7XG4gICAgICBpZiAob3BlbnBncC51dGlsLmhleHN0cmR1bXAoa2V5aWRzW2ldLndyaXRlKCkpID09IGlkKSB7XG4gICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cblxuICBmdW5jdGlvbiBjaGVja0ZvcklkZW50aXR5QW5kS2V5VHlwZU1hdGNoKGtleXMsIGlkZW50aXR5RnVuY3Rpb24sIGlkZW50aXR5SW5wdXQsIGtleVR5cGUpIHtcbiAgICB2YXIgcmVzdWx0cyA9IFtdO1xuICAgIGZvciAodmFyIHAgPSAwOyBwIDwga2V5cy5sZW5ndGg7IHArKykge1xuICAgICAgdmFyIGtleSA9IGtleXNbcF07XG4gICAgICBzd2l0Y2ggKGtleVR5cGUpIHtcbiAgICAgICAgY2FzZSBvcGVucGdwLmVudW1zLnBhY2tldC5wdWJsaWNfa2V5OlxuICAgICAgICAgIGlmIChrZXkuaXNQdWJsaWMoKSAmJiBpZGVudGl0eUZ1bmN0aW9uKGlkZW50aXR5SW5wdXQsIGtleSkpIHtcbiAgICAgICAgICAgIHJlc3VsdHMucHVzaChrZXkpO1xuICAgICAgICAgIH1cbiAgICAgICAgICBicmVhaztcbiAgICAgICAgY2FzZSBvcGVucGdwLmVudW1zLnBhY2tldC5wcml2YXRlX2tleTpcbiAgICAgICAgICBpZiAoa2V5LmlzUHJpdmF0ZSgpICYmIGlkZW50aXR5RnVuY3Rpb24oaWRlbnRpdHlJbnB1dCwga2V5KSkge1xuICAgICAgICAgICAgcmVzdWx0cy5wdXNoKGtleSk7XG4gICAgICAgICAgfVxuICAgICAgICAgIGJyZWFrO1xuICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gcmVzdWx0cztcbiAgfVxuICB0aGlzLmNoZWNrRm9ySWRlbnRpdHlBbmRLZXlUeXBlTWF0Y2ggPSBjaGVja0ZvcklkZW50aXR5QW5kS2V5VHlwZU1hdGNoO1xuXG4gIC8qKlxuICAgKiBzZWFyY2hlcyBhbGwgcHVibGljIGtleXMgaW4gdGhlIGtleXJpbmcgbWF0Y2hpbmcgdGhlIGFkZHJlc3Mgb3IgYWRkcmVzcyBwYXJ0IG9mIHRoZSB1c2VyIGlkc1xuICAgKiBAcGFyYW0ge1N0cmluZ30gZW1haWwgZW1haWwgYWRkcmVzcyB0byBzZWFyY2ggZm9yXG4gICAqIEByZXR1cm4ge29wZW5wZ3Aua2V5LktleVtdfSBUaGUgcHVibGljIGtleXMgYXNzb2NpYXRlZCB3aXRoIHByb3ZpZGVkIGVtYWlsIGFkZHJlc3MuXG4gICAqL1xuICBmdW5jdGlvbiBnZXRQdWJsaWNLZXlGb3JBZGRyZXNzKGVtYWlsKSB7XG4gICAgcmV0dXJuIGNoZWNrRm9ySWRlbnRpdHlBbmRLZXlUeXBlTWF0Y2godGhpcy5rZXlzLCBlbWFpbENoZWNrLCBlbWFpbCwgb3BlbnBncC5lbnVtcy5wYWNrZXQucHVibGljX2tleSk7XG4gIH1cbiAgdGhpcy5nZXRQdWJsaWNLZXlGb3JBZGRyZXNzID0gZ2V0UHVibGljS2V5Rm9yQWRkcmVzcztcblxuICAvKipcbiAgICogU2VhcmNoZXMgdGhlIGtleXJpbmcgZm9yIGEgcHJpdmF0ZSBrZXkgY29udGFpbmluZyB0aGUgc3BlY2lmaWVkIGVtYWlsIGFkZHJlc3NcbiAgICogQHBhcmFtIHtTdHJpbmd9IGVtYWlsIGVtYWlsIGFkZHJlc3MgdG8gc2VhcmNoIGZvclxuICAgKiBAcmV0dXJuIHtvcGVucGdwLmtleS5LZXlbXX0gcHJpdmF0ZSBrZXlzIGZvdW5kXG4gICAqL1xuICBmdW5jdGlvbiBnZXRQcml2YXRlS2V5Rm9yQWRkcmVzcyhlbWFpbCkge1xuICAgIHJldHVybiBjaGVja0ZvcklkZW50aXR5QW5kS2V5VHlwZU1hdGNoKHRoaXMua2V5cywgZW1haWxDaGVjaywgZW1haWwsIG9wZW5wZ3AuZW51bXMucGFja2V0LnNlY3JldF9rZXkpO1xuICB9XG4gIHRoaXMuZ2V0UHJpdmF0ZUtleUZvckFkZHJlc3MgPSBnZXRQcml2YXRlS2V5Rm9yQWRkcmVzcztcblxuICAvKipcbiAgICogU2VhcmNoZXMgdGhlIGtleXJpbmcgZm9yIHB1YmxpYyBrZXlzIGhhdmluZyB0aGUgc3BlY2lmaWVkIGtleSBpZFxuICAgKiBAcGFyYW0ge1N0cmluZ30ga2V5SWQgcHJvdmlkZWQgYXMgc3RyaW5nIG9mIGhleCBudW1iZXIgKGxvd2VyY2FzZSlcbiAgICogQHJldHVybiB7b3BlbnBncC5rZXkuS2V5W119IHB1YmxpYyBrZXlzIGZvdW5kXG4gICAqL1xuICBmdW5jdGlvbiBnZXRLZXlzRm9yS2V5SWQoa2V5SWQpIHtcbiAgICByZXR1cm4gdGhpcy5jaGVja0ZvcklkZW50aXR5QW5kS2V5VHlwZU1hdGNoKHRoaXMua2V5cywgaWRDaGVjaywga2V5SWQsIG9wZW5wZ3AuZW51bXMucGFja2V0LnB1YmxpY19rZXkpO1xuICB9XG4gIHRoaXMuZ2V0S2V5c0ZvcktleUlkID0gZ2V0S2V5c0ZvcktleUlkO1xuXG4gIC8qKlxuICAgKiBJbXBvcnRzIGEga2V5IGZyb20gYW4gYXNjaWkgYXJtb3JlZCBtZXNzYWdlXG4gICAqIEBwYXJhbSB7U3RyaW5nfSBhcm1vcmVkIG1lc3NhZ2UgdG8gcmVhZCB0aGUga2V5cy9rZXkgZnJvbVxuICAgKi9cbiAgZnVuY3Rpb24gaW1wb3J0S2V5KGFybW9yZWQpIHtcbiAgICB0aGlzLmtleXMgPSB0aGlzLmtleXMuY29uY2F0KG9wZW5wZ3Aua2V5LnJlYWRBcm1vcmVkKGFybW9yZWQpLmtleXMpO1xuXG4gICAgcmV0dXJuIHRydWU7XG4gIH1cbiAgdGhpcy5pbXBvcnRLZXkgPSBpbXBvcnRLZXk7XG5cbiAgLyoqXG4gICAqIHJldHVybnMgdGhlIGFybW9yZWQgbWVzc2FnZSByZXByZXNlbnRhdGlvbiBvZiB0aGUga2V5IGF0IGtleSByaW5nIGluZGV4XG4gICAqIEBwYXJhbSB7SW50ZWdlcn0gaW5kZXggdGhlIGluZGV4IG9mIHRoZSBrZXkgd2l0aGluIHRoZSBhcnJheVxuICAgKiBAcmV0dXJuIHtTdHJpbmd9IGFybW9yZWQgbWVzc2FnZSByZXByZXNlbnRpbmcgdGhlIGtleSBvYmplY3RcbiAgICovXG4gIGZ1bmN0aW9uIGV4cG9ydEtleShpbmRleCkge1xuICAgIHJldHVybiB0aGlzLmtleXNbaW5kZXhdLmFybW9yKCk7XG4gIH1cbiAgdGhpcy5leHBvcnRLZXkgPSBleHBvcnRLZXk7XG5cbiAgLyoqXG4gICAqIFJlbW92ZXMgYSBwdWJsaWMga2V5IGZyb20gdGhlIHB1YmxpYyBrZXkga2V5cmluZyBhdCB0aGUgc3BlY2lmaWVkIGluZGV4IFxuICAgKiBAcGFyYW0ge0ludGVnZXJ9IGluZGV4IHRoZSBpbmRleCBvZiB0aGUgcHVibGljIGtleSB3aXRoaW4gdGhlIHB1YmxpY0tleXMgYXJyYXlcbiAgICogQHJldHVybiB7b3BlbnBncC5rZXkuS2V5fSBUaGUgcHVibGljIGtleSBvYmplY3Qgd2hpY2ggaGFzIGJlZW4gcmVtb3ZlZFxuICAgKi9cbiAgZnVuY3Rpb24gcmVtb3ZlS2V5KGluZGV4KSB7XG4gICAgdmFyIHJlbW92ZWQgPSB0aGlzLmtleXMuc3BsaWNlKGluZGV4LCAxKTtcblxuICAgIHJldHVybiByZW1vdmVkO1xuICB9XG4gIHRoaXMucmVtb3ZlS2V5ID0gcmVtb3ZlS2V5O1xuXG4gIC8qKlxuICAgKiByZXR1cm5zIHRoZSBhcm1vcmVkIG1lc3NhZ2UgcmVwcmVzZW50YXRpb24gb2YgdGhlIHB1YmxpYyBrZXkgcG9ydGlvbiBvZiB0aGUga2V5IGF0IGtleSByaW5nIGluZGV4XG4gICAqIEBwYXJhbSB7SW50ZWdlcn0gaW5kZXggdGhlIGluZGV4IG9mIHRoZSBrZXkgd2l0aGluIHRoZSBhcnJheVxuICAgKiBAcmV0dXJuIHtTdHJpbmd9IGFybW9yZWQgbWVzc2FnZSByZXByZXNlbnRpbmcgdGhlIHB1YmxpYyBrZXkgb2JqZWN0XG4gICAqL1xuICBmdW5jdGlvbiBleHBvcnRQdWJsaWNLZXkoaW5kZXgpIHtcbiAgICByZXR1cm4gdGhpcy5rZXlzW2luZGV4XS50b1B1YmxpYygpLmFybW9yKCk7XG4gIH1cbiAgdGhpcy5leHBvcnRQdWJsaWNLZXkgPSBleHBvcnRQdWJsaWNLZXk7XG5cbn07XG5cbm1vZHVsZS5leHBvcnRzID0gbmV3IGtleXJpbmcoKTtcbiIsIi8vIEdQRzRCcm93c2VycyAtIEFuIE9wZW5QR1AgaW1wbGVtZW50YXRpb24gaW4gamF2YXNjcmlwdFxuLy8gQ29weXJpZ2h0IChDKSAyMDExIFJlY3VyaXR5IExhYnMgR21iSFxuLy8gXG4vLyBUaGlzIGxpYnJhcnkgaXMgZnJlZSBzb2Z0d2FyZTsgeW91IGNhbiByZWRpc3RyaWJ1dGUgaXQgYW5kL29yXG4vLyBtb2RpZnkgaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgTGVzc2VyIEdlbmVyYWwgUHVibGljXG4vLyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieSB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uOyBlaXRoZXJcbi8vIHZlcnNpb24gMi4xIG9mIHRoZSBMaWNlbnNlLCBvciAoYXQgeW91ciBvcHRpb24pIGFueSBsYXRlciB2ZXJzaW9uLlxuLy8gXG4vLyBUaGlzIGxpYnJhcnkgaXMgZGlzdHJpYnV0ZWQgaW4gdGhlIGhvcGUgdGhhdCBpdCB3aWxsIGJlIHVzZWZ1bCxcbi8vIGJ1dCBXSVRIT1VUIEFOWSBXQVJSQU5UWTsgd2l0aG91dCBldmVuIHRoZSBpbXBsaWVkIHdhcnJhbnR5IG9mXG4vLyBNRVJDSEFOVEFCSUxJVFkgb3IgRklUTkVTUyBGT1IgQSBQQVJUSUNVTEFSIFBVUlBPU0UuICBTZWUgdGhlIEdOVVxuLy8gTGVzc2VyIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgZm9yIG1vcmUgZGV0YWlscy5cbi8vIFxuLy8gWW91IHNob3VsZCBoYXZlIHJlY2VpdmVkIGEgY29weSBvZiB0aGUgR05VIExlc3NlciBHZW5lcmFsIFB1YmxpY1xuLy8gTGljZW5zZSBhbG9uZyB3aXRoIHRoaXMgbGlicmFyeTsgaWYgbm90LCB3cml0ZSB0byB0aGUgRnJlZSBTb2Z0d2FyZVxuLy8gRm91bmRhdGlvbiwgSW5jLiwgNTEgRnJhbmtsaW4gU3RyZWV0LCBGaWZ0aCBGbG9vciwgQm9zdG9uLCBNQSAgMDIxMTAtMTMwMSAgVVNBXG5cbnZhciBvcGVucGdwID0gcmVxdWlyZSgnb3BlbnBncCcpO1xuXG4vKipcbiAqIEBjbGFzc1xuICogQGNsYXNzZGVzYyBUaGUgY2xhc3MgdGhhdCBkZWFscyB3aXRoIHN0b3JhZ2Ugb2YgdGhlIGtleXJpbmcuIEN1cnJlbnRseSB0aGUgb25seSBvcHRpb24gaXMgdG8gdXNlIEhUTUw1IGxvY2FsIHN0b3JhZ2UuXG4gKi9cbnZhciBsb2NhbHN0b3JlID0gZnVuY3Rpb24oKSB7XG4gIC8qKlxuICAgKiBJbml0aWFsaXphdGlvbiByb3V0aW5lIGZvciB0aGUga2V5cmluZy4gVGhpcyBtZXRob2QgcmVhZHMgdGhlIFxuICAgKiBrZXlyaW5nIGZyb20gSFRNTDUgbG9jYWwgc3RvcmFnZSBhbmQgaW5pdGlhbGl6ZXMgdGhpcyBpbnN0YW5jZS5cbiAgICogVGhpcyBtZXRob2QgaXMgY2FsbGVkIGJ5IG9wZW5wZ3AuaW5pdCgpLlxuICAgKi9cbiAgZnVuY3Rpb24gaW5pdChrZXlzKSB7XG4gICAgdmFyIGFybW9yZWRLZXlzID0gSlNPTi5wYXJzZSh3aW5kb3cubG9jYWxTdG9yYWdlLmdldEl0ZW0oXCJhcm1vcmVkS2V5c1wiKSk7XG4gICAgaWYgKGFybW9yZWRLZXlzICE9PSBudWxsICYmIGFybW9yZWRLZXlzLmxlbmd0aCA9PT0gMCkge1xuICAgICAgdmFyIGtleTtcbiAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYXJtb3JlZEtleXMubGVuZ3RoOyBpKyspIHtcbiAgICAgICAga2V5ID0gb3BlbnBncC5rZXkucmVhZEFybW9yZWQoYXJtb3JlZEtleXNbaV0pO1xuICAgICAgICBrZXlzLnB1c2goa2V5KTtcbiAgICAgIH1cbiAgICB9IGVsc2Uge1xuICAgICAgdGhpcy5rZXlzID0gW107XG4gICAgfVxuICB9XG4gIHRoaXMuaW5pdCA9IGluaXQ7XG5cbiAgLyoqXG4gICAqIFNhdmVzIHRoZSBjdXJyZW50IHN0YXRlIG9mIHRoZSBrZXlyaW5nIHRvIEhUTUw1IGxvY2FsIHN0b3JhZ2UuXG4gICAqIFRoZSBwcml2YXRlS2V5cyBhcnJheSBhbmQgcHVibGljS2V5cyBhcnJheSBnZXRzIFN0cmluZ2lmaWVkIHVzaW5nIEpTT05cbiAgICovXG4gIGZ1bmN0aW9uIHN0b3JlKGtleXMpIHtcbiAgICB2YXIgYXJtb3JlZEtleXMgPSBbXTtcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IGtleXMubGVuZ3RoOyBpKyspIHtcbiAgICAgIGFybW9yZWRLZXlzLnB1c2goa2V5c1tpXS5hcm1vcigpKTtcbiAgICB9XG4gICAgd2luZG93LmxvY2FsU3RvcmFnZS5zZXRJdGVtKFwiYXJtb3JlZEtleXNcIiwgSlNPTi5zdHJpbmdpZnkoYXJtb3JlZEtleXMpKTtcbiAgfVxuICB0aGlzLnN0b3JlID0gc3RvcmU7XG59O1xuXG5tb2R1bGUuZXhwb3J0cyA9IG5ldyBsb2NhbHN0b3JlKCk7XG4iXX0=
;