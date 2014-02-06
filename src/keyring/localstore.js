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
 * @param {String} item itemname in localstore
 */
module.exports = LocalStore;

var openpgp = require('../');

function LocalStore(item) {
  if (typeof window != 'undefined' && window.localStorage) {
    this.storage = window.localStorage;
  } else {
    this.storage = new (require('node-localstorage').LocalStorage)(openpgp.config.node_store);
  }
  if(typeof item == 'string') {
    this.item = item;
  }
}

/*
 * Declare the localstore itemname
 */
LocalStore.prototype.item = 'armoredKeys';

/**
 * Load the keyring from HTML5 local storage and initializes this instance.
 * @return {Array<module:key~Key>} array of keys retrieved from localstore
 */
LocalStore.prototype.load = function () {
  var armoredKeys = JSON.parse(this.storage.getItem(this.item));
  var keys = [];
  if (armoredKeys !== null && armoredKeys.length !== 0) {
    var key;
    for (var i = 0; i < armoredKeys.length; i++) {
      key = openpgp.key.readArmored(armoredKeys[i]).keys[0];
      keys.push(key);
    }
  }
  return keys;
};

/**
 * Saves the current state of the keyring to HTML5 local storage.
 * The privateKeys array and publicKeys array gets Stringified using JSON
 * @param {Array<module:key~Key>} keys array of keys to save in localstore
 */
LocalStore.prototype.store = function (keys) {
  var armoredKeys = [];
  for (var i = 0; i < keys.length; i++) {
    armoredKeys.push(keys[i].armor());
  }
  this.storage.setItem(this.item, JSON.stringify(armoredKeys));
};
