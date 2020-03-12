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
 * @fileoverview Provides the LocalStore class
 * @requires web-stream-tools
 * @requires config
 * @requires key
 * @requires util
 * @module keyring/localstore
 */

import stream from 'web-stream-tools';
import config from '../config';
import { readArmored } from '../key';
import util from '../util';

/**
 * The class that deals with storage of the keyring.
 * Currently the only option is to use HTML5 local storage.
 * @constructor
 * @param {String} prefix prefix for itemnames in localstore
 */
function LocalStore(prefix) {
  prefix = prefix || 'openpgp-';
  this.publicKeysItem = prefix + this.publicKeysItem;
  this.privateKeysItem = prefix + this.privateKeysItem;
  if (typeof global !== 'undefined' && global.localStorage) {
    this.storage = global.localStorage;
  } else {
    this.storage = new (require('node-localstorage').LocalStorage)(config.node_store);
  }
}

/*
 * Declare the localstore itemnames
 */
LocalStore.prototype.publicKeysItem = 'public-keys';
LocalStore.prototype.privateKeysItem = 'private-keys';

/**
 * Load the public keys from HTML5 local storage.
 * @returns {Array<module:key.Key>} array of keys retrieved from localstore
 * @async
 */
LocalStore.prototype.loadPublic = async function () {
  return loadKeys(this.storage, this.publicKeysItem);
};

/**
 * Load the private keys from HTML5 local storage.
 * @returns {Array<module:key.Key>} array of keys retrieved from localstore
 * @async
 */
LocalStore.prototype.loadPrivate = async function () {
  return loadKeys(this.storage, this.privateKeysItem);
};

async function loadKeys(storage, itemname) {
  const armoredKeys = JSON.parse(storage.getItem(itemname));
  const keys = [];
  if (armoredKeys !== null && armoredKeys.length !== 0) {
    let key;
    for (let i = 0; i < armoredKeys.length; i++) {
      key = await readArmored(armoredKeys[i]);
      if (!key.err) {
        keys.push(key.keys[0]);
      } else {
        util.print_debug("Error reading armored key from keyring index: " + i);
      }
    }
  }
  return keys;
}

/**
 * Saves the current state of the public keys to HTML5 local storage.
 * The key array gets stringified using JSON
 * @param {Array<module:key.Key>} keys array of keys to save in localstore
 * @async
 */
LocalStore.prototype.storePublic = async function (keys) {
  await storeKeys(this.storage, this.publicKeysItem, keys);
};

/**
 * Saves the current state of the private keys to HTML5 local storage.
 * The key array gets stringified using JSON
 * @param {Array<module:key.Key>} keys array of keys to save in localstore
 * @async
 */
LocalStore.prototype.storePrivate = async function (keys) {
  await storeKeys(this.storage, this.privateKeysItem, keys);
};

async function storeKeys(storage, itemname, keys) {
  if (keys.length) {
    const armoredKeys = await Promise.all(keys.map(key => stream.readToEnd(key.armor())));
    storage.setItem(itemname, JSON.stringify(armoredKeys));
  } else {
    storage.removeItem(itemname);
  }
}

export default LocalStore;
