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
 * @module keyring/localstore
 */

import stream from 'web-stream-tools';
import config from '../config';
import { readArmored } from '../key';

/**
 * The class that deals with storage of the keyring.
 * Currently the only option is to use HTML5 local storage.
 */
class LocalStore {
  /**
   * @param {String} prefix prefix for itemnames in localstore
   */
  constructor(prefix) {
    prefix = prefix || 'openpgp-';
    this.publicKeysItem = prefix + this.publicKeysItem;
    this.privateKeysItem = prefix + this.privateKeysItem;
    if (typeof globalThis !== 'undefined' && globalThis.localStorage) {
      this.storage = globalThis.localStorage;
    } else {
      this.storage = new (require('node-localstorage').LocalStorage)(config.nodeStore);
    }
  }

  /**
   * Load the public keys from HTML5 local storage.
   * @returns {Array<module:key.Key>} array of keys retrieved from localstore
   * @async
   */
  async loadPublic() {
    return loadKeys(this.storage, this.publicKeysItem);
  }

  /**
   * Load the private keys from HTML5 local storage.
   * @returns {Array<module:key.Key>} array of keys retrieved from localstore
   * @async
   */
  async loadPrivate() {
    return loadKeys(this.storage, this.privateKeysItem);
  }

  /**
   * Saves the current state of the public keys to HTML5 local storage.
   * The key array gets stringified using JSON
   * @param {Array<module:key.Key>} keys array of keys to save in localstore
   * @async
   */
  async storePublic(keys) {
    await storeKeys(this.storage, this.publicKeysItem, keys);
  }

  /**
   * Saves the current state of the private keys to HTML5 local storage.
   * The key array gets stringified using JSON
   * @param {Array<module:key.Key>} keys array of keys to save in localstore
   * @async
   */
  async storePrivate(keys) {
    await storeKeys(this.storage, this.privateKeysItem, keys);
  }
}

/*
 * Declare the localstore itemnames
 */
LocalStore.prototype.publicKeysItem = 'public-keys';
LocalStore.prototype.privateKeysItem = 'private-keys';

async function loadKeys(storage, itemname) {
  const armoredKeys = JSON.parse(storage.getItem(itemname));
  const keys = [];
  if (armoredKeys !== null && armoredKeys.length !== 0) {
    let key;
    for (let i = 0; i < armoredKeys.length; i++) {
      key = await readArmored(armoredKeys[i]);
      keys.push(key);
    }
  }
  return keys;
}

async function storeKeys(storage, itemname, keys) {
  if (keys.length) {
    const armoredKeys = await Promise.all(keys.map(key => stream.readToEnd(key.armor())));
    storage.setItem(itemname, JSON.stringify(armoredKeys));
  } else {
    storage.removeItem(itemname);
  }
}

export default LocalStore;
