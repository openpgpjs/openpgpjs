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
 * @requires crypto
 * @requires enums
 * @requires packet
 * @requires type_keyid
 * @requires key
 * @module async_proxy
 */

'use strict';

import crypto from '../crypto';
import packet from '../packet';
import * as key from '../key.js';
import type_keyid from '../type/keyid.js';

const INITIAL_RANDOM_SEED = 50000, // random bytes seeded to worker
    RANDOM_SEED_REQUEST = 20000; // random bytes seeded after worker request

/**
 * Initializes a new proxy and loads the web worker
 * @constructor
 * @param {String} path     The path to the worker or 'openpgp.worker.js' by default
 * @param {Object} config   config The worker configuration
 * @param {Object} worker   alternative to path parameter: web worker initialized with 'openpgp.worker.js'
 * @return {Promise}
 */
export default function AsyncProxy({ path='openpgp.worker.js', worker, config } = {}) {
  this.worker = worker || new Worker(path);
  this.worker.onmessage = this.onMessage.bind(this);
  this.worker.onerror = e => {
    throw new Error('Unhandled error in openpgp worker: ' + e.message + ' (' + e.filename + ':' + e.lineno + ')');
  };
  this.seedRandom(INITIAL_RANDOM_SEED);
  // FIFO
  this.tasks = [];
  if (config) {
    this.worker.postMessage({ event:'configure', config });
  }
}

/**
 * Command pattern that wraps synchronous code into a promise
 * @param  {function} cmd     The synchronous function with a return value
 *                            to be wrapped in a promise
 * @return {Promise}          The promise wrapped around cmd
 */
AsyncProxy.prototype.execute = function(cmd) {
  return new Promise((resolve, reject) => {
    cmd();
    this.tasks.push({ resolve, reject });
  });
};

/**
 * Message handling
 */
AsyncProxy.prototype.onMessage = function(event) {
  const msg = event.data;
  switch (msg.event) {
    case 'method-return':
      if (msg.err) {
        // fail
        this.tasks.shift().reject(new Error(msg.err));
      } else {
        // success
        this.tasks.shift().resolve(msg.data);
      }
      break;
    case 'request-seed':
      this.seedRandom(RANDOM_SEED_REQUEST);
      break;
    default:
      throw new Error('Unknown Worker Event.');
  }
};

/**
 * Send message to worker with random data
 * @param  {Integer} size Number of bytes to send
 */
AsyncProxy.prototype.seedRandom = function(size) {
  const buf = this.getRandomBuffer(size);
  this.worker.postMessage({ event:'seed-random', buf });
};

/**
 * Get Uint8Array with random numbers
 * @param  {Integer} size Length of buffer
 * @return {Uint8Array}
 */
AsyncProxy.prototype.getRandomBuffer = function(size) {
  if (!size) {
    return null;
  }
  const buf = new Uint8Array(size);
  crypto.random.getRandomValues(buf);
  return buf;
};

/**
 * Terminates the worker
 */
AsyncProxy.prototype.terminate = function() {
  this.worker.terminate();
};


//////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                              //
//   Proxy functions. See the corresponding code in the openpgp module for the documentation.   //
//                                                                                              //
//////////////////////////////////////////////////////////////////////////////////////////////////


AsyncProxy.prototype.generateKey = function(options) {
  return new Promise((resolve, reject) => {
    this.worker.postMessage({
      event: 'generate-key',
      options: options
    });

    this.tasks.push({ resolve: data => {
      const packetlist = packet.List.fromStructuredClone(data.key);
      data.key = new key.Key(packetlist);
      resolve(data);
    }, reject });
  });
};

AsyncProxy.prototype.encrypt = function({ data, publicKeys, privateKeys, passwords, filename, packets }) {
  return this.execute(() => {
    if(publicKeys) {
      publicKeys = publicKeys.length ? publicKeys : [publicKeys];
      publicKeys = publicKeys.map(key => key.toPacketlist());
    }
    if(privateKeys) {
      privateKeys = privateKeys.length ? privateKeys : [privateKeys];
      privateKeys = privateKeys.map(key => key.toPacketlist());
    }
    this.worker.postMessage({
      event:'encrypt',
      options: { data, publicKeys, privateKeys, passwords, filename, packets }
    });
  });
};

AsyncProxy.prototype.encryptSessionKey = function({ sessionKey, algo, keys, passwords }) {
  return this.execute(() => {
    if(keys) {
      keys = keys.length ? keys : [keys];
      keys = keys.map(key => key.toPacketlist());
    }
    this.worker.postMessage({ event:'encrypt-session-key', sessionKey, algo, keys, passwords });
  });
};

AsyncProxy.prototype.signAndEncryptMessage = function(publicKeys, privateKey, text) {
  var self = this;

  return self.execute(function() {
    if (!publicKeys.length) {
      publicKeys = [publicKeys];
    }
    publicKeys = publicKeys.map(function(key) {
      return key.toPacketlist();
    });
    privateKey = privateKey.toPacketlist();
    self.worker.postMessage({
      event: 'sign-and-encrypt-message',
      publicKeys: publicKeys,
      privateKey: privateKey,
      text: text
    });
  });
};

AsyncProxy.prototype.decryptMessage = function({ message, privateKey, format }) {
  return this.execute(() => {
    if(!(String.prototype.isPrototypeOf(privateKey) || typeof privateKey === 'string' || Uint8Array.prototype.isPrototypeOf(privateKey))) {
      privateKey = privateKey.toPacketlist();
    }

    this.worker.postMessage({ event:'decrypt-message', message, privateKey, format });
  });
};

AsyncProxy.prototype.decryptSessionKey = function(privateKey, message) {
  var self = this;

  return self.execute(function() {
    if(!(String.prototype.isPrototypeOf(privateKey) || typeof privateKey === 'string')) {
      privateKey = privateKey.toPacketlist();
    }

    self.worker.postMessage({
      event: 'decrypt-session-key',
      privateKey: privateKey,
      message: message
    });
  });
};

AsyncProxy.prototype.decryptAndVerifyMessage = function(privateKey, publicKeys, message) {
  var self = this;

  var promise = new Promise(function(resolve, reject) {
    privateKey = privateKey.toPacketlist();
    if (!publicKeys.length) {
      publicKeys = [publicKeys];
    }
    publicKeys = publicKeys.map(function(key) {
      return key.toPacketlist();
    });
    self.worker.postMessage({
      event: 'decrypt-and-verify-message',
      privateKey: privateKey,
      publicKeys: publicKeys,
      message: message
    });

    self.tasks.push({ resolve:function(data) {
      data.signatures = data.signatures.map(function(sig) {
        sig.keyid = type_keyid.fromClone(sig.keyid);
        return sig;
      });
      resolve(data);
    }, reject:reject });
  });

  return promise;
};

AsyncProxy.prototype.signClearMessage = function(privateKeys, text) {
  var self = this;

  return self.execute(function() {
    if (!privateKeys.length) {
      privateKeys = [privateKeys];
    }
    privateKeys = privateKeys.map(function(key) {
      return key.toPacketlist();
    });
    self.worker.postMessage({
      event: 'sign-clear-message',
      privateKeys: privateKeys,
      text: text
    });
  });
};

AsyncProxy.prototype.verifyClearSignedMessage = function(publicKeys, message) {
  var self = this;

  var promise = new Promise(function(resolve, reject) {
    if (!publicKeys.length) {
      publicKeys = [publicKeys];
    }
    publicKeys = publicKeys.map(function(key) {
      return key.toPacketlist();
    });
    self.worker.postMessage({
      event: 'verify-clear-signed-message',
      publicKeys: publicKeys,
      message: message
    });

    self.tasks.push({ resolve:function(data) {
      data.signatures = data.signatures.map(function(sig) {
        sig.keyid = type_keyid.fromClone(sig.keyid);
        return sig;
      });
      resolve(data);
    }, reject:reject });
  });

  return promise;
};

AsyncProxy.prototype.decryptKey = function(privateKey, password) {
  var self = this;

  var promise = new Promise(function(resolve, reject) {
    privateKey = privateKey.toPacketlist();
    self.worker.postMessage({
      event: 'decrypt-key',
      privateKey: privateKey,
      password: password
    });

    self.tasks.push({ resolve:function(data) {
      var packetlist = packet.List.fromStructuredClone(data);
      data = new key.Key(packetlist);
      resolve(data);
    }, reject:reject });
  });

  return promise;
};

AsyncProxy.prototype.decryptKeyPacket = function(privateKey, keyIds, password) {
  var self = this;

  var promise = new Promise(function(resolve, reject) {
    privateKey = privateKey.toPacketlist();
    self.worker.postMessage({
      event: 'decrypt-key-packet',
      privateKey: privateKey,
      keyIds: keyIds,
      password: password
    });

    self.tasks.push({ resolve:function(data) {
      var packetlist = packet.List.fromStructuredClone(data);
      data = new key.Key(packetlist);
      resolve(data);
    }, reject:reject });
  });

  return promise;
};
