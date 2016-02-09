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
import * as message from '../message.js';
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


AsyncProxy.prototype.delegate = function(method, options) {
  return new Promise((resolve, reject) => {
    // clone packets (for web worker structured cloning algorithm)
    this.worker.postMessage({ event:method, options:clonePackets(options) });

    // remember to handle parsing cloned packets from worker
    this.tasks.push({ resolve: data => resolve(parseClonedPackets(data)), reject });
  });
};

function clonePackets(options) {
  if(options.publicKeys) {
    options.publicKeys = options.publicKeys.map(key => key.toPacketlist());
  }
  if(options.privateKeys) {
    options.privateKeys = options.privateKeys.map(key => key.toPacketlist());
  }
  if(options.privateKey) {
    options.privateKey = options.privateKey.toPacketlist();
  }
  return options;
}

function parseClonedPackets(data) {
  if (data.key) {
    data.key = packetlistCloneToKey(data.key);
  }
  if (data.message) {
    data.message = packetlistCloneToMessage(data.message);
  }
  if (data.signatures) {
    data.signatures = data.signatures.map(packetlistCloneToSignature);
  }
  return data;
}

function packetlistCloneToKey(clone) {
  const packetlist = packet.List.fromStructuredClone(clone);
  return new key.Key(packetlist);
}

function packetlistCloneToMessage(clone) {
  const packetlist = packet.List.fromStructuredClone(clone.packets);
  return new message.Message(packetlist);
}

function packetlistCloneToSignature(clone) {
  clone.keyid = type_keyid.fromClone(clone.keyid);
  return clone;
}

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
