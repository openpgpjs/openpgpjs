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

'use strict';

import util from '../util.js';
import crypto from '../crypto';
import packet from '../packet';

const INITIAL_RANDOM_SEED = 50000, // random bytes seeded to worker
    RANDOM_SEED_REQUEST = 20000; // random bytes seeded after worker request

/**
 * Initializes a new proxy and loads the web worker
 * @constructor
 * @param {String} path     The path to the worker or 'openpgp.worker.js' by default
 * @param {String} pgpPath  The path to OpenPGP.js or 'openpgp.js' by default
 * @param {Object} config   config The worker configuration
 * @param {Object} worker   alternative to path parameter: web worker initialized with 'openpgp.worker.js'
 * @return {Promise}
 */
export default function AsyncProxy({ path='openpgp.worker.js', pgpPath='openpgp.js', worker, config } = {}) {
  this.worker = worker || new Worker(path);
  this.worker.onmessage = this.onMessage.bind(this);
  this.worker.onerror = e => {
    throw new Error('Unhandled error in openpgp worker: ' + e.message + ' (' + e.filename + ':' + e.lineno + ')');
  };
  this.loadOpenPGP(pgpPath);
  this.seedRandom(INITIAL_RANDOM_SEED);
  // FIFO
  this.tasks = [];
  if (config) {
    this.worker.postMessage({ event:'configure', config });
  }
}

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
 * Send message to worker with url of openpgp.js
 * @param  {String} url Url of OpenPGP.js
 */
AsyncProxy.prototype.loadOpenPGP = function(url) {
  this.worker.postMessage({ event:'openpgp-url', url });
};

/**
 * Send message to worker with random data
 * @param  {Integer} size Number of bytes to send
 */
AsyncProxy.prototype.seedRandom = function(size) {
  const buf = this.getRandomBuffer(size);
  this.worker.postMessage({ event:'seed-random', buf }, util.getTransferables.call(util, buf));
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

/**
 * Generic proxy function that handles all commands from the public api.
 * @param  {String} method    the public api function to be delegated to the worker thread
 * @param  {Object} options   the api function's options
 * @return {Promise}          see the corresponding public api functions for their return types
 */
AsyncProxy.prototype.delegate = function(method, options) {
  return new Promise((resolve, reject) => {
    // clone packets (for web worker structured cloning algorithm)
    this.worker.postMessage({ event:method, options:packet.clone.clonePackets(options) }, util.getTransferables.call(util, options));

    // remember to handle parsing cloned packets from worker
    this.tasks.push({ resolve: data => resolve(packet.clone.parseClonedPackets(data, method)), reject });
  });
};
