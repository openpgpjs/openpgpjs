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
 * @fileoverview Provides functions for maintaining browser workers
 * @see module:openpgp.initWorker
 * @see module:openpgp.getWorker
 * @see module:openpgp.destroyWorker
 * @see module:worker/worker
 * @requires util
 * @requires config
 * @requires crypto
 * @requires packet
 * @module worker/async_proxy
 */

import util from '../util.js';
import config from '../config';
import crypto from '../crypto';
import packet from '../packet';


/**
 * Initializes a new proxy and loads the web worker
 * @param {String} path            The path to the worker or 'openpgp.worker.js' by default
 * @param {Number} n               number of workers to initialize if path given
 * @param {Object} config          config The worker configuration
 * @param {Array<Object>} worker   alternative to path parameter: web worker initialized with 'openpgp.worker.js'
 * @constructor
 */
function AsyncProxy({ path = 'openpgp.worker.js', n = 1, workers = [], config } = {}) {
  /**
   * Message handling
   */
  const handleMessage = workerId => event => {
    const msg = event.data;
    switch (msg.event) {
      case 'loaded':
        this.workers[workerId].loadedResolve(true);
        break;
      case 'method-return':
        if (msg.err) {
          // fail
          const err = new Error(msg.err);
          // add worker stack
          err.workerStack = msg.stack;
          this.tasks[msg.id].reject(err);
        } else {
          // success
          this.tasks[msg.id].resolve(msg.data);
        }
        delete this.tasks[msg.id];
        this.workers[workerId].requests--;
        break;
      case 'request-seed':
        this.seedRandom(workerId, msg.amount);
        break;
      default:
        throw new Error('Unknown Worker Event.');
    }
  };

  if (workers.length) {
    this.workers = workers;
  }
  else {
    this.workers = [];
    while (this.workers.length < n) {
      this.workers.push(new Worker(path));
    }
  }

  let workerId = 0;
  this.workers.forEach(worker => {
    worker.loadedPromise = new Promise(resolve => {
      worker.loadedResolve = resolve;
    });
    worker.requests = 0;
    worker.onmessage = handleMessage(workerId++);
    worker.onerror = e => {
      worker.loadedResolve(false);
      // eslint-disable-next-line no-console
      console.error('Unhandled error in openpgp worker: ' + e.message + ' (' + e.filename + ':' + e.lineno + ')');
      return false;
    };

    if (config) {
      worker.postMessage({ event:'configure', config });
    }
  });

  // Cannot rely on task order being maintained, use object keyed by request ID to track tasks
  this.tasks = {};
  this.currentID = 0;
}

/**
 * Returns a promise that resolves when all workers have finished loading
 * @returns {Promise<Boolean>} Resolves to true if all workers have loaded succesfully; false otherwise
*/
AsyncProxy.prototype.loaded = async function() {
  const loaded = await Promise.all(this.workers.map(worker => worker.loadedPromise));
  return loaded.every(Boolean);
};

/**
 * Get new request ID
 * @returns {integer}          New unique request ID
*/
AsyncProxy.prototype.getID = function() {
  return this.currentID++;
};

/**
 * Send message to worker with random data
 * @param  {Integer} size Number of bytes to send
 * @async
 */
AsyncProxy.prototype.seedRandom = async function(workerId, size) {
  const buf = await crypto.random.getRandomBytes(size);
  this.workers[workerId].postMessage({ event:'seed-random', buf }, util.getTransferables(buf, true));
};

/**
 * Clear key caches
 * @async
 */
AsyncProxy.prototype.clearKeyCache = async function() {
  await Promise.all(this.workers.map(worker => new Promise((resolve, reject) => {
    const id = this.getID();

    worker.postMessage({ id, event: 'clear-key-cache' });

    this.tasks[id] = { resolve, reject };
  })));
};

/**
 * Terminates the workers
 */
AsyncProxy.prototype.terminate = function() {
  this.workers.forEach(worker => {
    worker.terminate();
  });
};

/**
 * Generic proxy function that handles all commands from the public api.
 * @param  {String} method    the public api function to be delegated to the worker thread
 * @param  {Object} options   the api function's options
 * @returns {Promise}          see the corresponding public api functions for their return types
 * @async
 */
AsyncProxy.prototype.delegate = function(method, options) {

  const id = this.getID();
  const requests = this.workers.map(worker => worker.requests);
  const minRequests = Math.min(...requests);
  let workerId = 0;
  for (; workerId < this.workers.length; workerId++) {
    if (this.workers[workerId].requests === minRequests) {
      break;
    }
  }

  return new Promise((resolve, reject) => {
    // clone packets (for web worker structured cloning algorithm)
    this.workers[workerId].postMessage({ id:id, event:method, options:packet.clone.clonePackets(options) }, util.getTransferables(options, config.zero_copy));
    this.workers[workerId].requests++;

    // remember to handle parsing cloned packets from worker
    this.tasks[id] = { resolve: data => resolve(packet.clone.parseClonedPackets(util.restoreStreams(data), method)), reject };
  });
};

export default AsyncProxy;
