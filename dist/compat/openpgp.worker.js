/*! OpenPGP.js v4.10.8 - 2020-08-28 - this is LGPL licensed code, see LICENSE/our website https://openpgpjs.org/ for more information. */
(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
(function (global){
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

/* eslint-disable no-restricted-globals */
/* eslint-disable no-var */
/* eslint-disable vars-on-top */

/**
 * @fileoverview Provides functions for communicating with workers
 * @see module:openpgp.initWorker
 * @see module:openpgp.getWorker
 * @see module:openpgp.destroyWorker
 * @see module:worker/async_proxy
 * @module worker/worker
 */

importScripts('openpgp.js');
var openpgp = global.openpgp;

var randomQueue = [];
var MAX_SIZE_RANDOM_BUFFER = 60000;

/**
 * Handle random buffer exhaustion by requesting more random bytes from the main window
 * @returns {Promise<Object>}  Empty promise whose resolution indicates that the buffer has been refilled
 */
function randomCallback() {

  if (!randomQueue.length) {
    self.postMessage({ event: 'request-seed', amount: MAX_SIZE_RANDOM_BUFFER });
  }

  return new Promise(function(resolve) {
    randomQueue.push(resolve);
  });
}

openpgp.crypto.random.randomBuffer.init(MAX_SIZE_RANDOM_BUFFER, randomCallback);

/**
 * Handle messages from the main window.
 * @param  {Object} event   Contains event type and data
 */
self.onmessage = function(event) {
  var msg = event.data || {};

  switch (msg.event) {
    case 'configure':
      configure(msg.config);
      break;

    case 'seed-random':
      seedRandom(msg.buf);

      var queueCopy = randomQueue;
      randomQueue = [];
      for (var i = 0; i < queueCopy.length; i++) {
        queueCopy[i]();
      }

      break;

    default:
      delegate(msg.id, msg.event, msg.options || {});
  }
};

/**
 * Set config from main context to worker context.
 * @param  {Object} config   The openpgp configuration
 */
function configure(config) {
  Object.keys(config).forEach(function(key) {
    openpgp.config[key] = config[key];
  });
}

/**
 * Seed the library with entropy gathered global.crypto.getRandomValues
 * as this api is only avalible in the main window.
 * @param  {ArrayBuffer} buffer   Some random bytes
 */
function seedRandom(buffer) {
  if (!(buffer instanceof Uint8Array)) {
    buffer = new Uint8Array(buffer);
  }
  openpgp.crypto.random.randomBuffer.set(buffer);
}

const keyCache = new Map();
function getCachedKey(key) {
  const armor = key.armor();
  if (keyCache.has(armor)) {
    return keyCache.get(armor);
  }
  keyCache.set(armor, key);
  return key;
}

/**
 * Generic proxy function that handles all commands from the public api.
 * @param  {String} method    The public api function to be delegated to the worker thread
 * @param  {Object} options   The api function's options
 */
function delegate(id, method, options) {
  if (method === 'clear-key-cache') {
    Array.from(keyCache.values()).forEach(key => {
      if (key.isPrivate()) {
        key.clearPrivateParams();
      }
    });
    keyCache.clear();
    response({ id, event: 'method-return' });
    return;
  }
  if (typeof openpgp[method] !== 'function') {
    response({ id:id, event:'method-return', err:'Unknown Worker Event' });
    return;
  }
  // construct ReadableStreams from MessagePorts
  openpgp.util.restoreStreams(options);
  // parse cloned packets
  options = openpgp.packet.clone.parseClonedPackets(options, method);
  // cache keys by armor, so that we don't have to repeatedly verify self-signatures
  if (options.publicKeys) {
    options.publicKeys = options.publicKeys.map(getCachedKey);
  }
  if (options.privateKeys) {
    options.privateKeys = options.privateKeys.map(getCachedKey);
  }
  openpgp[method](options).then(function(data) {
    // clone packets (for web worker structured cloning algorithm)
    response({ id:id, event:'method-return', data:openpgp.packet.clone.clonePackets(data) });
  }).catch(function(e) {
    openpgp.util.print_debug_error(e);
    response({
      id:id, event:'method-return', err:e.message, stack:e.stack
    });
  });
}

/**
 * Respond to the main window.
 * @param  {Object} event  Contains event type and data
 */
function response(event) {
  self.postMessage(event, openpgp.util.getTransferables(event.data, openpgp.config.zero_copy));
}

/**
 * Let the main window know the worker has loaded.
 */
postMessage({ event: 'loaded' });

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{}]},{},[1]);
