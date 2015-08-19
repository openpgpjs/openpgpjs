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

var crypto = require('../crypto'),
  packet = require('../packet'),
  key = require('../key.js'),
  type_keyid = require('../type/keyid.js');

var INITIAL_RANDOM_SEED = 50000, // random bytes seeded to worker
    RANDOM_SEED_REQUEST = 20000; // random bytes seeded after worker request

/**
 * Initializes a new proxy and loads the web worker
 * @constructor
 * @param {String} path The path to the worker or 'openpgp.worker.js' by default
 * @param {Object} [options.config=Object] config The worker configuration
 * @param {Object} [options.worker=Object] alternative to path parameter:
 *                                         web worker initialized with 'openpgp.worker.js'
 */
function AsyncProxy(path, options) {
  if (options && options.worker) {
    this.worker = options.worker;
  } else {
    this.worker = new Worker(path || 'openpgp.worker.js');
  }
  this.worker.onmessage = this.onMessage.bind(this);
  this.worker.onerror = function(e) {
    throw new Error('Unhandled error in openpgp worker: ' + e.message + ' (' + e.filename + ':' + e.lineno + ')');
  };
  this.seedRandom(INITIAL_RANDOM_SEED);
  // FIFO
  this.tasks = [];
  if (options && options.config) {
    this.worker.postMessage({event: 'configure', config: options.config});
  }
}

/**
 * Command pattern that wraps synchronous code into a promise
 * @param  {Object}   self    The current this
 * @param  {function} cmd     The synchronous function with a return value
 *                            to be wrapped in a promise
 * @return {Promise}          The promise wrapped around cmd
 */
AsyncProxy.prototype.execute = function(cmd) {
  var self = this;

  var promise = new Promise(function(resolve, reject) {
    cmd();
    self.tasks.push({ resolve:resolve, reject:reject });
  });

  return promise;
};

/**
 * Message handling
 */
AsyncProxy.prototype.onMessage = function(event) {
  var msg = event.data;
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
  var buf = this.getRandomBuffer(size);
  this.worker.postMessage({event: 'seed-random', buf: buf});
};

/**
 * Get Uint8Array with random numbers
 * @param  {Integer} size Length of buffer
 * @return {Uint8Array}
 */
AsyncProxy.prototype.getRandomBuffer = function(size) {
  if (!size) return null;
  var buf = new Uint8Array(size);
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
 * Encrypts message text with keys
 * @param  {(Array<module:key~Key>|module:key~Key)}  keys array of keys or single key, used to encrypt the message
 * @param  {String} text message as native JavaScript string
 */
AsyncProxy.prototype.encryptMessage = function(keys, text) {
  var self = this;

  return self.execute(function() {
    if (!keys.length) {
      keys = [keys];
    }
    keys = keys.map(function(key) {
      return key.toPacketlist();
    });
    self.worker.postMessage({
      event: 'encrypt-message',
      keys: keys,
      text: text
    });
  });
};

/**
 * Signs message text and encrypts it
 * @param  {(Array<module:key~Key>|module:key~Key)}  publicKeys array of keys or single key, used to encrypt the message
 * @param  {module:key~Key}    privateKey private key with decrypted secret key data for signing
 * @param  {String} text       message as native JavaScript string
 */
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

/**
 * Decrypts message
 * @param  {module:key~Key}     privateKey private key with decrypted secret key data
 * @param  {module:message~Message} message    the message object with the encrypted data
 */
AsyncProxy.prototype.decryptMessage = function(privateKey, message) {
  var self = this;

  return self.execute(function() {
    privateKey = privateKey.toPacketlist();
    self.worker.postMessage({
      event: 'decrypt-message',
      privateKey: privateKey,
      message: message
    });
  });
};

/**
 * Decrypts message and verifies signatures
 * @param  {module:key~Key}     privateKey private key with decrypted secret key data
 * @param  {(Array<module:key~Key>|module:key~Key)}  publicKeys array of keys or single key to verify signatures
 * @param  {module:message~Message} message    the message object with signed and encrypted data
 */
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

/**
 * Signs a cleartext message
 * @param  {(Array<module:key~Key>|module:key~Key)}  privateKeys array of keys or single key, with decrypted secret key data to sign cleartext
 * @param  {String} text        cleartext
 */
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

/**
 * Verifies signatures of cleartext signed message
 * @param  {(Array<module:key~Key>|module:key~Key)}  publicKeys array of keys or single key, to verify signatures
 * @param  {module:cleartext~CleartextMessage} message    cleartext message object with signatures
 */
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

/**
 * Generates a new OpenPGP key pair. Currently only supports RSA keys.
 * Primary and subkey will be of same type.
 * @param {module:enums.publicKey} keyType    to indicate what type of key to make.
 *                             RSA is 1. See {@link http://tools.ietf.org/html/rfc4880#section-9.1}
 * @param {Integer} numBits    number of bits for the key creation. (should be 1024+, generally)
 * @param {String}  userId     assumes already in form of "User Name <username@email.com>"
 * @param {String}  passphrase The passphrase used to encrypt the resulting private key
 */
AsyncProxy.prototype.generateKeyPair = function(options) {
  var self = this;

  var promise = new Promise(function(resolve, reject) {
    self.worker.postMessage({
      event: 'generate-key-pair',
      options: options
    });

    self.tasks.push({ resolve:function(data) {
      var packetlist = packet.List.fromStructuredClone(data.key);
      data.key = new key.Key(packetlist);
      resolve(data);
    }, reject:reject });
  });

  return promise;
};

/**
 * Decrypts secret part of all secret key packets of key.
 * @param  {module:key~Key}     privateKey private key with encrypted secret key data
 * @param  {String} password    password to unlock the key
 */
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

/**
 * Decrypts secret part of key packets matching array of keyids.
 * @param  {module:key~Key}     privateKey private key with encrypted secret key data
 * @param  {Array<module:type/keyid>} keyIds
 * @param  {String} password    password to unlock the key
 */
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

module.exports = AsyncProxy;
