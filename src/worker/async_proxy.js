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
 * @requires crypto
 * @requires enums
 * @requires packet
 * @requires type_keyid
 * @requires key
 * @module async_proxy
 */

var crypto = require('../crypto'),
  packet = require('../packet'),
  key = require('../key.js'),
  type_keyid = require('../type/keyid.js'),
  enums = require('../enums.js');

var INITIAL_RANDOM_SEED = 50000, // random bytes seeded to worker
    RANDOM_SEED_REQUEST = 20000; // random bytes seeded after worker request

/**
 * Initializes a new proxy and loads the web worker
 * @constructor
 * @param {String} path The path to the worker or 'openpgp.worker.js' by default
 */
function AsyncProxy(path) {
  this.worker = new Worker(path || 'openpgp.worker.js');
  this.worker.onmessage = this.onMessage.bind(this);
  this.worker.onerror = function(e) {
    throw new Error('Unhandled error in openpgp worker: ' + e.message + ' (' + e.filename + ':' + e.lineno + ')');
  };
  this.seedRandom(INITIAL_RANDOM_SEED);
  // FIFO
  this.tasks = [];
}

/**
 * Message handling
 */
AsyncProxy.prototype.onMessage = function(event) {
  var msg = event.data;
  switch (msg.event) {
    case 'method-return':
      this.tasks.shift()(msg.err ? new Error(msg.err) : null, msg.data);
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
 * @param  {Function} callback receives encrypted ASCII armored message
 */
AsyncProxy.prototype.encryptMessage = function(keys, text, callback) {
  if (!keys.length) {
    keys = [keys];
  }
  keys = keys.map(function(key) {
    return key.toPacketlist();
  });
  this.worker.postMessage({
    event: 'encrypt-message',
    keys: keys,
    text: text
  });
  this.tasks.push(callback);
};

/**
 * Signs message text and encrypts it
 * @param  {(Array<module:key~Key>|module:key~Key)}  publicKeys array of keys or single key, used to encrypt the message
 * @param  {module:key~Key}    privateKey private key with decrypted secret key data for signing
 * @param  {String} text       message as native JavaScript string
 * @param  {Function} callback receives encrypted ASCII armored message
 */
AsyncProxy.prototype.signAndEncryptMessage = function(publicKeys, privateKey, text, callback) {
  if (!publicKeys.length) {
    publicKeys = [publicKeys];
  }
  publicKeys = publicKeys.map(function(key) {
    return key.toPacketlist();
  });
  privateKey = privateKey.toPacketlist();
  this.worker.postMessage({
    event: 'sign-and-encrypt-message',
    publicKeys: publicKeys,
    privateKey: privateKey,
    text: text
  });
  this.tasks.push(callback);
};

/**
 * Decrypts message
 * @param  {module:key~Key}     privateKey private key with decrypted secret key data
 * @param  {module:message~Message} message    the message object with the encrypted data
 * @param  {Function} callback   receives decrypted message as as native JavaScript string
 *                              or null if no literal data found
 */
AsyncProxy.prototype.decryptMessage = function(privateKey, message, callback) {
  privateKey = privateKey.toPacketlist();
  this.worker.postMessage({
    event: 'decrypt-message',
    privateKey: privateKey,
    message: message
  });
  this.tasks.push(callback);
};

/**
 * Decrypts message and verifies signatures
 * @param  {module:key~Key}     privateKey private key with decrypted secret key data
 * @param  {(Array<module:key~Key>|module:key~Key)}  publicKeys array of keys or single key to verify signatures
 * @param  {module:message~Message} message    the message object with signed and encrypted data
 * @param  {Function} callback   receives decrypted message as as native JavaScript string
 *                               with verified signatures or null if no literal data found
 */
AsyncProxy.prototype.decryptAndVerifyMessage = function(privateKey, publicKeys, message, callback) {
  privateKey = privateKey.toPacketlist();
  if (!publicKeys.length) {
    publicKeys = [publicKeys];
  }
  publicKeys = publicKeys.map(function(key) {
    return key.toPacketlist();
  });
  this.worker.postMessage({
    event: 'decrypt-and-verify-message',
    privateKey: privateKey,
    publicKeys: publicKeys,
    message: message
  });
  this.tasks.push(function(err, data) {
    if (data) {
      data.signatures = data.signatures.map(function(sig) {
        sig.keyid = type_keyid.fromClone(sig.keyid);
        return sig;
      });
    }
    callback(err, data);
  });
};

/**
 * Signs a cleartext message
 * @param  {(Array<module:key~Key>|module:key~Key)}  privateKeys array of keys or single key, with decrypted secret key data to sign cleartext
 * @param  {String} text        cleartext
 * @param  {Function} callback       receives ASCII armored message
 */
AsyncProxy.prototype.signClearMessage = function(privateKeys, text, callback) {
  if (!privateKeys.length) {
    privateKeys = [privateKeys];
  }
  privateKeys = privateKeys.map(function(key) {
    return key.toPacketlist();
  });
  this.worker.postMessage({
    event: 'sign-clear-message',
    privateKeys: privateKeys,
    text: text
  });
  this.tasks.push(callback);
};

/**
 * Verifies signatures of cleartext signed message
 * @param  {(Array<module:key~Key>|module:key~Key)}  publicKeys array of keys or single key, to verify signatures
 * @param  {module:cleartext~CleartextMessage} message    cleartext message object with signatures
 * @param  {Function} callback   receives cleartext with status of verified signatures
 */
AsyncProxy.prototype.verifyClearSignedMessage = function(publicKeys, message, callback) {
  if (!publicKeys.length) {
    publicKeys = [publicKeys];
  }
  publicKeys = publicKeys.map(function(key) {
    return key.toPacketlist();
  });
  this.worker.postMessage({
    event: 'verify-clear-signed-message',
    publicKeys: publicKeys,
    message: message
  });
  this.tasks.push(function(err, data) {
    if (data) {
      data.signatures = data.signatures.map(function(sig) {
        sig.keyid = type_keyid.fromClone(sig.keyid);
        return sig;
      });
    }
    callback(err, data);
  });
};

/**
 * Generates a new OpenPGP key pair. Currently only supports RSA keys.
 * Primary and subkey will be of same type.
 * @param {module:enums.publicKey} keyType    to indicate what type of key to make.
 *                             RSA is 1. See {@link http://tools.ietf.org/html/rfc4880#section-9.1}
 * @param {Integer} numBits    number of bits for the key creation. (should be 1024+, generally)
 * @param {String}  userId     assumes already in form of "User Name <username@email.com>"
 * @param {String}  passphrase The passphrase used to encrypt the resulting private key
 * @param {Function} callback receives object with key and public and private armored texts
 */
AsyncProxy.prototype.generateKeyPair = function(options, callback) {
  this.worker.postMessage({
    event: 'generate-key-pair',
    options: options
  });
  this.tasks.push(function(err, data) {
    if (data) {
      var packetlist = packet.List.fromStructuredClone(data.key);
      data.key = new key.Key(packetlist);
    }
    callback(err, data);
  });
};

/**
 * Decrypts secret part of all secret key packets of key.
 * @param  {module:key~Key}     privateKey private key with encrypted secret key data
 * @param  {String} password    password to unlock the key
 * @param  {Function} callback   receives decrypted key
 */
AsyncProxy.prototype.decryptKey = function(privateKey, password, callback) {
  privateKey = privateKey.toPacketlist();
  this.worker.postMessage({
    event: 'decrypt-key',
    privateKey: privateKey,
    password: password
  });
  this.tasks.push(function(err, data) {
    if (data) {
      var packetlist = packet.List.fromStructuredClone(data);
      data = new key.Key(packetlist);
    }
    callback(err, data);
  });
};

/**
 * Decrypts secret part of key packets matching array of keyids.
 * @param  {module:key~Key}     privateKey private key with encrypted secret key data
 * @param  {Array<module:type/keyid>} keyIds
 * @param  {String} password    password to unlock the key
 * @param  {Function} callback   receives decrypted key
 */
AsyncProxy.prototype.decryptKeyPacket = function(privateKey, keyIds, password, callback) {
  privateKey = privateKey.toPacketlist();
  this.worker.postMessage({
    event: 'decrypt-key-packet',
    privateKey: privateKey,
    keyIds: keyIds,
    password: password
  });
  this.tasks.push(function(err, data) {
    if (data) {
      var packetlist = packet.List.fromStructuredClone(data);
      data = new key.Key(packetlist);
    }
    callback(err, data);
  });
};

module.exports = AsyncProxy;
