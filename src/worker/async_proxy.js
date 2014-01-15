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

var INITIAL_SEED = 4096, // bytes seeded to worker
    SEED_REQUEST = 4096, // bytes seeded after worker request
    RSA_FACTOR = 2,
    DSA_FACTOR = 2,
    ELG_FACTOR = 2;

/**
 * Initializes a new proxy and loads the web worker
 * @constructor
 * @param {String} path The path to the worker or 'openpgp.worker.js' by default
 */
function AsyncProxy(path) {
  this.worker = new Worker(path || 'openpgp.worker.js');
  this.worker.onmessage = this.onMessage.bind(this);
  this.seedRandom(INITIAL_SEED);
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
      this.seedRandom(SEED_REQUEST);
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
 * Get Uint32Array with random numbers
 * @param  {Integer} size Length of buffer
 * @return {Uint32Array}
 */
AsyncProxy.prototype.getRandomBuffer = function(size) {
  if (!size) return null;
  var buf = new Uint32Array(size);
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
 * Estimation on how much random bytes are required to process the operation
 * @param  {String} op          'enc', 'sig' or 'gen'
 * @param  {Array<module:key~Key>} publicKeys
 * @param  {Array<module:key~Key>} privateKeys
 * @param  {Object} options
 * @return {Integer}             number of bytes required
 */
AsyncProxy.prototype.entropyEstimation = function(op, publicKeys, privateKeys, options) {
  var requ = 0; // required entropy in bytes
  switch (op) {
    case 'enc':
      requ += 32; // max. size of session key
      requ += 16; // max. size CFB prefix random
      publicKeys && publicKeys.forEach(function(key) {
        var subKeyPackets = key.getSubkeyPackets();
        for (var i = 0; i < subKeyPackets.length; i++) {
          if (enums.write(enums.publicKey, subKeyPackets[i].algorithm) == enums.publicKey.elgamal) {
            var keyByteSize = subKeyPackets[i].mpi[0].byteLength();
            requ += keyByteSize * ELG_FACTOR; // key byte size for ElGamal keys
            break;
          }
        }
      });
      break;
    case 'sig':
      privateKeys && privateKeys.forEach(function(key) {
        if (enums.write(enums.publicKey, key.primaryKey.algorithm) == enums.publicKey.dsa) {
          requ += 32 * DSA_FACTOR; // 32 bytes for DSA keys
        }
      });
      break;
    case 'gen':
      requ += 8; // salt for S2K;
      requ += 16; // CFB initialization vector
      requ += (Math.ceil(options.numBits / 8) + 1) * RSA_FACTOR;
      requ = requ * 2; // * number of key packets
      break;
    default:
      throw new Error('Unknown operation.');
  }
  return requ;
};

/**
 * Encrypts message text with keys
 * @param  {Array<module:key~Key>}  keys array of keys, used to encrypt the message
 * @param  {String} text message as native JavaScript string
 * @param  {Function} callback receives encrypted ASCII armored message
 */
AsyncProxy.prototype.encryptMessage = function(keys, text, callback) {
  var estimation = this.entropyEstimation('enc', keys);
  keys = keys.map(function(key) {
    return key.toPacketlist();
  });
  this.worker.postMessage({
    event: 'encrypt-message', 
    keys: keys,
    text: text,
    seed: this.getRandomBuffer(estimation)
  });
  this.tasks.push(callback);
};

/**
 * Signs message text and encrypts it
 * @param  {Array<module:key~Key>}  publicKeys array of keys, used to encrypt the message
 * @param  {module:key~Key}    privateKey private key with decrypted secret key data for signing
 * @param  {String} text       message as native JavaScript string
 * @param  {Function} callback receives encrypted ASCII armored message
 */
AsyncProxy.prototype.signAndEncryptMessage = function(publicKeys, privateKey, text, callback) {
  var estimation = this.entropyEstimation('enc', publikKeys) +
                   this.entropyEstimation('sig', null, [privateKey]);
  publicKeys = publicKeys.map(function(key) {
    return key.toPacketlist();
  });
  privateKey = privateKey.toPacketlist();
  this.worker.postMessage({
    event: 'sign-and-encrypt-message', 
    publicKeys: publicKeys,
    privateKey: privateKey,
    text: text,
    seed: this.getRandomBuffer(estimation)
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
 * @param  {Array<module:key~Key>}   publicKeys public keys to verify signatures
 * @param  {module:message~Message} message    the message object with signed and encrypted data
 * @param  {Function} callback   receives decrypted message as as native JavaScript string
 *                               with verified signatures or null if no literal data found
 */
AsyncProxy.prototype.decryptAndVerifyMessage = function(privateKey, publicKeys, message, callback) {
  privateKey = privateKey.toPacketlist();
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
 * @param  {Array<module:key~Key>}  privateKeys private key with decrypted secret key data to sign cleartext
 * @param  {String} text        cleartext
 * @param  {Function} callback       receives ASCII armored message
 */
AsyncProxy.prototype.signClearMessage = function(privateKeys, text, callback) {
  var estimation = this.entropyEstimation('sig', null, privateKeys);
  privateKeys = privateKeys.map(function(key) {
    return key.toPacketlist();
  });
  this.worker.postMessage({
    event: 'sign-clear-message', 
    privateKeys: privateKeys,
    text: text,
    seed: this.getRandomBuffer(estimation)
  });
  this.tasks.push(callback);
};

/**
 * Verifies signatures of cleartext signed message
 * @param  {Array<module:key~Key>}            publicKeys public keys to verify signatures
 * @param  {module:cleartext~CleartextMessage} message    cleartext message object with signatures
 * @param  {Function} callback   receives cleartext with status of verified signatures
 */
AsyncProxy.prototype.verifyClearSignedMessage = function(publicKeys, message, callback) {
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
AsyncProxy.prototype.generateKeyPair = function(keyType, numBits, userId, passphrase, callback) {
  this.worker.postMessage({
    event: 'generate-key-pair', 
    keyType: keyType, 
    numBits: numBits, 
    userId: userId, 
    passphrase: passphrase,
    seed: this.getRandomBuffer(this.entropyEstimation('gen', null, null, {numBits: numBits}))
  });
  this.tasks.push(function(err, data) {
    if (data) {
      var packetlist = packet.List.fromStructuredClone(data.key);
      data.key = new key.Key(packetlist);
    }
    callback(err, data);
  });
};

module.exports = AsyncProxy;
