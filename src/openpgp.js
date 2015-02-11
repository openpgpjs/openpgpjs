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
 * @fileoverview The openpgp base module should provide all of the functionality
 * to consume the openpgp.js library. All additional classes are documented
 * for extending and developing on top of the base library.
 */

/**
 * @requires cleartext
 * @requires config
 * @requires encoding/armor
 * @requires enums
 * @requires message
 * @requires packet
 * @module openpgp
 */

'use strict';

var armor = require('./encoding/armor.js'),
  enums = require('./enums.js'),
  message = require('./message.js'),
  cleartext = require('./cleartext.js'),
  key = require('./key.js'),
  util = require('./util'),
  AsyncProxy = require('./worker/async_proxy.js');

if (typeof Promise === 'undefined') {
  // load ES6 Promises polyfill
  require('es6-promise').polyfill();
}

var asyncProxy = null; // instance of the asyncproxy

/**
 * Set the path for the web worker script and create an instance of the async proxy
 * @param {String} path relative path to the worker scripts, default: 'openpgp.worker.js'
 * @param {Object} [options.worker=Object] alternative to path parameter:
 *                                         web worker initialized with 'openpgp.worker.js'
 * @return {Boolean} true if worker created successfully
 */
function initWorker(path, options) {
  if (options && options.worker || typeof window !== 'undefined' && window.Worker) {
    options = options || {};
    options.config = this.config;
    asyncProxy = new AsyncProxy(path, options);
    return true;
  } else {
    return false;
  }
}

/**
 * Returns a reference to the async proxy if the worker was initialized with openpgp.initWorker()
 * @return {module:worker/async_proxy~AsyncProxy|null} the async proxy or null if not initialized
 */
function getWorker() {
  return asyncProxy;
}

/**
 * Encrypts message text with keys
 * @param  {(Array<module:key~Key>|module:key~Key)}  keys array of keys or single key, used to encrypt the message
 * @param  {String} text message as native JavaScript string
 * @return {Promise<String>}      encrypted ASCII armored message
 * @static
 */
function encryptMessage(keys, text) {
  if (!keys.length) {
    keys = [keys];
  }

  if (asyncProxy) {
    return asyncProxy.encryptMessage(keys, text);
  }

  return execute(function() {
    var msg, armored;
    msg = message.fromText(text);
    msg = msg.encrypt(keys);
    armored = armor.encode(enums.armor.message, msg.packets.write());
    return armored;

  }, 'Error encrypting message!');
}

/**
 * Signs message text and encrypts it
 * @param  {(Array<module:key~Key>|module:key~Key)}  publicKeys array of keys or single key, used to encrypt the message
 * @param  {module:key~Key}    privateKey private key with decrypted secret key data for signing
 * @param  {String} text       message as native JavaScript string
 * @return {Promise<String>}   encrypted ASCII armored message
 * @static
 */
function signAndEncryptMessage(publicKeys, privateKey, text) {
  if (!publicKeys.length) {
    publicKeys = [publicKeys];
  }

  if (asyncProxy) {
    return asyncProxy.signAndEncryptMessage(publicKeys, privateKey, text);
  }

  return execute(function() {
    var msg, armored;
    msg = message.fromText(text);
    msg = msg.sign([privateKey]);
    msg = msg.encrypt(publicKeys);
    armored = armor.encode(enums.armor.message, msg.packets.write());
    return armored;

  }, 'Error signing and encrypting message!');
}

/**
 * Decrypts message
 * @param  {module:key~Key}                privateKey private key with decrypted secret key data
 * @param  {module:message~Message} msg    the message object with the encrypted data
 * @return {Promise<(String|null)>}        decrypted message as as native JavaScript string
 *                              or null if no literal data found
 * @static
 */
function decryptMessage(privateKey, msg) {
  if (asyncProxy) {
    return asyncProxy.decryptMessage(privateKey, msg);
  }

  return execute(function() {
    msg = msg.decrypt(privateKey);
    return msg.getText();

  }, 'Error decrypting message!');
}

/**
 * Decrypts message and verifies signatures
 * @param  {module:key~Key}     privateKey private key with decrypted secret key data
 * @param  {(Array<module:key~Key>|module:key~Key)}  publicKeys array of keys or single key, to verify signatures
 * @param  {module:message~Message} msg    the message object with signed and encrypted data
 * @return {Promise<{text: String, signatures: Array<{keyid: module:type/keyid, valid: Boolean}>}>}
 *                              decrypted message as as native JavaScript string
 *                              with verified signatures or null if no literal data found
 * @static
 */
function decryptAndVerifyMessage(privateKey, publicKeys, msg) {
  if (!publicKeys.length) {
    publicKeys = [publicKeys];
  }

  if (asyncProxy) {
    return asyncProxy.decryptAndVerifyMessage(privateKey, publicKeys, msg);
  }

  return execute(function() {
    var result = {};
    msg = msg.decrypt(privateKey);
    result.text = msg.getText();
    if (result.text) {
      result.signatures = msg.verify(publicKeys);
      return result;
    }
    return null;

  }, 'Error decrypting and verifying message!');
}

/**
 * Signs a cleartext message
 * @param  {(Array<module:key~Key>|module:key~Key)}  privateKeys array of keys or single key with decrypted secret key data to sign cleartext
 * @param  {String} text        cleartext
 * @return {Promise<String>}    ASCII armored message
 * @static
 */
function signClearMessage(privateKeys, text) {
  if (!privateKeys.length) {
    privateKeys = [privateKeys];
  }

  if (asyncProxy) {
    return asyncProxy.signClearMessage(privateKeys, text);
  }

  return execute(function() {
    var cleartextMessage = new cleartext.CleartextMessage(text);
    cleartextMessage.sign(privateKeys);
    return cleartextMessage.armor();

  }, 'Error signing cleartext message!');
}

/**
 * Verifies signatures of cleartext signed message
 * @param  {(Array<module:key~Key>|module:key~Key)}  publicKeys array of keys or single key, to verify signatures
 * @param  {module:cleartext~CleartextMessage} msg    cleartext message object with signatures
 * @return {Promise<{text: String, signatures: Array<{keyid: module:type/keyid, valid: Boolean}>}>}
 *                                       cleartext with status of verified signatures
 * @static
 */
function verifyClearSignedMessage(publicKeys, msg) {
  if (!publicKeys.length) {
    publicKeys = [publicKeys];
  }

  if (asyncProxy) {
    return asyncProxy.verifyClearSignedMessage(publicKeys, msg);
  }

  return execute(function() {
    var result = {};
    if (!(msg instanceof cleartext.CleartextMessage)) {
      throw new Error('Parameter [message] needs to be of type CleartextMessage.');
    }
    result.text = msg.getText();
    result.signatures = msg.verify(publicKeys);
    return result;

  }, 'Error verifying cleartext signed message!');
}

/**
 * Generates a new OpenPGP key pair. Currently only supports RSA keys.
 * Primary and subkey will be of same type.
 * @param {module:enums.publicKey} [options.keyType=module:enums.publicKey.rsa_encrypt_sign]    to indicate what type of key to make.
 *                             RSA is 1. See {@link http://tools.ietf.org/html/rfc4880#section-9.1}
 * @param {Integer} options.numBits    number of bits for the key creation. (should be 1024+, generally)
 * @param {String}  options.userId     assumes already in form of "User Name <username@email.com>"
 * @param {String}  options.passphrase The passphrase used to encrypt the resulting private key
 * @param {Boolean} [options.unlocked=false]    The secret part of the generated key is unlocked
 * @return {Promise<Object>} {key: module:key~Key, privateKeyArmored: String, publicKeyArmored: String}
 * @static
 */
function generateKeyPair(options) {
  // use web worker if web crypto apis are not supported
  if (!util.getWebCrypto() && asyncProxy) {
    return asyncProxy.generateKeyPair(options);
  }

  return key.generate(options).then(function(newKey) {
    var result = {};
    result.key = newKey;
    result.privateKeyArmored = newKey.armor();
    result.publicKeyArmored = newKey.toPublic().armor();
    return result;

  }).catch(function(err) {
    console.error(err);

    if (!util.getWebCrypto()) {
      // js fallback already tried
      throw new Error('Error generating keypair using js fallback!');
    }

    // fall back to js keygen in a worker
    console.log('Error generating keypair using native WebCrypto... falling back back to js!');
    return asyncProxy.generateKeyPair(options);

  }).catch(onError.bind(null, 'Error generating keypair!'));
}

//
// helper functions
//

/**
 * Command pattern that wraps synchronous code into a promise
 * @param  {function} cmd     The synchronous function with a return value
 *                            to be wrapped in a promise
 * @param  {String}   errMsg  A human readable error Message
 * @return {Promise}          The promise wrapped around cmd
 */
function execute(cmd, errMsg) {
  // wrap the sync cmd in a promise
  var promise = new Promise(function(resolve) {
    var result = cmd();
    resolve(result);
  });

  // handler error globally
  return promise.catch(onError.bind(null, errMsg));
}

/**
 * Global error handler that logs the stack trace and
 *   rethrows a high lvl error message
 * @param  {String} message   A human readable high level error Message
 * @param  {Error}  error     The internal error that caused the failure
 */
function onError(message, error) {
  // log the stack trace
  console.error(error.stack);
  // rethrow new high level error for api users
  throw new Error(message);
}

exports.initWorker = initWorker;
exports.getWorker = getWorker;
exports.encryptMessage = encryptMessage;
exports.signAndEncryptMessage = signAndEncryptMessage;
exports.decryptMessage = decryptMessage;
exports.decryptAndVerifyMessage = decryptAndVerifyMessage;
exports.signClearMessage = signClearMessage;
exports.verifyClearSignedMessage = verifyClearSignedMessage;
exports.generateKeyPair = generateKeyPair;