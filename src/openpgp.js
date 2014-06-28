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

var armor = require('./encoding/armor.js'),
  packet = require('./packet'),
  enums = require('./enums.js'),
  config = require('./config'),
  message = require('./message.js'),
  cleartext = require('./cleartext.js'),
  key = require('./key.js'),
  AsyncProxy = require('./worker/async_proxy.js');

var asyncProxy; // instance of the asyncproxy

/**
 * Set the path for the web worker script and create an instance of the async proxy
 * @param {String} path relative path to the worker scripts
 */
function initWorker(path) {
  asyncProxy = new AsyncProxy(path);
}

/**
 * Encrypts message text with keys
 * @param  {(Array<module:key~Key>|module:key~Key)}  keys array of keys or single key, used to encrypt the message
 * @param  {String} text message as native JavaScript string
 * @param  {function} callback (optional) callback(error, result) for async style
 * @return {String}      encrypted ASCII armored message
 * @static
 */
function encryptMessage(keys, text, callback) {
  if (!keys.length) {
    keys = [keys];
  }

  if (useWorker(callback)) {
    asyncProxy.encryptMessage(keys, text, callback);
    return;
  }

  return execute(function() {
    var msg, armored;
    msg = message.fromText(text);
    msg = msg.encrypt(keys);
    armored = armor.encode(enums.armor.message, msg.packets.write());
    return armored;
  }, callback);
}

/**
 * Signs message text and encrypts it
 * @param  {(Array<module:key~Key>|module:key~Key)}  publicKeys array of keys or single key, used to encrypt the message
 * @param  {module:key~Key}    privateKey private key with decrypted secret key data for signing
 * @param  {String} text       message as native JavaScript string
 * @param  {function} callback (optional) callback(error, result) for async style
 * @return {String}            encrypted ASCII armored message
 * @static
 */
function signAndEncryptMessage(publicKeys, privateKey, text, callback) {
  if (!publicKeys.length) {
    publicKeys = [publicKeys];
  }

  if (useWorker(callback)) {
    asyncProxy.signAndEncryptMessage(publicKeys, privateKey, text, callback);
    return;
  }

  return execute(function() {
    var msg, armored;
    msg = message.fromText(text);
    msg = msg.sign([privateKey]);
    msg = msg.encrypt(publicKeys);
    armored = armor.encode(enums.armor.message, msg.packets.write());
    return armored;
  }, callback);
}

/**
 * Decrypts message
 * @param  {module:key~Key}     privateKey private key with decrypted secret key data
 * @param  {module:message~Message} msg    the message object with the encrypted data
 * @param  {function} callback (optional) callback(error, result) for async style
 * @return {(String|null)}        decrypted message as as native JavaScript string
 *                              or null if no literal data found
 * @static
 */
function decryptMessage(privateKey, msg, callback) {
  if (useWorker(callback)) {
    asyncProxy.decryptMessage(privateKey, msg, callback);
    return;
  }

  return execute(function() {
    msg = msg.decrypt(privateKey);
    return msg.getText();
  }, callback);
}

/**
 * Decrypts message and verifies signatures
 * @param  {module:key~Key}     privateKey private key with decrypted secret key data
 * @param  {(Array<module:key~Key>|module:key~Key)}  publicKeys array of keys or single key, to verify signatures
 * @param  {module:message~Message} msg    the message object with signed and encrypted data
 * @param  {function} callback (optional) callback(error, result) for async style
 * @return {{text: String, signatures: Array<{keyid: module:type/keyid, valid: Boolean}>}}
 *                              decrypted message as as native JavaScript string
 *                              with verified signatures or null if no literal data found
 * @static
 */
function decryptAndVerifyMessage(privateKey, publicKeys, msg, callback) {
  if (!publicKeys.length) {
    publicKeys = [publicKeys];
  }

  if (useWorker(callback)) {
    asyncProxy.decryptAndVerifyMessage(privateKey, publicKeys, msg, callback);
    return;
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
  }, callback);
}

/**
 * Signs a cleartext message
 * @param  {(Array<module:key~Key>|module:key~Key)}  privateKeys array of keys or single key with decrypted secret key data to sign cleartext
 * @param  {String} text        cleartext
 * @param  {function} callback (optional) callback(error, result) for async style
 * @return {String}             ASCII armored message
 * @static
 */
function signClearMessage(privateKeys, text, callback) {
  if (!privateKeys.length) {
    privateKeys = [privateKeys];
  }

  if (useWorker(callback)) {
    asyncProxy.signClearMessage(privateKeys, text, callback);
    return;
  }

  return execute(function() {
    var cleartextMessage = new cleartext.CleartextMessage(text);
    cleartextMessage.sign(privateKeys);
    return cleartextMessage.armor();
  }, callback);
}

/**
 * Verifies signatures of cleartext signed message
 * @param  {(Array<module:key~Key>|module:key~Key)}  publicKeys array of keys or single key, to verify signatures
 * @param  {module:cleartext~CleartextMessage} msg    cleartext message object with signatures
 * @param  {function} callback (optional) callback(error, result) for async style
 * @return {{text: String, signatures: Array<{keyid: module:type/keyid, valid: Boolean}>}}
 *                                       cleartext with status of verified signatures
 * @static
 */
function verifyClearSignedMessage(publicKeys, msg, callback) {
  if (!publicKeys.length) {
    publicKeys = [publicKeys];
  }

  if (useWorker(callback)) {
    asyncProxy.verifyClearSignedMessage(publicKeys, msg, callback);
    return;
  }

  return execute(function() {
    var result = {};
    if (!(msg instanceof cleartext.CleartextMessage)) {
      throw new Error('Parameter [message] needs to be of type CleartextMessage.');
    }
    result.text = msg.getText();
    result.signatures = msg.verify(publicKeys);
    return result;
  }, callback);
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
 * @param  {function} callback (optional) callback(error, result) for async style
 * @return {Object} {key: module:key~Key, privateKeyArmored: String, publicKeyArmored: String}
 * @static
 */
function generateKeyPair(options, callback) {
  if (useWorker(callback)) {
    asyncProxy.generateKeyPair(options, callback);
    return;
  }

  return execute(function() {
    var result = {};
    var newKey = key.generate(options);
    result.key = newKey;
    result.privateKeyArmored = newKey.armor();
    result.publicKeyArmored = newKey.toPublic().armor();
    return result;
  }, callback);
}

//
// helper functions
//

/**
 * Are we in a browser and do we support worker?
 */
function useWorker(callback) {
  if (typeof window === 'undefined' || !window.Worker || typeof callback !== 'function') {
    return false;
  }

  if (!asyncProxy) {
    throw new Error('You need to set the worker path!');
  }

  return true;
}

/**
 * Command pattern that handles async calls gracefully
 */
function execute(cmd, callback) {
  var result;

  try {
    result = cmd();
  } catch (err) {
    if (callback) {
      callback(err);
      return;
    }

    throw err;
  }

  if (callback) {
    callback(null, result);
    return;
  }

  return result;
}

exports.initWorker = initWorker;
exports.encryptMessage = encryptMessage;
exports.signAndEncryptMessage = signAndEncryptMessage;
exports.decryptMessage = decryptMessage;
exports.decryptAndVerifyMessage = decryptAndVerifyMessage;
exports.signClearMessage = signClearMessage;
exports.verifyClearSignedMessage = verifyClearSignedMessage;
exports.generateKeyPair = generateKeyPair;
