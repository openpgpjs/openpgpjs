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

import * as message from './message.js';
import * as cleartext from './cleartext.js';
import * as key from './key.js';
import armor from './encoding/armor.js';
import enums from './enums.js';
import config from './config/config.js';
import util from './util';
import AsyncProxy from './worker/async_proxy.js';
import es6Promise from 'es6-promise';

es6Promise.polyfill(); // load ES6 Promises polyfill

let asyncProxy = null; // instance of the asyncproxy

/**
 * Set the path for the web worker script and create an instance of the async proxy
 * @param {String} path relative path to the worker scripts, default: 'openpgp.worker.js'
 * @param {Object} [options.worker=Object] alternative to path parameter:
 *                                         web worker initialized with 'openpgp.worker.js'
 * @return {Boolean} true if worker created successfully
 */
export function initWorker({ path='openpgp.worker.js', worker } = {}) {
  if (worker || typeof window !== 'undefined' && window.Worker) {
    asyncProxy = new AsyncProxy({ path, worker, config });
    return true;
  } else {
    return false;
  }
}

/**
 * Returns a reference to the async proxy if the worker was initialized with openpgp.initWorker()
 * @return {module:worker/async_proxy~AsyncProxy|null} the async proxy or null if not initialized
 */
export function getWorker() {
  return asyncProxy;
}

/**
 * Encrypts message text/data with keys or passwords
 * @param  {(Array<module:key~Key>|module:key~Key)} keys       array of keys or single key, used to encrypt the message
 * @param  {String} data                                       text/data message as native JavaScript string/binary string
 * @param  {(Array<String>|String)} passwords                  passwords for the message
 * @param  {Object} params                                     parameter object with optional properties binary {Boolean},
 *                                                             filename {String}, and packets {Boolean}
 * @return {Promise<String> or Promise<Packetlist>}            encrypted ASCII armored message, or Packetlist if params.packets is true
 * @static
 */
export function encryptMessage({ keys, data, passwords, filename, packets } = {}) {
  if (asyncProxy) { return asyncProxy.encryptMessage({ keys, data, passwords, filename, packets }); }

  return execute(() => {

    let msg;
    if (data instanceof Uint8Array) { msg = message.fromBinary(data, filename); }
    else { msg = message.fromText(data, filename); }
    msg = msg.encrypt(keys, passwords);

    if(packets) {

      const dataIndex = msg.packets.indexOfTag(enums.packet.symmetricallyEncrypted,enums.packet.symEncryptedIntegrityProtected)[0];
      const obj = {
        keys: msg.packets.slice(0,dataIndex).write(),
        data: msg.packets.slice(dataIndex,msg.packets.length).write()
      };
      return obj;

    } else {
      return armor.encode(enums.armor.message, msg.packets.write());
    }

  }, 'Error encrypting message!');
}

/**
 * Encrypts session key with keys or passwords
 * @param  {String} sessionKey                                 sessionKey as a binary string
 * @param  {String} algo                                       algorithm of sessionKey
 * @param  {(Array<module:key~Key>|module:key~Key)} keys       array of keys or single key, used to encrypt the key
 * @param  {(Array<String>|String)} passwords                  passwords for the message
 * @return {Promise<Packetlist>}                               Binary string of key packets
 * @static
 */
export function encryptSessionKey({ sessionKey, algo, keys, passwords } = {}) {
  if (asyncProxy) { return asyncProxy.encryptSessionKey({ sessionKey, algo, keys, passwords }); }

  return execute(() => message.encryptSessionKey(sessionKey, algo, keys, passwords).packets.write(),
    'Error encrypting session key!');
}

/**
 * Signs message text and encrypts it
 * @param  {(Array<module:key~Key>|module:key~Key)}  publicKeys array of keys or single key, used to encrypt the message
 * @param  {module:key~Key}    privateKey private key with decrypted secret key data for signing
 * @param  {String} text       message as native JavaScript string
 * @return {Promise<String>}   encrypted ASCII armored message
 * @static
 */
export function signAndEncryptMessage({ publicKeys, privateKey, text } = {}) {
  publicKeys = publicKeys.length ? publicKeys : [publicKeys];

  if (asyncProxy) { return asyncProxy.signAndEncryptMessage({ publicKeys, privateKey, text }); }

  return execute(() => {

    let msg = message.fromText(text);
    msg = msg.sign([privateKey]);
    msg = msg.encrypt(publicKeys);
    return armor.encode(enums.armor.message, msg.packets.write());

  }, 'Error signing and encrypting message!');
}

/**
 * Decrypts message
 * @param  {module:key~Key|String} privateKey   private key with decrypted secret key data, string password, or session key
 * @param  {module:message~Message} msg         the message object with the encrypted data
 * @param  {Object} params                      parameter object with optional properties binary {Boolean}
 *                                              and sessionKeyAlgorithm {String} which must only be set when privateKey is a session key
 * @return {Promise<(String|null)>}             decrypted message as as native JavaScript string
 *                                              or null if no literal data found
 * @static
 */
export function decryptMessage({ privateKey, msg, binary, sessionKeyAlgorithm } = {}) {
  if (asyncProxy) { return asyncProxy.decryptMessage({ privateKey, msg, binary, sessionKeyAlgorithm }); }

  return execute(() => {

    msg = msg.decrypt(privateKey, sessionKeyAlgorithm);
    if(binary) {
      return { data: msg.getLiteralData(), filename: msg.getFilename() };
    } else {
      return msg.getText();
    }

  }, 'Error decrypting message!');
}

/**
 * Decrypts message
 * @param  {module:key~Key|String} privateKey   private key with decrypted secret key data or string password
 * @param  {module:message~Message} msg         the message object with the encrypted session key packets
 * @return {Promise<Object|null>}               decrypted session key and algorithm in object form
 *                                              or null if no key packets found
 * @static
 */
export function decryptSessionKey({ privateKey, msg } = {}) {
  if (asyncProxy) { return asyncProxy.decryptSessionKey({ privateKey, msg }); }

  return execute(() => msg.decryptSessionKey(privateKey), 'Error decrypting session key!');
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
export function decryptAndVerifyMessage({ privateKey, publicKeys, msg } = {}) {
  publicKeys = publicKeys.length ? publicKeys : [publicKeys];

  if (asyncProxy) { return asyncProxy.decryptAndVerifyMessage({ privateKey, publicKeys, msg }); }

  return execute(() => {

    msg = msg.decrypt(privateKey);
    const result = { text:msg.getText() };
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
export function signClearMessage({ privateKeys, text } = {}) {
  privateKeys = privateKeys.length ? privateKeys : [privateKeys];

  if (asyncProxy) { return asyncProxy.signClearMessage({ privateKeys, text }); }

  return execute(() => {

    const cleartextMessage = new cleartext.CleartextMessage(text);
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
export function verifyClearSignedMessage({ publicKeys, msg } = {}) {
  publicKeys = publicKeys.length ? publicKeys : [publicKeys];

  if (asyncProxy) { return asyncProxy.verifyClearSignedMessage({ publicKeys, msg }); }

  return execute(() => {

    if (!(msg instanceof cleartext.CleartextMessage)) { throw new Error('Parameter [message] needs to be of type CleartextMessage.'); }
    return { text:msg.getText(), signatures:msg.verify(publicKeys) };

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
export function generateKeyPair({ numBits=2048, userId, passphrase, unlocked=false } = {}) {
  const options = { numBits, userId, passphrase, unlocked };

  // use web worker if web crypto apis are not supported
  if (!util.getWebCrypto() && asyncProxy) { return asyncProxy.generateKeyPair(options); }

  return key.generate(options).then(newKey => ({

    key: newKey,
    privateKeyArmored: newKey.armor(),
    publicKeyArmored: newKey.toPublic().armor()

  })).catch(err => {

    // js fallback already tried
    console.error(err);
    if (!util.getWebCrypto()) { throw new Error('Error generating keypair using js fallback!'); }
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
  const promise = new Promise(resolve => resolve(cmd()));
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
  if (config.debug) { console.error(error.stack); }
  // rethrow new high level error for api users
  throw new Error(message);
}
