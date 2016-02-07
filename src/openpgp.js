// OpenPGP.js - An OpenPGP implementation in javascript
// Copyright (C) 2016 Tankred Hase
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

'use strict';

import * as messageLib from './message.js';
import * as cleartext from './cleartext.js';
import * as key from './key.js';
import armor from './encoding/armor.js';
import enums from './enums.js';
import config from './config/config.js';
import util from './util';
import AsyncProxy from './worker/async_proxy.js';
import es6Promise from 'es6-promise';
es6Promise.polyfill(); // load ES6 Promises polyfill


//////////////////////////
//                      //
//   Web Worker setup   //
//                      //
//////////////////////////


let asyncProxy = null; // instance of the asyncproxy

/**
 * Set the path for the web worker script and create an instance of the async proxy
 * @param {String} path     relative path to the worker scripts, default: 'openpgp.worker.js'
 * @param {Object} worker   alternative to path parameter: web worker initialized with 'openpgp.worker.js'
 */
export function initWorker({ path='openpgp.worker.js', worker } = {}) {
  if (worker || typeof window !== 'undefined' && window.Worker) {
    asyncProxy = new AsyncProxy({ path, worker, config });
  } else {
    throw new Error('Initializing web worker failed!');
  }
}

/**
 * Returns a reference to the async proxy if the worker was initialized with openpgp.initWorker()
 * @return {module:worker/async_proxy~AsyncProxy|null} the async proxy or null if not initialized
 */
export function getWorker() {
  return asyncProxy;
}


////////////////////////////
//                        //
//   Keypair generation   //
//                        //
////////////////////////////


/**
 * Generates a new OpenPGP key pair. Currently only supports RSA keys. Primary and subkey will be of same type.
 * @param {Array<Object>} userIds   array of user IDs e.g. [{ name:'Phil Zimmermann', email:'phil@openpgp.org' }]
 * @param {String} passphrase       (optional) The passphrase used to encrypt the resulting private key
 * @param {Number} numBits          (optional) number of bits for the key creation. (should be 2048 or 4096)
 * @param {Boolean} unlocked        (optional) If the returned secret part of the generated key is unlocked
 * @return {Promise<Object>}        The generated key object in the form:
 *                                    { key:Key, privateKeyArmored:String, publicKeyArmored:String }
 * @static
 */
export function generateKeyPair({ userIds=[], passphrase, numBits=2048, unlocked=false } = {}) {
  userIds = userIds.map(id => id.name + ' <' + id.email + '>'); // format user ids for internal use
  const options = { userIds, passphrase, numBits, unlocked };

  if (!util.getWebCrypto() && asyncProxy) { // use web worker if web crypto apis are not supported
    return asyncProxy.generateKeyPair(options);
  }

  return key.generate(options).then(newKey => ({

    key: newKey,
    privateKeyArmored: newKey.armor(),
    publicKeyArmored: newKey.toPublic().armor()

  })).catch(err => {

    // js fallback already tried
    console.error(err);
    if (!util.getWebCrypto()) {
      throw new Error('Error generating keypair using js fallback!');
    }
    // fall back to js keygen in a worker
    console.log('Error generating keypair using native WebCrypto... falling back back to js!');
    return asyncProxy.generateKeyPair(options);

  }).catch(onError.bind(null, 'Error generating keypair!'));
}


///////////////////////////////////////////
//                                       //
//   Message encryption and decryption   //
//                                       //
///////////////////////////////////////////


/**
 * Encrypts message text/data with keys or passwords. Either public keys or passwords must be specified.
 *   If private keys are specified those will be used to sign the message.
 * @param {String|Uint8Array} data           text/data to be encrypted as JavaScript binary string or Uint8Array
 * @param {Key|Array<Key>} publicKeys        (optional) array of keys or single key, used to encrypt the message
 * @param {Key|Array<Key>} privateKeys       (optional) private keys for signing. If omitted message will not be signed
 * @param {String|Array<String>} passwords   (optional) array of passwords or a single password to encrypt the message
 * @param {String} filename                  (optional) a filename for the literal data packet
 * @param {Boolean} packets                  (optional) if the return value should be a Packetlist
 * @return {Promise<String|Packetlist>}      encrypted ASCII armored message, or Packetlist if 'packets' is true
 * @static
 */
export function encrypt({ data, publicKeys, privateKeys, passwords, filename, packets }) {
  publicKeys = publicKeys ? (publicKeys.length ? publicKeys : [publicKeys]) : undefined; // normalize key objects to arrays
  privateKeys = privateKeys ? (privateKeys.length ? privateKeys : [privateKeys]) : undefined;

  if (asyncProxy) { // use web worker if available
    return asyncProxy.encrypt({ data, publicKeys, privateKeys, passwords, filename, packets });
  }

  return execute(() => {

    let msg = createMessage(data, filename);
    if (privateKeys) { // sign the message only if private keys are specified
      msg = msg.sign(privateKeys);
    }
    msg = msg.encrypt(publicKeys, passwords);

    if(packets) {
      return getPackets(msg);
    } else {
      return getAsciiArmored(msg);
    }

  }, 'Error encrypting message!');
}

/**
 * Decrypts a message with the user's private key, a session key or a password.
 *   Either a private key, a session key or a password must be specified.
 * @param {Message} message             the message object with the encrypted data
 * @param {Key} privateKey              (optional) private key with decrypted secret key data or session key
 * @param {Key|Array<Key>} publickeys   (optional) array of publickeys or single key, to verify signatures
 * @param {String} sessionKey           (optional) session key as a binary string
 * @param {String} password             (optional) single password to decrypt the message
 * @param {String} format               (optional) return data format either as 'utf8' or 'binary'
 * @return {Promise<Object>}            decrypted and verified message in the form:
 *                                        { data:Uint8Array|String, filename:String, signatures:[{ keyid:String, valid:Boolean }] }
 * @static
 */
export function decrypt({ message, privateKey, publickeys, sessionKey, password, format='utf8' }) {
  publickeys = publickeys ? (publickeys.length ? publickeys : [publickeys]) : undefined; // normalize key objects to arrays

  if (asyncProxy) { // use web worker if available
    return asyncProxy.decrypt({ message, privateKey, publickeys, sessionKey, password, format });
  }

  return execute(() => {

    message = message.decrypt(privateKey, sessionKey, password);
    const result = parseMessage(message, format);
    if (publickeys && result.data) { // verify only if publickeys are specified
      result.signatures = message.verify(publickeys);
    }
    return result;

  }, 'Error decrypting message!');
}


//////////////////////////////////////////
//                                      //
//   Message signing and verification   //
//                                      //
//////////////////////////////////////////


/**
 * Signs a cleartext message
 * @param {String} data                  cleartext input to be signed
 * @param {Key|Array<Key>} privateKeys   array of keys or single key with decrypted secret key data to sign cleartext
 * @return {Promise<String>}             ASCII armored message
 * @static
 */
export function signCleartext({ data, privateKeys }) {
  privateKeys = privateKeys.length ? privateKeys : [privateKeys];

  if (asyncProxy) { // use web worker if available
    return asyncProxy.signCleartext({ data, privateKeys });
  }

  return execute(() => {

    const cleartextMessage = new cleartext.CleartextMessage(data);
    cleartextMessage.sign(privateKeys);
    return {
      data: cleartextMessage.armor()
    };

  }, 'Error signing cleartext message!');
}

/**
 * Verifies signatures of cleartext signed message
 * @param {Key|Array<Key>} publicKeys   array of publicKeys or single key, to verify signatures
 * @param {CleartextMessage} message    cleartext message object with signatures
 * @return {Promise<Object>}            cleartext with status of verified signatures in the form of:
 *                                        { data:String, signatures: [{ keyid:String, valid:Boolean }] }
 * @static
 */
export function verifyCleartext({ message, publicKeys }) {
  publicKeys = publicKeys.length ? publicKeys : [publicKeys];

  if (asyncProxy) { // use web worker if available
    return asyncProxy.verifyCleartext({ message, publicKeys });
  }

  return execute(() => {

    if (!(message instanceof cleartext.CleartextMessage)) {
      throw new Error('Parameter [message] needs to be of type CleartextMessage.');
    }
    return {
      data: message.getText(),
      signatures: message.verify(publicKeys)
    };

  }, 'Error verifying cleartext signed message!');
}


///////////////////////////////////////////////
//                                           //
//   Session key encryption and decryption   //
//                                           //
///////////////////////////////////////////////


/**
 * Encrypts session key with public keys or passwords. Either public keys or password must be specified.
 * @param {String} sessionKey                session key as a binary string
 * @param {String} algo                      algorithm of sessionKey
 * @param {Key|Array<Key>} publicKeys        (optional) array of public keys or single key, used to encrypt the key
 * @param {String|Array<String>} passwords   (optional) passwords for the message
 * @return {Promise<Message>}                Message object containing encrypted key packets
 * @static
 */
export function encryptSessionKey({ sessionKey, algo, publicKeys, passwords }) {
  if (asyncProxy) { // use web worker if available
    return asyncProxy.encryptSessionKey({ sessionKey, algo, publicKeys, passwords });
  }

  return execute(() => ({

    data: messageLib.encryptSessionKey(sessionKey, algo, publicKeys, passwords).packets.write()

  }), 'Error encrypting session key!');
}

/**
 * Decrypts session key with a private key, a session key or password.
 *   Either a private key, session key or a password must be specified.
 * @param {Message} message         the message object with the encrypted session key packets
 * @param {Key} privateKey          (optional) private key with decrypted secret key data
 * @param {String} sessionKey       (optional) session key as a binary string
 * @param {String} password         (optional) a single password to decrypt the session key
 * @return {Promise<Object|null>}   decrypted session key and algorithm in object form:
 *                                    { key:String, algo:String }
 *                                    or null if no key packets found
 * @static
 */
export function decryptSessionKey({ message, privateKey, sessionKey, password }) {
  if (asyncProxy) { // use web worker if available
    return asyncProxy.decryptSessionKey({ message, privateKey, sessionKey, password });
  }

  return execute(() => message.decryptSessionKey(privateKey, sessionKey, password), 'Error decrypting session key!');
}


//////////////////////////
//                      //
//   Helper functions   //
//                      //
//////////////////////////


/**
 * Creates a message obejct either from a Uint8Array or a string.
 * @param  {String|Uint8Array} data   the payload for the message
 * @param  {String} filename          the literal data packet's filename
 * @return {Message}                  a message object
 */
function createMessage(data, filename) {
  let msg;
  if (data instanceof Uint8Array) {
    msg = messageLib.fromBinary(data, filename);
  } else if (typeof data === 'string') {
    msg = messageLib.fromText(data, filename);
  } else {
    throw new Error('Data must be of type String or Uint8Array!');
  }
  return msg;
}

/**
 * Get the Packetlist from a message object.
 * @param  {Message} message   the message object
 * @return {Object}        an object contating keys and data
 */
function getPackets(message) {
  const dataIndex = message.packets.indexOfTag(enums.packet.symmetricallyEncrypted, enums.packet.symEncryptedIntegrityProtected)[0];
  return {
    keys: message.packets.slice(0, dataIndex).write(),
    data: message.packets.slice(dataIndex, message.packets.length).write()
  };
}

/**
 * Get the ascii armored message.
 * @param  {Message} message   the message object
 * @return {Object}            an object containt data
 */
function getAsciiArmored(message) {
  return {
    data: armor.encode(enums.armor.message, message.packets.write())
  };
}

/**
 * Parse the message given a certain format.
 * @param  {Message} message   the message object to be parse
 * @param  {String} format     the output format e.g. 'utf8' or 'binary'
 * @return {Object}            the parse data in the respective format
 */
function parseMessage(message, format) {
  if (format === 'binary') {
    return {
      data: message.getLiteralData(),
      filename: message.getFilename()
    };
  } else if (format === 'utf8') {
    return {
      data: message.getText()
    };
  } else {
    throw new Error('Invalid format!');
  }
}

/**
 * Command pattern that wraps synchronous code into a promise.
 * @param {function} cmd    The synchronous function with a return value
 *                            to be wrapped in a promise
 * @param {String} message   A human readable error Message
 * @return {Promise}          The promise wrapped around cmd
 */
function execute(cmd, message) {
  // wrap the sync cmd in a promise
  const promise = new Promise(resolve => resolve(cmd()));
  // handler error globally
  return promise.catch(onError.bind(null, message));
}

/**
 * Global error handler that logs the stack trace and rethrows a high lvl error message.
 * @param {String} message   A human readable high level error Message
 * @param {Error} error      The internal error that caused the failure
 */
function onError(message, error) {
  // log the stack trace
  if (config.debug) {
    console.error(error.stack);
  }
  // rethrow new high level error for api users
  throw new Error(message);
}
