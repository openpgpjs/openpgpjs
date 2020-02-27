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
 * @requires web-stream-tools
 * @requires message
 * @requires cleartext
 * @requires key
 * @requires config
 * @requires enums
 * @requires util
 * @requires polyfills
 * @requires worker/async_proxy
 * @module openpgp
 */

// This file intentionally has two separate file overviews so that
// a reference to this module appears at the end of doc/index.html.

/**
 * @fileoverview To view the full API documentation, start from
 * {@link module:openpgp}
 */

import stream from 'web-stream-tools';
import * as messageLib from './message';
import { CleartextMessage } from './cleartext';
import { generate, reformat } from './key';
import config from './config/config';
import enums from './enums';
import './polyfills';
import util from './util';
import AsyncProxy from './worker/async_proxy';

//////////////////////////
//                      //
//   Web Worker setup   //
//                      //
//////////////////////////


let asyncProxy; // instance of the asyncproxy

/**
 * Set the path for the web worker script and create an instance of the async proxy
 * @param {String} path            relative path to the worker scripts, default: 'openpgp.worker.js'
 * @param {Number} n               number of workers to initialize
 * @param {Array<Object>} workers  alternative to path parameter: web workers initialized with 'openpgp.worker.js'
 * @returns {Promise<Boolean>}     returns a promise that resolves to true if all workers have succesfully finished loading
 * @async
 */
export async function initWorker({ path = 'openpgp.worker.js', n = 1, workers = [] } = {}) {
  if (workers.length || (typeof global !== 'undefined' && global.Worker && global.MessageChannel)) {
    const proxy = new AsyncProxy({ path, n, workers, config });
    const loaded = await proxy.loaded();
    if (loaded) {
      asyncProxy = proxy;
      return true;
    }
  }
  return false;
}

/**
 * Returns a reference to the async proxy if the worker was initialized with openpgp.initWorker()
 * @returns {module:worker/async_proxy.AsyncProxy|null} the async proxy or null if not initialized
 */
export function getWorker() {
  return asyncProxy;
}

/**
 * Cleanup the current instance of the web worker.
 */
export async function destroyWorker() {
  const proxy = asyncProxy;
  asyncProxy = undefined;
  if (proxy) {
    await proxy.clearKeyCache();
    proxy.terminate();
  }
}


//////////////////////
//                  //
//   Key handling   //
//                  //
//////////////////////


/**
 * Generates a new OpenPGP key pair. Supports RSA and ECC keys. Primary and subkey will be of same type.
 * @param  {Array<Object>} userIds   array of user IDs e.g. [{ name:'Phil Zimmermann', email:'phil@openpgp.org' }]
 * @param  {String} passphrase       (optional) The passphrase used to encrypt the resulting private key
 * @param  {Number} rsaBits          (optional) number of bits for RSA keys: 2048 or 4096.
 * @param  {Number} keyExpirationTime (optional) The number of seconds after the key creation time that the key expires
 * @param  {String} curve            (optional) elliptic curve for ECC keys:
 *                                              curve25519, p256, p384, p521, secp256k1,
 *                                              brainpoolP256r1, brainpoolP384r1, or brainpoolP512r1.
 * @param  {Date} date               (optional) override the creation date of the key and the key signatures
 * @param  {Array<Object>} subkeys   (optional) options for each subkey, default to main key options. e.g. [{sign: true, passphrase: '123'}]
 *                                              sign parameter defaults to false, and indicates whether the subkey should sign rather than encrypt
 * @returns {Promise<Object>}         The generated key object in the form:
 *                                     { key:Key, privateKeyArmored:String, publicKeyArmored:String, revocationCertificate:String }
 * @async
 * @static
 */

export function generateKey({ userIds = [], passphrase = "", numBits = 2048, rsaBits = numBits, keyExpirationTime = 0, curve = "", date = new Date(), subkeys = [{}] }) {
  userIds = toArray(userIds);
  const options = { userIds, passphrase, rsaBits, keyExpirationTime, curve, date, subkeys };
  if (util.getWebCryptoAll() && rsaBits < 2048) {
    throw new Error('rsaBits should be 2048 or 4096, found: ' + rsaBits);
  }

  if (!util.getWebCryptoAll() && asyncProxy) { // use web worker if web crypto apis are not supported
    return asyncProxy.delegate('generateKey', options);
  }

  return generate(options).then(async key => {
    const revocationCertificate = await key.getRevocationCertificate(date);
    key.revocationSignatures = [];

    return convertStreams({

      key: key,
      privateKeyArmored: key.armor(),
      publicKeyArmored: key.toPublic().armor(),
      revocationCertificate: revocationCertificate

    });
  }).catch(onError.bind(null, 'Error generating keypair'));
}

/**
 * Reformats signature packets for a key and rewraps key object.
 * @param  {Key} privateKey          private key to reformat
 * @param  {Array<Object>} userIds   array of user IDs e.g. [{ name:'Phil Zimmermann', email:'phil@openpgp.org' }]
 * @param  {String} passphrase       (optional) The passphrase used to encrypt the resulting private key
 * @param  {Number} keyExpirationTime (optional) The number of seconds after the key creation time that the key expires
 * @returns {Promise<Object>}         The generated key object in the form:
 *                                     { key:Key, privateKeyArmored:String, publicKeyArmored:String, revocationCertificate:String }
 * @async
 * @static
 */
export function reformatKey({ privateKey, userIds = [], passphrase = "", keyExpirationTime = 0, date }) {
  userIds = toArray(userIds);
  const options = { privateKey, userIds, passphrase, keyExpirationTime, date };
  if (asyncProxy) {
    return asyncProxy.delegate('reformatKey', options);
  }

  return reformat(options).then(async key => {
    const revocationCertificate = await key.getRevocationCertificate(date);
    key.revocationSignatures = [];

    return convertStreams({

      key: key,
      privateKeyArmored: key.armor(),
      publicKeyArmored: key.toPublic().armor(),
      revocationCertificate: revocationCertificate

    });
  }).catch(onError.bind(null, 'Error reformatting keypair'));
}

/**
 * Revokes a key. Requires either a private key or a revocation certificate.
 *   If a revocation certificate is passed, the reasonForRevocation parameters will be ignored.
 * @param  {Key} key                 (optional) public or private key to revoke
 * @param  {String} revocationCertificate (optional) revocation certificate to revoke the key with
 * @param  {Object} reasonForRevocation (optional) object indicating the reason for revocation
 * @param  {module:enums.reasonForRevocation} reasonForRevocation.flag (optional) flag indicating the reason for revocation
 * @param  {String} reasonForRevocation.string (optional) string explaining the reason for revocation
 * @returns {Promise<Object>}         The revoked key object in the form:
 *                                     { privateKey:Key, privateKeyArmored:String, publicKey:Key, publicKeyArmored:String }
 *                                     (if private key is passed) or { publicKey:Key, publicKeyArmored:String } (otherwise)
 * @static
 */
export function revokeKey({
  key, revocationCertificate, reasonForRevocation
} = {}) {
  const options = {
    key, revocationCertificate, reasonForRevocation
  };

  if (!util.getWebCryptoAll() && asyncProxy) { // use web worker if web crypto apis are not supported
    return asyncProxy.delegate('revokeKey', options);
  }

  return Promise.resolve().then(() => {
    if (revocationCertificate) {
      return key.applyRevocationCertificate(revocationCertificate);
    } else {
      return key.revoke(reasonForRevocation);
    }
  }).then(async key => {
    await convertStreams(key);
    if (key.isPrivate()) {
      const publicKey = key.toPublic();
      return {
        privateKey: key,
        privateKeyArmored: key.armor(),
        publicKey: publicKey,
        publicKeyArmored: publicKey.armor()
      };
    }
    return {
      publicKey: key,
      publicKeyArmored: key.armor()
    };
  }).catch(onError.bind(null, 'Error revoking key'));
}

/**
 * Unlock a private key with your passphrase.
 * @param  {Key} privateKey                    the private key that is to be decrypted
 * @param  {String|Array<String>} passphrase   the user's passphrase(s) chosen during key generation
 * @returns {Promise<Object>}                  the unlocked key object in the form: { key:Key }
 * @async
 */
export function decryptKey({ privateKey, passphrase }) {
  if (asyncProxy) { // use web worker if available
    return asyncProxy.delegate('decryptKey', { privateKey, passphrase });
  }

  return Promise.resolve().then(async function() {
    await privateKey.decrypt(passphrase);

    return {
      key: privateKey
    };
  }).catch(onError.bind(null, 'Error decrypting private key'));
}

/**
 * Lock a private key with your passphrase.
 * @param  {Key} privateKey                      the private key that is to be decrypted
 * @param  {String|Array<String>} passphrase     the user's passphrase(s) chosen during key generation
 * @returns {Promise<Object>}                    the locked key object in the form: { key:Key }
 * @async
 */
export function encryptKey({ privateKey, passphrase }) {
  if (asyncProxy) { // use web worker if available
    return asyncProxy.delegate('encryptKey', { privateKey, passphrase });
  }

  return Promise.resolve().then(async function() {
    await privateKey.encrypt(passphrase);

    return {
      key: privateKey
    };
  }).catch(onError.bind(null, 'Error decrypting private key'));
}


///////////////////////////////////////////
//                                       //
//   Message encryption and decryption   //
//                                       //
///////////////////////////////////////////


/**
 * Encrypts message text/data with public keys, passwords or both at once. At least either public keys or passwords
 *   must be specified. If private keys are specified, those will be used to sign the message.
 * @param  {Message} message                      message to be encrypted as created by openpgp.message.fromText or openpgp.message.fromBinary
 * @param  {Key|Array<Key>} publicKeys            (optional) array of keys or single key, used to encrypt the message
 * @param  {Key|Array<Key>} privateKeys           (optional) private keys for signing. If omitted message will not be signed
 * @param  {String|Array<String>} passwords       (optional) array of passwords or a single password to encrypt the message
 * @param  {Object} sessionKey                    (optional) session key in the form: { data:Uint8Array, algorithm:String }
 * @param  {module:enums.compression} compression (optional) which compression algorithm to compress the message with, defaults to what is specified in config
 * @param  {Boolean} armor                        (optional) if the return values should be ascii armored or the message/signature objects
 * @param  {'web'|'node'|false} streaming         (optional) whether to return data as a stream. Defaults to the type of stream `message` was created from, if any.
 * @param  {Boolean} detached                     (optional) if the signature should be detached (if true, signature will be added to returned object)
 * @param  {Signature} signature                  (optional) a detached signature to add to the encrypted message
 * @param  {Boolean} returnSessionKey             (optional) if the unencrypted session key should be added to returned object
 * @param  {Boolean} wildcard                     (optional) use a key ID of 0 instead of the public key IDs
 * @param  {Date} date                            (optional) override the creation date of the message signature
 * @param  {Array} fromUserIds                    (optional) array of user IDs to sign with, one per key in `privateKeys`, e.g. [{ name:'Steve Sender', email:'steve@openpgp.org' }]
 * @param  {Array} toUserIds                      (optional) array of user IDs to encrypt for, one per key in `publicKeys`, e.g. [{ name:'Robert Receiver', email:'robert@openpgp.org' }]
 * @returns {Promise<Object>}                     Object containing encrypted (and optionally signed) message in the form:
 *
 *     {
 *       data: String|ReadableStream<String>|NodeStream, (if `armor` was true, the default)
 *       message: Message, (if `armor` was false)
 *       signature: String|ReadableStream<String>|NodeStream, (if `detached` was true and `armor` was true)
 *       signature: Signature (if `detached` was true and `armor` was false)
 *       sessionKey: { data, algorithm, aeadAlgorithm } (if `returnSessionKey` was true)
 *     }
 * @async
 * @static
 */
export function encrypt({ message, publicKeys, privateKeys, passwords, sessionKey, compression = config.compression, armor = true, streaming = message && message.fromStream, detached = false, signature = null, returnSessionKey = false, wildcard = false, date = new Date(), fromUserIds = [], toUserIds = [] }) {
  checkMessage(message); publicKeys = toArray(publicKeys); privateKeys = toArray(privateKeys); passwords = toArray(passwords); fromUserIds = toArray(fromUserIds); toUserIds = toArray(toUserIds);

  if (!nativeAEAD() && asyncProxy) { // use web worker if web crypto apis are not supported
    return asyncProxy.delegate('encrypt', { message, publicKeys, privateKeys, passwords, sessionKey, compression, armor, streaming, detached, signature, returnSessionKey, wildcard, date, fromUserIds, toUserIds });
  }
  const result = {};
  return Promise.resolve().then(async function() {
    if (!privateKeys) {
      privateKeys = [];
    }
    if (privateKeys.length || signature) { // sign the message only if private keys or signature is specified
      if (detached) {
        const detachedSignature = await message.signDetached(privateKeys, signature, date, fromUserIds, message.fromStream);
        result.signature = armor ? detachedSignature.armor() : detachedSignature;
      } else {
        message = await message.sign(privateKeys, signature, date, fromUserIds, message.fromStream);
      }
    }
    message = message.compress(compression);
    return message.encrypt(publicKeys, passwords, sessionKey, wildcard, date, toUserIds, streaming);

  }).then(async encrypted => {
    if (armor) {
      result.data = encrypted.message.armor();
    } else {
      result.message = encrypted.message;
    }
    if (returnSessionKey) {
      result.sessionKey = encrypted.sessionKey;
    }
    return convertStreams(result, streaming, armor ? ['signature', 'data'] : []);
  }).catch(onError.bind(null, 'Error encrypting message'));
}

/**
 * Decrypts a message with the user's private key, a session key or a password. Either a private key,
 *   a session key or a password must be specified.
 * @param  {Message} message                  the message object with the encrypted data
 * @param  {Key|Array<Key>} privateKeys       (optional) private keys with decrypted secret key data or session key
 * @param  {String|Array<String>} passwords   (optional) passwords to decrypt the message
 * @param  {Object|Array<Object>} sessionKeys (optional) session keys in the form: { data:Uint8Array, algorithm:String }
 * @param  {Key|Array<Key>} publicKeys        (optional) array of public keys or single key, to verify signatures
 * @param  {'utf8'|'binary'} format           (optional) whether to return data as a string(Stream) or Uint8Array(Stream). If 'utf8' (the default), also normalize newlines.
 * @param  {'web'|'node'|false} streaming     (optional) whether to return data as a stream. Defaults to the type of stream `message` was created from, if any.
 * @param  {Signature} signature              (optional) detached signature for verification
 * @param  {Date} date                        (optional) use the given date for verification instead of the current time
 * @returns {Promise<Object>}                 Object containing decrypted and verified message in the form:
 *
 *     {
 *       data: String|ReadableStream<String>|NodeStream, (if format was 'utf8', the default)
 *       data: Uint8Array|ReadableStream<Uint8Array>|NodeStream, (if format was 'binary')
 *       filename: String,
 *       signatures: [
 *         {
 *           keyid: module:type/keyid,
 *           verified: Promise<Boolean>,
 *           valid: Boolean (if streaming was false)
 *         }, ...
 *       ]
 *     }
 * @async
 * @static
 */
export function decrypt({ message, privateKeys, passwords, sessionKeys, publicKeys, format = 'utf8', streaming = message && message.fromStream, signature = null, date = new Date() }) {
  checkMessage(message); publicKeys = toArray(publicKeys); privateKeys = toArray(privateKeys); passwords = toArray(passwords); sessionKeys = toArray(sessionKeys);

  if (!nativeAEAD() && asyncProxy) { // use web worker if web crypto apis are not supported
    return asyncProxy.delegate('decrypt', { message, privateKeys, passwords, sessionKeys, publicKeys, format, streaming, signature, date });
  }

  return message.decrypt(privateKeys, passwords, sessionKeys, streaming).then(async function(decrypted) {
    if (!publicKeys) {
      publicKeys = [];
    }

    const result = {};
    result.signatures = signature ? await decrypted.verifyDetached(signature, publicKeys, date, streaming) : await decrypted.verify(publicKeys, date, streaming);
    result.data = format === 'binary' ? decrypted.getLiteralData() : decrypted.getText();
    result.filename = decrypted.getFilename();
    if (streaming) linkStreams(result, message);
    result.data = await convertStream(result.data, streaming);
    if (!streaming) await prepareSignatures(result.signatures);
    return result;
  }).catch(onError.bind(null, 'Error decrypting message'));
}


//////////////////////////////////////////
//                                      //
//   Message signing and verification   //
//                                      //
//////////////////////////////////////////


/**
 * Signs a cleartext message.
 * @param  {CleartextMessage|Message} message (cleartext) message to be signed
 * @param  {Key|Array<Key>} privateKeys       array of keys or single key with decrypted secret key data to sign cleartext
 * @param  {Boolean} armor                    (optional) if the return value should be ascii armored or the message object
 * @param  {'web'|'node'|false} streaming     (optional) whether to return data as a stream. Defaults to the type of stream `message` was created from, if any.
 * @param  {Boolean} detached                 (optional) if the return value should contain a detached signature
 * @param  {Date} date                        (optional) override the creation date of the signature
 * @param  {Array} fromUserIds                (optional) array of user IDs to sign with, one per key in `privateKeys`, e.g. [{ name:'Steve Sender', email:'steve@openpgp.org' }]
 * @returns {Promise<Object>}                 Object containing signed message in the form:
 *
 *     {
 *       data: String|ReadableStream<String>|NodeStream, (if `armor` was true, the default)
 *       message: Message (if `armor` was false)
 *     }
 *
 * Or, if `detached` was true:
 *
 *     {
 *       signature: String|ReadableStream<String>|NodeStream, (if `armor` was true, the default)
 *       signature: Signature (if `armor` was false)
 *     }
 * @async
 * @static
 */
export function sign({ message, privateKeys, armor = true, streaming = message && message.fromStream, detached = false, date = new Date(), fromUserIds = [] }) {
  checkCleartextOrMessage(message);
  privateKeys = toArray(privateKeys); fromUserIds = toArray(fromUserIds);
  if (asyncProxy) { // use web worker if available
    return asyncProxy.delegate('sign', {
      message, privateKeys, armor, streaming, detached, date, fromUserIds
    });
  }

  const result = {};
  return Promise.resolve().then(async function() {
    if (detached) {
      const signature = await message.signDetached(privateKeys, undefined, date, fromUserIds, message.fromStream);
      result.signature = armor ? signature.armor() : signature;
      if (message.packets) {
        result.signature = stream.transformPair(message.packets.write(), async (readable, writable) => {
          await Promise.all([
            stream.pipe(result.signature, writable),
            stream.readToEnd(readable).catch(() => {})
          ]);
        });
      }
    } else {
      message = await message.sign(privateKeys, undefined, date, fromUserIds, message.fromStream);
      if (armor) {
        result.data = message.armor();
      } else {
        result.message = message;
      }
    }
    return convertStreams(result, streaming, armor ? ['signature', 'data'] : []);
  }).catch(onError.bind(null, 'Error signing cleartext message'));
}

/**
 * Verifies signatures of cleartext signed message
 * @param  {Key|Array<Key>} publicKeys         array of publicKeys or single key, to verify signatures
 * @param  {CleartextMessage|Message} message  (cleartext) message object with signatures
 * @param  {'web'|'node'|false} streaming      (optional) whether to return data as a stream. Defaults to the type of stream `message` was created from, if any.
 * @param  {Signature} signature               (optional) detached signature for verification
 * @param  {Date} date                         (optional) use the given date for verification instead of the current time
 * @returns {Promise<Object>}                  Object containing verified message in the form:
 *
 *     {
 *       data: String|ReadableStream<String>|NodeStream, (if `message` was a CleartextMessage)
 *       data: Uint8Array|ReadableStream<Uint8Array>|NodeStream, (if `message` was a Message)
 *       signatures: [
 *         {
 *           keyid: module:type/keyid,
 *           verified: Promise<Boolean>,
 *           valid: Boolean (if `streaming` was false)
 *         }, ...
 *       ]
 *     }
 * @async
 * @static
 */
export function verify({ message, publicKeys, streaming = message && message.fromStream, signature = null, date = new Date() }) {
  checkCleartextOrMessage(message);
  publicKeys = toArray(publicKeys);

  if (asyncProxy) { // use web worker if available
    return asyncProxy.delegate('verify', { message, publicKeys, streaming, signature, date });
  }

  return Promise.resolve().then(async function() {
    const result = {};
    result.signatures = signature ? await message.verifyDetached(signature, publicKeys, date, streaming) : await message.verify(publicKeys, date, streaming);
    result.data = message instanceof CleartextMessage ? message.getText() : message.getLiteralData();
    if (streaming) linkStreams(result, message);
    result.data = await convertStream(result.data, streaming);
    if (!streaming) await prepareSignatures(result.signatures);
    return result;
  }).catch(onError.bind(null, 'Error verifying cleartext signed message'));
}


///////////////////////////////////////////////
//                                           //
//   Session key encryption and decryption   //
//                                           //
///////////////////////////////////////////////


/**
 * Encrypt a symmetric session key with public keys, passwords, or both at once. At least either public keys
 *   or passwords must be specified.
 * @param  {Uint8Array} data                  the session key to be encrypted e.g. 16 random bytes (for aes128)
 * @param  {String} algorithm                 algorithm of the symmetric session key e.g. 'aes128' or 'aes256'
 * @param  {String} aeadAlgorithm             (optional) aead algorithm, e.g. 'eax' or 'ocb'
 * @param  {Key|Array<Key>} publicKeys        (optional) array of public keys or single key, used to encrypt the key
 * @param  {String|Array<String>} passwords   (optional) passwords for the message
 * @param  {Boolean} wildcard                 (optional) use a key ID of 0 instead of the public key IDs
 * @param  {Date} date                        (optional) override the date
 * @param  {Array} toUserIds                  (optional) array of user IDs to encrypt for, one per key in `publicKeys`, e.g. [{ name:'Phil Zimmermann', email:'phil@openpgp.org' }]
 * @returns {Promise<Message>}                 the encrypted session key packets contained in a message object
 * @async
 * @static
 */
export function encryptSessionKey({ data, algorithm, aeadAlgorithm, publicKeys, passwords, wildcard = false, date = new Date(), toUserIds = [] }) {
  checkBinary(data); checkString(algorithm, 'algorithm'); publicKeys = toArray(publicKeys); passwords = toArray(passwords); toUserIds = toArray(toUserIds);

  if (asyncProxy) { // use web worker if available
    return asyncProxy.delegate('encryptSessionKey', { data, algorithm, aeadAlgorithm, publicKeys, passwords, wildcard, date, toUserIds });
  }

  return Promise.resolve().then(async function() {

    return { message: await messageLib.encryptSessionKey(data, algorithm, aeadAlgorithm, publicKeys, passwords, wildcard, date, toUserIds) };

  }).catch(onError.bind(null, 'Error encrypting session key'));
}

/**
 * Decrypt symmetric session keys with a private key or password. Either a private key or
 *   a password must be specified.
 * @param  {Message} message                 a message object containing the encrypted session key packets
 * @param  {Key|Array<Key>} privateKeys     (optional) private keys with decrypted secret key data
 * @param  {String|Array<String>} passwords (optional) passwords to decrypt the session key
 * @returns {Promise<Object|undefined>}    Array of decrypted session key, algorithm pairs in form:
 *                                          { data:Uint8Array, algorithm:String }
 *                                          or 'undefined' if no key packets found
 * @async
 * @static
 */
export function decryptSessionKeys({ message, privateKeys, passwords }) {
  checkMessage(message); privateKeys = toArray(privateKeys); passwords = toArray(passwords);

  if (asyncProxy) { // use web worker if available
    return asyncProxy.delegate('decryptSessionKeys', { message, privateKeys, passwords });
  }

  return Promise.resolve().then(async function() {

    return message.decryptSessionKeys(privateKeys, passwords);

  }).catch(onError.bind(null, 'Error decrypting session keys'));
}


//////////////////////////
//                      //
//   Helper functions   //
//                      //
//////////////////////////


/**
 * Input validation
 */
function checkString(data, name) {
  if (!util.isString(data)) {
    throw new Error('Parameter [' + (name || 'data') + '] must be of type String');
  }
}
function checkBinary(data, name) {
  if (!util.isUint8Array(data)) {
    throw new Error('Parameter [' + (name || 'data') + '] must be of type Uint8Array');
  }
}
function checkMessage(message) {
  if (!(message instanceof messageLib.Message)) {
    throw new Error('Parameter [message] needs to be of type Message');
  }
}
function checkCleartextOrMessage(message) {
  if (!(message instanceof CleartextMessage) && !(message instanceof messageLib.Message)) {
    throw new Error('Parameter [message] needs to be of type Message or CleartextMessage');
  }
}

/**
 * Normalize parameter to an array if it is not undefined.
 * @param  {Object} param              the parameter to be normalized
 * @returns {Array<Object>|undefined}   the resulting array or undefined
 */
function toArray(param) {
  if (param && !util.isArray(param)) {
    param = [param];
  }
  return param;
}

/**
 * Convert data to or from Stream
 * @param  {Object} data                   the data to convert
 * @param  {'web'|'node'|false} streaming  (optional) whether to return a ReadableStream
 * @returns {Object}                       the data in the respective format
 */
async function convertStream(data, streaming) {
  if (!streaming && util.isStream(data)) {
    return stream.readToEnd(data);
  }
  if (streaming && !util.isStream(data)) {
    data = new ReadableStream({
      start(controller) {
        controller.enqueue(data);
        controller.close();
      }
    });
  }
  if (streaming === 'node') {
    data = stream.webToNode(data);
  }
  return data;
}

/**
 * Convert object properties from Stream
 * @param  {Object} obj                    the data to convert
 * @param  {'web'|'node'|false} streaming  (optional) whether to return ReadableStreams
 * @param  {Array<String>} keys            (optional) which keys to return as streams, if possible
 * @returns {Object}                       the data in the respective format
 */
async function convertStreams(obj, streaming, keys = []) {
  if (Object.prototype.isPrototypeOf(obj) && !Uint8Array.prototype.isPrototypeOf(obj)) {
    await Promise.all(Object.entries(obj).map(async ([key, value]) => { // recursively search all children
      if (util.isStream(value) || keys.includes(key)) {
        obj[key] = await convertStream(value, streaming);
      } else {
        await convertStreams(obj[key], streaming);
      }
    }));
  }
  return obj;
}

/**
 * Link result.data to the message stream for cancellation.
 * @param  {Object} result                  the data to convert
 * @param  {Message} message                message object
 * @returns {Object}
 */
function linkStreams(result, message) {
  result.data = stream.transformPair(message.packets.stream, async (readable, writable) => {
    await stream.pipe(result.data, writable);
  });
}

/**
 * Wait until signature objects have been verified
 * @param  {Object} signatures              list of signatures
 */
async function prepareSignatures(signatures) {
  await Promise.all(signatures.map(async signature => {
    signature.signature = await signature.signature;
    try {
      signature.valid = await signature.verified;
    } catch (e) {
      signature.valid = false;
      signature.error = e;
      util.print_debug_error(e);
    }
  }));
}


/**
 * Global error handler that logs the stack trace and rethrows a high lvl error message.
 * @param {String} message   A human readable high level error Message
 * @param {Error} error      The internal error that caused the failure
 */
function onError(message, error) {
  // log the stack trace
  util.print_debug_error(error);

  // update error message
  try {
    error.message = message + ': ' + error.message;
  } catch (e) {}

  throw error;
}

/**
 * Check for native AEAD support and configuration by the user. Only
 * browsers that implement the current WebCrypto specification support
 * native GCM. Native EAX is built on CTR and CBC, which current
 * browsers support. OCB and CFB are not natively supported.
 * @returns {Boolean}   If authenticated encryption should be used
 */
function nativeAEAD() {
  return config.aead_protect && (config.aead_mode === enums.aead.eax || config.aead_mode === enums.aead.experimental_gcm) && util.getWebCrypto();
}
