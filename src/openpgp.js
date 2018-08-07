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

import * as messageLib from './message';
import { CleartextMessage } from './cleartext';
import { generate, reformat } from './key';
import config from './config/config';
import enums from './enums';
import util from './util';
import AsyncProxy from './worker/async_proxy';

// Old browser polyfills
if (typeof window !== 'undefined') {
  require('./polyfills');
}

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
 */
export function initWorker({ path='openpgp.worker.js', n = 1, workers = [] } = {}) {
  if (workers.length || (typeof window !== 'undefined' && window.Worker)) {
    asyncProxy = new AsyncProxy({ path, n, workers, config });
    return true;
  }
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
export function destroyWorker() {
  asyncProxy = undefined;
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
 * @param  {Number} numBits          (optional) number of bits for RSA keys: 2048 or 4096.
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

export function generateKey({ userIds=[], passphrase="", numBits=2048, keyExpirationTime=0, curve="", date=new Date(), subkeys=[{}] }) {
  userIds = toArray(userIds);
  const options = { userIds, passphrase, numBits, keyExpirationTime, curve, date, subkeys };
  if (util.getWebCryptoAll() && numBits < 2048) {
    throw new Error('numBits should be 2048 or 4096, found: ' + numBits);
  }

  if (!util.getWebCryptoAll() && asyncProxy) { // use web worker if web crypto apis are not supported
    return asyncProxy.delegate('generateKey', options);
  }

  return generate(options).then(key => {
    const revocationCertificate = key.getRevocationCertificate();
    key.revocationSignatures = [];

    return {

      key: key,
      privateKeyArmored: key.armor(),
      publicKeyArmored: key.toPublic().armor(),
      revocationCertificate: revocationCertificate

    };
  }).catch(onError.bind(null, 'Error generating keypair'));
}

/**
 * Reformats signature packets for a key and rewraps key object.
 * @param  {Key} privateKey          private key to reformat
 * @param  {Array<Object>} userIds   array of user IDs e.g. [{ name:'Phil Zimmermann', email:'phil@openpgp.org' }]
 * @param  {String} passphrase       (optional) The passphrase used to encrypt the resulting private key
 * @param  {Number} keyExpirationTime (optional) The number of seconds after the key creation time that the key expires
 * @param  {Boolean} revocationCertificate (optional) Whether the returned object should include a revocation certificate to revoke the public key
 * @returns {Promise<Object>}         The generated key object in the form:
 *                                     { key:Key, privateKeyArmored:String, publicKeyArmored:String, revocationCertificate:String }
 * @async
 * @static
 */
export function reformatKey({privateKey, userIds=[], passphrase="", keyExpirationTime=0, date, revocationCertificate=true}) {
  userIds = toArray(userIds);
  const options = { privateKey, userIds, passphrase, keyExpirationTime, date, revocationCertificate };
  if (asyncProxy) {
    return asyncProxy.delegate('reformatKey', options);
  }

  options.revoked = options.revocationCertificate;

  return reformat(options).then(key => {
    const revocationCertificate = key.getRevocationCertificate();
    key.revocationSignatures = [];

    return {

      key: key,
      privateKeyArmored: key.armor(),
      publicKeyArmored: key.toPublic().armor(),
      revocationCertificate: revocationCertificate

    };
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
 * @return {Promise<Object>}         The revoked key object in the form:
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
  }).then(key => {
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
 * @param  {String|Uint8Array} data               text/data to be encrypted as JavaScript binary string or Uint8Array
 * @param  {utf8|binary|text|mime} dataType       (optional) data packet type
 * @param  {Key|Array<Key>} publicKeys            (optional) array of keys or single key, used to encrypt the message
 * @param  {Key|Array<Key>} privateKeys           (optional) private keys for signing. If omitted message will not be signed
 * @param  {String|Array<String>} passwords       (optional) array of passwords or a single password to encrypt the message
 * @param  {Object} sessionKey                    (optional) session key in the form: { data:Uint8Array, algorithm:String }
 * @param  {String} filename                      (optional) a filename for the literal data packet
 * @param  {module:enums.compression} compression (optional) which compression algorithm to compress the message with, defaults to what is specified in config
 * @param  {Boolean} armor                        (optional) if the return values should be ascii armored or the message/signature objects
 * @param  {Boolean} detached                     (optional) if the signature should be detached (if true, signature will be added to returned object)
 * @param  {Signature} signature                  (optional) a detached signature to add to the encrypted message
 * @param  {Boolean} returnSessionKey             (optional) if the unencrypted session key should be added to returned object
 * @param  {Boolean} wildcard                     (optional) use a key ID of 0 instead of the public key IDs
 * @param  {Date} date                            (optional) override the creation date of the message and the message signature
 * @param  {Object} fromUserId                    (optional) user ID to sign with, e.g. { name:'Steve Sender', email:'steve@openpgp.org' }
 * @param  {Object} toUserId                      (optional) user ID to encrypt for, e.g. { name:'Robert Receiver', email:'robert@openpgp.org' }
 * @returns {Promise<Object>}                      encrypted (and optionally signed message) in the form:
 *                                                  {data: ASCII armored message if 'armor' is true,
 *                                                  message: full Message object if 'armor' is false, signature: detached signature if 'detached' is true}
 * @async
 * @static
 */
export function encrypt({ data, dataType, publicKeys, privateKeys, passwords, sessionKey, filename, compression=config.compression, armor=true, detached=false, signature=null, returnSessionKey=false, wildcard=false, date=new Date(), fromUserId={}, toUserId={}, signatureExpirationTime=0 }) {
  checkData(data); publicKeys = toArray(publicKeys); privateKeys = toArray(privateKeys); passwords = toArray(passwords);

  if (!nativeAEAD() && asyncProxy) { // use web worker if web crypto apis are not supported
    return asyncProxy.delegate('encrypt', { data, dataType, publicKeys, privateKeys, passwords, sessionKey, filename, compression, armor, detached, signature, returnSessionKey, wildcard, date, fromUserId, toUserId });
  }
  const result = {};
  return Promise.resolve().then(async function() {
    let message = createMessage(data, filename, date, dataType);
    if (!privateKeys) {
      privateKeys = [];
    }
    if (privateKeys.length || signature) { // sign the message only if private keys or signature is specified
      if (detached) {
        const detachedSignature = await message.signDetachedEx(privateKeys, {signature, date, userId:fromUserId, signatureExpirationTime});
        result.signature = armor ? detachedSignature.armor() : detachedSignature;
      } else {
        message = await message.signEx(privateKeys, {signature, date, userId:fromUserId, signatureExpirationTime});
      }
    }
    message = message.compress(compression);
    return message.encrypt(publicKeys, passwords, sessionKey, wildcard, date, toUserId);

  }).then(encrypted => {
    if (armor) {
      result.data = encrypted.message.armor();
    } else {
      result.message = encrypted.message;
    }
    if (returnSessionKey) {
      result.sessionKey = encrypted.sessionKey;
    }
    return result;
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
 * @param  {String} format                    (optional) return data format either as 'utf8' or 'binary'
 * @param  {Signature} signature              (optional) detached signature for verification
 * @param  {Date} date                        (optional) use the given date for verification instead of the current time
 * @returns {Promise<Object>}             decrypted and verified message in the form:
 *                                         { data:Uint8Array|String, filename:String, signatures:[{ keyid:String, valid:Boolean }] }
 * @async
 * @static
 */
export function decrypt({ message, privateKeys, passwords, sessionKeys, publicKeys, format='utf8', signature=null, date=new Date() }) {
  checkMessage(message); publicKeys = toArray(publicKeys); privateKeys = toArray(privateKeys); passwords = toArray(passwords); sessionKeys = toArray(sessionKeys);

  if (!nativeAEAD() && asyncProxy) { // use web worker if web crypto apis are not supported
    return asyncProxy.delegate('decrypt', { message, privateKeys, passwords, sessionKeys, publicKeys, format, signature, date });
  }

  return message.decrypt(privateKeys, passwords, sessionKeys).then(async function(message) {

    const result = parseMessage(message, format);

    if (!publicKeys) {
      publicKeys = [];
    }

    result.signatures = signature ? await message.verifyDetached(signature, publicKeys, date) : await message.verify(publicKeys, date);
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
 * @param  {String | Uint8Array} data           cleartext input to be signed
 * @param  {utf8|binary|text|mime} dataType     (optional) data packet type
 * @param  {Key|Array<Key>} privateKeys         array of keys or single key with decrypted secret key data to sign cleartext
 * @param  {Boolean} armor                      (optional) if the return value should be ascii armored or the message object
 * @param  {Boolean} detached                   (optional) if the return value should contain a detached signature
 * @param  {Date} date                          (optional) override the creation date signature
 * @param  {Object} fromUserId                  (optional) user ID to sign with, e.g. { name:'Steve Sender', email:'steve@openpgp.org' }
 * @param  {Integer} signatureExpirationTime (optional) the expired time(seconds) of the signature
 * @returns {Promise<Object>}                    signed cleartext in the form:
 *                                                {data: ASCII armored message if 'armor' is true,
 *                                                message: full Message object if 'armor' is false, signature: detached signature if 'detached' is true}
 * @async
 * @static
 */
export function sign({ data, dataType, privateKeys, armor=true, detached=false, date=new Date(), fromUserId={}, signatureExpirationTime=0 }) {
  checkData(data);
  privateKeys = toArray(privateKeys);

  if (asyncProxy) { // use web worker if available
    return asyncProxy.delegate('sign', {
      data, dataType, privateKeys, armor, detached, date, fromUserId
    });
  }

  const result = {};
  return Promise.resolve().then(async function() {
    let message = util.isString(data) ? new CleartextMessage(data) : messageLib.fromBinary(data, dataType, date);

    if (detached) {
      const signature = await message.signDetachedEx(privateKeys, {date, userId:fromUserId, signatureExpirationTime});
      result.signature = armor ? signature.armor() : signature;
    } else {
      message = await message.signEx(privateKeys, {date, userId:fromUserId, signatureExpirationTime});
      if (armor) {
        result.data = message.armor();
      } else {
        result.message = message;
      }
    }
    return result;
  }).catch(onError.bind(null, 'Error signing cleartext message'));
}

/**
 * Verifies signatures of cleartext signed message
 * @param  {Key|Array<Key>} publicKeys   array of publicKeys or single key, to verify signatures
 * @param  {CleartextMessage} message    cleartext message object with signatures
 * @param  {Signature} signature         (optional) detached signature for verification
 * @param  {Date} date                   (optional) use the given date for verification instead of the current time
 * @returns {Promise<Object>}             cleartext with status of verified signatures in the form of:
 *                                       { data:String, signatures: [{ keyid:String, valid:Boolean }] }
 * @async
 * @static
 */
export function verify({ message, publicKeys, signature=null, date=new Date() }) {
  checkCleartextOrMessage(message);
  publicKeys = toArray(publicKeys);

  if (asyncProxy) { // use web worker if available
    return asyncProxy.delegate('verify', { message, publicKeys, signature, date });
  }

  return Promise.resolve().then(async function() {
    const result = {};
    result.data = message instanceof CleartextMessage ? message.getText() : message.getLiteralData();
    result.signatures = signature ?
      await message.verifyDetached(signature, publicKeys, date) :
      await message.verify(publicKeys, date);
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
 * @param  {Object} toUserId                  (optional) user ID to encrypt for, e.g. { name:'Phil Zimmermann', email:'phil@openpgp.org' }
 * @returns {Promise<Message>}                 the encrypted session key packets contained in a message object
 * @async
 * @static
 */
export function encryptSessionKey({ data, algorithm, aeadAlgorithm, publicKeys, passwords, wildcard=false, date=new Date(), toUserId={} }) {
  checkBinary(data); checkString(algorithm, 'algorithm'); publicKeys = toArray(publicKeys); passwords = toArray(passwords);

  if (asyncProxy) { // use web worker if available
    return asyncProxy.delegate('encryptSessionKey', { data, algorithm, aeadAlgorithm, publicKeys, passwords, wildcard, date, toUserId });
  }

  return Promise.resolve().then(async function() {

    return { message: await messageLib.encryptSessionKey(data, algorithm, aeadAlgorithm, publicKeys, passwords, wildcard, date, toUserId) };

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
function checkData(data, name) {
  if (!util.isUint8Array(data) && !util.isString(data)) {
    throw new Error('Parameter [' + (name || 'data') + '] must be of type String or Uint8Array');
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
 * Creates a message obejct either from a Uint8Array or a string.
 * @param  {String|Uint8Array} data   the payload for the message
 * @param  {String} filename          the literal data packet's filename
 * @param  {Date} date      the creation date of the package
 * @param  {utf8|binary|text|mime} type (optional) data packet type
 * @returns {Message}                  a message object
 */
function createMessage(data, filename, date=new Date(), type) {
  let msg;
  if (util.isUint8Array(data)) {
    msg = messageLib.fromBinary(data, filename, date, type);
  } else if (util.isString(data)) {
    msg = messageLib.fromText(data, filename, date, type);
  } else {
    throw new Error('Data must be of type String or Uint8Array');
  }
  return msg;
}

/**
 * Parse the message given a certain format.
 * @param  {Message} message   the message object to be parse
 * @param  {String} format     the output format e.g. 'utf8' or 'binary'
 * @returns {Object}            the parse data in the respective format
 */
function parseMessage(message, format) {
  if (format === 'binary') {
    return {
      data: message.getLiteralData(),
      filename: message.getFilename()
    };
  } else if (format === 'utf8') {
    return {
      data: message.getText(),
      filename: message.getFilename()
    };
  }
  throw new Error('Invalid format');
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
  } catch(e) {}

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
  return config.aead_protect && (
    ((config.aead_protect_version !== 4 || config.aead_mode === enums.aead.experimental_gcm) && util.getWebCrypto()) ||
    (config.aead_protect_version === 4 && config.aead_mode === enums.aead.eax && util.getWebCrypto())
  );
}
