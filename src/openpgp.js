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
 * @module openpgp
 */

// This file intentionally has two separate file overviews so that
// a reference to this module appears at the end of doc/index.html.

/**
 * @fileoverview To view the full API documentation, start from
 * {@link module:openpgp}
 */

import stream from 'web-stream-tools';
import { createReadableStreamWrapper } from '@mattiasbuelens/web-streams-adapter';
import { Message } from './message';
import { CleartextMessage } from './cleartext';
import { generate, reformat } from './key';
import config from './config/config';
import './polyfills';
import util from './util';

let toNativeReadable;
if (globalThis.ReadableStream) {
  try {
    toNativeReadable = createReadableStreamWrapper(globalThis.ReadableStream);
  } catch (e) {}
}

//////////////////////
//                  //
//   Key handling   //
//                  //
//////////////////////


/**
 * Generates a new OpenPGP key pair. Supports RSA and ECC keys. By default, primary and subkeys will be of same type.
 * @param  {ecc|rsa} type                  (optional) The primary key algorithm type: ECC (default) or RSA
 * @param  {Object|Array<Object>} userIds  User IDs as objects: { name:'Jo Doe', email:'info@jo.com' }
 * @param  {String} passphrase             (optional) The passphrase used to encrypt the resulting private key
 * @param  {Number} rsaBits                (optional) Number of bits for RSA keys, defaults to 4096
 * @param  {String} curve                  (optional) Elliptic curve for ECC keys:
 *                                             curve25519 (default), p256, p384, p521, secp256k1,
 *                                             brainpoolP256r1, brainpoolP384r1, or brainpoolP512r1
 * @param  {Date}   date                   (optional) Override the creation date of the key and the key signatures
 * @param  {Number} keyExpirationTime      (optional) Number of seconds from the key creation time after which the key expires
 * @param  {Array<Object>} subkeys         (optional) Options for each subkey, default to main key options. e.g. [{sign: true, passphrase: '123'}]
 *                                             sign parameter defaults to false, and indicates whether the subkey should sign rather than encrypt
 * @returns {Promise<Object>}         The generated key object in the form:
 *                                     { key:Key, privateKeyArmored:String, publicKeyArmored:String, revocationCertificate:String }
 * @async
 * @static
 */
export function generateKey({ userIds = [], passphrase = "", type = "ecc", rsaBits = 4096, curve = "curve25519", keyExpirationTime = 0, date = new Date(), subkeys = [{}] }) {
  userIds = toArray(userIds);
  const options = { userIds, passphrase, type, rsaBits, curve, keyExpirationTime, date, subkeys };
  if (type === "rsa" && rsaBits < config.minRsaBits) {
    throw new Error(`rsaBits should be at least ${config.minRsaBits}, got: ${rsaBits}`);
  }

  return generate(options).then(async key => {
    const revocationCertificate = await key.getRevocationCertificate(date);
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
 * @param  {Key} privateKey                Private key to reformat
 * @param  {Object|Array<Object>} userIds  User IDs as objects: { name:'Jo Doe', email:'info@jo.com' }
 * @param  {String} passphrase             (optional) The passphrase used to encrypt the resulting private key
 * @param  {Number} keyExpirationTime      (optional) Number of seconds from the key creation time after which the key expires
 * @returns {Promise<Object>}         The generated key object in the form:
 *                                     { key:Key, privateKeyArmored:String, publicKeyArmored:String, revocationCertificate:String }
 * @async
 * @static
 */
export function reformatKey({ privateKey, userIds = [], passphrase = "", keyExpirationTime = 0, date }) {
  userIds = toArray(userIds);
  const options = { privateKey, userIds, passphrase, keyExpirationTime, date };

  return reformat(options).then(async key => {
    const revocationCertificate = await key.getRevocationCertificate(date);
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
 * @returns {Promise<Object>}         The revoked key object in the form:
 *                                     { privateKey:Key, privateKeyArmored:String, publicKey:Key, publicKeyArmored:String }
 *                                     (if private key is passed) or { publicKey:Key, publicKeyArmored:String } (otherwise)
 * @static
 */
export function revokeKey({
  key, revocationCertificate, reasonForRevocation
} = {}) {
  return Promise.resolve().then(() => {
    if (revocationCertificate) {
      return key.applyRevocationCertificate(revocationCertificate);
    } else {
      return key.revoke(reasonForRevocation);
    }
  }).then(async key => {
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
 * Unlock a private key with the given passphrase.
 * This method does not change the original key.
 * @param  {Key} privateKey                   the private key to decrypt
 * @param  {String|Array<String>} passphrase  the user's passphrase(s)
 * @returns {Promise<Key>}                    the unlocked key object
 * @async
 */
export async function decryptKey({ privateKey, passphrase }) {
  const key = await privateKey.clone();
  // shallow clone is enough since the encrypted material is not changed in place by decryption
  key.getKeys().forEach(k => {
    k.keyPacket = Object.create(
      Object.getPrototypeOf(k.keyPacket),
      Object.getOwnPropertyDescriptors(k.keyPacket)
    );
  });
  try {
    await key.decrypt(passphrase);
    return key;
  } catch (err) {
    key.clearPrivateParams();
    return onError('Error decrypting private key', err);
  }
}

/**
 * Lock a private key with the given passphrase.
 * This method does not change the original key.
 * @param  {Key} privateKey                   the private key to encrypt
 * @param  {String|Array<String>} passphrase  if multiple passphrases, they should be in the same order as the packets each should encrypt
 * @returns {Promise<Key>}                    the locked key object
 * @async
 */
export async function encryptKey({ privateKey, passphrase }) {
  const key = await privateKey.clone();
  key.getKeys().forEach(k => {
    // shallow clone the key packets
    k.keyPacket = Object.create(
      Object.getPrototypeOf(k.keyPacket),
      Object.getOwnPropertyDescriptors(k.keyPacket)
    );
    if (!k.keyPacket.isDecrypted()) return;
    // deep clone the private params, which are cleared during encryption
    const privateParams = {};
    Object.keys(k.keyPacket.privateParams).forEach(name => {
      privateParams[name] = new Uint8Array(k.keyPacket.privateParams[name]);
    });
    k.keyPacket.privateParams = privateParams;
  });
  try {
    await key.encrypt(passphrase);
    return key;
  } catch (err) {
    key.clearPrivateParams();
    return onError('Error encrypting private key', err);
  }
}


///////////////////////////////////////////
//                                       //
//   Message encryption and decryption   //
//                                       //
///////////////////////////////////////////


/**
 * Encrypts message text/data with public keys, passwords or both at once. At least either public keys or passwords
 *   must be specified. If private keys are specified, those will be used to sign the message.
 * @param  {Message} message                          message to be encrypted as created by openpgp.Message.fromText or openpgp.Message.fromBinary
 * @param  {Key|Array<Key>} publicKeys                (optional) array of keys or single key, used to encrypt the message
 * @param  {Key|Array<Key>} privateKeys               (optional) private keys for signing. If omitted message will not be signed
 * @param  {String|Array<String>} passwords           (optional) array of passwords or a single password to encrypt the message
 * @param  {Object} sessionKey                        (optional) session key in the form: { data:Uint8Array, algorithm:String }
 * @param  {module:enums.compression} compression     (optional) which compression algorithm to compress the message with, defaults to what is specified in config
 * @param  {Boolean} armor                            (optional) whether the return values should be ascii armored (true, the default) or binary (false)
 * @param  {'web'|'ponyfill'|'node'|false} streaming  (optional) whether to return data as a stream. Defaults to the type of stream `message` was created from, if any.
 * @param  {Signature} signature                      (optional) a detached signature to add to the encrypted message
 * @param  {Boolean} wildcard                         (optional) use a key ID of 0 instead of the public key IDs
 * @param  {Date} date                                (optional) override the creation date of the message signature
 * @param  {Array<Object>} fromUserIds                (optional) array of user IDs to sign with, one per key in `privateKeys`, e.g. [{ name:'Steve Sender', email:'steve@openpgp.org' }]
 * @param  {Array<Object>} toUserIds                  (optional) array of user IDs to encrypt for, one per key in `publicKeys`, e.g. [{ name:'Robert Receiver', email:'robert@openpgp.org' }]
 * @returns {Promise<String|ReadableStream<String>|NodeStream<String>|Uint8Array|ReadableStream<Uint8Array>|NodeStream<Uint8Array>>} (String if `armor` was true, the default; Uint8Array if `armor` was false)
 * @async
 * @static
 */
export function encrypt({ message, publicKeys, privateKeys, passwords, sessionKey, compression = config.compression, armor = true, streaming = message && message.fromStream, detached = false, signature = null, wildcard = false, date = new Date(), fromUserIds = [], toUserIds = [] }) {
  checkMessage(message); publicKeys = toArray(publicKeys); privateKeys = toArray(privateKeys); passwords = toArray(passwords); fromUserIds = toArray(fromUserIds); toUserIds = toArray(toUserIds);
  if (detached) {
    throw new Error("detached option has been removed from openpgp.encrypt. Separately call openpgp.sign instead. Don't forget to remove privateKeys option as well.");
  }

  return Promise.resolve().then(async function() {
    if (!privateKeys) {
      privateKeys = [];
    }
    if (privateKeys.length || signature) { // sign the message only if private keys or signature is specified
      message = await message.sign(privateKeys, signature, date, fromUserIds, message.fromStream);
    }
    message = message.compress(compression);
    message = await message.encrypt(publicKeys, passwords, sessionKey, wildcard, date, toUserIds, streaming);
    const data = armor ? message.armor() : message.write();
    return convertStream(data, streaming, armor ? 'utf8' : 'binary');
  }).catch(onError.bind(null, 'Error encrypting message'));
}

/**
 * Decrypts a message with the user's private key, a session key or a password. Either a private key,
 *   a session key or a password must be specified.
 * @param  {Message} message                          the message object with the encrypted data
 * @param  {Key|Array<Key>} privateKeys               (optional) private keys with decrypted secret key data or session key
 * @param  {String|Array<String>} passwords           (optional) passwords to decrypt the message
 * @param  {Object|Array<Object>} sessionKeys         (optional) session keys in the form: { data:Uint8Array, algorithm:String }
 * @param  {Key|Array<Key>} publicKeys                (optional) array of public keys or single key, to verify signatures
 * @param  {'utf8'|'binary'} format                   (optional) whether to return data as a string(Stream) or Uint8Array(Stream). If 'utf8' (the default), also normalize newlines.
 * @param  {'web'|'ponyfill'|'node'|false} streaming  (optional) whether to return data as a stream. Defaults to the type of stream `message` was created from, if any.
 * @param  {Signature} signature                      (optional) detached signature for verification
 * @param  {Date} date                                (optional) use the given date for verification instead of the current time
 * @returns {Promise<Object>}                         Object containing decrypted and verified message in the form:
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

  return message.decrypt(privateKeys, passwords, sessionKeys, streaming).then(async function(decrypted) {
    if (!publicKeys) {
      publicKeys = [];
    }

    const result = {};
    result.signatures = signature ? await decrypted.verifyDetached(signature, publicKeys, date, streaming) : await decrypted.verify(publicKeys, date, streaming);
    result.data = format === 'binary' ? decrypted.getLiteralData() : decrypted.getText();
    result.filename = decrypted.getFilename();
    linkStreams(result, message);
    result.data = await convertStream(result.data, streaming, format);
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
 * Signs a message.
 * @param  {CleartextMessage|Message} message         (cleartext) message to be signed
 * @param  {Key|Array<Key>} privateKeys               array of keys or single key with decrypted secret key data to sign cleartext
 * @param  {Boolean} armor                            (optional) whether the return values should be ascii armored (true, the default) or binary (false)
 * @param  {'web'|'ponyfill'|'node'|false} streaming  (optional) whether to return data as a stream. Defaults to the type of stream `message` was created from, if any.
 * @param  {Boolean} detached                         (optional) if the return value should contain a detached signature
 * @param  {Date} date                                (optional) override the creation date of the signature
 * @param  {Array<Object>} fromUserIds                (optional) array of user IDs to sign with, one per key in `privateKeys`, e.g. [{ name:'Steve Sender', email:'steve@openpgp.org' }]
 * @returns {Promise<String|ReadableStream<String>|NodeStream<String>|Uint8Array|ReadableStream<Uint8Array>|NodeStream<Uint8Array>>} (String if `armor` was true, the default; Uint8Array if `armor` was false)
 * @async
 * @static
 */
export function sign({ message, privateKeys, armor = true, streaming = message && message.fromStream, detached = false, date = new Date(), fromUserIds = [] }) {
  checkCleartextOrMessage(message);
  if (message instanceof CleartextMessage && !armor) throw new Error("Can't sign non-armored cleartext message");
  if (message instanceof CleartextMessage && detached) throw new Error("Can't sign detached cleartext message");
  privateKeys = toArray(privateKeys); fromUserIds = toArray(fromUserIds);

  return Promise.resolve().then(async function() {
    let signature;
    if (detached) {
      signature = await message.signDetached(privateKeys, undefined, date, fromUserIds, message.fromStream);
    } else {
      signature = await message.sign(privateKeys, undefined, date, fromUserIds, message.fromStream);
    }
    signature = armor ? signature.armor() : signature.write();
    if (detached) {
      signature = stream.transformPair(message.packets.write(), async (readable, writable) => {
        await Promise.all([
          stream.pipe(signature, writable),
          stream.readToEnd(readable).catch(() => {})
        ]);
      });
    }
    return convertStream(signature, streaming, armor ? 'utf8' : 'binary');
  }).catch(onError.bind(null, 'Error signing message'));
}

/**
 * Verifies signatures of cleartext signed message
 * @param  {Key|Array<Key>} publicKeys                array of publicKeys or single key, to verify signatures
 * @param  {CleartextMessage|Message} message         (cleartext) message object with signatures
 * @param  {'utf8'|'binary'} format                   (optional) whether to return data as a string(Stream) or Uint8Array(Stream). If 'utf8' (the default), also normalize newlines.
 * @param  {'web'|'ponyfill'|'node'|false} streaming  (optional) whether to return data as a stream. Defaults to the type of stream `message` was created from, if any.
 * @param  {Signature} signature                      (optional) detached signature for verification
 * @param  {Date} date                                (optional) use the given date for verification instead of the current time
 * @returns {Promise<Object>}                         Object containing verified message in the form:
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
export function verify({ message, publicKeys, format = 'utf8', streaming = message && message.fromStream, signature = null, date = new Date() }) {
  checkCleartextOrMessage(message);
  if (message instanceof CleartextMessage && format === 'binary') throw new Error("Can't return cleartext message data as binary");
  publicKeys = toArray(publicKeys);

  return Promise.resolve().then(async function() {
    const result = {};
    result.signatures = signature ? await message.verifyDetached(signature, publicKeys, date, streaming) : await message.verify(publicKeys, date, streaming);
    result.data = format === 'binary' ? message.getLiteralData() : message.getText();
    if (streaming) linkStreams(result, message);
    result.data = await convertStream(result.data, streaming, format);
    if (!streaming) await prepareSignatures(result.signatures);
    return result;
  }).catch(onError.bind(null, 'Error verifying signed message'));
}


///////////////////////////////////////////////
//                                           //
//   Session key encryption and decryption   //
//                                           //
///////////////////////////////////////////////

/**
 * Generate a new session key object, taking the algorithm preferences of the passed public keys into account.
 * @param  {Key|Array<Key>} publicKeys  array of public keys or single key used to select algorithm preferences for
 * @param  {Date} date                  (optional) date to select algorithm preferences at
 * @param  {Array} toUserIds            (optional) user IDs to select algorithm preferences for
 * @returns {Promise<{ data: Uint8Array, algorithm: String }>} object with session key data and algorithm
 * @async
 * @static
 */
export function generateSessionKey({ publicKeys, date = new Date(), toUserIds = [] }) {
  publicKeys = toArray(publicKeys); toUserIds = toArray(toUserIds);

  return Promise.resolve().then(async function() {

    return Message.generateSessionKey(publicKeys, date, toUserIds);

  }).catch(onError.bind(null, 'Error generating session key'));
}

/**
 * Encrypt a symmetric session key with public keys, passwords, or both at once. At least either public keys
 *   or passwords must be specified.
 * @param  {Uint8Array} data                  the session key to be encrypted e.g. 16 random bytes (for aes128)
 * @param  {String} algorithm                 algorithm of the symmetric session key e.g. 'aes128' or 'aes256'
 * @param  {String} aeadAlgorithm             (optional) aead algorithm, e.g. 'eax' or 'ocb'
 * @param  {Key|Array<Key>} publicKeys        (optional) array of public keys or single key, used to encrypt the key
 * @param  {String|Array<String>} passwords   (optional) passwords for the message
 * @param  {Boolean} armor                    (optional) whether the return values should be ascii armored (true, the default) or binary (false)
 * @param  {Boolean} wildcard                 (optional) use a key ID of 0 instead of the public key IDs
 * @param  {Date} date                        (optional) override the date
 * @param  {Array} toUserIds                  (optional) array of user IDs to encrypt for, one per key in `publicKeys`, e.g. [{ name:'Phil Zimmermann', email:'phil@openpgp.org' }]
 * @returns {Promise<String|Uint8Array>} (String if `armor` was true, the default; Uint8Array if `armor` was false)
 * @async
 * @static
 */
export function encryptSessionKey({ data, algorithm, aeadAlgorithm, publicKeys, passwords, armor = true, wildcard = false, date = new Date(), toUserIds = [] }) {
  checkBinary(data); checkString(algorithm, 'algorithm'); publicKeys = toArray(publicKeys); passwords = toArray(passwords); toUserIds = toArray(toUserIds);

  return Promise.resolve().then(async function() {

    const message = await Message.encryptSessionKey(data, algorithm, aeadAlgorithm, publicKeys, passwords, wildcard, date, toUserIds);
    return armor ? message.armor() : message.write();

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
  if (!(message instanceof Message)) {
    throw new Error('Parameter [message] needs to be of type Message');
  }
}
function checkCleartextOrMessage(message) {
  if (!(message instanceof CleartextMessage) && !(message instanceof Message)) {
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
 * @param  {Object} data                              the data to convert
 * @param  {'web'|'ponyfill'|'node'|false} streaming  (optional) whether to return a ReadableStream, and of what type
 * @param  {'utf8'|'binary'} encoding                 (optional) how to return data in Node Readable streams
 * @returns {Object}                                  the data in the respective format
 */
async function convertStream(data, streaming, encoding = 'utf8') {
  let streamType = util.isStream(data);
  if (!streaming && streamType) {
    return stream.readToEnd(data);
  }
  if (streaming && !streamType) {
    data = stream.toStream(data);
    streamType = util.isStream(data);
  }
  if (streaming === 'node') {
    data = stream.webToNode(data);
    if (encoding !== 'binary') data.setEncoding(encoding);
    return data;
  }
  if (streaming === 'web' && streamType === 'ponyfill' && toNativeReadable) {
    return toNativeReadable(data);
  }
  return data;
}

/**
 * Link result.data to the message stream for cancellation.
 * Also, forward errors in the message to result.data.
 * @param  {Object} result                  the data to convert
 * @param  {Message} message                message object
 * @returns {Object}
 */
function linkStreams(result, message) {
  result.data = stream.transformPair(message.packets.stream, async (readable, writable) => {
    await stream.pipe(result.data, writable, {
      preventClose: true
    });
    const writer = stream.getWriter(writable);
    try {
      // Forward errors in the message stream to result.data.
      await stream.readToEnd(readable, _ => _);
      await writer.close();
    } catch (e) {
      await writer.abort(e);
    }
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
      util.printDebugError(e);
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
  util.printDebugError(error);

  // update error message
  try {
    error.message = message + ': ' + error.message;
  } catch (e) {}

  throw error;
}
