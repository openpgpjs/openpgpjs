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

import stream from '@openpgp/web-stream-tools';
import { createReadableStreamWrapper } from '@mattiasbuelens/web-streams-adapter';
import { Message } from './message';
import { CleartextMessage } from './cleartext';
import { generate, reformat, getPreferredAlgo } from './key';
import defaultConfig from './config';
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
 * @param {Object} options
 * @param {'ecc'|'rsa'} [options.type='ecc'] - The primary key algorithm type: ECC (default) or RSA
 * @param {Object|Array<Object>} options.userIds - User IDs as objects: `{ name: 'Jo Doe', email: 'info@jo.com' }`
 * @param {String} [options.passphrase=(not protected)] - The passphrase used to encrypt the generated private key
 * @param {Number} [options.rsaBits=4096] - Number of bits for RSA keys
 * @param {String} [options.curve='curve25519'] - Elliptic curve for ECC keys:
 *                                             curve25519 (default), p256, p384, p521, secp256k1,
 *                                             brainpoolP256r1, brainpoolP384r1, or brainpoolP512r1
 * @param {Date} [options.date=current date] - Override the creation date of the key and the key signatures
 * @param {Number} [options.keyExpirationTime=0 (never expires)] - Number of seconds from the key creation time after which the key expires
 * @param {Array<Object>} [options.subkeys=a single encryption subkey] - Options for each subkey, default to main key options. e.g. `[{sign: true, passphrase: '123'}]`
 *                                             sign parameter defaults to false, and indicates whether the subkey should sign rather than encrypt
 * @param {Object} [options.config] - Custom configuration settings to overwrite those in [config]{@link module:config}
 * @returns {Object} The generated key object in the form:
 *                                     { key:Key, privateKeyArmored:String, publicKeyArmored:String, revocationCertificate:String }
 * @async
 * @static
 */
export function generateKey({ userIds = [], passphrase = "", type = "ecc", rsaBits = 4096, curve = "curve25519", keyExpirationTime = 0, date = new Date(), subkeys = [{}], config }) {
  config = { ...defaultConfig, ...config };
  userIds = toArray(userIds);
  const options = { userIds, passphrase, type, rsaBits, curve, keyExpirationTime, date, subkeys };
  if (type === "rsa" && rsaBits < config.minRSABits) {
    throw new Error(`rsaBits should be at least ${config.minRSABits}, got: ${rsaBits}`);
  }

  return generate(options, config).then(async key => {
    const revocationCertificate = await key.getRevocationCertificate(date, config);
    key.revocationSignatures = [];

    return {

      key: key,
      privateKeyArmored: key.armor(config),
      publicKeyArmored: key.toPublic().armor(config),
      revocationCertificate: revocationCertificate

    };
  }).catch(onError.bind(null, 'Error generating keypair'));
}

/**
 * Reformats signature packets for a key and rewraps key object.
 * @param {Object} options
 * @param {Key} options.privateKey - Private key to reformat
 * @param {Object|Array<Object>} options.userIds - User IDs as objects: `{ name: 'Jo Doe', email: 'info@jo.com' }`
 * @param {String} [options.passphrase=(not protected)] - The passphrase used to encrypt the generated private key
 * @param {Number} [options.keyExpirationTime=0 (never expires)] - Number of seconds from the key creation time after which the key expires
 * @param {Object} [options.config] - Custom configuration settings to overwrite those in [config]{@link module:config}
 * @returns {Object} The generated key object in the form:
 *                                     { key:Key, privateKeyArmored:String, publicKeyArmored:String, revocationCertificate:String }
 * @async
 * @static
 */
export function reformatKey({ privateKey, userIds = [], passphrase = "", keyExpirationTime = 0, date, config }) {
  config = { ...defaultConfig, ...config };
  userIds = toArray(userIds);
  const options = { privateKey, userIds, passphrase, keyExpirationTime, date };

  return reformat(options, config).then(async key => {
    const revocationCertificate = await key.getRevocationCertificate(date, config);
    key.revocationSignatures = [];

    return {

      key: key,
      privateKeyArmored: key.armor(config),
      publicKeyArmored: key.toPublic().armor(config),
      revocationCertificate: revocationCertificate

    };
  }).catch(onError.bind(null, 'Error reformatting keypair'));
}

/**
 * Revokes a key. Requires either a private key or a revocation certificate.
 *   If a revocation certificate is passed, the reasonForRevocation parameter will be ignored.
 * @param {Object} options
 * @param {Key} options.key - Public or private key to revoke
 * @param {String} [options.revocationCertificate] - Revocation certificate to revoke the key with
 * @param {Object} [options.reasonForRevocation] - Object indicating the reason for revocation
 * @param {module:enums.reasonForRevocation} [options.reasonForRevocation.flag=[noReason]{@link module:enums.reasonForRevocation}] - Flag indicating the reason for revocation
 * @param {String} [options.reasonForRevocation.string=""] - String explaining the reason for revocation
 * @param {Object} [options.config] - Custom configuration settings to overwrite those in [config]{@link module:config}
 * @returns {Object} The revoked key object in the form:
 *                                     `{ privateKey:Key, privateKeyArmored:String, publicKey:Key, publicKeyArmored:String }`
 *                                     (if private key is passed) or `{ publicKey:Key, publicKeyArmored:String }` (otherwise)
 * @async
 * @static
 */
export function revokeKey({ key, revocationCertificate, reasonForRevocation, config }) {
  config = { ...defaultConfig, ...config };
  return Promise.resolve().then(() => {
    if (revocationCertificate) {
      return key.applyRevocationCertificate(revocationCertificate, config);
    } else {
      return key.revoke(reasonForRevocation, undefined, config);
    }
  }).then(async key => {
    if (key.isPrivate()) {
      const publicKey = key.toPublic();
      return {
        privateKey: key,
        privateKeyArmored: key.armor(config),
        publicKey: publicKey,
        publicKeyArmored: publicKey.armor(config)
      };
    }
    return {
      publicKey: key,
      publicKeyArmored: key.armor(config)
    };
  }).catch(onError.bind(null, 'Error revoking key'));
}

/**
 * Unlock a private key with the given passphrase.
 * This method does not change the original key.
 * @param {Object} options
 * @param {Key} options.privateKey - The private key to decrypt
 * @param {String|Array<String>} options.passphrase - The user's passphrase(s)
 * @param {Object} [options.config] - Custom configuration settings to overwrite those in [config]{@link module:config}
 * @returns {Key} The unlocked key object.
 * @async
 */
export async function decryptKey({ privateKey, passphrase, config }) {
  config = { ...defaultConfig, ...config };
  const key = await privateKey.clone();
  // shallow clone is enough since the encrypted material is not changed in place by decryption
  key.getKeys().forEach(k => {
    k.keyPacket = Object.create(
      Object.getPrototypeOf(k.keyPacket),
      Object.getOwnPropertyDescriptors(k.keyPacket)
    );
  });
  try {
    await key.decrypt(passphrase, undefined, config);
    return key;
  } catch (err) {
    key.clearPrivateParams();
    return onError('Error decrypting private key', err);
  }
}

/**
 * Lock a private key with the given passphrase.
 * This method does not change the original key.
 * @param {Object} options
 * @param {Key} options.privateKey - The private key to encrypt
 * @param {String|Array<String>} options.passphrase - If multiple passphrases, they should be in the same order as the packets each should encrypt
 * @param {Object} [options.config] - Custom configuration settings to overwrite those in [config]{@link module:config}
 * @returns {Key} The locked key object.
 * @async
 */
export async function encryptKey({ privateKey, passphrase, config }) {
  config = { ...defaultConfig, ...config };
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
    await key.encrypt(passphrase, undefined, config);
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
 * @param {Object} options
 * @param {Message} options.message - Message to be encrypted as created by {@link Message.fromText} or {@link Message.fromBinary}
 * @param {Key|Array<Key>} [options.publicKeys] - Array of keys or single key, used to encrypt the message
 * @param {Key|Array<Key>} [options.privateKeys] - Private keys for signing. If omitted message will not be signed
 * @param {String|Array<String>} [options.passwords] - Array of passwords or a single password to encrypt the message
 * @param {Object} [options.sessionKey] - Session key in the form: `{ data:Uint8Array, algorithm:String }`
 * @param {Boolean} [options.armor=true] - Whether the return values should be ascii armored (true, the default) or binary (false)
 * @param {'web'|'ponyfill'|'node'|false} [options.streaming=type of stream `message` was created from, if any] - Whether to return data as a stream
 * @param {Signature} [options.signature] - A detached signature to add to the encrypted message
 * @param {Boolean} [options.wildcard=false] - Use a key ID of 0 instead of the public key IDs
 * @param {Array<module:type/keyid~KeyID>} [options.signingKeyIDs=latest-created valid signing (sub)keys] - Array of key IDs to use for signing. Each `signingKeyIDs[i]` corresponds to `privateKeys[i]`
 * @param {Array<module:type/keyid~KeyID>} [options.encryptionKeyIDs=latest-created valid encryption (sub)keys] - Array of key IDs to use for encryption. Each `encryptionKeyIDs[i]` corresponds to `publicKeys[i]`
 * @param {Date} [options.date=current date] - Override the creation date of the message signature
 * @param {Array<Object>} [options.fromUserIds=primary user IDs] - Array of user IDs to sign with, one per key in `privateKeys`, e.g. `[{ name: 'Steve Sender', email: 'steve@openpgp.org' }]`
 * @param {Array<Object>} [options.toUserIds=primary user IDs] - Array of user IDs to encrypt for, one per key in `publicKeys`, e.g. `[{ name: 'Robert Receiver', email: 'robert@openpgp.org' }]`
 * @param {Object} [options.config] - Custom configuration settings to overwrite those in [config]{@link module:config}
 * @returns {String|ReadableStream<String>|NodeStream<String>|Uint8Array|ReadableStream<Uint8Array>|NodeStream<Uint8Array>} Encrypted message (string if `armor` was true, the default; Uint8Array if `armor` was false).
 * @async
 * @static
 */
export function encrypt({ message, publicKeys, privateKeys, passwords, sessionKey, armor = true, streaming = message && message.fromStream, detached = false, signature = null, wildcard = false, signingKeyIDs = [], encryptionKeyIDs = [], date = new Date(), fromUserIds = [], toUserIds = [], config }) {
  config = { ...defaultConfig, ...config };
  checkMessage(message); publicKeys = toArray(publicKeys); privateKeys = toArray(privateKeys); passwords = toArray(passwords); fromUserIds = toArray(fromUserIds); toUserIds = toArray(toUserIds);
  if (detached) {
    throw new Error("detached option has been removed from openpgp.encrypt. Separately call openpgp.sign instead. Don't forget to remove privateKeys option as well.");
  }

  return Promise.resolve().then(async function() {
    if (!privateKeys) {
      privateKeys = [];
    }
    if (privateKeys.length || signature) { // sign the message only if private keys or signature is specified
      message = await message.sign(privateKeys, signature, signingKeyIDs, date, fromUserIds, message.fromStream, config);
    }
    message = message.compress(
      await getPreferredAlgo('compression', publicKeys, date, toUserIds, config),
      config
    );
    message = await message.encrypt(publicKeys, passwords, sessionKey, wildcard, encryptionKeyIDs, date, toUserIds, streaming, config);
    const data = armor ? message.armor(config) : message.write();
    return convertStream(data, streaming, armor ? 'utf8' : 'binary');
  }).catch(onError.bind(null, 'Error encrypting message'));
}

/**
 * Decrypts a message with the user's private key, a session key or a password. Either a private key,
 *   a session key or a password must be specified.
 * @param {Object} options
 * @param {Message} options.message - The message object with the encrypted data
 * @param {Key|Array<Key>} [options.privateKeys] - Private keys with decrypted secret key data or session key
 * @param {String|Array<String>} [options.passwords] - Passwords to decrypt the message
 * @param {Object|Array<Object>} [options.sessionKeys] - Session keys in the form: { data:Uint8Array, algorithm:String }
 * @param {Key|Array<Key>} [options.publicKeys] - Array of public keys or single key, to verify signatures
 * @param {'utf8'|'binary'} [options.format='utf8'] - Whether to return data as a string(Stream) or Uint8Array(Stream). If 'utf8' (the default), also normalize newlines.
 * @param {'web'|'ponyfill'|'node'|false} [options.streaming=type of stream `message` was created from, if any] - Whether to return data as a stream. Defaults to the type of stream `message` was created from, if any.
 * @param {Signature} [options.signature] - Detached signature for verification
 * @param {Date} [options.date=current date] - Use the given date for verification instead of the current time
 * @param {Object} [options.config] - Custom configuration settings to overwrite those in [config]{@link module:config}
 * @returns {Object} Object containing decrypted and verified message in the form:
 *
 *     {
 *       data: String|ReadableStream<String>|NodeStream, (if format was 'utf8', the default)
 *       data: Uint8Array|ReadableStream<Uint8Array>|NodeStream, (if format was 'binary')
 *       filename: String,
 *       signatures: [
 *         {
 *           keyID: module:type/keyid~KeyID,
 *           verified: Promise<Boolean>,
 *           valid: Boolean (if streaming was false)
 *         }, ...
 *       ]
 *     }
 * @async
 * @static
 */
export function decrypt({ message, privateKeys, passwords, sessionKeys, publicKeys, format = 'utf8', streaming = message && message.fromStream, signature = null, date = new Date(), config }) {
  config = { ...defaultConfig, ...config };
  checkMessage(message); publicKeys = toArray(publicKeys); privateKeys = toArray(privateKeys); passwords = toArray(passwords); sessionKeys = toArray(sessionKeys);

  return message.decrypt(privateKeys, passwords, sessionKeys, streaming, config).then(async function(decrypted) {
    if (!publicKeys) {
      publicKeys = [];
    }

    const result = {};
    result.signatures = signature ? await decrypted.verifyDetached(signature, publicKeys, date, streaming, config) : await decrypted.verify(publicKeys, date, streaming, config);
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
 * @param {Object} options
 * @param {CleartextMessage|Message} options.message - (cleartext) message to be signed
 * @param {Key|Array<Key>} options.privateKeys - Array of keys or single key with decrypted secret key data to sign cleartext
 * @param {Boolean} [options.armor=true] - Whether the return values should be ascii armored (true, the default) or binary (false)
 * @param {'web'|'ponyfill'|'node'|false} [options.streaming=type of stream `message` was created from, if any] - Whether to return data as a stream. Defaults to the type of stream `message` was created from, if any.
 * @param {Boolean} [options.detached=false] - If the return value should contain a detached signature
 * @param {Array<module:type/keyid~KeyID>} [options.signingKeyIDs=latest-created valid signing (sub)keys] - Array of key IDs to use for signing. Each signingKeyIDs[i] corresponds to privateKeys[i]
 * @param {Date} [options.date=current date] - Override the creation date of the signature
 * @param {Array<Object>} [options.fromUserIds=primary user IDs] - Array of user IDs to sign with, one per key in `privateKeys`, e.g. `[{ name: 'Steve Sender', email: 'steve@openpgp.org' }]`
 * @param {Object} [options.config] - Custom configuration settings to overwrite those in [config]{@link module:config}
 * @returns {String|ReadableStream<String>|NodeStream<String>|Uint8Array|ReadableStream<Uint8Array>|NodeStream<Uint8Array>} Signed message (string if `armor` was true, the default; Uint8Array if `armor` was false).
 * @async
 * @static
 */
export function sign({ message, privateKeys, armor = true, streaming = message && message.fromStream, detached = false, signingKeyIDs = [], date = new Date(), fromUserIds = [], config }) {
  config = { ...defaultConfig, ...config };
  checkCleartextOrMessage(message);
  if (message instanceof CleartextMessage && !armor) throw new Error("Can't sign non-armored cleartext message");
  if (message instanceof CleartextMessage && detached) throw new Error("Can't detach-sign a cleartext message");
  privateKeys = toArray(privateKeys); fromUserIds = toArray(fromUserIds);

  return Promise.resolve().then(async function() {
    let signature;
    if (message instanceof CleartextMessage) {
      signature = await message.sign(privateKeys, undefined, signingKeyIDs, date, fromUserIds, config);
    } else if (detached) {
      signature = await message.signDetached(privateKeys, undefined, signingKeyIDs, date, fromUserIds, message.fromStream, config);
    } else {
      signature = await message.sign(privateKeys, undefined, signingKeyIDs, date, fromUserIds, message.fromStream, config);
    }
    signature = armor ? signature.armor(config) : signature.write();
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
 * @param {Object} options
 * @param {Key|Array<Key>} options.publicKeys - Array of publicKeys or single key, to verify signatures
 * @param {CleartextMessage|Message} options.message - (cleartext) message object with signatures
 * @param {'utf8'|'binary'} [options.format='utf8'] - Whether to return data as a string(Stream) or Uint8Array(Stream). If 'utf8' (the default), also normalize newlines.
 * @param {'web'|'ponyfill'|'node'|false} [options.streaming=type of stream `message` was created from, if any] - Whether to return data as a stream. Defaults to the type of stream `message` was created from, if any.
 * @param {Signature} [options.signature] - Detached signature for verification
 * @param {Date} [options.date=current date] - Use the given date for verification instead of the current time
 * @param {Object} [options.config] - Custom configuration settings to overwrite those in [config]{@link module:config}
 * @returns {Object} Object containing verified message in the form:
 *
 *     {
 *       data: String|ReadableStream<String>|NodeStream, (if `message` was a CleartextMessage)
 *       data: Uint8Array|ReadableStream<Uint8Array>|NodeStream, (if `message` was a Message)
 *       signatures: [
 *         {
 *           keyID: module:type/keyid~KeyID,
 *           verified: Promise<Boolean>,
 *           valid: Boolean (if `streaming` was false)
 *         }, ...
 *       ]
 *     }
 * @async
 * @static
 */
export function verify({ message, publicKeys, format = 'utf8', streaming = message && message.fromStream, signature = null, date = new Date(), config }) {
  config = { ...defaultConfig, ...config };
  checkCleartextOrMessage(message);
  if (message instanceof CleartextMessage && format === 'binary') throw new Error("Can't return cleartext message data as binary");
  if (message instanceof CleartextMessage && signature) throw new Error("Can't verify detached cleartext signature");
  publicKeys = toArray(publicKeys);

  return Promise.resolve().then(async function() {
    const result = {};
    if (message instanceof CleartextMessage) {
      result.signatures = await message.verify(publicKeys, date, config);
    } else {
      result.signatures = signature ? await message.verifyDetached(signature, publicKeys, date, streaming, config) : await message.verify(publicKeys, date, streaming, config);
    }
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
 * @param {Object} options
 * @param {Key|Array<Key>} options.publicKeys - Array of public keys or single key used to select algorithm preferences for
 * @param {Date} [options.date=current date] - Date to select algorithm preferences at
 * @param {Array} [options.toUserIds=primary user IDs] - User IDs to select algorithm preferences for
 * @param {Object} [options.config] - Custom configuration settings to overwrite those in [config]{@link module:config}
 * @returns {{ data: Uint8Array, algorithm: String }} Object with session key data and algorithm.
 * @async
 * @static
 */
export function generateSessionKey({ publicKeys, date = new Date(), toUserIds = [], config }) {
  config = { ...defaultConfig, ...config };
  publicKeys = toArray(publicKeys); toUserIds = toArray(toUserIds);

  return Promise.resolve().then(async function() {

    return Message.generateSessionKey(publicKeys, date, toUserIds, config);

  }).catch(onError.bind(null, 'Error generating session key'));
}

/**
 * Encrypt a symmetric session key with public keys, passwords, or both at once. At least either public keys
 *   or passwords must be specified.
 * @param {Object} options
 * @param {Uint8Array} options.data - The session key to be encrypted e.g. 16 random bytes (for aes128)
 * @param {String} options.algorithm - Algorithm of the symmetric session key e.g. 'aes128' or 'aes256'
 * @param {String} [options.aeadAlgorithm] - Aead algorithm, e.g. 'eax' or 'ocb'
 * @param {Key|Array<Key>} [options.publicKeys] - Array of public keys or single key, used to encrypt the key
 * @param {String|Array<String>} [options.passwords] - Passwords for the message
 * @param {Boolean} [options.armor=true] - Whether the return values should be ascii armored (true, the default) or binary (false)
 * @param {Boolean} [options.wildcard=false] - Use a key ID of 0 instead of the public key IDs
 * @param {Array<module:type/keyid~KeyID>} [options.encryptionKeyIDs=latest-created valid encryption (sub)keys] - Array of key IDs to use for encryption. Each encryptionKeyIDs[i] corresponds to publicKeys[i]
 * @param {Date} [options.date=current date] - Override the date
 * @param {Array} [options.toUserIds=primary user IDs] - Array of user IDs to encrypt for, one per key in `publicKeys`, e.g. `[{ name: 'Phil Zimmermann', email: 'phil@openpgp.org' }]`
 * @param {Object} [options.config] - Custom configuration settings to overwrite those in [config]{@link module:config}
 * @returns {String|Uint8Array} Encrypted session keys (string if `armor` was true, the default; Uint8Array if `armor` was false).
 * @async
 * @static
 */
export function encryptSessionKey({ data, algorithm, aeadAlgorithm, publicKeys, passwords, armor = true, wildcard = false, encryptionKeyIDs = [], date = new Date(), toUserIds = [], config }) {
  config = { ...defaultConfig, ...config };
  checkBinary(data); checkString(algorithm, 'algorithm'); publicKeys = toArray(publicKeys); passwords = toArray(passwords); toUserIds = toArray(toUserIds);

  return Promise.resolve().then(async function() {

    const message = await Message.encryptSessionKey(data, algorithm, aeadAlgorithm, publicKeys, passwords, wildcard, encryptionKeyIDs, date, toUserIds, config);
    return armor ? message.armor(config) : message.write();

  }).catch(onError.bind(null, 'Error encrypting session key'));
}

/**
 * Decrypt symmetric session keys with a private key or password. Either a private key or
 *   a password must be specified.
 * @param {Object} options
 * @param {Message} options.message - A message object containing the encrypted session key packets
 * @param {Key|Array<Key>} [options.privateKeys] - Private keys with decrypted secret key data
 * @param {String|Array<String>} [options.passwords] - Passwords to decrypt the session key
 * @param {Object} [options.config] - Custom configuration settings to overwrite those in [config]{@link module:config}
 * @returns {Object|undefined} Array of decrypted session key, algorithm pairs in the form:
 *                                            { data:Uint8Array, algorithm:String }
 *                                            or 'undefined' if no key packets found
 * @async
 * @static
 */
export function decryptSessionKeys({ message, privateKeys, passwords, config }) {
  config = { ...defaultConfig, ...config };
  checkMessage(message); privateKeys = toArray(privateKeys); passwords = toArray(passwords);

  return Promise.resolve().then(async function() {

    return message.decryptSessionKeys(privateKeys, passwords, config);

  }).catch(onError.bind(null, 'Error decrypting session keys'));
}


//////////////////////////
//                      //
//   Helper functions   //
//                      //
//////////////////////////


/**
 * Input validation
 * @private
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
 * @param {Object} param - the parameter to be normalized
 * @returns {Array<Object>|undefined} The resulting array or undefined.
 * @private
 */
function toArray(param) {
  if (param && !util.isArray(param)) {
    param = [param];
  }
  return param;
}

/**
 * Convert data to or from Stream
 * @param {Object} data - the data to convert
 * @param {'web'|'ponyfill'|'node'|false} [options.streaming] - Whether to return a ReadableStream, and of what type
 * @param {'utf8'|'binary'} [options.encoding] - How to return data in Node Readable streams
 * @returns {Object} The data in the respective format.
 * @private
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
 * @param {Object} result - the data to convert
 * @param {Message} message - message object
 * @returns {Object}
 * @private
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
 * @param {Object} signatures - list of signatures
 * @private
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
 * @param {String} message - A human readable high level error Message
 * @param {Error} error - The internal error that caused the failure
 * @private
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
