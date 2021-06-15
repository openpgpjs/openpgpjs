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

import * as stream from '@openpgp/web-stream-tools';
import { Message } from './message';
import { CleartextMessage } from './cleartext';
import { generate, reformat, getPreferredAlgo } from './key';
import defaultConfig from './config';
import util from './util';


//////////////////////
//                  //
//   Key handling   //
//                  //
//////////////////////


/**
 * Generates a new OpenPGP key pair. Supports RSA and ECC keys. By default, primary and subkeys will be of same type.
 * @param {Object} options
 * @param {Object|Array<Object>} options.userIDs - User IDs as objects: `{ name: 'Jo Doe', email: 'info@jo.com' }`
 * @param {'ecc'|'rsa'} [options.type='ecc'] - The primary key algorithm type: ECC (default) or RSA
 * @param {String} [options.passphrase=(not protected)] - The passphrase used to encrypt the generated private key. If omitted, the key won't be encrypted.
 * @param {Number} [options.rsaBits=4096] - Number of bits for RSA keys
 * @param {String} [options.curve='curve25519'] - Elliptic curve for ECC keys:
 *                                             curve25519 (default), p256, p384, p521, secp256k1,
 *                                             brainpoolP256r1, brainpoolP384r1, or brainpoolP512r1
 * @param {Date} [options.date=current date] - Override the creation date of the key and the key signatures
 * @param {Number} [options.keyExpirationTime=0 (never expires)] - Number of seconds from the key creation time after which the key expires
 * @param {Array<Object>} [options.subkeys=a single encryption subkey] - Options for each subkey e.g. `[{sign: true, passphrase: '123'}]`
 *                                             default to main key options, except for `sign` parameter that defaults to false, and indicates whether the subkey should sign rather than encrypt
 * @param {Object} [options.config] - Custom configuration settings to overwrite those in [config]{@link module:config}
 * @returns {Promise<Object>} The generated key object in the form:
 *                                     { key:PrivateKey, privateKeyArmored:String, publicKeyArmored:String, revocationCertificate:String }
 * @async
 * @static
 */
export async function generateKey({ userIDs = [], passphrase = "", type = "ecc", rsaBits = 4096, curve = "curve25519", keyExpirationTime = 0, date = new Date(), subkeys = [{}], config }) {
  config = { ...defaultConfig, ...config };
  userIDs = toArray(userIDs);
  if (userIDs.length === 0) {
    throw new Error('UserIDs are required for key generation');
  }
  if (type === "rsa" && rsaBits < config.minRSABits) {
    throw new Error(`rsaBits should be at least ${config.minRSABits}, got: ${rsaBits}`);
  }
  const options = { userIDs, passphrase, type, rsaBits, curve, keyExpirationTime, date, subkeys };

  try {
    const key = await generate(options, config);
    const revocationCertificate = await key.getRevocationCertificate(date, config);
    key.revocationSignatures = [];

    return {
      key,
      privateKeyArmored: key.armor(config),
      publicKeyArmored: key.toPublic().armor(config),
      revocationCertificate: revocationCertificate
    };
  } catch (err) {
    throw util.wrapError('Error generating keypair', err);
  }
}

/**
 * Reformats signature packets for a key and rewraps key object.
 * @param {Object} options
 * @param {PrivateKey} options.privateKey - Private key to reformat
 * @param {Object|Array<Object>} options.userIDs - User IDs as objects: `{ name: 'Jo Doe', email: 'info@jo.com' }`
 * @param {String} [options.passphrase=(not protected)] - The passphrase used to encrypt the reformatted private key. If omitted, the key won't be encrypted.
 * @param {Number} [options.keyExpirationTime=0 (never expires)] - Number of seconds from the key creation time after which the key expires
 * @param {Date}   [options.date] - Override the creation date of the key signatures
 * @param {Object} [options.config] - Custom configuration settings to overwrite those in [config]{@link module:config}
 * @returns {Promise<Object>} The generated key object in the form:
 *                                     { key:PrivateKey, privateKeyArmored:String, publicKeyArmored:String, revocationCertificate:String }
 * @async
 * @static
 */
export async function reformatKey({ privateKey, userIDs = [], passphrase = "", keyExpirationTime = 0, date, config }) {
  config = { ...defaultConfig, ...config };
  userIDs = toArray(userIDs);
  if (userIDs.length === 0) {
    throw new Error('UserIDs are required for key reformat');
  }
  const options = { privateKey, userIDs, passphrase, keyExpirationTime, date };

  try {
    const reformattedKey = await reformat(options, config);
    const revocationCertificate = await reformattedKey.getRevocationCertificate(date, config);
    reformattedKey.revocationSignatures = [];

    return {
      key: reformattedKey,
      privateKeyArmored: reformattedKey.armor(config),
      publicKeyArmored: reformattedKey.toPublic().armor(config),
      revocationCertificate: revocationCertificate
    };
  } catch (err) {
    throw util.wrapError('Error reformatting keypair', err);
  }
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
 * @param {Date} [options.date] - Use the given date instead of the current time to verify validity of revocation certificate (if provided), or as creation time of the revocation signature
 * @param {Object} [options.config] - Custom configuration settings to overwrite those in [config]{@link module:config}
 * @returns {Promise<Object>} The revoked key object in the form:
 *                                     `{ privateKey:PrivateKey, privateKeyArmored:String, publicKey:PublicKey, publicKeyArmored:String }`
 *                                     (if private key is passed) or `{ publicKey:PublicKey, publicKeyArmored:String }` (otherwise)
 * @async
 * @static
 */
export async function revokeKey({ key, revocationCertificate, reasonForRevocation, date = new Date(), config }) {
  config = { ...defaultConfig, ...config };
  try {
    const revokedKey = revocationCertificate ?
      await key.applyRevocationCertificate(revocationCertificate, date, config) :
      await key.revoke(reasonForRevocation, date, config);

    if (revokedKey.isPrivate()) {
      const publicKey = revokedKey.toPublic();
      return {
        privateKey: revokedKey,
        privateKeyArmored: revokedKey.armor(config),
        publicKey: publicKey,
        publicKeyArmored: publicKey.armor(config)
      };
    }

    return {
      publicKey: revokedKey,
      publicKeyArmored: revokedKey.armor(config)
    };
  } catch (err) {
    throw util.wrapError('Error revoking key', err);
  }
}

/**
 * Unlock a private key with the given passphrase.
 * This method does not change the original key.
 * @param {Object} options
 * @param {PrivateKey} options.privateKey - The private key to decrypt
 * @param {String|Array<String>} options.passphrase - The user's passphrase(s)
 * @param {Object} [options.config] - Custom configuration settings to overwrite those in [config]{@link module:config}
 * @returns {Promise<PrivateKey>} The unlocked key object.
 * @async
 */
export async function decryptKey({ privateKey, passphrase, config }) {
  config = { ...defaultConfig, ...config };
  if (!privateKey.isPrivate()) {
    throw new Error("Cannot decrypt a public key");
  }
  const clonedPrivateKey = privateKey.clone(true);
  const passphrases = util.isArray(passphrase) ? passphrase : [passphrase];

  try {
    await Promise.all(clonedPrivateKey.getKeys().map(key => (
      // try to decrypt each key with any of the given passphrases
      util.anyPromise(passphrases.map(passphrase => key.keyPacket.decrypt(passphrase)))
    )));

    await clonedPrivateKey.validate(config);
    return clonedPrivateKey;
  } catch (err) {
    clonedPrivateKey.clearPrivateParams();
    throw util.wrapError('Error decrypting private key', err);
  }
}

/**
 * Lock a private key with the given passphrase.
 * This method does not change the original key.
 * @param {Object} options
 * @param {PrivateKey} options.privateKey - The private key to encrypt
 * @param {String|Array<String>} options.passphrase - If multiple passphrases, they should be in the same order as the packets each should encrypt
 * @param {Object} [options.config] - Custom configuration settings to overwrite those in [config]{@link module:config}
 * @returns {Promise<PrivateKey>} The locked key object.
 * @async
 */
export async function encryptKey({ privateKey, passphrase, config }) {
  config = { ...defaultConfig, ...config };
  if (!privateKey.isPrivate()) {
    throw new Error("Cannot encrypt a public key");
  }
  const clonedPrivateKey = privateKey.clone(true);

  const keys = clonedPrivateKey.getKeys();
  const passphrases = util.isArray(passphrase) ? passphrase : new Array(keys.length).fill(passphrase);
  if (passphrases.length !== keys.length) {
    throw new Error("Invalid number of passphrases given for key encryption");
  }

  try {
    await Promise.all(keys.map(async (key, i) => {
      const { keyPacket } = key;
      await keyPacket.encrypt(passphrases[i], config);
      keyPacket.clearPrivateParams();
    }));
    return clonedPrivateKey;
  } catch (err) {
    clonedPrivateKey.clearPrivateParams();
    throw util.wrapError('Error encrypting private key', err);
  }
}


///////////////////////////////////////////
//                                       //
//   Message encryption and decryption   //
//                                       //
///////////////////////////////////////////


/**
 * Encrypts message text/data with public keys, passwords or both at once. At least either encryption keys or passwords
 *   must be specified. If signing keys are specified, those will be used to sign the message.
 * @param {Object} options
 * @param {Message} options.message - Message to be encrypted as created by {@link createMessage}
 * @param {PublicKey|PublicKey[]} [options.encryptionKeys] - Array of keys or single key, used to encrypt the message
 * @param {PrivateKey|PrivateKey[]} [options.signingKeys] - Private keys for signing. If omitted message will not be signed
 * @param {String|String[]} [options.passwords] - Array of passwords or a single password to encrypt the message
 * @param {Object} [options.sessionKey] - Session key in the form: `{ data:Uint8Array, algorithm:String }`
 * @param {Boolean} [options.armor=true] - Whether the return values should be ascii armored (true, the default) or binary (false)
 * @param {Signature} [options.signature] - A detached signature to add to the encrypted message
 * @param {Boolean} [options.wildcard=false] - Use a key ID of 0 instead of the public key IDs
 * @param {Array<module:type/keyid~KeyID>} [options.signingKeyIDs=latest-created valid signing (sub)keys] - Array of key IDs to use for signing. Each `signingKeyIDs[i]` corresponds to `signingKeys[i]`
 * @param {Array<module:type/keyid~KeyID>} [options.encryptionKeyIDs=latest-created valid encryption (sub)keys] - Array of key IDs to use for encryption. Each `encryptionKeyIDs[i]` corresponds to `encryptionKeys[i]`
 * @param {Date} [options.date=current date] - Override the creation date of the message signature
 * @param {Array<Object>} [options.signingUserIDs=primary user IDs] - Array of user IDs to sign with, one per key in `signingKeys`, e.g. `[{ name: 'Steve Sender', email: 'steve@openpgp.org' }]`
 * @param {Array<Object>} [options.encryptionUserIDs=primary user IDs] - Array of user IDs to encrypt for, one per key in `encryptionKeys`, e.g. `[{ name: 'Robert Receiver', email: 'robert@openpgp.org' }]`
 * @param {Object} [options.config] - Custom configuration settings to overwrite those in [config]{@link module:config}
 * @returns {Promise<MaybeStream<String>|MaybeStream<Uint8Array>>} Encrypted message (string if `armor` was true, the default; Uint8Array if `armor` was false).
 * @async
 * @static
 */
export async function encrypt({ message, encryptionKeys, signingKeys, passwords, sessionKey, armor = true, signature = null, wildcard = false, signingKeyIDs = [], encryptionKeyIDs = [], date = new Date(), signingUserIDs = [], encryptionUserIDs = [], config, ...rest }) {
  config = { ...defaultConfig, ...config };
  checkMessage(message); encryptionKeys = toArray(encryptionKeys); signingKeys = toArray(signingKeys); passwords = toArray(passwords); signingUserIDs = toArray(signingUserIDs); encryptionUserIDs = toArray(encryptionUserIDs);
  if (rest.detached) {
    throw new Error("The `detached` option has been removed from openpgp.encrypt, separately call openpgp.sign instead. Don't forget to remove the `privateKeys` option as well.");
  }
  if (rest.publicKeys) throw new Error("The `publicKeys` option has been removed from openpgp.encrypt, pass `encryptionKeys` instead");
  if (rest.privateKeys) throw new Error("The `privateKeys` option has been removed from openpgp.encrypt, pass `signingKeys` instead");

  if (!signingKeys) {
    signingKeys = [];
  }

  const streaming = message.fromStream;
  try {
    if (signingKeys.length || signature) { // sign the message only if signing keys or signature is specified
      message = await message.sign(signingKeys, signature, signingKeyIDs, date, signingUserIDs, config);
    }
    message = message.compress(
      await getPreferredAlgo('compression', encryptionKeys, date, encryptionUserIDs, config),
      config
    );
    message = await message.encrypt(encryptionKeys, passwords, sessionKey, wildcard, encryptionKeyIDs, date, encryptionUserIDs, config);
    const data = armor ? message.armor(config) : message.write();
    return convertStream(data, streaming, armor ? 'utf8' : 'binary');
  } catch (err) {
    throw util.wrapError('Error encrypting message', err);
  }
}

/**
 * Decrypts a message with the user's private key, a session key or a password. Either a private key,
 *   a session key or a password must be specified.
 * @param {Object} options
 * @param {Message} options.message - The message object with the encrypted data
 * @param {PrivateKey|PrivateKey[]} [options.decryptionKeys] - Private keys with decrypted secret key data or session key
 * @param {String|String[]} [options.passwords] - Passwords to decrypt the message
 * @param {Object|Object[]} [options.sessionKeys] - Session keys in the form: { data:Uint8Array, algorithm:String }
 * @param {PublicKey|PublicKey[]} [options.verificationKeys] - Array of public keys or single key, to verify signatures
 * @param {Boolean} [options.expectSigned=false] - If true, data decryption fails if the message is not signed with the provided publicKeys
 * @param {'utf8'|'binary'} [options.format='utf8'] - Whether to return data as a string(Stream) or Uint8Array(Stream). If 'utf8' (the default), also normalize newlines.
 * @param {Signature} [options.signature] - Detached signature for verification
 * @param {Date} [options.date=current date] - Use the given date for verification instead of the current time
 * @param {Object} [options.config] - Custom configuration settings to overwrite those in [config]{@link module:config}
 * @returns {Promise<Object>} Object containing decrypted and verified message in the form:
 *
 *     {
 *       data: MaybeStream<String>, (if format was 'utf8', the default)
 *       data: MaybeStream<Uint8Array>, (if format was 'binary')
 *       filename: String,
 *       signatures: [
 *         {
 *           keyID: module:type/keyid~KeyID,
 *           verified: Promise<Boolean>,
 *           valid: Boolean (if `message` was not created from a stream)
 *         }, ...
 *       ]
 *     }
 * @async
 * @static
 */
export async function decrypt({ message, decryptionKeys, passwords, sessionKeys, verificationKeys, expectSigned = false, format = 'utf8', signature = null, date = new Date(), config, ...rest }) {
  config = { ...defaultConfig, ...config };
  checkMessage(message); verificationKeys = toArray(verificationKeys); decryptionKeys = toArray(decryptionKeys); passwords = toArray(passwords); sessionKeys = toArray(sessionKeys);
  if (rest.privateKeys) throw new Error("The `privateKeys` option has been removed from openpgp.decrypt, pass `decryptionKeys` instead");
  if (rest.publicKeys) throw new Error("The `publicKeys` option has been removed from openpgp.decrypt, pass `verificationKeys` instead");

  try {
    const decrypted = await message.decrypt(decryptionKeys, passwords, sessionKeys, date, config);
    if (!verificationKeys) {
      verificationKeys = [];
    }

    const result = {};
    result.signatures = signature ? await decrypted.verifyDetached(signature, verificationKeys, date, config) : await decrypted.verify(verificationKeys, date, config);
    result.data = format === 'binary' ? decrypted.getLiteralData() : decrypted.getText();
    result.filename = decrypted.getFilename();
    linkStreams(result, message);
    if (expectSigned) {
      if (verificationKeys.length === 0) {
        throw new Error('Verification keys are required to verify message signatures');
      }
      if (result.signatures.length === 0) {
        throw new Error('Message is not signed');
      }
      result.data = stream.concat([
        result.data,
        stream.fromAsync(async () => {
          await util.anyPromise(result.signatures.map(sig => sig.verified));
        })
      ]);
    }
    result.data = await convertStream(result.data, message.fromStream, format);
    if (!message.fromStream) await prepareSignatures(result.signatures);
    return result;
  } catch (err) {
    throw util.wrapError('Error decrypting message', err);
  }
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
 * @param {PrivateKey|PrivateKey[]} options.signingKeys - Array of keys or single key with decrypted secret key data to sign cleartext
 * @param {Boolean} [options.armor=true] - Whether the return values should be ascii armored (true, the default) or binary (false)
 * @param {Boolean} [options.detached=false] - If the return value should contain a detached signature
 * @param {Array<module:type/keyid~KeyID>} [options.signingKeyIDs=latest-created valid signing (sub)keys] - Array of key IDs to use for signing. Each signingKeyIDs[i] corresponds to signingKeys[i]
 * @param {Date} [options.date=current date] - Override the creation date of the signature
 * @param {Object[]} [options.signingUserIDs=primary user IDs] - Array of user IDs to sign with, one per key in `signingKeys`, e.g. `[{ name: 'Steve Sender', email: 'steve@openpgp.org' }]`
 * @param {Object} [options.config] - Custom configuration settings to overwrite those in [config]{@link module:config}
 * @returns {Promise<MaybeStream<String>|MaybeStream<Uint8Array>>} Signed message (string if `armor` was true, the default; Uint8Array if `armor` was false).
 * @async
 * @static
 */
export async function sign({ message, signingKeys, armor = true, detached = false, signingKeyIDs = [], date = new Date(), signingUserIDs = [], config, ...rest }) {
  config = { ...defaultConfig, ...config };
  checkCleartextOrMessage(message);
  if (rest.privateKeys) throw new Error("The `privateKeys` option has been removed from openpgp.sign, pass `signingKeys` instead");
  if (message instanceof CleartextMessage && !armor) throw new Error("Can't sign non-armored cleartext message");
  if (message instanceof CleartextMessage && detached) throw new Error("Can't detach-sign a cleartext message");

  signingKeys = toArray(signingKeys); signingUserIDs = toArray(signingUserIDs);
  if (!signingKeys || signingKeys.length === 0) {
    throw new Error('No signing keys provided');
  }

  try {
    let signature;
    if (detached) {
      signature = await message.signDetached(signingKeys, undefined, signingKeyIDs, date, signingUserIDs, config);
    } else {
      signature = await message.sign(signingKeys, undefined, signingKeyIDs, date, signingUserIDs, config);
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
    return convertStream(signature, message.fromStream, armor ? 'utf8' : 'binary');
  } catch (err) {
    throw util.wrapError('Error signing message', err);
  }
}

/**
 * Verifies signatures of cleartext signed message
 * @param {Object} options
 * @param {CleartextMessage|Message} options.message - (cleartext) message object with signatures
 * @param {PublicKey|PublicKey[]} options.verificationKeys - Array of publicKeys or single key, to verify signatures
 * @param {Boolean} [options.expectSigned=false] - If true, verification throws if the message is not signed with the provided publicKeys
 * @param {'utf8'|'binary'} [options.format='utf8'] - Whether to return data as a string(Stream) or Uint8Array(Stream). If 'utf8' (the default), also normalize newlines.
 * @param {Signature} [options.signature] - Detached signature for verification
 * @param {Date} [options.date=current date] - Use the given date for verification instead of the current time
 * @param {Object} [options.config] - Custom configuration settings to overwrite those in [config]{@link module:config}
 * @returns {Promise<Object>} Object containing verified message in the form:
 *
 *     {
 *       data: MaybeStream<String>, (if `message` was a CleartextMessage)
 *       data: MaybeStream<Uint8Array>, (if `message` was a Message)
 *       signatures: [
 *         {
 *           keyID: module:type/keyid~KeyID,
 *           verified: Promise<Boolean>,
 *           valid: Boolean (if `message` was not created from a stream)
 *         }, ...
 *       ]
 *     }
 * @async
 * @static
 */
export async function verify({ message, verificationKeys, expectSigned = false, format = 'utf8', signature = null, date = new Date(), config, ...rest }) {
  config = { ...defaultConfig, ...config };
  checkCleartextOrMessage(message);
  if (rest.publicKeys) throw new Error("The `publicKeys` option has been removed from openpgp.verify, pass `verificationKeys` instead");
  if (message instanceof CleartextMessage && format === 'binary') throw new Error("Can't return cleartext message data as binary");
  if (message instanceof CleartextMessage && signature) throw new Error("Can't verify detached cleartext signature");

  verificationKeys = toArray(verificationKeys);

  try {
    const result = {};
    if (signature) {
      result.signatures = await message.verifyDetached(signature, verificationKeys, date, config);
    } else {
      result.signatures = await message.verify(verificationKeys, date, config);
    }
    result.data = format === 'binary' ? message.getLiteralData() : message.getText();
    if (message.fromStream) linkStreams(result, message);
    if (expectSigned) {
      if (result.signatures.length === 0) {
        throw new Error('Message is not signed');
      }
      result.data = stream.concat([
        result.data,
        stream.fromAsync(async () => {
          await util.anyPromise(result.signatures.map(sig => sig.verified));
        })
      ]);
    }
    result.data = await convertStream(result.data, message.fromStream, format);
    if (!message.fromStream) await prepareSignatures(result.signatures);
    return result;
  } catch (err) {
    throw util.wrapError('Error verifying signed message', err);
  }
}


///////////////////////////////////////////////
//                                           //
//   Session key encryption and decryption   //
//                                           //
///////////////////////////////////////////////

/**
 * Generate a new session key object, taking the algorithm preferences of the passed public keys into account.
 * @param {Object} options
 * @param {PublicKey|PublicKey[]} options.encryptionKeys - Array of public keys or single key used to select algorithm preferences for
 * @param {Date} [options.date=current date] - Date to select algorithm preferences at
 * @param {Array} [options.encryptionUserIDs=primary user IDs] - User IDs to select algorithm preferences for
 * @param {Object} [options.config] - Custom configuration settings to overwrite those in [config]{@link module:config}
 * @returns {Promise<{ data: Uint8Array, algorithm: String }>} Object with session key data and algorithm.
 * @async
 * @static
 */
export async function generateSessionKey({ encryptionKeys, date = new Date(), encryptionUserIDs = [], config, ...rest }) {
  config = { ...defaultConfig, ...config };
  encryptionKeys = toArray(encryptionKeys); encryptionUserIDs = toArray(encryptionUserIDs);
  if (rest.publicKeys) throw new Error("The `publicKeys` option has been removed from openpgp.generateSessionKey, pass `encryptionKeys` instead");

  try {
    const sessionKeys = await Message.generateSessionKey(encryptionKeys, date, encryptionUserIDs, config);
    return sessionKeys;
  } catch (err) {
    throw util.wrapError('Error generating session key', err);
  }
}

/**
 * Encrypt a symmetric session key with public keys, passwords, or both at once. At least either public keys
 *   or passwords must be specified.
 * @param {Object} options
 * @param {Uint8Array} options.data - The session key to be encrypted e.g. 16 random bytes (for aes128)
 * @param {String} options.algorithm - Algorithm of the symmetric session key e.g. 'aes128' or 'aes256'
 * @param {String} [options.aeadAlgorithm] - AEAD algorithm, e.g. 'eax' or 'ocb'
 * @param {PublicKey|PublicKey[]} [options.encryptionKeys] - Array of public keys or single key, used to encrypt the key
 * @param {String|String[]} [options.passwords] - Passwords for the message
 * @param {Boolean} [options.armor=true] - Whether the return values should be ascii armored (true, the default) or binary (false)
 * @param {Boolean} [options.wildcard=false] - Use a key ID of 0 instead of the public key IDs
 * @param {Array<module:type/keyid~KeyID>} [options.encryptionKeyIDs=latest-created valid encryption (sub)keys] - Array of key IDs to use for encryption. Each encryptionKeyIDs[i] corresponds to encryptionKeys[i]
 * @param {Date} [options.date=current date] - Override the date
 * @param {Array} [options.encryptionUserIDs=primary user IDs] - Array of user IDs to encrypt for, one per key in `encryptionKeys`, e.g. `[{ name: 'Phil Zimmermann', email: 'phil@openpgp.org' }]`
 * @param {Object} [options.config] - Custom configuration settings to overwrite those in [config]{@link module:config}
 * @returns {Promise<String|Uint8Array>} Encrypted session keys (string if `armor` was true, the default; Uint8Array if `armor` was false).
 * @async
 * @static
 */
export async function encryptSessionKey({ data, algorithm, aeadAlgorithm, encryptionKeys, passwords, armor = true, wildcard = false, encryptionKeyIDs = [], date = new Date(), encryptionUserIDs = [], config, ...rest }) {
  config = { ...defaultConfig, ...config };
  checkBinary(data); checkString(algorithm, 'algorithm'); encryptionKeys = toArray(encryptionKeys); passwords = toArray(passwords); encryptionUserIDs = toArray(encryptionUserIDs);
  if (rest.publicKeys) throw new Error("The `publicKeys` option has been removed from openpgp.encryptSessionKey, pass `encryptionKeys` instead");

  try {
    const message = await Message.encryptSessionKey(data, algorithm, aeadAlgorithm, encryptionKeys, passwords, wildcard, encryptionKeyIDs, date, encryptionUserIDs, config);
    return armor ? message.armor(config) : message.write();
  } catch (err) {
    throw util.wrapError('Error encrypting session key', err);
  }
}

/**
 * Decrypt symmetric session keys with a private key or password. Either a private key or
 *   a password must be specified.
 * @param {Object} options
 * @param {Message} options.message - A message object containing the encrypted session key packets
 * @param {PrivateKey|PrivateKey[]} [options.decryptionKeys] - Private keys with decrypted secret key data
 * @param {String|String[]} [options.passwords] - Passwords to decrypt the session key
 * @param {Date} [options.date] - Date to use for key verification instead of the current time
 * @param {Object} [options.config] - Custom configuration settings to overwrite those in [config]{@link module:config}
 * @returns {Promise<Object>} Array of decrypted session key, algorithm pairs in the form:
 *                                            { data:Uint8Array, algorithm:String }
 * @throws if no session key could be found or decrypted
 * @async
 * @static
 */
export async function decryptSessionKeys({ message, decryptionKeys, passwords, date = new Date(), config, ...rest }) {
  config = { ...defaultConfig, ...config };
  checkMessage(message); decryptionKeys = toArray(decryptionKeys); passwords = toArray(passwords);
  if (rest.privateKeys) throw new Error("The `privateKeys` option has been removed from openpgp.decryptSessionKeys, pass `decryptionKeys` instead");

  try {
    const sessionKeys = await message.decryptSessionKeys(decryptionKeys, passwords, date, config);
    return sessionKeys;
  } catch (err) {
    throw util.wrapError('Error decrypting session keys', err);
  }
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
 * @param {'web'|'ponyfill'|'node'|false} streaming - Whether to return a ReadableStream, and of what type
 * @param {'utf8'|'binary'} [encoding] - How to return data in Node Readable streams
 * @returns {Promise<Object>} The data in the respective format.
 * @async
 * @private
 */
async function convertStream(data, streaming, encoding = 'utf8') {
  const streamType = util.isStream(data);
  if (streamType === 'array') {
    return stream.readToEnd(data);
  }
  if (streaming === 'node') {
    data = stream.webToNode(data);
    if (encoding !== 'binary') data.setEncoding(encoding);
    return data;
  }
  if (streaming === 'web' && streamType === 'ponyfill') {
    return stream.toNativeReadable(data);
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
 * @async
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
