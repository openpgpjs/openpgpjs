// OpenPGP.js - An OpenPGP implementation in javascript
// Copyright (C) 2015-2016 Decentral
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
 * @fileoverview Provides factory methods for key creation
 * @requires packet
 * @requires key/Key
 * @requires key/helper
 * @requires enums
 * @requires util
 * @requires config
 * @requires armor
 * @module key/factory
 */

import { PacketList, UserIDPacket, SignaturePacket } from '../packet';
import Key from './key';
import * as helper from './helper';
import enums from '../enums';
import util from '../util';
import config from '../config';
import armor from '../encoding/armor';

/**
 * Generates a new OpenPGP key. Supports RSA and ECC keys.
 * Primary and subkey will be of same type.
 * @param {module:enums.publicKey} [options.keyType=module:enums.publicKey.rsaEncryptSign]
 *                             To indicate what type of key to make.
 *                             RSA is 1. See {@link https://tools.ietf.org/html/rfc4880#section-9.1}
 * @param {Integer} options.rsaBits    number of bits for the key creation.
 * @param {String|Array<String>}  options.userIds
 *                             Assumes already in form of "User Name <username@email.com>"
 *                             If array is used, the first userId is set as primary user Id
 * @param {String}  options.passphrase The passphrase used to encrypt the resulting private key
 * @param {Number} [options.keyExpirationTime=0]
 *                             The number of seconds after the key creation time that the key expires
 * @param  {String} options.curve            (optional) elliptic curve for ECC keys
 * @param  {Date} options.date         Override the creation date of the key and the key signatures
 * @param  {Array<Object>} options.subkeys   (optional) options for each subkey, default to main key options. e.g. [{sign: true, passphrase: '123'}]
 *                                              sign parameter defaults to false, and indicates whether the subkey should sign rather than encrypt
 * @returns {Promise<module:key.Key>}
 * @async
 * @static
 */
export async function generate(options) {
  options.sign = true; // primary key is always a signing key
  options = helper.sanitizeKeyOptions(options);
  options.subkeys = options.subkeys.map(function(subkey, index) { return helper.sanitizeKeyOptions(options.subkeys[index], options); });

  let promises = [helper.generateSecretKey(options)];
  promises = promises.concat(options.subkeys.map(helper.generateSecretSubkey));
  return Promise.all(promises).then(packets => wrapKeyObject(packets[0], packets.slice(1), options));
}

/**
 * Reformats and signs an OpenPGP key with a given User ID. Currently only supports RSA keys.
 * @param {module:key.Key} options.privateKey   The private key to reformat
 * @param {module:enums.publicKey} [options.keyType=module:enums.publicKey.rsaEncryptSign]
 * @param {String|Array<String>}  options.userIds
 *                             Assumes already in form of "User Name <username@email.com>"
 *                             If array is used, the first userId is set as primary user Id
 * @param {String}  options.passphrase The passphrase used to encrypt the resulting private key
 * @param {Number} [options.keyExpirationTime=0]
 *                             The number of seconds after the key creation time that the key expires
 * @param  {Date} options.date         Override the creation date of the key and the key signatures
 * @param  {Array<Object>} options.subkeys   (optional) options for each subkey, default to main key options. e.g. [{sign: true, passphrase: '123'}]
 *
 * @returns {Promise<module:key.Key>}
 * @async
 * @static
 */
export async function reformat(options) {
  options = sanitize(options);

  try {
    const isDecrypted = options.privateKey.getKeys().every(key => key.isDecrypted());
    if (!isDecrypted) {
      await options.privateKey.decrypt();
    }
  } catch (err) {
    throw new Error('Key not decrypted');
  }

  const packetlist = options.privateKey.toPacketlist();
  let secretKeyPacket;
  const secretSubkeyPackets = [];
  for (let i = 0; i < packetlist.length; i++) {
    if (packetlist[i].tag === enums.packet.secretKey) {
      secretKeyPacket = packetlist[i];
    } else if (packetlist[i].tag === enums.packet.secretSubkey) {
      secretSubkeyPackets.push(packetlist[i]);
    }
  }
  if (!secretKeyPacket) {
    throw new Error('Key does not contain a secret key packet');
  }

  if (!options.subkeys) {
    options.subkeys = await Promise.all(secretSubkeyPackets.map(async secretSubkeyPacket => ({
      sign: await options.privateKey.getSigningKey(secretSubkeyPacket.getKeyId(), null).catch(() => {}) &&
          !await options.privateKey.getEncryptionKey(secretSubkeyPacket.getKeyId(), null).catch(() => {})
    })));
  }

  if (options.subkeys.length !== secretSubkeyPackets.length) {
    throw new Error('Number of subkey options does not match number of subkeys');
  }

  options.subkeys = options.subkeys.map(function(subkey, index) { return sanitize(options.subkeys[index], options); });

  return wrapKeyObject(secretKeyPacket, secretSubkeyPackets, options);

  function sanitize(options, subkeyDefaults = {}) {
    options.keyExpirationTime = options.keyExpirationTime || subkeyDefaults.keyExpirationTime;
    options.passphrase = util.isString(options.passphrase) ? options.passphrase : subkeyDefaults.passphrase;
    options.date = options.date || subkeyDefaults.date;

    return options;
  }
}


async function wrapKeyObject(secretKeyPacket, secretSubkeyPackets, options) {
  // set passphrase protection
  if (options.passphrase) {
    await secretKeyPacket.encrypt(options.passphrase);
  }

  await Promise.all(secretSubkeyPackets.map(async function(secretSubkeyPacket, index) {
    const subkeyPassphrase = options.subkeys[index].passphrase;
    if (subkeyPassphrase) {
      await secretSubkeyPacket.encrypt(subkeyPassphrase);
    }
  }));

  const packetlist = new PacketList();

  packetlist.push(secretKeyPacket);

  await Promise.all(options.userIds.map(async function(userId, index) {
    function createdPreferredAlgos(algos, configAlgo) {
      if (configAlgo) { // Not `uncompressed` / `plaintext`
        const configIndex = algos.indexOf(configAlgo);
        if (configIndex >= 1) { // If it is included and not in first place,
          algos.splice(configIndex, 1); // remove it.
        }
        if (configIndex !== 0) { // If it was included and not in first place, or wasn't included,
          algos.unshift(configAlgo); // add it to the front.
        }
      }
      return algos;
    }

    const userIdPacket = new UserIDPacket();
    userIdPacket.format(userId);

    const dataToSign = {};
    dataToSign.userId = userIdPacket;
    dataToSign.key = secretKeyPacket;
    const signaturePacket = new SignaturePacket(options.date);
    signaturePacket.signatureType = enums.signature.certGeneric;
    signaturePacket.publicKeyAlgorithm = secretKeyPacket.algorithm;
    signaturePacket.hashAlgorithm = await helper.getPreferredHashAlgo(null, secretKeyPacket);
    signaturePacket.keyFlags = [enums.keyFlags.certifyKeys | enums.keyFlags.signData];
    signaturePacket.preferredSymmetricAlgorithms = createdPreferredAlgos([
      // prefer aes256, aes128, then aes192 (no WebCrypto support: https://www.chromium.org/blink/webcrypto#TOC-AES-support)
      enums.symmetric.aes256,
      enums.symmetric.aes128,
      enums.symmetric.aes192
    ], config.encryptionCipher);
    if (config.aeadProtect) {
      signaturePacket.preferredAeadAlgorithms = createdPreferredAlgos([
        enums.aead.eax,
        enums.aead.ocb
      ], config.aeadMode);
    }
    signaturePacket.preferredHashAlgorithms = createdPreferredAlgos([
      // prefer fast asm.js implementations (SHA-256)
      enums.hash.sha256,
      enums.hash.sha512
    ], config.preferHashAlgorithm);
    signaturePacket.preferredCompressionAlgorithms = createdPreferredAlgos([
      enums.compression.zlib,
      enums.compression.zip,
      enums.compression.uncompressed
    ], config.compression);
    if (index === 0) {
      signaturePacket.isPrimaryUserID = true;
    }
    if (config.integrityProtect) {
      signaturePacket.features = [0];
      signaturePacket.features[0] |= enums.features.modificationDetection;
    }
    if (config.aeadProtect) {
      signaturePacket.features || (signaturePacket.features = [0]);
      signaturePacket.features[0] |= enums.features.aead;
    }
    if (config.v5Keys) {
      signaturePacket.features || (signaturePacket.features = [0]);
      signaturePacket.features[0] |= enums.features.v5Keys;
    }
    if (options.keyExpirationTime > 0) {
      signaturePacket.keyExpirationTime = options.keyExpirationTime;
      signaturePacket.keyNeverExpires = false;
    }
    await signaturePacket.sign(secretKeyPacket, dataToSign);

    return { userIdPacket, signaturePacket };
  })).then(list => {
    list.forEach(({ userIdPacket, signaturePacket }) => {
      packetlist.push(userIdPacket);
      packetlist.push(signaturePacket);
    });
  });

  await Promise.all(secretSubkeyPackets.map(async function(secretSubkeyPacket, index) {
    const subkeyOptions = options.subkeys[index];
    const subkeySignaturePacket = await helper.createBindingSignature(secretSubkeyPacket, secretKeyPacket, subkeyOptions);
    return { secretSubkeyPacket, subkeySignaturePacket };
  })).then(packets => {
    packets.forEach(({ secretSubkeyPacket, subkeySignaturePacket }) => {
      packetlist.push(secretSubkeyPacket);
      packetlist.push(subkeySignaturePacket);
    });
  });

  // Add revocation signature packet for creating a revocation certificate.
  // This packet should be removed before returning the key.
  const dataToSign = { key: secretKeyPacket };
  packetlist.push(await helper.createSignaturePacket(dataToSign, null, secretKeyPacket, {
    signatureType: enums.signature.keyRevocation,
    reasonForRevocationFlag: enums.reasonForRevocation.noReason,
    reasonForRevocationString: ''
  }, options.date));

  // set passphrase protection
  if (options.passphrase) {
    secretKeyPacket.clearPrivateParams();
  }

  await Promise.all(secretSubkeyPackets.map(async function(secretSubkeyPacket, index) {
    const subkeyPassphrase = options.subkeys[index].passphrase;
    if (subkeyPassphrase) {
      secretSubkeyPacket.clearPrivateParams();
    }
  }));

  return new Key(packetlist);
}

/**
 * Reads an unarmored OpenPGP key and returns a key object
 * @param {Uint8Array} data to be parsed
 * @returns {Promise<module:key.Key>} key object
 * @async
 * @static
 */
export async function read(data) {
  const packetlist = new PacketList();
  await packetlist.read(data, helper.allowedKeyPackets);
  return new Key(packetlist);
}

/**
 * Reads an OpenPGP armored key and returns a key object
 * @param {String | ReadableStream<String>} armoredKey text to be parsed
 * @returns {Promise<module:key.Key>} key object
 * @async
 * @static
 */
export async function readArmored(armoredKey) {
  const input = await armor.decode(armoredKey);
  if (!(input.type === enums.armor.publicKey || input.type === enums.armor.privateKey)) {
    throw new Error('Armored text not of type key');
  }
  return read(input.data);
}

/**
 * Reads an unarmored OpenPGP key block and returns a list of key objects
 * @param {Uint8Array} data to be parsed
 * @returns {Promise<Array<module:key.Key>>} key object
 * @async
 * @static
 */
export async function readAll(data) {
  const keys = [];
  const packetlist = new PacketList();
  await packetlist.read(data, helper.allowedKeyPackets);
  const keyIndex = packetlist.indexOfTag(enums.packet.publicKey, enums.packet.secretKey);
  if (keyIndex.length === 0) {
    throw new Error('No key packet found');
  }
  for (let i = 0; i < keyIndex.length; i++) {
    const oneKeyList = packetlist.slice(keyIndex[i], keyIndex[i + 1]);
    const newKey = new Key(oneKeyList);
    keys.push(newKey);
  }
  return keys;
}

/**
 * Reads an OpenPGP armored key block and returns a list of key objects
 * @param {String | ReadableStream<String>} armoredKey text to be parsed
 * @returns {Promise<Array<module:key.Key>>} key objects
 * @async
 * @static
 */
export async function readAllArmored(armoredKey) {
  const input = await armor.decode(armoredKey);
  if (!(input.type === enums.armor.publicKey || input.type === enums.armor.privateKey)) {
    throw new Error('Armored text not of type key');
  }
  return readAll(input.data);
}
