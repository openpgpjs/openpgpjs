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

import { PacketList, UserIDPacket, SignaturePacket } from '../packet';
import Key from './key';
import * as helper from './helper';
import enums from '../enums';
import util from '../util';
import defaultConfig from '../config';
import { unarmor } from '../encoding/armor';

/**
 * Generates a new OpenPGP key. Supports RSA and ECC keys.
 * By default, primary and subkeys will be of same type.
 * @param {ecc|rsa} options.type                  The primary key algorithm type: ECC or RSA
 * @param {String}  options.curve                 Elliptic curve for ECC keys
 * @param {Integer} options.rsaBits               Number of bits for RSA keys
 * @param {Array<String|Object>} options.userIds  User IDs as strings or objects: 'Jo Doe <info@jo.com>' or { name:'Jo Doe', email:'info@jo.com' }
 * @param {String}  options.passphrase            Passphrase used to encrypt the resulting private key
 * @param {Number}  options.keyExpirationTime     (optional) Number of seconds from the key creation time after which the key expires
 * @param {Date}    options.date                  Creation date of the key and the key signatures
 * @param {Object}  config                        Full configuration
 * @param {Array<Object>} options.subkeys         (optional) options for each subkey, default to main key options. e.g. [{sign: true, passphrase: '123'}]
 *                                                  sign parameter defaults to false, and indicates whether the subkey should sign rather than encrypt
 * @returns {Promise<Key>}
 * @async
 * @static
 * @private
 */
export async function generate(options, config) {
  options.sign = true; // primary key is always a signing key
  options = helper.sanitizeKeyOptions(options);
  options.subkeys = options.subkeys.map((subkey, index) => helper.sanitizeKeyOptions(options.subkeys[index], options));
  let promises = [helper.generateSecretKey(options, config)];
  promises = promises.concat(options.subkeys.map(options => helper.generateSecretSubkey(options, config)));
  return Promise.all(promises).then(packets => wrapKeyObject(packets[0], packets.slice(1), options, config));
}

/**
 * Reformats and signs an OpenPGP key with a given User ID. Currently only supports RSA keys.
 * @param {Key} options.privateKey     The private key to reformat
 * @param {Array<String|Object>} options.userIds  User IDs as strings or objects: 'Jo Doe <info@jo.com>' or { name:'Jo Doe', email:'info@jo.com' }
 * @param {String} options.passphrase             Passphrase used to encrypt the resulting private key
 * @param {Number} options.keyExpirationTime      Number of seconds from the key creation time after which the key expires
 * @param {Date}   options.date                   Override the creation date of the key and the key signatures
 * @param {Array<Object>} options.subkeys         (optional) options for each subkey, default to main key options. e.g. [{sign: true, passphrase: '123'}]
 * @param {Object} config                         Full configuration
 *
 * @returns {Promise<Key>}
 * @async
 * @static
 * @private
 */
export async function reformat(options, config) {
  options = sanitize(options);

  if (options.privateKey.primaryKey.isDummy()) {
    throw new Error('Cannot reformat a gnu-dummy primary key');
  }

  const isDecrypted = options.privateKey.getKeys().every(({ keyPacket }) => keyPacket.isDecrypted());
  if (!isDecrypted) {
    throw new Error('Key is not decrypted');
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
      sign: await options.privateKey.getSigningKey(secretSubkeyPacket.getKeyId(), null, undefined, config).catch(() => {}) &&
          !await options.privateKey.getEncryptionKey(secretSubkeyPacket.getKeyId(), null, undefined, config).catch(() => {})
    })));
  }

  if (options.subkeys.length !== secretSubkeyPackets.length) {
    throw new Error('Number of subkey options does not match number of subkeys');
  }

  options.subkeys = options.subkeys.map(function(subkey, index) { return sanitize(options.subkeys[index], options); });

  return wrapKeyObject(secretKeyPacket, secretSubkeyPackets, options, config);

  function sanitize(options, subkeyDefaults = {}) {
    options.keyExpirationTime = options.keyExpirationTime || subkeyDefaults.keyExpirationTime;
    options.passphrase = util.isString(options.passphrase) ? options.passphrase : subkeyDefaults.passphrase;
    options.date = options.date || subkeyDefaults.date;

    return options;
  }
}


async function wrapKeyObject(secretKeyPacket, secretSubkeyPackets, options, config) {
  // set passphrase protection
  if (options.passphrase) {
    await secretKeyPacket.encrypt(options.passphrase, config);
  }

  await Promise.all(secretSubkeyPackets.map(async function(secretSubkeyPacket, index) {
    const subkeyPassphrase = options.subkeys[index].passphrase;
    if (subkeyPassphrase) {
      await secretSubkeyPacket.encrypt(subkeyPassphrase, config);
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

    const userIdPacket = UserIDPacket.fromObject(userId);
    const dataToSign = {};
    dataToSign.userId = userIdPacket;
    dataToSign.key = secretKeyPacket;
    const signaturePacket = new SignaturePacket(options.date);
    signaturePacket.signatureType = enums.signature.certGeneric;
    signaturePacket.publicKeyAlgorithm = secretKeyPacket.algorithm;
    signaturePacket.hashAlgorithm = await helper.getPreferredHashAlgo(null, secretKeyPacket, undefined, undefined, config);
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
    const subkeySignaturePacket = await helper.createBindingSignature(secretSubkeyPacket, secretKeyPacket, subkeyOptions, config);
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
  }, options.date, undefined, undefined, undefined, config));

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
 * Reads an (optionally armored) OpenPGP key and returns a key object
 * @param {Object} options
 * @param {String | ReadableStream<String>} [options.armoredKey] - armored key to be parsed
 * @param {Uint8Array | ReadableStream<Uint8Array>} [options.binaryKey] - binary key to be parsed
 * @param {Object} [options.config] - custom configuration settings to overwrite those in [config]{@link module:config}
 * @returns {Promise<Key>} key object
 * @async
 * @static
 */
export async function readKey({ armoredKey, binaryKey, config }) {
  config = { ...defaultConfig, ...config };
  if (!armoredKey && !binaryKey) {
    throw new Error('readKey: must pass options object containing `armoredKey` or `binaryKey`');
  }
  let input;
  if (armoredKey) {
    const { type, data } = await unarmor(armoredKey, config);
    if (!(type === enums.armor.publicKey || type === enums.armor.privateKey)) {
      throw new Error('Armored text not of type key');
    }
    input = data;
  } else {
    input = binaryKey;
  }
  const packetlist = new PacketList();
  await packetlist.read(input, helper.allowedKeyPackets, undefined, config);
  return new Key(packetlist);
}

/**
 * Reads an (optionally armored) OpenPGP key block and returns a list of key objects
 * @param {Object} options
 * @param {String | ReadableStream<String>} [options.armoredKeys] - armored keys to be parsed
 * @param {Uint8Array | ReadableStream<Uint8Array>} [options.binaryKeys] - binary keys to be parsed
 * @param {Object} [options.config] - custom configuration settings to overwrite those in [config]{@link module:config}
 * @returns {Promise<Array<Key>>} key objects
 * @async
 * @static
 */
export async function readKeys({ armoredKeys, binaryKeys, config }) {
  config = { ...defaultConfig, ...config };
  let input = armoredKeys || binaryKeys;
  if (!input) {
    throw new Error('readKeys: must pass options object containing `armoredKeys` or `binaryKeys`');
  }
  if (armoredKeys) {
    const { type, data } = await unarmor(armoredKeys, config);
    if (type !== enums.armor.publicKey && type !== enums.armor.privateKey) {
      throw new Error('Armored text not of type key');
    }
    input = data;
  }
  const keys = [];
  const packetlist = new PacketList();
  await packetlist.read(input, helper.allowedKeyPackets, undefined, config);
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
