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

import {
  PacketList,
  UserIDPacket,
  SignaturePacket,
  PublicKeyPacket,
  PublicSubkeyPacket,
  SecretKeyPacket,
  SecretSubkeyPacket,
  UserAttributePacket
} from '../packet';
import PrivateKey from './private_key';
import PublicKey from './public_key';
import * as helper from './helper';
import enums from '../enums';
import util from '../util';
import defaultConfig from '../config';
import { unarmor } from '../encoding/armor';

// A Key can contain the following packets
const allowedKeyPackets = /*#__PURE__*/ util.constructAllowedPackets([
  PublicKeyPacket,
  PublicSubkeyPacket,
  SecretKeyPacket,
  SecretSubkeyPacket,
  UserIDPacket,
  UserAttributePacket,
  SignaturePacket
]);

/**
 * Creates a PublicKey or PrivateKey depending on the packetlist in input
 * @param {PacketList} - packets to parse
 * @return {Key} parsed key
 * @throws if no key packet was found
 */
function createKey(packetlist) {
  for (const packet of packetlist) {
    switch (packet.constructor.tag) {
      case enums.packet.secretKey:
        return new PrivateKey(packetlist);
      case enums.packet.publicKey:
        return new PublicKey(packetlist);
    }
  }
  throw new Error('No key packet found');
}


/**
 * Generates a new OpenPGP key. Supports RSA and ECC keys, as well as the newer Curve448 and Curve25519 keys.
 * By default, primary and subkeys will be of same type.
 * @param {ecc|rsa|curve448|curve25519} options.type                  The primary key algorithm type: ECC, RSA, Curve448 or Curve25519 (new format).
 * @param {String}  options.curve                 Elliptic curve for ECC keys
 * @param {Integer} options.rsaBits               Number of bits for RSA keys
 * @param {Array<String|Object>} options.userIDs  User IDs as strings or objects: 'Jo Doe <info@jo.com>' or { name:'Jo Doe', email:'info@jo.com' }
 * @param {String}  options.passphrase            Passphrase used to encrypt the resulting private key
 * @param {Number}  options.keyExpirationTime     (optional) Number of seconds from the key creation time after which the key expires
 * @param {Date}    options.date                  Creation date of the key and the key signatures
 * @param {Object} config - Full configuration
 * @param {Array<Object>} options.subkeys         (optional) options for each subkey, default to main key options. e.g. [{sign: true, passphrase: '123'}]
 *                                                  sign parameter defaults to false, and indicates whether the subkey should sign rather than encrypt
 * @returns {Promise<{{ key: PrivateKey, revocationCertificate: String }}>}
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
  const packets = await Promise.all(promises);

  const key = await wrapKeyObject(packets[0], packets.slice(1), options, config);
  const revocationCertificate = await key.getRevocationCertificate(options.date, config);
  key.revocationSignatures = [];
  return { key, revocationCertificate };
}

/**
 * Reformats and signs an OpenPGP key with a given User ID. Currently only supports RSA keys.
 * @param {PrivateKey} options.privateKey         The private key to reformat
 * @param {Array<String|Object>} options.userIDs  User IDs as strings or objects: 'Jo Doe <info@jo.com>' or { name:'Jo Doe', email:'info@jo.com' }
 * @param {String} options.passphrase             Passphrase used to encrypt the resulting private key
 * @param {Number} options.keyExpirationTime      Number of seconds from the key creation time after which the key expires
 * @param {Date}   options.date                   Override the creation date of the key signatures
 * @param {Array<Object>} options.subkeys         (optional) options for each subkey, default to main key options. e.g. [{sign: true, passphrase: '123'}]
 * @param {Object} config - Full configuration
 *
 * @returns {Promise<{{ key: PrivateKey, revocationCertificate: String }}>}
 * @async
 * @static
 * @private
 */
export async function reformat(options, config) {
  options = sanitize(options);
  const { privateKey } = options;

  if (!privateKey.isPrivate()) {
    throw new Error('Cannot reformat a public key');
  }

  if (privateKey.keyPacket.isDummy()) {
    throw new Error('Cannot reformat a gnu-dummy primary key');
  }

  const isDecrypted = privateKey.getKeys().every(({ keyPacket }) => keyPacket.isDecrypted());
  if (!isDecrypted) {
    throw new Error('Key is not decrypted');
  }

  const secretKeyPacket = privateKey.keyPacket;

  if (!options.subkeys) {
    options.subkeys = await Promise.all(privateKey.subkeys.map(async subkey => {
      const secretSubkeyPacket = subkey.keyPacket;
      const dataToVerify = { key: secretKeyPacket, bind: secretSubkeyPacket };
      const bindingSignature = await (
        helper.getLatestValidSignature(subkey.bindingSignatures, secretKeyPacket, enums.signature.subkeyBinding, dataToVerify, null, config)
      ).catch(() => ({}));
      return {
        sign: bindingSignature.keyFlags && (bindingSignature.keyFlags[0] & enums.keyFlags.signData)
      };
    }));
  }

  const secretSubkeyPackets = privateKey.subkeys.map(subkey => subkey.keyPacket);
  if (options.subkeys.length !== secretSubkeyPackets.length) {
    throw new Error('Number of subkey options does not match number of subkeys');
  }

  options.subkeys = options.subkeys.map(subkeyOptions => sanitize(subkeyOptions, options));

  const key = await wrapKeyObject(secretKeyPacket, secretSubkeyPackets, options, config);
  const revocationCertificate = await key.getRevocationCertificate(options.date, config);
  key.revocationSignatures = [];
  return { key, revocationCertificate };

  function sanitize(options, subkeyDefaults = {}) {
    options.keyExpirationTime = options.keyExpirationTime || subkeyDefaults.keyExpirationTime;
    options.passphrase = util.isString(options.passphrase) ? options.passphrase : subkeyDefaults.passphrase;
    options.date = options.date || subkeyDefaults.date;

    return options;
  }
}

/**
 * Construct PrivateKey object from the given key packets, add certification signatures and set passphrase protection
 * The new key includes a revocation certificate that must be removed before returning the key, otherwise the key is considered revoked.
 * @param {SecretKeyPacket} secretKeyPacket
 * @param {SecretSubkeyPacket} secretSubkeyPackets
 * @param {Object} options
 * @param {Object} config - Full configuration
 * @returns {PrivateKey}
 */
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

  function createPreferredAlgos(algos, preferredAlgo) {
    return [preferredAlgo, ...algos.filter(algo => algo !== preferredAlgo)];
  }

  function getKeySignatureProperties() {
    const signatureProperties = {};
    signatureProperties.keyFlags = [enums.keyFlags.certifyKeys | enums.keyFlags.signData];
    const symmetricAlgorithms = createPreferredAlgos([
      // prefer aes256, aes128, no aes192 (no Web Crypto support in Chrome: https://www.chromium.org/blink/webcrypto#TOC-AES-support)
      enums.symmetric.aes256,
      enums.symmetric.aes128
    ], config.preferredSymmetricAlgorithm);
    signatureProperties.preferredSymmetricAlgorithms = symmetricAlgorithms;
    if (config.aeadProtect) {
      const aeadAlgorithms = createPreferredAlgos([
        enums.aead.gcm,
        enums.aead.eax,
        enums.aead.ocb
      ], config.preferredAEADAlgorithm);
      signatureProperties.preferredCipherSuites = aeadAlgorithms.flatMap(aeadAlgorithm => {
        return symmetricAlgorithms.map(symmetricAlgorithm => {
          return [symmetricAlgorithm, aeadAlgorithm];
        });
      });
    }
    signatureProperties.preferredHashAlgorithms = createPreferredAlgos([
      enums.hash.sha512,
      enums.hash.sha256,
      enums.hash.sha3_512,
      enums.hash.sha3_256
    ], config.preferredHashAlgorithm);
    signatureProperties.preferredCompressionAlgorithms = createPreferredAlgos([
      enums.compression.uncompressed,
      enums.compression.zlib,
      enums.compression.zip
    ], config.preferredCompressionAlgorithm);
    // integrity protection always enabled
    signatureProperties.features = [0];
    signatureProperties.features[0] |= enums.features.modificationDetection;
    if (config.aeadProtect) {
      signatureProperties.features[0] |= enums.features.seipdv2;
    }
    if (options.keyExpirationTime > 0) {
      signatureProperties.keyExpirationTime = options.keyExpirationTime;
      signatureProperties.keyNeverExpires = false;
    }
    return signatureProperties;
  }

  if (secretKeyPacket.version === 6) { // add direct key signature with key prefs
    const dataToSign = {
      key: secretKeyPacket
    };

    const signatureProperties = getKeySignatureProperties();
    signatureProperties.signatureType = enums.signature.key;

    const signaturePacket = await helper.createSignaturePacket(dataToSign, [], secretKeyPacket, signatureProperties, options.date, undefined, undefined, undefined, config);
    packetlist.push(signaturePacket);
  }

  await Promise.all(options.userIDs.map(async function(userID, index) {
    const userIDPacket = UserIDPacket.fromObject(userID);
    const dataToSign = {
      userID: userIDPacket,
      key: secretKeyPacket
    };
    const signatureProperties = secretKeyPacket.version !== 6 ? getKeySignatureProperties() : {};
    signatureProperties.signatureType = enums.signature.certPositive;
    if (index === 0) {
      signatureProperties.isPrimaryUserID = true;
    }

    const signaturePacket = await helper.createSignaturePacket(dataToSign, [], secretKeyPacket, signatureProperties, options.date, undefined, undefined, undefined, config);

    return { userIDPacket, signaturePacket };
  })).then(list => {
    list.forEach(({ userIDPacket, signaturePacket }) => {
      packetlist.push(userIDPacket);
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
  packetlist.push(await helper.createSignaturePacket(dataToSign, [], secretKeyPacket, {
    signatureType: enums.signature.keyRevocation,
    reasonForRevocationFlag: enums.reasonForRevocation.noReason,
    reasonForRevocationString: ''
  }, options.date, undefined, undefined, undefined, config));

  if (options.passphrase) {
    secretKeyPacket.clearPrivateParams();
  }

  await Promise.all(secretSubkeyPackets.map(async function(secretSubkeyPacket, index) {
    const subkeyPassphrase = options.subkeys[index].passphrase;
    if (subkeyPassphrase) {
      secretSubkeyPacket.clearPrivateParams();
    }
  }));

  return new PrivateKey(packetlist);
}

/**
 * Reads an (optionally armored) OpenPGP key and returns a key object
 * @param {Object} options
 * @param {String} [options.armoredKey] - Armored key to be parsed
 * @param {Uint8Array} [options.binaryKey] - Binary key to be parsed
 * @param {Object} [options.config] - Custom configuration settings to overwrite those in [config]{@link module:config}
 * @returns {Promise<Key>} Key object.
 * @async
 * @static
 */
export async function readKey({ armoredKey, binaryKey, config, ...rest }) {
  config = { ...defaultConfig, ...config };
  if (!armoredKey && !binaryKey) {
    throw new Error('readKey: must pass options object containing `armoredKey` or `binaryKey`');
  }
  if (armoredKey && !util.isString(armoredKey)) {
    throw new Error('readKey: options.armoredKey must be a string');
  }
  if (binaryKey && !util.isUint8Array(binaryKey)) {
    throw new Error('readKey: options.binaryKey must be a Uint8Array');
  }
  const unknownOptions = Object.keys(rest); if (unknownOptions.length > 0) throw new Error(`Unknown option: ${unknownOptions.join(', ')}`);

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
  const packetlist = await PacketList.fromBinary(input, allowedKeyPackets, config);
  const keyIndex = packetlist.indexOfTag(enums.packet.publicKey, enums.packet.secretKey);
  if (keyIndex.length === 0) {
    throw new Error('No key packet found');
  }
  const firstKeyPacketList = packetlist.slice(keyIndex[0], keyIndex[1]);
  return createKey(firstKeyPacketList);
}

/**
 * Reads an (optionally armored) OpenPGP private key and returns a PrivateKey object
 * @param {Object} options
 * @param {String} [options.armoredKey] - Armored key to be parsed
 * @param {Uint8Array} [options.binaryKey] - Binary key to be parsed
 * @param {Object} [options.config] - Custom configuration settings to overwrite those in [config]{@link module:config}
 * @returns {Promise<PrivateKey>} Key object.
 * @async
 * @static
 */
export async function readPrivateKey({ armoredKey, binaryKey, config, ...rest }) {
  config = { ...defaultConfig, ...config };
  if (!armoredKey && !binaryKey) {
    throw new Error('readPrivateKey: must pass options object containing `armoredKey` or `binaryKey`');
  }
  if (armoredKey && !util.isString(armoredKey)) {
    throw new Error('readPrivateKey: options.armoredKey must be a string');
  }
  if (binaryKey && !util.isUint8Array(binaryKey)) {
    throw new Error('readPrivateKey: options.binaryKey must be a Uint8Array');
  }
  const unknownOptions = Object.keys(rest); if (unknownOptions.length > 0) throw new Error(`Unknown option: ${unknownOptions.join(', ')}`);

  let input;
  if (armoredKey) {
    const { type, data } = await unarmor(armoredKey, config);
    if (!(type === enums.armor.privateKey)) {
      throw new Error('Armored text not of type private key');
    }
    input = data;
  } else {
    input = binaryKey;
  }
  const packetlist = await PacketList.fromBinary(input, allowedKeyPackets, config);
  const keyIndex = packetlist.indexOfTag(enums.packet.publicKey, enums.packet.secretKey);
  for (let i = 0; i < keyIndex.length; i++) {
    if (packetlist[keyIndex[i]].constructor.tag === enums.packet.publicKey) {
      continue;
    }
    const firstPrivateKeyList = packetlist.slice(keyIndex[i], keyIndex[i + 1]);
    return new PrivateKey(firstPrivateKeyList);
  }
  throw new Error('No secret key packet found');
}

/**
 * Reads an (optionally armored) OpenPGP key block and returns a list of key objects
 * @param {Object} options
 * @param {String} [options.armoredKeys] - Armored keys to be parsed
 * @param {Uint8Array} [options.binaryKeys] - Binary keys to be parsed
 * @param {Object} [options.config] - Custom configuration settings to overwrite those in [config]{@link module:config}
 * @returns {Promise<Array<Key>>} Key objects.
 * @async
 * @static
 */
export async function readKeys({ armoredKeys, binaryKeys, config, ...rest }) {
  config = { ...defaultConfig, ...config };
  let input = armoredKeys || binaryKeys;
  if (!input) {
    throw new Error('readKeys: must pass options object containing `armoredKeys` or `binaryKeys`');
  }
  if (armoredKeys && !util.isString(armoredKeys)) {
    throw new Error('readKeys: options.armoredKeys must be a string');
  }
  if (binaryKeys && !util.isUint8Array(binaryKeys)) {
    throw new Error('readKeys: options.binaryKeys must be a Uint8Array');
  }
  const unknownOptions = Object.keys(rest); if (unknownOptions.length > 0) throw new Error(`Unknown option: ${unknownOptions.join(', ')}`);

  if (armoredKeys) {
    const { type, data } = await unarmor(armoredKeys, config);
    if (type !== enums.armor.publicKey && type !== enums.armor.privateKey) {
      throw new Error('Armored text not of type key');
    }
    input = data;
  }
  const keys = [];
  const packetlist = await PacketList.fromBinary(input, allowedKeyPackets, config);
  const keyIndex = packetlist.indexOfTag(enums.packet.publicKey, enums.packet.secretKey);
  if (keyIndex.length === 0) {
    throw new Error('No key packet found');
  }
  for (let i = 0; i < keyIndex.length; i++) {
    const oneKeyList = packetlist.slice(keyIndex[i], keyIndex[i + 1]);
    const newKey = createKey(oneKeyList);
    keys.push(newKey);
  }
  return keys;
}

/**
 * Reads an (optionally armored) OpenPGP private key block and returns a list of PrivateKey objects
 * @param {Object} options
 * @param {String} [options.armoredKeys] - Armored keys to be parsed
 * @param {Uint8Array} [options.binaryKeys] - Binary keys to be parsed
 * @param {Object} [options.config] - Custom configuration settings to overwrite those in [config]{@link module:config}
 * @returns {Promise<Array<PrivateKey>>} Key objects.
 * @async
 * @static
 */
export async function readPrivateKeys({ armoredKeys, binaryKeys, config }) {
  config = { ...defaultConfig, ...config };
  let input = armoredKeys || binaryKeys;
  if (!input) {
    throw new Error('readPrivateKeys: must pass options object containing `armoredKeys` or `binaryKeys`');
  }
  if (armoredKeys && !util.isString(armoredKeys)) {
    throw new Error('readPrivateKeys: options.armoredKeys must be a string');
  }
  if (binaryKeys && !util.isUint8Array(binaryKeys)) {
    throw new Error('readPrivateKeys: options.binaryKeys must be a Uint8Array');
  }
  if (armoredKeys) {
    const { type, data } = await unarmor(armoredKeys, config);
    if (type !== enums.armor.privateKey) {
      throw new Error('Armored text not of type private key');
    }
    input = data;
  }
  const keys = [];
  const packetlist = await PacketList.fromBinary(input, allowedKeyPackets, config);
  const keyIndex = packetlist.indexOfTag(enums.packet.publicKey, enums.packet.secretKey);
  for (let i = 0; i < keyIndex.length; i++) {
    if (packetlist[keyIndex[i]].constructor.tag === enums.packet.publicKey) {
      continue;
    }
    const oneKeyList = packetlist.slice(keyIndex[i], keyIndex[i + 1]);
    const newKey = new PrivateKey(oneKeyList);
    keys.push(newKey);
  }
  if (keys.length === 0) {
    throw new Error('No secret key packet found');
  }
  return keys;
}
