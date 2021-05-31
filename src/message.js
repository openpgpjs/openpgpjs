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

import * as stream from '@openpgp/web-stream-tools';
import { armor, unarmor } from './encoding/armor';
import KeyID from './type/keyid';
import defaultConfig from './config';
import crypto from './crypto';
import enums from './enums';
import util from './util';
import { Signature } from './signature';
import { getPreferredHashAlgo, getPreferredAlgo, isAEADSupported, createSignaturePacket } from './key';
import {
  PacketList,
  LiteralDataPacket,
  CompressedDataPacket,
  AEADEncryptedDataPacket,
  SymEncryptedIntegrityProtectedDataPacket,
  SymmetricallyEncryptedDataPacket,
  PublicKeyEncryptedSessionKeyPacket,
  SymEncryptedSessionKeyPacket,
  OnePassSignaturePacket,
  SignaturePacket
} from './packet';

// A Message can contain the following packets
const allowedMessagePackets = /*#__PURE__*/ util.constructAllowedPackets([
  LiteralDataPacket,
  CompressedDataPacket,
  AEADEncryptedDataPacket,
  SymEncryptedIntegrityProtectedDataPacket,
  SymmetricallyEncryptedDataPacket,
  PublicKeyEncryptedSessionKeyPacket,
  SymEncryptedSessionKeyPacket,
  OnePassSignaturePacket,
  SignaturePacket
]);
// A SKESK packet can contain the following packets
const allowedSymSessionKeyPackets = /*#__PURE__*/ util.constructAllowedPackets([SymEncryptedSessionKeyPacket]);
// A detached signature can contain the following packets
const allowedDetachedSignaturePackets = /*#__PURE__*/ util.constructAllowedPackets([SignaturePacket]);

/**
 * Class that represents an OpenPGP message.
 * Can be an encrypted message, signed message, compressed message or literal message
 * See {@link https://tools.ietf.org/html/rfc4880#section-11.3}
 */
export class Message {
  /**
   * @param {PacketList} packetlist - The packets that form this message
   */
  constructor(packetlist) {
    this.packets = packetlist || new PacketList();
  }

  /**
   * Returns the key IDs of the keys to which the session key is encrypted
   * @returns {Array<module:type/keyid~KeyID>} Array of keyID objects.
   */
  getEncryptionKeyIDs() {
    const keyIDs = [];
    const pkESKeyPacketlist = this.packets.filterByTag(enums.packet.publicKeyEncryptedSessionKey);
    pkESKeyPacketlist.forEach(function(packet) {
      keyIDs.push(packet.publicKeyID);
    });
    return keyIDs;
  }

  /**
   * Returns the key IDs of the keys that signed the message
   * @returns {Array<module:type/keyid~KeyID>} Array of keyID objects.
   */
  getSigningKeyIDs() {
    const keyIDs = [];
    const msg = this.unwrapCompressed();
    // search for one pass signatures
    const onePassSigList = msg.packets.filterByTag(enums.packet.onePassSignature);
    onePassSigList.forEach(function(packet) {
      keyIDs.push(packet.issuerKeyID);
    });
    // if nothing found look for signature packets
    if (!keyIDs.length) {
      const signatureList = msg.packets.filterByTag(enums.packet.signature);
      signatureList.forEach(function(packet) {
        keyIDs.push(packet.issuerKeyID);
      });
    }
    return keyIDs;
  }

  /**
   * Decrypt the message. Either a private key, a session key, or a password must be specified.
   * @param {Array<PrivateKey>} [decryptionKeys] - Private keys with decrypted secret data
   * @param {Array<String>} [passwords] - Passwords used to decrypt
   * @param {Array<Object>} [sessionKeys] - Session keys in the form: { data:Uint8Array, algorithm:String, [aeadAlgorithm:String] }
   * @param {Date} [date] - Use the given date for key verification instead of the current time
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Message>} New message with decrypted content.
   * @async
   */
  async decrypt(decryptionKeys, passwords, sessionKeys, date = new Date(), config = defaultConfig) {
    const keyObjs = sessionKeys || await this.decryptSessionKeys(decryptionKeys, passwords, date, config);

    const symEncryptedPacketlist = this.packets.filterByTag(
      enums.packet.symmetricallyEncryptedData,
      enums.packet.symEncryptedIntegrityProtectedData,
      enums.packet.aeadEncryptedData
    );

    if (symEncryptedPacketlist.length === 0) {
      return this;
    }

    const symEncryptedPacket = symEncryptedPacketlist[0];
    let exception = null;
    const decryptedPromise = Promise.all(keyObjs.map(async keyObj => {
      if (!keyObj || !util.isUint8Array(keyObj.data) || !util.isString(keyObj.algorithm)) {
        throw new Error('Invalid session key for decryption.');
      }

      try {
        await symEncryptedPacket.decrypt(keyObj.algorithm, keyObj.data, config);
      } catch (e) {
        util.printDebugError(e);
        exception = e;
      }
    }));
    // We don't await stream.cancel here because it only returns when the other copy is canceled too.
    stream.cancel(symEncryptedPacket.encrypted); // Don't keep copy of encrypted data in memory.
    symEncryptedPacket.encrypted = null;
    await decryptedPromise;

    if (!symEncryptedPacket.packets || !symEncryptedPacket.packets.length) {
      throw exception || new Error('Decryption failed.');
    }

    const resultMsg = new Message(symEncryptedPacket.packets);
    symEncryptedPacket.packets = new PacketList(); // remove packets after decryption

    return resultMsg;
  }

  /**
   * Decrypt encrypted session keys either with private keys or passwords.
   * @param {Array<PrivateKey>} [decryptionKeys] - Private keys with decrypted secret data
   * @param {Array<String>} [passwords] - Passwords used to decrypt
   * @param {Date} [date] - Use the given date for key verification, instead of current time
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Array<{
   *   data: Uint8Array,
   *   algorithm: String
   * }>>} array of object with potential sessionKey, algorithm pairs
   * @async
   */
  async decryptSessionKeys(decryptionKeys, passwords, date = new Date(), config = defaultConfig) {
    let keyPackets = [];

    let exception;
    if (passwords) {
      const symESKeyPacketlist = this.packets.filterByTag(enums.packet.symEncryptedSessionKey);
      if (symESKeyPacketlist.length === 0) {
        throw new Error('No symmetrically encrypted session key packet found.');
      }
      await Promise.all(passwords.map(async function(password, i) {
        let packets;
        if (i) {
          packets = await PacketList.fromBinary(symESKeyPacketlist.write(), allowedSymSessionKeyPackets, config);
        } else {
          packets = symESKeyPacketlist;
        }
        await Promise.all(packets.map(async function(keyPacket) {
          try {
            await keyPacket.decrypt(password);
            keyPackets.push(keyPacket);
          } catch (err) {
            util.printDebugError(err);
          }
        }));
      }));
    } else if (decryptionKeys) {
      const pkESKeyPacketlist = this.packets.filterByTag(enums.packet.publicKeyEncryptedSessionKey);
      if (pkESKeyPacketlist.length === 0) {
        throw new Error('No public key encrypted session key packet found.');
      }
      await Promise.all(pkESKeyPacketlist.map(async function(keyPacket) {
        await Promise.all(decryptionKeys.map(async function(decryptionKey) {
          let algos = [
            enums.symmetric.aes256, // Old OpenPGP.js default fallback
            enums.symmetric.aes128, // RFC4880bis fallback
            enums.symmetric.tripledes, // RFC4880 fallback
            enums.symmetric.cast5 // Golang OpenPGP fallback
          ];
          try {
            const primaryUser = await decryptionKey.getPrimaryUser(date, undefined, config); // TODO: Pass userID from somewhere.
            if (primaryUser.selfCertification.preferredSymmetricAlgorithms) {
              algos = algos.concat(primaryUser.selfCertification.preferredSymmetricAlgorithms);
            }
          } catch (e) {}

          // do not check key expiration to allow decryption of old messages
          const decryptionKeyPackets = (await decryptionKey.getDecryptionKeys(keyPacket.publicKeyID, null, undefined, config)).map(key => key.keyPacket);
          await Promise.all(decryptionKeyPackets.map(async function(decryptionKeyPacket) {
            if (!decryptionKeyPacket || decryptionKeyPacket.isDummy()) {
              return;
            }
            if (!decryptionKeyPacket.isDecrypted()) {
              throw new Error('Decryption key is not decrypted.');
            }
            try {
              await keyPacket.decrypt(decryptionKeyPacket);
              if (!algos.includes(enums.write(enums.symmetric, keyPacket.sessionKeyAlgorithm))) {
                throw new Error('A non-preferred symmetric algorithm was used.');
              }
              keyPackets.push(keyPacket);
            } catch (err) {
              util.printDebugError(err);
              exception = err;
            }
          }));
        }));
        stream.cancel(keyPacket.encrypted); // Don't keep copy of encrypted data in memory.
        keyPacket.encrypted = null;
      }));
    } else {
      throw new Error('No key or password specified.');
    }

    if (keyPackets.length) {
      // Return only unique session keys
      if (keyPackets.length > 1) {
        const seen = new Set();
        keyPackets = keyPackets.filter(item => {
          const k = item.sessionKeyAlgorithm + util.uint8ArrayToString(item.sessionKey);
          if (seen.has(k)) {
            return false;
          }
          seen.add(k);
          return true;
        });
      }

      return keyPackets.map(packet => ({ data: packet.sessionKey, algorithm: packet.sessionKeyAlgorithm }));
    }
    throw exception || new Error('Session key decryption failed.');
  }

  /**
   * Get literal data that is the body of the message
   * @returns {(Uint8Array|null)} Literal body of the message as Uint8Array.
   */
  getLiteralData() {
    const msg = this.unwrapCompressed();
    const literal = msg.packets.findPacket(enums.packet.literalData);
    return (literal && literal.getBytes()) || null;
  }

  /**
   * Get filename from literal data packet
   * @returns {(String|null)} Filename of literal data packet as string.
   */
  getFilename() {
    const msg = this.unwrapCompressed();
    const literal = msg.packets.findPacket(enums.packet.literalData);
    return (literal && literal.getFilename()) || null;
  }

  /**
   * Get literal data as text
   * @returns {(String|null)} Literal body of the message interpreted as text.
   */
  getText() {
    const msg = this.unwrapCompressed();
    const literal = msg.packets.findPacket(enums.packet.literalData);
    if (literal) {
      return literal.getText();
    }
    return null;
  }

  /**
   * Generate a new session key object, taking the algorithm preferences of the passed encryption keys into account, if any.
   * @param {Array<PublicKey>} [encryptionKeys] - Public key(s) to select algorithm preferences for
   * @param {Date} [date] - Date to select algorithm preferences at
   * @param {Array<Object>} [userIDs] - User IDs to select algorithm preferences for
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<{ data: Uint8Array, algorithm: String }>} Object with session key data and algorithm.
   * @async
   */
  static async generateSessionKey(encryptionKeys = [], date = new Date(), userIDs = [], config = defaultConfig) {
    const algorithm = enums.read(enums.symmetric, await getPreferredAlgo('symmetric', encryptionKeys, date, userIDs, config));
    const aeadAlgorithm = config.aeadProtect && await isAEADSupported(encryptionKeys, date, userIDs, config) ?
      enums.read(enums.aead, await getPreferredAlgo('aead', encryptionKeys, date, userIDs, config)) :
      undefined;

    const sessionKeyData = await crypto.generateSessionKey(algorithm);
    return { data: sessionKeyData, algorithm, aeadAlgorithm };
  }

  /**
   * Encrypt the message either with public keys, passwords, or both at once.
   * @param {Array<PublicKey>} [encryptionKeys] - Public key(s) for message encryption
   * @param {Array<String>} [passwords] - Password(s) for message encryption
   * @param {Object} [sessionKey] - Session key in the form: { data:Uint8Array, algorithm:String, [aeadAlgorithm:String] }
   * @param {Boolean} [wildcard] - Use a key ID of 0 instead of the public key IDs
   * @param {Array<module:type/keyid~KeyID>} [encryptionKeyIDs] - Array of key IDs to use for encryption. Each encryptionKeyIDs[i] corresponds to keys[i]
   * @param {Date} [date] - Override the creation date of the literal package
   * @param {Array<Object>} [userIDs] - User IDs to encrypt for, e.g. [{ name:'Robert Receiver', email:'robert@openpgp.org' }]
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Message>} New message with encrypted content.
   * @async
   */
  async encrypt(encryptionKeys, passwords, sessionKey, wildcard = false, encryptionKeyIDs = [], date = new Date(), userIDs = [], config = defaultConfig) {
    if (sessionKey) {
      if (!util.isUint8Array(sessionKey.data) || !util.isString(sessionKey.algorithm)) {
        throw new Error('Invalid session key for encryption.');
      }
    } else if (encryptionKeys && encryptionKeys.length) {
      sessionKey = await Message.generateSessionKey(encryptionKeys, date, userIDs, config);
    } else if (passwords && passwords.length) {
      sessionKey = await Message.generateSessionKey(undefined, undefined, undefined, config);
    } else {
      throw new Error('No keys, passwords, or session key provided.');
    }

    const { data: sessionKeyData, algorithm, aeadAlgorithm } = sessionKey;

    const msg = await Message.encryptSessionKey(sessionKeyData, algorithm, aeadAlgorithm, encryptionKeys, passwords, wildcard, encryptionKeyIDs, date, userIDs, config);

    let symEncryptedPacket;
    if (aeadAlgorithm) {
      symEncryptedPacket = new AEADEncryptedDataPacket();
      symEncryptedPacket.aeadAlgorithm = aeadAlgorithm;
    } else {
      symEncryptedPacket = new SymEncryptedIntegrityProtectedDataPacket();
    }
    symEncryptedPacket.packets = this.packets;

    await symEncryptedPacket.encrypt(algorithm, sessionKeyData, config);

    msg.packets.push(symEncryptedPacket);
    symEncryptedPacket.packets = new PacketList(); // remove packets after encryption
    return msg;
  }

  /**
   * Encrypt a session key either with public keys, passwords, or both at once.
   * @param {Uint8Array} sessionKey - session key for encryption
   * @param {String} algorithm - session key algorithm
   * @param {String} [aeadAlgorithm] - AEAD algorithm, e.g. 'eax' or 'ocb'
   * @param {Array<PublicKey>} [encryptionKeys] - Public key(s) for message encryption
   * @param {Array<String>} [passwords] - For message encryption
   * @param {Boolean} [wildcard] - Use a key ID of 0 instead of the public key IDs
   * @param {Array<module:type/keyid~KeyID>} [encryptionKeyIDs] - Array of key IDs to use for encryption. Each encryptionKeyIDs[i] corresponds to encryptionKeys[i]
   * @param {Date} [date] - Override the date
   * @param {Array} [userIDs] - User IDs to encrypt for, e.g. [{ name:'Robert Receiver', email:'robert@openpgp.org' }]
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Message>} New message with encrypted content.
   * @async
   */
  static async encryptSessionKey(sessionKey, algorithm, aeadAlgorithm, encryptionKeys, passwords, wildcard = false, encryptionKeyIDs = [], date = new Date(), userIDs = [], config = defaultConfig) {
    const packetlist = new PacketList();

    if (encryptionKeys) {
      const results = await Promise.all(encryptionKeys.map(async function(primaryKey, i) {
        const encryptionKey = await primaryKey.getEncryptionKey(encryptionKeyIDs[i], date, userIDs, config);
        const pkESKeyPacket = new PublicKeyEncryptedSessionKeyPacket();
        pkESKeyPacket.publicKeyID = wildcard ? KeyID.wildcard() : encryptionKey.getKeyID();
        pkESKeyPacket.publicKeyAlgorithm = encryptionKey.keyPacket.algorithm;
        pkESKeyPacket.sessionKey = sessionKey;
        pkESKeyPacket.sessionKeyAlgorithm = algorithm;
        await pkESKeyPacket.encrypt(encryptionKey.keyPacket);
        delete pkESKeyPacket.sessionKey; // delete plaintext session key after encryption
        return pkESKeyPacket;
      }));
      packetlist.push(...results);
    }
    if (passwords) {
      const testDecrypt = async function(keyPacket, password) {
        try {
          await keyPacket.decrypt(password);
          return 1;
        } catch (e) {
          return 0;
        }
      };

      const sum = (accumulator, currentValue) => accumulator + currentValue;

      const encryptPassword = async function(sessionKey, algorithm, aeadAlgorithm, password) {
        const symEncryptedSessionKeyPacket = new SymEncryptedSessionKeyPacket(config);
        symEncryptedSessionKeyPacket.sessionKey = sessionKey;
        symEncryptedSessionKeyPacket.sessionKeyAlgorithm = algorithm;
        if (aeadAlgorithm) {
          symEncryptedSessionKeyPacket.aeadAlgorithm = aeadAlgorithm;
        }
        await symEncryptedSessionKeyPacket.encrypt(password, config);

        if (config.passwordCollisionCheck) {
          const results = await Promise.all(passwords.map(pwd => testDecrypt(symEncryptedSessionKeyPacket, pwd)));
          if (results.reduce(sum) !== 1) {
            return encryptPassword(sessionKey, algorithm, password);
          }
        }

        delete symEncryptedSessionKeyPacket.sessionKey; // delete plaintext session key after encryption
        return symEncryptedSessionKeyPacket;
      };

      const results = await Promise.all(passwords.map(pwd => encryptPassword(sessionKey, algorithm, aeadAlgorithm, pwd)));
      packetlist.push(...results);
    }

    return new Message(packetlist);
  }

  /**
   * Sign the message (the literal data packet of the message)
   * @param {Array<PrivateKey>} signingKeys - private keys with decrypted secret key data for signing
   * @param {Signature} [signature] - Any existing detached signature to add to the message
   * @param {Array<module:type/keyid~KeyID>} [signingKeyIDs] - Array of key IDs to use for signing. Each signingKeyIDs[i] corresponds to signingKeys[i]
   * @param {Date} [date] - Override the creation time of the signature
   * @param {Array} [userIDs] - User IDs to sign with, e.g. [{ name:'Steve Sender', email:'steve@openpgp.org' }]
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Message>} New message with signed content.
   * @async
   */
  async sign(signingKeys = [], signature = null, signingKeyIDs = [], date = new Date(), userIDs = [], config = defaultConfig) {
    const packetlist = new PacketList();

    const literalDataPacket = this.packets.findPacket(enums.packet.literalData);
    if (!literalDataPacket) {
      throw new Error('No literal data packet to sign.');
    }

    let i;
    let existingSigPacketlist;
    // If data packet was created from Uint8Array, use binary, otherwise use text
    const signatureType = literalDataPacket.text === null ?
      enums.signature.binary : enums.signature.text;

    if (signature) {
      existingSigPacketlist = signature.packets.filterByTag(enums.packet.signature);
      for (i = existingSigPacketlist.length - 1; i >= 0; i--) {
        const signaturePacket = existingSigPacketlist[i];
        const onePassSig = new OnePassSignaturePacket();
        onePassSig.signatureType = signaturePacket.signatureType;
        onePassSig.hashAlgorithm = signaturePacket.hashAlgorithm;
        onePassSig.publicKeyAlgorithm = signaturePacket.publicKeyAlgorithm;
        onePassSig.issuerKeyID = signaturePacket.issuerKeyID;
        if (!signingKeys.length && i === 0) {
          onePassSig.flags = 1;
        }
        packetlist.push(onePassSig);
      }
    }

    await Promise.all(Array.from(signingKeys).reverse().map(async function (primaryKey, i) {
      if (primaryKey.isPublic()) {
        throw new Error('Need private key for signing');
      }
      const signingKeyID = signingKeyIDs[signingKeys.length - 1 - i];
      const signingKey = await primaryKey.getSigningKey(signingKeyID, date, userIDs, config);
      const onePassSig = new OnePassSignaturePacket();
      onePassSig.signatureType = signatureType;
      onePassSig.hashAlgorithm = await getPreferredHashAlgo(primaryKey, signingKey.keyPacket, date, userIDs, config);
      onePassSig.publicKeyAlgorithm = signingKey.keyPacket.algorithm;
      onePassSig.issuerKeyID = signingKey.getKeyID();
      if (i === signingKeys.length - 1) {
        onePassSig.flags = 1;
      }
      return onePassSig;
    })).then(onePassSignatureList => {
      onePassSignatureList.forEach(onePassSig => packetlist.push(onePassSig));
    });

    packetlist.push(literalDataPacket);
    packetlist.push(...(await createSignaturePackets(literalDataPacket, signingKeys, signature, signingKeyIDs, date, userIDs, false, config)));

    return new Message(packetlist);
  }

  /**
   * Compresses the message (the literal and -if signed- signature data packets of the message)
   * @param {module:enums.compression} algo - compression algorithm
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Message} New message with compressed content.
   */
  compress(algo, config = defaultConfig) {
    if (algo === enums.compression.uncompressed) {
      return this;
    }

    const compressed = new CompressedDataPacket(config);
    compressed.algorithm = enums.read(enums.compression, algo);
    compressed.packets = this.packets;

    const packetList = new PacketList();
    packetList.push(compressed);

    return new Message(packetList);
  }

  /**
   * Create a detached signature for the message (the literal data packet of the message)
   * @param {Array<PrivateKey>} signingKeys - private keys with decrypted secret key data for signing
   * @param {Signature} [signature] - Any existing detached signature
   * @param {Array<module:type/keyid~KeyID>} [signingKeyIDs] - Array of key IDs to use for signing. Each signingKeyIDs[i] corresponds to signingKeys[i]
   * @param {Date} [date] - Override the creation time of the signature
   * @param {Array} [userIDs] - User IDs to sign with, e.g. [{ name:'Steve Sender', email:'steve@openpgp.org' }]
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Signature>} New detached signature of message content.
   * @async
   */
  async signDetached(signingKeys = [], signature = null, signingKeyIDs = [], date = new Date(), userIDs = [], config = defaultConfig) {
    const literalDataPacket = this.packets.findPacket(enums.packet.literalData);
    if (!literalDataPacket) {
      throw new Error('No literal data packet to sign.');
    }
    return new Signature(await createSignaturePackets(literalDataPacket, signingKeys, signature, signingKeyIDs, date, userIDs, true, config));
  }

  /**
   * Verify message signatures
   * @param {Array<PublicKey>} verificationKeys - Array of public keys to verify signatures
   * @param {Date} [date] - Verify the signature against the given date, i.e. check signature creation time < date < expiration time
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Array<{
   *   keyID: module:type/keyid~KeyID,
   *   signature: Promise<Signature>,
   *   verified: Promise<Boolean>
   * }>>} List of signer's keyID and validity of signatures.
   * @async
   */
  async verify(verificationKeys, date = new Date(), config = defaultConfig) {
    const msg = this.unwrapCompressed();
    const literalDataList = msg.packets.filterByTag(enums.packet.literalData);
    if (literalDataList.length !== 1) {
      throw new Error('Can only verify message with one literal data packet.');
    }
    if (stream.isArrayStream(msg.packets.stream)) {
      msg.packets.push(...await stream.readToEnd(msg.packets.stream, _ => _ || []));
    }
    const onePassSigList = msg.packets.filterByTag(enums.packet.onePassSignature).reverse();
    const signatureList = msg.packets.filterByTag(enums.packet.signature);
    if (onePassSigList.length && !signatureList.length && util.isStream(msg.packets.stream) && !stream.isArrayStream(msg.packets.stream)) {
      await Promise.all(onePassSigList.map(async onePassSig => {
        onePassSig.correspondingSig = new Promise((resolve, reject) => {
          onePassSig.correspondingSigResolve = resolve;
          onePassSig.correspondingSigReject = reject;
        });
        onePassSig.signatureData = stream.fromAsync(async () => (await onePassSig.correspondingSig).signatureData);
        onePassSig.hashed = stream.readToEnd(await onePassSig.hash(onePassSig.signatureType, literalDataList[0], undefined, false));
        onePassSig.hashed.catch(() => {});
      }));
      msg.packets.stream = stream.transformPair(msg.packets.stream, async (readable, writable) => {
        const reader = stream.getReader(readable);
        const writer = stream.getWriter(writable);
        try {
          for (let i = 0; i < onePassSigList.length; i++) {
            const { value: signature } = await reader.read();
            onePassSigList[i].correspondingSigResolve(signature);
          }
          await reader.readToEnd();
          await writer.ready;
          await writer.close();
        } catch (e) {
          onePassSigList.forEach(onePassSig => {
            onePassSig.correspondingSigReject(e);
          });
          await writer.abort(e);
        }
      });
      return createVerificationObjects(onePassSigList, literalDataList, verificationKeys, date, false, config);
    }
    return createVerificationObjects(signatureList, literalDataList, verificationKeys, date, false, config);
  }

  /**
   * Verify detached message signature
   * @param {Array<PublicKey>} verificationKeys - Array of public keys to verify signatures
   * @param {Signature} signature
   * @param {Date} date - Verify the signature against the given date, i.e. check signature creation time < date < expiration time
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Array<{
   *   keyID: module:type/keyid~KeyID,
   *   signature: Promise<Signature>,
   *   verified: Promise<Boolean>
   * }>>} List of signer's keyID and validity of signature.
   * @async
   */
  verifyDetached(signature, verificationKeys, date = new Date(), config = defaultConfig) {
    const msg = this.unwrapCompressed();
    const literalDataList = msg.packets.filterByTag(enums.packet.literalData);
    if (literalDataList.length !== 1) {
      throw new Error('Can only verify message with one literal data packet.');
    }
    const signatureList = signature.packets;
    return createVerificationObjects(signatureList, literalDataList, verificationKeys, date, true, config);
  }

  /**
   * Unwrap compressed message
   * @returns {Message} Message Content of compressed message.
   */
  unwrapCompressed() {
    const compressed = this.packets.filterByTag(enums.packet.compressedData);
    if (compressed.length) {
      return new Message(compressed[0].packets);
    }
    return this;
  }

  /**
   * Append signature to unencrypted message object
   * @param {String|Uint8Array} detachedSignature - The detached ASCII-armored or Uint8Array PGP signature
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   */
  async appendSignature(detachedSignature, config = defaultConfig) {
    await this.packets.read(
      util.isUint8Array(detachedSignature) ? detachedSignature : (await unarmor(detachedSignature)).data,
      allowedDetachedSignaturePackets,
      config
    );
  }

  /**
   * Returns binary encoded message
   * @returns {ReadableStream<Uint8Array>} Binary message.
   */
  write() {
    return this.packets.write();
  }

  /**
   * Returns ASCII armored text of message
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {ReadableStream<String>} ASCII armor.
   */
  armor(config = defaultConfig) {
    return armor(enums.armor.message, this.write(), null, null, null, config);
  }
}

/**
 * Create signature packets for the message
 * @param {LiteralDataPacket} literalDataPacket - the literal data packet to sign
 * @param {Array<PrivateKey>} [signingKeys] - private keys with decrypted secret key data for signing
 * @param {Signature} [signature] - Any existing detached signature to append
 * @param {Array<module:type/keyid~KeyID>} [signingKeyIDs] - Array of key IDs to use for signing. Each signingKeyIDs[i] corresponds to signingKeys[i]
 * @param {Date} [date] - Override the creationtime of the signature
 * @param {Array} [userIDs] - User IDs to sign with, e.g. [{ name:'Steve Sender', email:'steve@openpgp.org' }]
 * @param {Boolean} [detached] - Whether to create detached signature packets
 * @param {Object} [config] - Full configuration, defaults to openpgp.config
 * @returns {Promise<PacketList>} List of signature packets.
 * @async
 * @private
 */
export async function createSignaturePackets(literalDataPacket, signingKeys, signature = null, signingKeyIDs = [], date = new Date(), userIDs = [], detached = false, config = defaultConfig) {
  const packetlist = new PacketList();

  // If data packet was created from Uint8Array, use binary, otherwise use text
  const signatureType = literalDataPacket.text === null ?
    enums.signature.binary : enums.signature.text;

  await Promise.all(signingKeys.map(async (primaryKey, i) => {
    const userID = userIDs[i];
    if (primaryKey.isPublic()) {
      throw new Error('Need private key for signing');
    }
    const signingKey = await primaryKey.getSigningKey(signingKeyIDs[i], date, userID, config);
    return createSignaturePacket(literalDataPacket, primaryKey, signingKey.keyPacket, { signatureType }, date, userID, detached, config);
  })).then(signatureList => {
    packetlist.push(...signatureList);
  });

  if (signature) {
    const existingSigPacketlist = signature.packets.filterByTag(enums.packet.signature);
    packetlist.push(...existingSigPacketlist);
  }
  return packetlist;
}

/**
 * Create object containing signer's keyID and validity of signature
 * @param {SignaturePacket} signature - Signature packet
 * @param {Array<LiteralDataPacket>} literalDataList - Array of literal data packets
 * @param {Array<PublicKey>} verificationKeys - Array of public keys to verify signatures
 * @param {Date} [date] - Check signature validity with respect to the given date
 * @param {Boolean} [detached] - Whether to verify detached signature packets
 * @param {Object} [config] - Full configuration, defaults to openpgp.config
 * @returns {Promise<{
 *   keyID: module:type/keyid~KeyID,
 *   signature: Promise<Signature>,
 *   verified: Promise<Boolean>
 * }>} signer's keyID and validity of signature
 * @async
 * @private
 */
async function createVerificationObject(signature, literalDataList, verificationKeys, date = new Date(), detached = false, config = defaultConfig) {
  let primaryKey;
  let unverifiedSigningKey;

  for (const key of verificationKeys) {
    const issuerKeys = key.getKeys(signature.issuerKeyID);
    if (issuerKeys.length > 0) {
      primaryKey = key;
      unverifiedSigningKey = issuerKeys[0];
      break;
    }
  }

  const isOnePassSignature = signature instanceof OnePassSignaturePacket;
  const signaturePacketPromise = isOnePassSignature ? signature.correspondingSig : signature;

  const verifiedSig = {
    keyID: signature.issuerKeyID,
    verified: (async () => {
      if (!unverifiedSigningKey) {
        throw new Error(`Could not find signing key with key ID ${signature.issuerKeyID.toHex()}`);
      }

      await signature.verify(unverifiedSigningKey.keyPacket, signature.signatureType, literalDataList[0], date, detached, config);
      const signaturePacket = await signaturePacketPromise;
      if (unverifiedSigningKey.getCreationTime() > signaturePacket.created) {
        throw new Error('Key is newer than the signature');
      }
      // We pass the signature creation time to check whether the key was expired at the time of signing.
      // We check this after signature verification because for streamed one-pass signatures, the creation time is not available before
      await primaryKey.getSigningKey(unverifiedSigningKey.getKeyID(), signaturePacket.created, undefined, config);
      return true;
    })(),
    signature: (async () => {
      const signaturePacket = await signaturePacketPromise;
      const packetlist = new PacketList();
      signaturePacket && packetlist.push(signaturePacket);
      return new Signature(packetlist);
    })()
  };

  // Mark potential promise rejections as "handled". This is needed because in
  // some cases, we reject them before the user has a reasonable chance to
  // handle them (e.g. `await readToEnd(result.data); await result.verified` and
  // the data stream errors).
  verifiedSig.signature.catch(() => {});
  verifiedSig.verified.catch(() => {});

  return verifiedSig;
}

/**
 * Create list of objects containing signer's keyID and validity of signature
 * @param {Array<SignaturePacket>} signatureList - Array of signature packets
 * @param {Array<LiteralDataPacket>} literalDataList - Array of literal data packets
 * @param {Array<PublicKey>} verificationKeys - Array of public keys to verify signatures
 * @param {Date} date - Verify the signature against the given date,
 *                    i.e. check signature creation time < date < expiration time
 * @param {Boolean} [detached] - Whether to verify detached signature packets
 * @param {Object} [config] - Full configuration, defaults to openpgp.config
 * @returns {Promise<Array<{
 *   keyID: module:type/keyid~KeyID,
 *   signature: Promise<Signature>,
 *   verified: Promise<Boolean>
 * }>>} list of signer's keyID and validity of signatures
 * @async
 * @private
 */
export async function createVerificationObjects(signatureList, literalDataList, verificationKeys, date = new Date(), detached = false, config = defaultConfig) {
  return Promise.all(signatureList.filter(function(signature) {
    return ['text', 'binary'].includes(enums.read(enums.signature, signature.signatureType));
  }).map(async function(signature) {
    return createVerificationObject(signature, literalDataList, verificationKeys, date, detached, config);
  }));
}

/**
 * Reads an (optionally armored) OpenPGP message and returns a Message object
 * @param {Object} options
 * @param {String | ReadableStream<String>} [options.armoredMessage] - Armored message to be parsed
 * @param {Uint8Array | ReadableStream<Uint8Array>} [options.binaryMessage] - Binary to be parsed
 * @param {Object} [options.config] - Custom configuration settings to overwrite those in [config]{@link module:config}
 * @returns {Promise<Message>} New message object.
 * @async
 * @static
 */
export async function readMessage({ armoredMessage, binaryMessage, config }) {
  config = { ...defaultConfig, ...config };
  let input = armoredMessage || binaryMessage;
  if (!input) {
    throw new Error('readMessage: must pass options object containing `armoredMessage` or `binaryMessage`');
  }
  if (armoredMessage && !util.isString(armoredMessage) && !util.isStream(armoredMessage)) {
    throw new Error('readMessage: options.armoredMessage must be a string or stream');
  }
  if (binaryMessage && !util.isUint8Array(binaryMessage) && !util.isStream(binaryMessage)) {
    throw new Error('readMessage: options.binaryMessage must be a Uint8Array or stream');
  }
  const streamType = util.isStream(input);
  if (streamType) {
    await stream.loadStreamsPonyfill();
    input = stream.toStream(input);
  }
  if (armoredMessage) {
    const { type, data } = await unarmor(input, config);
    if (type !== enums.armor.message) {
      throw new Error('Armored text not of type message');
    }
    input = data;
  }
  const packetlist = await PacketList.fromBinary(input, allowedMessagePackets, config);
  const message = new Message(packetlist);
  message.fromStream = streamType;
  return message;
}

/**
 * Creates new message object from text or binary data.
 * @param {Object} options
 * @param {String | ReadableStream<String>} [options.text] - The text message contents
 * @param {Uint8Array | ReadableStream<Uint8Array>} [options.binary] - The binary message contents
 * @param {String} [options.filename=""] - Name of the file (if any)
 * @param {Date} [options.date=current date] - Date of the message, or modification date of the file
 * @param {'utf8'|'binary'|'text'|'mime'} [options.format='utf8' if text is passed, 'binary' otherwise] - Data packet type
 * @returns {Promise<Message>} New message object.
 * @async
 * @static
 */
export async function createMessage({ text, binary, filename, date = new Date(), format = text !== undefined ? 'utf8' : 'binary' }) {
  let input = text !== undefined ? text : binary;
  if (input === undefined) {
    throw new Error('createMessage: must pass options object containing `text` or `binary`');
  }
  if (text && !util.isString(text) && !util.isStream(text)) {
    throw new Error('createMessage: options.text must be a string or stream');
  }
  if (binary && !util.isUint8Array(binary) && !util.isStream(binary)) {
    throw new Error('createMessage: options.binary must be a Uint8Array or stream');
  }
  const streamType = util.isStream(input);
  if (streamType) {
    await stream.loadStreamsPonyfill();
    input = stream.toStream(input);
  }
  const literalDataPacket = new LiteralDataPacket(date);
  if (text !== undefined) {
    literalDataPacket.setText(input, format);
  } else {
    literalDataPacket.setBytes(input, format);
  }
  if (filename !== undefined) {
    literalDataPacket.setFilename(filename);
  }
  const literalDataPacketlist = new PacketList();
  literalDataPacketlist.push(literalDataPacket);
  const message = new Message(literalDataPacketlist);
  message.fromStream = streamType;
  return message;
}
