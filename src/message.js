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

/**
 * @requires web-stream-tools
 * @requires encoding/armor
 * @requires type/keyid
 * @requires config
 * @requires crypto
 * @requires enums
 * @requires util
 * @requires packet
 * @requires signature
 * @requires key
 * @module message
 */

import stream from 'web-stream-tools';
import armor from './encoding/armor';
import type_keyid from './type/keyid';
import config from './config';
import crypto from './crypto';
import enums from './enums';
import util from './util';
import packet from './packet';
import { Signature } from './signature';
import { getPreferredHashAlgo, getPreferredAlgo, isAeadSupported, createSignaturePacket } from './key';


/**
 * @class
 * @classdesc Class that represents an OpenPGP message.
 * Can be an encrypted message, signed message, compressed message or literal message
 * @param  {module:packet.List} packetlist The packets that form this message
 * See {@link https://tools.ietf.org/html/rfc4880#section-11.3}
 */

export function Message(packetlist) {
  if (!(this instanceof Message)) {
    return new Message(packetlist);
  }
  this.packets = packetlist || new packet.List();
}

/**
 * Returns the key IDs of the keys to which the session key is encrypted
 * @returns {Array<module:type/keyid>} array of keyid objects
 */
Message.prototype.getEncryptionKeyIds = function() {
  const keyIds = [];
  const pkESKeyPacketlist = this.packets.filterByTag(enums.packet.publicKeyEncryptedSessionKey);
  pkESKeyPacketlist.forEach(function(packet) {
    keyIds.push(packet.publicKeyId);
  });
  return keyIds;
};

/**
 * Returns the key IDs of the keys that signed the message
 * @returns {Array<module:type/keyid>} array of keyid objects
 */
Message.prototype.getSigningKeyIds = function() {
  const keyIds = [];
  const msg = this.unwrapCompressed();
  // search for one pass signatures
  const onePassSigList = msg.packets.filterByTag(enums.packet.onePassSignature);
  onePassSigList.forEach(function(packet) {
    keyIds.push(packet.issuerKeyId);
  });
  // if nothing found look for signature packets
  if (!keyIds.length) {
    const signatureList = msg.packets.filterByTag(enums.packet.signature);
    signatureList.forEach(function(packet) {
      keyIds.push(packet.issuerKeyId);
    });
  }
  return keyIds;
};

/**
 * Decrypt the message. Either a private key, a session key, or a password must be specified.
 * @param  {Array<Key>} privateKeys     (optional) private keys with decrypted secret data
 * @param  {Array<String>} passwords    (optional) passwords used to decrypt
 * @param  {Array<Object>} sessionKeys  (optional) session keys in the form: { data:Uint8Array, algorithm:String, [aeadAlgorithm:String] }
 * @param  {Boolean} streaming          (optional) whether to process data as a stream
 * @returns {Promise<Message>}             new message with decrypted content
 * @async
 */
Message.prototype.decrypt = async function(privateKeys, passwords, sessionKeys, streaming) {
  const keyObjs = sessionKeys || await this.decryptSessionKeys(privateKeys, passwords);

  const symEncryptedPacketlist = this.packets.filterByTag(
    enums.packet.symmetricallyEncrypted,
    enums.packet.symEncryptedIntegrityProtected,
    enums.packet.symEncryptedAEADProtected
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
      await symEncryptedPacket.decrypt(keyObj.algorithm, keyObj.data, streaming);
    } catch (e) {
      util.print_debug_error(e);
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
  symEncryptedPacket.packets = new packet.List(); // remove packets after decryption

  return resultMsg;
};

/**
 * Decrypt encrypted session keys either with private keys or passwords.
 * @param  {Array<Key>} privateKeys    (optional) private keys with decrypted secret data
 * @param  {Array<String>} passwords   (optional) passwords used to decrypt
 * @returns {Promise<Array<{ data:      Uint8Array,
                             algorithm: String }>>} array of object with potential sessionKey, algorithm pairs
 * @async
 */
Message.prototype.decryptSessionKeys = async function(privateKeys, passwords) {
  let keyPackets = [];

  let exception;
  if (passwords) {
    const symESKeyPacketlist = this.packets.filterByTag(enums.packet.symEncryptedSessionKey);
    if (!symESKeyPacketlist) {
      throw new Error('No symmetrically encrypted session key packet found.');
    }
    await Promise.all(passwords.map(async function(password, i) {
      let packets;
      if (i) {
        packets = new packet.List();
        await packets.read(symESKeyPacketlist.write());
      } else {
        packets = symESKeyPacketlist;
      }
      await Promise.all(packets.map(async function(keyPacket) {
        try {
          await keyPacket.decrypt(password);
          keyPackets.push(keyPacket);
        } catch (err) {
          util.print_debug_error(err);
        }
      }));
    }));
  } else if (privateKeys) {
    const pkESKeyPacketlist = this.packets.filterByTag(enums.packet.publicKeyEncryptedSessionKey);
    if (!pkESKeyPacketlist) {
      throw new Error('No public key encrypted session key packet found.');
    }
    await Promise.all(pkESKeyPacketlist.map(async function(keyPacket) {
      await Promise.all(privateKeys.map(async function(privateKey) {
        let algos = [
          enums.symmetric.aes256, // Old OpenPGP.js default fallback
          enums.symmetric.aes128, // RFC4880bis fallback
          enums.symmetric.tripledes, // RFC4880 fallback
          enums.symmetric.cast5 // Golang OpenPGP fallback
        ];
        try {
          const primaryUser = await privateKey.getPrimaryUser(); // TODO: Pass userId from somewhere.
          if (primaryUser.selfCertification.preferredSymmetricAlgorithms) {
            algos = algos.concat(primaryUser.selfCertification.preferredSymmetricAlgorithms);
          }
        } catch (e) {}

        // do not check key expiration to allow decryption of old messages
        const privateKeyPackets = (await privateKey.getDecryptionKeys(keyPacket.publicKeyId, null)).map(key => key.keyPacket);
        await Promise.all(privateKeyPackets.map(async function(privateKeyPacket) {
          if (!privateKeyPacket) {
            return;
          }
          if (!privateKeyPacket.isDecrypted()) {
            throw new Error('Private key is not decrypted.');
          }
          try {
            await keyPacket.decrypt(privateKeyPacket);
            if (!algos.includes(enums.write(enums.symmetric, keyPacket.sessionKeyAlgorithm))) {
              throw new Error('A non-preferred symmetric algorithm was used.');
            }
            keyPackets.push(keyPacket);
          } catch (err) {
            util.print_debug_error(err);
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
      const seen = {};
      keyPackets = keyPackets.filter(function(item) {
        const k = item.sessionKeyAlgorithm + util.Uint8Array_to_str(item.sessionKey);
        if (seen.hasOwnProperty(k)) {
          return false;
        }
        seen[k] = true;
        return true;
      });
    }

    return keyPackets.map(packet => ({ data: packet.sessionKey, algorithm: packet.sessionKeyAlgorithm }));
  }
  throw exception || new Error('Session key decryption failed.');
};

/**
 * Get literal data that is the body of the message
 * @returns {(Uint8Array|null)} literal body of the message as Uint8Array
 */
Message.prototype.getLiteralData = function() {
  const msg = this.unwrapCompressed();
  const literal = msg.packets.findPacket(enums.packet.literal);
  return (literal && literal.getBytes()) || null;
};

/**
 * Get filename from literal data packet
 * @returns {(String|null)} filename of literal data packet as string
 */
Message.prototype.getFilename = function() {
  const msg = this.unwrapCompressed();
  const literal = msg.packets.findPacket(enums.packet.literal);
  return (literal && literal.getFilename()) || null;
};

/**
 * Get literal data as text
 * @returns {(String|null)} literal body of the message interpreted as text
 */
Message.prototype.getText = function() {
  const msg = this.unwrapCompressed();
  const literal = msg.packets.findPacket(enums.packet.literal);
  if (literal) {
    return literal.getText();
  }
  return null;
};

/**
 * Encrypt the message either with public keys, passwords, or both at once.
 * @param  {Array<Key>} keys           (optional) public key(s) for message encryption
 * @param  {Array<String>} passwords   (optional) password(s) for message encryption
 * @param  {Object} sessionKey         (optional) session key in the form: { data:Uint8Array, algorithm:String, [aeadAlgorithm:String] }
 * @param  {Boolean} wildcard          (optional) use a key ID of 0 instead of the public key IDs
 * @param  {Date} date                 (optional) override the creation date of the literal package
 * @param  {Array} userIds             (optional) user IDs to encrypt for, e.g. [{ name:'Robert Receiver', email:'robert@openpgp.org' }]
 * @param  {Boolean} streaming         (optional) whether to process data as a stream
 * @returns {Promise<Message>}                   new message with encrypted content
 * @async
 */
Message.prototype.encrypt = async function(keys, passwords, sessionKey, wildcard = false, date = new Date(), userIds = [], streaming) {
  let symAlgo;
  let aeadAlgo;
  let symEncryptedPacket;

  if (sessionKey) {
    if (!util.isUint8Array(sessionKey.data) || !util.isString(sessionKey.algorithm)) {
      throw new Error('Invalid session key for encryption.');
    }
    symAlgo = sessionKey.algorithm;
    aeadAlgo = sessionKey.aeadAlgorithm;
    sessionKey = sessionKey.data;
  } else if (keys && keys.length) {
    symAlgo = enums.read(enums.symmetric, await getPreferredAlgo('symmetric', keys, date, userIds));
    if (config.aead_protect && await isAeadSupported(keys, date, userIds)) {
      aeadAlgo = enums.read(enums.aead, await getPreferredAlgo('aead', keys, date, userIds));
    }
  } else if (passwords && passwords.length) {
    symAlgo = enums.read(enums.symmetric, config.encryption_cipher);
    aeadAlgo = enums.read(enums.aead, config.aead_mode);
  } else {
    throw new Error('No keys, passwords, or session key provided.');
  }

  if (!sessionKey) {
    sessionKey = await crypto.generateSessionKey(symAlgo);
  }

  const msg = await encryptSessionKey(sessionKey, symAlgo, aeadAlgo, keys, passwords, wildcard, date, userIds);

  if (config.aead_protect && aeadAlgo) {
    symEncryptedPacket = new packet.SymEncryptedAEADProtected();
    symEncryptedPacket.aeadAlgorithm = aeadAlgo;
  } else if (config.integrity_protect) {
    symEncryptedPacket = new packet.SymEncryptedIntegrityProtected();
  } else {
    symEncryptedPacket = new packet.SymmetricallyEncrypted();
  }
  symEncryptedPacket.packets = this.packets;

  await symEncryptedPacket.encrypt(symAlgo, sessionKey, streaming);

  msg.packets.push(symEncryptedPacket);
  symEncryptedPacket.packets = new packet.List(); // remove packets after encryption
  return {
    message: msg,
    sessionKey: {
      data: sessionKey,
      algorithm: symAlgo,
      aeadAlgorithm: aeadAlgo
    }
  };
};

/**
 * Encrypt a session key either with public keys, passwords, or both at once.
 * @param  {Uint8Array} sessionKey     session key for encryption
 * @param  {String} symAlgo            session key algorithm
 * @param  {String} aeadAlgo           (optional) aead algorithm, e.g. 'eax' or 'ocb'
 * @param  {Array<Key>} publicKeys     (optional) public key(s) for message encryption
 * @param  {Array<String>} passwords   (optional) for message encryption
 * @param  {Boolean} wildcard          (optional) use a key ID of 0 instead of the public key IDs
 * @param  {Date} date                 (optional) override the date
 * @param  {Array} userIds             (optional) user IDs to encrypt for, e.g. [{ name:'Robert Receiver', email:'robert@openpgp.org' }]
 * @returns {Promise<Message>}          new message with encrypted content
 * @async
 */
export async function encryptSessionKey(sessionKey, symAlgo, aeadAlgo, publicKeys, passwords, wildcard = false, date = new Date(), userIds = []) {
  const packetlist = new packet.List();

  if (publicKeys) {
    const results = await Promise.all(publicKeys.map(async function(publicKey) {
      const encryptionKey = await publicKey.getEncryptionKey(undefined, date, userIds);
      const pkESKeyPacket = new packet.PublicKeyEncryptedSessionKey();
      pkESKeyPacket.publicKeyId = wildcard ? type_keyid.wildcard() : encryptionKey.getKeyId();
      pkESKeyPacket.publicKeyAlgorithm = encryptionKey.keyPacket.algorithm;
      pkESKeyPacket.sessionKey = sessionKey;
      pkESKeyPacket.sessionKeyAlgorithm = symAlgo;
      await pkESKeyPacket.encrypt(encryptionKey.keyPacket);
      delete pkESKeyPacket.sessionKey; // delete plaintext session key after encryption
      return pkESKeyPacket;
    }));
    packetlist.concat(results);
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

    const encryptPassword = async function(sessionKey, symAlgo, aeadAlgo, password) {
      const symEncryptedSessionKeyPacket = new packet.SymEncryptedSessionKey();
      symEncryptedSessionKeyPacket.sessionKey = sessionKey;
      symEncryptedSessionKeyPacket.sessionKeyAlgorithm = symAlgo;
      if (aeadAlgo) {
        symEncryptedSessionKeyPacket.aeadAlgorithm = aeadAlgo;
      }
      await symEncryptedSessionKeyPacket.encrypt(password);

      if (config.password_collision_check) {
        const results = await Promise.all(passwords.map(pwd => testDecrypt(symEncryptedSessionKeyPacket, pwd)));
        if (results.reduce(sum) !== 1) {
          return encryptPassword(sessionKey, symAlgo, password);
        }
      }

      delete symEncryptedSessionKeyPacket.sessionKey; // delete plaintext session key after encryption
      return symEncryptedSessionKeyPacket;
    };

    const results = await Promise.all(passwords.map(pwd => encryptPassword(sessionKey, symAlgo, aeadAlgo, pwd)));
    packetlist.concat(results);
  }

  return new Message(packetlist);
}

/**
 * Sign the message (the literal data packet of the message)
 * @param  {Array<module:key.Key>}        privateKeys private keys with decrypted secret key data for signing
 * @param  {Signature} signature          (optional) any existing detached signature to add to the message
 * @param  {Date} date                    (optional) override the creation time of the signature
 * @param  {Array} userIds                (optional) user IDs to sign with, e.g. [{ name:'Steve Sender', email:'steve@openpgp.org' }]
 * @param  {Boolean} streaming            (optional) whether to process data as a stream
 * @returns {Promise<Message>}             new message with signed content
 * @async
 */
Message.prototype.sign = async function(privateKeys = [], signature = null, date = new Date(), userIds = [], streaming = false) {
  const packetlist = new packet.List();

  const literalDataPacket = this.packets.findPacket(enums.packet.literal);
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
      const onePassSig = new packet.OnePassSignature();
      onePassSig.signatureType = signaturePacket.signatureType;
      onePassSig.hashAlgorithm = signaturePacket.hashAlgorithm;
      onePassSig.publicKeyAlgorithm = signaturePacket.publicKeyAlgorithm;
      onePassSig.issuerKeyId = signaturePacket.issuerKeyId;
      if (!privateKeys.length && i === 0) {
        onePassSig.flags = 1;
      }
      packetlist.push(onePassSig);
    }
  }

  await Promise.all(Array.from(privateKeys).reverse().map(async function (privateKey, i) {
    if (privateKey.isPublic()) {
      throw new Error('Need private key for signing');
    }
    const signingKey = await privateKey.getSigningKey(undefined, date, userIds);
    const onePassSig = new packet.OnePassSignature();
    onePassSig.signatureType = signatureType;
    onePassSig.hashAlgorithm = await getPreferredHashAlgo(privateKey, signingKey.keyPacket, date, userIds);
    onePassSig.publicKeyAlgorithm = signingKey.keyPacket.algorithm;
    onePassSig.issuerKeyId = signingKey.getKeyId();
    if (i === privateKeys.length - 1) {
      onePassSig.flags = 1;
    }
    return onePassSig;
  })).then(onePassSignatureList => {
    onePassSignatureList.forEach(onePassSig => packetlist.push(onePassSig));
  });

  packetlist.push(literalDataPacket);
  packetlist.concat(await createSignaturePackets(literalDataPacket, privateKeys, signature, date, userIds, false, streaming));

  return new Message(packetlist);
};

/**
 * Compresses the message (the literal and -if signed- signature data packets of the message)
 * @param  {module:enums.compression}   compression     compression algorithm to be used
 * @returns {module:message.Message}       new message with compressed content
 */
Message.prototype.compress = function(compression) {
  if (compression === enums.compression.uncompressed) {
    return this;
  }

  const compressed = new packet.Compressed();
  compressed.packets = this.packets;
  compressed.algorithm = enums.read(enums.compression, compression);

  const packetList = new packet.List();
  packetList.push(compressed);

  return new Message(packetList);
};

/**
 * Create a detached signature for the message (the literal data packet of the message)
 * @param  {Array<module:key.Key>}               privateKeys private keys with decrypted secret key data for signing
 * @param  {Signature} signature                 (optional) any existing detached signature
 * @param  {Date} date                           (optional) override the creation time of the signature
 * @param  {Array} userIds                       (optional) user IDs to sign with, e.g. [{ name:'Steve Sender', email:'steve@openpgp.org' }]
 * @param  {Boolean} streaming                   (optional) whether to process data as a stream
 * @returns {Promise<module:signature.Signature>} new detached signature of message content
 * @async
 */
Message.prototype.signDetached = async function(privateKeys = [], signature = null, date = new Date(), userIds = [], streaming = false) {
  const literalDataPacket = this.packets.findPacket(enums.packet.literal);
  if (!literalDataPacket) {
    throw new Error('No literal data packet to sign.');
  }
  return new Signature(await createSignaturePackets(literalDataPacket, privateKeys, signature, date, userIds, true, streaming));
};

/**
 * Create signature packets for the message
 * @param  {module:packet.Literal}             literalDataPacket the literal data packet to sign
 * @param  {Array<module:key.Key>}             privateKeys private keys with decrypted secret key data for signing
 * @param  {Signature} signature               (optional) any existing detached signature to append
 * @param  {Date} date                         (optional) override the creationtime of the signature
 * @param  {Array} userIds                     (optional) user IDs to sign with, e.g. [{ name:'Steve Sender', email:'steve@openpgp.org' }]
 * @param  {Boolean} detached                  (optional) whether to create detached signature packets
 * @param  {Boolean} streaming                 (optional) whether to process data as a stream
 * @returns {Promise<module:packet.List>} list of signature packets
 * @async
 */
export async function createSignaturePackets(literalDataPacket, privateKeys, signature = null, date = new Date(), userIds = [], detached = false, streaming = false) {
  const packetlist = new packet.List();

  // If data packet was created from Uint8Array, use binary, otherwise use text
  const signatureType = literalDataPacket.text === null ?
    enums.signature.binary : enums.signature.text;

  await Promise.all(privateKeys.map(async (privateKey, i) => {
    const userId = userIds[i];
    if (privateKey.isPublic()) {
      throw new Error('Need private key for signing');
    }
    const signingKey = await privateKey.getSigningKey(undefined, date, userId);
    return createSignaturePacket(literalDataPacket, privateKey, signingKey.keyPacket, { signatureType }, date, userId, detached, streaming);
  })).then(signatureList => {
    signatureList.forEach(signaturePacket => packetlist.push(signaturePacket));
  });

  if (signature) {
    const existingSigPacketlist = signature.packets.filterByTag(enums.packet.signature);
    packetlist.concat(existingSigPacketlist);
  }
  return packetlist;
}

/**
 * Verify message signatures
 * @param {Array<module:key.Key>} keys array of keys to verify signatures
 * @param {Date} date (optional) Verify the signature against the given date, i.e. check signature creation time < date < expiration time
 * @param  {Boolean} streaming (optional) whether to process data as a stream
 * @returns {Promise<Array<({keyid: module:type/keyid, valid: Boolean})>>} list of signer's keyid and validity of signature
 * @async
 */
Message.prototype.verify = async function(keys, date = new Date(), streaming) {
  const msg = this.unwrapCompressed();
  const literalDataList = msg.packets.filterByTag(enums.packet.literal);
  if (literalDataList.length !== 1) {
    throw new Error('Can only verify message with one literal data packet.');
  }
  if (!streaming) {
    msg.packets.concat(await stream.readToEnd(msg.packets.stream, _ => _));
  }
  const onePassSigList = msg.packets.filterByTag(enums.packet.onePassSignature).reverse();
  const signatureList = msg.packets.filterByTag(enums.packet.signature);
  if (streaming && onePassSigList.length && !signatureList.length && msg.packets.stream) {
    await Promise.all(onePassSigList.map(async onePassSig => {
      onePassSig.correspondingSig = new Promise((resolve, reject) => {
        onePassSig.correspondingSigResolve = resolve;
        onePassSig.correspondingSigReject = reject;
      });
      onePassSig.signatureData = stream.fromAsync(async () => (await onePassSig.correspondingSig).signatureData);
      onePassSig.hashed = stream.readToEnd(await onePassSig.hash(onePassSig.signatureType, literalDataList[0], undefined, false, streaming));
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
    return createVerificationObjects(onePassSigList, literalDataList, keys, date, false, streaming);
  }
  return createVerificationObjects(signatureList, literalDataList, keys, date, false, streaming);
};

/**
 * Verify detached message signature
 * @param {Array<module:key.Key>} keys array of keys to verify signatures
 * @param {Signature} signature
 * @param {Date} date Verify the signature against the given date, i.e. check signature creation time < date < expiration time
 * @returns {Promise<Array<({keyid: module:type/keyid, valid: Boolean})>>} list of signer's keyid and validity of signature
 * @async
 */
Message.prototype.verifyDetached = function(signature, keys, date = new Date()) {
  const msg = this.unwrapCompressed();
  const literalDataList = msg.packets.filterByTag(enums.packet.literal);
  if (literalDataList.length !== 1) {
    throw new Error('Can only verify message with one literal data packet.');
  }
  const signatureList = signature.packets;
  return createVerificationObjects(signatureList, literalDataList, keys, date, true);
};

/**
 * Create object containing signer's keyid and validity of signature
 * @param {module:packet.Signature} signature signature packets
 * @param {Array<module:packet.Literal>} literalDataList array of literal data packets
 * @param {Array<module:key.Key>} keys array of keys to verify signatures
 * @param {Date} date Verify the signature against the given date,
 *                    i.e. check signature creation time < date < expiration time
 * @param {Boolean} detached (optional) whether to verify detached signature packets
 * @returns {Promise<Array<{keyid: module:type/keyid,
 *                          valid: Boolean}>>} list of signer's keyid and validity of signature
 * @async
 */
async function createVerificationObject(signature, literalDataList, keys, date = new Date(), detached = false, streaming = false) {
  let primaryKey = null;
  let signingKey = null;
  await Promise.all(keys.map(async function(key) {
    // Look for the unique key that matches issuerKeyId of signature
    try {
      signingKey = await key.getSigningKey(signature.issuerKeyId, null);
      primaryKey = key;
    } catch (e) {}
  }));

  const signaturePacket = signature.correspondingSig || signature;
  const verifiedSig = {
    keyid: signature.issuerKeyId,
    verified: (async () => {
      if (!signingKey) {
        return null;
      }
      const verified = await signature.verify(signingKey.keyPacket, signature.signatureType, literalDataList[0], detached, streaming);
      const sig = await signaturePacket;
      if (sig.isExpired(date) || !(
        sig.created >= signingKey.getCreationTime() &&
        sig.created < await (signingKey === primaryKey ?
          signingKey.getExpirationTime() :
          signingKey.getExpirationTime(primaryKey, date)
        )
      )) {
        throw new Error('Signature is expired');
      }
      return verified;
    })(),
    signature: (async () => {
      const sig = await signaturePacket;
      const packetlist = new packet.List();
      packetlist.push(sig);
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
 * Create list of objects containing signer's keyid and validity of signature
 * @param {Array<module:packet.Signature>} signatureList array of signature packets
 * @param {Array<module:packet.Literal>} literalDataList array of literal data packets
 * @param {Array<module:key.Key>} keys array of keys to verify signatures
 * @param {Date} date Verify the signature against the given date,
 *                    i.e. check signature creation time < date < expiration time
 * @param {Boolean} detached (optional) whether to verify detached signature packets
 * @returns {Promise<Array<{keyid: module:type/keyid,
 *                          valid: Boolean}>>} list of signer's keyid and validity of signature
 * @async
 */
export async function createVerificationObjects(signatureList, literalDataList, keys, date = new Date(), detached = false, streaming = false) {
  return Promise.all(signatureList.filter(function(signature) {
    return ['text', 'binary'].includes(enums.read(enums.signature, signature.signatureType));
  }).map(async function(signature) {
    return createVerificationObject(signature, literalDataList, keys, date, detached, streaming);
  }));
}

/**
 * Unwrap compressed message
 * @returns {module:message.Message} message Content of compressed message
 */
Message.prototype.unwrapCompressed = function() {
  const compressed = this.packets.filterByTag(enums.packet.compressed);
  if (compressed.length) {
    return new Message(compressed[0].packets);
  }
  return this;
};

/**
 * Append signature to unencrypted message object
 * @param {String|Uint8Array} detachedSignature The detached ASCII-armored or Uint8Array PGP signature
 */
Message.prototype.appendSignature = async function(detachedSignature) {
  await this.packets.read(util.isUint8Array(detachedSignature) ? detachedSignature : (await armor.decode(detachedSignature)).data);
};

/**
 * Returns ASCII armored text of message
 * @returns {ReadableStream<String>} ASCII armor
 */
Message.prototype.armor = function() {
  return armor.encode(enums.armor.message, this.packets.write());
};

/**
 * reads an OpenPGP armored message and returns a message object
 * @param {String | ReadableStream<String>} armoredText text to be parsed
 * @returns {Promise<module:message.Message>} new message object
 * @async
 * @static
 */
export async function readArmored(armoredText) {
  //TODO how do we want to handle bad text? Exception throwing
  //TODO don't accept non-message armored texts
  const streamType = util.isStream(armoredText);
  if (streamType === 'node') {
    armoredText = stream.nodeToWeb(armoredText);
  }
  const input = await armor.decode(armoredText);
  return read(input.data, streamType);
}

/**
 * reads an OpenPGP message as byte array and returns a message object
 * @param {Uint8Array | ReadableStream<Uint8Array>} input    binary message
 * @param {Boolean} fromStream  whether the message was created from a Stream
 * @returns {Promise<module:message.Message>} new message object
 * @async
 * @static
 */
export async function read(input, fromStream = util.isStream(input)) {
  const streamType = util.isStream(input);
  if (streamType === 'node') {
    input = stream.nodeToWeb(input);
  }
  const packetlist = new packet.List();
  await packetlist.read(input, fromStream);
  const message = new Message(packetlist);
  message.fromStream = fromStream;
  return message;
}

/**
 * creates new message object from text
 * @param {String | ReadableStream<String>} text
 * @param {String} filename (optional)
 * @param {Date} date (optional)
 * @param {utf8|binary|text|mime} type (optional) data packet type
 * @returns {module:message.Message} new message object
 * @static
 */
export function fromText(text, filename, date = new Date(), type = 'utf8') {
  const streamType = util.isStream(text);
  if (streamType === 'node') {
    text = stream.nodeToWeb(text);
  }
  const literalDataPacket = new packet.Literal(date);
  // text will be converted to UTF8
  literalDataPacket.setText(text, type);
  if (filename !== undefined) {
    literalDataPacket.setFilename(filename);
  }
  const literalDataPacketlist = new packet.List();
  literalDataPacketlist.push(literalDataPacket);
  const message = new Message(literalDataPacketlist);
  message.fromStream = streamType;
  return message;
}

/**
 * creates new message object from binary data
 * @param {Uint8Array | ReadableStream<Uint8Array>} bytes
 * @param {String} filename (optional)
 * @param {Date} date (optional)
 * @param {utf8|binary|text|mime} type (optional) data packet type
 * @returns {module:message.Message} new message object
 * @static
 */
export function fromBinary(bytes, filename, date = new Date(), type = 'binary') {
  const streamType = util.isStream(bytes);
  if (!util.isUint8Array(bytes) && !streamType) {
    throw new Error('Data must be in the form of a Uint8Array or Stream');
  }
  if (streamType === 'node') {
    bytes = stream.nodeToWeb(bytes);
  }

  const literalDataPacket = new packet.Literal(date);
  literalDataPacket.setBytes(bytes, type);
  if (filename !== undefined) {
    literalDataPacket.setFilename(filename);
  }
  const literalDataPacketlist = new packet.List();
  literalDataPacketlist.push(literalDataPacket);
  const message = new Message(literalDataPacketlist);
  message.fromStream = streamType;
  return message;
}
