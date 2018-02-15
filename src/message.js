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
 * @requires config
 * @requires crypto
 * @requires encoding/armor
 * @requires enums
 * @requires util
 * @requires packet
 * @requires signature
 * @requires key
 * @module message
 */

import config from './config';
import crypto from './crypto';
import armor from './encoding/armor';
import enums from './enums';
import util from './util';
import packet from './packet';
import type_keyid from './type/keyid';
import { Signature } from './signature';
import { getPreferredHashAlgo, getPreferredSymAlgo } from './key';


/**
 * @class
 * @classdesc Class that represents an OpenPGP message.
 * Can be an encrypted message, signed message, compressed message or literal message
 * @param  {module:packet/packetlist} packetlist The packets that form this message
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
 * @return {Array<module:type/keyid>} array of keyid objects
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
 * @return {Array<module:type/keyid>} array of keyid objects
 */
Message.prototype.getSigningKeyIds = function() {
  const keyIds = [];
  const msg = this.unwrapCompressed();
  // search for one pass signatures
  const onePassSigList = msg.packets.filterByTag(enums.packet.onePassSignature);
  onePassSigList.forEach(function(packet) {
    keyIds.push(packet.signingKeyId);
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
 * @param  {Array<Object>} sessionKeys  (optional) session keys in the form: { data:Uint8Array, algorithm:String }
 * @return {Message}             new message with decrypted content
 */
Message.prototype.decrypt = async function(privateKeys, passwords, sessionKeys) {
  const keyObjs = sessionKeys || await this.decryptSessionKeys(privateKeys, passwords);

  const symEncryptedPacketlist = this.packets.filterByTag(
    enums.packet.symmetricallyEncrypted,
    enums.packet.symEncryptedIntegrityProtected,
    enums.packet.symEncryptedAEADProtected
  );

  if (symEncryptedPacketlist.length === 0) {
    return;
  }

  const symEncryptedPacket = symEncryptedPacketlist[0];
  let exception = null;
  for (let i = 0; i < keyObjs.length; i++) {
    if (!keyObjs[i] || !util.isUint8Array(keyObjs[i].data) || !util.isString(keyObjs[i].algorithm)) {
      throw new Error('Invalid session key for decryption.');
    }

    try {
      // eslint-disable-next-line no-await-in-loop
      await symEncryptedPacket.decrypt(keyObjs[i].algorithm, keyObjs[i].data);
      break;
    } catch (e) {
      exception = e;
    }
  }

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
 * @return {Array<{ data:Uint8Array, algorithm:String }>} array of object with potential sessionKey, algorithm pairs
 */
Message.prototype.decryptSessionKeys = function(privateKeys, passwords) {
  let keyPackets = [];
  return Promise.resolve().then(async () => {
    if (passwords) {
      const symESKeyPacketlist = this.packets.filterByTag(enums.packet.symEncryptedSessionKey);
      if (!symESKeyPacketlist) {
        throw new Error('No symmetrically encrypted session key packet found.');
      }
      await Promise.all(symESKeyPacketlist.map(async function(packet) {
        await Promise.all(passwords.map(async function(password) {
          try {
            await packet.decrypt(password);
            keyPackets.push(packet);
          } catch (err) {}
        }));
      }));

    } else if (privateKeys) {
      const pkESKeyPacketlist = this.packets.filterByTag(enums.packet.publicKeyEncryptedSessionKey);
      if (!pkESKeyPacketlist) {
        throw new Error('No public key encrypted session key packet found.');
      }
      await Promise.all(pkESKeyPacketlist.map(async function(packet) {
        const privateKeyPackets = privateKeys.reduce(function(acc, privateKey) {
          return acc.concat(privateKey.getKeyPackets(packet.publicKeyId));
        }, []);
        await Promise.all(privateKeyPackets.map(async function(privateKeyPacket) {
          if (!privateKeyPacket) {
           return;
          }
          if (!privateKeyPacket.isDecrypted) {
            throw new Error('Private key is not decrypted.');
          }
          try {
            await packet.decrypt(privateKeyPacket);
            keyPackets.push(packet);
          } catch (err) {}
        }));
      }));
    } else {
      throw new Error('No key or password specified.');
    }
  }).then(() => {
    if (keyPackets.length) {
      // Return only unique session keys
      if (keyPackets.length > 1) {
        const seen = {};
        keyPackets = keyPackets.filter(function(item) {
          const k = item.sessionKeyAlgorithm + util.Uint8Array2str(item.sessionKey);
          if (seen.hasOwnProperty(k)) {
            return false;
          }
          seen[k] = true;
          return true;
        });
      }

      return keyPackets.map(packet => ({ data: packet.sessionKey, algorithm: packet.sessionKeyAlgorithm }));
    }
    throw new Error('Session key decryption failed.');
  });
};

/**
 * Get literal data that is the body of the message
 * @return {(Uint8Array|null)} literal body of the message as Uint8Array
 */
Message.prototype.getLiteralData = function() {
  const literal = this.packets.findPacket(enums.packet.literal);
  return (literal && literal.data) || null;
};

/**
 * Get filename from literal data packet
 * @return {(String|null)} filename of literal data packet as string
 */
Message.prototype.getFilename = function() {
  const literal = this.packets.findPacket(enums.packet.literal);
  return (literal && literal.getFilename()) || null;
};

/**
 * Get literal data as text
 * @return {(String|null)} literal body of the message interpreted as text
 */
Message.prototype.getText = function() {
  const literal = this.packets.findPacket(enums.packet.literal);
  if (literal) {
    return literal.getText();
  }
  return null;
};

/**
 * Encrypt the message either with public keys, passwords, or both at once.
 * @param  {Array<Key>} keys           (optional) public key(s) for message encryption
 * @param  {Array<String>} passwords   (optional) password(s) for message encryption
 * @param  {Object} sessionKey         (optional) session key in the form: { data:Uint8Array, algorithm:String }
 * @param  {Boolean} wildcard          (optional) use a key ID of 0 instead of the public key IDs
 * @param  {Date} date         (optional) the current date of encryption
 * @return {Message}                   new message with encrypted content
 */
Message.prototype.encrypt = function(keys, passwords, sessionKey, wildcard = false, date = new Date()) {
  let symAlgo;
  let msg;
  let symEncryptedPacket;
  return Promise.resolve().then(async () => {
    if (sessionKey) {
      if (!util.isUint8Array(sessionKey.data) || !util.isString(sessionKey.algorithm)) {
        throw new Error('Invalid session key for encryption.');
      }
      symAlgo = sessionKey.algorithm;
      sessionKey = sessionKey.data;
    } else if (keys && keys.length) {
      symAlgo = enums.read(enums.symmetric, getPreferredSymAlgo(keys));
    } else if (passwords && passwords.length) {
      symAlgo = enums.read(enums.symmetric, config.encryption_cipher);
    } else {
      throw new Error('No keys, passwords, or session key provided.');
    }

    if (!sessionKey) {
      sessionKey = crypto.generateSessionKey(symAlgo);
    }

    msg = await encryptSessionKey(sessionKey, symAlgo, keys, passwords, wildcard, date);

    if (config.aead_protect) {
      symEncryptedPacket = new packet.SymEncryptedAEADProtected();
    } else if (config.integrity_protect) {
      symEncryptedPacket = new packet.SymEncryptedIntegrityProtected();
    } else {
      symEncryptedPacket = new packet.SymmetricallyEncrypted();
    }
    symEncryptedPacket.packets = this.packets;

    return symEncryptedPacket.encrypt(symAlgo, sessionKey);
  }).then(() => {
    msg.packets.push(symEncryptedPacket);
    symEncryptedPacket.packets = new packet.List(); // remove packets after encryption
    return {
      message: msg,
      sessionKey: {
        data: sessionKey,
        algorithm: symAlgo
      }
    };
  });
};

/**
 * Encrypt a session key either with public keys, passwords, or both at once.
 * @param  {Uint8Array} sessionKey     session key for encryption
 * @param  {String} symAlgo            session key algorithm
 * @param  {Array<Key>} publicKeys     (optional) public key(s) for message encryption
 * @param  {Array<String>} passwords   (optional) for message encryption
 * @param  {Boolean} wildcard          (optional) use a key ID of 0 instead of the public key IDs
 * @param  {Date} date                 (optional) the date used to encrypt
 * @return {Message}                   new message with encrypted content
 */
export function encryptSessionKey(sessionKey, symAlgo, publicKeys, passwords, wildcard=false, date = new Date()) {
  const packetlist = new packet.List();

  return Promise.resolve().then(async () => {
    if (publicKeys) {
      const results = await Promise.all(publicKeys.map(async function(key) {
        await key.verifyPrimaryUser();
        const encryptionKeyPacket = key.getEncryptionKeyPacket(undefined, date);
        if (!encryptionKeyPacket) {
          throw new Error('Could not find valid key packet for encryption in key ' + key.primaryKey.getKeyId().toHex());
        }
        const pkESKeyPacket = new packet.PublicKeyEncryptedSessionKey();
        pkESKeyPacket.publicKeyId = wildcard ? type_keyid.wildcard() : encryptionKeyPacket.getKeyId();
        pkESKeyPacket.publicKeyAlgorithm = encryptionKeyPacket.algorithm;
        pkESKeyPacket.sessionKey = sessionKey;
        pkESKeyPacket.sessionKeyAlgorithm = symAlgo;
        await pkESKeyPacket.encrypt(encryptionKeyPacket);
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

      const encryptPassword = async function(sessionKey, symAlgo, password) {
        const symEncryptedSessionKeyPacket = new packet.SymEncryptedSessionKey();
        symEncryptedSessionKeyPacket.sessionKey = sessionKey;
        symEncryptedSessionKeyPacket.sessionKeyAlgorithm = symAlgo;
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

      const results = await Promise.all(passwords.map(pwd => encryptPassword(sessionKey, symAlgo, pwd)));
      packetlist.concat(results);
    }
  }).then(() => new Message(packetlist));
}

/**
 * Sign the message (the literal data packet of the message)
 * @param  {Array<module:key~Key>} privateKeys private keys with decrypted secret key data for signing
 * @param  {Signature} signature          (optional) any existing detached signature to add to the message
 * @param  {Date} date}                   (optional) the creation date of the signature used for creating a new signature
 * @return {module:message~Message}       new message with signed content
 */
Message.prototype.sign = async function(privateKeys=[], signature=null, date = new Date()) {
  const packetlist = new packet.List();

  const literalDataPacket = this.packets.findPacket(enums.packet.literal);
  if (!literalDataPacket) {
    throw new Error('No literal data packet to sign.');
  }

  let i;
  let existingSigPacketlist;
  const literalFormat = enums.write(enums.literal, literalDataPacket.format);
  const signatureType = literalFormat === enums.literal.binary ?
    enums.signature.binary : enums.signature.text;

  if (signature) {
    existingSigPacketlist = signature.packets.filterByTag(enums.packet.signature);
    for (i = existingSigPacketlist.length - 1; i >= 0; i--) {
      const signaturePacket = existingSigPacketlist[i];
      const onePassSig = new packet.OnePassSignature();
      onePassSig.type = signatureType;
      onePassSig.hashAlgorithm = signaturePacket.hashAlgorithm;
      onePassSig.publicKeyAlgorithm = signaturePacket.publicKeyAlgorithm;
      onePassSig.signingKeyId = signaturePacket.issuerKeyId;
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
    await privateKey.verifyPrimaryUser();
    const signingKeyPacket = privateKey.getSigningKeyPacket(null, date);
    if (!signingKeyPacket) {
      throw new Error('Could not find valid key packet for signing in key ' +
                      privateKey.primaryKey.getKeyId().toHex());
    }
    const onePassSig = new packet.OnePassSignature();
    onePassSig.type = signatureType;
    onePassSig.hashAlgorithm = getPreferredHashAlgo(privateKey);
    onePassSig.publicKeyAlgorithm = signingKeyPacket.algorithm;
    onePassSig.signingKeyId = signingKeyPacket.getKeyId();
    if (i === privateKeys.length - 1) {
      onePassSig.flags = 1;
    }
    return onePassSig;
  })).then(onePassSignatureList => {
    onePassSignatureList.forEach(onePassSig => packetlist.push(onePassSig));
  });

  packetlist.push(literalDataPacket);
  packetlist.concat(await createSignaturePackets(literalDataPacket, privateKeys, signature, date));

  return new Message(packetlist);
};

/**
 * Compresses the message (the literal and -if signed- signature data packets of the message)
 * @param  {module:enums.compression}   compression     compression algorithm to be used
 * @return {module:message~Message}       new message with compressed content
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
 * @param  {Array<module:key~Key>}           privateKeys private keys with decrypted secret key data for signing
 * @param  {Signature} signature             (optional) any existing detached signature
 * @param  {Date} date                       (optional) the creation date to sign the message with
 * @return {module:signature~Signature}      new detached signature of message content
 */
Message.prototype.signDetached = async function(privateKeys=[], signature=null, date = new Date()) {
  const packetlist = new packet.List();

  const literalDataPacket = this.packets.findPacket(enums.packet.literal);
  if (!literalDataPacket) {
    throw new Error('No literal data packet to sign.');
  }
  return new Signature(await createSignaturePackets(literalDataPacket, privateKeys, signature, date));
};

/**
 * Create signature packets for the message
 * @param  {module:packet/literal}           literalDataPacket the literal data packet to sign
 * @param  {Array<module:key~Key>}           privateKeys private keys with decrypted secret key data for signing
 * @param  {Signature} signature             (optional) any existing detached signature to append
 * @param  {Date} date               (optional) the creation date to sign the message with
 * @return {module:packet/packetlist}        list of signature packets
 */
export async function createSignaturePackets(literalDataPacket, privateKeys, signature=null, date = new Date()) {
  const packetlist = new packet.List();

  const literalFormat = enums.write(enums.literal, literalDataPacket.format);
  const signatureType = literalFormat === enums.literal.binary ?
    enums.signature.binary : enums.signature.text;

  await Promise.all(privateKeys.map(async function(privateKey) {
    if (privateKey.isPublic()) {
      throw new Error('Need private key for signing');
    }
    await privateKey.verifyPrimaryUser();
    const signingKeyPacket = privateKey.getSigningKeyPacket(null, date);
    if (!signingKeyPacket) {
      throw new Error('Could not find valid key packet for signing in key ' + privateKey.primaryKey.getKeyId().toHex());
    }
    if (!signingKeyPacket.isDecrypted) {
      throw new Error('Private key is not decrypted.');
    }
    const signaturePacket = new packet.Signature(date);
    signaturePacket.signatureType = signatureType;
    signaturePacket.publicKeyAlgorithm = signingKeyPacket.algorithm;
    signaturePacket.hashAlgorithm = getPreferredHashAlgo(privateKey);
    await signaturePacket.sign(signingKeyPacket, literalDataPacket);
    return signaturePacket;
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
 * @param {Array<module:key~Key>} keys array of keys to verify signatures
 * @param {Date} date the current date
 * @return {Array<({keyid: module:type/keyid, valid: Boolean})>} list of signer's keyid and validity of signature
 */
Message.prototype.verify = function(keys, date = new Date()) {
  const msg = this.unwrapCompressed();
  const literalDataList = msg.packets.filterByTag(enums.packet.literal);
  if (literalDataList.length !== 1) {
    throw new Error('Can only verify message with one literal data packet.');
  }
  const signatureList = msg.packets.filterByTag(enums.packet.signature);
  return createVerificationObjects(signatureList, literalDataList, keys, date);
};

/**
 * Verify detached message signature
 * @param {Array<module:key~Key>} keys array of keys to verify signatures
 * @param {Signature} signature
 * @param {Date} date the current date
 * @return {Array<({keyid: module:type/keyid, valid: Boolean})>} list of signer's keyid and validity of signature
 */
Message.prototype.verifyDetached = function(signature, keys, date = new Date()) {
  const msg = this.unwrapCompressed();
  const literalDataList = msg.packets.filterByTag(enums.packet.literal);
  if (literalDataList.length !== 1) {
    throw new Error('Can only verify message with one literal data packet.');
  }
  const signatureList = signature.packets;
  return createVerificationObjects(signatureList, literalDataList, keys, date);
};

/**
 * Create list of objects containing signer's keyid and validity of signature
 * @param {Array<module:packet/signature>} signatureList array of signature packets
 * @param {Array<module:packet/literal>} literalDataList array of literal data packets
 * @param {Array<module:key~Key>} keys array of keys to verify signatures
 * @param {Date} date the current date
 * @return {Array<({keyid: module:type/keyid, valid: Boolean})>} list of signer's keyid and validity of signature
 */
export async function createVerificationObjects(signatureList, literalDataList, keys, date = new Date()) {
  return Promise.all(signatureList.map(async function(signature) {
    let keyPacket = null;
    await Promise.all(keys.map(async function(key) {
      await key.verifyPrimaryUser();
      // Look for the unique key packet that matches issuerKeyId of signature
      const result = key.getSigningKeyPacket(signature.issuerKeyId, date);
      if (result) {
        keyPacket = result;
      }
    }));

    // Look for the unique key packet that matches issuerKeyId of signature
    const verifiedSig = {
      keyid: signature.issuerKeyId,
      valid: keyPacket ? await signature.verify(keyPacket, literalDataList[0]) : null
    };

    const packetlist = new packet.List();
    packetlist.push(signature);
    verifiedSig.signature = new Signature(packetlist);

    return verifiedSig;
  }));
}

/**
 * Unwrap compressed message
 * @return {module:message~Message} message Content of compressed message
 */
Message.prototype.unwrapCompressed = function() {
  const compressed = this.packets.filterByTag(enums.packet.compressed);
  if (compressed.length) {
    return new Message(compressed[0].packets);
  }
  return this;
};

/**
 * Returns ASCII armored text of message
 * @return {String} ASCII armor
 */
Message.prototype.armor = function() {
  return armor.encode(enums.armor.message, this.packets.write());
};

/**
 * reads an OpenPGP armored message and returns a message object
 * @param {String} armoredText text to be parsed
 * @return {module:message~Message} new message object
 * @static
 */
export function readArmored(armoredText) {
  //TODO how do we want to handle bad text? Exception throwing
  //TODO don't accept non-message armored texts
  const input = armor.decode(armoredText).data;
  return read(input);
}

/**
 * reads an OpenPGP message as byte array and returns a message object
 * @param {Uint8Array} input   binary message
 * @return {Message}           new message object
 * @static
 */
export function read(input) {
  const packetlist = new packet.List();
  packetlist.read(input);
  return new Message(packetlist);
}

/**
 * Create a message object from signed content and a detached armored signature.
 * @param {String} content An 8 bit ascii string containing e.g. a MIME subtree with text nodes or attachments
 * @param {String} detachedSignature The detached ascii armored PGP signature
 */
export function readSignedContent(content, detachedSignature) {
  const literalDataPacket = new packet.Literal();
  literalDataPacket.setBytes(util.str2Uint8Array(content), enums.read(enums.literal, enums.literal.binary));
  const packetlist = new packet.List();
  packetlist.push(literalDataPacket);
  const input = armor.decode(detachedSignature).data;
  packetlist.read(input);
  return new Message(packetlist);
}

/**
 * creates new message object from text
 * @param {String} text
 * @param {String} filename (optional)
 * @param {Date} date (optional)
 * @return {module:message~Message} new message object
 * @static
 */
export function fromText(text, filename, date = new Date()) {
  const literalDataPacket = new packet.Literal(date);
  // text will be converted to UTF8
  literalDataPacket.setText(text);
  if (filename !== undefined) {
    literalDataPacket.setFilename(filename);
  }
  const literalDataPacketlist = new packet.List();
  literalDataPacketlist.push(literalDataPacket);
  return new Message(literalDataPacketlist);
}

/**
 * creates new message object from binary data
 * @param {Uint8Array} bytes
 * @param {String} filename (optional)
 * @param {Date} date (optional)
 * @return {module:message~Message} new message object
 * @static
 */
export function fromBinary(bytes, filename, date = new Date()) {
  if (!util.isUint8Array(bytes)) {
    throw new Error('Data must be in the form of a Uint8Array');
  }

  const literalDataPacket = new packet.Literal(date);
  if (filename) {
    literalDataPacket.setFilename(filename);
  }
  literalDataPacket.setBytes(bytes, enums.read(enums.literal, enums.literal.binary));
  if (filename !== undefined) {
    literalDataPacket.setFilename(filename);
  }
  const literalDataPacketlist = new packet.List();
  literalDataPacketlist.push(literalDataPacket);
  return new Message(literalDataPacketlist);
}
