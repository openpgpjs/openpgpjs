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

import { armor, unarmor } from '../encoding/armor';
import {
  PacketList,
  SignaturePacket
} from '../packet';
import defaultConfig from '../config';
import enums from '../enums';
import util from '../util';
import User from './user';
import SubKey from './subkey';
import * as helper from './helper';
import PrivateKey from './private_key';
import PublicKey from './public_key';

// A key revocation certificate can contain the following packets
const allowedRevocationPackets = /*#__PURE__*/ util.constructAllowedPackets([SignaturePacket]);

/**
 * Abstract class that represents an OpenPGP key. Must contain a primary key.
 * Can contain additional subkeys, signatures, user ids, user attributes.
 * @borrows PublicKeyPacket#getKeyID as Key#getKeyID
 * @borrows PublicKeyPacket#getFingerprint as Key#getFingerprint
 * @borrows PublicKeyPacket#hasSameFingerprintAs as Key#hasSameFingerprintAs
 * @borrows PublicKeyPacket#getAlgorithmInfo as Key#getAlgorithmInfo
 * @borrows PublicKeyPacket#getCreationTime as Key#getCreationTime
 */
class Key {
  /**
   * Transforms packetlist to structured key data
   * @param {PacketList} packetlist - The packets that form a key
   * @param {Set<enums.packet>} disallowedPackets - disallowed packet tags
   */
  packetListToStructure(packetlist, disallowedPackets = new Set()) {
    let user;
    let primaryKeyID;
    let subKey;
    for (const packet of packetlist) {
      const tag = packet.constructor.tag;
      if (disallowedPackets.has(tag)) {
        throw new Error(`Unexpected packet type: ${tag}`);
      }
      switch (tag) {
        case enums.packet.publicKey:
        case enums.packet.secretKey:
          if (this.keyPacket) {
            throw new Error('Key block contains multiple keys');
          }
          this.keyPacket = packet;
          primaryKeyID = this.getKeyID();
          if (!primaryKeyID) {
            throw new Error('Missing Key ID');
          }
          break;
        case enums.packet.userID:
        case enums.packet.userAttribute:
          user = new User(packet);
          this.users.push(user);
          break;
        case enums.packet.publicSubkey:
        case enums.packet.secretSubkey:
          user = null;
          subKey = new SubKey(packet, this);
          this.subKeys.push(subKey);
          break;
        case enums.packet.signature:
          switch (packet.signatureType) {
            case enums.signature.certGeneric:
            case enums.signature.certPersona:
            case enums.signature.certCasual:
            case enums.signature.certPositive:
              if (!user) {
                util.printDebug('Dropping certification signatures without preceding user packet');
                continue;
              }
              if (packet.issuerKeyID.equals(primaryKeyID)) {
                user.selfCertifications.push(packet);
              } else {
                user.otherCertifications.push(packet);
              }
              break;
            case enums.signature.certRevocation:
              if (user) {
                user.revocationSignatures.push(packet);
              } else {
                this.directSignatures.push(packet);
              }
              break;
            case enums.signature.key:
              this.directSignatures.push(packet);
              break;
            case enums.signature.subkeyBinding:
              if (!subKey) {
                util.printDebug('Dropping subkey binding signature without preceding subkey packet');
                continue;
              }
              subKey.bindingSignatures.push(packet);
              break;
            case enums.signature.keyRevocation:
              this.revocationSignatures.push(packet);
              break;
            case enums.signature.subkeyRevocation:
              if (!subKey) {
                util.printDebug('Dropping subkey revocation signature without preceding subkey packet');
                continue;
              }
              subKey.revocationSignatures.push(packet);
              break;
          }
          break;
      }
    }
  }

  /**
   * Transforms structured key data to packetlist
   * @returns {PacketList} The packets that form a key.
   */
  toPacketList() {
    const packetlist = new PacketList();
    packetlist.push(this.keyPacket);
    packetlist.push(...this.revocationSignatures);
    packetlist.push(...this.directSignatures);
    this.users.map(user => packetlist.push(...user.toPacketList()));
    this.subKeys.map(subKey => packetlist.push(...subKey.toPacketList()));
    return packetlist;
  }

  /**
   * Clones the key object
   * @param {Boolean} [deep=false] Whether to return a deep clone
   * @returns {Promise<Key>} Clone of the key.
   */
  clone(deep = false) {
    const key = new this.constructor(this.toPacketList());
    if (deep) {
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
    }
    return key;
  }

  /**
   * Returns an array containing all public or private subkeys matching keyID;
   * If no keyID is given, returns all subkeys.
   * @param {type/keyID} [keyID] - key ID to look for
   * @returns {Array<SubKey>} array of subkeys
   */
  getSubkeys(keyID = null) {
    const subKeys = this.subKeys.filter(subKey => (
      !keyID || subKey.getKeyID().equals(keyID, true)
    ));
    return subKeys;
  }

  /**
   * Returns an array containing all public or private keys matching keyID.
   * If no keyID is given, returns all keys, starting with the primary key.
   * @param {type/keyid~KeyID} [keyID] - key ID to look for
   * @returns {Array<Key|SubKey>} array of keys
   */
  getKeys(keyID = null) {
    const keys = [];
    if (!keyID || this.getKeyID().equals(keyID, true)) {
      keys.push(this);
    }
    return keys.concat(this.getSubkeys(keyID));
  }

  /**
   * Returns key IDs of all keys
   * @returns {Array<module:type/keyid~KeyID>}
   */
  getKeyIDs() {
    return this.getKeys().map(key => key.getKeyID());
  }

  /**
   * Returns userIDs
   * @returns {Array<string>} Array of userIDs.
   */
  getUserIDs() {
    return this.users.map(user => {
      return user.userID ? user.userID.userID : null;
    }).filter(userID => userID !== null);
  }

  /**
   * Returns binary encoded key
   * @returns {Uint8Array} Binary key.
   */
  write() {
    return this.toPacketList().write();
  }

  /**
   * Returns last created key or key by given keyID that is available for signing and verification
   * @param  {module:type/keyid~KeyID} [keyID] - key ID of a specific key to retrieve
   * @param  {Date} [date] - use the fiven date date to  to check key validity instead of the current date
   * @param  {Object} [userID] - filter keys for the given user ID
   * @param  {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Key|SubKey>} signing key
   * @throws if no valid signing key was found
   * @async
   */
  async getSigningKey(keyID = null, date = new Date(), userID = {}, config = defaultConfig) {
    await this.verifyPrimaryKey(date, userID, config);
    const primaryKey = this.keyPacket;
    const subKeys = this.subKeys.slice().sort((a, b) => b.keyPacket.created - a.keyPacket.created);
    let exception;
    for (const subKey of subKeys) {
      if (!keyID || subKey.getKeyID().equals(keyID)) {
        try {
          await subKey.verify(date, config);
          const dataToVerify = { key: primaryKey, bind: subKey.keyPacket };
          const bindingSignature = await helper.getLatestValidSignature(
            subKey.bindingSignatures, primaryKey, enums.signature.subkeyBinding, dataToVerify, date, config
          );
          if (!helper.isValidSigningKeyPacket(subKey.keyPacket, bindingSignature)) {
            continue;
          }
          if (!bindingSignature.embeddedSignature) {
            throw new Error('Missing embedded signature');
          }
          // verify embedded signature
          await helper.getLatestValidSignature(
            [bindingSignature.embeddedSignature], subKey.keyPacket, enums.signature.keyBinding, dataToVerify, date, config
          );
          helper.checkKeyStrength(subKey.keyPacket, config);
          return subKey;
        } catch (e) {
          exception = e;
        }
      }
    }

    try {
      const primaryUser = await this.getPrimaryUser(date, userID, config);
      if (date && primaryKey.getCreationTime() > date) {
        throw new Error('Primary key was created after the given date');
      }
      if ((!keyID || primaryKey.getKeyID().equals(keyID)) &&
          helper.isValidSigningKeyPacket(primaryKey, primaryUser.selfCertification, config)) {
        helper.checkKeyStrength(primaryKey, config);
        return this;
      }
    } catch (e) {
      exception = e;
    }
    throw util.wrapError('Could not find valid signing key packet in key ' + this.getKeyID().toHex(), exception);
  }

  /**
   * Returns last created key or key by given keyID that is available for encryption or decryption
   * @param  {module:type/keyid~KeyID} [keyID] - key ID of a specific key to retrieve
   * @param  {Date}   [date] - use the fiven date date to  to check key validity instead of the current date
   * @param  {Object} [userID] - filter keys for the given user ID
   * @param  {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Key|SubKey>} encryption key
   * @throws if no valid encryption key was found
   * @async
   */
  async getEncryptionKey(keyID, date = new Date(), userID = {}, config = defaultConfig) {
    await this.verifyPrimaryKey(date, userID, config);
    const primaryKey = this.keyPacket;
    // V4: by convention subkeys are preferred for encryption service
    const subKeys = this.subKeys.slice().sort((a, b) => b.keyPacket.created - a.keyPacket.created);
    let exception;
    for (const subKey of subKeys) {
      if (!keyID || subKey.getKeyID().equals(keyID)) {
        try {
          await subKey.verify(date, config);
          const dataToVerify = { key: primaryKey, bind: subKey.keyPacket };
          const bindingSignature = await helper.getLatestValidSignature(subKey.bindingSignatures, primaryKey, enums.signature.subkeyBinding, dataToVerify, date, config);
          if (helper.isValidEncryptionKeyPacket(subKey.keyPacket, bindingSignature)) {
            helper.checkKeyStrength(subKey.keyPacket, config);
            return subKey;
          }
        } catch (e) {
          exception = e;
        }
      }
    }

    try {
      // if no valid subkey for encryption, evaluate primary key
      const primaryUser = await this.getPrimaryUser(date, userID, config);
      if ((!keyID || primaryKey.getKeyID().equals(keyID)) &&
          helper.isValidEncryptionKeyPacket(primaryKey, primaryUser.selfCertification)) {
        helper.checkKeyStrength(primaryKey, config);
        return this;
      }
    } catch (e) {
      exception = e;
    }
    throw util.wrapError('Could not find valid encryption key packet in key ' + this.getKeyID().toHex(), exception);
  }

  /**
   * Checks if a signature on a key is revoked
   * @param {SignaturePacket} signature - The signature to verify
   * @param  {PublicSubkeyPacket|
   *          SecretSubkeyPacket|
   *          PublicKeyPacket|
   *          SecretKeyPacket} key, optional The key to verify the signature
   * @param {Date} [date] - Use the given date for verification, instead of the current time
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Boolean>} True if the certificate is revoked.
   * @async
   */
  async isRevoked(signature, key, date = new Date(), config = defaultConfig) {
    return helper.isDataRevoked(
      this.keyPacket, enums.signature.keyRevocation, { key: this.keyPacket }, this.revocationSignatures, signature, key, date, config
    );
  }

  /**
   * Verify primary key. Checks for revocation signatures, expiration time
   * and valid self signature. Throws if the primary key is invalid.
   * @param {Date} [date] - Use the given date for verification instead of the current time
   * @param {Object} [userID] - User ID
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @throws {Error} If key verification failed
   * @async
   */
  async verifyPrimaryKey(date = new Date(), userID = {}, config = defaultConfig) {
    const primaryKey = this.keyPacket;
    // check for key revocation signatures
    if (await this.isRevoked(null, null, date, config)) {
      throw new Error('Primary key is revoked');
    }
    // check for valid, unrevoked, unexpired self signature
    const { selfCertification } = await this.getPrimaryUser(date, userID, config);
    // check for expiration time in binding signatures
    if (helper.isDataExpired(primaryKey, selfCertification, date)) {
      throw new Error('Primary key is expired');
    }
    // check for expiration time in direct signatures
    if (this.directSignatures.length > 0) {
      const directSignature = await helper.getLatestValidSignature(
        this.directSignatures, primaryKey, enums.signature.key, { key: primaryKey }, date, config
      ).catch(() => {}); // invalid signatures are discarded, to avoid breaking the key

      if (directSignature && helper.isDataExpired(primaryKey, directSignature, date)) {
        throw new Error('Primary key is expired through a direct signature');
      }
    }
  }

  /**
   * Returns the latest date when the key can be used for encrypting, signing, or both, depending on the `capabilities` paramater.
   * When `capabilities` is null, defaults to returning the expiry date of the primary key.
   * Returns null if `capabilities` is passed and the key does not have the specified capabilities or is revoked or invalid.
   * Returns Infinity if the key doesn't expire.
   * @param  {encrypt|sign|encrypt_sign} [capabilities] - capabilities to look up
   * @param  {module:type/keyid~KeyID} [keyID] - key ID of the specific key to check
   * @param  {Object} [userID] - User ID to consider instead of the primary user
   * @param  {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Date | Infinity | null>}
   * @async
   */
  async getExpirationTime(capabilities, keyID, userID, config = defaultConfig) {
    const toDateOrInfinity = value => (value === Infinity ? value : new Date(value));
    const minNotNull = (...args) => { // Like Math.min but aware of `null`, to avoid treating them as 0
      const notNull = args.filter(arg => arg !== null);
      if (notNull.length === 0) return null;
      return Math.min(...notNull);
    };

    let primaryKeyExpiry;
    try {
      const { selfCertification } = await this.getPrimaryUser(null, userID, config);
      const keyExpiry = helper.getKeyExpirationTime(this.keyPacket, selfCertification);
      const sigExpiry = selfCertification.getExpirationTime();
      // TODO check direct signatures
      primaryKeyExpiry = toDateOrInfinity(Math.min(keyExpiry, sigExpiry));
    } catch (e) {
      primaryKeyExpiry = null;
    }
    if (!capabilities) return primaryKeyExpiry;

    // loop through subkeys based on requested capabilities and retrieve their expiration times
    const getLatestKeyExpiry = async keys => (keys.length === 0 ? null : toDateOrInfinity(
      Math.max(...await Promise.all(
        keys.map(async key => (key instanceof SubKey ? key.getExpirationTime(null, config) : primaryKeyExpiry))
      ))
    ));
    let encryptExpiry = null;
    if (capabilities === 'encrypt' || capabilities === 'encrypt_sign') {
      const encryptionKeys = (await Promise.all(
        this.getKeys(keyID).map(key => this.getEncryptionKey(key.getKeyID(), null, userID, config).catch(() => null))
      )).filter(Boolean);
      if (encryptionKeys.length === 0) return null; // the key cannot encrypt
      encryptExpiry = await getLatestKeyExpiry(encryptionKeys);
    }
    let signExpiry = null;
    if (capabilities === 'sign' || capabilities === 'encrypt_sign') {
      const signingKeys = (await Promise.all(
        this.getKeys(keyID).map(key => this.getSigningKey(key.getKeyID(), null, userID, config).catch(() => null))
      )).filter(Boolean);
      if (signingKeys.length === 0) return null; // the key cannot sign
      signExpiry = await getLatestKeyExpiry(signingKeys);
    }
    return toDateOrInfinity(minNotNull(encryptExpiry, signExpiry));
  }

  /**
   * Returns primary user and most significant (latest valid) self signature
   * - if multiple primary users exist, returns the one with the latest self signature
   * - otherwise, returns the user with the latest self signature
   * @param {Date} [date] - Use the given date for verification instead of the current time
   * @param {Object} [userID] - User ID to get instead of the primary user, if it exists
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<{
   *   user: User,
   *   selfCertification: SignaturePacket
   * }>} The primary user and the self signature
   * @async
   */
  async getPrimaryUser(date = new Date(), userID = {}, config = defaultConfig) {
    const primaryKey = this.keyPacket;
    const users = [];
    let exception;
    for (let i = 0; i < this.users.length; i++) {
      try {
        const user = this.users[i];
        if (!user.userID) {
          continue;
        }
        if (
          (userID.name !== undefined && user.userID.name !== userID.name) ||
          (userID.email !== undefined && user.userID.email !== userID.email) ||
          (userID.comment !== undefined && user.userID.comment !== userID.comment)
        ) {
          throw new Error('Could not find user that matches that user ID');
        }
        const dataToVerify = { userID: user.userID, key: primaryKey };
        const selfCertification = await helper.getLatestValidSignature(user.selfCertifications, primaryKey, enums.signature.certGeneric, dataToVerify, date, config);
        users.push({ index: i, user, selfCertification });
      } catch (e) {
        exception = e;
      }
    }
    if (!users.length) {
      throw exception || new Error('Could not find primary user');
    }
    await Promise.all(users.map(async function (a) {
      return a.user.revoked || a.user.isRevoked(primaryKey, a.selfCertification, null, date, config);
    }));
    // sort by primary user flag and signature creation time
    const primaryUser = users.sort(function(a, b) {
      const A = a.selfCertification;
      const B = b.selfCertification;
      return B.revoked - A.revoked || A.isPrimaryUserID - B.isPrimaryUserID || A.created - B.created;
    }).pop();
    const { user, selfCertification: cert } = primaryUser;
    if (cert.revoked || await user.isRevoked(primaryKey, cert, null, date, config)) {
      throw new Error('Primary user is revoked');
    }
    return primaryUser;
  }

  /**
   * Update key with new components from specified key with same key ID:
   * users, subkeys, certificates are merged into the destination key,
   * duplicates and expired signatures are ignored.
   *
   * If the source key is a private key and the destination key is public,
   * a private key is returned.
   * @param {Key} sourceKey - Source key to merge
   * @param {Date} [date] - Date to verify validity of signatures and keys
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Key>} updated key
   * @async
   */
  async update(sourceKey, date = new Date(), config = defaultConfig) {
    if (!this.hasSameFingerprintAs(sourceKey)) {
      throw new Error('Primary key fingerprints must be equal to update the key');
    }
    if (this.isPublic() && sourceKey.isPrivate()) {
      // check for equal subkey packets
      const equal = (this.subKeys.length === sourceKey.subKeys.length) &&
            (this.subKeys.every(destSubKey => {
              return sourceKey.subKeys.some(srcSubKey => {
                return destSubKey.hasSameFingerprintAs(srcSubKey);
              });
            }));
      if (!equal) {
        throw new Error('Cannot update public key with private key if subkeys mismatch');
      }

      return sourceKey.update(this, config);
    }
    // from here on, either:
    // - destination key is private, source key is public
    // - the keys are of the same type
    // hence we don't need to convert the destination key type
    const updatedKey = this.clone();
    // revocation signatures
    await helper.mergeSignatures(sourceKey, updatedKey, 'revocationSignatures', date, srcRevSig => {
      return helper.isDataRevoked(updatedKey.keyPacket, enums.signature.keyRevocation, updatedKey, [srcRevSig], null, sourceKey.keyPacket, date, config);
    });
    // direct signatures
    await helper.mergeSignatures(sourceKey, updatedKey, 'directSignatures', date);
    // update users
    await Promise.all(sourceKey.users.map(async srcUser => {
      // multiple users with the same ID/attribute are not explicitly disallowed by the spec
      // hence we support them, just in case
      const usersToUpdate = updatedKey.users.filter(dstUser => (
        (srcUser.userID && srcUser.userID.equals(dstUser.userID)) ||
        (srcUser.userAttribute && srcUser.userAttribute.equals(dstUser.userAttribute))
      ));
      if (usersToUpdate.length > 0) {
        await Promise.all(
          usersToUpdate.map(userToUpdate => userToUpdate.update(srcUser, updatedKey.keyPacket, date, config))
        );
      } else {
        updatedKey.users.push(srcUser);
      }
    }));
    // update subkeys
    await Promise.all(sourceKey.subKeys.map(async srcSubkey => {
      // multiple subkeys with same fingerprint might be preset
      const subkeysToUpdate = updatedKey.subKeys.filter(dstSubkey => (
        dstSubkey.hasSameFingerprintAs(srcSubkey)
      ));
      if (subkeysToUpdate.length > 0) {
        await Promise.all(
          subkeysToUpdate.map(subkeyToUpdate => subkeyToUpdate.update(srcSubkey, date, config))
        );
      } else {
        updatedKey.subKeys.push(srcSubkey);
      }
    }));

    return updatedKey;
  }

  /**
   * Get revocation certificate from a revoked key.
   *   (To get a revocation certificate for an unrevoked key, call revoke() first.)
   * @param {Date} date - Use the given date instead of the current time
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<String>} Armored revocation certificate.
   * @async
   */
  async getRevocationCertificate(date = new Date(), config = defaultConfig) {
    const dataToVerify = { key: this.keyPacket };
    const revocationSignature = await helper.getLatestValidSignature(this.revocationSignatures, this.keyPacket, enums.signature.keyRevocation, dataToVerify, date, config);
    const packetlist = new PacketList();
    packetlist.push(revocationSignature);
    return armor(enums.armor.publicKey, packetlist.write(), null, null, 'This is a revocation certificate');
  }

  /**
   * Applies a revocation certificate to a key
   * This adds the first signature packet in the armored text to the key,
   * if it is a valid revocation signature.
   * @param {String} revocationCertificate - armored revocation certificate
   * @param {Date} [date] - Date to verify the certificate
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Key>} Revoked key.
   * @async
   */
  async applyRevocationCertificate(revocationCertificate, date = new Date(), config = defaultConfig) {
    const input = await unarmor(revocationCertificate, config);
    const packetlist = await PacketList.fromBinary(input.data, allowedRevocationPackets, config);
    const revocationSignature = packetlist.findPacket(enums.packet.signature);
    if (!revocationSignature || revocationSignature.signatureType !== enums.signature.keyRevocation) {
      throw new Error('Could not find revocation signature packet');
    }
    if (!revocationSignature.issuerKeyID.equals(this.getKeyID())) {
      throw new Error('Revocation signature does not match key');
    }
    try {
      await revocationSignature.verify(this.keyPacket, enums.signature.keyRevocation, { key: this.keyPacket }, date, undefined, config);
    } catch (e) {
      throw util.wrapError('Could not verify revocation signature', e);
    }
    const key = this.clone();
    key.revocationSignatures.push(revocationSignature);
    return key;
  }

  /**
   * Signs primary user of key
   * @param {Array<PrivateKey>} privateKeys - decrypted private keys for signing
   * @param {Date} [date] - Use the given date for verification instead of the current time
   * @param {Object} [userID] - User ID to get instead of the primary user, if it exists
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Key>} Key with new certificate signature.
   * @async
   */
  async signPrimaryUser(privateKeys, date, userID, config = defaultConfig) {
    const { index, user } = await this.getPrimaryUser(date, userID, config);
    const userSign = await user.sign(this.keyPacket, privateKeys, date, config);
    const key = await this.clone();
    key.users[index] = userSign;
    return key;
  }

  /**
   * Signs all users of key
   * @param {Array<PrivateKey>} privateKeys - decrypted private keys for signing
   * @param {Date} [date] - Use the given date for signing, instead of the current time
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Key>} Key with new certificate signature.
   * @async
   */
  async signAllUsers(privateKeys, date = new Date(), config = defaultConfig) {
    const that = this;
    const key = this.clone();
    key.users = await Promise.all(this.users.map(function(user) {
      return user.sign(that.keyPacket, privateKeys, date, config);
    }));
    return key;
  }

  /**
   * Verifies primary user of key
   * - if no arguments are given, verifies the self certificates;
   * - otherwise, verifies all certificates signed with given keys.
   * @param {Array<Key>} keys - array of keys to verify certificate signatures
   * @param {Date} [date] - Use the given date for verification instead of the current time
   * @param {Object} [userID] - User ID to get instead of the primary user, if it exists
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Array<{
   *   keyID: module:type/keyid~KeyID,
   *   valid: Boolean
   * }>>} List of signer's keyID and validity of signature
   * @async
   */
  async verifyPrimaryUser(keys, date = new Date(), userID, config = defaultConfig) {
    const primaryKey = this.keyPacket;
    const { user } = await this.getPrimaryUser(date, userID, config);
    const results = keys ? await user.verifyAllCertifications(primaryKey, keys, date, config) :
      [{ keyID: primaryKey.getKeyID(), valid: await user.verify(primaryKey, date, config).catch(() => false) }];
    return results;
  }

  /**
   * Verifies all users of key
   * - if no arguments are given, verifies the self certificates;
   * - otherwise, verifies all certificates signed with given keys.
   * @param {Array<Key>} keys - array of keys to verify certificate signatures
   * @param {Date} [date] - Use the given date for verification instead of the current time
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Array<{
   *   userID: String,
   *   keyID: module:type/keyid~KeyID,
   *   valid: Boolean
   * }>>} List of userID, signer's keyID and validity of signature
   * @async
   */
  async verifyAllUsers(keys, date = new Date(), config = defaultConfig) {
    const results = [];
    const primaryKey = this.keyPacket;
    await Promise.all(this.users.map(async function(user) {
      const signatures = keys ? await user.verifyAllCertifications(primaryKey, keys, date, config) :
        [{ keyID: primaryKey.getKeyID(), valid: await user.verify(primaryKey, date, config).catch(() => false) }];
      signatures.forEach(signature => {
        results.push({
          userID: user.userID.userID,
          keyID: signature.keyID,
          valid: signature.valid
        });
      });
    }));
    return results;
  }
}

['getKeyID', 'getFingerprint', 'getAlgorithmInfo', 'getCreationTime', 'hasSameFingerprintAs'].forEach(name => {
  Key.prototype[name] =
  SubKey.prototype[name];
});

export default Key;

/**
 * Creates a PublicKey or PrivateKey depending on the packetlist in input
 * @param {PacketList} - packets to parse
 * @return {Key} parsed key
 * @throws if no key packet was found
 */
export function createKey(packetlist) {
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
