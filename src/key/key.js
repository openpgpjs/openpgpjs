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
  PublicKeyPacket,
  PublicSubkeyPacket,
  SignaturePacket
} from '../packet';
import defaultConfig from '../config';
import enums from '../enums';
import util from '../util';
import User from './user';
import SubKey from './subkey';
import * as helper from './helper';

// A key revocation certificate can contain the following packets
const allowedRevocationPackets = /*#__PURE__*/ util.constructAllowedPackets([SignaturePacket]);

/**
 * Class that represents an OpenPGP key. Must contain a primary key.
 * Can contain additional subkeys, signatures, user ids, user attributes.
 * @borrows PublicKeyPacket#getKeyID as Key#getKeyID
 * @borrows PublicKeyPacket#getFingerprint as Key#getFingerprint
 * @borrows PublicKeyPacket#hasSameFingerprintAs as Key#hasSameFingerprintAs
 * @borrows PublicKeyPacket#getAlgorithmInfo as Key#getAlgorithmInfo
 * @borrows PublicKeyPacket#getCreationTime as Key#getCreationTime
 */
class Key {
  /**
   * @param {PacketList} packetlist - The packets that form this key
   */
  constructor(packetlist) {
    if (!(this instanceof Key)) {
      return new Key(packetlist);
    }
    // same data as in packetlist but in structured form
    this.keyPacket = null;
    this.revocationSignatures = [];
    this.directSignatures = [];
    this.users = [];
    this.subKeys = [];
    this.packetlist2structure(packetlist);
    if (!this.keyPacket) {
      throw new Error('Invalid key: need at least key packet');
    }
  }

  get primaryKey() {
    return this.keyPacket;
  }

  /**
   * Transforms packetlist to structured key data
   * @param {PacketList} packetlist - The packets that form a key
   */
  packetlist2structure(packetlist) {
    let user;
    let primaryKeyID;
    let subKey;
    for (let i = 0; i < packetlist.length; i++) {
      switch (packetlist[i].constructor.tag) {
        case enums.packet.publicKey:
        case enums.packet.secretKey:
          if (this.keyPacket) {
            throw new Error('Key block contains multiple keys');
          }
          this.keyPacket = packetlist[i];
          primaryKeyID = this.getKeyID();
          break;
        case enums.packet.userID:
        case enums.packet.userAttribute:
          user = new User(packetlist[i]);
          this.users.push(user);
          break;
        case enums.packet.publicSubkey:
        case enums.packet.secretSubkey:
          user = null;
          subKey = new SubKey(packetlist[i]);
          this.subKeys.push(subKey);
          break;
        case enums.packet.signature:
          switch (packetlist[i].signatureType) {
            case enums.signature.certGeneric:
            case enums.signature.certPersona:
            case enums.signature.certCasual:
            case enums.signature.certPositive:
              if (!user) {
                util.printDebug('Dropping certification signatures without preceding user packet');
                continue;
              }
              if (packetlist[i].issuerKeyID.equals(primaryKeyID)) {
                user.selfCertifications.push(packetlist[i]);
              } else {
                user.otherCertifications.push(packetlist[i]);
              }
              break;
            case enums.signature.certRevocation:
              if (user) {
                user.revocationSignatures.push(packetlist[i]);
              } else {
                this.directSignatures.push(packetlist[i]);
              }
              break;
            case enums.signature.key:
              this.directSignatures.push(packetlist[i]);
              break;
            case enums.signature.subkeyBinding:
              if (!subKey) {
                util.printDebug('Dropping subkey binding signature without preceding subkey packet');
                continue;
              }
              subKey.bindingSignatures.push(packetlist[i]);
              break;
            case enums.signature.keyRevocation:
              this.revocationSignatures.push(packetlist[i]);
              break;
            case enums.signature.subkeyRevocation:
              if (!subKey) {
                util.printDebug('Dropping subkey revocation signature without preceding subkey packet');
                continue;
              }
              subKey.revocationSignatures.push(packetlist[i]);
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
  toPacketlist() {
    const packetlist = new PacketList();
    packetlist.push(this.keyPacket);
    packetlist.push(...this.revocationSignatures);
    packetlist.push(...this.directSignatures);
    this.users.map(user => packetlist.push(...user.toPacketlist()));
    this.subKeys.map(subKey => packetlist.push(...subKey.toPacketlist()));
    return packetlist;
  }

  /**
   * Clones the key object
   * @param {Boolean} [deep=false] Whether to return a deep clone
   * @returns {Promise<Key>} Clone of the key.
   * @async
   */
  async clone(deep = false) {
    const key = new Key(this.toPacketlist());
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
   * If keyID is not present, returns all subkeys.
   * @param {type/keyid} keyID
   * @returns {Array<SubKey>}
   */
  getSubkeys(keyID = null) {
    const subKeys = [];
    this.subKeys.forEach(subKey => {
      if (!keyID || subKey.getKeyID().equals(keyID, true)) {
        subKeys.push(subKey);
      }
    });
    return subKeys;
  }

  /**
   * Returns an array containing all public or private keys matching keyID.
   * If keyID is not present, returns all keys starting with the primary key.
   * @param {type/keyid} keyID
   * @returns {Array<Key|SubKey>}
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
   * Returns true if this is a public key
   * @returns {Boolean}
   */
  isPublic() {
    return this.keyPacket.constructor.tag === enums.packet.publicKey;
  }

  /**
   * Returns true if this is a private key
   * @returns {Boolean}
   */
  isPrivate() {
    return this.keyPacket.constructor.tag === enums.packet.secretKey;
  }

  /**
   * Returns key as public key (shallow copy)
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Key} New public Key.
   */
  toPublic() {
    const packetlist = new PacketList();
    const keyPackets = this.toPacketlist();
    let bytes;
    let pubKeyPacket;
    let pubSubkeyPacket;
    for (let i = 0; i < keyPackets.length; i++) {
      switch (keyPackets[i].constructor.tag) {
        case enums.packet.secretKey:
          bytes = keyPackets[i].writePublicKey();
          pubKeyPacket = new PublicKeyPacket();
          pubKeyPacket.read(bytes);
          packetlist.push(pubKeyPacket);
          break;
        case enums.packet.secretSubkey:
          bytes = keyPackets[i].writePublicKey();
          pubSubkeyPacket = new PublicSubkeyPacket();
          pubSubkeyPacket.read(bytes);
          packetlist.push(pubSubkeyPacket);
          break;
        default:
          packetlist.push(keyPackets[i]);
      }
    }
    return new Key(packetlist);
  }

  /**
   * Returns binary encoded key
   * @returns {Uint8Array} Binary key.
   */
  write() {
    return this.toPacketlist().write();
  }

  /**
   * Returns ASCII armored text of key
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {ReadableStream<String>} ASCII armor.
   */
  armor(config = defaultConfig) {
    const type = this.isPublic() ? enums.armor.publicKey : enums.armor.privateKey;
    return armor(type, this.toPacketlist().write(), undefined, undefined, undefined, config);
  }

  /**
   * Returns last created key or key by given keyID that is available for signing and verification
   * @param  {module:type/keyid~KeyID} keyID, optional
   * @param {Date} [date] - Use the given date for verification instead of the current time
   * @param  {Object} userID, optional user ID
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Key|SubKey|null>} Key or null if no signing key has been found.
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
          await subKey.verify(primaryKey, date, config);
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
   * @param  {module:type/keyid~KeyID} keyID, optional
   * @param  {Date}              date, optional
   * @param  {String}            userID, optional
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Key|SubKey|null>} Key or null if no encryption key has been found.
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
          await subKey.verify(primaryKey, date, config);
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
   * Returns all keys that are available for decryption, matching the keyID when given
   * This is useful to retrieve keys for session key decryption
   * @param  {module:type/keyid~KeyID} keyID, optional
   * @param  {Date}              date, optional
   * @param  {String}            userID, optional
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Array<Key|SubKey>>} Array of decryption keys.
   * @async
   */
  async getDecryptionKeys(keyID, date = new Date(), userID = {}, config = defaultConfig) {
    const primaryKey = this.keyPacket;
    const keys = [];
    for (let i = 0; i < this.subKeys.length; i++) {
      if (!keyID || this.subKeys[i].getKeyID().equals(keyID, true)) {
        try {
          const dataToVerify = { key: primaryKey, bind: this.subKeys[i].keyPacket };
          const bindingSignature = await helper.getLatestValidSignature(this.subKeys[i].bindingSignatures, primaryKey, enums.signature.subkeyBinding, dataToVerify, date, config);
          if (helper.isValidDecryptionKeyPacket(bindingSignature, config)) {
            keys.push(this.subKeys[i]);
          }
        } catch (e) {}
      }
    }

    // evaluate primary key
    const primaryUser = await this.getPrimaryUser(date, userID, config);
    if ((!keyID || primaryKey.getKeyID().equals(keyID, true)) &&
        helper.isValidDecryptionKeyPacket(primaryUser.selfCertification, config)) {
      keys.push(this);
    }

    return keys;
  }

  /**
   * Returns true if the primary key or any subkey is decrypted.
   * A dummy key is considered encrypted.
   */
  isDecrypted() {
    return this.getKeys().some(({ keyPacket }) => keyPacket.isDecrypted());
  }

  /**
   * Check whether the private and public primary key parameters correspond
   * Together with verification of binding signatures, this guarantees key integrity
   * In case of gnu-dummy primary key, it is enough to validate any signing subkeys
   *   otherwise all encryption subkeys are validated
   * If only gnu-dummy keys are found, we cannot properly validate so we throw an error
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @throws {Error} if validation was not successful and the key cannot be trusted
   * @async
   */
  async validate(config = defaultConfig) {
    if (!this.isPrivate()) {
      throw new Error("Cannot validate a public key");
    }

    let signingKeyPacket;
    if (!this.primaryKey.isDummy()) {
      signingKeyPacket = this.primaryKey;
    } else {
      /**
       * It is enough to validate any signing keys
       * since its binding signatures are also checked
       */
      const signingKey = await this.getSigningKey(null, null, undefined, { ...config, rejectPublicKeyAlgorithms: new Set(), minRSABits: 0 });
      // This could again be a dummy key
      if (signingKey && !signingKey.keyPacket.isDummy()) {
        signingKeyPacket = signingKey.keyPacket;
      }
    }

    if (signingKeyPacket) {
      return signingKeyPacket.validate();
    } else {
      const keys = this.getKeys();
      const allDummies = keys.map(key => key.keyPacket.isDummy()).every(Boolean);
      if (allDummies) {
        throw new Error("Cannot validate an all-gnu-dummy key");
      }

      return Promise.all(keys.map(async key => key.keyPacket.validate()));
    }
  }

  /**
   * Clear private key parameters
   */
  clearPrivateParams() {
    if (!this.isPrivate()) {
      throw new Error("Can't clear private parameters of a public key");
    }
    this.getKeys().forEach(({ keyPacket }) => {
      if (keyPacket.isDecrypted()) {
        keyPacket.clearPrivateParams();
      }
    });
  }

  /**
   * Checks if a signature on a key is revoked
   * @param {SignaturePacket} signature - The signature to verify
   * @param  {PublicSubkeyPacket|
   *          SecretSubkeyPacket|
   *          PublicKeyPacket|
   *          SecretKeyPacket} key, optional The key to verify the signature
   * @param {Date} date - Use the given date instead of the current time
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
    // check for expiration time
    if (helper.isDataExpired(primaryKey, selfCertification, date)) {
      throw new Error('Primary key is expired');
    }
  }

  /**
   * Returns the latest date when the key can be used for encrypting, signing, or both, depending on the `capabilities` paramater.
   * When `capabilities` is null, defaults to returning the expiry date of the primary key.
   * Returns null if `capabilities` is passed and the key does not have the specified capabilities or is revoked or invalid.
   * Returns Infinity if the key doesn't expire.
   * @param  {encrypt|sign|encrypt_sign} capabilities, optional
   * @param  {module:type/keyid~KeyID} keyID, optional
   * @param  {Object} userID, optional user ID
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Date | Infinity | null>}
   * @async
   */
  async getExpirationTime(capabilities, keyID, userID, config = defaultConfig) {
    const primaryUser = await this.getPrimaryUser(null, userID, config);
    const selfCert = primaryUser.selfCertification;
    const keyExpiry = helper.getExpirationTime(this.keyPacket, selfCert);
    const sigExpiry = selfCert.getExpirationTime();
    let expiry = keyExpiry < sigExpiry ? keyExpiry : sigExpiry;
    if (capabilities === 'encrypt' || capabilities === 'encrypt_sign') {
      const encryptKey =
        await this.getEncryptionKey(keyID, expiry, userID, { ...config, rejectPublicKeyAlgorithms: new Set(), minRSABits: 0 }).catch(() => {}) ||
        await this.getEncryptionKey(keyID, null, userID, { ...config, rejectPublicKeyAlgorithms: new Set(), minRSABits: 0 }).catch(() => {});
      if (!encryptKey) return null;
      const encryptExpiry = await encryptKey.getExpirationTime(this.keyPacket, undefined, config);
      if (encryptExpiry < expiry) expiry = encryptExpiry;
    }
    if (capabilities === 'sign' || capabilities === 'encrypt_sign') {
      const signKey =
        await this.getSigningKey(keyID, expiry, userID, { ...config, rejectPublicKeyAlgorithms: new Set(), minRSABits: 0 }).catch(() => {}) ||
        await this.getSigningKey(keyID, null, userID, { ...config, rejectPublicKeyAlgorithms: new Set(), minRSABits: 0 }).catch(() => {});
      if (!signKey) return null;
      const signExpiry = await signKey.getExpirationTime(this.keyPacket, undefined, config);
      if (signExpiry < expiry) expiry = signExpiry;
    }
    return expiry;
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
   * If the specified key is a private key and the destination key is public,
   * the destination key is transformed to a private key.
   * @param {Key} key - Source key to merge
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<undefined>}
   * @async
   */
  async update(key, config = defaultConfig) {
    if (!this.hasSameFingerprintAs(key)) {
      throw new Error('Key update method: fingerprints of keys not equal');
    }
    if (this.isPublic() && key.isPrivate()) {
      // check for equal subkey packets
      const equal = (this.subKeys.length === key.subKeys.length) &&
            (this.subKeys.every(destSubKey => {
              return key.subKeys.some(srcSubKey => {
                return destSubKey.hasSameFingerprintAs(srcSubKey);
              });
            }));
      if (!equal) {
        throw new Error('Cannot update public key with private key if subkey mismatch');
      }
      this.keyPacket = key.keyPacket;
    }
    // revocation signatures
    await helper.mergeSignatures(key, this, 'revocationSignatures', srcRevSig => {
      return helper.isDataRevoked(this.keyPacket, enums.signature.keyRevocation, this, [srcRevSig], null, key.keyPacket, undefined, config);
    });
    // direct signatures
    await helper.mergeSignatures(key, this, 'directSignatures');
    // TODO replace when Promise.some or Promise.any are implemented
    // users
    await Promise.all(key.users.map(async srcUser => {
      let found = false;
      await Promise.all(this.users.map(async dstUser => {
        if ((srcUser.userID && dstUser.userID &&
              (srcUser.userID.userID === dstUser.userID.userID)) ||
            (srcUser.userAttribute && (srcUser.userAttribute.equals(dstUser.userAttribute)))) {
          await dstUser.update(srcUser, this.keyPacket, config);
          found = true;
        }
      }));
      if (!found) {
        this.users.push(srcUser);
      }
    }));
    // TODO replace when Promise.some or Promise.any are implemented
    // subkeys
    await Promise.all(key.subKeys.map(async srcSubKey => {
      let found = false;
      await Promise.all(this.subKeys.map(async dstSubKey => {
        if (dstSubKey.hasSameFingerprintAs(srcSubKey)) {
          await dstSubKey.update(srcSubKey, this.keyPacket, config);
          found = true;
        }
      }));
      if (!found) {
        this.subKeys.push(srcSubKey);
      }
    }));
  }

  /**
   * Revokes the key
   * @param {Object} reasonForRevocation - optional, object indicating the reason for revocation
   * @param  {module:enums.reasonForRevocation} reasonForRevocation.flag optional, flag indicating the reason for revocation
   * @param  {String} reasonForRevocation.string optional, string explaining the reason for revocation
   * @param {Date} date - optional, override the creationtime of the revocation signature
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Key>} New key with revocation signature.
   * @async
   */
  async revoke(
    {
      flag: reasonForRevocationFlag = enums.reasonForRevocation.noReason,
      string: reasonForRevocationString = ''
    } = {},
    date = new Date(),
    config = defaultConfig
  ) {
    if (this.isPublic()) {
      throw new Error('Need private key for revoking');
    }
    const dataToSign = { key: this.keyPacket };
    const key = await this.clone();
    key.revocationSignatures.push(await helper.createSignaturePacket(dataToSign, null, this.keyPacket, {
      signatureType: enums.signature.keyRevocation,
      reasonForRevocationFlag: enums.write(enums.reasonForRevocation, reasonForRevocationFlag),
      reasonForRevocationString
    }, date, undefined, undefined, config));
    return key;
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
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Key>} New revoked key.
   * @async
   */
  async applyRevocationCertificate(revocationCertificate, config = defaultConfig) {
    const input = await unarmor(revocationCertificate, config);
    const packetlist = new PacketList();
    await packetlist.read(input.data, allowedRevocationPackets, undefined, config);
    const revocationSignature = packetlist.findPacket(enums.packet.signature);
    if (!revocationSignature || revocationSignature.signatureType !== enums.signature.keyRevocation) {
      throw new Error('Could not find revocation signature packet');
    }
    if (!revocationSignature.issuerKeyID.equals(this.getKeyID())) {
      throw new Error('Revocation signature does not match key');
    }
    if (revocationSignature.isExpired()) {
      throw new Error('Revocation signature is expired');
    }
    try {
      await revocationSignature.verify(this.keyPacket, enums.signature.keyRevocation, { key: this.keyPacket }, undefined, config);
    } catch (e) {
      throw util.wrapError('Could not verify revocation signature', e);
    }
    const key = await this.clone();
    key.revocationSignatures.push(revocationSignature);
    return key;
  }

  /**
   * Signs primary user of key
   * @param {Array<Key>} privateKeys - decrypted private keys for signing
   * @param {Date} [date] - Use the given date for verification instead of the current time
   * @param {Object} [userID] - User ID to get instead of the primary user, if it exists
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Key>} New public key with new certificate signature.
   * @async
   */
  async signPrimaryUser(privateKeys, date, userID, config = defaultConfig) {
    const { index, user } = await this.getPrimaryUser(date, userID, config);
    const userSign = await user.sign(this.keyPacket, privateKeys, config);
    const key = await this.clone();
    key.users[index] = userSign;
    return key;
  }

  /**
   * Signs all users of key
   * @param {Array<Key>} privateKeys - decrypted private keys for signing
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Key>} New public key with new certificate signature.
   * @async
   */
  async signAllUsers(privateKeys, config = defaultConfig) {
    const that = this;
    const key = await this.clone();
    key.users = await Promise.all(this.users.map(function(user) {
      return user.sign(that.keyPacket, privateKeys, config);
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
  async verifyPrimaryUser(keys, date, userID, config = defaultConfig) {
    const primaryKey = this.keyPacket;
    const { user } = await this.getPrimaryUser(date, userID, config);
    const results = keys ? await user.verifyAllCertifications(primaryKey, keys, undefined, config) :
      [{ keyID: primaryKey.keyID, valid: await user.verify(primaryKey, undefined, config).catch(() => false) }];
    return results;
  }

  /**
   * Verifies all users of key
   * - if no arguments are given, verifies the self certificates;
   * - otherwise, verifies all certificates signed with given keys.
   * @param {Array<Key>} keys - array of keys to verify certificate signatures
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Array<{
   *   userID: String,
   *   keyID: module:type/keyid~KeyID,
   *   valid: Boolean
   * }>>} List of userID, signer's keyID and validity of signature
   * @async
   */
  async verifyAllUsers(keys, config = defaultConfig) {
    const results = [];
    const primaryKey = this.keyPacket;
    await Promise.all(this.users.map(async function(user) {
      const signatures = keys ? await user.verifyAllCertifications(primaryKey, keys, undefined, config) :
        [{ keyID: primaryKey.keyID, valid: await user.verify(primaryKey, undefined, config).catch(() => false) }];
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

  /**
   * Generates a new OpenPGP subkey, and returns a clone of the Key object with the new subkey added.
   * Supports RSA and ECC keys. Defaults to the algorithm and bit size/curve of the primary key. DSA primary keys default to RSA subkeys.
   * @param {ecc|rsa} options.type       The subkey algorithm: ECC or RSA
   * @param {String}  options.curve      (optional) Elliptic curve for ECC keys
   * @param {Integer} options.rsaBits    (optional) Number of bits for RSA subkeys
   * @param {Number}  options.keyExpirationTime (optional) Number of seconds from the key creation time after which the key expires
   * @param {Date}    options.date       (optional) Override the creation date of the key and the key signatures
   * @param {Boolean} options.sign       (optional) Indicates whether the subkey should sign rather than encrypt. Defaults to false
   * @param {Object}  options.config     (optional) custom configuration settings to overwrite those in [config]{@link module:config}
   * @returns {Promise<Key>}
   * @async
   */
  async addSubkey(options = {}) {
    const config = { ...defaultConfig, ...options.config };
    if (!this.isPrivate()) {
      throw new Error("Cannot add a subkey to a public key");
    }
    if (options.passphrase) {
      throw new Error("Subkey could not be encrypted here, please encrypt whole key");
    }
    if (options.rsaBits < config.minRSABits) {
      throw new Error(`rsaBits should be at least ${config.minRSABits}, got: ${options.rsaBits}`);
    }
    const secretKeyPacket = this.primaryKey;
    if (secretKeyPacket.isDummy()) {
      throw new Error("Cannot add subkey to gnu-dummy primary key");
    }
    if (!secretKeyPacket.isDecrypted()) {
      throw new Error("Key is not decrypted");
    }
    const defaultOptions = secretKeyPacket.getAlgorithmInfo();
    defaultOptions.type = defaultOptions.curve ? 'ecc' : 'rsa'; // DSA keys default to RSA
    defaultOptions.rsaBits = defaultOptions.bits || 4096;
    defaultOptions.curve = defaultOptions.curve || 'curve25519';
    options = helper.sanitizeKeyOptions(options, defaultOptions);
    const keyPacket = await helper.generateSecretSubkey(options);
    const bindingSignature = await helper.createBindingSignature(keyPacket, secretKeyPacket, options, config);
    const packetList = this.toPacketlist();
    packetList.push(keyPacket);
    packetList.push(bindingSignature);
    return new Key(packetList);
  }
}

['getKeyID', 'getFingerprint', 'getAlgorithmInfo', 'getCreationTime', 'hasSameFingerprintAs'].forEach(name => {
  Key.prototype[name] =
  SubKey.prototype[name];
});

export default Key;

