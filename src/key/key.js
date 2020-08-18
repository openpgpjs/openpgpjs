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
 * @requires encoding/armor
 * @requires packet
 * @requires enums
 * @requires util
 * @requires key/User
 * @requires key/Subkey
 * @module key/Key
 */

import armor from '../encoding/armor';
import packet from '../packet';
import enums from '../enums';
import util from '../util';
import User from './user';
import SubKey from './subkey';
import * as helper from './helper';

/**
 * @class
 * @classdesc Class that represents an OpenPGP key. Must contain a primary key.
 * Can contain additional subkeys, signatures, user ids, user attributes.
 * @param  {module:packet.List} packetlist The packets that form this key
 * @borrows module:packet.PublicKey#getKeyId as Key#getKeyId
 * @borrows module:packet.PublicKey#getFingerprint as Key#getFingerprint
 * @borrows module:packet.PublicKey#hasSameFingerprintAs as Key#hasSameFingerprintAs
 * @borrows module:packet.PublicKey#getAlgorithmInfo as Key#getAlgorithmInfo
 * @borrows module:packet.PublicKey#getCreationTime as Key#getCreationTime
 * @borrows module:packet.PublicKey#isDecrypted as Key#isDecrypted
 */
export default function Key(packetlist) {
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
  if (!this.keyPacket || !this.users.length) {
    throw new Error('Invalid key: need at least key and user ID packet');
  }
}

Object.defineProperty(Key.prototype, 'primaryKey', {
  get() {
    return this.keyPacket;
  },
  configurable: true,
  enumerable: true
});

/**
 * Transforms packetlist to structured key data
 * @param  {module:packet.List} packetlist The packets that form a key
 */
Key.prototype.packetlist2structure = function(packetlist) {
  let user;
  let primaryKeyId;
  let subKey;
  for (let i = 0; i < packetlist.length; i++) {
    switch (packetlist[i].tag) {
      case enums.packet.publicKey:
      case enums.packet.secretKey:
        this.keyPacket = packetlist[i];
        primaryKeyId = this.getKeyId();
        break;
      case enums.packet.userid:
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
          case enums.signature.cert_generic:
          case enums.signature.cert_persona:
          case enums.signature.cert_casual:
          case enums.signature.cert_positive:
            if (!user) {
              util.print_debug('Dropping certification signatures without preceding user packet');
              continue;
            }
            if (packetlist[i].issuerKeyId.equals(primaryKeyId)) {
              user.selfCertifications.push(packetlist[i]);
            } else {
              user.otherCertifications.push(packetlist[i]);
            }
            break;
          case enums.signature.cert_revocation:
            if (user) {
              user.revocationSignatures.push(packetlist[i]);
            } else {
              this.directSignatures.push(packetlist[i]);
            }
            break;
          case enums.signature.key:
            this.directSignatures.push(packetlist[i]);
            break;
          case enums.signature.subkey_binding:
            if (!subKey) {
              util.print_debug('Dropping subkey binding signature without preceding subkey packet');
              continue;
            }
            subKey.bindingSignatures.push(packetlist[i]);
            break;
          case enums.signature.key_revocation:
            this.revocationSignatures.push(packetlist[i]);
            break;
          case enums.signature.subkey_revocation:
            if (!subKey) {
              util.print_debug('Dropping subkey revocation signature without preceding subkey packet');
              continue;
            }
            subKey.revocationSignatures.push(packetlist[i]);
            break;
        }
        break;
    }
  }
};

/**
 * Transforms structured key data to packetlist
 * @returns {module:packet.List} The packets that form a key
 */
Key.prototype.toPacketlist = function() {
  const packetlist = new packet.List();
  packetlist.push(this.keyPacket);
  packetlist.concat(this.revocationSignatures);
  packetlist.concat(this.directSignatures);
  this.users.map(user => packetlist.concat(user.toPacketlist()));
  this.subKeys.map(subKey => packetlist.concat(subKey.toPacketlist()));
  return packetlist;
};

/**
 * Returns an array containing all public or private subkeys matching keyId;
 * If keyId is not present, returns all subkeys.
 * @param  {type/keyid} keyId
 * @returns {Array<module:key~SubKey>}
 */
Key.prototype.getSubkeys = function(keyId = null) {
  const subKeys = [];
  this.subKeys.forEach(subKey => {
    if (!keyId || subKey.getKeyId().equals(keyId, true)) {
      subKeys.push(subKey);
    }
  });
  return subKeys;
};

/**
 * Returns an array containing all public or private keys matching keyId.
 * If keyId is not present, returns all keys starting with the primary key.
 * @param  {type/keyid} keyId
 * @returns {Array<module:key.Key|module:key~SubKey>}
 */
Key.prototype.getKeys = function(keyId = null) {
  const keys = [];
  if (!keyId || this.getKeyId().equals(keyId, true)) {
    keys.push(this);
  }
  return keys.concat(this.getSubkeys(keyId));
};

/**
 * Returns key IDs of all keys
 * @returns {Array<module:type/keyid>}
 */
Key.prototype.getKeyIds = function() {
  return this.getKeys().map(key => key.getKeyId());
};

/**
 * Returns userids
 * @returns {Array<string>} array of userids
 */
Key.prototype.getUserIds = function() {
  return this.users.map(user => {
    return user.userId ? user.userId.userid : null;
  }).filter(userid => userid !== null);
};

/**
 * Returns true if this is a public key
 * @returns {Boolean}
 */
Key.prototype.isPublic = function() {
  return this.keyPacket.tag === enums.packet.publicKey;
};

/**
 * Returns true if this is a private key
 * @returns {Boolean}
 */
Key.prototype.isPrivate = function() {
  return this.keyPacket.tag === enums.packet.secretKey;
};

/**
 * Returns key as public key (shallow copy)
 * @returns {module:key.Key} new public Key
 */
Key.prototype.toPublic = function() {
  const packetlist = new packet.List();
  const keyPackets = this.toPacketlist();
  let bytes;
  let pubKeyPacket;
  let pubSubkeyPacket;
  for (let i = 0; i < keyPackets.length; i++) {
    switch (keyPackets[i].tag) {
      case enums.packet.secretKey:
        bytes = keyPackets[i].writePublicKey();
        pubKeyPacket = new packet.PublicKey();
        pubKeyPacket.read(bytes);
        packetlist.push(pubKeyPacket);
        break;
      case enums.packet.secretSubkey:
        bytes = keyPackets[i].writePublicKey();
        pubSubkeyPacket = new packet.PublicSubkey();
        pubSubkeyPacket.read(bytes);
        packetlist.push(pubSubkeyPacket);
        break;
      default:
        packetlist.push(keyPackets[i]);
    }
  }
  return new Key(packetlist);
};

/**
 * Returns ASCII armored text of key
 * @returns {ReadableStream<String>} ASCII armor
 */
Key.prototype.armor = function() {
  const type = this.isPublic() ? enums.armor.public_key : enums.armor.private_key;
  return armor.encode(type, this.toPacketlist().write());
};

/**
 * Returns last created key or key by given keyId that is available for signing and verification
 * @param  {module:type/keyid} keyId, optional
 * @param  {Date} date (optional) use the given date for verification instead of the current time
 * @param  {Object} userId, optional user ID
 * @returns {Promise<module:key.Key|module:key~SubKey|null>} key or null if no signing key has been found
 * @async
 */
Key.prototype.getSigningKey = async function (keyId = null, date = new Date(), userId = {}) {
  await this.verifyPrimaryKey(date, userId);
  const primaryKey = this.keyPacket;
  const subKeys = this.subKeys.slice().sort((a, b) => b.keyPacket.created - a.keyPacket.created);
  let exception;
  for (let i = 0; i < subKeys.length; i++) {
    if (!keyId || subKeys[i].getKeyId().equals(keyId)) {
      try {
        await subKeys[i].verify(primaryKey, date);
        const dataToVerify = { key: primaryKey, bind: subKeys[i].keyPacket };
        const bindingSignature = await helper.getLatestValidSignature(subKeys[i].bindingSignatures, primaryKey, enums.signature.subkey_binding, dataToVerify, date);
        if (
          bindingSignature &&
          bindingSignature.embeddedSignature &&
          helper.isValidSigningKeyPacket(subKeys[i].keyPacket, bindingSignature) &&
          await helper.getLatestValidSignature([bindingSignature.embeddedSignature], subKeys[i].keyPacket, enums.signature.key_binding, dataToVerify, date)
        ) {
          return subKeys[i];
        }
      } catch (e) {
        exception = e;
      }
    }
  }
  const primaryUser = await this.getPrimaryUser(date, userId);
  if ((!keyId || primaryKey.getKeyId().equals(keyId)) &&
      helper.isValidSigningKeyPacket(primaryKey, primaryUser.selfCertification)) {
    return this;
  }
  throw util.wrapError('Could not find valid signing key packet in key ' + this.getKeyId().toHex(), exception);
};

/**
 * Returns last created key or key by given keyId that is available for encryption or decryption
 * @param  {module:type/keyid} keyId, optional
 * @param  {Date}              date, optional
 * @param  {String}            userId, optional
 * @returns {Promise<module:key.Key|module:key~SubKey|null>} key or null if no encryption key has been found
 * @async
 */
Key.prototype.getEncryptionKey = async function(keyId, date = new Date(), userId = {}) {
  await this.verifyPrimaryKey(date, userId);
  const primaryKey = this.keyPacket;
  // V4: by convention subkeys are preferred for encryption service
  const subKeys = this.subKeys.slice().sort((a, b) => b.keyPacket.created - a.keyPacket.created);
  let exception;
  for (let i = 0; i < subKeys.length; i++) {
    if (!keyId || subKeys[i].getKeyId().equals(keyId)) {
      try {
        await subKeys[i].verify(primaryKey, date);
        const dataToVerify = { key: primaryKey, bind: subKeys[i].keyPacket };
        const bindingSignature = await helper.getLatestValidSignature(subKeys[i].bindingSignatures, primaryKey, enums.signature.subkey_binding, dataToVerify, date);
        if (bindingSignature && helper.isValidEncryptionKeyPacket(subKeys[i].keyPacket, bindingSignature)) {
          return subKeys[i];
        }
      } catch (e) {
        exception = e;
      }
    }
  }
  // if no valid subkey for encryption, evaluate primary key
  const primaryUser = await this.getPrimaryUser(date, userId);
  if ((!keyId || primaryKey.getKeyId().equals(keyId)) &&
      helper.isValidEncryptionKeyPacket(primaryKey, primaryUser.selfCertification)) {
    return this;
  }
  throw util.wrapError('Could not find valid encryption key packet in key ' + this.getKeyId().toHex(), exception);
};

/**
 * Returns all keys that are available for decryption, matching the keyId when given
 * This is useful to retrieve keys for session key decryption
 * @param  {module:type/keyid} keyId, optional
 * @param  {Date}              date, optional
 * @param  {String}            userId, optional
 * @returns {Promise<Array<module:key.Key|module:key~SubKey>>} array of decryption keys
 * @async
 */
Key.prototype.getDecryptionKeys = async function(keyId, date = new Date(), userId = {}) {
  const primaryKey = this.keyPacket;
  const keys = [];
  for (let i = 0; i < this.subKeys.length; i++) {
    if (!keyId || this.subKeys[i].getKeyId().equals(keyId, true)) {
      try {
        const dataToVerify = { key: primaryKey, bind: this.subKeys[i].keyPacket };
        const bindingSignature = await helper.getLatestValidSignature(this.subKeys[i].bindingSignatures, primaryKey, enums.signature.subkey_binding, dataToVerify, date);
        if (bindingSignature && helper.isValidDecryptionKeyPacket(bindingSignature)) {
          keys.push(this.subKeys[i]);
        }
      } catch (e) {}
    }
  }

  // evaluate primary key
  const primaryUser = await this.getPrimaryUser(date, userId);
  if ((!keyId || primaryKey.getKeyId().equals(keyId, true)) &&
      helper.isValidDecryptionKeyPacket(primaryUser.selfCertification)) {
    keys.push(this);
  }

  return keys;
};

/**
 * Encrypts all secret key and subkey packets matching keyId
 * @param  {String|Array<String>} passphrases - if multiple passphrases, then should be in same order as packets each should encrypt
 * @param  {module:type/keyid} keyId
 * @returns {Promise<Array<module:packet.SecretKey|module:packet.SecretSubkey>>}
 * @async
 */
Key.prototype.encrypt = async function(passphrases, keyId = null) {
  if (!this.isPrivate()) {
    throw new Error("Nothing to encrypt in a public key");
  }

  const keys = this.getKeys(keyId);
  passphrases = util.isArray(passphrases) ? passphrases : new Array(keys.length).fill(passphrases);
  if (passphrases.length !== keys.length) {
    throw new Error("Invalid number of passphrases for key");
  }

  return Promise.all(keys.map(async function(key, i) {
    const { keyPacket } = key;
    await keyPacket.encrypt(passphrases[i]);
    keyPacket.clearPrivateParams();
    return keyPacket;
  }));
};

/**
 * Decrypts all secret key and subkey packets matching keyId
 * @param  {String|Array<String>} passphrases
 * @param  {module:type/keyid} keyId
 * @returns {Promise<Boolean>} true if all matching key and subkey packets decrypted successfully
 * @throws {Error} if any matching key or subkey packets did not decrypt successfully
 * @async
 */
Key.prototype.decrypt = async function(passphrases, keyId = null) {
  if (!this.isPrivate()) {
    throw new Error("Nothing to decrypt in a public key");
  }
  passphrases = util.isArray(passphrases) ? passphrases : [passphrases];

  const results = await Promise.all(this.getKeys(keyId).map(async function(key) {
    let decrypted = false;
    let error = null;
    await Promise.all(passphrases.map(async function(passphrase) {
      try {
        await key.keyPacket.decrypt(passphrase);
        // If we are decrypting a single key packet, we also validate it directly
        if (keyId) await key.keyPacket.validate();
        decrypted = true;
      } catch (e) {
        error = e;
      }
    }));
    if (!decrypted) {
      throw error;
    }
    return decrypted;
  }));

  if (!keyId) {
    // The full key should be decrypted and we can validate it all
    await this.validate();
  }

  return results.every(result => result === true);
};

/**
 * Check whether the private and public primary key parameters correspond
 * Together with verification of binding signatures, this guarantees key integrity
 * In case of gnu-dummy primary key, it is enough to validate any signing subkeys
 *   otherwise all encryption subkeys are validated
 * If only gnu-dummy keys are found, we cannot properly validate so we throw an error
 * @throws {Error} if validation was not successful and the key cannot be trusted
 * @async
 */
Key.prototype.validate = async function() {
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
    const signingKey = await this.getSigningKey(null, null);
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
};

/**
 * Clear private key parameters
 */
Key.prototype.clearPrivateParams = function () {
  if (!this.isPrivate()) {
    throw new Error("Can't clear private parameters of a public key");
  }
  this.getKeys().forEach(({ keyPacket }) => {
    if (keyPacket.isDecrypted()) {
      keyPacket.clearPrivateParams();
    }
  });
};

/**
 * Checks if a signature on a key is revoked
 * @param  {module:packet.SecretKey|
 * @param  {module:packet.Signature}  signature    The signature to verify
 * @param  {module:packet.PublicSubkey|
 *          module:packet.SecretSubkey|
 *          module:packet.PublicKey|
 *          module:packet.SecretKey} key, optional The key to verify the signature
 * @param  {Date}                     date          Use the given date instead of the current time
 * @returns {Promise<Boolean>}                      True if the certificate is revoked
 * @async
 */
Key.prototype.isRevoked = async function(signature, key, date = new Date()) {
  return helper.isDataRevoked(
    this.keyPacket, enums.signature.key_revocation, { key: this.keyPacket }, this.revocationSignatures, signature, key, date
  );
};

/**
 * Verify primary key. Checks for revocation signatures, expiration time
 * and valid self signature. Throws if the primary key is invalid.
 * @param {Date} date (optional) use the given date for verification instead of the current time
 * @param  {Object} userId (optional) user ID
 * @returns {Promise<true>} The status of the primary key
 * @async
 */
Key.prototype.verifyPrimaryKey = async function(date = new Date(), userId = {}) {
  const primaryKey = this.keyPacket;
  // check for key revocation signatures
  if (await this.isRevoked(null, null, date)) {
    throw new Error('Primary key is revoked');
  }
  // check for at least one self signature. Self signature of user ID not mandatory
  // See {@link https://tools.ietf.org/html/rfc4880#section-11.1}
  if (!this.users.some(user => user.userId && user.selfCertifications.length)) {
    throw new Error('No self-certifications');
  }
  // check for valid, unrevoked, unexpired self signature
  const { selfCertification } = await this.getPrimaryUser(date, userId);
  // check for expiration time
  if (helper.isDataExpired(primaryKey, selfCertification, date)) {
    throw new Error('Primary key is expired');
  }
};

/**
 * Returns the latest date when the key can be used for encrypting, signing, or both, depending on the `capabilities` paramater.
 * When `capabilities` is null, defaults to returning the expiry date of the primary key.
 * Returns null if `capabilities` is passed and the key does not have the specified capabilities or is revoked or invalid.
 * Returns Infinity if the key doesn't expire.
 * @param  {encrypt|sign|encrypt_sign} capabilities, optional
 * @param  {module:type/keyid} keyId, optional
 * @param  {Object} userId, optional user ID
 * @returns {Promise<Date | Infinity | null>}
 * @async
 */
Key.prototype.getExpirationTime = async function(capabilities, keyId, userId) {
  const primaryUser = await this.getPrimaryUser(null, userId);
  const selfCert = primaryUser.selfCertification;
  const keyExpiry = helper.getExpirationTime(this.keyPacket, selfCert);
  const sigExpiry = selfCert.getExpirationTime();
  let expiry = keyExpiry < sigExpiry ? keyExpiry : sigExpiry;
  if (capabilities === 'encrypt' || capabilities === 'encrypt_sign') {
    const encryptKey =
      await this.getEncryptionKey(keyId, expiry, userId).catch(() => {}) ||
      await this.getEncryptionKey(keyId, null, userId).catch(() => {});
    if (!encryptKey) return null;
    const encryptExpiry = await encryptKey.getExpirationTime(this.keyPacket);
    if (encryptExpiry < expiry) expiry = encryptExpiry;
  }
  if (capabilities === 'sign' || capabilities === 'encrypt_sign') {
    const signKey =
      await this.getSigningKey(keyId, expiry, userId).catch(() => {}) ||
      await this.getSigningKey(keyId, null, userId).catch(() => {});
    if (!signKey) return null;
    const signExpiry = await signKey.getExpirationTime(this.keyPacket);
    if (signExpiry < expiry) expiry = signExpiry;
  }
  return expiry;
};

/**
 * Returns primary user and most significant (latest valid) self signature
 * - if multiple primary users exist, returns the one with the latest self signature
 * - otherwise, returns the user with the latest self signature
 * @param  {Date} date (optional) use the given date for verification instead of the current time
 * @param  {Object} userId (optional) user ID to get instead of the primary user, if it exists
 * @returns {Promise<{user: module:key.User,
 *                    selfCertification: module:packet.Signature}>} The primary user and the self signature
 * @async
 */
Key.prototype.getPrimaryUser = async function(date = new Date(), userId = {}) {
  const primaryKey = this.keyPacket;
  const users = [];
  let exception;
  for (let i = 0; i < this.users.length; i++) {
    try {
      const user = this.users[i];
      if (!user.userId) {
        continue;
      }
      if (
        (userId.name !== undefined && user.userId.name !== userId.name) ||
        (userId.email !== undefined && user.userId.email !== userId.email) ||
        (userId.comment !== undefined && user.userId.comment !== userId.comment)
      ) {
        throw new Error('Could not find user that matches that user ID');
      }
      const dataToVerify = { userId: user.userId, key: primaryKey };
      const selfCertification = await helper.getLatestValidSignature(user.selfCertifications, primaryKey, enums.signature.cert_generic, dataToVerify, date);
      users.push({ index: i, user, selfCertification });
    } catch (e) {
      exception = e;
    }
  }
  if (!users.length) {
    throw exception || new Error('Could not find primary user');
  }
  await Promise.all(users.map(async function (a) {
    return a.user.revoked || a.user.isRevoked(primaryKey, a.selfCertification, null, date);
  }));
  // sort by primary user flag and signature creation time
  const primaryUser = users.sort(function(a, b) {
    const A = a.selfCertification;
    const B = b.selfCertification;
    return B.revoked - A.revoked || A.isPrimaryUserID - B.isPrimaryUserID || A.created - B.created;
  }).pop();
  const { user, selfCertification: cert } = primaryUser;
  if (cert.revoked || await user.isRevoked(primaryKey, cert, null, date)) {
    throw new Error('Primary user is revoked');
  }
  return primaryUser;
};

/**
 * Update key with new components from specified key with same key ID:
 * users, subkeys, certificates are merged into the destination key,
 * duplicates and expired signatures are ignored.
 *
 * If the specified key is a private key and the destination key is public,
 * the destination key is transformed to a private key.
 * @param  {module:key.Key} key Source key to merge
 * @returns {Promise<undefined>}
 * @async
 */
Key.prototype.update = async function(key) {
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
    return helper.isDataRevoked(this.keyPacket, enums.signature.key_revocation, this, [srcRevSig], null, key.keyPacket);
  });
  // direct signatures
  await helper.mergeSignatures(key, this, 'directSignatures');
  // TODO replace when Promise.some or Promise.any are implemented
  // users
  await Promise.all(key.users.map(async srcUser => {
    let found = false;
    await Promise.all(this.users.map(async dstUser => {
      if ((srcUser.userId && dstUser.userId &&
            (srcUser.userId.userid === dstUser.userId.userid)) ||
          (srcUser.userAttribute && (srcUser.userAttribute.equals(dstUser.userAttribute)))) {
        await dstUser.update(srcUser, this.keyPacket);
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
        await dstSubKey.update(srcSubKey, this.keyPacket);
        found = true;
      }
    }));
    if (!found) {
      this.subKeys.push(srcSubKey);
    }
  }));
};

/**
 * Revokes the key
 * @param  {Object} reasonForRevocation optional, object indicating the reason for revocation
 * @param  {module:enums.reasonForRevocation} reasonForRevocation.flag optional, flag indicating the reason for revocation
 * @param  {String} reasonForRevocation.string optional, string explaining the reason for revocation
 * @param  {Date} date optional, override the creationtime of the revocation signature
 * @returns {Promise<module:key.Key>} new key with revocation signature
 * @async
 */
Key.prototype.revoke = async function({
  flag: reasonForRevocationFlag = enums.reasonForRevocation.no_reason,
  string: reasonForRevocationString = ''
} = {}, date = new Date()) {
  if (this.isPublic()) {
    throw new Error('Need private key for revoking');
  }
  const dataToSign = { key: this.keyPacket };
  const key = new Key(this.toPacketlist());
  key.revocationSignatures.push(await helper.createSignaturePacket(dataToSign, null, this.keyPacket, {
    signatureType: enums.signature.key_revocation,
    reasonForRevocationFlag: enums.write(enums.reasonForRevocation, reasonForRevocationFlag),
    reasonForRevocationString
  }, date));
  return key;
};

/**
 * Get revocation certificate from a revoked key.
 *   (To get a revocation certificate for an unrevoked key, call revoke() first.)
 * @param  {Date} date Use the given date instead of the current time
 * @returns {Promise<String>} armored revocation certificate
 * @async
 */
Key.prototype.getRevocationCertificate = async function(date = new Date()) {
  const dataToVerify = { key: this.keyPacket };
  const revocationSignature = await helper.getLatestValidSignature(this.revocationSignatures, this.keyPacket, enums.signature.key_revocation, dataToVerify, date);
  const packetlist = new packet.List();
  packetlist.push(revocationSignature);
  return armor.encode(enums.armor.public_key, packetlist.write(), null, null, 'This is a revocation certificate');
};

/**
 * Applies a revocation certificate to a key
 * This adds the first signature packet in the armored text to the key,
 * if it is a valid revocation signature.
 * @param  {String} revocationCertificate armored revocation certificate
 * @returns {Promise<module:key.Key>} new revoked key
 * @async
 */
Key.prototype.applyRevocationCertificate = async function(revocationCertificate) {
  const input = await armor.decode(revocationCertificate);
  const packetlist = new packet.List();
  await packetlist.read(input.data);
  const revocationSignature = packetlist.findPacket(enums.packet.signature);
  if (!revocationSignature || revocationSignature.signatureType !== enums.signature.key_revocation) {
    throw new Error('Could not find revocation signature packet');
  }
  if (!revocationSignature.issuerKeyId.equals(this.getKeyId())) {
    throw new Error('Revocation signature does not match key');
  }
  if (revocationSignature.isExpired()) {
    throw new Error('Revocation signature is expired');
  }
  try {
    await revocationSignature.verify(this.keyPacket, enums.signature.key_revocation, { key: this.keyPacket });
  } catch (e) {
    throw util.wrapError('Could not verify revocation signature', e);
  }
  const key = new Key(this.toPacketlist());
  key.revocationSignatures.push(revocationSignature);
  return key;
};

/**
 * Signs primary user of key
 * @param  {Array<module:key.Key>} privateKey decrypted private keys for signing
 * @param  {Date} date (optional) use the given date for verification instead of the current time
 * @param  {Object} userId (optional) user ID to get instead of the primary user, if it exists
 * @returns {Promise<module:key.Key>} new public key with new certificate signature
 * @async
 */
Key.prototype.signPrimaryUser = async function(privateKeys, date, userId) {
  const { index, user } = await this.getPrimaryUser(date, userId);
  const userSign = await user.sign(this.keyPacket, privateKeys);
  const key = new Key(this.toPacketlist());
  key.users[index] = userSign;
  return key;
};

/**
 * Signs all users of key
 * @param  {Array<module:key.Key>} privateKeys decrypted private keys for signing
 * @returns {Promise<module:key.Key>} new public key with new certificate signature
 * @async
 */
Key.prototype.signAllUsers = async function(privateKeys) {
  const that = this;
  const key = new Key(this.toPacketlist());
  key.users = await Promise.all(this.users.map(function(user) {
    return user.sign(that.keyPacket, privateKeys);
  }));
  return key;
};

/**
 * Verifies primary user of key
 * - if no arguments are given, verifies the self certificates;
 * - otherwise, verifies all certificates signed with given keys.
 * @param  {Array<module:key.Key>} keys array of keys to verify certificate signatures
 * @param  {Date} date (optional) use the given date for verification instead of the current time
 * @param  {Object} userId (optional) user ID to get instead of the primary user, if it exists
 * @returns {Promise<Array<{keyid: module:type/keyid,
 *                          valid: Boolean}>>}    List of signer's keyid and validity of signature
 * @async
 */
Key.prototype.verifyPrimaryUser = async function(keys, date, userId) {
  const primaryKey = this.keyPacket;
  const { user } = await this.getPrimaryUser(date, userId);
  const results = keys ? await user.verifyAllCertifications(primaryKey, keys) :
    [{ keyid: primaryKey.keyid, valid: await user.verify(primaryKey).catch(() => false) }];
  return results;
};

/**
 * Verifies all users of key
 * - if no arguments are given, verifies the self certificates;
 * - otherwise, verifies all certificates signed with given keys.
 * @param  {Array<module:key.Key>} keys array of keys to verify certificate signatures
 * @returns {Promise<Array<{userid: String,
 *                          keyid: module:type/keyid,
 *                          valid: Boolean}>>} list of userid, signer's keyid and validity of signature
 * @async
 */
Key.prototype.verifyAllUsers = async function(keys) {
  const results = [];
  const primaryKey = this.keyPacket;
  await Promise.all(this.users.map(async function(user) {
    const signatures = keys ? await user.verifyAllCertifications(primaryKey, keys) :
      [{ keyid: primaryKey.keyid, valid: await user.verify(primaryKey).catch(() => false) }];
    signatures.forEach(signature => {
      results.push({
        userid: user.userId.userid,
        keyid: signature.keyid,
        valid: signature.valid
      });
    });
  }));
  return results;
};

/**
 * Generates a new OpenPGP subkey, and returns a clone of the Key object with the new subkey added.
 * Supports RSA and ECC keys. Defaults to the algorithm and bit size/curve of the primary key.
 * @param {Integer} options.rsaBits    number of bits for the key creation.
 * @param {Number} [options.keyExpirationTime=0]
 *                             The number of seconds after the key creation time that the key expires
 * @param {String} curve       (optional) Elliptic curve for ECC keys
 * @param {Date} date          (optional) Override the creation date of the key and the key signatures
 * @param {Boolean} sign       (optional) Indicates whether the subkey should sign rather than encrypt. Defaults to false
 * @returns {Promise<module:key.Key>}
 * @async
 */
Key.prototype.addSubkey = async function(options = {}) {
  if (!this.isPrivate()) {
    throw new Error("Cannot add a subkey to a public key");
  }
  if (options.passphrase) {
    throw new Error("Subkey could not be encrypted here, please encrypt whole key");
  }
  if (util.getWebCryptoAll() && options.rsaBits < 2048) {
    throw new Error('When using webCrypto rsaBits should be 2048 or 4096, found: ' + options.rsaBits);
  }
  const secretKeyPacket = this.primaryKey;
  if (!secretKeyPacket.isDecrypted()) {
    throw new Error("Key is not decrypted");
  }
  const defaultOptions = secretKeyPacket.getAlgorithmInfo();
  options = helper.sanitizeKeyOptions(options, defaultOptions);
  const keyPacket = await helper.generateSecretSubkey(options);
  const bindingSignature = await helper.createBindingSignature(keyPacket, secretKeyPacket, options);
  const packetList = this.toPacketlist();
  packetList.push(keyPacket);
  packetList.push(bindingSignature);
  return new Key(packetList);
};

['getKeyId', 'getFingerprint', 'getAlgorithmInfo', 'getCreationTime', 'isDecrypted', 'hasSameFingerprintAs'].forEach(name => {
  Key.prototype[name] =
  SubKey.prototype[name];
});
