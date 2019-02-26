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
 * @requires crypto
 * @requires packet
 * @requires config
 * @requires enums
 * @requires util
 * @module key
 */

import armor from './encoding/armor';
import crypto from './crypto';
import packet from './packet';
import config from './config';
import enums from './enums';
import util from './util';

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
export function Key(packetlist) {
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
              checkRevocationKey(packetlist[i], primaryKeyId);
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
            checkRevocationKey(packetlist[i], primaryKeyId);
            this.directSignatures.push(packetlist[i]);
            break;
          case enums.signature.subkey_binding:
            if (!subKey) {
              util.print_debug('Dropping subkey binding signature without preceding subkey packet');
              continue;
            }
            checkRevocationKey(packetlist[i], primaryKeyId);
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
Key.prototype.getSubkeys = function(keyId=null) {
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
Key.prototype.getKeys = function(keyId=null) {
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
 * Returns the valid and non-expired signature that has the latest creation date, while ignoring signatures created in the future.
 * @param  {Array<module:packet.Signature>} signatures  List of signatures
 * @param  {Date}                           date        Use the given date instead of the current time
 * @returns {Promise<module:packet.Signature>} The latest valid signature
 * @async
 */
async function getLatestValidSignature(signatures, primaryKey, signatureType, dataToVerify, date=new Date()) {
  let signature;
  for (let i = signatures.length - 1; i >= 0; i--) {
    if (
      (!signature || signatures[i].created >= signature.created) &&
      // check binding signature is not expired (ie, check for V4 expiration time)
      !signatures[i].isExpired(date) &&
      // check binding signature is verified
      (signatures[i].verified || await signatures[i].verify(primaryKey, signatureType, dataToVerify))
    ) {
      signature = signatures[i];
    }
  }
  return signature;
}

/**
 * Returns last created key or key by given keyId that is available for signing and verification
 * @param  {module:type/keyid} keyId, optional
 * @param  {Date} date (optional) use the given date for verification instead of the current time
 * @param  {Object} userId, optional user ID
 * @returns {Promise<module:key.Key|module:key~SubKey|null>} key or null if no signing key has been found
 * @async
 */
Key.prototype.getSigningKey = async function (keyId=null, date=new Date(), userId={}) {
  const primaryKey = this.keyPacket;
  if (await this.verifyPrimaryKey(date, userId) === enums.keyStatus.valid) {
    const subKeys = this.subKeys.slice().sort((a, b) => b.keyPacket.created - a.keyPacket.created);
    for (let i = 0; i < subKeys.length; i++) {
      if (!keyId || subKeys[i].getKeyId().equals(keyId)) {
        if (await subKeys[i].verify(primaryKey, date) === enums.keyStatus.valid) {
          const dataToVerify = { key: primaryKey, bind: subKeys[i].keyPacket };
          const bindingSignature = await getLatestValidSignature(subKeys[i].bindingSignatures, primaryKey, enums.signature.subkey_binding, dataToVerify, date);
          if (
            bindingSignature &&
            bindingSignature.embeddedSignature &&
            isValidSigningKeyPacket(subKeys[i].keyPacket, bindingSignature) &&
            await getLatestValidSignature([bindingSignature.embeddedSignature], subKeys[i].keyPacket, enums.signature.key_binding, dataToVerify, date)
          ) {
            return subKeys[i];
          }
        }
      }
    }
    const primaryUser = await this.getPrimaryUser(date, userId);
    if (primaryUser && (!keyId || primaryKey.getKeyId().equals(keyId)) &&
        isValidSigningKeyPacket(primaryKey, primaryUser.selfCertification)) {
      return this;
    }
  }
  return null;

  function isValidSigningKeyPacket(keyPacket, signature) {
    if (!signature.verified || signature.revoked !== false) { // Sanity check
      throw new Error('Signature not verified');
    }
    return keyPacket.algorithm !== enums.read(enums.publicKey, enums.publicKey.rsa_encrypt) &&
      keyPacket.algorithm !== enums.read(enums.publicKey, enums.publicKey.elgamal) &&
      keyPacket.algorithm !== enums.read(enums.publicKey, enums.publicKey.ecdh) &&
      (!signature.keyFlags ||
        (signature.keyFlags[0] & enums.keyFlags.sign_data) !== 0);
  }
};

/**
 * Returns last created key or key by given keyId that is available for encryption or decryption
 * @param  {module:type/keyid} keyId, optional
 * @param  {Date}              date, optional
 * @param  {String}            userId, optional
 * @returns {Promise<module:key.Key|module:key~SubKey|null>} key or null if no encryption key has been found
 * @async
 */
Key.prototype.getEncryptionKey = async function(keyId, date=new Date(), userId={}) {
  const primaryKey = this.keyPacket;
  if (await this.verifyPrimaryKey(date, userId) === enums.keyStatus.valid) {
    // V4: by convention subkeys are preferred for encryption service
    const subKeys = this.subKeys.slice().sort((a, b) => b.keyPacket.created - a.keyPacket.created);
    for (let i = 0; i < subKeys.length; i++) {
      if (!keyId || subKeys[i].getKeyId().equals(keyId)) {
        if (await subKeys[i].verify(primaryKey, date) === enums.keyStatus.valid) {
          const dataToVerify = { key: primaryKey, bind: subKeys[i].keyPacket };
          const bindingSignature = await getLatestValidSignature(subKeys[i].bindingSignatures, primaryKey, enums.signature.subkey_binding, dataToVerify, date);
          if (bindingSignature && isValidEncryptionKeyPacket(subKeys[i].keyPacket, bindingSignature)) {
            return subKeys[i];
          }
        }
      }
    }
    // if no valid subkey for encryption, evaluate primary key
    const primaryUser = await this.getPrimaryUser(date, userId);
    if (primaryUser && (!keyId || primaryKey.getKeyId().equals(keyId)) &&
        isValidEncryptionKeyPacket(primaryKey, primaryUser.selfCertification)) {
      return this;
    }
  }
  return null;

  function isValidEncryptionKeyPacket(keyPacket, signature) {
    if (!signature.verified || signature.revoked !== false) { // Sanity check
      throw new Error('Signature not verified');
    }
    return keyPacket.algorithm !== enums.read(enums.publicKey, enums.publicKey.dsa) &&
      keyPacket.algorithm !== enums.read(enums.publicKey, enums.publicKey.rsa_sign) &&
      keyPacket.algorithm !== enums.read(enums.publicKey, enums.publicKey.ecdsa) &&
      keyPacket.algorithm !== enums.read(enums.publicKey, enums.publicKey.eddsa) &&
      (!signature.keyFlags ||
        (signature.keyFlags[0] & enums.keyFlags.encrypt_communication) !== 0 ||
        (signature.keyFlags[0] & enums.keyFlags.encrypt_storage) !== 0);
  }
};

/**
 * Encrypts all secret key and subkey packets matching keyId
 * @param  {String|Array<String>} passphrases - if multiple passphrases, then should be in same order as packets each should encrypt
 * @param  {module:type/keyid} keyId
 * @returns {Promise<Array<module:packet.SecretKey|module:packet.SecretSubkey>>}
 * @async
 */
Key.prototype.encrypt = async function(passphrases, keyId=null) {
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
 * @async
 */
Key.prototype.decrypt = async function(passphrases, keyId=null) {
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
  return results.every(result => result === true);
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
Key.prototype.isRevoked = async function(signature, key, date=new Date()) {
  return isDataRevoked(
    this.keyPacket, enums.signature.key_revocation, { key: this.keyPacket }, this.revocationSignatures, signature, key, date
  );
};

/**
 * Verify primary key. Checks for revocation signatures, expiration time
 * and valid self signature
 * @param {Date} date (optional) use the given date for verification instead of the current time
 * @param  {Object} userId (optional) user ID
 * @returns {Promise<module:enums.keyStatus>} The status of the primary key
 * @async
 */
Key.prototype.verifyPrimaryKey = async function(date=new Date(), userId={}) {
  const primaryKey = this.keyPacket;
  // check for key revocation signatures
  if (await this.isRevoked(null, null, date)) {
    return enums.keyStatus.revoked;
  }
  // check for at least one self signature. Self signature of user ID not mandatory
  // See {@link https://tools.ietf.org/html/rfc4880#section-11.1}
  if (!this.users.some(user => user.userId && user.selfCertifications.length)) {
    return enums.keyStatus.no_self_cert;
  }
  // check for valid, unrevoked, unexpired self signature
  const { user, selfCertification } = await this.getPrimaryUser(date, userId) || {};
  if (!user) {
    return enums.keyStatus.invalid;
  }
  // check for expiration time
  if (isDataExpired(primaryKey, selfCertification, date)) {
    return enums.keyStatus.expired;
  }
  return enums.keyStatus.valid;
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
  if (!primaryUser) {
    throw new Error('Could not find primary user');
  }
  const selfCert = primaryUser.selfCertification;
  const keyExpiry = getExpirationTime(this.keyPacket, selfCert);
  const sigExpiry = selfCert.getExpirationTime();
  let expiry = keyExpiry < sigExpiry ? keyExpiry : sigExpiry;
  if (capabilities === 'encrypt' || capabilities === 'encrypt_sign') {
    const encryptKey =
      await this.getEncryptionKey(keyId, expiry, userId) ||
      await this.getEncryptionKey(keyId, null, userId);
    if (!encryptKey) return null;
    const encryptExpiry = await encryptKey.getExpirationTime(this.keyPacket);
    if (encryptExpiry < expiry) expiry = encryptExpiry;
  }
  if (capabilities === 'sign' || capabilities === 'encrypt_sign') {
    const signKey =
      await this.getSigningKey(keyId, expiry, userId) ||
      await this.getSigningKey(keyId, null, userId);
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
Key.prototype.getPrimaryUser = async function(date=new Date(), userId={}) {
  const primaryKey = this.keyPacket;
  const users = [];
  for (let i = 0; i < this.users.length; i++) {
    const user = this.users[i];
    if (!user.userId || !(
      (userId.name === undefined || user.userId.name === userId.name) &&
      (userId.email === undefined || user.userId.email === userId.email) &&
      (userId.comment === undefined || user.userId.comment === userId.comment)
    )) continue;
    const dataToVerify = { userId: user.userId, key: primaryKey };
    const selfCertification = await getLatestValidSignature(user.selfCertifications, primaryKey, enums.signature.cert_generic, dataToVerify, date);
    if (!selfCertification) continue;
    users.push({ index: i, user, selfCertification });
  }
  if (!users.length) {
    if (userId.name !== undefined || userId.email !== undefined ||
        userId.comment !== undefined) {
      throw new Error('Could not find user that matches that user ID');
    }
    return null;
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
    return null;
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
  if (await key.verifyPrimaryKey() === enums.keyStatus.invalid) {
    return;
  }
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
  await mergeSignatures(key, this, 'revocationSignatures', srcRevSig => {
    return isDataRevoked(this.keyPacket, enums.signature.key_revocation, this, [srcRevSig], null, key.keyPacket);
  });
  // direct signatures
  await mergeSignatures(key, this, 'directSignatures');
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
 * Merges signatures from source[attr] to dest[attr]
 * @private
 * @param  {Object} source
 * @param  {Object} dest
 * @param  {String} attr
 * @param  {Function} checkFn optional, signature only merged if true
 */
async function mergeSignatures(source, dest, attr, checkFn) {
  source = source[attr];
  if (source) {
    if (!dest[attr].length) {
      dest[attr] = source;
    } else {
      await Promise.all(source.map(async function(sourceSig) {
        if (!sourceSig.isExpired() && (!checkFn || await checkFn(sourceSig)) &&
            !dest[attr].some(function(destSig) {
              return util.equalsUint8Array(destSig.signature, sourceSig.signature);
            })) {
          dest[attr].push(sourceSig);
        }
      }));
    }
  }
}

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
  flag: reasonForRevocationFlag=enums.reasonForRevocation.no_reason,
  string: reasonForRevocationString=''
} = {}, date=new Date()) {
  if (this.isPublic()) {
    throw new Error('Need private key for revoking');
  }
  const dataToSign = { key: this.keyPacket };
  const key = new Key(this.toPacketlist());
  key.revocationSignatures.push(await createSignaturePacket(dataToSign, null, this.keyPacket, {
    signatureType: enums.signature.key_revocation,
    reasonForRevocationFlag: enums.write(enums.reasonForRevocation, reasonForRevocationFlag),
    reasonForRevocationString
  }, date));
  return key;
};

/**
 * Get revocation certificate from a revoked key.
 *   (To get a revocation certificate for an unrevoked key, call revoke() first.)
 * @returns {Promise<String>} armored revocation certificate
 * @async
 */
Key.prototype.getRevocationCertificate = async function() {
  const dataToVerify = { key: this.keyPacket };
  const revocationSignature = await getLatestValidSignature(this.revocationSignatures, this.keyPacket, enums.signature.key_revocation, dataToVerify);
  if (revocationSignature) {
    const packetlist = new packet.List();
    packetlist.push(revocationSignature);
    return armor.encode(enums.armor.public_key, packetlist.write(), null, null, 'This is a revocation certificate');
  }
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
  if (!await revocationSignature.verify(this.keyPacket, enums.signature.key_revocation, { key: this.keyPacket })) {
    throw new Error('Could not verify revocation signature');
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
  const { index, user } = await this.getPrimaryUser(date, userId) || {};
  if (!user) {
    throw new Error('Could not find primary user');
  }
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
  const { user } = await this.getPrimaryUser(date, userId) || {};
  if (!user) {
    throw new Error('Could not find primary user');
  }
  const results = keys ? await user.verifyAllCertifications(primaryKey, keys) :
    [{ keyid: primaryKey.keyid, valid: await user.verify(primaryKey) === enums.keyStatus.valid }];
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
      [{ keyid: primaryKey.keyid, valid: await user.verify(primaryKey) === enums.keyStatus.valid }];
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
 * @class
 * @classdesc Class that represents an user ID or attribute packet and the relevant signatures.
 */
function User(userPacket) {
  if (!(this instanceof User)) {
    return new User(userPacket);
  }
  this.userId = userPacket.tag === enums.packet.userid ? userPacket : null;
  this.userAttribute = userPacket.tag === enums.packet.userAttribute ? userPacket : null;
  this.selfCertifications = [];
  this.otherCertifications = [];
  this.revocationSignatures = [];
}

/**
 * Transforms structured user data to packetlist
 * @returns {module:packet.List}
 */
User.prototype.toPacketlist = function() {
  const packetlist = new packet.List();
  packetlist.push(this.userId || this.userAttribute);
  packetlist.concat(this.revocationSignatures);
  packetlist.concat(this.selfCertifications);
  packetlist.concat(this.otherCertifications);
  return packetlist;
};

/**
 * Signs user
 * @param  {module:packet.SecretKey|
 *          module:packet.PublicKey} primaryKey  The primary key packet
 * @param  {Array<module:key.Key>}    privateKeys Decrypted private keys for signing
 * @returns {Promise<module:key.Key>}             New user with new certificate signatures
 * @async
 */
User.prototype.sign = async function(primaryKey, privateKeys) {
  const dataToSign = {
    userId: this.userId,
    userAttribute: this.userAttribute,
    key: primaryKey
  };
  const user = new User(dataToSign.userId || dataToSign.userAttribute);
  user.otherCertifications = await Promise.all(privateKeys.map(async function(privateKey) {
    if (privateKey.isPublic()) {
      throw new Error('Need private key for signing');
    }
    if (privateKey.hasSameFingerprintAs(primaryKey)) {
      throw new Error('Not implemented for self signing');
    }
    const signingKey = await privateKey.getSigningKey();
    if (!signingKey) {
      throw new Error('Could not find valid signing key packet in key ' +
                      privateKey.getKeyId().toHex());
    }
    return createSignaturePacket(dataToSign, privateKey, signingKey.keyPacket, {
      // Most OpenPGP implementations use generic certification (0x10)
      signatureType: enums.signature.cert_generic,
      keyFlags: [enums.keyFlags.certify_keys | enums.keyFlags.sign_data]
    });
  }));
  await user.update(this, primaryKey);
  return user;
};

/**
 * Checks if a given certificate of the user is revoked
 * @param  {module:packet.SecretKey|
 *          module:packet.PublicKey} primaryKey    The primary key packet
 * @param  {module:packet.Signature}  certificate   The certificate to verify
 * @param  {module:packet.PublicSubkey|
 *          module:packet.SecretSubkey|
 *          module:packet.PublicKey|
 *          module:packet.SecretKey} key, optional The key to verify the signature
 * @param  {Date}                     date          Use the given date instead of the current time
 * @returns {Promise<Boolean>}                      True if the certificate is revoked
 * @async
 */
User.prototype.isRevoked = async function(primaryKey, certificate, key, date=new Date()) {
  return isDataRevoked(
    primaryKey, enums.signature.cert_revocation, {
      key: primaryKey,
      userId: this.userId,
      userAttribute: this.userAttribute
    }, this.revocationSignatures, certificate, key, date
  );
};

/**
 * Create signature packet
 * @param  {Object}                          dataToSign Contains packets to be signed
 * @param  {module:packet.SecretKey|
 *          module:packet.SecretSubkey}      signingKeyPacket secret key packet for signing
 * @param  {Object} signatureProperties      (optional) properties to write on the signature packet before signing
 * @param  {Date} date                       (optional) override the creationtime of the signature
 * @param  {Object} userId                   (optional) user ID
 * @returns {module:packet/signature}         signature packet
 */
export async function createSignaturePacket(dataToSign, privateKey, signingKeyPacket, signatureProperties, date, userId) {
  if (!signingKeyPacket.isDecrypted()) {
    throw new Error('Private key is not decrypted.');
  }
  const signaturePacket = new packet.Signature(date);
  Object.assign(signaturePacket, signatureProperties);
  signaturePacket.publicKeyAlgorithm = signingKeyPacket.algorithm;
  signaturePacket.hashAlgorithm = await getPreferredHashAlgo(privateKey, signingKeyPacket, date, userId);
  await signaturePacket.sign(signingKeyPacket, dataToSign);
  return signaturePacket;
}

/**
 * Verifies the user certificate
 * @param  {module:packet.SecretKey|
 *          module:packet.PublicKey} primaryKey  The primary key packet
 * @param  {module:packet.Signature}  certificate A certificate of this user
 * @param  {Array<module:key.Key>}    keys        Array of keys to verify certificate signatures
 * @param  {Date}                     date        Use the given date instead of the current time
 * @returns {Promise<module:enums.keyStatus>}     status of the certificate
 * @async
 */
User.prototype.verifyCertificate = async function(primaryKey, certificate, keys, date=new Date()) {
  const that = this;
  const keyid = certificate.issuerKeyId;
  const dataToVerify = {
    userId: this.userId,
    userAttribute: this.userAttribute,
    key: primaryKey
  };
  const results = await Promise.all(keys.map(async function(key) {
    if (!key.getKeyIds().some(id => id.equals(keyid))) { return; }
    const signingKey = await key.getSigningKey(keyid, date);
    if (certificate.revoked || await that.isRevoked(primaryKey, certificate, signingKey.keyPacket)) {
      return enums.keyStatus.revoked;
    }
    if (!(certificate.verified || await certificate.verify(signingKey.keyPacket, enums.signature.cert_generic, dataToVerify))) {
      return enums.keyStatus.invalid;
    }
    if (certificate.isExpired()) {
      return enums.keyStatus.expired;
    }
    return enums.keyStatus.valid;
  }));
  return results.find(result => result !== undefined);
};

/**
 * Verifies all user certificates
 * @param  {module:packet.SecretKey|
 *          module:packet.PublicKey} primaryKey The primary key packet
 * @param  {Array<module:key.Key>}    keys       Array of keys to verify certificate signatures
 * @returns {Promise<Array<{keyid: module:type/keyid,
 *                          valid: Boolean}>>}   List of signer's keyid and validity of signature
 * @async
 */
User.prototype.verifyAllCertifications = async function(primaryKey, keys) {
  const that = this;
  const certifications = this.selfCertifications.concat(this.otherCertifications);
  return Promise.all(certifications.map(async function(certification) {
    const status = await that.verifyCertificate(primaryKey, certification, keys);
    return {
      keyid: certification.issuerKeyId,
      valid: status === undefined ? null : status === enums.keyStatus.valid
    };
  }));
};

/**
 * Verify User. Checks for existence of self signatures, revocation signatures
 * and validity of self signature
 * @param  {module:packet.SecretKey|
 *          module:packet.PublicKey} primaryKey The primary key packet
 * @returns {Promise<module:enums.keyStatus>}    Status of user
 * @async
 */
User.prototype.verify = async function(primaryKey) {
  if (!this.selfCertifications.length) {
    return enums.keyStatus.no_self_cert;
  }
  const that = this;
  const dataToVerify = {
    userId: this.userId,
    userAttribute: this.userAttribute,
    key: primaryKey
  };
  // TODO replace when Promise.some or Promise.any are implemented
  const results = [enums.keyStatus.invalid].concat(
    await Promise.all(this.selfCertifications.map(async function(selfCertification) {
      if (selfCertification.revoked || await that.isRevoked(primaryKey, selfCertification)) {
        return enums.keyStatus.revoked;
      }
      if (!(selfCertification.verified || await selfCertification.verify(primaryKey, enums.signature.cert_generic, dataToVerify))) {
        return enums.keyStatus.invalid;
      }
      if (selfCertification.isExpired()) {
        return enums.keyStatus.expired;
      }
      return enums.keyStatus.valid;
    })));
  return results.some(status => status === enums.keyStatus.valid) ?
    enums.keyStatus.valid : results.pop();
};

/**
 * Update user with new components from specified user
 * @param  {module:key.User}             user       Source user to merge
 * @param  {module:packet.SecretKey|
 *          module:packet.SecretSubkey} primaryKey primary key used for validation
 * @returns {Promise<undefined>}
 * @async
 */
User.prototype.update = async function(user, primaryKey) {
  const dataToVerify = {
    userId: this.userId,
    userAttribute: this.userAttribute,
    key: primaryKey
  };
  // self signatures
  await mergeSignatures(user, this, 'selfCertifications', async function(srcSelfSig) {
    return srcSelfSig.verified || srcSelfSig.verify(primaryKey, enums.signature.cert_generic, dataToVerify);
  });
  // other signatures
  await mergeSignatures(user, this, 'otherCertifications');
  // revocation signatures
  await mergeSignatures(user, this, 'revocationSignatures', function(srcRevSig) {
    return isDataRevoked(primaryKey, enums.signature.cert_revocation, dataToVerify, [srcRevSig]);
  });
};

/**
 * @class
 * @classdesc Class that represents a subkey packet and the relevant signatures.
 * @borrows module:packet.PublicSubkey#getKeyId as SubKey#getKeyId
 * @borrows module:packet.PublicSubkey#getFingerprint as SubKey#getFingerprint
 * @borrows module:packet.PublicSubkey#hasSameFingerprintAs as SubKey#hasSameFingerprintAs
 * @borrows module:packet.PublicSubkey#getAlgorithmInfo as SubKey#getAlgorithmInfo
 * @borrows module:packet.PublicSubkey#getCreationTime as SubKey#getCreationTime
 * @borrows module:packet.PublicSubkey#isDecrypted as SubKey#isDecrypted
 */
function SubKey(subKeyPacket) {
  if (!(this instanceof SubKey)) {
    return new SubKey(subKeyPacket);
  }
  this.keyPacket = subKeyPacket;
  this.bindingSignatures = [];
  this.revocationSignatures = [];
}

/**
 * Transforms structured subkey data to packetlist
 * @returns {module:packet.List}
 */
SubKey.prototype.toPacketlist = function() {
  const packetlist = new packet.List();
  packetlist.push(this.keyPacket);
  packetlist.concat(this.revocationSignatures);
  packetlist.concat(this.bindingSignatures);
  return packetlist;
};

/**
 * Checks if a binding signature of a subkey is revoked
 * @param  {module:packet.SecretKey|
 *          module:packet.PublicKey} primaryKey    The primary key packet
 * @param  {module:packet.Signature}  signature     The binding signature to verify
 * @param  {module:packet.PublicSubkey|
 *          module:packet.SecretSubkey|
 *          module:packet.PublicKey|
 *          module:packet.SecretKey} key, optional The key to verify the signature
 * @param  {Date}                     date          Use the given date instead of the current time
 * @returns {Promise<Boolean>}                      True if the binding signature is revoked
 * @async
 */
SubKey.prototype.isRevoked = async function(primaryKey, signature, key, date=new Date()) {
  return isDataRevoked(
    primaryKey, enums.signature.subkey_revocation, {
      key: primaryKey,
      bind: this.keyPacket
    }, this.revocationSignatures, signature, key, date
  );
};

/**
 * Verify subkey. Checks for revocation signatures, expiration time
 * and valid binding signature
 * @param  {module:packet.SecretKey|
 *          module:packet.PublicKey} primaryKey The primary key packet
 * @param  {Date}                     date       Use the given date instead of the current time
 * @returns {Promise<module:enums.keyStatus>}    The status of the subkey
 * @async
 */
SubKey.prototype.verify = async function(primaryKey, date=new Date()) {
  const that = this;
  const dataToVerify = { key: primaryKey, bind: this.keyPacket };
  // check subkey binding signatures
  const bindingSignature = await getLatestValidSignature(this.bindingSignatures, primaryKey, enums.signature.subkey_binding, dataToVerify, date);
  // check binding signature is verified
  if (!bindingSignature) {
    return enums.keyStatus.invalid;
  }
  // check binding signature is not revoked
  if (bindingSignature.revoked || await that.isRevoked(primaryKey, bindingSignature, null, date)) {
    return enums.keyStatus.revoked;
  }
  // check for expiration time
  if (isDataExpired(this.keyPacket, bindingSignature, date)) {
    return enums.keyStatus.expired;
  }
  return enums.keyStatus.valid; // binding signature passed all checks
};

/**
 * Returns the expiration time of the subkey or Infinity if key does not expire
 * Returns null if the subkey is invalid.
 * @param  {module:packet.SecretKey|
 *          module:packet.PublicKey} primaryKey  The primary key packet
 * @param  {Date}                     date       Use the given date instead of the current time
 * @returns {Promise<Date | Infinity | null>}
 * @async
 */
SubKey.prototype.getExpirationTime = async function(primaryKey, date=new Date()) {
  const dataToVerify = { key: primaryKey, bind: this.keyPacket };
  const bindingSignature = await getLatestValidSignature(this.bindingSignatures, primaryKey, enums.signature.subkey_binding, dataToVerify, date);
  if (!bindingSignature) return null;
  const keyExpiry = getExpirationTime(this.keyPacket, bindingSignature);
  const sigExpiry = bindingSignature.getExpirationTime();
  return keyExpiry < sigExpiry ? keyExpiry : sigExpiry;
};

/**
 * Update subkey with new components from specified subkey
 * @param  {module:key~SubKey}           subKey     Source subkey to merge
 * @param  {module:packet.SecretKey|
            module:packet.SecretSubkey} primaryKey primary key used for validation
 * @returns {Promise<undefined>}
 * @async
 */
SubKey.prototype.update = async function(subKey, primaryKey) {
  if (await subKey.verify(primaryKey) === enums.keyStatus.invalid) {
    return;
  }
  if (!this.hasSameFingerprintAs(subKey)) {
    throw new Error('SubKey update method: fingerprints of subkeys not equal');
  }
  // key packet
  if (this.keyPacket.tag === enums.packet.publicSubkey &&
      subKey.keyPacket.tag === enums.packet.secretSubkey) {
    this.keyPacket = subKey.keyPacket;
  }
  // update missing binding signatures
  const that = this;
  const dataToVerify = { key: primaryKey, bind: that.keyPacket };
  await mergeSignatures(subKey, this, 'bindingSignatures', async function(srcBindSig) {
    if (!(srcBindSig.verified || await srcBindSig.verify(primaryKey, enums.signature.subkey_binding, dataToVerify))) {
      return false;
    }
    for (let i = 0; i < that.bindingSignatures.length; i++) {
      if (that.bindingSignatures[i].issuerKeyId.equals(srcBindSig.issuerKeyId)) {
        if (srcBindSig.created > that.bindingSignatures[i].created) {
          that.bindingSignatures[i] = srcBindSig;
        }
        return false;
      }
    }
    return true;
  });
  // revocation signatures
  await mergeSignatures(subKey, this, 'revocationSignatures', function(srcRevSig) {
    return isDataRevoked(primaryKey, enums.signature.subkey_revocation, dataToVerify, [srcRevSig]);
  });
};

/**
 * Revokes the subkey
 * @param  {module:packet.SecretKey} primaryKey decrypted private primary key for revocation
 * @param  {Object} reasonForRevocation optional, object indicating the reason for revocation
 * @param  {module:enums.reasonForRevocation} reasonForRevocation.flag optional, flag indicating the reason for revocation
 * @param  {String} reasonForRevocation.string optional, string explaining the reason for revocation
 * @param  {Date} date optional, override the creationtime of the revocation signature
 * @returns {Promise<module:key~SubKey>} new subkey with revocation signature
 * @async
 */
SubKey.prototype.revoke = async function(primaryKey, {
  flag: reasonForRevocationFlag=enums.reasonForRevocation.no_reason,
  string: reasonForRevocationString=''
} = {}, date=new Date()) {
  const dataToSign = { key: primaryKey, bind: this.keyPacket };
  const subKey = new SubKey(this.keyPacket);
  subKey.revocationSignatures.push(await createSignaturePacket(dataToSign, null, primaryKey, {
    signatureType: enums.signature.subkey_revocation,
    reasonForRevocationFlag: enums.write(enums.reasonForRevocation, reasonForRevocationFlag),
    reasonForRevocationString
  }, date));
  await subKey.update(this, primaryKey);
  return subKey;
};

['getKeyId', 'getFingerprint', 'getAlgorithmInfo', 'getCreationTime', 'isDecrypted'].forEach(name => {
  Key.prototype[name] =
  SubKey.prototype[name] =
    function() {
      return this.keyPacket[name]();
    };
});

Key.prototype.hasSameFingerprintAs =
SubKey.prototype.hasSameFingerprintAs =
  function(other) {
    return this.keyPacket.hasSameFingerprintAs(other.keyPacket || other);
  };

/**
 * Reads an unarmored OpenPGP key list and returns one or multiple key objects
 * @param {Uint8Array} data to be parsed
 * @returns {Promise<{keys: Array<module:key.Key>,
 *            err: (Array<Error>|null)}>} result object with key and error arrays
 * @async
 * @static
 */
export async function read(data) {
  const result = {};
  result.keys = [];
  const err = [];
  try {
    const packetlist = new packet.List();
    await packetlist.read(data);
    const keyIndex = packetlist.indexOfTag(enums.packet.publicKey, enums.packet.secretKey);
    if (keyIndex.length === 0) {
      throw new Error('No key packet found');
    }
    for (let i = 0; i < keyIndex.length; i++) {
      const oneKeyList = packetlist.slice(keyIndex[i], keyIndex[i + 1]);
      try {
        const newKey = new Key(oneKeyList);
        result.keys.push(newKey);
      } catch (e) {
        err.push(e);
      }
    }
  } catch (e) {
    err.push(e);
  }
  if (err.length) {
    result.err = err;
  }
  return result;
}

/**
 * Reads an OpenPGP armored text and returns one or multiple key objects
 * @param {String | ReadableStream<String>} armoredText text to be parsed
 * @returns {Promise<{keys: Array<module:key.Key>,
 *            err: (Array<Error>|null)}>} result object with key and error arrays
 * @async
 * @static
 */
export async function readArmored(armoredText) {
  try {
    const input = await armor.decode(armoredText);
    if (!(input.type === enums.armor.public_key || input.type === enums.armor.private_key)) {
      throw new Error('Armored text not of type key');
    }
    return read(input.data);
  } catch (e) {
    const result = { keys: [], err: [] };
    result.err.push(e);
    return result;
  }
}

/**
 * Generates a new OpenPGP key. Supports RSA and ECC keys.
 * Primary and subkey will be of same type.
 * @param {module:enums.publicKey} [options.keyType=module:enums.publicKey.rsa_encrypt_sign]
 *                             To indicate what type of key to make.
 *                             RSA is 1. See {@link https://tools.ietf.org/html/rfc4880#section-9.1}
 * @param {Integer} options.numBits    number of bits for the key creation.
 * @param {String|Array<String>}  options.userIds
 *                             Assumes already in form of "User Name <username@email.com>"
 *                             If array is used, the first userId is set as primary user Id
 * @param {String}  options.passphrase The passphrase used to encrypt the resulting private key
 * @param {Number} [options.keyExpirationTime=0]
 *                             The number of seconds after the key creation time that the key expires
 * @param  {String} curve            (optional) elliptic curve for ECC keys
 * @param  {Date} date         Override the creation date of the key and the key signatures
 * @param  {Array<Object>} subkeys   (optional) options for each subkey, default to main key options. e.g. [{sign: true, passphrase: '123'}]
 *                                              sign parameter defaults to false, and indicates whether the subkey should sign rather than encrypt
 * @returns {Promise<module:key.Key>}
 * @async
 * @static
 */
export async function generate(options) {
  options.sign = true; // primary key is always a signing key
  options = sanitizeKeyOptions(options);
  options.subkeys = options.subkeys.map(function(subkey, index) { return sanitizeKeyOptions(options.subkeys[index], options); });

  let promises = [generateSecretKey(options)];
  promises = promises.concat(options.subkeys.map(generateSecretSubkey));
  return Promise.all(promises).then(packets => wrapKeyObject(packets[0], packets.slice(1), options));

  function sanitizeKeyOptions(options, subkeyDefaults={}) {
    options.curve = options.curve || subkeyDefaults.curve;
    options.numBits = options.numBits || subkeyDefaults.numBits;
    options.keyExpirationTime = options.keyExpirationTime !== undefined ? options.keyExpirationTime : subkeyDefaults.keyExpirationTime;
    options.passphrase = util.isString(options.passphrase) ? options.passphrase : subkeyDefaults.passphrase;
    options.date = options.date || subkeyDefaults.date;

    options.sign = options.sign || false;

    if (options.curve) {
      try {
        options.curve = enums.write(enums.curve, options.curve);
      } catch (e) {
        throw new Error('Not valid curve.');
      }
      if (options.curve === enums.curve.ed25519 || options.curve === enums.curve.curve25519) {
        if (options.sign) {
          options.algorithm = enums.publicKey.eddsa;
          options.curve = enums.curve.ed25519;
        } else {
          options.algorithm = enums.publicKey.ecdh;
          options.curve = enums.curve.curve25519;
        }
      } else {
        if (options.sign) {
          options.algorithm = enums.publicKey.ecdsa;
        } else {
          options.algorithm = enums.publicKey.ecdh;
        }
      }
    } else if (options.numBits) {
      options.algorithm = enums.publicKey.rsa_encrypt_sign;
    } else {
      throw new Error('Unrecognized key type');
    }
    return options;
  }

  async function generateSecretKey(options) {
    const secretKeyPacket = new packet.SecretKey(options.date);
    secretKeyPacket.packets = null;
    secretKeyPacket.algorithm = enums.read(enums.publicKey, options.algorithm);
    await secretKeyPacket.generate(options.numBits, options.curve);
    return secretKeyPacket;
  }

  async function generateSecretSubkey(options) {
    const secretSubkeyPacket = new packet.SecretSubkey(options.date);
    secretSubkeyPacket.packets = null;
    secretSubkeyPacket.algorithm = enums.read(enums.publicKey, options.algorithm);
    await secretSubkeyPacket.generate(options.numBits, options.curve);
    return secretSubkeyPacket;
  }
}

/**
 * Reformats and signs an OpenPGP key with a given User ID. Currently only supports RSA keys.
 * @param {module:key.Key} options.privateKey   The private key to reformat
 * @param {module:enums.publicKey} [options.keyType=module:enums.publicKey.rsa_encrypt_sign]
 * @param {String|Array<String>}  options.userIds
 *                             Assumes already in form of "User Name <username@email.com>"
 *                             If array is used, the first userId is set as primary user Id
 * @param {String}  options.passphrase The passphrase used to encrypt the resulting private key
 * @param {Number} [options.keyExpirationTime=0]
 *                             The number of seconds after the key creation time that the key expires
 * @param  {Date} date         Override the creation date of the key and the key signatures
 * @param  {Array<Object>} subkeys   (optional) options for each subkey, default to main key options. e.g. [{sign: true, passphrase: '123'}]
 *
 * @returns {Promise<module:key.Key>}
 * @async
 * @static
 */
export async function reformat(options) {
  options = sanitizeKeyOptions(options);

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
    options.subkeys = secretSubkeyPackets.map(() => ({}));
  }

  if (options.subkeys.length !== secretSubkeyPackets.length) {
    throw new Error('Number of subkey options does not match number of subkeys');
  }

  options.subkeys = options.subkeys.map(function(subkey, index) { return sanitizeKeyOptions(options.subkeys[index], options); });

  return wrapKeyObject(secretKeyPacket, secretSubkeyPackets, options);

  function sanitizeKeyOptions(options, subkeyDefaults={}) {
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

  const packetlist = new packet.List();

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

    const userIdPacket = new packet.Userid();
    userIdPacket.format(userId);

    const dataToSign = {};
    dataToSign.userId = userIdPacket;
    dataToSign.key = secretKeyPacket;
    const signaturePacket = new packet.Signature(options.date);
    signaturePacket.signatureType = enums.signature.cert_generic;
    signaturePacket.publicKeyAlgorithm = secretKeyPacket.algorithm;
    signaturePacket.hashAlgorithm = await getPreferredHashAlgo(null, secretKeyPacket);
    signaturePacket.keyFlags = [enums.keyFlags.certify_keys | enums.keyFlags.sign_data];
    signaturePacket.preferredSymmetricAlgorithms = createdPreferredAlgos([
      // prefer aes256, aes128, then aes192 (no WebCrypto support: https://www.chromium.org/blink/webcrypto#TOC-AES-support)
      enums.symmetric.aes256,
      enums.symmetric.aes128,
      enums.symmetric.aes192,
      enums.symmetric.cast5,
      enums.symmetric.tripledes
    ], config.encryption_cipher);
    if (config.aead_protect && config.aead_protect_version === 4) {
      signaturePacket.preferredAeadAlgorithms = createdPreferredAlgos([
        enums.aead.eax,
        enums.aead.ocb
      ], config.aead_mode);
    }
    signaturePacket.preferredHashAlgorithms = createdPreferredAlgos([
      // prefer fast asm.js implementations (SHA-256). SHA-1 will not be secure much longer...move to bottom of list
      enums.hash.sha256,
      enums.hash.sha512,
      enums.hash.sha1
    ], config.prefer_hash_algorithm);
    signaturePacket.preferredCompressionAlgorithms = createdPreferredAlgos([
      enums.compression.zlib,
      enums.compression.zip
    ], config.compression);
    if (index === 0) {
      signaturePacket.isPrimaryUserID = true;
    }
    if (config.integrity_protect) {
      signaturePacket.features = [0];
      signaturePacket.features[0] |= enums.features.modification_detection;
    }
    if (config.aead_protect && config.aead_protect_version === 4) {
      signaturePacket.features || (signaturePacket.features = [0]);
      signaturePacket.features[0] |= enums.features.aead;
      signaturePacket.features[0] |= enums.features.v5_keys;
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
    const dataToSign = {};
    dataToSign.key = secretKeyPacket;
    dataToSign.bind = secretSubkeyPacket;
    const subkeySignaturePacket = new packet.Signature(subkeyOptions.date);
    subkeySignaturePacket.signatureType = enums.signature.subkey_binding;
    subkeySignaturePacket.publicKeyAlgorithm = secretKeyPacket.algorithm;
    subkeySignaturePacket.hashAlgorithm = await getPreferredHashAlgo(null, secretSubkeyPacket);
    if (subkeyOptions.sign) {
      subkeySignaturePacket.keyFlags = [enums.keyFlags.sign_data];
      subkeySignaturePacket.embeddedSignature = await createSignaturePacket(dataToSign, null, secretSubkeyPacket, {
        signatureType: enums.signature.key_binding
      }, subkeyOptions.date);
    } else {
      subkeySignaturePacket.keyFlags = [enums.keyFlags.encrypt_communication | enums.keyFlags.encrypt_storage];
    }
    if (subkeyOptions.keyExpirationTime > 0) {
      subkeySignaturePacket.keyExpirationTime = subkeyOptions.keyExpirationTime;
      subkeySignaturePacket.keyNeverExpires = false;
    }
    await subkeySignaturePacket.sign(secretKeyPacket, dataToSign);

    return { secretSubkeyPacket, subkeySignaturePacket};
  })).then(packets => {
    packets.forEach(({ secretSubkeyPacket, subkeySignaturePacket }) => {
      packetlist.push(secretSubkeyPacket);
      packetlist.push(subkeySignaturePacket);
    });
  });

  // Add revocation signature packet for creating a revocation certificate.
  // This packet should be removed before returning the key.
  const dataToSign = { key: secretKeyPacket };
  packetlist.push(await createSignaturePacket(dataToSign, null, secretKeyPacket, {
    signatureType: enums.signature.key_revocation,
    reasonForRevocationFlag: enums.reasonForRevocation.no_reason,
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
 * Checks if a given certificate or binding signature is revoked
 * @param  {module:packet.SecretKey|
 *          module:packet.PublicKey}       primaryKey   The primary key packet
 * @param  {Object}                         dataToVerify The data to check
 * @param  {Array<module:packet.Signature>} revocations  The revocation signatures to check
 * @param  {module:packet.Signature}        signature    The certificate or signature to check
 * @param  {module:packet.PublicSubkey|
 *          module:packet.SecretSubkey|
 *          module:packet.PublicKey|
 *          module:packet.SecretKey} key, optional The key packet to check the signature
 * @param  {Date}                     date          Use the given date instead of the current time
 * @returns {Promise<Boolean>}                      True if the signature revokes the data
 * @async
 */
async function isDataRevoked(primaryKey, signatureType, dataToVerify, revocations, signature, key, date=new Date()) {
  key = key || primaryKey;
  const normDate = util.normalizeDate(date);
  const revocationKeyIds = [];
  await Promise.all(revocations.map(async function(revocationSignature) {
    if (
      // Note: a third-party revocation signature could legitimately revoke a
      // self-signature if the signature has an authorized revocation key.
      // However, we don't support passing authorized revocation keys, nor
      // verifying such revocation signatures. Instead, we indicate an error
      // when parsing a key with an authorized revocation key, and ignore
      // third-party revocation signatures here. (It could also be revoking a
      // third-party key certification, which should only affect
      // `verifyAllCertifications`.)
      (!signature || revocationSignature.issuerKeyId.equals(signature.issuerKeyId)) &&
      !(config.revocations_expire && revocationSignature.isExpired(normDate)) &&
      (revocationSignature.verified || await revocationSignature.verify(key, signatureType, dataToVerify))
    ) {
      // TODO get an identifier of the revoked object instead
      revocationKeyIds.push(revocationSignature.issuerKeyId);
      return true;
    }
    return false;
  }));
  // TODO further verify that this is the signature that should be revoked
  if (signature) {
    signature.revoked = revocationKeyIds.some(keyId => keyId.equals(signature.issuerKeyId)) ? true :
      signature.revoked || false;
    return signature.revoked;
  }
  return revocationKeyIds.length > 0;
}

function isDataExpired(keyPacket, signature, date=new Date()) {
  const normDate = util.normalizeDate(date);
  if (normDate !== null) {
    const expirationTime = getExpirationTime(keyPacket, signature);
    return !(keyPacket.created <= normDate && normDate <= expirationTime) ||
      (signature && signature.isExpired(date));
  }
  return false;
}

function getExpirationTime(keyPacket, signature) {
  let expirationTime;
  // check V4 expiration time
  if (signature.keyNeverExpires === false) {
    expirationTime = keyPacket.created.getTime() + signature.keyExpirationTime*1000;
  }
  return expirationTime ? new Date(expirationTime) : Infinity;
}

/**
 * Check if signature has revocation key sub packet (not supported by OpenPGP.js)
 * and throw error if found
 * @param {module:packet.Signature} signature The certificate or signature to check
 * @param {type/keyid} keyId Check only certificates or signatures from a certain issuer key ID
 */
function checkRevocationKey(signature, keyId) {
  if (signature.revocationKeyClass !== null &&
      signature.issuerKeyId.equals(keyId)) {
    throw new Error('This key is intended to be revoked with an authorized key, which OpenPGP.js does not support.');
  }
}

/**
 * Returns the preferred signature hash algorithm of a key
 * @param  {module:key.Key} key (optional) the key to get preferences from
 * @param  {module:packet.SecretKey|module:packet.SecretSubkey} keyPacket key packet used for signing
 * @param  {Date} date (optional) use the given date for verification instead of the current time
 * @param  {Object} userId (optional) user ID
 * @returns {Promise<String>}
 * @async
 */
export async function getPreferredHashAlgo(key, keyPacket, date=new Date(), userId={}) {
  let hash_algo = config.prefer_hash_algorithm;
  let pref_algo = hash_algo;
  if (key instanceof Key) {
    const primaryUser = await key.getPrimaryUser(date, userId);
    if (primaryUser && primaryUser.selfCertification.preferredHashAlgorithms) {
      [pref_algo] = primaryUser.selfCertification.preferredHashAlgorithms;
      hash_algo = crypto.hash.getHashByteLength(hash_algo) <= crypto.hash.getHashByteLength(pref_algo) ?
        pref_algo : hash_algo;
    }
  }
  switch (Object.getPrototypeOf(keyPacket)) {
    case packet.SecretKey.prototype:
    case packet.PublicKey.prototype:
    case packet.SecretSubkey.prototype:
    case packet.PublicSubkey.prototype:
      switch (keyPacket.algorithm) {
        case 'ecdh':
        case 'ecdsa':
        case 'eddsa':
          pref_algo = crypto.publicKey.elliptic.getPreferredHashAlgo(keyPacket.params[0]);
      }
  }
  return crypto.hash.getHashByteLength(hash_algo) <= crypto.hash.getHashByteLength(pref_algo) ?
    pref_algo : hash_algo;
}

/**
 * Returns the preferred symmetric/aead algorithm for a set of keys
 * @param  {symmetric|aead} type Type of preference to return
 * @param  {Array<module:key.Key>} keys Set of keys
 * @param  {Date} date (optional) use the given date for verification instead of the current time
 * @param  {Array} userIds (optional) user IDs
 * @returns {Promise<module:enums.symmetric>}   Preferred symmetric algorithm
 * @async
 */
export async function getPreferredAlgo(type, keys, date=new Date(), userIds=[]) {
  const prefProperty = type === 'symmetric' ? 'preferredSymmetricAlgorithms' : 'preferredAeadAlgorithms';
  const defaultAlgo = type === 'symmetric' ? enums.symmetric.aes128 : enums.aead.eax;
  const prioMap = {};
  await Promise.all(keys.map(async function(key, i) {
    const primaryUser = await key.getPrimaryUser(date, userIds[i]);
    if (!primaryUser || !primaryUser.selfCertification[prefProperty]) {
      return defaultAlgo;
    }
    primaryUser.selfCertification[prefProperty].forEach(function(algo, index) {
      const entry = prioMap[algo] || (prioMap[algo] = { prio: 0, count: 0, algo: algo });
      entry.prio += 64 >> index;
      entry.count++;
    });
  }));
  let prefAlgo = { prio: 0, algo: defaultAlgo };
  Object.values(prioMap).forEach(({ prio, count, algo }) => {
    try {
      if (algo !== enums[type].plaintext &&
          algo !== enums[type].idea && // not implemented
          enums.read(enums[type], algo) && // known algorithm
          count === keys.length && // available for all keys
          prio > prefAlgo.prio) {
        prefAlgo = prioMap[algo];
      }
    } catch (e) {}
  });
  return prefAlgo.algo;
}

/**
 * Returns whether aead is supported by all keys in the set
 * @param  {Array<module:key.Key>} keys Set of keys
 * @param  {Date} date (optional) use the given date for verification instead of the current time
 * @param  {Array} userIds (optional) user IDs
 * @returns {Promise<Boolean>}
 * @async
 */
export async function isAeadSupported(keys, date=new Date(), userIds=[]) {
  let supported = true;
  // TODO replace when Promise.some or Promise.any are implemented
  await Promise.all(keys.map(async function(key, i) {
    const primaryUser = await key.getPrimaryUser(date, userIds[i]);
    if (!primaryUser || !primaryUser.selfCertification.features ||
        !(primaryUser.selfCertification.features[0] & enums.features.aead)) {
      supported = false;
    }
  }));
  return supported;
}
