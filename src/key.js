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
 * @requires encoding/armor
 * @requires enums
 * @requires packet
 * @module key
 */

'use strict';

import packet from './packet';
import enums from './enums.js';
import armor from './encoding/armor.js';
import config from './config';
import util from './util';
import crypto from './crypto';

/**
 * @class
 * @classdesc Class that represents an OpenPGP key. Must contain a primary key.
 * Can contain additional subkeys, signatures, user ids, user attributes.
 * @param  {module:packet/packetlist} packetlist The packets that form this key
 */

export function Key(packetlist) {
  if (!(this instanceof Key)) {
    return new Key(packetlist);
  }
  // same data as in packetlist but in structured form
  this.primaryKey = null;
  this.revocationSignature = null;
  this.directSignatures = null;
  this.users = null;
  this.subKeys = null;
  this.packetlist2structure(packetlist);
  if (!this.primaryKey || !this.users) {
    throw new Error('Invalid key: need at least key and user ID packet');
  }
}

/**
 * Transforms packetlist to structured key data
 * @param  {module:packet/packetlist} packetlist The packets that form a key
 */
Key.prototype.packetlist2structure = function(packetlist) {
  var user, primaryKeyId, subKey;
  for (var i = 0; i < packetlist.length; i++) {
    switch (packetlist[i].tag) {
      case enums.packet.publicKey:
      case enums.packet.secretKey:
        this.primaryKey = packetlist[i];
        primaryKeyId = this.primaryKey.getKeyId();
        break;
      case enums.packet.userid:
      case enums.packet.userAttribute:
        user = new User(packetlist[i]);
        if (!this.users) {
          this.users = [];
        }
        this.users.push(user);
        break;
      case enums.packet.publicSubkey:
      case enums.packet.secretSubkey:
        user = null;
        if (!this.subKeys) {
          this.subKeys = [];
        }
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
              if (!user.selfCertifications) {
                user.selfCertifications = [];
              }
              user.selfCertifications.push(packetlist[i]);
            } else {
              if (!user.otherCertifications) {
                user.otherCertifications = [];
              }
              user.otherCertifications.push(packetlist[i]);
            }
            break;
          case enums.signature.cert_revocation:
            if (user) {
              if (!user.revocationCertifications) {
                user.revocationCertifications = [];
              }
              user.revocationCertifications.push(packetlist[i]);
            } else {
              if (!this.directSignatures) {
                this.directSignatures = [];
              }
              this.directSignatures.push(packetlist[i]);
            }
            break;
          case enums.signature.key:
            if (!this.directSignatures) {
              this.directSignatures = [];
            }
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
            this.revocationSignature = packetlist[i];
            break;
          case enums.signature.subkey_revocation:
            if (!subKey) {
              util.print_debug('Dropping subkey revocation signature without preceding subkey packet');
              continue;
            }
            subKey.revocationSignature = packetlist[i];
            break;
        }
        break;
    }
  }
};

/**
 * Transforms structured key data to packetlist
 * @return {module:packet/packetlist} The packets that form a key
 */
Key.prototype.toPacketlist = function() {
  var packetlist = new packet.List();
  packetlist.push(this.primaryKey);
  packetlist.push(this.revocationSignature);
  packetlist.concat(this.directSignatures);
  var i;
  for (i = 0; i < this.users.length; i++) {
    packetlist.concat(this.users[i].toPacketlist());
  }
  if (this.subKeys) {
    for (i = 0; i < this.subKeys.length; i++) {
      packetlist.concat(this.subKeys[i].toPacketlist());
    }
  }
  return packetlist;
};

/**
 * Returns all the private and public subkey packets
 * @returns {Array<(module:packet/public_subkey|module:packet/secret_subkey)>}
 */
Key.prototype.getSubkeyPackets = function() {
  var subKeys = [];
  if (this.subKeys) {
    for (var i = 0; i < this.subKeys.length; i++) {
      subKeys.push(this.subKeys[i].subKey);
    }
  }
  return subKeys;
};

/**
 * Returns all the private and public key and subkey packets
 * @returns {Array<(module:packet/public_subkey|module:packet/secret_subkey|module:packet/secret_key|module:packet/public_key)>}
 */
Key.prototype.getAllKeyPackets = function() {
  return [this.primaryKey].concat(this.getSubkeyPackets());
};

/**
 * Returns key IDs of all key packets
 * @returns {Array<module:type/keyid>}
 */
Key.prototype.getKeyIds = function() {
  var keyIds = [];
  var keys = this.getAllKeyPackets();
  for (var i = 0; i < keys.length; i++) {
    keyIds.push(keys[i].getKeyId());
  }
  return keyIds;
};

/**
 * Returns first key packet for given array of key IDs
 * @param  {Array<module:type/keyid>} keyIds
 * @return {(module:packet/public_subkey|module:packet/public_key|
 *           module:packet/secret_subkey|module:packet/secret_key|null)}
 */
Key.prototype.getKeyPacket = function(keyIds) {
  var keys = this.getAllKeyPackets();
  for (var i = 0; i < keys.length; i++) {
    var keyId = keys[i].getKeyId();
    for (var j = 0; j < keyIds.length; j++) {
      if (keyId.equals(keyIds[j])) {
        return keys[i];
      }
    }
  }
  return null;
};

/**
 * Returns userids
 * @return {Array<string>} array of userids
 */
Key.prototype.getUserIds = function() {
  var userids = [];
  for (var i = 0; i < this.users.length; i++) {
    if (this.users[i].userId) {
      userids.push(util.Uint8Array2str(this.users[i].userId.write()));
    }
  }
  return userids;
};

/**
 * Returns true if this is a public key
 * @return {Boolean}
 */
Key.prototype.isPublic = function() {
  return this.primaryKey.tag === enums.packet.publicKey;
};

/**
 * Returns true if this is a private key
 * @return {Boolean}
 */
Key.prototype.isPrivate = function() {
  return this.primaryKey.tag === enums.packet.secretKey;
};

/**
 * Returns key as public key (shallow copy)
 * @return {module:key~Key} new public Key
 */
Key.prototype.toPublic = function() {
  var packetlist = new packet.List();
  var keyPackets = this.toPacketlist();
  var bytes;
  for (var i = 0; i < keyPackets.length; i++) {
    switch (keyPackets[i].tag) {
      case enums.packet.secretKey:
        bytes = keyPackets[i].writePublicKey();
        var pubKeyPacket = new packet.PublicKey();
        pubKeyPacket.read(bytes);
        packetlist.push(pubKeyPacket);
        break;
      case enums.packet.secretSubkey:
        bytes = keyPackets[i].writePublicKey();
        var pubSubkeyPacket = new packet.PublicSubkey();
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
 * @return {String} ASCII armor
 */
Key.prototype.armor = function() {
  var type = this.isPublic() ? enums.armor.public_key : enums.armor.private_key;
  return armor.encode(type, this.toPacketlist().write());
};

/**
 * Returns first key packet or key packet by given keyId that is available for signing or signature verification
 * @param  {module:type/keyid} keyId, optional
 * @param  {Boolean} allowExpired allows signature verification with expired keys
 * @return {(module:packet/secret_subkey|module:packet/secret_key|null)} key packet or null if no signing key has been found
 */
Key.prototype.getSigningKeyPacket = function(keyId, allowExpired=false) {
  var primaryUser = this.getPrimaryUser(allowExpired);
  if (primaryUser && (!keyId || this.primaryKey.getKeyId().equals(keyId)) &&
      isValidSigningKeyPacket(this.primaryKey, primaryUser.selfCertificate, allowExpired)) {
    return this.primaryKey;
  }
  if (this.subKeys) {
    for (var i = 0; i < this.subKeys.length; i++) {
      if (!keyId || this.subKeys[i].subKey.getKeyId().equals(keyId)) {
        for (var j = 0; j < this.subKeys[i].bindingSignatures.length; j++) {
          if (isValidSigningKeyPacket(
            this.subKeys[i].subKey, this.subKeys[i].bindingSignatures[j], allowExpired)) {
            return this.subKeys[i].subKey;
          }
        }
      }
    }
  }
  return null;
};

function isValidEncryptionKeyPacket(keyPacket, signature, allowExpired=false) {
  return keyPacket.algorithm !== enums.read(enums.publicKey, enums.publicKey.dsa) &&
         keyPacket.algorithm !== enums.read(enums.publicKey, enums.publicKey.rsa_sign) &&
         keyPacket.algorithm !== enums.read(enums.publicKey, enums.publicKey.ecdsa) &&
         keyPacket.algorithm !== enums.read(enums.publicKey, enums.publicKey.eddsa) &&
         (!signature.keyFlags ||
          (signature.keyFlags[0] & enums.keyFlags.encrypt_communication) !== 0 ||
          (signature.keyFlags[0] & enums.keyFlags.encrypt_storage) !== 0) &&
         (allowExpired || (!signature.isExpired() &&
          // check expiration time of V3 key packet
          !(keyPacket.version === 3 && keyPacket.expirationTimeV3 !== 0 &&
            Date.now() > (keyPacket.created.getTime() + keyPacket.expirationTimeV3*24*3600*1000)) &&
          // check expiration time of V4 key packet
          !(keyPacket.version === 4 && signature.keyNeverExpires === false &&
            Date.now() > (keyPacket.created.getTime() + signature.keyExpirationTime*1000))));
}

function isValidSigningKeyPacket(keyPacket, signature, allowExpired=false) {
  return keyPacket.algorithm !== enums.read(enums.publicKey, enums.publicKey.rsa_encrypt) &&
         keyPacket.algorithm !== enums.read(enums.publicKey, enums.publicKey.elgamal) &&
         keyPacket.algorithm !== enums.read(enums.publicKey, enums.publicKey.ecdh) &&
         (!signature.keyFlags ||
          (signature.keyFlags[0] & enums.keyFlags.sign_data) !== 0) &&
         (allowExpired || (!signature.isExpired() &&
          // check expiration time of V3 key packet
          !(keyPacket.version === 3 && keyPacket.expirationTimeV3 !== 0 &&
            Date.now() > (keyPacket.created.getTime() + keyPacket.expirationTimeV3*24*3600*1000)) &&
          // check expiration time of V4 key packet
          !(keyPacket.version === 4 && signature.keyNeverExpires === false &&
            Date.now() > (keyPacket.created.getTime() + signature.keyExpirationTime*1000))));

}

/**
 * Returns first key packet or key packet by given keyId that is available for encryption or decryption
 * @param  {module:type/keyid} keyId, optional
 * @returns {(module:packet/public_subkey|module:packet/secret_subkey|module:packet/secret_key|module:packet/public_key|null)} key packet or null if no encryption key has been found
 */
Key.prototype.getEncryptionKeyPacket = function(keyId) {
  // V4: by convention subkeys are prefered for encryption service
  // V3: keys MUST NOT have subkeys
  if (this.subKeys) {
    for (var i = 0; i < this.subKeys.length; i++) {
      if (!keyId || this.subKeys[i].subKey.getKeyId().equals(keyId)) {
        for (var j = 0; j < this.subKeys[i].bindingSignatures.length; j++) {
          if (isValidEncryptionKeyPacket(
            this.subKeys[i].subKey, this.subKeys[i].bindingSignatures[j])) {
            return this.subKeys[i].subKey;
          }
        }
      }
    }
  }
  // if no valid subkey for encryption, evaluate primary key
  var primaryUser = this.getPrimaryUser();
  if (primaryUser && (!keyId || this.primaryKey.getKeyId().equals(keyId)) &&
      isValidEncryptionKeyPacket(this.primaryKey, primaryUser.selfCertificate)) {
    return this.primaryKey;
  }
  return null;
};

/**
 * Encrypts all secret key and subkey packets
 * @param  {String} passphrase
 */
Key.prototype.encrypt = function(passphrase) {
  if (!this.isPrivate()) {
    throw new Error("Nothing to encrypt in a public key");
  }

  var keys = this.getAllKeyPackets();
  for (var i = 0; i < keys.length; i++) {
    keys[i].encrypt(passphrase);
    keys[i].clearPrivateParams();
  }
};

/**
 * Decrypts all secret key and subkey packets
 * @param  {String} passphrase
 * @return {Boolean} true if all key and subkey packets decrypted successfully
 */
Key.prototype.decrypt = function(passphrase) {
  if (this.isPrivate()) {
    var keys = this.getAllKeyPackets();
    for (var i = 0; i < keys.length; i++) {
      var success = keys[i].decrypt(passphrase);
      if (!success) {
        return false;
      }
    }
  } else {
    throw new Error("Nothing to decrypt in a public key");
  }
  return true;
};

/**
 * Decrypts specific key packets by key ID
 * @param  {Array<module:type/keyid>} keyIds
 * @param  {String} passphrase
 * @return {Boolean} true if all key packets decrypted successfully
 */
Key.prototype.decryptKeyPacket = function(keyIds, passphrase) {
  if (this.isPrivate()) {
    var keys = this.getAllKeyPackets();
    for (var i = 0; i < keys.length; i++) {
      var keyId = keys[i].getKeyId();
      for (var j = 0; j < keyIds.length; j++) {
        if (keyId.equals(keyIds[j])) {
          var success = keys[i].decrypt(passphrase);
          if (!success) {
            return false;
          }
        }
      }
    }
  } else {
    throw new Error("Nothing to decrypt in a public key");
  }
  return true;
};

/**
 * Verify primary key. Checks for revocation signatures, expiration time
 * and valid self signature
 * @param  {Boolean} allowExpired allows signature verification with expired keys
 * @return {module:enums.keyStatus} The status of the primary key
 */
Key.prototype.verifyPrimaryKey = async function(allowExpired=false) {
  // TODO clarify OpenPGP's behavior given an expired revocation signature
  // check revocation signature
  if (this.revocationSignature && !this.revocationSignature.isExpired() &&
     (this.revocationSignature.verified ||
      await this.revocationSignature.verify(this.primaryKey, {key: this.primaryKey}))) {
    return enums.keyStatus.revoked;
  }
  // check V3 expiration time
  if (!allowExpired && this.primaryKey.version === 3 && this.primaryKey.expirationTimeV3 !== 0 &&
    Date.now() > (this.primaryKey.created.getTime() + this.primaryKey.expirationTimeV3*24*3600*1000)) {
    return enums.keyStatus.expired;
  }
  // check for at least one self signature. Self signature of user ID not mandatory
  // See {@link http://tools.ietf.org/html/rfc4880#section-11.1}
  if (!this.users.some(user => user.userId && user.selfCertifications)) {
    return enums.keyStatus.no_self_cert;
  }
  // check for valid self signature
  await this.verifyPrimaryUser();
  var primaryUser = this.getPrimaryUser(allowExpired);
  if (!primaryUser) {
    return enums.keyStatus.invalid;
  }
  // check V4 expiration time
  if (!allowExpired && this.primaryKey.version === 4 && primaryUser.selfCertificate.keyNeverExpires === false &&
    Date.now() > (this.primaryKey.created.getTime() + primaryUser.selfCertificate.keyExpirationTime*1000)) {
    return enums.keyStatus.expired;
  }
  return enums.keyStatus.valid;
};

/**
 * Returns the expiration time of the primary key or null if key does not expire
 * @return {Date|null}
 */
Key.prototype.getExpirationTime = function() {
  if (this.primaryKey.version === 3) {
    return getExpirationTime(this.primaryKey);
  }
  if (this.primaryKey.version === 4) {
    var primaryUser = this.getPrimaryUser();
    if (!primaryUser) {
      return null;
    }
    return getExpirationTime(this.primaryKey, primaryUser.selfCertificate);
  }
};


function getExpirationTime(keyPacket, selfCertificate) {
  // check V3 expiration time
  if (keyPacket.version === 3 && keyPacket.expirationTimeV3 !== 0) {
    return new Date(keyPacket.created.getTime() + keyPacket.expirationTimeV3*24*3600*1000);
  }
  // check V4 expiration time
  if (keyPacket.version === 4 && selfCertificate.keyNeverExpires === false) {
    return new Date(keyPacket.created.getTime() + selfCertificate.keyExpirationTime*1000);
  }
  return null;
}

/**
 * Returns primary user and most significant (latest valid) self signature
 * - if multiple users are marked as primary users returns the one with the latest self signature
 * - if no primary user is found returns the user with the latest self signature
 * @param  {Boolean} allowExpired allows signature verification with expired keys
 * @return {{user: Array<module:packet/User>, selfCertificate: Array<module:packet/signature>}|null} The primary user and the self signature
 */
Key.prototype.getPrimaryUser = function(allowExpired=false) {
  var primaryUsers = [];
  for (var i = 0; i < this.users.length; i++) {
    // here we only check the primary user ID, ignoring the primary user attribute
    if (!this.users[i].userId || !this.users[i].selfCertifications) {
      continue;
    }
    for (var j = 0; j < this.users[i].selfCertifications.length; j++) {
      // only consider already validated certificates
      if (!this.users[i].selfCertifications[j].verified ||
           this.users[i].selfCertifications[j].revoked ||
          (this.users[i].selfCertifications[j].isExpired() && !allowExpired)) {
        continue;
      }
      primaryUsers.push(
        { index: i, user: this.users[i], selfCertificate: this.users[i].selfCertifications[j] }
      );
    }
  }
  // sort by primary user flag and signature creation time
  primaryUsers = primaryUsers.sort(function(a, b) {
    var A = a.selfCertificate, B = b.selfCertificate;
    return A.isPrimaryUserID < B.isPrimaryUserID || A.created < B.created;
  });
  return primaryUsers.pop();
};

/**
 * Update key with new components from specified key with same key ID:
 * users, subkeys, certificates are merged into the destination key,
 * duplicates are ignored.
 * If the specified key is a private key and the destination key is public,
 * the destination key is tranformed to a private key.
 * @param  {module:key~Key} key source key to merge
 */
Key.prototype.update = async function(key) {
  var that = this;
  if (await key.verifyPrimaryKey() === enums.keyStatus.invalid) {
    return;
  }
  if (this.primaryKey.getFingerprint() !== key.primaryKey.getFingerprint()) {
    throw new Error('Key update method: fingerprints of keys not equal');
  }
  if (this.isPublic() && key.isPrivate()) {
    // check for equal subkey packets
    var equal = ((this.subKeys && this.subKeys.length) === (key.subKeys && key.subKeys.length)) &&
                (!this.subKeys || this.subKeys.every(function(destSubKey) {
                  return key.subKeys.some(function(srcSubKey) {
                    return destSubKey.subKey.getFingerprint() === srcSubKey.subKey.getFingerprint();
                  });
                }));
    if (!equal) {
      throw new Error('Cannot update public key with private key if subkey mismatch');
    }
    this.primaryKey = key.primaryKey;
  }
  // TODO clarify OpenPGP's behavior given an expired revocation signature
  // revocation signature
  if (!this.revocationSignature && key.revocationSignature && !key.revocationSignature.isExpired() &&
     (key.revocationSignature.verified ||
      await key.revocationSignature.verify(key.primaryKey, {key: key.primaryKey}))) {
    this.revocationSignature = key.revocationSignature;
  }
  // direct signatures
  await mergeSignatures(key, this, 'directSignatures');
  // TODO replace when Promise.some or Promise.any are implemented
  // users
  await Promise.all(key.users.map(async function(srcUser) {
    var found = false;
    await Promise.all(that.users.map(async function(dstUser) {
      if ((srcUser.userId && (srcUser.userId.userid === dstUser.userId.userid)) ||
          (srcUser.userAttribute && (srcUser.userAttribute.equals(dstUser.userAttribute)))) {
        await dstUser.update(srcUser, that.primaryKey);
        found = true;
      }
    }));
    if (!found) {
      that.users.push(srcUser);
    }
  }));
  // TODO replace when Promise.some or Promise.any are implemented
  // subkeys
  if (key.subKeys) {
    await Promise.all(key.subKeys.map(async function(srcSubKey) {
      var found = false;
      await Promise.all(that.subKeys.map(async function(dstSubKey) {
        if (srcSubKey.subKey.getFingerprint() === dstSubKey.subKey.getFingerprint()) {
          await dstSubKey.update(srcSubKey, that.primaryKey);
          found = true;
        }
      }));
      if (!found) {
        that.subKeys.push(srcSubKey);
      }
    }));
  }
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
    if (!dest[attr]) {
      dest[attr] = source;
    } else {
      await Promise.all(source.map(async function(sourceSig) {
        if (!sourceSig.isExpired() && (!checkFn || await checkFn(sourceSig)) &&
            !dest[attr].some(function(destSig) {
              return util.equalsUint8Array(destSig.signature,sourceSig.signature);
            })) {
          dest[attr].push(sourceSig);
        }
      }));
    }
  }
}

// TODO
Key.prototype.revoke = function() {

};

/**
 * Signs primary user of key
 * @param  {Array<module:key~Key>} privateKey decrypted private keys for signing
 * @return {module:key~Key} new public key with new certificate signature
 */
Key.prototype.signPrimaryUser = async function(privateKeys) {
  await this.verifyPrimaryUser();
  var {index, user} = this.getPrimaryUser() || {};
  if (!user) {
    throw new Error('Could not find primary user');
  }
  user = await user.sign(this.primaryKey, privateKeys);
  var key = new Key(this.toPacketlist());
  key.users[index] = user;
  return key;
};

/**
 * Signs all users of key
 * @param  {Array<module:key~Key>} privateKeys decrypted private keys for signing
 * @return {module:key~Key} new public key with new certificate signature
 */
Key.prototype.signAllUsers = async function(privateKeys) {
  var that = this;
  var key = new Key(this.toPacketlist());
  key.users = await Promise.all(this.users.map(function(user) {
    return user.sign(that.primaryKey, privateKeys);
  }));
  return key;
};

/**
 * Verifies primary user of key
 * - if no arguments are given, verifies the self certificates;
 * - otherwise, verifies all certificates signed with given keys.
 * @param  {Array<module:key~Key>} keys array of keys to verify certificate signatures
 * @return {Array<({keyid: module:type/keyid, valid: Boolean})>} list of signer's keyid and validity of signature
 */
Key.prototype.verifyPrimaryUser = async function(keys) {
  var primaryKey = this.primaryKey, primaryUsers = [];
  var lastCreated = null, lastPrimaryUserID = null;
  await Promise.all(this.users.map(async function(user) {
    // here we verify both the primary user ID or the primary user attribute
    if (!(user.userId || user.userAttribute) || !user.selfCertifications) {
      return;
    }
    var dataToVerify = { userid: user.userId || user.userAttribute, key: primaryKey };
    await Promise.all(user.selfCertifications.map(async function(selfCertification) {
      // skip if certificate is not the most recent
      if ((selfCertification.isPrimaryUserID &&
           selfCertification.isPrimaryUserID < lastPrimaryUserID) ||
          (!lastPrimaryUserID && selfCertification.created < lastCreated)) {
        return;
      }
      // skip if certificates is not valid
      if (!(selfCertification.verified || await selfCertification.verify(primaryKey, dataToVerify)) ||
          (selfCertification.revoked || await user.isRevoked(primaryKey, selfCertification)) ||
          selfCertification.isExpired()) {
        return;
      }
      lastPrimaryUserID = selfCertification.isPrimaryUserID;
      lastCreated = selfCertification.created;
      primaryUsers.push(user);
    }));
  }));
  var user = primaryUsers.pop();
  var results = !user ? [] : keys ? await user.verifyAllCertifications(primaryKey, keys) :
      [{ keyid: primaryKey.keyid, valid: await user.verify(primaryKey) === enums.keyStatus.valid }];
  return results;
};

/**
 * Verifies all users of key
 * - if no arguments are given, verifies the self certificates;
 * - otherwise, verifies all certificates signed with given keys.
 * @param  {Array<module:key~Key>} keys array of keys to verify certificate signatures
 * @return {Array<({userid: String, keyid: module:type/keyid, valid: Boolean})>} list of userid, signer's keyid and validity of signature
 */
Key.prototype.verifyAllUsers = async function(keys) {
  var results = [];
  var primaryKey = this.primaryKey;
  await Promise.all(this.users.map(async function(user) {
    var signatures = keys ? await user.verifyAllCertifications(primaryKey, keys) :
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
  this.selfCertifications = null;
  this.otherCertifications = null;
  this.revocationCertifications = null;
}

/**
 * Transforms structured user data to packetlist
 * @return {module:packet/packetlist}
 */
User.prototype.toPacketlist = function() {
  var packetlist = new packet.List();
  packetlist.push(this.userId || this.userAttribute);
  packetlist.concat(this.revocationCertifications);
  packetlist.concat(this.selfCertifications);
  packetlist.concat(this.otherCertifications);
  return packetlist;
};

/**
 * Checks if a self certificate of the user is revoked
 * @param  {module:packet/secret_key|module:packet/public_key} primaryKey  The primary key packet
 * @param  {module:packet/signature} certificate The certificate to verify
 * @param  {module:packet/public_subkey|module:packet/public_key|
 *          module:packet/secret_subkey|module:packet/secret_key} key, optional The key to verify the signature
 * @return {Boolean} True if the certificate is revoked
 */
User.prototype.isRevoked = async function(primaryKey, certificate, key) {
  if (this.revocationCertifications) {
    var dataToVerify = { userid: this.userId || this.userAttribute, key: primaryKey };
    // TODO clarify OpenPGP's behavior given an expired revocation signature
    var results = await Promise.all(this.revocationCertifications.map(async function(revCert) {
      return revCert.issuerKeyId.equals(certificate.issuerKeyId) &&
            !revCert.isExpired() &&
            (revCert.verified || revCert.verify(key ? key : primaryKey, dataToVerify));
    }));
    certificate.revoked = results.some(result => result === true);
    return certificate.revoked;
  } else {
    return false;
  }
};

/**
 * Signs user
 * @param  {module:packet/secret_key|module:packet/public_key} primaryKey The primary key packet
 * @param  {Array<module:key~Key>} privateKeys decrypted private keys for signing
 * @return {module:key~Key} new user with new certificate signatures
 */
User.prototype.sign = async function(primaryKey, privateKeys) {
  const dataToSign = { userid: this.userId || this.userAttribute, key: primaryKey };
  const user = new User(dataToSign.userid);
  user.otherCertifications = await Promise.all(privateKeys.map(async function(privateKey) {
    if (privateKey.isPublic()) {
      throw new Error('Need private key for signing');
    }
    if (privateKey.primaryKey.getFingerprint() === primaryKey.getFingerprint()) {
      throw new Error('Not implemented for self signing');
    }
    await privateKey.verifyPrimaryUser();
    const signingKeyPacket = privateKey.getSigningKeyPacket();
    if (!signingKeyPacket) {
      throw new Error('Could not find valid signing key packet in key ' +
                      privateKey.primaryKey.getKeyId().toHex());
    }
    if (!signingKeyPacket.isDecrypted) {
      throw new Error('Private key is not decrypted.');
    }
    const signaturePacket = new packet.Signature();
    // Most OpenPGP implementations use generic certification (0x10)
    signaturePacket.signatureType = enums.write(enums.signature, enums.signature.cert_generic);
    signaturePacket.keyFlags = [enums.keyFlags.certify_keys | enums.keyFlags.sign_data];
    signaturePacket.publicKeyAlgorithm = signingKeyPacket.algorithm;
    signaturePacket.hashAlgorithm = getPreferredHashAlgorithm(privateKey);
    signaturePacket.signingKeyId = signingKeyPacket.getKeyId();
    signaturePacket.sign(signingKeyPacket, dataToSign);
    return signaturePacket;
  }));
  await user.update(this, primaryKey);
  return user;
};

/**
 * Verifies the user certificate
 * @param  {module:packet/secret_key|module:packet/public_key} primaryKey  The primary key packet
 * @param  {module:packet/signature}  certificate A certificate of this user
 * @param  {Array<module:key~Key>} keys array of keys to verify certificate signatures
 * @param  {Boolean} allowExpired allows signature verification with expired keys
 * @return {module:enums.keyStatus} status of the certificate
 */
User.prototype.verifyCertificate = async function(primaryKey, certificate, keys, allowExpired=false) {
  var that = this;
  var keyid = certificate.issuerKeyId;
  var dataToVerify = { userid: this.userId || this.userAttribute, key: primaryKey };
  var results = await Promise.all(keys.map(async function(key) {
    if (!key.getKeyIds().some(id => id.equals(keyid))) { return; }
    await key.verifyPrimaryUser();
    var keyPacket = key.getSigningKeyPacket(keyid);
    if (certificate.revoked || await that.isRevoked(primaryKey, certificate, keyPacket)) {
      return enums.keyStatus.revoked;
    }
    if (!(certificate.verified || await certificate.verify(keyPacket, dataToVerify))) {
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
 * @param  {module:packet/secret_key|module:packet/public_key} primaryKey The primary key packet
 * @param  {Array<module:key~Key>} keys array of keys to verify certificate signatures
 * @return {Array<({keyid: module:type/keyid, valid: Boolean})>} list of signer's keyid and validity of signature
 */
User.prototype.verifyAllCertifications = async function(primaryKey, keys) {
  var that = this;
  var certifications = this.selfCertifications.concat(this.otherCertifications || []);
  return Promise.all(certifications.map(async function(certification) {
    var status = await that.verifyCertificate(primaryKey, certification, keys);
    return { keyid: certification.issuerKeyId,
             valid: status === undefined ? null : status === enums.keyStatus.valid };
  }));
};

/**
 * Verify User. Checks for existence of self signatures, revocation signatures
 * and validity of self signature
 * @param  {module:packet/secret_key|module:packet/public_key} primaryKey The primary key packet
 * @return {module:enums.keyStatus} status of user
 */
User.prototype.verify = async function(primaryKey) {
  if (!this.selfCertifications) {
    return enums.keyStatus.no_self_cert;
  }
  var that = this;
  var dataToVerify = { userid: this.userId || this.userAttribute, key: primaryKey };
  // TODO replace when Promise.some or Promise.any are implemented
  var results = [enums.keyStatus.invalid].concat(
    await Promise.all(this.selfCertifications.map(async function(selfCertification, i) {
      if (selfCertification.revoked || await that.isRevoked(primaryKey, selfCertification)) {
        return enums.keyStatus.revoked;
      }
      if (!(selfCertification.verified || await selfCertification.verify(primaryKey, dataToVerify))) {
        return enums.keyStatus.invalid;
      }
      if (selfCertification.isExpired()) {
        return enums.keyStatus.expired;
      }
      return enums.keyStatus.valid;
    })));
  return results.some(status => status === enums.keyStatus.valid)?
    enums.keyStatus.valid : results.pop();
};

/**
 * Update user with new components from specified user
 * @param  {module:key~User} user source user to merge
 * @param  {module:packet/signature} primaryKey primary key used for validation
 */
User.prototype.update = async function(user, primaryKey) {
  var dataToVerify = { userid: this.userId || this.userAttribute, key: primaryKey };
  // self signatures
  await mergeSignatures(user, this, 'selfCertifications', async function(srcSelfSig) {
    return srcSelfSig.verified || srcSelfSig.verify(primaryKey, dataToVerify);
  });
  // other signatures
  await mergeSignatures(user, this, 'otherCertifications');
  // revocation signatures
  await mergeSignatures(user, this, 'revocationCertifications');
};

/**
 * @class
 * @classdesc Class that represents a subkey packet and the relevant signatures.
 */
function SubKey(subKeyPacket) {
  if (!(this instanceof SubKey)) {
    return new SubKey(subKeyPacket);
  }
  this.subKey = subKeyPacket;
  this.bindingSignatures = [];
  this.revocationSignature = null;
}

/**
 * Transforms structured subkey data to packetlist
 * @return {module:packet/packetlist}
 */
SubKey.prototype.toPacketlist = function() {
  var packetlist = new packet.List();
  packetlist.push(this.subKey);
  packetlist.push(this.revocationSignature);
  for(var i = 0; i < this.bindingSignatures.length; i++) {
    packetlist.push(this.bindingSignatures[i]);
  }
  return packetlist;
};

/**
 * Returns true if the subkey can be used for encryption
 * @param  {module:packet/secret_key|module:packet/public_key}  primaryKey The primary key packet
 * @return {Boolean}
 */
SubKey.prototype.isValidEncryptionKey = async function(primaryKey) {
  if(await this.verify(primaryKey) !== enums.keyStatus.valid) {
    return false;
  }
  for(var i = 0; i < this.bindingSignatures.length; i++) {
    if(isValidEncryptionKeyPacket(this.subKey, this.bindingSignatures[i])) {
      return true;
    }
  }
  return false;
};

/**
 * Returns true if the subkey can be used for signing of data
 * @param  {module:packet/secret_key|module:packet/public_key}  primaryKey The primary key packet
 * @param  {Boolean} allowExpired allows signature verification with expired keys
 * @return {Boolean}
 */
SubKey.prototype.isValidSigningKey = async function(primaryKey, allowExpired=false) {
  if(await this.verify(primaryKey, allowExpired) !== enums.keyStatus.valid) {
    return false;
  }
  for(var i = 0; i < this.bindingSignatures.length; i++) {
    if(isValidSigningKeyPacket(this.subKey, this.bindingSignatures[i], allowExpired)) {
      return true;
    }
  }
  return false;
};

/**
 * Verify subkey. Checks for revocation signatures, expiration time
 * and valid binding signature
 * @param  {module:packet/secret_key|module:packet/public_key}  primaryKey The primary key packet
 * @param  {Boolean} allowExpired allows signature verification with expired keys
 * @return {module:enums.keyStatus} The status of the subkey
 */
SubKey.prototype.verify = async function(primaryKey, allowExpired=false) {
  var that = this;
  // TODO clarify OpenPGP's behavior given an expired revocation signature
  // check subkey revocation signature
  if (this.revocationSignature && !this.revocationSignature.isExpired() &&
     (this.revocationSignature.verified ||
      await this.revocationSignature.verify(primaryKey, {key:primaryKey, bind: this.subKey}))) {
    return enums.keyStatus.revoked;
  }
  // check V3 expiration time
  if (!allowExpired && this.subKey.version === 3 && this.subKey.expirationTimeV3 !== 0 &&
      Date.now() > (this.subKey.created.getTime() + this.subKey.expirationTimeV3*24*3600*1000)) {
    return enums.keyStatus.expired;
  }
  // check subkey binding signatures (at least one valid binding sig needed)
  // TODO replace when Promise.some or Promise.any are implemented
  var results = [enums.keyStatus.invalid].concat(
    await Promise.all(this.bindingSignatures.map(async function(bindingSignature) {
    // check binding signature is not expired
    if(!allowExpired && bindingSignature.isExpired()) {
      return enums.keyStatus.expired; // last expired binding signature
    }
    // check binding signature can verify
    if (!(bindingSignature.verified ||
          await bindingSignature.verify(primaryKey, {key: primaryKey, bind: that.subKey}))) {
      return enums.keyStatus.invalid; // last invalid binding signature
    }
    // check V4 expiration time
    if (that.subKey.version === 4) {
      if(!allowExpired && bindingSignature.keyNeverExpires === false &&
         Date.now() > (that.subKey.created.getTime() + bindingSignature.keyExpirationTime*1000)) {
        return enums.keyStatus.expired; // last V4 expired binding signature
      }
    }
    return enums.keyStatus.valid; // found a binding signature that passed all checks
    })));
  return results.some(status => status === enums.keyStatus.valid) ?
    enums.keyStatus.valid : results.pop();
};

/**
 * Returns the expiration time of the subkey or null if key does not expire
 * @return {Date|null}
 */
SubKey.prototype.getExpirationTime = function() {
  var highest;
  for(var i = 0; i < this.bindingSignatures.length; i++) {
    var current = getExpirationTime(this.subKey, this.bindingSignatures[i]);
    if(current === null) {
      return null;
    }
    if(!highest || current > highest) {
      highest = current;
    }
  }
  return highest;
};

/**
 * Update subkey with new components from specified subkey
 * @param  {module:key~SubKey} subKey source subkey to merge
 * @param  {module:packet/signature} primaryKey primary key used for validation
 */
SubKey.prototype.update = async function(subKey, primaryKey) {
  if (await subKey.verify(primaryKey) === enums.keyStatus.invalid) {
    return;
  }
  if (this.subKey.getFingerprint() !== subKey.subKey.getFingerprint()) {
    throw new Error('SubKey update method: fingerprints of subkeys not equal');
  }
  // key packet
  if (this.subKey.tag === enums.packet.publicSubkey &&
      subKey.subKey.tag === enums.packet.secretSubkey) {
    this.subKey = subKey.subKey;
  }
  // update missing binding signatures
  var that = this;
  await Promise.all(subKey.bindingSignatures.map(async function(newBindingSignature) {
    if (newBindingSignature.verified ||
        await newBindingSignature.verify(primaryKey, {key: primaryKey, bind: that.subKey })) {
      for (var i = 0; i < that.bindingSignatures.length; i++) {
        if (that.bindingSignatures[i].issuerKeyId.equals(newBindingSignature.issuerKeyId)) {
          that.bindingSignatures[i] = newBindingSignature;
          return;
        }
      }
      that.bindingSignatures.push(newBindingSignature);
    }
  }));
  // TODO clarify OpenPGP's behavior given an expired revocation signature
  // revocation signature
  if (!this.revocationSignature &&
      subKey.revocationSignature &&
      !subKey.revocationSignature.isExpired() &&
      (subKey.revocationSignature.verified ||
       await subKey.revocationSignature.verify(
         primaryKey, {key: primaryKey, bind: this.subKey}
       ))) {
    this.revocationSignature = subKey.revocationSignature;
  }
};

/**
 * Reads an unarmored OpenPGP key list and returns one or multiple key objects
 * @param {Uint8Array} data to be parsed
 * @return {{keys: Array<module:key~Key>, err: (Array<Error>|null)}} result object with key and error arrays
 * @static
 */
export function read(data) {
  var result = {};
  result.keys = [];
  try {
    var packetlist = new packet.List();
    packetlist.read(data);
    var keyIndex = packetlist.indexOfTag(enums.packet.publicKey, enums.packet.secretKey);
    if (keyIndex.length === 0) {
      throw new Error('No key packet found');
    }
    for (var i = 0; i < keyIndex.length; i++) {
      var oneKeyList = packetlist.slice(keyIndex[i], keyIndex[i + 1]);
      try {
        var newKey = new Key(oneKeyList);
        result.keys.push(newKey);
      } catch (e) {
        result.err = result.err || [];
        result.err.push(e);
      }
    }
  } catch (e) {
    result.err = result.err || [];
    result.err.push(e);
  }
  return result;
}

/**
 * Reads an OpenPGP armored text and returns one or multiple key objects
 * @param {String} armoredText text to be parsed
 * @return {{keys: Array<module:key~Key>, err: (Array<Error>|null)}} result object with key and error arrays
 * @static
 */
export function readArmored(armoredText) {
  try {
    var input = armor.decode(armoredText);
    if (!(input.type === enums.armor.public_key || input.type === enums.armor.private_key)) {
      throw new Error('Armored text not of type key');
    }
    return read(input.data);
  } catch (e) {
    var result = {keys: [], err: []};
    result.err.push(e);
    return result;
  }
}

/**
 * Generates a new OpenPGP key. Supports RSA and ECC keys.
 * Primary and subkey will be of same type.
 * @param {module:enums.publicKey} [options.keyType=module:enums.publicKey.rsa_encrypt_sign]    to indicate what type of key to make.
 *                             RSA is 1. See {@link http://tools.ietf.org/html/rfc4880#section-9.1}
 * @param {Integer} options.numBits    number of bits for the key creation.
 * @param {String|Array<String>}  options.userIds    assumes already in form of "User Name <username@email.com>"
                                                     If array is used, the first userId is set as primary user Id
 * @param {String}  options.passphrase The passphrase used to encrypt the resulting private key
 * @param {Boolean} [options.unlocked=false]    The secret part of the generated key is unlocked
 * @param {Number} [options.keyExpirationTime=0] The number of seconds after the key creation time that the key expires
 * @return {module:key~Key}
 * @static
 */
export function generate(options) {
  var secretKeyPacket, secretSubkeyPacket;
  return Promise.resolve().then(() => {

    if (options.curve) {
      try {
        options.curve = enums.write(enums.curve, options.curve);
      } catch (e) {
        throw new Error('Not valid curve.')
      }
      if (options.curve === enums.curve.ed25519 || options.curve === enums.curve.curve25519) {
        options.keyType = options.keyType || enums.publicKey.eddsa;
      } else {
        options.keyType = options.keyType || enums.publicKey.ecdsa;
      }
      options.subkeyType = options.subkeyType || enums.publicKey.ecdh;
    } else if (options.numBits) {
      options.keyType = options.keyType || enums.publicKey.rsa_encrypt_sign;
      options.subkeyType = options.subkeyType || enums.publicKey.rsa_encrypt_sign;
    } else {
      throw new Error('Key type not specified.');
    }

    if (options.keyType !== enums.publicKey.rsa_encrypt_sign &&
        options.keyType !== enums.publicKey.ecdsa &&
        options.keyType !== enums.publicKey.eddsa) {
      // RSA Encrypt-Only and RSA Sign-Only are deprecated and SHOULD NOT be generated
      throw new Error('Unsupported key type');
    }

    if (options.subkeyType !== enums.publicKey.rsa_encrypt_sign &&
        options.subkeyType !== enums.publicKey.ecdh) {
      // RSA Encrypt-Only and RSA Sign-Only are deprecated and SHOULD NOT be generated
      throw new Error('Unsupported subkey type');
    }

    if (!options.passphrase) { // Key without passphrase is unlocked by definition
      options.unlocked = true;
    }
    if (String.prototype.isPrototypeOf(options.userIds) || typeof options.userIds === 'string') {
      options.userIds = [options.userIds];
    }

    return Promise.all([generateSecretKey(), generateSecretSubkey()]).then(() => {
      return wrapKeyObject(secretKeyPacket, secretSubkeyPacket, options);
    });
  });

  function generateSecretKey() {
    secretKeyPacket = new packet.SecretKey();
    secretKeyPacket.packets = null;
    secretKeyPacket.algorithm = enums.read(enums.publicKey, options.keyType);
    options.curve = options.curve === enums.curve.curve25519 ? enums.curve.ed25519 : options.curve;
    return secretKeyPacket.generate(options.numBits, options.curve);
  }

  function generateSecretSubkey() {
    secretSubkeyPacket = new packet.SecretSubkey();
    secretKeyPacket.packets = null;
    secretSubkeyPacket.algorithm = enums.read(enums.publicKey, options.subkeyType);
    options.curve = options.curve === enums.curve.ed25519 ? enums.curve.curve25519 : options.curve;
    return secretSubkeyPacket.generate(options.numBits, options.curve);
  }
}

/**
 * Reformats and signs an OpenPGP with a given User ID. Currently only supports RSA keys.
 * @param {module:key~Key} options.privateKey   The private key to reformat
 * @param {module:enums.publicKey} [options.keyType=module:enums.publicKey.rsa_encrypt_sign]
 * @param {String|Array<String>}  options.userIds    assumes already in form of "User Name <username@email.com>"
                                                     If array is used, the first userId is set as primary user Id
 * @param {String}  options.passphrase The passphrase used to encrypt the resulting private key
 * @param {Boolean} [options.unlocked=false]    The secret part of the generated key is unlocked
 * @param {Number} [options.keyExpirationTime=0] The number of seconds after the key creation time that the key expires
 * @return {module:key~Key}
 * @static
 */
export function reformat(options) {
  var secretKeyPacket, secretSubkeyPacket;
  return Promise.resolve().then(() => {

    options.keyType = options.keyType || enums.publicKey.rsa_encrypt_sign;
    if (options.keyType !== enums.publicKey.rsa_encrypt_sign) { // RSA Encrypt-Only and RSA Sign-Only are deprecated and SHOULD NOT be generated
      throw new Error('Only RSA Encrypt or Sign supported');
    }

    if (!options.privateKey.decrypt()) {
      throw new Error('Key not decrypted');
    }

    if (!options.passphrase) { // Key without passphrase is unlocked by definition
      options.unlocked = true;
    }
    if (String.prototype.isPrototypeOf(options.userIds) || typeof options.userIds === 'string') {
      options.userIds = [options.userIds];
    }
    var packetlist = options.privateKey.toPacketlist();
    for (var i = 0; i < packetlist.length; i++) {
      if (packetlist[i].tag === enums.packet.secretKey) {
        secretKeyPacket = packetlist[i];
        options.keyType = secretKeyPacket.algorithm;
      } else if (packetlist[i].tag === enums.packet.secretSubkey) {
        secretSubkeyPacket = packetlist[i];
        options.subkeyType = secretSubkeyPacket.algorithm;
      }
    }
    return wrapKeyObject(secretKeyPacket, secretSubkeyPacket, options);
  });
}

async function wrapKeyObject(secretKeyPacket, secretSubkeyPacket, options) {
  // set passphrase protection
  if (options.passphrase) {
    secretKeyPacket.encrypt(options.passphrase);
    secretSubkeyPacket.encrypt(options.passphrase);
  }

  var packetlist = new packet.List();

  packetlist.push(secretKeyPacket);

  await Promise.all(options.userIds.map(async function(userId, index) {

    var userIdPacket = new packet.Userid();
    userIdPacket.read(util.str2Uint8Array(userId));

    var dataToSign = {};
    dataToSign.userid = userIdPacket;
    dataToSign.key = secretKeyPacket;
    var signaturePacket = new packet.Signature();
    signaturePacket.signatureType = enums.signature.cert_generic;
    signaturePacket.publicKeyAlgorithm = options.keyType;
    signaturePacket.hashAlgorithm = getPreferredHashAlgorithm(secretKeyPacket);
    signaturePacket.keyFlags = [enums.keyFlags.certify_keys | enums.keyFlags.sign_data];
    signaturePacket.preferredSymmetricAlgorithms = [];
    // prefer aes256, aes128, then aes192 (no WebCrypto support: https://www.chromium.org/blink/webcrypto#TOC-AES-support)
    signaturePacket.preferredSymmetricAlgorithms.push(enums.symmetric.aes256);
    signaturePacket.preferredSymmetricAlgorithms.push(enums.symmetric.aes128);
    signaturePacket.preferredSymmetricAlgorithms.push(enums.symmetric.aes192);
    signaturePacket.preferredSymmetricAlgorithms.push(enums.symmetric.cast5);
    signaturePacket.preferredSymmetricAlgorithms.push(enums.symmetric.tripledes);
    signaturePacket.preferredHashAlgorithms = [];
    // prefer fast asm.js implementations (SHA-256). SHA-1 will not be secure much longer...move to bottom of list
    signaturePacket.preferredHashAlgorithms.push(enums.hash.sha256);
    signaturePacket.preferredHashAlgorithms.push(enums.hash.sha512);
    signaturePacket.preferredHashAlgorithms.push(enums.hash.sha1);
    signaturePacket.preferredCompressionAlgorithms = [];
    signaturePacket.preferredCompressionAlgorithms.push(enums.compression.zlib);
    signaturePacket.preferredCompressionAlgorithms.push(enums.compression.zip);
    if (index === 0) {
      signaturePacket.isPrimaryUserID = true;
    }
    if (config.integrity_protect) {
      signaturePacket.features = [];
      signaturePacket.features.push(1); // Modification Detection
    }
    if (options.keyExpirationTime > 0) {
      signaturePacket.keyExpirationTime = options.keyExpirationTime;
      signaturePacket.keyNeverExpires = false;
    }
    await signaturePacket.sign(secretKeyPacket, dataToSign);

    return {userIdPacket, signaturePacket};
  })).then(list => {
    list.forEach(({userIdPacket, signaturePacket}) => {
      packetlist.push(userIdPacket);
      packetlist.push(signaturePacket);
    });
  });

  var dataToSign = {};
  dataToSign.key = secretKeyPacket;
  dataToSign.bind = secretSubkeyPacket;
  var subkeySignaturePacket = new packet.Signature();
  subkeySignaturePacket.signatureType = enums.signature.subkey_binding;
  subkeySignaturePacket.publicKeyAlgorithm = options.keyType;
  subkeySignaturePacket.hashAlgorithm = getPreferredHashAlgorithm(secretSubkeyPacket);
  subkeySignaturePacket.keyFlags = [enums.keyFlags.encrypt_communication | enums.keyFlags.encrypt_storage];
  if (options.keyExpirationTime > 0) {
    subkeySignaturePacket.keyExpirationTime = options.keyExpirationTime;
    subkeySignaturePacket.keyNeverExpires = false;
  }
  await subkeySignaturePacket.sign(secretKeyPacket, dataToSign);

  packetlist.push(secretSubkeyPacket);
  packetlist.push(subkeySignaturePacket);

  if (!options.unlocked) {
    secretKeyPacket.clearPrivateParams();
    secretSubkeyPacket.clearPrivateParams();
  }

  return new Key(packetlist);
}

/**
 * Returns the preferred signature hash algorithm of a key
 * @param  {object} key
 * @return {String}
 */
export function getPreferredHashAlgorithm(key) {
  var hash_algo = config.prefer_hash_algorithm,
      pref_algo = hash_algo;
  if (Key.prototype.isPrototypeOf(key)) {
    var primaryUser = key.getPrimaryUser();
    if (primaryUser && primaryUser.selfCertificate.preferredHashAlgorithms) {
      pref_algo = primaryUser.selfCertificate.preferredHashAlgorithms[0];
      hash_algo = crypto.hash.getHashByteLength(hash_algo) <= crypto.hash.getHashByteLength(pref_algo) ?
        pref_algo : hash_algo;
    }
    key = key.getSigningKeyPacket();
  }
  switch(Object.getPrototypeOf(key)) {
    case packet.SecretKey.prototype:
    case packet.PublicKey.prototype:
    case packet.SecretSubkey.prototype:
    case packet.PublicSubkey.prototype:
      switch(key.algorithm) {
        case 'ecdh':
        case 'ecdsa':
        case 'eddsa':
          pref_algo = crypto.publicKey.elliptic.getPreferredHashAlgorithm(key.params[0]);
      }
  }
  return crypto.hash.getHashByteLength(hash_algo) <= crypto.hash.getHashByteLength(pref_algo) ?
    pref_algo : hash_algo;
}

/**
 * Returns the preferred symmetric algorithm for a set of keys
 * @param  {Array<module:key~Key>} keys Set of keys
 * @return {enums.symmetric}   Preferred symmetric algorithm
 */
export function getPreferredSymAlgo(keys) {
  var prioMap = {};
  keys.forEach(function(key) {
    var primaryUser = key.getPrimaryUser();
    if (!primaryUser || !primaryUser.selfCertificate.preferredSymmetricAlgorithms) {
      return config.encryption_cipher;
    }
    primaryUser.selfCertificate.preferredSymmetricAlgorithms.forEach(function(algo, index) {
      var entry = prioMap[algo] || (prioMap[algo] = {prio: 0, count: 0, algo: algo});
      entry.prio += 64 >> index;
      entry.count++;
    });
  });
  var prefAlgo = {prio: 0, algo: config.encryption_cipher};
  for (var algo in prioMap) {
    try {
      if (algo !== enums.symmetric.plaintext &&
          algo !== enums.symmetric.idea && // not implemented
          enums.read(enums.symmetric, algo) && // known algorithm
          prioMap[algo].count === keys.length && // available for all keys
          prioMap[algo].prio > prefAlgo.prio) {
        prefAlgo = prioMap[algo];
      }
    } catch (e) {}
  }
  return prefAlgo.algo;
}
