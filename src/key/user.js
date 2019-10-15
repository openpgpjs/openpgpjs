/**
 * @requires enums
 * @requires packet
 * @requires key/helper
 * @module key/User
 */

import packet from '../packet';
import enums from '../enums';
import { mergeSignatures, isDataRevoked, createSignaturePacket } from './helper';

/**
 * @class
 * @classdesc Class that represents an user ID or attribute packet and the relevant signatures.
 */
export default function User(userPacket) {
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
User.prototype.isRevoked = async function(primaryKey, certificate, key, date = new Date()) {
  return isDataRevoked(
    primaryKey, enums.signature.cert_revocation, {
      key: primaryKey,
      userId: this.userId,
      userAttribute: this.userAttribute
    }, this.revocationSignatures, certificate, key, date
  );
};


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
User.prototype.verifyCertificate = async function(primaryKey, certificate, keys, date = new Date()) {
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
    if (certificate.revoked || await that.isRevoked(primaryKey, certificate, signingKey.keyPacket, date)) {
      return enums.keyStatus.revoked;
    }
    if (!(certificate.verified || await certificate.verify(signingKey.keyPacket, enums.signature.cert_generic, dataToVerify))) {
      return enums.keyStatus.invalid;
    }
    if (certificate.isExpired(date)) {
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
 * @param  {Date}                     date        Use the given date instead of the current time
 * @returns {Promise<Array<{keyid: module:type/keyid,
 *                          valid: Boolean}>>}   List of signer's keyid and validity of signature
 * @async
 */
User.prototype.verifyAllCertifications = async function(primaryKey, keys, date = new Date()) {
  const that = this;
  const certifications = this.selfCertifications.concat(this.otherCertifications);
  return Promise.all(certifications.map(async function(certification) {
    const status = await that.verifyCertificate(primaryKey, certification, keys, date);
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
 * @param  {Date}                    date       Use the given date instead of the current time
 * @returns {Promise<module:enums.keyStatus>}    Status of user
 * @async
 */
User.prototype.verify = async function(primaryKey, date = new Date()) {
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
      if (selfCertification.revoked || await that.isRevoked(primaryKey, selfCertification, undefined, date)) {
        return enums.keyStatus.revoked;
      }
      if (!(selfCertification.verified || await selfCertification.verify(primaryKey, enums.signature.cert_generic, dataToVerify))) {
        return enums.keyStatus.invalid;
      }
      if (selfCertification.isExpired(date)) {
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
