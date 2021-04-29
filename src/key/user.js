/**
 * @module key/User
 * @private
 */

import enums from '../enums';
import util from '../util';
import { PacketList } from '../packet';
import { mergeSignatures, isDataRevoked, createSignaturePacket } from './helper';

/**
 * Class that represents an user ID or attribute packet and the relevant signatures.
 */
class User {
  constructor(userPacket) {
    if (!(this instanceof User)) {
      return new User(userPacket);
    }
    this.userID = userPacket.constructor.tag === enums.packet.userID ? userPacket : null;
    this.userAttribute = userPacket.constructor.tag === enums.packet.userAttribute ? userPacket : null;
    this.selfCertifications = [];
    this.otherCertifications = [];
    this.revocationSignatures = [];
  }

  /**
   * Transforms structured user data to packetlist
   * @returns {PacketList}
   */
  toPacketlist() {
    const packetlist = new PacketList();
    packetlist.push(this.userID || this.userAttribute);
    packetlist.push(...this.revocationSignatures);
    packetlist.push(...this.selfCertifications);
    packetlist.push(...this.otherCertifications);
    return packetlist;
  }

  /**
   * Signs user
   * @param  {SecretKeyPacket|
   *          PublicKeyPacket}          primaryKey  The primary key packet
   * @param {Array<Key>} privateKeys - Decrypted private keys for signing
   * @param {Object} config - Full configuration
   * @returns {Promise<Key>} New user with new certificate signatures.
   * @async
   */
  async sign(primaryKey, privateKeys, config) {
    const dataToSign = {
      userID: this.userID,
      userAttribute: this.userAttribute,
      key: primaryKey
    };
    const user = new User(dataToSign.userID || dataToSign.userAttribute);
    user.otherCertifications = await Promise.all(privateKeys.map(async function(privateKey) {
      if (privateKey.isPublic()) {
        throw new Error('Need private key for signing');
      }
      if (privateKey.hasSameFingerprintAs(primaryKey)) {
        throw new Error('Not implemented for self signing');
      }
      const signingKey = await privateKey.getSigningKey(undefined, undefined, undefined, config);
      return createSignaturePacket(dataToSign, privateKey, signingKey.keyPacket, {
        // Most OpenPGP implementations use generic certification (0x10)
        signatureType: enums.signature.certGeneric,
        keyFlags: [enums.keyFlags.certifyKeys | enums.keyFlags.signData]
      }, undefined, undefined, undefined, config);
    }));
    await user.update(this, primaryKey);
    return user;
  }

  /**
   * Checks if a given certificate of the user is revoked
   * @param  {SecretKeyPacket|
   *          PublicKeyPacket} primaryKey    The primary key packet
   * @param {SignaturePacket} certificate - The certificate to verify
   * @param  {PublicSubkeyPacket|
   *          SecretSubkeyPacket|
   *          PublicKeyPacket|
   *          SecretKeyPacket} key, optional The key to verify the signature
   * @param {Date} date - Use the given date instead of the current time
   * @param {Object} config - Full configuration
   * @returns {Promise<Boolean>} True if the certificate is revoked.
   * @async
   */
  async isRevoked(primaryKey, certificate, key, date = new Date(), config) {
    return isDataRevoked(
      primaryKey, enums.signature.certRevocation, {
        key: primaryKey,
        userID: this.userID,
        userAttribute: this.userAttribute
      }, this.revocationSignatures, certificate, key, date, config
    );
  }

  /**
   * Verifies the user certificate. Throws if the user certificate is invalid.
   * @param  {SecretKeyPacket|
   *          PublicKeyPacket} primaryKey  The primary key packet
   * @param {SignaturePacket} certificate - A certificate of this user
   * @param {Array<Key>} keys - Array of keys to verify certificate signatures
   * @param {Date} date - Use the given date instead of the current time
   * @param {Object} config - Full configuration
   * @returns {Promise<true|null>} Status of the certificate.
   * @async
   */
  async verifyCertificate(primaryKey, certificate, keys, date = new Date(), config) {
    const that = this;
    const keyID = certificate.issuerKeyID;
    const dataToVerify = {
      userID: this.userID,
      userAttribute: this.userAttribute,
      key: primaryKey
    };
    const results = await Promise.all(keys.map(async function(key) {
      if (!key.getKeyIDs().some(id => id.equals(keyID))) {
        return null;
      }
      const signingKey = await key.getSigningKey(keyID, date, undefined, config);
      if (certificate.revoked || await that.isRevoked(primaryKey, certificate, signingKey.keyPacket, date, config)) {
        throw new Error('User certificate is revoked');
      }
      try {
        certificate.verified || await certificate.verify(signingKey.keyPacket, enums.signature.certGeneric, dataToVerify, undefined, config);
      } catch (e) {
        throw util.wrapError('User certificate is invalid', e);
      }
      if (certificate.isExpired(date)) {
        throw new Error('User certificate is expired');
      }
      return true;
    }));
    return results.find(result => result !== null) || null;
  }

  /**
   * Verifies all user certificates
   * @param  {SecretKeyPacket|
   *          PublicKeyPacket} primaryKey The primary key packet
   * @param {Array<Key>} keys - Array of keys to verify certificate signatures
   * @param {Date} date - Use the given date instead of the current time
   * @param {Object} config - Full configuration
   * @returns {Promise<Array<{
   *   keyID: module:type/keyid~KeyID,
   *   valid: Boolean
   * }>>} List of signer's keyID and validity of signature
   * @async
   */
  async verifyAllCertifications(primaryKey, keys, date = new Date(), config) {
    const that = this;
    const certifications = this.selfCertifications.concat(this.otherCertifications);
    return Promise.all(certifications.map(async function(certification) {
      return {
        keyID: certification.issuerKeyID,
        valid: await that.verifyCertificate(primaryKey, certification, keys, date, config).catch(() => false)
      };
    }));
  }

  /**
   * Verify User. Checks for existence of self signatures, revocation signatures
   * and validity of self signature.
   * @param  {SecretKeyPacket|
   *          PublicKeyPacket} primaryKey The primary key packet
   * @param {Date} date - Use the given date instead of the current time
   * @param {Object} config - Full configuration
   * @returns {Promise<true>} Status of user.
   * @throws {Error} if there are no valid self signatures.
   * @async
   */
  async verify(primaryKey, date = new Date(), config) {
    if (!this.selfCertifications.length) {
      throw new Error('No self-certifications');
    }
    const that = this;
    const dataToVerify = {
      userID: this.userID,
      userAttribute: this.userAttribute,
      key: primaryKey
    };
    // TODO replace when Promise.some or Promise.any are implemented
    let exception;
    for (let i = this.selfCertifications.length - 1; i >= 0; i--) {
      try {
        const selfCertification = this.selfCertifications[i];
        if (selfCertification.revoked || await that.isRevoked(primaryKey, selfCertification, undefined, date, config)) {
          throw new Error('Self-certification is revoked');
        }
        try {
          selfCertification.verified || await selfCertification.verify(primaryKey, enums.signature.certGeneric, dataToVerify, undefined, config);
        } catch (e) {
          throw util.wrapError('Self-certification is invalid', e);
        }
        if (selfCertification.isExpired(date)) {
          throw new Error('Self-certification is expired');
        }
        return true;
      } catch (e) {
        exception = e;
      }
    }
    throw exception;
  }

  /**
   * Update user with new components from specified user
   * @param {User} user - Source user to merge
   * @param  {SecretKeyPacket|
   *          SecretSubkeyPacket} primaryKey primary key used for validation
   * @param {Object} config - Full configuration
   * @returns {Promise<undefined>}
   * @async
   */
  async update(user, primaryKey, config) {
    const dataToVerify = {
      userID: this.userID,
      userAttribute: this.userAttribute,
      key: primaryKey
    };
    // self signatures
    await mergeSignatures(user, this, 'selfCertifications', async function(srcSelfSig) {
      try {
        srcSelfSig.verified || await srcSelfSig.verify(primaryKey, enums.signature.certGeneric, dataToVerify, undefined, config);
        return true;
      } catch (e) {
        return false;
      }
    });
    // other signatures
    await mergeSignatures(user, this, 'otherCertifications');
    // revocation signatures
    await mergeSignatures(user, this, 'revocationSignatures', function(srcRevSig) {
      return isDataRevoked(primaryKey, enums.signature.certRevocation, dataToVerify, [srcRevSig], undefined, undefined, undefined, config);
    });
  }
}

export default User;
