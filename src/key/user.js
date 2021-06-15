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
  * @param {UserIDPacket|UserAttributePacket} userPacket - packet containing the user info
  * @param {Key} mainKey - reference to main Key object containing the primary key and subkeys that the user is associated with
 */
class User {
  constructor(userPacket, mainKey) {
    this.userID = userPacket.constructor.tag === enums.packet.userID ? userPacket : null;
    this.userAttribute = userPacket.constructor.tag === enums.packet.userAttribute ? userPacket : null;
    this.selfCertifications = [];
    this.otherCertifications = [];
    this.revocationSignatures = [];
    this.mainKey = mainKey;
  }

  /**
   * Transforms structured user data to packetlist
   * @returns {PacketList}
   */
  toPacketList() {
    const packetlist = new PacketList();
    packetlist.push(this.userID || this.userAttribute);
    packetlist.push(...this.revocationSignatures);
    packetlist.push(...this.selfCertifications);
    packetlist.push(...this.otherCertifications);
    return packetlist;
  }

  /**
   * Shallow clone
   * @returns {User}
   */
  clone() {
    const user = new User(this.userID || this.userAttribute, this.mainKey);
    user.selfCertifications = [...this.selfCertifications];
    user.otherCertifications = [...this.otherCertifications];
    user.revocationSignatures = [...this.revocationSignatures];
    return user;
  }

  /**
   * Generate third-party certifications over this user and its primary key
   * @param {Array<PrivateKey>} signingKeys - Decrypted private keys for signing
   * @param {Date} [date] - Date to use as creation date of the certificate, instead of the current time
   * @param {Object} config - Full configuration
   * @returns {Promise<User>} New user with new certifications.
   * @async
   */
  async certify(signingKeys, date, config) {
    const primaryKey = this.mainKey.keyPacket;
    const dataToSign = {
      userID: this.userID,
      userAttribute: this.userAttribute,
      key: primaryKey
    };
    const user = new User(dataToSign.userID || dataToSign.userAttribute, this.mainKey);
    user.otherCertifications = await Promise.all(signingKeys.map(async function(privateKey) {
      if (privateKey.isPublic()) {
        throw new Error('Need private key for signing');
      }
      if (privateKey.hasSameFingerprintAs(primaryKey)) {
        throw new Error("The user's own key can only be used for self-certifications");
      }
      const signingKey = await privateKey.getSigningKey(undefined, date, undefined, config);
      return createSignaturePacket(dataToSign, privateKey, signingKey.keyPacket, {
        // Most OpenPGP implementations use generic certification (0x10)
        signatureType: enums.signature.certGeneric,
        keyFlags: [enums.keyFlags.certifyKeys | enums.keyFlags.signData]
      }, date, undefined, undefined, config);
    }));
    await user.update(this, date, config);
    return user;
  }

  /**
   * Checks if a given certificate of the user is revoked
   * @param {SignaturePacket} certificate - The certificate to verify
   * @param  {PublicSubkeyPacket|
   *          SecretSubkeyPacket|
   *          PublicKeyPacket|
   *          SecretKeyPacket} [keyPacket] The key packet to verify the signature, instead of the primary key
   * @param {Date} [date] - Use the given date for verification instead of the current time
   * @param {Object} config - Full configuration
   * @returns {Promise<Boolean>} True if the certificate is revoked.
   * @async
   */
  async isRevoked(certificate, keyPacket, date = new Date(), config) {
    const primaryKey = this.mainKey.keyPacket;
    return isDataRevoked(primaryKey, enums.signature.certRevocation, {
      key: primaryKey,
      userID: this.userID,
      userAttribute: this.userAttribute
    }, this.revocationSignatures, certificate, keyPacket, date, config);
  }

  /**
   * Verifies the user certificate.
   * @param {SignaturePacket} certificate - A certificate of this user
   * @param {Array<PublicKey>} verificationKeys - Array of keys to verify certificate signatures
   * @param {Date} [date] - Use the given date instead of the current time
   * @param {Object} config - Full configuration
   * @returns {Promise<true|null>} true if the certificate could be verified, or null if the verification keys do not correspond to the certificate
   * @throws if the user certificate is invalid.
   * @async
   */
  async verifyCertificate(certificate, verificationKeys, date = new Date(), config) {
    const that = this;
    const primaryKey = this.mainKey.keyPacket;
    const dataToVerify = {
      userID: this.userID,
      userAttribute: this.userAttribute,
      key: primaryKey
    };
    const { issuerKeyID } = certificate;
    const issuerKeys = verificationKeys.filter(key => key.getKeys(issuerKeyID).length > 0);
    if (issuerKeys.length === 0) {
      return null;
    }
    await Promise.all(issuerKeys.map(async key => {
      const signingKey = await key.getSigningKey(issuerKeyID, certificate.created, undefined, config);
      if (certificate.revoked || await that.isRevoked(certificate, signingKey.keyPacket, date, config)) {
        throw new Error('User certificate is revoked');
      }
      try {
        await certificate.verify(signingKey.keyPacket, enums.signature.certGeneric, dataToVerify, date, undefined, config);
      } catch (e) {
        throw util.wrapError('User certificate is invalid', e);
      }
    }));
    return true;
  }

  /**
   * Verifies all user certificates
   * @param {Array<PublicKey>} verificationKeys - Array of keys to verify certificate signatures
   * @param {Date} [date] - Use the given date instead of the current time
   * @param {Object} config - Full configuration
   * @returns {Promise<Array<{
   *   keyID: module:type/keyid~KeyID,
   *   valid: Boolean | null
   * }>>} List of signer's keyID and validity of signature.
   *      Signature validity is null if the verification keys do not correspond to the certificate.
   * @async
   */
  async verifyAllCertifications(verificationKeys, date = new Date(), config) {
    const that = this;
    const certifications = this.selfCertifications.concat(this.otherCertifications);
    return Promise.all(certifications.map(async certification => ({
      keyID: certification.issuerKeyID,
      valid: await that.verifyCertificate(certification, verificationKeys, date, config).catch(() => false)
    })));
  }

  /**
   * Verify User. Checks for existence of self signatures, revocation signatures
   * and validity of self signature.
   * @param {Date} date - Use the given date instead of the current time
   * @param {Object} config - Full configuration
   * @returns {Promise<true>} Status of user.
   * @throws {Error} if there are no valid self signatures.
   * @async
   */
  async verify(date = new Date(), config) {
    if (!this.selfCertifications.length) {
      throw new Error('No self-certifications found');
    }
    const that = this;
    const primaryKey = this.mainKey.keyPacket;
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
        if (selfCertification.revoked || await that.isRevoked(selfCertification, undefined, date, config)) {
          throw new Error('Self-certification is revoked');
        }
        try {
          await selfCertification.verify(primaryKey, enums.signature.certGeneric, dataToVerify, date, undefined, config);
        } catch (e) {
          throw util.wrapError('Self-certification is invalid', e);
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
   * @param {User} sourceUser - Source user to merge
   * @param {Date} date - Date to verify the validity of signatures
   * @param {Object} config - Full configuration
   * @returns {Promise<undefined>}
   * @async
   */
  async update(sourceUser, date, config) {
    const primaryKey = this.mainKey.keyPacket;
    const dataToVerify = {
      userID: this.userID,
      userAttribute: this.userAttribute,
      key: primaryKey
    };
    // self signatures
    await mergeSignatures(sourceUser, this, 'selfCertifications', date, async function(srcSelfSig) {
      try {
        await srcSelfSig.verify(primaryKey, enums.signature.certGeneric, dataToVerify, date, false, config);
        return true;
      } catch (e) {
        return false;
      }
    });
    // other signatures
    await mergeSignatures(sourceUser, this, 'otherCertifications', date);
    // revocation signatures
    await mergeSignatures(sourceUser, this, 'revocationSignatures', date, function(srcRevSig) {
      return isDataRevoked(primaryKey, enums.signature.certRevocation, dataToVerify, [srcRevSig], undefined, undefined, date, config);
    });
  }
}

export default User;
