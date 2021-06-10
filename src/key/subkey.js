/**
 * @module key/Subkey
 * @private
 */

import enums from '../enums';
import * as helper from './helper';
import { PacketList } from '../packet';
import defaultConfig from '../config';

/**
 * Class that represents a subkey packet and the relevant signatures.
 * @borrows PublicSubkeyPacket#getKeyID as Subkey#getKeyID
 * @borrows PublicSubkeyPacket#getFingerprint as Subkey#getFingerprint
 * @borrows PublicSubkeyPacket#hasSameFingerprintAs as Subkey#hasSameFingerprintAs
 * @borrows PublicSubkeyPacket#getAlgorithmInfo as Subkey#getAlgorithmInfo
 * @borrows PublicSubkeyPacket#getCreationTime as Subkey#getCreationTime
 * @borrows PublicSubkeyPacket#isDecrypted as Subkey#isDecrypted
 */
class Subkey {
  /**
   * @param {SecretSubkeyPacket|PublicSubkeyPacket} subkeyPacket - subkey packet to hold in the Subkey
   * @param {Key} mainKey - reference to main Key object, containing the primary key packet corresponding to the subkey
   */
  constructor(subkeyPacket, mainKey) {
    this.keyPacket = subkeyPacket;
    this.bindingSignatures = [];
    this.revocationSignatures = [];
    this.mainKey = mainKey;
  }

  /**
   * Transforms structured subkey data to packetlist
   * @returns {PacketList}
   */
  toPacketList() {
    const packetlist = new PacketList();
    packetlist.push(this.keyPacket);
    packetlist.push(...this.revocationSignatures);
    packetlist.push(...this.bindingSignatures);
    return packetlist;
  }

  /**
   * Shallow clone
   * @return {Subkey}
   */
  clone() {
    const subkey = new Subkey(this.keyPacket, this.mainKey);
    subkey.bindingSignatures = [...this.bindingSignatures];
    subkey.revocationSignatures = [...this.revocationSignatures];
    return subkey;
  }

  /**
   * Checks if a binding signature of a subkey is revoked
   * @param {SignaturePacket} signature - The binding signature to verify
   * @param  {PublicSubkeyPacket|
   *          SecretSubkeyPacket|
   *          PublicKeyPacket|
   *          SecretKeyPacket} key, optional The key to verify the signature
   * @param {Date} [date] - Use the given date for verification instead of the current time
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Boolean>} True if the binding signature is revoked.
   * @async
   */
  async isRevoked(signature, key, date = new Date(), config = defaultConfig) {
    const primaryKey = this.mainKey.keyPacket;
    return helper.isDataRevoked(
      primaryKey, enums.signature.subkeyRevocation, {
        key: primaryKey,
        bind: this.keyPacket
      }, this.revocationSignatures, signature, key, date, config
    );
  }

  /**
   * Verify subkey. Checks for revocation signatures, expiration time
   * and valid binding signature.
   * @param {Date} date - Use the given date instead of the current time
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<SignaturePacket>}
   * @throws {Error}           if the subkey is invalid.
   * @async
   */
  async verify(date = new Date(), config = defaultConfig) {
    const primaryKey = this.mainKey.keyPacket;
    const dataToVerify = { key: primaryKey, bind: this.keyPacket };
    // check subkey binding signatures
    const bindingSignature = await helper.getLatestValidSignature(this.bindingSignatures, primaryKey, enums.signature.subkeyBinding, dataToVerify, date, config);
    // check binding signature is not revoked
    if (bindingSignature.revoked || await this.isRevoked(bindingSignature, null, date, config)) {
      throw new Error('Subkey is revoked');
    }
    // check for expiration time
    if (helper.isDataExpired(this.keyPacket, bindingSignature, date)) {
      throw new Error('Subkey is expired');
    }
    return bindingSignature;
  }

  /**
   * Returns the expiration time of the subkey or Infinity if key does not expire.
   * Returns null if the subkey is invalid.
   * @param {Date} date - Use the given date instead of the current time
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Date | Infinity | null>}
   * @async
   */
  async getExpirationTime(date = new Date(), config = defaultConfig) {
    const primaryKey = this.mainKey.keyPacket;
    const dataToVerify = { key: primaryKey, bind: this.keyPacket };
    let bindingSignature;
    try {
      bindingSignature = await helper.getLatestValidSignature(this.bindingSignatures, primaryKey, enums.signature.subkeyBinding, dataToVerify, date, config);
    } catch (e) {
      return null;
    }
    const keyExpiry = helper.getKeyExpirationTime(this.keyPacket, bindingSignature);
    const sigExpiry = bindingSignature.getExpirationTime();
    return keyExpiry < sigExpiry ? keyExpiry : sigExpiry;
  }

  /**
   * Update subkey with new components from specified subkey
   * @param {Subkey} subkey - Source subkey to merge
   * @param {Date} [date] - Date to verify validity of signatures
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @throws {Error} if update failed
   * @async
   */
  async update(subkey, date = new Date(), config = defaultConfig) {
    const primaryKey = this.mainKey.keyPacket;
    if (!this.hasSameFingerprintAs(subkey)) {
      throw new Error('Subkey update method: fingerprints of subkeys not equal');
    }
    // key packet
    if (this.keyPacket.constructor.tag === enums.packet.publicSubkey &&
        subkey.keyPacket.constructor.tag === enums.packet.secretSubkey) {
      this.keyPacket = subkey.keyPacket;
    }
    // update missing binding signatures
    const that = this;
    const dataToVerify = { key: primaryKey, bind: that.keyPacket };
    await helper.mergeSignatures(subkey, this, 'bindingSignatures', date, async function(srcBindSig) {
      for (let i = 0; i < that.bindingSignatures.length; i++) {
        if (that.bindingSignatures[i].issuerKeyID.equals(srcBindSig.issuerKeyID)) {
          if (srcBindSig.created > that.bindingSignatures[i].created) {
            that.bindingSignatures[i] = srcBindSig;
          }
          return false;
        }
      }
      try {
        await srcBindSig.verify(primaryKey, enums.signature.subkeyBinding, dataToVerify, date, undefined, config);
        return true;
      } catch (e) {
        return false;
      }
    });
    // revocation signatures
    await helper.mergeSignatures(subkey, this, 'revocationSignatures', date, function(srcRevSig) {
      return helper.isDataRevoked(primaryKey, enums.signature.subkeyRevocation, dataToVerify, [srcRevSig], undefined, undefined, date, config);
    });
  }

  /**
   * Revokes the subkey
   * @param {SecretKeyPacket} primaryKey - decrypted private primary key for revocation
   * @param {Object} reasonForRevocation - optional, object indicating the reason for revocation
   * @param  {module:enums.reasonForRevocation} reasonForRevocation.flag optional, flag indicating the reason for revocation
   * @param  {String} reasonForRevocation.string optional, string explaining the reason for revocation
   * @param {Date} date - optional, override the creationtime of the revocation signature
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Subkey>} New subkey with revocation signature.
   * @async
   */
  async revoke(
    primaryKey,
    {
      flag: reasonForRevocationFlag = enums.reasonForRevocation.noReason,
      string: reasonForRevocationString = ''
    } = {},
    date = new Date(),
    config = defaultConfig
  ) {
    const dataToSign = { key: primaryKey, bind: this.keyPacket };
    const subkey = new Subkey(this.keyPacket, this.mainKey);
    subkey.revocationSignatures.push(await helper.createSignaturePacket(dataToSign, null, primaryKey, {
      signatureType: enums.signature.subkeyRevocation,
      reasonForRevocationFlag: enums.write(enums.reasonForRevocation, reasonForRevocationFlag),
      reasonForRevocationString
    }, date, undefined, false, config));
    await subkey.update(this);
    return subkey;
  }

  hasSameFingerprintAs(other) {
    return this.keyPacket.hasSameFingerprintAs(other.keyPacket || other);
  }
}

['getKeyID', 'getFingerprint', 'getAlgorithmInfo', 'getCreationTime', 'isDecrypted'].forEach(name => {
  Subkey.prototype[name] =
    function() {
      return this.keyPacket[name]();
    };
});

export default Subkey;
