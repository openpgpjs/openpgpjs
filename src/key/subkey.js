/**
 * @requires enums
 * @requires key/helper
 * @requires packet
 * @module key/SubKey
 */

import enums from '../enums';
import * as helper from './helper';
import packet from '../packet';

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
export default function SubKey(subKeyPacket) {
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
SubKey.prototype.isRevoked = async function(primaryKey, signature, key, date = new Date()) {
  return helper.isDataRevoked(
    primaryKey, enums.signature.subkey_revocation, {
      key: primaryKey,
      bind: this.keyPacket
    }, this.revocationSignatures, signature, key, date
  );
};


/**
 * Verify subkey. Checks for revocation signatures, expiration time
 * and valid binding signature. Throws if the subkey is invalid.
 * @param  {module:packet.SecretKey|
 *          module:packet.PublicKey} primaryKey  The primary key packet
 * @param  {Date}                    date        Use the given date instead of the current time
 * @returns {Promise<undefined>}
 * @async
 */
SubKey.prototype.verify = async function(primaryKey, date = new Date()) {
  const dataToVerify = { key: primaryKey, bind: this.keyPacket };
  // check subkey binding signatures
  const bindingSignature = await helper.getLatestValidSignature(this.bindingSignatures, primaryKey, enums.signature.subkey_binding, dataToVerify, date);
  // check binding signature is not revoked
  if (bindingSignature.revoked || await this.isRevoked(primaryKey, bindingSignature, null, date)) {
    throw new Error('Subkey is revoked');
  }
  // check for expiration time
  if (helper.isDataExpired(this.keyPacket, bindingSignature, date)) {
    throw new Error('Subkey is expired');
  }
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
SubKey.prototype.getExpirationTime = async function(primaryKey, date = new Date()) {
  const dataToVerify = { key: primaryKey, bind: this.keyPacket };
  let bindingSignature;
  try {
    bindingSignature = await helper.getLatestValidSignature(this.bindingSignatures, primaryKey, enums.signature.subkey_binding, dataToVerify, date);
  } catch (e) {
    return null;
  }
  const keyExpiry = helper.getExpirationTime(this.keyPacket, bindingSignature);
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
  await helper.mergeSignatures(subKey, this, 'bindingSignatures', async function(srcBindSig) {
    for (let i = 0; i < that.bindingSignatures.length; i++) {
      if (that.bindingSignatures[i].issuerKeyId.equals(srcBindSig.issuerKeyId)) {
        if (srcBindSig.created > that.bindingSignatures[i].created) {
          that.bindingSignatures[i] = srcBindSig;
        }
        return false;
      }
    }
    try {
      return srcBindSig.verified || await srcBindSig.verify(primaryKey, enums.signature.subkey_binding, dataToVerify);
    } catch (e) {
      return false;
    }
  });
  // revocation signatures
  await helper.mergeSignatures(subKey, this, 'revocationSignatures', function(srcRevSig) {
    return helper.isDataRevoked(primaryKey, enums.signature.subkey_revocation, dataToVerify, [srcRevSig]);
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
  flag: reasonForRevocationFlag = enums.reasonForRevocation.no_reason,
  string: reasonForRevocationString = ''
} = {}, date = new Date()) {
  const dataToSign = { key: primaryKey, bind: this.keyPacket };
  const subKey = new SubKey(this.keyPacket);
  subKey.revocationSignatures.push(await helper.createSignaturePacket(dataToSign, null, primaryKey, {
    signatureType: enums.signature.subkey_revocation,
    reasonForRevocationFlag: enums.write(enums.reasonForRevocation, reasonForRevocationFlag),
    reasonForRevocationString
  }, date));
  await subKey.update(this, primaryKey);
  return subKey;
};

['getKeyId', 'getFingerprint', 'getAlgorithmInfo', 'getCreationTime', 'isDecrypted'].forEach(name => {
  SubKey.prototype[name] =
    function() {
      return this.keyPacket[name]();
    };
});

SubKey.prototype.hasSameFingerprintAs =
  function(other) {
    return this.keyPacket.hasSameFingerprintAs(other.keyPacket || other);
  };
