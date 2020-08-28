/**
 * @fileoverview Provides helpers methods for key module
 * @requires packet
 * @requires enums
 * @requires config
 * @requires crypto
 * @module key/helper
 */

import packet from '../packet';
import enums from '../enums';
import config from '../config';
import crypto from '../crypto';
import util from '../util';

export async function generateSecretSubkey(options) {
  const secretSubkeyPacket = new packet.SecretSubkey(options.date);
  secretSubkeyPacket.packets = null;
  secretSubkeyPacket.algorithm = enums.read(enums.publicKey, options.algorithm);
  await secretSubkeyPacket.generate(options.rsaBits, options.curve);
  return secretSubkeyPacket;
}

export async function generateSecretKey(options) {
  const secretKeyPacket = new packet.SecretKey(options.date);
  secretKeyPacket.packets = null;
  secretKeyPacket.algorithm = enums.read(enums.publicKey, options.algorithm);
  await secretKeyPacket.generate(options.rsaBits, options.curve);
  return secretKeyPacket;
}

/**
 * Returns the valid and non-expired signature that has the latest creation date, while ignoring signatures created in the future.
 * @param  {Array<module:packet.Signature>} signatures  List of signatures
 * @param  {Date}                           date        Use the given date instead of the current time
 * @returns {Promise<module:packet.Signature>} The latest valid signature
 * @async
 */
export async function getLatestValidSignature(signatures, primaryKey, signatureType, dataToVerify, date = new Date()) {
  let signature;
  let exception;
  for (let i = signatures.length - 1; i >= 0; i--) {
    try {
      if (
        (!signature || signatures[i].created >= signature.created) &&
        // check binding signature is not expired (ie, check for V4 expiration time)
        !signatures[i].isExpired(date) &&
        // check binding signature is verified
        (signatures[i].verified || await signatures[i].verify(primaryKey, signatureType, dataToVerify))
      ) {
        signature = signatures[i];
      }
    } catch (e) {
      exception = e;
    }
  }
  if (!signature) {
    throw util.wrapError(
      `Could not find valid ${enums.read(enums.signature, signatureType)} signature in key ${primaryKey.getKeyId().toHex()}`
        .replace('cert_generic ', 'self-')
        .replace('_', ' ')
      , exception);
  }
  return signature;
}

export function isDataExpired(keyPacket, signature, date = new Date()) {
  const normDate = util.normalizeDate(date);
  if (normDate !== null) {
    const expirationTime = getExpirationTime(keyPacket, signature);
    return !(keyPacket.created <= normDate && normDate <= expirationTime) ||
      (signature && signature.isExpired(date));
  }
  return false;
}

/**
 * Create Binding signature to the key according to the {@link https://tools.ietf.org/html/rfc4880#section-5.2.1}
 * @param {module:packet.SecretSubkey} subkey Subkey key packet
 * @param {module:packet.SecretKey} primaryKey Primary key packet
 * @param {Object} options
 */
export async function createBindingSignature(subkey, primaryKey, options) {
  const dataToSign = {};
  dataToSign.key = primaryKey;
  dataToSign.bind = subkey;
  const subkeySignaturePacket = new packet.Signature(options.date);
  subkeySignaturePacket.signatureType = enums.signature.subkey_binding;
  subkeySignaturePacket.publicKeyAlgorithm = primaryKey.algorithm;
  subkeySignaturePacket.hashAlgorithm = await getPreferredHashAlgo(null, subkey);
  if (options.sign) {
    subkeySignaturePacket.keyFlags = [enums.keyFlags.sign_data];
    subkeySignaturePacket.embeddedSignature = await createSignaturePacket(dataToSign, null, subkey, {
      signatureType: enums.signature.key_binding
    }, options.date);
  } else {
    subkeySignaturePacket.keyFlags = [enums.keyFlags.encrypt_communication | enums.keyFlags.encrypt_storage];
  }
  if (options.keyExpirationTime > 0) {
    subkeySignaturePacket.keyExpirationTime = options.keyExpirationTime;
    subkeySignaturePacket.keyNeverExpires = false;
  }
  await subkeySignaturePacket.sign(primaryKey, dataToSign);
  return subkeySignaturePacket;
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
export async function getPreferredHashAlgo(key, keyPacket, date = new Date(), userId = {}) {
  let hash_algo = config.prefer_hash_algorithm;
  let pref_algo = hash_algo;
  if (key) {
    const primaryUser = await key.getPrimaryUser(date, userId);
    if (primaryUser.selfCertification.preferredHashAlgorithms) {
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
export async function getPreferredAlgo(type, keys, date = new Date(), userIds = []) {
  const prefProperty = type === 'symmetric' ? 'preferredSymmetricAlgorithms' : 'preferredAeadAlgorithms';
  const defaultAlgo = type === 'symmetric' ? enums.symmetric.aes128 : enums.aead.eax;
  const prioMap = {};
  await Promise.all(keys.map(async function(key, i) {
    const primaryUser = await key.getPrimaryUser(date, userIds[i]);
    if (!primaryUser.selfCertification[prefProperty]) {
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
 * Create signature packet
 * @param  {Object}                          dataToSign Contains packets to be signed
 * @param  {module:packet.SecretKey|
 *          module:packet.SecretSubkey}      signingKeyPacket secret key packet for signing
 * @param  {Object} signatureProperties      (optional) properties to write on the signature packet before signing
 * @param  {Date} date                       (optional) override the creationtime of the signature
 * @param  {Object} userId                   (optional) user ID
 * @param  {Object} detached                 (optional) whether to create a detached signature packet
 * @param  {Boolean} streaming               (optional) whether to process data as a stream
 * @returns {module:packet/signature}         signature packet
 */
export async function createSignaturePacket(dataToSign, privateKey, signingKeyPacket, signatureProperties, date, userId, detached = false, streaming = false) {
  if (!signingKeyPacket.isDecrypted()) {
    throw new Error('Private key is not decrypted.');
  }
  const signaturePacket = new packet.Signature(date);
  Object.assign(signaturePacket, signatureProperties);
  signaturePacket.publicKeyAlgorithm = signingKeyPacket.algorithm;
  signaturePacket.hashAlgorithm = await getPreferredHashAlgo(privateKey, signingKeyPacket, date, userId);
  await signaturePacket.sign(signingKeyPacket, dataToSign, detached, streaming);
  return signaturePacket;
}

/**
 * Merges signatures from source[attr] to dest[attr]
 * @private
 * @param  {Object} source
 * @param  {Object} dest
 * @param  {String} attr
 * @param  {Function} checkFn optional, signature only merged if true
 */
export async function mergeSignatures(source, dest, attr, checkFn) {
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
export async function isDataRevoked(primaryKey, signatureType, dataToVerify, revocations, signature, key, date = new Date()) {
  key = key || primaryKey;
  const normDate = util.normalizeDate(date);
  const revocationKeyIds = [];
  await Promise.all(revocations.map(async function(revocationSignature) {
    try {
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
      }
    } catch (e) {}
  }));
  // TODO further verify that this is the signature that should be revoked
  if (signature) {
    signature.revoked = revocationKeyIds.some(keyId => keyId.equals(signature.issuerKeyId)) ? true :
      signature.revoked || false;
    return signature.revoked;
  }
  return revocationKeyIds.length > 0;
}

export function getExpirationTime(keyPacket, signature) {
  let expirationTime;
  // check V4 expiration time
  if (signature.keyNeverExpires === false) {
    expirationTime = keyPacket.created.getTime() + signature.keyExpirationTime * 1000;
  }
  return expirationTime ? new Date(expirationTime) : Infinity;
}

/**
 * Returns whether aead is supported by all keys in the set
 * @param  {Array<module:key.Key>} keys Set of keys
 * @param  {Date} date (optional) use the given date for verification instead of the current time
 * @param  {Array} userIds (optional) user IDs
 * @returns {Promise<Boolean>}
 * @async
 */
export async function isAeadSupported(keys, date = new Date(), userIds = []) {
  let supported = true;
  // TODO replace when Promise.some or Promise.any are implemented
  await Promise.all(keys.map(async function(key, i) {
    const primaryUser = await key.getPrimaryUser(date, userIds[i]);
    if (!primaryUser.selfCertification.features ||
        !(primaryUser.selfCertification.features[0] & enums.features.aead)) {
      supported = false;
    }
  }));
  return supported;
}

export function sanitizeKeyOptions(options, subkeyDefaults = {}) {
  options.curve = options.curve || subkeyDefaults.curve;
  options.rsaBits = options.rsaBits || subkeyDefaults.rsaBits;
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
      options.curve = options.sign ? enums.curve.ed25519 : enums.curve.curve25519;
    }
    if (options.sign) {
      options.algorithm = options.curve === enums.curve.ed25519 ? enums.publicKey.eddsa : enums.publicKey.ecdsa;
    } else {
      options.algorithm = enums.publicKey.ecdh;
    }
  } else if (options.rsaBits) {
    options.algorithm = enums.publicKey.rsa_encrypt_sign;
  } else {
    throw new Error('Unrecognized key type');
  }
  return options;
}

export function isValidSigningKeyPacket(keyPacket, signature) {
  if (!signature.verified || signature.revoked !== false) { // Sanity check
    throw new Error('Signature not verified');
  }
  return keyPacket.algorithm !== enums.read(enums.publicKey, enums.publicKey.rsa_encrypt) &&
    keyPacket.algorithm !== enums.read(enums.publicKey, enums.publicKey.elgamal) &&
    keyPacket.algorithm !== enums.read(enums.publicKey, enums.publicKey.ecdh) &&
    (!signature.keyFlags ||
      (signature.keyFlags[0] & enums.keyFlags.sign_data) !== 0);
}

export function isValidEncryptionKeyPacket(keyPacket, signature) {
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

export function isValidDecryptionKeyPacket(signature) {
  if (!signature.verified) { // Sanity check
    throw new Error('Signature not verified');
  }

  if (config.allow_insecure_decryption_with_signing_keys) {
    // This is only relevant for RSA keys, all other signing ciphers cannot decrypt
    return true;
  }

  return !signature.keyFlags ||
    (signature.keyFlags[0] & enums.keyFlags.encrypt_communication) !== 0 ||
    (signature.keyFlags[0] & enums.keyFlags.encrypt_storage) !== 0;
}
