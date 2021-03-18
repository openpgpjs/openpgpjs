/**
 * @fileoverview Provides helpers methods for key module
 * @module key/helper
 * @private
 */

import {
  PublicKeyPacket,
  PublicSubkeyPacket,
  SecretKeyPacket,
  SecretSubkeyPacket,
  UserIDPacket,
  UserAttributePacket,
  SignaturePacket
} from '../packet';
import enums from '../enums';
import crypto from '../crypto';
import util from '../util';
import defaultConfig from '../config';

export const allowedKeyPackets = {
  PublicKeyPacket,
  PublicSubkeyPacket,
  SecretKeyPacket,
  SecretSubkeyPacket,
  UserIDPacket,
  UserAttributePacket,
  SignaturePacket
};

export async function generateSecretSubkey(options, config) {
  const secretSubkeyPacket = new SecretSubkeyPacket(options.date, config);
  secretSubkeyPacket.packets = null;
  secretSubkeyPacket.algorithm = enums.read(enums.publicKey, options.algorithm);
  await secretSubkeyPacket.generate(options.rsaBits, options.curve);
  return secretSubkeyPacket;
}

export async function generateSecretKey(options, config) {
  const secretKeyPacket = new SecretKeyPacket(options.date, config);
  secretKeyPacket.packets = null;
  secretKeyPacket.algorithm = enums.read(enums.publicKey, options.algorithm);
  await secretKeyPacket.generate(options.rsaBits, options.curve, options.config);
  return secretKeyPacket;
}

/**
 * Returns the valid and non-expired signature that has the latest creation date, while ignoring signatures created in the future.
 * @param {Array<SignaturePacket>} signatures - List of signatures
 * @param {Date} date - Use the given date instead of the current time
 * @param {Object} config - full configuration
 * @returns {SignaturePacket} The latest valid signature.
 * @async
 */
export async function getLatestValidSignature(signatures, primaryKey, signatureType, dataToVerify, date = new Date(), config) {
  let signature;
  let exception;
  for (let i = signatures.length - 1; i >= 0; i--) {
    try {
      if (
        (!signature || signatures[i].created >= signature.created) &&
        // check binding signature is not expired (ie, check for V4 expiration time)
        !signatures[i].isExpired(date)
      ) {
        // check binding signature is verified
        signatures[i].verified || await signatures[i].verify(primaryKey, signatureType, dataToVerify, undefined, undefined, config);
        signature = signatures[i];
      }
    } catch (e) {
      exception = e;
    }
  }
  if (!signature) {
    throw util.wrapError(
      `Could not find valid ${enums.read(enums.signature, signatureType)} signature in key ${primaryKey.getKeyId().toHex()}`
        .replace('certGeneric ', 'self-')
        .replace(/([a-z])([A-Z])/g, (_, $1, $2) => $1 + ' ' + $2.toLowerCase())
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
 * @param {SecretSubkeyPacket} subkey - Subkey key packet
 * @param {SecretKeyPacket} primaryKey - Primary key packet
 * @param {Object} options
 * @param {Object} config - Full configuration
 */
export async function createBindingSignature(subkey, primaryKey, options, config) {
  const dataToSign = {};
  dataToSign.key = primaryKey;
  dataToSign.bind = subkey;
  const subkeySignaturePacket = new SignaturePacket(options.date);
  subkeySignaturePacket.signatureType = enums.signature.subkeyBinding;
  subkeySignaturePacket.publicKeyAlgorithm = primaryKey.algorithm;
  subkeySignaturePacket.hashAlgorithm = await getPreferredHashAlgo(null, subkey, undefined, undefined, config);
  if (options.sign) {
    subkeySignaturePacket.keyFlags = [enums.keyFlags.signData];
    subkeySignaturePacket.embeddedSignature = await createSignaturePacket(dataToSign, null, subkey, {
      signatureType: enums.signature.keyBinding
    }, options.date, undefined, undefined, undefined, config);
  } else {
    subkeySignaturePacket.keyFlags = [enums.keyFlags.encryptCommunication | enums.keyFlags.encryptStorage];
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
 * @param {Key} [key] - The key to get preferences from
 * @param {SecretKeyPacket|SecretSubkeyPacket} keyPacket - key packet used for signing
 * @param {Date} [date] - Use the given date for verification instead of the current time
 * @param {Object} [userId] - User ID
 * @param {Object} config - full configuration
 * @returns {String}
 * @async
 */
export async function getPreferredHashAlgo(key, keyPacket, date = new Date(), userId = {}, config) {
  let hash_algo = config.preferredHashAlgorithm;
  let pref_algo = hash_algo;
  if (key) {
    const primaryUser = await key.getPrimaryUser(date, userId, config);
    if (primaryUser.selfCertification.preferredHashAlgorithms) {
      [pref_algo] = primaryUser.selfCertification.preferredHashAlgorithms;
      hash_algo = crypto.hash.getHashByteLength(hash_algo) <= crypto.hash.getHashByteLength(pref_algo) ?
        pref_algo : hash_algo;
    }
  }
  switch (Object.getPrototypeOf(keyPacket)) {
    case SecretKeyPacket.prototype:
    case PublicKeyPacket.prototype:
    case SecretSubkeyPacket.prototype:
    case PublicSubkeyPacket.prototype:
      switch (keyPacket.algorithm) {
        case 'ecdh':
        case 'ecdsa':
        case 'eddsa':
          pref_algo = crypto.publicKey.elliptic.getPreferredHashAlgo(keyPacket.publicParams.oid);
      }
  }
  return crypto.hash.getHashByteLength(hash_algo) <= crypto.hash.getHashByteLength(pref_algo) ?
    pref_algo : hash_algo;
}

/**
 * Returns the preferred symmetric/aead/compression algorithm for a set of keys
 * @param {symmetric|aead|compression} type - Type of preference to return
 * @param {Array<Key>} [keys] - Set of keys
 * @param {Date} [date] - Use the given date for verification instead of the current time
 * @param {Array} [userIds] - User IDs
 * @param {Object} [config] - Full configuration, defaults to openpgp.config
 * @returns {module:enums.symmetric|aead|compression} Preferred algorithm
 * @async
 */
export async function getPreferredAlgo(type, keys = [], date = new Date(), userIds = [], config = defaultConfig) {
  const defaultAlgo = { // these are all must-implement in rfc4880bis
    'symmetric': enums.symmetric.aes128,
    'aead': enums.aead.eax,
    'compression': enums.compression.uncompressed
  }[type];
  const preferredSenderAlgo = {
    'symmetric': config.preferredSymmetricAlgorithm,
    'aead': config.preferredAEADAlgorithm,
    'compression': config.preferredCompressionAlgorithm
  }[type];
  const prefPropertyName = {
    'symmetric': 'preferredSymmetricAlgorithms',
    'aead': 'preferredAEADAlgorithms',
    'compression': 'preferredCompressionAlgorithms'
  }[type];

  // if preferredSenderAlgo appears in the prefs of all recipients, we pick it
  // otherwise we use the default algo
  // if no keys are available, preferredSenderAlgo is returned
  const senderAlgoSupport = await Promise.all(keys.map(async function(key, i) {
    const primaryUser = await key.getPrimaryUser(date, userIds[i], config);
    const recipientPrefs = primaryUser.selfCertification[prefPropertyName];
    return !!recipientPrefs && recipientPrefs.indexOf(preferredSenderAlgo) >= 0;
  }));
  return senderAlgoSupport.every(Boolean) ? preferredSenderAlgo : defaultAlgo;
}

/**
 * Create signature packet
 * @param {Object} dataToSign - Contains packets to be signed
 * @param  {SecretKeyPacket|
 *          SecretSubkeyPacket}              signingKeyPacket secret key packet for signing
 * @param {Object} [signatureProperties] - Properties to write on the signature packet before signing
 * @param {Date} [date] - Override the creationtime of the signature
 * @param {Object} [userId] - User ID
 * @param {Object} [detached] - Whether to create a detached signature packet
 * @param {Boolean} [streaming] - Whether to process data as a stream
 * @param {Object} config - full configuration
 * @returns {SignaturePacket} Signature packet.
 * @async
 */
export async function createSignaturePacket(dataToSign, privateKey, signingKeyPacket, signatureProperties, date, userId, detached = false, streaming = false, config) {
  if (signingKeyPacket.isDummy()) {
    throw new Error('Cannot sign with a gnu-dummy key.');
  }
  if (!signingKeyPacket.isDecrypted()) {
    throw new Error('Private key is not decrypted.');
  }
  const signaturePacket = new SignaturePacket(date);
  Object.assign(signaturePacket, signatureProperties);
  signaturePacket.publicKeyAlgorithm = signingKeyPacket.algorithm;
  signaturePacket.hashAlgorithm = await getPreferredHashAlgo(privateKey, signingKeyPacket, date, userId, config);
  await signaturePacket.sign(signingKeyPacket, dataToSign, detached, streaming);
  return signaturePacket;
}

/**
 * Merges signatures from source[attr] to dest[attr]
 * @param {Object} source
 * @param {Object} dest
 * @param {String} attr
 * @param {Function} checkFn - optional, signature only merged if true
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
              return util.equalsUint8Array(destSig.write_params(), sourceSig.write_params());
            })) {
          dest[attr].push(sourceSig);
        }
      }));
    }
  }
}

/**
 * Checks if a given certificate or binding signature is revoked
 * @param  {SecretKeyPacket|
 *          PublicKeyPacket}        primaryKey   The primary key packet
 * @param {Object} dataToVerify - The data to check
 * @param {Array<SignaturePacket>} revocations - The revocation signatures to check
 * @param {SignaturePacket} signature - The certificate or signature to check
 * @param  {PublicSubkeyPacket|
 *          SecretSubkeyPacket|
 *          PublicKeyPacket|
 *          SecretKeyPacket} key, optional The key packet to check the signature
 * @param {Date} date - Use the given date instead of the current time
 * @param {Object} config - Full configuration
 * @returns {Boolean} True if the signature revokes the data.
 * @async
 */
export async function isDataRevoked(primaryKey, signatureType, dataToVerify, revocations, signature, key, date = new Date(), config) {
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
        !(config.revocationsExpire && revocationSignature.isExpired(normDate))
      ) {
        revocationSignature.verified || await revocationSignature.verify(key, signatureType, dataToVerify, undefined, undefined, config);

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
 * @param {Array<Key>} keys - Set of keys
 * @param {Date} [date] - Use the given date for verification instead of the current time
 * @param {Array} [userIds] - User IDs
 * @param {Object} config - full configuration
 * @returns {Boolean}
 * @async
 */
export async function isAeadSupported(keys, date = new Date(), userIds = [], config = defaultConfig) {
  let supported = true;
  // TODO replace when Promise.some or Promise.any are implemented
  await Promise.all(keys.map(async function(key, i) {
    const primaryUser = await key.getPrimaryUser(date, userIds[i], config);
    if (!primaryUser.selfCertification.features ||
        !(primaryUser.selfCertification.features[0] & enums.features.aead)) {
      supported = false;
    }
  }));
  return supported;
}

export function sanitizeKeyOptions(options, subkeyDefaults = {}) {
  options.type = options.type || subkeyDefaults.type;
  options.curve = options.curve || subkeyDefaults.curve;
  options.rsaBits = options.rsaBits || subkeyDefaults.rsaBits;
  options.keyExpirationTime = options.keyExpirationTime !== undefined ? options.keyExpirationTime : subkeyDefaults.keyExpirationTime;
  options.passphrase = util.isString(options.passphrase) ? options.passphrase : subkeyDefaults.passphrase;
  options.date = options.date || subkeyDefaults.date;

  options.sign = options.sign || false;

  switch (options.type) {
    case 'ecc':
      try {
        options.curve = enums.write(enums.curve, options.curve);
      } catch (e) {
        throw new Error('Invalid curve');
      }
      if (options.curve === enums.curve.ed25519 || options.curve === enums.curve.curve25519) {
        options.curve = options.sign ? enums.curve.ed25519 : enums.curve.curve25519;
      }
      if (options.sign) {
        options.algorithm = options.curve === enums.curve.ed25519 ? enums.publicKey.eddsa : enums.publicKey.ecdsa;
      } else {
        options.algorithm = enums.publicKey.ecdh;
      }
      break;
    case 'rsa':
      options.algorithm = enums.publicKey.rsaEncryptSign;
      break;
    default:
      throw new Error(`Unsupported key type ${options.type}`);
  }
  return options;
}

export function isValidSigningKeyPacket(keyPacket, signature) {
  if (!signature.verified || signature.revoked !== false) { // Sanity check
    throw new Error('Signature not verified');
  }

  const keyAlgo = enums.write(enums.publicKey, keyPacket.algorithm);
  return keyAlgo !== enums.publicKey.rsaEncrypt &&
    keyAlgo !== enums.publicKey.elgamal &&
    keyAlgo !== enums.publicKey.ecdh &&
    (!signature.keyFlags ||
      (signature.keyFlags[0] & enums.keyFlags.signData) !== 0);
}

export function isValidEncryptionKeyPacket(keyPacket, signature) {
  if (!signature.verified || signature.revoked !== false) { // Sanity check
    throw new Error('Signature not verified');
  }

  const keyAlgo = enums.write(enums.publicKey, keyPacket.algorithm);
  return keyAlgo !== enums.publicKey.dsa &&
    keyAlgo !== enums.publicKey.rsaSign &&
    keyAlgo !== enums.publicKey.ecdsa &&
    keyAlgo !== enums.publicKey.eddsa &&
    (!signature.keyFlags ||
      (signature.keyFlags[0] & enums.keyFlags.encryptCommunication) !== 0 ||
      (signature.keyFlags[0] & enums.keyFlags.encryptStorage) !== 0);
}

export function isValidDecryptionKeyPacket(signature, config) {
  if (!signature.verified) { // Sanity check
    throw new Error('Signature not verified');
  }

  if (config.allowInsecureDecryptionWithSigningKeys) {
    // This is only relevant for RSA keys, all other signing algorithms cannot decrypt
    return true;
  }

  return !signature.keyFlags ||
    (signature.keyFlags[0] & enums.keyFlags.encryptCommunication) !== 0 ||
    (signature.keyFlags[0] & enums.keyFlags.encryptStorage) !== 0;
}

export function checkKeyStrength(keyPacket, config) {
  const keyAlgo = enums.write(enums.publicKey, keyPacket.algorithm);
  if (config.rejectPublicKeyAlgorithms.has(keyAlgo)) {
    throw new Error(`${keyPacket.algorithm} keys are considered too weak.`);
  }
  const rsaAlgos = new Set([enums.publicKey.rsaEncryptSign, enums.publicKey.rsaSign, enums.publicKey.rsaEncrypt]);
  if (rsaAlgos.has(keyAlgo) && util.uint8ArrayBitLength(keyPacket.publicParams.n) < config.minRSABits) {
    throw new Error(`RSA keys shorter than ${config.minRSABits} bits are considered too weak.`);
  }
}
