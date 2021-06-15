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
  SignaturePacket
} from '../packet';
import enums from '../enums';
import crypto from '../crypto';
import util from '../util';
import defaultConfig from '../config';

export async function generateSecretSubkey(options, config) {
  const secretSubkeyPacket = new SecretSubkeyPacket(options.date, config);
  secretSubkeyPacket.packets = null;
  secretSubkeyPacket.algorithm = enums.read(enums.publicKey, options.algorithm);
  await secretSubkeyPacket.generate(options.rsaBits, options.curve);
  await secretSubkeyPacket.computeFingerprintAndKeyID();
  return secretSubkeyPacket;
}

export async function generateSecretKey(options, config) {
  const secretKeyPacket = new SecretKeyPacket(options.date, config);
  secretKeyPacket.packets = null;
  secretKeyPacket.algorithm = enums.read(enums.publicKey, options.algorithm);
  await secretKeyPacket.generate(options.rsaBits, options.curve, options.config);
  await secretKeyPacket.computeFingerprintAndKeyID();
  return secretKeyPacket;
}

/**
 * Returns the valid and non-expired signature that has the latest creation date, while ignoring signatures created in the future.
 * @param {Array<SignaturePacket>} signatures - List of signatures
 * @param {PublicKeyPacket|PublicSubkeyPacket} publicKey - Public key packet to verify the signature
 * @param {Date} date - Use the given date instead of the current time
 * @param {Object} config - full configuration
 * @returns {Promise<SignaturePacket>} The latest valid signature.
 * @async
 */
export async function getLatestValidSignature(signatures, publicKey, signatureType, dataToVerify, date = new Date(), config) {
  let latestValid;
  let exception;
  for (let i = signatures.length - 1; i >= 0; i--) {
    try {
      if (
        (!latestValid || signatures[i].created >= latestValid.created)
      ) {
        await signatures[i].verify(publicKey, signatureType, dataToVerify, date, undefined, config);
        latestValid = signatures[i];
      }
    } catch (e) {
      exception = e;
    }
  }
  if (!latestValid) {
    throw util.wrapError(
      `Could not find valid ${enums.read(enums.signature, signatureType)} signature in key ${publicKey.getKeyID().toHex()}`
        .replace('certGeneric ', 'self-')
        .replace(/([a-z])([A-Z])/g, (_, $1, $2) => $1 + ' ' + $2.toLowerCase())
      , exception);
  }
  return latestValid;
}

export function isDataExpired(keyPacket, signature, date = new Date()) {
  const normDate = util.normalizeDate(date);
  if (normDate !== null) {
    const expirationTime = getKeyExpirationTime(keyPacket, signature);
    return !(keyPacket.created <= normDate && normDate < expirationTime);
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
  const subkeySignaturePacket = new SignaturePacket();
  subkeySignaturePacket.signatureType = enums.signature.subkeyBinding;
  subkeySignaturePacket.publicKeyAlgorithm = primaryKey.algorithm;
  subkeySignaturePacket.hashAlgorithm = await getPreferredHashAlgo(null, subkey, undefined, undefined, config);
  if (options.sign) {
    subkeySignaturePacket.keyFlags = [enums.keyFlags.signData];
    subkeySignaturePacket.embeddedSignature = await createSignaturePacket(dataToSign, null, subkey, {
      signatureType: enums.signature.keyBinding
    }, options.date, undefined, undefined, config);
  } else {
    subkeySignaturePacket.keyFlags = [enums.keyFlags.encryptCommunication | enums.keyFlags.encryptStorage];
  }
  if (options.keyExpirationTime > 0) {
    subkeySignaturePacket.keyExpirationTime = options.keyExpirationTime;
    subkeySignaturePacket.keyNeverExpires = false;
  }
  await subkeySignaturePacket.sign(primaryKey, dataToSign, options.date);
  return subkeySignaturePacket;
}

/**
 * Returns the preferred signature hash algorithm of a key
 * @param {Key} [key] - The key to get preferences from
 * @param {SecretKeyPacket|SecretSubkeyPacket} keyPacket - key packet used for signing
 * @param {Date} [date] - Use the given date for verification instead of the current time
 * @param {Object} [userID] - User ID
 * @param {Object} config - full configuration
 * @returns {Promise<String>}
 * @async
 */
export async function getPreferredHashAlgo(key, keyPacket, date = new Date(), userID = {}, config) {
  let hashAlgo = config.preferredHashAlgorithm;
  let prefAlgo = hashAlgo;
  if (key) {
    const primaryUser = await key.getPrimaryUser(date, userID, config);
    if (primaryUser.selfCertification.preferredHashAlgorithms) {
      [prefAlgo] = primaryUser.selfCertification.preferredHashAlgorithms;
      hashAlgo = crypto.hash.getHashByteLength(hashAlgo) <= crypto.hash.getHashByteLength(prefAlgo) ?
        prefAlgo : hashAlgo;
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
          prefAlgo = crypto.publicKey.elliptic.getPreferredHashAlgo(keyPacket.publicParams.oid);
      }
  }
  return crypto.hash.getHashByteLength(hashAlgo) <= crypto.hash.getHashByteLength(prefAlgo) ?
    prefAlgo : hashAlgo;
}

/**
 * Returns the preferred symmetric/aead/compression algorithm for a set of keys
 * @param {symmetric|aead|compression} type - Type of preference to return
 * @param {Array<Key>} [keys] - Set of keys
 * @param {Date} [date] - Use the given date for verification instead of the current time
 * @param {Array} [userIDs] - User IDs
 * @param {Object} [config] - Full configuration, defaults to openpgp.config
 * @returns {Promise<module:enums.symmetric|aead|compression>} Preferred algorithm
 * @async
 */
export async function getPreferredAlgo(type, keys = [], date = new Date(), userIDs = [], config = defaultConfig) {
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
    const primaryUser = await key.getPrimaryUser(date, userIDs[i], config);
    const recipientPrefs = primaryUser.selfCertification[prefPropertyName];
    return !!recipientPrefs && recipientPrefs.indexOf(preferredSenderAlgo) >= 0;
  }));
  return senderAlgoSupport.every(Boolean) ? preferredSenderAlgo : defaultAlgo;
}

/**
 * Create signature packet
 * @param {Object} dataToSign - Contains packets to be signed
 * @param {PrivateKey} privateKey - key to get preferences from
 * @param  {SecretKeyPacket|
 *          SecretSubkeyPacket}              signingKeyPacket secret key packet for signing
 * @param {Object} [signatureProperties] - Properties to write on the signature packet before signing
 * @param {Date} [date] - Override the creationtime of the signature
 * @param {Object} [userID] - User ID
 * @param {Object} [detached] - Whether to create a detached signature packet
 * @param {Object} config - full configuration
 * @returns {Promise<SignaturePacket>} Signature packet.
 */
export async function createSignaturePacket(dataToSign, privateKey, signingKeyPacket, signatureProperties, date, userID, detached = false, config) {
  if (signingKeyPacket.isDummy()) {
    throw new Error('Cannot sign with a gnu-dummy key.');
  }
  if (!signingKeyPacket.isDecrypted()) {
    throw new Error('Signing key is not decrypted.');
  }
  const signaturePacket = new SignaturePacket();
  Object.assign(signaturePacket, signatureProperties);
  signaturePacket.publicKeyAlgorithm = signingKeyPacket.algorithm;
  signaturePacket.hashAlgorithm = await getPreferredHashAlgo(privateKey, signingKeyPacket, date, userID, config);
  await signaturePacket.sign(signingKeyPacket, dataToSign, date, detached);
  return signaturePacket;
}

/**
 * Merges signatures from source[attr] to dest[attr]
 * @param {Object} source
 * @param {Object} dest
 * @param {String} attr
 * @param {Date} [date] - date to use for signature expiration check, instead of the current time
 * @param {Function} [checkFn] - signature only merged if true
 */
export async function mergeSignatures(source, dest, attr, date = new Date(), checkFn) {
  source = source[attr];
  if (source) {
    if (!dest[attr].length) {
      dest[attr] = source;
    } else {
      await Promise.all(source.map(async function(sourceSig) {
        if (!sourceSig.isExpired(date) && (!checkFn || await checkFn(sourceSig)) &&
            !dest[attr].some(function(destSig) {
              return util.equalsUint8Array(destSig.writeParams(), sourceSig.writeParams());
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
 *          SecretKeyPacket} key, optional The key packet to verify the signature, instead of the primary key
 * @param {Date} date - Use the given date instead of the current time
 * @param {Object} config - Full configuration
 * @returns {Promise<Boolean>} True if the signature revokes the data.
 * @async
 */
export async function isDataRevoked(primaryKey, signatureType, dataToVerify, revocations, signature, key, date = new Date(), config) {
  key = key || primaryKey;
  const revocationKeyIDs = [];
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
        !signature || revocationSignature.issuerKeyID.equals(signature.issuerKeyID)
      ) {
        await revocationSignature.verify(
          key, signatureType, dataToVerify, config.revocationsExpire ? date : null, false, config
        );

        // TODO get an identifier of the revoked object instead
        revocationKeyIDs.push(revocationSignature.issuerKeyID);
      }
    } catch (e) {}
  }));
  // TODO further verify that this is the signature that should be revoked
  if (signature) {
    signature.revoked = revocationKeyIDs.some(keyID => keyID.equals(signature.issuerKeyID)) ? true :
      signature.revoked || false;
    return signature.revoked;
  }
  return revocationKeyIDs.length > 0;
}

/**
 * Returns key expiration time based on the given certification signature.
 * The expiration time of the signature is ignored.
 * @param {PublicSubkeyPacket|PublicKeyPacket} keyPacket - key to check
 * @param {SignaturePacket} signature - signature to process
 * @returns {Date|Infinity} expiration time or infinity if the key does not expire
 */
export function getKeyExpirationTime(keyPacket, signature) {
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
 * @param {Array} [userIDs] - User IDs
 * @param {Object} config - full configuration
 * @returns {Promise<Boolean>}
 * @async
 */
export async function isAEADSupported(keys, date = new Date(), userIDs = [], config = defaultConfig) {
  let supported = true;
  // TODO replace when Promise.some or Promise.any are implemented
  await Promise.all(keys.map(async function(key, i) {
    const primaryUser = await key.getPrimaryUser(date, userIDs[i], config);
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
  const keyAlgo = enums.write(enums.publicKey, keyPacket.algorithm);
  return keyAlgo !== enums.publicKey.rsaEncrypt &&
    keyAlgo !== enums.publicKey.elgamal &&
    keyAlgo !== enums.publicKey.ecdh &&
    (!signature.keyFlags ||
      (signature.keyFlags[0] & enums.keyFlags.signData) !== 0);
}

export function isValidEncryptionKeyPacket(keyPacket, signature) {
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
