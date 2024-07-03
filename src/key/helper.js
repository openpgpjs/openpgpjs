/**
 * @fileoverview Provides helpers methods for key module
 * @module key/helper
 */

import {
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
  secretSubkeyPacket.algorithm = enums.write(enums.publicKey, options.algorithm);
  await secretSubkeyPacket.generate(options.rsaBits, options.curve);
  await secretSubkeyPacket.computeFingerprintAndKeyID();
  return secretSubkeyPacket;
}

export async function generateSecretKey(options, config) {
  const secretKeyPacket = new SecretKeyPacket(options.date, config);
  secretKeyPacket.packets = null;
  secretKeyPacket.algorithm = enums.write(enums.publicKey, options.algorithm);
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
        .replace(/([a-z])([A-Z])/g, (_, $1, $2) => $1 + ' ' + $2.toLowerCase()),
      exception);
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
  const signatureProperties = { signatureType: enums.signature.subkeyBinding };
  if (options.sign) {
    signatureProperties.keyFlags = [enums.keyFlags.signData];
    signatureProperties.embeddedSignature = await createSignaturePacket(dataToSign, null, subkey, {
      signatureType: enums.signature.keyBinding
    }, options.date, undefined, undefined, undefined, config);
  } else {
    signatureProperties.keyFlags = [enums.keyFlags.encryptCommunication | enums.keyFlags.encryptStorage];
  }
  if (options.keyExpirationTime > 0) {
    signatureProperties.keyExpirationTime = options.keyExpirationTime;
    signatureProperties.keyNeverExpires = false;
  }
  const subkeySignaturePacket = await createSignaturePacket(dataToSign, null, primaryKey, signatureProperties, options.date, undefined, undefined, undefined, config);
  return subkeySignaturePacket;
}

/**
 * Returns the preferred signature hash algorithm of a key
 * @param {Key} [key] - The key to get preferences from
 * @param {SecretKeyPacket|SecretSubkeyPacket} keyPacket - key packet used for signing
 * @param {Date} [date] - Use the given date for verification instead of the current time
 * @param {Object} [userID] - User ID
 * @param {Object} config - full configuration
 * @returns {Promise<enums.hash>}
 * @async
 */
export async function getPreferredHashAlgo(key, keyPacket, date = new Date(), userID = {}, config) {
  let hashAlgo = config.preferredHashAlgorithm;
  let prefAlgo = hashAlgo;
  if (key) {
    const selfCertification = await key.getPrimarySelfSignature(date, userID, config);
    if (selfCertification.preferredHashAlgorithms) {
      [prefAlgo] = selfCertification.preferredHashAlgorithms;
      hashAlgo = crypto.hash.getHashByteLength(hashAlgo) <= crypto.hash.getHashByteLength(prefAlgo) ?
        prefAlgo : hashAlgo;
    }
  }
  switch (keyPacket.algorithm) {
    case enums.publicKey.ecdsa:
    case enums.publicKey.eddsaLegacy:
    case enums.publicKey.ed25519:
    case enums.publicKey.ed448:
      prefAlgo = crypto.getPreferredCurveHashAlgo(keyPacket.algorithm, keyPacket.publicParams.oid);
  }

  return crypto.hash.getHashByteLength(hashAlgo) <= crypto.hash.getHashByteLength(prefAlgo) ?
    prefAlgo : hashAlgo;
}

/**
 * Returns the preferred compression algorithm for a set of keys
 * @param {Array<Key>} [keys] - Set of keys
 * @param {Date} [date] - Use the given date for verification instead of the current time
 * @param {Array} [userIDs] - User IDs
 * @param {Object} [config] - Full configuration, defaults to openpgp.config
 * @returns {Promise<module:enums.compression>} Preferred compression algorithm
 * @async
 */
export async function getPreferredCompressionAlgo(keys = [], date = new Date(), userIDs = [], config = defaultConfig) {
  const defaultAlgo = enums.compression.uncompressed;
  const preferredSenderAlgo = config.preferredCompressionAlgorithm;

  // if preferredSenderAlgo appears in the prefs of all recipients, we pick it
  // otherwise we use the default algo
  // if no keys are available, preferredSenderAlgo is returned
  const senderAlgoSupport = await Promise.all(keys.map(async function(key, i) {
    const selfCertification = await key.getPrimarySelfSignature(date, userIDs[i], config);
    const recipientPrefs = selfCertification.preferredCompressionAlgorithms;
    return !!recipientPrefs && recipientPrefs.indexOf(preferredSenderAlgo) >= 0;
  }));
  return senderAlgoSupport.every(Boolean) ? preferredSenderAlgo : defaultAlgo;
}

/**
 * Returns the preferred symmetric and AEAD algorithm (if any) for a set of keys
 * @param {Array<Key>} [keys] - Set of keys
 * @param {Date} [date] - Use the given date for verification instead of the current time
 * @param {Array} [userIDs] - User IDs
 * @param {Object} [config] - Full configuration, defaults to openpgp.config
 * @returns {Promise<{ symmetricAlgo: module:enums.symmetric, aeadAlgo: module:enums.aead | undefined }>} Object containing the preferred symmetric algorithm, and the preferred AEAD algorithm, or undefined if CFB is preferred
 * @async
 */
export async function getPreferredCipherSuite(keys = [], date = new Date(), userIDs = [], config = defaultConfig) {
  const selfSigs = await Promise.all(keys.map((key, i) => key.getPrimarySelfSignature(date, userIDs[i], config)));
  const withAEAD = keys.length ?
    selfSigs.every(selfSig => selfSig.features && (selfSig.features[0] & enums.features.seipdv2)) :
    config.aeadProtect;

  if (withAEAD) {
    const defaultCipherSuite = { symmetricAlgo: enums.symmetric.aes128, aeadAlgo: enums.aead.ocb };
    const desiredCipherSuite = { symmetricAlgo: config.preferredSymmetricAlgorithm, aeadAlgo: config.preferredAEADAlgorithm };
    return selfSigs.every(selfSig => selfSig.preferredCipherSuites && selfSig.preferredCipherSuites.some(
      cipherSuite => cipherSuite[0] === desiredCipherSuite.symmetricAlgo && cipherSuite[1] === desiredCipherSuite.aeadAlgo
    )) ?
      desiredCipherSuite :
      defaultCipherSuite;
  }
  const defaultSymAlgo = enums.symmetric.aes128;
  const desiredSymAlgo = config.preferredSymmetricAlgorithm;
  return {
    symmetricAlgo: selfSigs.every(selfSig => selfSig.preferredSymmetricAlgorithms && selfSig.preferredSymmetricAlgorithms.includes(desiredSymAlgo)) ?
      desiredSymAlgo :
      defaultSymAlgo,
    aeadAlgo: undefined
  };
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
 * @param {Array} [notations] - Notation Data to add to the signature, e.g. [{ name: 'test@example.org', value: new TextEncoder().encode('test'), humanReadable: true, critical: false }]
 * @param {Object} [detached] - Whether to create a detached signature packet
 * @param {Object} config - full configuration
 * @returns {Promise<SignaturePacket>} Signature packet.
 */
export async function createSignaturePacket(dataToSign, privateKey, signingKeyPacket, signatureProperties, date, userID, notations = [], detached = false, config) {
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
  signaturePacket.rawNotations = [...notations];
  await signaturePacket.sign(signingKeyPacket, dataToSign, date, detached, config);
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
        if (![
          enums.reasonForRevocation.keyRetired,
          enums.reasonForRevocation.keySuperseded,
          enums.reasonForRevocation.userIDInvalid
        ].includes(revocationSignature.reasonForRevocationFlag)) {
          date = null; // Hard revocations apply at any time.
        }
        await revocationSignature.verify(
          key, signatureType, dataToVerify, date, false, config
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

export function sanitizeKeyOptions(options, subkeyDefaults = {}) {
  options.type = options.type || subkeyDefaults.type;
  options.curve = options.curve || subkeyDefaults.curve;
  options.rsaBits = options.rsaBits || subkeyDefaults.rsaBits;
  options.keyExpirationTime = options.keyExpirationTime !== undefined ? options.keyExpirationTime : subkeyDefaults.keyExpirationTime;
  options.passphrase = util.isString(options.passphrase) ? options.passphrase : subkeyDefaults.passphrase;
  options.date = options.date || subkeyDefaults.date;

  options.sign = options.sign || false;

  switch (options.type) {
    case 'ecc': // NB: this case also handles legacy eddsa and x25519 keys, based on `options.curve`
      try {
        options.curve = enums.write(enums.curve, options.curve);
      } catch (e) {
        throw new Error('Unknown curve');
      }
      if (options.curve === enums.curve.ed25519Legacy || options.curve === enums.curve.curve25519Legacy ||
        options.curve === 'ed25519' || options.curve === 'curve25519') { // keep support for curve names without 'Legacy' addition, for now
        options.curve = options.sign ? enums.curve.ed25519Legacy : enums.curve.curve25519Legacy;
      }
      if (options.sign) {
        options.algorithm = options.curve === enums.curve.ed25519Legacy ? enums.publicKey.eddsaLegacy : enums.publicKey.ecdsa;
      } else {
        options.algorithm = enums.publicKey.ecdh;
      }
      break;
    case 'curve25519':
      options.algorithm = options.sign ? enums.publicKey.ed25519 : enums.publicKey.x25519;
      break;
    case 'curve448':
      options.algorithm = options.sign ? enums.publicKey.ed448 : enums.publicKey.x448;
      break;
    case 'rsa':
      options.algorithm = enums.publicKey.rsaEncryptSign;
      break;
    default:
      throw new Error(`Unsupported key type ${options.type}`);
  }
  return options;
}

export function validateSigningKeyPacket(keyPacket, signature, config) {
  switch (keyPacket.algorithm) {
    case enums.publicKey.rsaEncryptSign:
    case enums.publicKey.rsaSign:
    case enums.publicKey.dsa:
    case enums.publicKey.ecdsa:
    case enums.publicKey.eddsaLegacy:
    case enums.publicKey.ed25519:
    case enums.publicKey.ed448:
      if (!signature.keyFlags && !config.allowMissingKeyFlags) {
        throw new Error('None of the key flags is set: consider passing `config.allowMissingKeyFlags`');
      }
      return !signature.keyFlags ||
        (signature.keyFlags[0] & enums.keyFlags.signData) !== 0;
    default:
      return false;
  }
}

export function validateEncryptionKeyPacket(keyPacket, signature, config) {
  switch (keyPacket.algorithm) {
    case enums.publicKey.rsaEncryptSign:
    case enums.publicKey.rsaEncrypt:
    case enums.publicKey.elgamal:
    case enums.publicKey.ecdh:
    case enums.publicKey.x25519:
    case enums.publicKey.x448:
      if (!signature.keyFlags && !config.allowMissingKeyFlags) {
        throw new Error('None of the key flags is set: consider passing `config.allowMissingKeyFlags`');
      }
      return !signature.keyFlags ||
        (signature.keyFlags[0] & enums.keyFlags.encryptCommunication) !== 0 ||
        (signature.keyFlags[0] & enums.keyFlags.encryptStorage) !== 0;
    default:
      return false;
  }
}

export function validateDecryptionKeyPacket(keyPacket, signature, config) {
  if (!signature.keyFlags && !config.allowMissingKeyFlags) {
    throw new Error('None of the key flags is set: consider passing `config.allowMissingKeyFlags`');
  }

  switch (keyPacket.algorithm) {
    case enums.publicKey.rsaEncryptSign:
    case enums.publicKey.rsaEncrypt:
    case enums.publicKey.elgamal:
    case enums.publicKey.ecdh:
    case enums.publicKey.x25519:
    case enums.publicKey.x448: {
      const isValidSigningKeyPacket = !signature.keyFlags || (signature.keyFlags[0] & enums.keyFlags.signData) !== 0;
      if (isValidSigningKeyPacket && config.allowInsecureDecryptionWithSigningKeys) {
        // This is only relevant for RSA keys, all other signing algorithms cannot decrypt
        return true;
      }

      return !signature.keyFlags ||
      (signature.keyFlags[0] & enums.keyFlags.encryptCommunication) !== 0 ||
      (signature.keyFlags[0] & enums.keyFlags.encryptStorage) !== 0;
    }
    default:
      return false;
  }
}

/**
 * Check key against blacklisted algorithms and minimum strength requirements.
 * @param {SecretKeyPacket|PublicKeyPacket|
 *        SecretSubkeyPacket|PublicSubkeyPacket} keyPacket
 * @param {Config} config
 * @throws {Error} if the key packet does not meet the requirements
 */
export function checkKeyRequirements(keyPacket, config) {
  const keyAlgo = enums.write(enums.publicKey, keyPacket.algorithm);
  const algoInfo = keyPacket.getAlgorithmInfo();
  if (config.rejectPublicKeyAlgorithms.has(keyAlgo)) {
    throw new Error(`${algoInfo.algorithm} keys are considered too weak.`);
  }
  switch (keyAlgo) {
    case enums.publicKey.rsaEncryptSign:
    case enums.publicKey.rsaSign:
    case enums.publicKey.rsaEncrypt:
      if (algoInfo.bits < config.minRSABits) {
        throw new Error(`RSA keys shorter than ${config.minRSABits} bits are considered too weak.`);
      }
      break;
    case enums.publicKey.ecdsa:
    case enums.publicKey.eddsaLegacy:
    case enums.publicKey.ecdh:
      if (config.rejectCurves.has(algoInfo.curve)) {
        throw new Error(`Support for ${algoInfo.algorithm} keys using curve ${algoInfo.curve} is disabled.`);
      }
      break;
    default:
      break;
  }
}
