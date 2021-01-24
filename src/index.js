/**
 * Export high level API functions.
 * Usage:
 *
 *   import { encrypt } from 'openpgp';
 *   encrypt({ message, publicKeys });
 */
export {
  encrypt, decrypt, sign, verify,
  generateKey, reformatKey, revokeKey, decryptKey, encryptKey,
  generateSessionKey, encryptSessionKey, decryptSessionKeys
} from './openpgp';

/**
 * @see module:key
 * @name module:openpgp.key
 */
export { Key, readKey, readKeys } from './key';

/**
 * @see module:signature
 * @name module:openpgp.signature
 */
export { Signature, readSignature } from './signature';

/**
 * @see module:message
 * @name module:openpgp.message
 */
export { Message, readMessage } from './message';

/**
 * @see module:cleartext
 * @name module:openpgp.cleartext
 */
export { CleartextMessage, readCleartextMessage } from './cleartext';

/**
 * @see module:packet
 * @name module:openpgp.packet
 */
export * from './packet';

/**
 * @see streams
 * @name module:openpgp.stream
 */
export { default as stream } from 'web-stream-tools';

/**
 * @see module:encoding/armor
 * @name module:openpgp.armor
 */
export * from './encoding/armor';

/**
 * @see module:enums
 * @name module:openpgp.enums
 */
export { default as enums } from './enums';

/**
 * @see module:config/config
 * @name module:openpgp.config
 */
export { default as config } from './config/config';

/**
 * @see module:keyring
 * @name module:openpgp.Keyring
 */
export { default as Keyring } from './keyring';

/**
 * @see module:hkp
 * @name module:openpgp.HKP
 */
export { default as HKP } from './hkp';

/**
 * @see module:wkd
 * @name module:openpgp.WKD
 */
export { default as WKD } from './wkd';
