/* eslint-disable import/newline-after-import, import/first */

/**
 * Export high level API functions.
 * Usage:
 *
 *   import { encrypt } from 'openpgp'
 *   encrypt({ message, publicKeys })
 */
export {
  encrypt, decrypt, sign, verify,
  generateKey, reformatKey, revokeKey, decryptKey,
  generateSessionKey, encryptSessionKey, decryptSessionKeys
} from './openpgp';

/**
 * @see module:key
 * @name module:openpgp.key
 */
import * as keyMod from './key';
export const key = keyMod;

/**
 * @see module:signature
 * @name module:openpgp.signature
 */
import * as signatureMod from './signature';
export const signature = signatureMod;

/**
 * @see module:message
 * @name module:openpgp.message
 */
import * as messageMod from './message';
export const message = messageMod;

/**
 * @see module:cleartext
 * @name module:openpgp.cleartext
 */
import * as cleartextMod from './cleartext';
export const cleartext = cleartextMod;

/**
 * @see module:util
 * @name module:openpgp.util
 */
export { default as util } from './util';

/**
 * @see module:packet
 * @name module:openpgp.packet
 */
export * from './packet';

/**
 * @see module:type/mpi
 * @name module:openpgp.MPI
 */
export { default as MPI } from './type/mpi';

/**
 * @see module:type/s2k
 * @name module:openpgp.S2K
 */
export { default as S2K } from './type/s2k';

/**
 * @see module:type/keyid
 * @name module:openpgp.Keyid
 */
export { default as Keyid } from './type/keyid';

/**
 * @see module:type/ecdh_symkey
 * @name module:openpgp.ECDHSymmetricKey
 */
export { default as ECDHSymmetricKey } from './type/ecdh_symkey';

/**
 * @see module:type/kdf_params
 * @name module:openpgp.KDFParams
 */
export { default as KDFParams } from './type/kdf_params';

/**
 * @see module:type/oid
 * @name module:openpgp.OID
 */
export { default as OID } from './type/oid';

/**
 * @see streams
 * @name module:openpgp.stream
 */
export { default as stream } from 'web-stream-tools';

/**
 * @see module:encoding/armor
 * @name module:openpgp.armor
 */
export { default as armor } from './encoding/armor';

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
 * @see module:crypto
 * @name module:openpgp.crypto
 */
export { default as crypto } from './crypto';

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
