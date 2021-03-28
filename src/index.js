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

export { Key, readKey, readKeys } from './key';

export { Signature, readSignature } from './signature';

export { Message, readMessage, createMessage } from './message';

export { CleartextMessage, readCleartextMessage, createCleartextMessage } from './cleartext';

export * from './packet';

import * as streamMod from '@openpgp/web-stream-tools'; // eslint-disable-line
export const stream = streamMod;

export * from './encoding/armor';

export { default as enums } from './enums';

export { default as config } from './config/config';
