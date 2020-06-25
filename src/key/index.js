/**
 * @fileoverview helper, factory methods, constructors dealing with openPGP key object
 * @module key
 */

import {
  readKey, readArmoredKey,
  readKeys, readArmoredKeys,
  generate,
  reformat
} from './factory';

import {
  getPreferredAlgo,
  isAeadSupported,
  getPreferredHashAlgo,
  createSignaturePacket
} from './helper';

import Key from './key.js';

export {
  readKey, readArmoredKey,
  readKeys, readArmoredKeys,
  generate,
  reformat,
  getPreferredAlgo,
  isAeadSupported,
  getPreferredHashAlgo,
  createSignaturePacket,
  Key
};
