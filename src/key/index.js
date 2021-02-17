/**
 * @fileoverview helper, factory methods, constructors dealing with openPGP key object
 * @module key
 */

import {
  readKey,
  readKeys,
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
  readKey,
  readKeys,
  generate,
  reformat,
  getPreferredAlgo,
  isAeadSupported,
  getPreferredHashAlgo,
  createSignaturePacket,
  Key
};
