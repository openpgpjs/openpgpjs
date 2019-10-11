/**
 * @fileoverview helper, factory methods, constructors dealing with openPGP key object
 * @module key
 */

import {
  readArmored,
  generate,
  read,
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
  readArmored,
  generate,
  read,
  reformat,
  getPreferredAlgo,
  isAeadSupported,
  getPreferredHashAlgo,
  createSignaturePacket,
  Key
};
