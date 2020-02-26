/**
 * @fileoverview helper, factory methods, constructors dealing with openPGP key object
 * @module key
 */

import {
  read, readArmored,
  readAll, readAllArmored,
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
  read, readArmored,
  readAll, readAllArmored,
  generate,
  reformat,
  getPreferredAlgo,
  isAeadSupported,
  getPreferredHashAlgo,
  createSignaturePacket,
  Key
};
