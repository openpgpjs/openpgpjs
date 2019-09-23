/**
 * @fileoverview functions dealing with openPGP key object
 * @see module:key/key
 * @module key
 */

import key from './key';
import { readArmored, generate, read, reformat } from './factory';
import { getPreferredAlgo, isAeadSupported } from './helper';

const mod = {
  getPreferredAlgo: getPreferredAlgo,
  isAeadSupported: isAeadSupported,
  readArmored: readArmored,
  generate: generate,
  read: read,
  reformat: reformat,
  Key: key.Key
};

module.exports = mod;
