/**
 * @fileoverview functions dealing with openPGP key object
 * @see module:key/key
 * @module key
 */

import Key from './key';
import { readArmored, generate, read, reformat } from './factory';
import { getPreferredAlgo, isAeadSupported, getPreferredHashAlgo, createSignaturePacket } from './helper';

const mod = {
  getPreferredAlgo,
  getPreferredHashAlgo,
  createSignaturePacket,
  isAeadSupported,
  readArmored,
  generate,
  read,
  reformat,
  Key
};

export default mod;