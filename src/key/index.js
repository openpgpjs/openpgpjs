/**
 * @fileoverview functions dealing with openPGP key object
 * @see module:key/key
 * @module key
 */

import Key from './key';
import { readArmored, generate, read, reformat } from './factory';
import { getPreferredAlgo, isAeadSupported, getPreferredHashAlgo, createSignaturePacket } from './helper';

//eslint-disable-next-line
export const mod = {
  getPreferredAlgo: getPreferredAlgo,
  getPreferredHashAlgo: getPreferredHashAlgo,
  createSignaturePacket: createSignaturePacket,
  isAeadSupported: isAeadSupported,
  readArmored: readArmored,
  generate: generate,
  read: read,
  reformat: reformat,
  Key: Key
};

//export mod;
