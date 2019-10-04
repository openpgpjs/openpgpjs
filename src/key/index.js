/**
 * @fileoverview functions dealing with openPGP key object
 * @see module:key/key
 * @module key
 */

import { readArmored as readArmoredMod, generate as generateMod, read as readMod, reformat as reformatMod } from './factory';
import { getPreferredAlgo as getPreferredAlgoMod, isAeadSupported as isAeadSupportedMod, getPreferredHashAlgo as getPreferredHashAlgoMod, createSignaturePacket as createSignaturePacketMod } from './helper';

export const generate = generateMod;
export const reformat = reformatMod;
export { default as Key } from './key.js';
export const readArmored = readArmoredMod;
export const read = readMod;
export const getPreferredAlgo = getPreferredAlgoMod;
export const isAeadSupported = isAeadSupportedMod;
export const getPreferredHashAlgo = getPreferredHashAlgoMod;
export const createSignaturePacket = createSignaturePacketMod;