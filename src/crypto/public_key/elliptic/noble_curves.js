/**
 * This file is needed to dynamic import the noble-curves.
 * Separate dynamic imports are not convenient as they result in too many chunks,
 * which share a lot of code anyway.
 */

import { p256 as nistP256, p384 as nistP384, p521 as nistP521 } from '@noble/curves/nist.js';
import { x448, ed448 } from '@noble/curves/ed448.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { brainpoolP256r1, brainpoolP384r1, brainpoolP512r1 } from '@noble/curves/misc.js';

export const nobleCurves = new Map(Object.entries({
  nistP256,
  nistP384,
  nistP521,
  brainpoolP256r1,
  brainpoolP384r1,
  brainpoolP512r1,
  secp256k1,
  x448,
  ed448
}));

