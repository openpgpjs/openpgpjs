/**
 * This file is needed to dynamic import the noble-curves.
 * Separate dynamic imports are not convenient as they result in too many chunks,
 * which share a lot of code anyway.
 */

import { p256 as nistP256 } from '@openpgp/noble-curves/p256';
import { p384 as nistP384 } from '@openpgp/noble-curves/p384';
import { p521 as nistP521 } from '@openpgp/noble-curves/p521';
import { brainpoolP256r1 } from '@openpgp/noble-curves/brainpoolP256r1';
import { brainpoolP384r1 } from '@openpgp/noble-curves/brainpoolP384r1';
import { brainpoolP512r1 } from '@openpgp/noble-curves/brainpoolP512r1';
import { x448, ed448 } from '@openpgp/noble-curves/ed448';
import { secp256k1 } from '@openpgp/noble-curves/secp256k1';

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

