/**
 * This file is needed to dynamic import the legacy ciphers.
 * Separate dynamic imports are not convenient as they result in multiple chunks.
 */

import { TripleDES } from './des';
import CAST5 from './cast5';
import TwoFish from './twofish';
import BlowFish from './blowfish';
import enums from '../../enums';

export const legacyCiphers = new Map([
  [enums.symmetric.tripledes, TripleDES],
  [enums.symmetric.cast5, CAST5],
  [enums.symmetric.blowfish, BlowFish],
  [enums.symmetric.twofish, TwoFish]
]);
