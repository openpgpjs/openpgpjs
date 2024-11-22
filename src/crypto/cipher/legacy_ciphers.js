/**
 * This file is needed to dynamic import the legacy ciphers.
 * Separate dynamic imports are not convenient as they result in multiple chunks.
 */

import { TripleDES as tripledes } from './des';
import cast5 from './cast5';
import twofish from './twofish';
import blowfish from './blowfish';

// We avoid importing 'enums' as this module is lazy loaded, and doing so could mess up
// chunking for the lightweight build
export const legacyCiphers = new Map(Object.entries({
  tripledes,
  cast5,
  twofish,
  blowfish
}));
