/**
 * This file is needed to dynamic import the noble-hashes.
 * Separate dynamic imports are not convenient as they result in too many chunks,
 * which share a lot of code anyway.
 */

import { sha224, sha256, sha384, sha512 } from '@noble/hashes/sha2.js';
import { sha3_256, sha3_512 } from '@noble/hashes/sha3.js';
import { md5, ripemd160, sha1 } from '@noble/hashes/legacy.js';

export const nobleHashes = new Map(Object.entries({
  md5,
  sha1,
  sha224,
  sha256,
  sha384,
  sha512,
  sha3_256,
  sha3_512,
  ripemd160
}));
