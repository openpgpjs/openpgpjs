/**
 * This file is needed to dynamic import the noble-hashes.
 * Separate dynamic imports are not convenient as they result in too many chunks,
 * which share a lot of code anyway.
 */

import { sha1 } from '@noble/hashes/sha1';
import { sha224, sha256 } from '@noble/hashes/sha256';
import { sha384, sha512 } from '@noble/hashes/sha512';
import { sha3_256, sha3_512 } from '@noble/hashes/sha3';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { md5 } from './md5';

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
