// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/* eslint-disable no-console */

/**
 * This object contains utility functions
 * @module util
 * @access private
 */

import {
  concat as streamConcat,
  transform as streamTransform,
  concatUint8Array,
  isStream,
  isUint8Array,
  type MaybeStream
} from '@openpgp/web-stream-tools';

declare module '@openpgp/web-stream-tools' {
  export function isUint8Array(input: unknown): input is Uint8Array;

  export function concatUint8Array(arrays: Uint8Array[]): Uint8Array;

  /** Returns a stream if any input is a stream; otherwise joins the strings or Uint8Arrays */
  export function concat<T extends Uint8Array | string>(list: T[]): T;
  export function concat<T extends Stream<Uint8Array | string>>(list: T): T;
}
import { createRequire } from 'module'; // Must be stripped in browser built
import enums, { type Enums } from './enums.ts';
import defaultConfig from './config.ts';
import type { NobleCurves } from './crypto/public_key/elliptic/noble_curves.js';

const debugMode = (() => {
  try {
    return process.env.NODE_ENV === 'development';
  } catch {}
  return false;
})();

export function isString(data: unknown) {
  return typeof data === 'string' || data instanceof String;
}

export const nodeRequire = createRequire(import.meta.url);

export function isArray(data: unknown) {
  return data instanceof Array;
}

export { isUint8Array };

export { isStream };

/**
 * Load noble-curves lib on demand and return the requested curve function
 * @param {enums.publicKey} publicKeyAlgo
 * @param {enums.curve} [curveName] - for algos supporting different curves (e.g. ECDSA)
 * @returns curve implementation
 * @throws on unrecognized curve, or curve not implemented by noble-curve
 */
export async function getNobleCurve(publicKeyAlgo: typeof enums.publicKey.x448): Promise<NobleCurves['x448']>;
export async function getNobleCurve(publicKeyAlgo: typeof enums.publicKey.ed448): Promise<NobleCurves['ed448']>;
export async function getNobleCurve<C extends keyof NobleCurves>(publicKeyAlgo: typeof enums.publicKey.ecdh | typeof enums.publicKey.ecdsa, curveName: C): Promise<NobleCurves[C]>;
export async function getNobleCurve(publicKeyAlgo: Enums['publicKey'], curveName?: Enums['curve']) {
  if (!defaultConfig.useEllipticFallback) {
    throw new Error('This curve is only supported in the full build of OpenPGP.js');
  }

  const { nobleCurves } = await import('./crypto/public_key/elliptic/noble_curves.js');
  switch (publicKeyAlgo) {
    case enums.publicKey.ecdh:
    case enums.publicKey.ecdsa:
      if (!curveName || !nobleCurves[curveName]) throw new Error('Unsupported curve');
      return nobleCurves[curveName];
    case enums.publicKey.x448:
      return nobleCurves.x448;
    case enums.publicKey.ed448:
      return nobleCurves.ed448;
    default:
      throw new Error('Unsupported curve');
  }
}

export function readNumber(bytes: Uint8Array) {
  let n = 0;
  for (let i = 0; i < bytes.length; i++) {
    n += (256 ** i) * bytes[bytes.length - 1 - i];
  }
  return n;
}

export function writeNumber(n: number, byteLength: number) {
  const b = new Uint8Array(byteLength);
  for (let i = 0; i < byteLength; i++) {
    b[i] = (n >> (8 * (byteLength - i - 1))) & 0xFF;
  }

  return b;
}

export function readDate(bytes: Uint8Array) {
  const n = readNumber(bytes);
  const d = new Date(n * 1000);
  return d;
}

export function writeDate(time: Date) {
  const numeric = Math.floor(time.getTime() / 1000);

  return writeNumber(numeric, 4);
}

export function normalizeDate(time = Date.now()) {
  return time === null || time === Infinity ? time : new Date(Math.floor(+time / 1000) * 1000);
}

/**
 * Read one MPI from bytes in input
 * @param bytes - Input data to parse
 * @returns Parsed MPI.
 */
export function readMPI(bytes: Uint8Array) {
  const bits = (bytes[0] << 8) | bytes[1];
  const bytelen = (bits + 7) >>> 3;
  // There is a decryption oracle risk here by enforcing the MPI length using `readExactSubarray` in the context of SEIPDv1 encrypted signatures,
  // where unauthenticated streamed decryption is done (via `config.allowUnauthenticatedStream`), since the decrypted signature data being processed
  // has not been authenticated (yet).
  // However, such config setting is known to be insecure, and there are other packet parsing errors that can cause similar issues.
  // Also, AEAD is also not affected.
  return readExactSubarray(bytes, 2, 2 + bytelen);
}

/**
 * Read exactly `end - start` bytes from input.
 * This is a stricter version of `.subarray`.
 * @param input - Input data to parse
 * @returns subarray of size always equal to `end - start`
 * @throws if the input array is too short.
 */
export function readExactSubarray(input: Uint8Array, start: number, end: number) {
  if (input.length < end) {
    throw new Error('Input array too short');
  }
  return input.subarray(start, end);
}

/**
 * Left-pad Uint8Array to length by adding 0x0 bytes
 * @param bytes - Data to pad
 * @param length - Padded length
 * @returns Padded bytes.
 */
export function leftPad(bytes: Uint8Array, length: number) {
  if (bytes.length > length) {
    throw new Error('Input array too long');
  }
  if (bytes.length === length) {
    return bytes;
  }
  const padded = new Uint8Array(length);
  const offset = length - bytes.length;
  padded.set(bytes, offset);
  return padded;
}

/**
 * Convert a Uint8Array to an MPI-formatted Uint8Array.
 * @param bin - An array of 8-bit integers to convert
 * @returns MPI-formatted Uint8Array.
 */
export function uint8ArrayToMPI(bin: Uint8Array) {
  const bitSize = uint8ArrayBitLength(bin);
  if (bitSize === 0) {
    throw new Error('Zero MPI');
  }
  const stripped = bin.subarray(bin.length - Math.ceil(bitSize / 8));
  const prefix = new Uint8Array([(bitSize & 0xFF00) >> 8, bitSize & 0xFF]);
  return concatUint8Array([prefix, stripped]);
}

/**
 * Return bit length of the input data
 * @param bin input data (big endian)
 * @returns bit length
 */
export function uint8ArrayBitLength(bin: Uint8Array) {
  let i; // index of leading non-zero byte
  for (i = 0; i < bin.length; i++) if (bin[i] !== 0) break;
  if (i === bin.length) {
    return 0;
  }
  const stripped = bin.subarray(i);
  return (stripped.length - 1) * 8 + nbits(stripped[0]);
}

/**
 * Convert a hex string to an array of 8-bit integers
 * @param hex - A hex string to convert
 * @returns An array of 8-bit integers.
 */
export function hexToUint8Array(hex: string) {
  const result = new Uint8Array(hex.length >> 1);
  for (let k = 0; k < hex.length >> 1; k++) {
    result[k] = parseInt(hex.substr(k << 1, 2), 16);
  }
  return result;
}

/**
 * Convert an array of 8-bit integers to a hex string
 * @param bytes - Array of 8-bit integers to convert
 * @returns Hexadecimal representation of the array.
 */
export function uint8ArrayToHex(bytes: Uint8Array) {
  const hexAlphabet = '0123456789abcdef';
  let s = '';
  bytes.forEach(v => { s += hexAlphabet[v >> 4] + hexAlphabet[v & 15]; });
  return s;
}

/**
 * Convert a string to an array of 8-bit integers
 * @param String to convert
 * @returns An array of 8-bit integers.
 */
export function stringToUint8Array(input: string) {
  return streamTransform(input, (str: string) => {
    if (!isString(str)) {
      throw new Error('stringToUint8Array: Data must be in the form of a string');
    }

    const result = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
      result[i] = str.charCodeAt(i);
    }
    return result;
  });
}

/**
 * Convert an array of 8-bit integers to a string
 * @param bytes - An array of 8-bit integers to convert
 * @returns String representation of the array.
 */
export function uint8ArrayToString(bytes: Uint8Array) {
  bytes = new Uint8Array(bytes);
  const result = [];
  const bs = 1 << 14;
  const j = bytes.length;

  for (let i = 0; i < j; i += bs) {
    result.push(
      String.fromCharCode.apply(
        String,
        // @ts-expect-error expects number[] instead of Uint8Array
        bytes.subarray(i, i + bs < j ? i + bs : j)
      )
    );
  }
  return result.join('');
}

/**
 * Convert a native javascript string to a Uint8Array of utf8 bytes
 * @param str - The string to convert
 * @returns A valid squence of utf8 bytes.
 */
export function encodeUTF8<T extends MaybeStream<string>>(str: T) {
  const encoder = new TextEncoder();
  const process = (value: string) => encoder.encode(value);

  return streamTransform(str, process, () => process(''));
}


/**
 * Convert a Uint8Array of utf8 bytes to a native javascript string
 * @param utf8 - A valid squence of utf8 bytes
 * @returns A native javascript string.
 */
export function decodeUTF8<T extends MaybeStream<Uint8Array>>(utf8: T) {
  const decoder = new TextDecoder('utf-8');

  const process = (value: Uint8Array, lastChunk = false) => (
    decoder.decode(value, { stream: !lastChunk })
  );
  return streamTransform(utf8, process, () => process(new Uint8Array(), true));
}

/**
 * Concat a list of Uint8Arrays, Strings or Streams
 * The caller must not mix Uint8Arrays with Strings, but may mix Streams with non-Streams.
 * @param {Array<Uint8Array|String|ReadableStream>} Array - Of Uint8Arrays/Strings/Streams to concatenate
 * @returns {Uint8Array|String|ReadableStream} Concatenated array.
 */
export { streamConcat as concat };

/**
 * Concat Uint8Arrays
 * @param {Array<Uint8Array>} Array - Of Uint8Arrays to concatenate
 * @returns {Uint8Array} Concatenated array.
 */
export { concatUint8Array };

/**
 * Check Uint8Array equality
 * @param {Uint8Array} array1 - First array
 * @param {Uint8Array} array2 - Second array
 * @returns {Boolean} Equality.
 */
export function equalsUint8Array(array1: Uint8Array, array2: Uint8Array) {
  if (!isUint8Array(array1) || !isUint8Array(array2)) {
    throw new Error('Data must be in the form of a Uint8Array');
  }

  if (array1.length !== array2.length) {
    return false;
  }

  for (let i = 0; i < array1.length; i++) {
    if (array1[i] !== array2[i]) {
      return false;
    }
  }
  return true;
}

/**
 * Check Uint8Array equality in algorithmic constant time
 * @param array1 - First array
 * @param array2 - Second array
 * @returns Equality
 * @throws on input arrays of different lengths
 */
export function timingSafeEqualsUint8Array(array1: Uint8Array, array2: Uint8Array) {
  if (array1.length !== array2.length) {
    throw new Error('Equal input arrays expected');
  }

  let equal = 1;
  for (let i = 0; i < array1.length; i++) {
    equal &= Number(array1[i] === array2[i]);
  }
  return !!equal;
}

/**
 * Calculates a 16bit sum of a Uint8Array by adding each character
 * codes modulus 65535
 * @param text - To create a sum of
 * @returns 2 bytes containing the sum of all charcodes % 65535.
 */
export function writeChecksum(text: Uint8Array) {
  let s = 0;
  for (let i = 0; i < text.length; i++) {
    s = (s + text[i]) & 0xFFFF;
  }
  return writeNumber(s, 2);
}

/**
 * Helper function to print a debug message. Debug
 * messages are only printed if
 * @param str - String of the debug message
 */
export function printDebug(str: string) {
  if (debugMode) {
    console.log('[OpenPGP.js debug]', str);
  }
}

/**
 * Helper function to print a debug error. Debug
 * messages are only printed if
 * @param str - String of the debug message
 */
export function printDebugError(error: Error) {
  if (debugMode) {
    console.error('[OpenPGP.js debug]', error);
  }
}

// returns bit length of the integer x
export function nbits(x: number) {
  let r = 1;
  let t = x >>> 16;
  if (t !== 0) {
    x = t;
    r += 16;
  }
  t = x >> 8;
  if (t !== 0) {
    x = t;
    r += 8;
  }
  t = x >> 4;
  if (t !== 0) {
    x = t;
    r += 4;
  }
  t = x >> 2;
  if (t !== 0) {
    x = t;
    r += 2;
  }
  t = x >> 1;
  if (t !== 0) {
    x = t;
    r += 1;
  }
  return r;
}

/**
 * If S[1] == 0, then double(S) == (S[2..128] || 0);
 * otherwise, double(S) == (S[2..128] || 0) xor
 * (zeros(120) || 10000111).
 *
 * Both OCB and EAX (through CMAC) require this function to be constant-time.
 *
 * @param data
 */
export function double(data: Uint8Array) {
  const doubleVar = new Uint8Array(data.length);
  const last = data.length - 1;
  for (let i = 0; i < last; i++) {
    doubleVar[i] = (data[i] << 1) ^ (data[i + 1] >> 7);
  }
  doubleVar[last] = (data[last] << 1) ^ ((data[0] >> 7) * 0x87);
  return doubleVar;
}

/**
 * Shift a Uint8Array to the right by n bits
 * @param array - The array to shift
 * @param bits - Amount of bits to shift (MUST be smaller
 * than 8)
 * @returns Resulting array.
 */
export function shiftRight(array: Uint8Array, bits: number) {
  if (bits < 0 || bits > 8) {
    throw new Error('Invalid bits input: must be withing 0 and 8');
  }
  if (bits) {
    for (let i = array.length - 1; i >= 0; i--) {
      array[i] >>= bits;
      if (i > 0) {
        array[i] |= (array[i - 1] << (8 - bits));
      }
    }
  }
  return array;
}

/**
 * Native crypto getters, kept in a mutable object so that tests can stub them
 */
export const cryptoProviders = {
  /**
   * Get native Web Cryptography API.
   * @returns The SubtleCrypto API
   * @throws if the API is not available
   */
  getWebCrypto() {
    const webCrypto = typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle;
    if (!webCrypto) {
      throw new Error('The WebCrypto API is not available');
    }
    return webCrypto;
  },
  /**
   * Get native Node.js crypto api.
   * @returns The crypto module or 'undefined'.
   */
  getNodeCrypto() {
    return nodeRequire('crypto') as typeof import('node:crypto');
  }
};

export function getNodeZlib() {
  return nodeRequire('zlib');
}

/**
 * Get native Node.js Buffer constructor
 * @returns The Buffer constructor or 'undefined'.
 */
export function getNodeBuffer(): typeof import('node:buffer').Buffer | undefined {
  return (nodeRequire('buffer') || {}).Buffer;
}

export function getHardwareConcurrency() {
  if (typeof navigator !== 'undefined') {
    return navigator.hardwareConcurrency || 1;
  }

  const os = nodeRequire('os') as typeof import('node:os'); // Assume we're on Node.js.
  return os.cpus().length;
}

/**
 * Test email format to ensure basic compliance:
 * - must include a single @
 * - no control or space unicode chars allowed
 * - no backslash and square brackets (as the latter can mess with the userID parsing)
 * - cannot end with a punctuation char
 * These checks are not meant to be exhaustive; applications are strongly encouraged to implement stricter validation,
 * e.g. based on the W3C HTML spec (https://html.spec.whatwg.org/multipage/input.html#email-state-(type=email)).
 */
export function isEmailAddress(data: string) {
  const re = /^[^\p{C}\p{Z}@<>\\]+@[^\p{C}\p{Z}@<>\\]+[^\p{C}\p{Z}\p{P}]$/u;
  return re.test(data);
}

/**
 * Normalize line endings to <CR><LF>
 * Support any encoding where CR=0x0D, LF=0x0A
 */
export function canonicalizeEOL(data: Uint8Array) {
  const CR = 13;
  const LF = 10;
  let carryOverCR = false;

  return streamTransform(data, (bytes: Uint8Array) => {
    if (carryOverCR) {
      bytes = concatUint8Array([new Uint8Array([CR]), bytes]);
    }

    if (bytes[bytes.length - 1] === CR) {
      carryOverCR = true;
      bytes = bytes.subarray(0, -1);
    } else {
      carryOverCR = false;
    }

    let index;
    const indices = [];
    for (let i = 0; ; i = index) {
      index = bytes.indexOf(LF, i) + 1;
      if (index) {
        if (bytes[index - 2] !== CR) indices.push(index);
      } else {
        break;
      }
    }
    if (!indices.length) {
      return bytes;
    }

    const normalized = new Uint8Array(bytes.length + indices.length);
    let j = 0;
    for (let i = 0; i < indices.length; i++) {
      const sub = bytes.subarray(indices[i - 1] || 0, indices[i]);
      normalized.set(sub, j);
      j += sub.length;
      normalized[j - 1] = CR;
      normalized[j] = LF;
      j++;
    }
    normalized.set(bytes.subarray(indices[indices.length - 1] || 0), j);
    return normalized;
  }, () => (carryOverCR ? new Uint8Array([CR]) : undefined));
}

/**
 * Convert line endings from canonicalized <CR><LF> to native <LF>
 * Support any encoding where CR=0x0D, LF=0x0A
 */
export function nativeEOL(data: Uint8Array) {
  const CR = 13;
  const LF = 10;
  let carryOverCR = false;

  return streamTransform(data, (bytes: Uint8Array) => {
    if (carryOverCR && bytes[0] !== LF) {
      bytes = concatUint8Array([new Uint8Array([CR]), bytes]);
    } else {
      bytes = new Uint8Array(bytes); // Don't mutate passed bytes
    }

    if (bytes[bytes.length - 1] === CR) {
      carryOverCR = true;
      bytes = bytes.subarray(0, -1);
    } else {
      carryOverCR = false;
    }

    let index;
    let j = 0;
    for (let i = 0; i !== bytes.length; i = index) {
      index = bytes.indexOf(CR, i) + 1;
      if (!index) index = bytes.length;
      const last = index - (bytes[index] === LF ? 1 : 0);
      if (i) bytes.copyWithin(j, i, last);
      j += last - i;
    }
    return bytes.subarray(0, j);
  }, () => (carryOverCR ? new Uint8Array([CR]) : undefined));
}

/**
 * Remove trailing spaces, carriage returns and tabs from each line
 */
export function removeTrailingSpaces(text: string) {
  return text.split('\n').map(line => {
    let i = line.length - 1;
    for (; i >= 0 && (line[i] === ' ' || line[i] === '\t' || line[i] === '\r'); i--);
    return line.substr(0, i + 1);
  }).join('\n');
}

export function wrapError(error: unknown, cause: unknown) {
  if (!(cause instanceof Error)) {
    if (error instanceof Error) {
      return error;
    }
    return new Error(error as string);
  }

  if (error instanceof Error) {
    // update error message
    try {
      error.message += ': ' + cause.message;
      error.cause = cause;
    } catch {}
    return error;
  }
  return new Error(error + ': ' + cause.message, { cause });
}

/**
 * Map allowed packet tags to corresponding classes
 * Meant to be used to format `allowedPacket` for Packetlist.read
 * @param allowedClasses
 * @returns map from enum.packet to corresponding *Packet class
 */
export function constructAllowedPackets<const PacketClassType extends { new(): any; tag: Enums['packet'] }>(allowedClasses: PacketClassType[]) {
  const map: Partial<Record<Enums['packet'], PacketClassType>> = {};
  allowedClasses.forEach(PacketClass => {
    if (!PacketClass.tag) {
      throw new Error('Invalid input: expected a packet class');
    }
    map[PacketClass.tag] = PacketClass;
  });
  return map as { [C in PacketClassType as C['tag']]: C };
}

/**
 * Return a Promise that will resolve as soon as one of the promises in input resolves
 * or will reject if all input promises all rejected
 * (similar to Promise.any, but with slightly different error handling)
 * @param promises
 * @return Promise resolving to the result of the fastest fulfilled promise
 *                          or rejected with the Error of the last settled Promise (if all promises are rejected)
 */
export function anyPromise<T>(promises: Promise<T>[]) {
  return new Promise<T>((resolve, reject) => {
    let exception: unknown;
    void Promise.all(promises.map(async promise => {
      try {
        resolve(await promise);
      } catch (e) {
        exception = e;
      }
    })).then(() => {
      reject(exception);
    });
  });
}

const boolToBit = (b: boolean) => Number(b) as 0 | 1;
/**
 * Return either `a` or `b` based on `cond`, in algorithmic constant time.
 * @param cond
 * @param a
 * @param b
 * @returns `a` if `cond` is true, `b` otherwise
 */
export function selectUint8Array(cond: boolean, a: Uint8Array, b: Uint8Array) {
  const length = Math.max(a.length, b.length);
  const result = new Uint8Array(length);
  const condBit = boolToBit(cond);
  let end = 0;
  for (let i = 0; i < result.length; i++) {
    result[i] = (a[i] & (256 - condBit)) | (b[i] & (255 + condBit));
    end += (condBit & boolToBit(i < a.length)) | ((1 - condBit) & boolToBit(i < b.length));
  }
  return result.subarray(0, end);
}

/**
 * Return either `a` or `b` based on `cond`, in algorithmic constant time.
 * NB: it only supports `a, b` with values between 0-255.
 * @param cond
 * @param a (uint8)
 * @param b (uint8)
 * @returns `a` if `cond` is true, `b` otherwise
 */
export function selectUint8(cond: boolean, a: number, b: number) {
  const condBit = boolToBit(cond);
  return (a & (256 - condBit)) | (b & (255 + condBit));
}

export function isAES(cipherAlgo: Enums['symmetric']) {
  return cipherAlgo === enums.symmetric.aes128 || cipherAlgo === enums.symmetric.aes192 || cipherAlgo === enums.symmetric.aes256;
}
