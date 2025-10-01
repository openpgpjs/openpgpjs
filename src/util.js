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
 */

import { concat as streamConcat, transform as streamTransform, concatUint8Array, isStream, isUint8Array } from '@openpgp/web-stream-tools';
import { createRequire } from 'module'; // Must be stripped in browser built
import enums from './enums';
import defaultConfig from './config';

const debugMode = (() => {
  try {
    return process.env.NODE_ENV === 'development';
  } catch {}
  return false;
})();

const util = {
  isString: function(data) {
    return typeof data === 'string' || data instanceof String;
  },

  nodeRequire: createRequire(import.meta.url),

  isArray: function(data) {
    return data instanceof Array;
  },

  isUint8Array: isUint8Array,

  isStream: isStream,

  /**
   * Load noble-curves lib on demand and return the requested curve function
   * @param {enums.publicKey} publicKeyAlgo
   * @param {enums.curve} [curveName] - for algos supporting different curves (e.g. ECDSA)
   * @returns curve implementation
   * @throws on unrecognized curve, or curve not implemented by noble-curve
   */
  getNobleCurve: async (publicKeyAlgo, curveName) => {
    if (!defaultConfig.useEllipticFallback) {
      throw new Error('This curve is only supported in the full build of OpenPGP.js');
    }

    const { nobleCurves } = await import('./crypto/public_key/elliptic/noble_curves');
    switch (publicKeyAlgo) {
      case enums.publicKey.ecdh:
      case enums.publicKey.ecdsa: {
        const curve = nobleCurves.get(curveName);
        if (!curve) throw new Error('Unsupported curve');
        return curve;
      }
      case enums.publicKey.x448:
        return nobleCurves.get('x448');
      case enums.publicKey.ed448:
        return nobleCurves.get('ed448');
      default:
        throw new Error('Unsupported curve');
    }
  },

  readNumber: function (bytes) {
    let n = 0;
    for (let i = 0; i < bytes.length; i++) {
      n += (256 ** i) * bytes[bytes.length - 1 - i];
    }
    return n;
  },

  writeNumber: function (n, bytes) {
    const b = new Uint8Array(bytes);
    for (let i = 0; i < bytes; i++) {
      b[i] = (n >> (8 * (bytes - i - 1))) & 0xFF;
    }

    return b;
  },

  readDate: function (bytes) {
    const n = util.readNumber(bytes);
    const d = new Date(n * 1000);
    return d;
  },

  writeDate: function (time) {
    const numeric = Math.floor(time.getTime() / 1000);

    return util.writeNumber(numeric, 4);
  },

  normalizeDate: function (time = Date.now()) {
    return time === null || time === Infinity ? time : new Date(Math.floor(+time / 1000) * 1000);
  },

  /**
   * Read one MPI from bytes in input
   * @param {Uint8Array} bytes - Input data to parse
   * @returns {Uint8Array} Parsed MPI.
   */
  readMPI: function (bytes) {
    const bits = (bytes[0] << 8) | bytes[1];
    const bytelen = (bits + 7) >>> 3;
    // There is a decryption oracle risk here by enforcing the MPI length using `readExactSubarray` in the context of SEIPDv1 encrypted signatures,
    // where unauthenticated streamed decryption is done (via `config.allowUnauthenticatedStream`), since the decrypted signature data being processed
    // has not been authenticated (yet).
    // However, such config setting is known to be insecure, and there are other packet parsing errors that can cause similar issues.
    // Also, AEAD is also not affected.
    return util.readExactSubarray(bytes, 2, 2 + bytelen);
  },

  /**
   * Read exactly `end - start` bytes from input.
   * This is a stricter version of `.subarray`.
   * @param {Uint8Array} input - Input data to parse
   * @returns {Uint8Array} subarray of size always equal to `end - start`
   * @throws if the input array is too short.
   */
  readExactSubarray: function (input, start, end) {
    if (input.length < (end - start)) {
      throw new Error('Input array too short');
    }
    return input.subarray(start, end);
  },

  /**
   * Left-pad Uint8Array to length by adding 0x0 bytes
   * @param {Uint8Array} bytes - Data to pad
   * @param {Number} length - Padded length
   * @returns {Uint8Array} Padded bytes.
   */
  leftPad(bytes, length) {
    if (bytes.length > length) {
      throw new Error('Input array too long');
    }
    const padded = new Uint8Array(length);
    const offset = length - bytes.length;
    padded.set(bytes, offset);
    return padded;
  },

  /**
   * Convert a Uint8Array to an MPI-formatted Uint8Array.
   * @param {Uint8Array} bin - An array of 8-bit integers to convert
   * @returns {Uint8Array} MPI-formatted Uint8Array.
   */
  uint8ArrayToMPI: function (bin) {
    const bitSize = util.uint8ArrayBitLength(bin);
    if (bitSize === 0) {
      throw new Error('Zero MPI');
    }
    const stripped = bin.subarray(bin.length - Math.ceil(bitSize / 8));
    const prefix = new Uint8Array([(bitSize & 0xFF00) >> 8, bitSize & 0xFF]);
    return util.concatUint8Array([prefix, stripped]);
  },

  /**
   * Return bit length of the input data
   * @param {Uint8Array} bin input data (big endian)
   * @returns bit length
   */
  uint8ArrayBitLength: function (bin) {
    let i; // index of leading non-zero byte
    for (i = 0; i < bin.length; i++) if (bin[i] !== 0) break;
    if (i === bin.length) {
      return 0;
    }
    const stripped = bin.subarray(i);
    return (stripped.length - 1) * 8 + util.nbits(stripped[0]);
  },

  /**
   * Convert a hex string to an array of 8-bit integers
   * @param {String} hex - A hex string to convert
   * @returns {Uint8Array} An array of 8-bit integers.
   */
  hexToUint8Array: function (hex) {
    const result = new Uint8Array(hex.length >> 1);
    for (let k = 0; k < hex.length >> 1; k++) {
      result[k] = parseInt(hex.substr(k << 1, 2), 16);
    }
    return result;
  },

  /**
   * Convert an array of 8-bit integers to a hex string
   * @param {Uint8Array} bytes - Array of 8-bit integers to convert
   * @returns {String} Hexadecimal representation of the array.
   */
  uint8ArrayToHex: function (bytes) {
    const hexAlphabet = '0123456789abcdef';
    let s = '';
    bytes.forEach(v => { s += hexAlphabet[v >> 4] + hexAlphabet[v & 15]; });
    return s;
  },

  /**
   * Convert a string to an array of 8-bit integers
   * @param {String} str - String to convert
   * @returns {Uint8Array} An array of 8-bit integers.
   */
  stringToUint8Array: function (str) {
    return streamTransform(str, str => {
      if (!util.isString(str)) {
        throw new Error('stringToUint8Array: Data must be in the form of a string');
      }

      const result = new Uint8Array(str.length);
      for (let i = 0; i < str.length; i++) {
        result[i] = str.charCodeAt(i);
      }
      return result;
    });
  },

  /**
   * Convert an array of 8-bit integers to a string
   * @param {Uint8Array} bytes - An array of 8-bit integers to convert
   * @returns {String} String representation of the array.
   */
  uint8ArrayToString: function (bytes) {
    bytes = new Uint8Array(bytes);
    const result = [];
    const bs = 1 << 14;
    const j = bytes.length;

    for (let i = 0; i < j; i += bs) {
      result.push(String.fromCharCode.apply(String, bytes.subarray(i, i + bs < j ? i + bs : j)));
    }
    return result.join('');
  },

  /**
   * Convert a native javascript string to a Uint8Array of utf8 bytes
   * @param {String|ReadableStream} str - The string to convert
   * @returns {Uint8Array|ReadableStream} A valid squence of utf8 bytes.
   */
  encodeUTF8: function (str) {
    const encoder = new TextEncoder('utf-8');

    function process(value, lastChunk = false) {
      return encoder.encode(value, { stream: !lastChunk });
    }
    return streamTransform(str, process, () => process('', true));
  },

  /**
   * Convert a Uint8Array of utf8 bytes to a native javascript string
   * @param {Uint8Array|ReadableStream} utf8 - A valid squence of utf8 bytes
   * @returns {String|ReadableStream} A native javascript string.
   */
  decodeUTF8: function (utf8) {
    const decoder = new TextDecoder('utf-8');

    function process(value, lastChunk = false) {
      return decoder.decode(value, { stream: !lastChunk });
    }
    return streamTransform(utf8, process, () => process(new Uint8Array(), true));
  },

  /**
   * Concat a list of Uint8Arrays, Strings or Streams
   * The caller must not mix Uint8Arrays with Strings, but may mix Streams with non-Streams.
   * @param {Array<Uint8Array|String|ReadableStream>} Array - Of Uint8Arrays/Strings/Streams to concatenate
   * @returns {Uint8Array|String|ReadableStream} Concatenated array.
   */
  concat: streamConcat,

  /**
   * Concat Uint8Arrays
   * @param {Array<Uint8Array>} Array - Of Uint8Arrays to concatenate
   * @returns {Uint8Array} Concatenated array.
   */
  concatUint8Array: concatUint8Array,

  /**
   * Check Uint8Array equality
   * @param {Uint8Array} array1 - First array
   * @param {Uint8Array} array2 - Second array
   * @returns {Boolean} Equality.
   */
  equalsUint8Array: function (array1, array2) {
    if (!util.isUint8Array(array1) || !util.isUint8Array(array2)) {
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
  },

  /**
   * Same as Array.findLastIndex, which is not supported on Safari 14 .
   * @param {Array} arr
   * @param {function(element, index, arr): boolean} findFn
   * @return index of last element matching `findFn`, -1 if not found
   */
  findLastIndex: function(arr, findFn) {
    for (let i = arr.length; i >= 0; i--) {
      if (findFn(arr[i], i, arr)) {
        return i;
      }
    }
    return -1;
  },

  /**
   * Calculates a 16bit sum of a Uint8Array by adding each character
   * codes modulus 65535
   * @param {Uint8Array} Uint8Array - To create a sum of
   * @returns {Uint8Array} 2 bytes containing the sum of all charcodes % 65535.
   */
  writeChecksum: function (text) {
    let s = 0;
    for (let i = 0; i < text.length; i++) {
      s = (s + text[i]) & 0xFFFF;
    }
    return util.writeNumber(s, 2);
  },

  /**
   * Helper function to print a debug message. Debug
   * messages are only printed if
   * @param {String} str - String of the debug message
   */
  printDebug: function (str) {
    if (debugMode) {
      console.log('[OpenPGP.js debug]', str);
    }
  },

  /**
   * Helper function to print a debug error. Debug
   * messages are only printed if
   * @param {String} str - String of the debug message
   */
  printDebugError: function (error) {
    if (debugMode) {
      console.error('[OpenPGP.js debug]', error);
    }
  },

  // returns bit length of the integer x
  nbits: function (x) {
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
  },

  /**
   * If S[1] == 0, then double(S) == (S[2..128] || 0);
   * otherwise, double(S) == (S[2..128] || 0) xor
   * (zeros(120) || 10000111).
   *
   * Both OCB and EAX (through CMAC) require this function to be constant-time.
   *
   * @param {Uint8Array} data
   */
  double: function(data) {
    const doubleVar = new Uint8Array(data.length);
    const last = data.length - 1;
    for (let i = 0; i < last; i++) {
      doubleVar[i] = (data[i] << 1) ^ (data[i + 1] >> 7);
    }
    doubleVar[last] = (data[last] << 1) ^ ((data[0] >> 7) * 0x87);
    return doubleVar;
  },

  /**
   * Shift a Uint8Array to the right by n bits
   * @param {Uint8Array} array - The array to shift
   * @param {Integer} bits - Amount of bits to shift (MUST be smaller
   * than 8)
   * @returns {String} Resulting array.
   */
  shiftRight: function (array, bits) {
    if (bits) {
      for (let i = array.length - 1; i >= 0; i--) {
        array[i] >>= bits;
        if (i > 0) {
          array[i] |= (array[i - 1] << (8 - bits));
        }
      }
    }
    return array;
  },

  /**
   * Get native Web Cryptography API.
   * @returns {Object} The SubtleCrypto API
   * @throws if the API is not available
   */
  getWebCrypto: function() {
    const globalWebCrypto = typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle;
    // Fallback for Node 16, which does not expose WebCrypto as a global
    const webCrypto = globalWebCrypto || this.getNodeCrypto()?.webcrypto.subtle;
    if (!webCrypto) {
      throw new Error('The WebCrypto API is not available');
    }
    return webCrypto;
  },

  /** @typedef {import('node:crypto')} NodeCrypto */
  /**
   * Get native Node.js crypto api.
   * @returns {NodeCrypto} The crypto module or 'undefined'.
   */
  getNodeCrypto: function() {
    return this.nodeRequire('crypto');
  },

  getNodeZlib: function() {
    return this.nodeRequire('zlib');
  },

  /**
   * Get native Node.js Buffer constructor. This should be used since
   * Buffer is not available under browserify.
   * @returns {Function} The Buffer constructor or 'undefined'.
   */
  getNodeBuffer: function() {
    return (this.nodeRequire('buffer') || {}).Buffer;
  },

  getHardwareConcurrency: function() {
    if (typeof navigator !== 'undefined') {
      return navigator.hardwareConcurrency || 1;
    }

    const os = this.nodeRequire('os'); // Assume we're on Node.js.
    return os.cpus().length;
  },

  /**
   * Test email format to ensure basic compliance:
   * - must include a single @
   * - no control or space unicode chars allowed
   * - no backslash and square brackets (as the latter can mess with the userID parsing)
   * - cannot end with a punctuation char
   * These checks are not meant to be exhaustive; applications are strongly encouraged to implement stricter validation,
   * e.g. based on the W3C HTML spec (https://html.spec.whatwg.org/multipage/input.html#email-state-(type=email)).
   */
  isEmailAddress: function(data) {
    if (!util.isString(data)) {
      return false;
    }
    const re = /^[^\p{C}\p{Z}@<>\\]+@[^\p{C}\p{Z}@<>\\]+[^\p{C}\p{Z}\p{P}]$/u;
    return re.test(data);
  },

  /**
   * Normalize line endings to <CR><LF>
   * Support any encoding where CR=0x0D, LF=0x0A
   */
  canonicalizeEOL: function(data) {
    const CR = 13;
    const LF = 10;
    let carryOverCR = false;

    return streamTransform(data, bytes => {
      if (carryOverCR) {
        bytes = util.concatUint8Array([new Uint8Array([CR]), bytes]);
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
  },

  /**
   * Convert line endings from canonicalized <CR><LF> to native <LF>
   * Support any encoding where CR=0x0D, LF=0x0A
   */
  nativeEOL: function(data) {
    const CR = 13;
    const LF = 10;
    let carryOverCR = false;

    return streamTransform(data, bytes => {
      if (carryOverCR && bytes[0] !== LF) {
        bytes = util.concatUint8Array([new Uint8Array([CR]), bytes]);
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
  },

  /**
   * Remove trailing spaces, carriage returns and tabs from each line
   */
  removeTrailingSpaces: function(text) {
    return text.split('\n').map(line => {
      let i = line.length - 1;
      for (; i >= 0 && (line[i] === ' ' || line[i] === '\t' || line[i] === '\r'); i--);
      return line.substr(0, i + 1);
    }).join('\n');
  },

  wrapError: function(error, cause) {
    if (!cause) {
      if (error instanceof Error) {
        return error;
      }
      return new Error(error);
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
  },

  /**
   * Map allowed packet tags to corresponding classes
   * Meant to be used to format `allowedPacket` for Packetlist.read
   * @param {Array<Object>} allowedClasses
   * @returns {Object} map from enum.packet to corresponding *Packet class
   */
  constructAllowedPackets: function(allowedClasses) {
    const map = {};
    allowedClasses.forEach(PacketClass => {
      if (!PacketClass.tag) {
        throw new Error('Invalid input: expected a packet class');
      }
      map[PacketClass.tag] = PacketClass;
    });
    return map;
  },

  /**
   * Return a Promise that will resolve as soon as one of the promises in input resolves
   * or will reject if all input promises all rejected
   * (similar to Promise.any, but with slightly different error handling)
   * @param {Array<Promise>} promises
   * @return {Promise<Any>} Promise resolving to the result of the fastest fulfilled promise
   *                          or rejected with the Error of the last resolved Promise (if all promises are rejected)
   */
  anyPromise: function(promises) {
    return new Promise((resolve, reject) => {
      let exception;
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
  },

  /**
   * Return either `a` or `b` based on `cond`, in algorithmic constant time.
   * @param {Boolean} cond
   * @param {Uint8Array} a
   * @param {Uint8Array} b
   * @returns `a` if `cond` is true, `b` otherwise
   */
  selectUint8Array: function(cond, a, b) {
    const length = Math.max(a.length, b.length);
    const result = new Uint8Array(length);
    let end = 0;
    for (let i = 0; i < result.length; i++) {
      result[i] = (a[i] & (256 - cond)) | (b[i] & (255 + cond));
      end += (cond & i < a.length) | ((1 - cond) & i < b.length);
    }
    return result.subarray(0, end);
  },
  /**
   * Return either `a` or `b` based on `cond`, in algorithmic constant time.
   * NB: it only supports `a, b` with values between 0-255.
   * @param {Boolean} cond
   * @param {Uint8} a
   * @param {Uint8} b
   * @returns `a` if `cond` is true, `b` otherwise
   */
  selectUint8: function(cond, a, b) {
    return (a & (256 - cond)) | (b & (255 + cond));
  },
  /**
   * @param {module:enums.symmetric} cipherAlgo
   */
  isAES: function(cipherAlgo) {
    return cipherAlgo === enums.symmetric.aes128 || cipherAlgo === enums.symmetric.aes192 || cipherAlgo === enums.symmetric.aes256;
  }
};

export default util;
