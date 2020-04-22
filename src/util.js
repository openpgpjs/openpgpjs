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
 * @requires email-addresses
 * @requires web-stream-tools
 * @requires config
 * @requires encoding/base64
 * @module util
 */

import emailAddresses from 'email-addresses';
import stream from 'web-stream-tools';
import config from './config';
import util from './util'; // re-import module to access util functions
import b64 from './encoding/base64';

export default {
  isString: function(data) {
    return typeof data === 'string' || String.prototype.isPrototypeOf(data);
  },

  isArray: function(data) {
    return Array.prototype.isPrototypeOf(data);
  },

  isUint8Array: stream.isUint8Array,

  isStream: stream.isStream,

  /**
   * Get transferable objects to pass buffers with zero copy (similar to "pass by reference" in C++)
   *   See: https://developer.mozilla.org/en-US/docs/Web/API/Worker/postMessage
   * Also, convert ReadableStreams to MessagePorts
   * @param  {Object} obj           the options object to be passed to the web worker
   * @returns {Array<ArrayBuffer>}   an array of binary data to be passed
   */
  getTransferables: function(obj, zero_copy) {
    const transferables = [];
    util.collectTransferables(obj, transferables, zero_copy);
    return transferables.length ? transferables : undefined;
  },

  collectTransferables: function(obj, collection, zero_copy) {
    if (!obj) {
      return;
    }

    if (util.isUint8Array(obj)) {
      if (zero_copy && collection.indexOf(obj.buffer) === -1 && !(
        navigator.userAgent.indexOf('Version/11.1') !== -1 || // Safari 11.1
        ((navigator.userAgent.match(/Chrome\/(\d+)/) || [])[1] < 56 && navigator.userAgent.indexOf('Edge') === -1) // Chrome < 56
      )) {
        collection.push(obj.buffer);
      }
      return;
    }
    if (Object.prototype.isPrototypeOf(obj)) {
      Object.entries(obj).forEach(([key, value]) => { // recursively search all children
        if (util.isStream(value)) {
          if (value.locked) {
            obj[key] = null;
          } else {
            const transformed = stream.transformPair(value, async readable => {
              const reader = stream.getReader(readable);
              const { port1, port2 } = new MessageChannel();
              port1.onmessage = async function({ data: { action } }) {
                if (action === 'read') {
                  try {
                    const result = await reader.read();
                    port1.postMessage(result, util.getTransferables(result));
                  } catch (e) {
                    port1.postMessage({ error: e.message });
                  }
                } else if (action === 'cancel') {
                  await transformed.cancel();
                  port1.postMessage();
                }
              };
              obj[key] = port2;
              collection.push(port2);
            });
          }
          return;
        }
        if (Object.prototype.toString.call(value) === '[object MessagePort]') {
          throw new Error("Can't transfer the same stream twice.");
        }
        util.collectTransferables(value, collection, zero_copy);
      });
    }
  },

  /**
   * Convert MessagePorts back to ReadableStreams
   * @param  {Object} obj
   * @returns {Object}
   */
  restoreStreams: function(obj) {
    if (Object.prototype.isPrototypeOf(obj) && !Uint8Array.prototype.isPrototypeOf(obj)) {
      Object.entries(obj).forEach(([key, value]) => { // recursively search all children
        if (Object.prototype.toString.call(value) === '[object MessagePort]') {
          obj[key] = new ReadableStream({
            pull(controller) {
              return new Promise(resolve => {
                value.onmessage = evt => {
                  const { done, value, error } = evt.data;
                  if (error) {
                    controller.error(new Error(error));
                  } else if (!done) {
                    controller.enqueue(value);
                  } else {
                    controller.close();
                  }
                  resolve();
                };
                value.postMessage({ action: 'read' });
              });
            },
            cancel() {
              return new Promise(resolve => {
                value.onmessage = resolve;
                value.postMessage({ action: 'cancel' });
              });
            }
          }, { highWaterMark: 0 });
          return;
        }
        util.restoreStreams(value);
      });
    }
    return obj;
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
   * Create hex string from a binary
   * @param {String} str String to convert
   * @returns {String} String containing the hexadecimal values
   */
  str_to_hex: function (str) {
    if (str === null) {
      return "";
    }
    const r = [];
    const e = str.length;
    let c = 0;
    let h;
    while (c < e) {
      h = str.charCodeAt(c++).toString(16);
      while (h.length < 2) {
        h = "0" + h;
      }
      r.push("" + h);
    }
    return r.join('');
  },

  /**
   * Create binary string from a hex encoded string
   * @param {String} str Hex string to convert
   * @returns {String}
   */
  hex_to_str: function (hex) {
    let str = '';
    for (let i = 0; i < hex.length; i += 2) {
      str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }
    return str;
  },

  /**
   * Convert a Uint8Array to an MPI-formatted Uint8Array.
   * Note: the output is **not** an MPI object.
   * @see {@link module:type/mpi/MPI.fromUint8Array}
   * @see {@link module:type/mpi/MPI.toUint8Array}
   * @param {Uint8Array} bin An array of 8-bit integers to convert
   * @returns {Uint8Array} MPI-formatted Uint8Array
   */
  Uint8Array_to_MPI: function (bin) {
    const size = (bin.length - 1) * 8 + util.nbits(bin[0]);
    const prefix = Uint8Array.from([(size & 0xFF00) >> 8, size & 0xFF]);
    return util.concatUint8Array([prefix, bin]);
  },

  /**
   * Convert a Base-64 encoded string an array of 8-bit integer
   *
   * Note: accepts both Radix-64 and URL-safe strings
   * @param {String} base64 Base-64 encoded string to convert
   * @returns {Uint8Array} An array of 8-bit integers
   */
  b64_to_Uint8Array: function (base64) {
    return b64.decode(base64.replace(/-/g, '+').replace(/_/g, '/'));
  },

  /**
   * Convert an array of 8-bit integer to a Base-64 encoded string
   * @param {Uint8Array} bytes An array of 8-bit integers to convert
   * @param {bool}       url   If true, output is URL-safe
   * @returns {String}          Base-64 encoded string
   */
  Uint8Array_to_b64: function (bytes, url) {
    let encoded = b64.encode(bytes).replace(/[\r\n]/g, '');
    if (url) {
      encoded = encoded.replace(/[+]/g, '-').replace(/[/]/g, '_').replace(/[=]/g, '');
    }
    return encoded;
  },

  /**
   * Convert a hex string to an array of 8-bit integers
   * @param {String} hex  A hex string to convert
   * @returns {Uint8Array} An array of 8-bit integers
   */
  hex_to_Uint8Array: function (hex) {
    const result = new Uint8Array(hex.length >> 1);
    for (let k = 0; k < hex.length >> 1; k++) {
      result[k] = parseInt(hex.substr(k << 1, 2), 16);
    }
    return result;
  },

  /**
   * Convert an array of 8-bit integers to a hex string
   * @param {Uint8Array} bytes Array of 8-bit integers to convert
   * @returns {String} Hexadecimal representation of the array
   */
  Uint8Array_to_hex: function (bytes) {
    const r = [];
    const e = bytes.length;
    let c = 0;
    let h;
    while (c < e) {
      h = bytes[c++].toString(16);
      while (h.length < 2) {
        h = "0" + h;
      }
      r.push("" + h);
    }
    return r.join('');
  },

  /**
   * Convert a string to an array of 8-bit integers
   * @param {String} str String to convert
   * @returns {Uint8Array} An array of 8-bit integers
   */
  str_to_Uint8Array: function (str) {
    return stream.transform(str, str => {
      if (!util.isString(str)) {
        throw new Error('str_to_Uint8Array: Data must be in the form of a string');
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
   * @param {Uint8Array} bytes An array of 8-bit integers to convert
   * @returns {String} String representation of the array
   */
  Uint8Array_to_str: function (bytes) {
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
   * @param {String|ReadableStream} str The string to convert
   * @returns {Uint8Array|ReadableStream} A valid squence of utf8 bytes
   */
  encode_utf8: function (str) {
    const encoder = new TextEncoder('utf-8');
    // eslint-disable-next-line no-inner-declarations
    function process(value, lastChunk = false) {
      return encoder.encode(value, { stream: !lastChunk });
    }
    return stream.transform(str, process, () => process('', true));
  },

  /**
   * Convert a Uint8Array of utf8 bytes to a native javascript string
   * @param {Uint8Array|ReadableStream} utf8 A valid squence of utf8 bytes
   * @returns {String|ReadableStream} A native javascript string
   */
  decode_utf8: function (utf8) {
    const decoder = new TextDecoder('utf-8');
    // eslint-disable-next-line no-inner-declarations
    function process(value, lastChunk = false) {
      return decoder.decode(value, { stream: !lastChunk });
    }
    return stream.transform(utf8, process, () => process(new Uint8Array(), true));
  },

  /**
   * Concat a list of Uint8Arrays, Strings or Streams
   * The caller must not mix Uint8Arrays with Strings, but may mix Streams with non-Streams.
   * @param {Array<Uint8Array|String|ReadableStream>} Array of Uint8Arrays/Strings/Streams to concatenate
   * @returns {Uint8Array|String|ReadableStream} Concatenated array
   */
  concat: stream.concat,

  /**
   * Concat Uint8Arrays
   * @param {Array<Uint8Array>} Array of Uint8Arrays to concatenate
   * @returns {Uint8Array} Concatenated array
   */
  concatUint8Array: stream.concatUint8Array,

  /**
   * Check Uint8Array equality
   * @param {Uint8Array} first array
   * @param {Uint8Array} second array
   * @returns {Boolean} equality
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
   * Calculates a 16bit sum of a Uint8Array by adding each character
   * codes modulus 65535
   * @param {Uint8Array} Uint8Array to create a sum of
   * @returns {Uint8Array} 2 bytes containing the sum of all charcodes % 65535
   */
  write_checksum: function (text) {
    let s = 0;
    for (let i = 0; i < text.length; i++) {
      s = (s + text[i]) & 0xFFFF;
    }
    return util.writeNumber(s, 2);
  },

  /**
   * Helper function to print a debug message. Debug
   * messages are only printed if
   * @link module:config/config.debug is set to true.
   * @param {String} str String of the debug message
   */
  print_debug: function (str) {
    if (config.debug) {
      console.log(str);
    }
  },

  /**
   * Helper function to print a debug message. Debug
   * messages are only printed if
   * @link module:config/config.debug is set to true.
   * Different than print_debug because will call Uint8Array_to_hex iff necessary.
   * @param {String} str String of the debug message
   */
  print_debug_hexarray_dump: function (str, arrToHex) {
    if (config.debug) {
      str += ': ' + util.Uint8Array_to_hex(arrToHex);
      console.log(str);
    }
  },

  /**
   * Helper function to print a debug message. Debug
   * messages are only printed if
   * @link module:config/config.debug is set to true.
   * Different than print_debug because will call str_to_hex iff necessary.
   * @param {String} str String of the debug message
   */
  print_debug_hexstr_dump: function (str, strToHex) {
    if (config.debug) {
      str += util.str_to_hex(strToHex);
      console.log(str);
    }
  },

  /**
   * Helper function to print a debug error. Debug
   * messages are only printed if
   * @link module:config/config.debug is set to true.
   * @param {String} str String of the debug message
   */
  print_debug_error: function (error) {
    if (config.debug) {
      console.error(error);
    }
  },

  /**
   * Read a stream to the end and print it to the console when it's closed.
   * @param {String} str String of the debug message
   * @param {ReadableStream|Uint8array|String} input Stream to print
   * @param {Function} concat Function to concatenate chunks of the stream (defaults to util.concat).
   */
  print_entire_stream: function (str, input, concat) {
    stream.readToEnd(stream.clone(input), concat).then(result => {
      console.log(str + ': ', result);
    });
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
    const double_var = new Uint8Array(data.length);
    const last = data.length - 1;
    for (let i = 0; i < last; i++) {
      double_var[i] = (data[i] << 1) ^ (data[i + 1] >> 7);
    }
    double_var[last] = (data[last] << 1) ^ ((data[0] >> 7) * 0x87);
    return double_var;
  },

  /**
   * Shift a Uint8Array to the right by n bits
   * @param {Uint8Array} array The array to shift
   * @param {Integer} bits Amount of bits to shift (MUST be smaller
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
   * Get native Web Cryptography api, only the current version of the spec.
   * The default configuration is to use the api when available. But it can
   * be deactivated with config.use_native
   * @returns {Object}   The SubtleCrypto api or 'undefined'
   */
  getWebCrypto: function() {
    if (!config.use_native) {
      return;
    }

    return typeof global !== 'undefined' && global.crypto && global.crypto.subtle;
  },

  /**
   * Get native Web Cryptography api for all browsers, including legacy
   * implementations of the spec e.g IE11 and Safari 8/9. The default
   * configuration is to use the api when available. But it can be deactivated
   * with config.use_native
   * @returns {Object}   The SubtleCrypto api or 'undefined'
   */
  getWebCryptoAll: function() {
    if (!config.use_native) {
      return;
    }

    if (typeof global !== 'undefined') {
      if (global.crypto) {
        return global.crypto.subtle || global.crypto.webkitSubtle;
      }
      if (global.msCrypto) {
        return global.msCrypto.subtle;
      }
    }
  },

  /**
   * Detect Node.js runtime.
   */
  detectNode: function() {
    return typeof global.process === 'object' &&
      typeof global.process.versions === 'object';
  },

  /**
   * Get native Node.js module
   * @param {String}     The module to require
   * @returns {Object}   The required module or 'undefined'
   */
  nodeRequire: function(module) {
    if (!util.detectNode()) {
      return;
    }

    // Requiring the module dynamically allows us to access the native node module.
    // otherwise, it gets replaced with the browserified version
    // eslint-disable-next-line import/no-dynamic-require
    return require(module);
  },

  /**
   * Get native Node.js crypto api. The default configuration is to use
   * the api when available. But it can also be deactivated with config.use_native
   * @returns {Object}   The crypto module or 'undefined'
   */
  getNodeCrypto: function() {
    if (!config.use_native) {
      return;
    }

    return util.nodeRequire('crypto');
  },

  getNodeZlib: function() {
    if (!config.use_native) {
      return;
    }

    return util.nodeRequire('zlib');
  },

  /**
   * Get native Node.js Buffer constructor. This should be used since
   * Buffer is not available under browserify.
   * @returns {Function}   The Buffer constructor or 'undefined'
   */
  getNodeBuffer: function() {
    return (util.nodeRequire('buffer') || {}).Buffer;
  },

  getNodeStream: function() {
    return (util.nodeRequire('stream') || {}).Readable;
  },

  getHardwareConcurrency: function() {
    if (util.detectNode()) {
      const os = util.nodeRequire('os');
      return os.cpus().length;
    }

    return navigator.hardwareConcurrency || 1;
  },

  isEmailAddress: function(data) {
    if (!util.isString(data)) {
      return false;
    }
    const re = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+([a-zA-Z]{2,}|xn--[a-zA-Z\-0-9]+)))$/;
    return re.test(data);
  },

  /**
   * Format user id for internal use.
   */
  formatUserId: function(id) {
    // name, email address and comment can be empty but must be of the correct type
    if ((id.name && !util.isString(id.name)) ||
        (id.email && !util.isEmailAddress(id.email)) ||
        (id.comment && !util.isString(id.comment))) {
      throw new Error('Invalid user id format');
    }
    const components = [];
    if (id.name) {
      components.push(id.name);
    }
    if (id.comment) {
      components.push(`(${id.comment})`);
    }
    if (id.email) {
      components.push(`<${id.email}>`);
    }
    return components.join(' ');
  },

  /**
   * Parse user id.
   */
  parseUserId: function(userid) {
    if (userid.length > config.max_userid_length) {
      throw new Error('User id string is too long');
    }
    try {
      const { name, address: email, comments } = emailAddresses.parseOneAddress({ input: userid, atInDisplayName: true });
      return { name, email, comment: comments.replace(/^\(|\)$/g, '') };
    } catch (e) {
      throw new Error('Invalid user id format');
    }
  },

  /**
   * Normalize line endings to <CR><LF>
   * Support any encoding where CR=0x0D, LF=0x0A
   */
  canonicalizeEOL: function(data) {
    const CR = 13;
    const LF = 10;
    let carryOverCR = false;

    return stream.transform(data, bytes => {
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

    return stream.transform(data, bytes => {
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
   * Remove trailing spaces and tabs from each line
   */
  removeTrailingSpaces: function(text) {
    return text.split('\n').map(line => {
      let i = line.length - 1;
      for (; i >= 0 && (line[i] === ' ' || line[i] === '\t'); i--);
      return line.substr(0, i + 1);
    }).join('\n');
  },

  /**
   * Encode input buffer using Z-Base32 encoding.
   * See: https://tools.ietf.org/html/rfc6189#section-5.1.6
   *
   * @param {Uint8Array} data The binary data to encode
   * @returns {String} Binary data encoded using Z-Base32
   */
  encodeZBase32: function(data) {
    if (data.length === 0) {
      return "";
    }
    const ALPHABET = "ybndrfg8ejkmcpqxot1uwisza345h769";
    const SHIFT = 5;
    const MASK = 31;
    let buffer = data[0];
    let index = 1;
    let bitsLeft = 8;
    let result = '';
    while (bitsLeft > 0 || index < data.length) {
      if (bitsLeft < SHIFT) {
        if (index < data.length) {
          buffer <<= 8;
          buffer |= data[index++] & 0xff;
          bitsLeft += 8;
        } else {
          const pad = SHIFT - bitsLeft;
          buffer <<= pad;
          bitsLeft += pad;
        }
      }
      bitsLeft -= SHIFT;
      result += ALPHABET[MASK & (buffer >> bitsLeft)];
    }
    return result;
  },

  wrapError: function(message, error) {
    if (!error) {
      return new Error(message);
    }

    // update error message
    try {
      error.message = message + ': ' + error.message;
    } catch (e) {}

    return error;
  }
};
