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

/**
 * This object contains utility functions
 * @requires config
 * @requires encoding/base64
 * @module util
 */

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

  isUint8Array: function(data) {
    return Uint8Array.prototype.isPrototypeOf(data);
  },

  /**
   * Get transferable objects to pass buffers with zero copy (similar to "pass by reference" in C++)
   *   See: https://developer.mozilla.org/en-US/docs/Web/API/Worker/postMessage
   * @param  {Object} obj           the options object to be passed to the web worker
   * @returns {Array<ArrayBuffer>}   an array of binary data to be passed
   */
  getTransferables: function(obj) {
    if (config.zero_copy && Object.prototype.isPrototypeOf(obj)) {
      const transferables = [];
      util.collectBuffers(obj, transferables);
      return transferables.length ? transferables : undefined;
    }
  },

  collectBuffers: function(obj, collection) {
    if (!obj) {
      return;
    }
    if (util.isUint8Array(obj) && collection.indexOf(obj.buffer) === -1) {
      collection.push(obj.buffer);
      return;
    }
    if (Object.prototype.isPrototypeOf(obj)) {
      for (const key in obj) { // recursively search all children
        util.collectBuffers(obj[key], collection);
      }
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
      return time === null ? time : new Date(Math.floor(+time / 1000) * 1000);
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
//    atob(base64.replace(/\-/g, '+').replace(/_/g, '/'));
    return b64.decode(base64.replace(/\-/g, '+').replace(/_/g, '/'));
  },

  /**
   * Convert an array of 8-bit integer to a Base-64 encoded string
   * @param {Uint8Array} bytes An array of 8-bit integers to convert
   * @param {bool}       url   If true, output is URL-safe
   * @returns {String}          Base-64 encoded string
   */
  Uint8Array_to_b64: function (bytes, url) {
//    btoa(util.Uint8Array_to_str(bytes)).replace(/\+/g, '-').replace(/\//g, '_');
    return b64.encode(bytes, url).replace('\n', '');
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
    if (!util.isString(str)) {
      throw new Error('str_to_Uint8Array: Data must be in the form of a string');
    }

    const result = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
      result[i] = str.charCodeAt(i);
    }
    return result;
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
      result.push(String.fromCharCode.apply(String, bytes.subarray(i, i+bs < j ? i+bs : j)));
    }
    return result.join('');
  },

  /**
   * Convert a native javascript string to a string of utf8 bytes
   * @param {String} str The string to convert
   * @returns {String} A valid squence of utf8 bytes
   */
  encode_utf8: function (str) {
    return unescape(encodeURIComponent(str));
  },

  /**
   * Convert a string of utf8 bytes to a native javascript string
   * @param {String} utf8 A valid squence of utf8 bytes
   * @returns {String} A native javascript string
   */
  decode_utf8: function (utf8) {
    if (typeof utf8 !== 'string') {
      throw new Error('Parameter "utf8" is not of type string');
    }
    try {
      return decodeURIComponent(escape(utf8));
    } catch (e) {
      return utf8;
    }
  },

  /**
   * Concat Uint8arrays
   * @param {Array<Uint8array>} Array of Uint8Arrays to concatenate
   * @returns {Uint8array} Concatenated array
   */
  concatUint8Array: function (arrays) {
    let totalLength = 0;
    for (let i = 0; i < arrays.length; i++) {
      if (!util.isUint8Array(arrays[i])) {
        throw new Error('concatUint8Array: Data must be in the form of a Uint8Array');
      }

      totalLength += arrays[i].length;
    }

    const result = new Uint8Array(totalLength);
    let pos = 0;
    arrays.forEach(function (element) {
      result.set(element, pos);
      pos += element.length;
    });

    return result;
  },

  /**
   * Deep copy Uint8Array
   * @param {Uint8Array} Array to copy
   * @returns {Uint8Array} new Uint8Array
   */
  copyUint8Array: function (array) {
    if (!util.isUint8Array(array)) {
      throw new Error('Data must be in the form of a Uint8Array');
    }

    const copy = new Uint8Array(array.length);
    copy.set(array);
    return copy;
  },

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
   * @returns {Integer} An integer containing the sum of all character
   * codes % 65535
   */
  calc_checksum: function (text) {
    const checksum = {
      s: 0,
      add: function (sadd) {
        this.s = (this.s + sadd) % 65536;
      }
    };
    for (let i = 0; i < text.length; i++) {
      checksum.add(text[i]);
    }
    return checksum.s;
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
   * Different than print_debug because will call str_to_hex iff necessary.
   * @param {String} str String of the debug message
   */
  print_debug_hexstr_dump: function (str, strToHex) {
    if (config.debug) {
      str += util.str_to_hex(strToHex);
      console.log(str);
    }
  },

  // TODO rewrite getLeftNBits to work with Uint8Arrays
  getLeftNBits: function (string, bitcount) {
    const rest = bitcount % 8;
    if (rest === 0) {
      return string.substring(0, bitcount / 8);
    }
    const bytes = (bitcount - rest) / 8 + 1;
    const result = string.substring(0, bytes);
    return util.shiftRight(result, 8 - rest); // +String.fromCharCode(string.charCodeAt(bytes -1) << (8-rest) & 0xFF);
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
   * Shifting a string to n bits right
   * @param {String} value The string to shift
   * @param {Integer} bitcount Amount of bits to shift (MUST be smaller
   * than 9)
   * @returns {String} Resulting string.
   */
  shiftRight: function (value, bitcount) {
    const temp = util.str_to_Uint8Array(value);
    if (bitcount % 8 !== 0) {
      for (let i = temp.length - 1; i >= 0; i--) {
        temp[i] >>= bitcount % 8;
        if (i > 0) {
          temp[i] |= (temp[i - 1] << (8 - (bitcount % 8))) & 0xFF;
        }
      }
    } else {
      return value;
    }
    return util.Uint8Array_to_str(temp);
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

    return typeof window !== 'undefined' && window.crypto && window.crypto.subtle;
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

    if (typeof window !== 'undefined') {
      if (window.crypto) {
        return window.crypto.subtle || window.crypto.webkitSubtle;
      }
      if (window.msCrypto) {
        return window.msCrypto.subtle;
      }
    }
  },

  /**
   * Detect Node.js runtime.
   */
  detectNode: function() {
    return typeof window === 'undefined';
  },

  /**
   * Get native Node.js crypto api. The default configuration is to use
   * the api when available. But it can also be deactivated with config.use_native
   * @returns {Object}   The crypto module or 'undefined'
   */
  getNodeCrypto: function() {
    if (!util.detectNode() || !config.use_native) {
      return;
    }

    return require('crypto');
  },

  /**
   * Get native Node.js Buffer constructor. This should be used since
   * Buffer is not available under browserify.
   * @returns {Function}   The Buffer constructor or 'undefined'
   */
  getNodeBuffer: function() {
    if (!util.detectNode()) {
      return;
    }

    // This "hack" allows us to access the native node buffer module.
    // otherwise, it gets replaced with the browserified version
    // eslint-disable-next-line no-useless-concat, import/no-dynamic-require
    return require('buf'+'fer').Buffer;
  },

  getNodeZlib: function() {
    if (!util.detectNode() || !config.use_native) {
      return;
    }

    return require('zlib');
  },

  isEmailAddress: function(data) {
    if (!util.isString(data)) {
      return false;
    }
    const re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+([a-zA-Z]{2,}|xn--[a-zA-Z\-0-9]+)))$/;
    return re.test(data);
  },

  isUserId: function(data) {
    if (!util.isString(data)) {
      return false;
    }
    return /</.test(data) && />$/.test(data);
  }
};
