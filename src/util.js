// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
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
 * @module util
 */

var config = require('./config');

module.exports = {
  readNumber: function (bytes) {
    var n = 0;

    for (var i = 0; i < bytes.length; i++) {
      n <<= 8;
      n += bytes.charCodeAt(i);
    }

    return n;
  },

  writeNumber: function (n, bytes) {
    var b = '';
    for (var i = 0; i < bytes; i++) {
      b += String.fromCharCode((n >> (8 * (bytes - i - 1))) & 0xFF);
    }

    return b;
  },

  readDate: function (bytes) {
    var n = this.readNumber(bytes);
    var d = new Date();
    d.setTime(n * 1000);
    return d;
  },

  writeDate: function (time) {
    var numeric = Math.round(time.getTime() / 1000);

    return this.writeNumber(numeric, 4);
  },

  emailRegEx: /^[+a-zA-Z0-9_.-]+@([a-zA-Z0-9-]+\.)+[a-zA-Z0-9]{2,6}$/,

  hexdump: function (str) {
    var r = [];
    var e = str.length;
    var c = 0;
    var h;
    var i = 0;
    while (c < e) {
      h = str.charCodeAt(c++).toString(16);
      while (h.length < 2) h = "0" + h;
      r.push(" " + h);
      i++;
      if (i % 32 === 0)
        r.push("\n           ");
    }
    return r.join('');
  },

  /**
   * Create hexstring from a binary
   * @param {String} str String to convert
   * @return {String} String containing the hexadecimal values
   */
  hexstrdump: function (str) {
    if (str === null)
      return "";
    var r = [];
    var e = str.length;
    var c = 0;
    var h;
    while (c < e) {
      h = str.charCodeAt(c++).toString(16);
      while (h.length < 2) h = "0" + h;
      r.push("" + h);
    }
    return r.join('');
  },

  /**
   * Create binary string from a hex encoded string
   * @param {String} str Hex string to convert
   * @return {String} String containing the binary values
   */
  hex2bin: function (hex) {
    var str = '';
    for (var i = 0; i < hex.length; i += 2)
      str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    return str;
  },

  /**
   * Creating a hex string from an binary array of integers (0..255)
   * @param {String} str Array of bytes to convert
   * @return {String} Hexadecimal representation of the array
   */
  hexidump: function (str) {
    var r = [];
    var e = str.length;
    var c = 0;
    var h;
    while (c < e) {
      h = str[c++].toString(16);
      while (h.length < 2) h = "0" + h;
      r.push("" + h);
    }
    return r.join('');
  },


  /**
   * Convert a native javascript string to a string of utf8 bytes
   * @param {String} str The string to convert
   * @return {String} A valid squence of utf8 bytes
   */
  encode_utf8: function (str) {
    return unescape(encodeURIComponent(str));
  },

  /**
   * Convert a string of utf8 bytes to a native javascript string
   * @param {String} utf8 A valid squence of utf8 bytes
   * @return {String} A native javascript string
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
   * Convert an array of integers(0.255) to a string
   * @param {Array<Integer>} bin An array of (binary) integers to convert
   * @return {String} The string representation of the array
   */
  bin2str: function (bin) {
    var result = [];
    for (var i = 0; i < bin.length; i++) {
      result[i] = String.fromCharCode(bin[i]);
    }
    return result.join('');
  },

  /**
   * Convert a string to an array of integers(0.255)
   * @param {String} str String to convert
   * @return {Array<Integer>} An array of (binary) integers
   */
  str2bin: function (str) {
    var result = [];
    for (var i = 0; i < str.length; i++) {
      result[i] = str.charCodeAt(i);
    }
    return result;
  },


  /**
   * Convert a string to a Uint8Array
   * @param {String} str String to convert
   * @return {Uint8Array} The array of (binary) integers
   */
  str2Uint8Array: function (str) {
    var result = new Uint8Array(str.length);
    for (var i = 0; i < str.length; i++) {
      result[i] = str.charCodeAt(i);
    }
    return result;
  },

  /**
   * Convert a Uint8Array to a string. This currently functions 
   * the same as bin2str.
   * @function module:util.Uint8Array2str
   * @param {Uint8Array} bin An array of (binary) integers to convert
   * @return {String} String representation of the array
   */
  Uint8Array2str: function (bin) {
    var result = '';
    for (var i = 0; i < bin.length; i++) {
      result += String.fromCharCode(bin[i]);
    }
    return result;
  },

  /**
   * Calculates a 16bit sum of a string by adding each character
   * codes modulus 65535
   * @param {String} text String to create a sum of
   * @return {Integer} An integer containing the sum of all character
   * codes % 65535
   */
  calc_checksum: function (text) {
    var checksum = {
      s: 0,
      add: function (sadd) {
        this.s = (this.s + sadd) % 65536;
      }
    };
    for (var i = 0; i < text.length; i++) {
      checksum.add(text.charCodeAt(i));
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
   * Different than print_debug because will call hexstrdump iff necessary.
   * @param {String} str String of the debug message
   */
  print_debug_hexstr_dump: function (str, strToHex) {
    if (config.debug) {
      str = str + this.hexstrdump(strToHex);
      console.log(str);
    }
  },

  getLeftNBits: function (string, bitcount) {
    var rest = bitcount % 8;
    if (rest === 0)
      return string.substring(0, bitcount / 8);
    var bytes = (bitcount - rest) / 8 + 1;
    var result = string.substring(0, bytes);
    return this.shiftRight(result, 8 - rest); // +String.fromCharCode(string.charCodeAt(bytes -1) << (8-rest) & 0xFF);
  },

  /**
   * Shifting a string to n bits right
   * @param {String} value The string to shift
   * @param {Integer} bitcount Amount of bits to shift (MUST be smaller 
   * than 9)
   * @return {String} Resulting string. 
   */
  shiftRight: function (value, bitcount) {
    var temp = util.str2bin(value);
    if (bitcount % 8 !== 0) {
      for (var i = temp.length - 1; i >= 0; i--) {
        temp[i] >>= bitcount % 8;
        if (i > 0)
          temp[i] |= (temp[i - 1] << (8 - (bitcount % 8))) & 0xFF;
      }
    } else {
      return value;
    }
    return util.bin2str(temp);
  },

  /**
   * Return the algorithm type as string
   * @return {String} String representing the message type
   */
  get_hashAlgorithmString: function (algo) {
    switch (algo) {
      case 1:
        return "MD5";
      case 2:
        return "SHA1";
      case 3:
        return "RIPEMD160";
      case 8:
        return "SHA256";
      case 9:
        return "SHA384";
      case 10:
        return "SHA512";
      case 11:
        return "SHA224";
    }
    return "unknown";
  }
};
