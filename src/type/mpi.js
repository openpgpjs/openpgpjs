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

// Hint: We hold our MPIs as an array of octets in big endian format preceding a two
// octet scalar: MPI: [a,b,c,d,e,f]
// - MPI size: (a << 8) | b
// - MPI = c | d << 8 | e << ((MPI.length -2)*8) | f ((MPI.length -2)*8)

/**
 * Implementation of type MPI ({@link https://tools.ietf.org/html/rfc4880#section-3.2|RFC4880 3.2})
 * Multiprecision integers (also called MPIs) are unsigned integers used
 * to hold large integers such as the ones used in cryptographic
 * calculations.
 * An MPI consists of two pieces: a two-octet scalar that is the length
 * of the MPI in bits followed by a string of octets that contain the
 * actual integer.
 * @requires bn.js
 * @requires util
 * @module type/mpi
 */

import BN from 'bn.js';
import util from '../util';

/**
 * @constructor
 */
function MPI(data) {
  /** An implementation dependent integer */
  if (data instanceof MPI) {
    this.data = data.data;
  } else if (BN.isBN(data)) {
    this.fromBN(data);
  } else if (util.isUint8Array(data)) {
    this.fromUint8Array(data);
  } else if (util.isString(data)) {
    this.fromString(data);
  } else {
    this.data = null;
  }
}

/**
 * Parsing function for a MPI ({@link https://tools.ietf.org/html/rfc4880#section-3.2|RFC 4880 3.2}).
 * @param {Uint8Array} input  Payload of MPI data
 * @param {String}     endian Endianness of the data; 'be' for big-endian or 'le' for little-endian
 * @returns {Integer}          Length of data read
 */
MPI.prototype.read = function (bytes, endian = 'be') {
  if (util.isString(bytes)) {
    bytes = util.str_to_Uint8Array(bytes);
  }

  const bits = (bytes[0] << 8) | bytes[1];
  const bytelen = (bits + 7) >>> 3;
  const payload = bytes.subarray(2, 2 + bytelen);

  this.fromUint8Array(payload, endian);

  return 2 + bytelen;
};

/**
 * Converts the mpi object to a bytes as specified in
 * {@link https://tools.ietf.org/html/rfc4880#section-3.2|RFC4880 3.2}
 * @param {String} endian Endianness of the payload; 'be' for big-endian or 'le' for little-endian
 * @param {Integer} length Length of the data part of the MPI
 * @returns {Uint8Aray} mpi Byte representation
 */
MPI.prototype.write = function (endian, length) {
  return util.Uint8Array_to_MPI(this.toUint8Array(endian, length));
};

MPI.prototype.bitLength = function () {
  return (this.data.length - 1) * 8 + util.nbits(this.data[0]);
};

MPI.prototype.byteLength = function () {
  return this.data.length;
};

MPI.prototype.toUint8Array = function (endian, length) {
  endian = endian || 'be';
  length = length || this.data.length;

  const payload = new Uint8Array(length);
  const start = endian === 'le' ? 0 : length - this.data.length;
  payload.set(this.data, start);
  if (endian === 'le') {
    payload.reverse();
  }
  return payload;
};

MPI.prototype.fromUint8Array = function (bytes, endian = 'be') {
  this.data = new Uint8Array(bytes.length);
  this.data.set(bytes);

  if (endian === 'le') {
    this.data.reverse();
  }
};

MPI.prototype.toString = function () {
  return util.Uint8Array_to_str(this.toUint8Array());
};

MPI.prototype.fromString = function (str, endian = 'be') {
  this.fromUint8Array(util.str_to_Uint8Array(str), endian);
};

MPI.prototype.toBN = function () {
  return new BN(this.toUint8Array());
};

MPI.prototype.fromBN = function (bn) {
  this.data = bn.toArrayLike(Uint8Array);
};

MPI.fromClone = function (clone) {
  return new MPI(clone.data);
};

export default MPI;
