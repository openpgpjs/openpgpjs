// OpenPGP.js - An OpenPGP implementation in javascript
// Copyright (C) 2015-2016 Decentral
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
 * Implementation of type KDF parameters
 *
 * {@link https://tools.ietf.org/html/rfc6637#section-7|RFC 6637 7}:
 * A key derivation function (KDF) is necessary to implement the EC
 * encryption.  The Concatenation Key Derivation Function (Approved
 * Alternative 1) [NIST-SP800-56A] with the KDF hash function that is
 * SHA2-256 [FIPS-180-3] or stronger is REQUIRED.
 * @requires enums
 * @module type/kdf_params
 */

/**
 * @constructor
 * @param  {enums.hash}       hash    Hash algorithm
 * @param  {enums.symmetric}  cipher  Symmetric algorithm
 */
function KDFParams(data) {
  if (data) {
    const { hash, cipher } = data;
    this.hash = hash;
    this.cipher = cipher;
  } else {
    this.hash = null;
    this.cipher = null;
  }
}

/**
 * Read KDFParams from an Uint8Array
 * @param  {Uint8Array}  input  Where to read the KDFParams from
 * @returns {Number}             Number of read bytes
 */
KDFParams.prototype.read = function (input) {
  if (input.length < 4 || input[0] !== 3 || input[1] !== 1) {
    throw new Error('Cannot read KDFParams');
  }
  this.hash = input[2];
  this.cipher = input[3];
  return 4;
};

/**
 * Write KDFParams to an Uint8Array
 * @returns  {Uint8Array}  Array with the KDFParams value
 */
KDFParams.prototype.write = function () {
  return new Uint8Array([3, 1, this.hash, this.cipher]);
};

KDFParams.fromClone = function (clone) {
  const { hash, cipher } = clone;
  return new KDFParams({ hash, cipher });
};

export default KDFParams;
