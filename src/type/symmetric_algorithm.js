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
 * Symmetric algorithms
 *
 * @requires enums
 * @module type/symmetric_algo.js
 */


import enums from "../enums";

class SymmetricAlgorithm {
  constructor(data) {
    if (typeof data === 'undefined') {
      this.data = null;
    } else {
      this.data = enums.write(enums.symmetric, data);
    }
  }

  /**
   * Read a SymmetricKey from a string
   * @param  {string|Number}  input  Where to read the symmetric algo from
   */
  read(input) {
    const data = input[0];
    this.data = enums.write(enums.symmetric, data);
    return 1;
  }

  /**
   * Write a Symmetric Algorithm as an integer
   * @returns  {Uint8Array}  An integer representing the algorithm
   */
  write() {
    return new Uint8Array([this.data]);
  }

  /**
   * Get the name of the symmetric algorithm
   * @returns  {string}  The name of the algorithm
   */
  getName() {
    return enums.read(enums.symmetric, this.data);
  }
}

export default SymmetricAlgorithm;
