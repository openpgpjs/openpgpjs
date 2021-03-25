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
 * Wrapper for enums
 *
 * @requires enums
 * @module type/enum.js
 */


import enums from "../enums";

const type_enum = e => class EnumType {
  constructor(data) {
    if (typeof data === 'undefined') {
      this.data = null;
    } else {
      this.data = enums.write(e, data);
    }
  }

  /**
   * Read an enum entry
   * @param  {Uint8Array}  input  Where to read the symmetric algo from
   */
  read(input) {
    const data = input[0];
    this.data = enums.write(e, data);
    return 1;
  }

  /**
   * Write an enum as an integer
   * @returns  {Uint8Array}  An integer representing the algorithm
   */
  write() {
    return new Uint8Array([this.data]);
  }

  /**
   * Get the name of the enum entry
   * @returns  {string}  The name string
   */
  getName() {
    return enums.read(e, this.data);
  }
};
const AEADEnum = type_enum(enums.aead);
const SymAlgoEnum = type_enum(enums.symmetric);
const HashEnum = type_enum(enums.hash);


export { SymAlgoEnum, AEADEnum, HashEnum };

export default type_enum;
