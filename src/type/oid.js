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
 * Wrapper to an OID value
 *
 * {@link https://tools.ietf.org/html/rfc6637#section-11|RFC6637, section 11}:
 * The sequence of octets in the third column is the result of applying
 * the Distinguished Encoding Rules (DER) to the ASN.1 Object Identifier
 * with subsequent truncation.  The truncation removes the two fields of
 * encoded Object Identifier.  The first omitted field is one octet
 * representing the Object Identifier tag, and the second omitted field
 * is the length of the Object Identifier body.  For example, the
 * complete ASN.1 DER encoding for the NIST P-256 curve OID is "06 08 2A
 * 86 48 CE 3D 03 01 07", from which the first entry in the table above
 * is constructed by omitting the first two octets.  Only the truncated
 * sequence of octets is the valid representation of a curve OID.
 * @module type/oid
 */

import util from '../util';
import enums from '../enums';

const knownOIDs = {
  '2a8648ce3d030107': enums.curve.nistP256,
  '2b81040022': enums.curve.nistP384,
  '2b81040023': enums.curve.nistP521,
  '2b8104000a': enums.curve.secp256k1,
  '2b06010401da470f01': enums.curve.ed25519Legacy,
  '2b060104019755010501': enums.curve.curve25519Legacy,
  '2b2403030208010107': enums.curve.brainpoolP256r1,
  '2b240303020801010b': enums.curve.brainpoolP384r1,
  '2b240303020801010d': enums.curve.brainpoolP512r1
};

class OID {
  constructor(oid) {
    if (oid instanceof OID) {
      this.oid = oid.oid;
    } else if (util.isArray(oid) ||
               util.isUint8Array(oid)) {
      oid = new Uint8Array(oid);
      if (oid[0] === 0x06) { // DER encoded oid byte array
        if (oid[1] !== oid.length - 2) {
          throw new Error('Length mismatch in DER encoded oid');
        }
        oid = oid.subarray(2);
      }
      this.oid = oid;
    } else {
      this.oid = '';
    }
  }

  /**
   * Method to read an OID object
   * @param {Uint8Array} input - Where to read the OID from
   * @returns {Number} Number of read bytes.
   */
  read(input) {
    if (input.length >= 1) {
      const length = input[0];
      if (input.length >= 1 + length) {
        this.oid = input.subarray(1, 1 + length);
        return 1 + this.oid.length;
      }
    }
    throw new Error('Invalid oid');
  }

  /**
   * Serialize an OID object
   * @returns {Uint8Array} Array with the serialized value the OID.
   */
  write() {
    return util.concatUint8Array([new Uint8Array([this.oid.length]), this.oid]);
  }

  /**
   * Serialize an OID object as a hex string
   * @returns {string} String with the hex value of the OID.
   */
  toHex() {
    return util.uint8ArrayToHex(this.oid);
  }

  /**
   * If a known curve object identifier, return the canonical name of the curve
   * @returns {enums.curve} String with the canonical name of the curve
   * @throws if unknown
   */
  getName() {
    const name = knownOIDs[this.toHex()];
    if (!name) {
      throw new Error('Unknown curve object identifier.');
    }

    return name;
  }
}

export default OID;
