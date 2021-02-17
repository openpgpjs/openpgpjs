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
 * @requires encoding/armor
 * @requires packet
 * @requires enums
 * @module signature
 */

import { armor, unarmor } from './encoding/armor';
import { PacketList, SignaturePacket } from './packet';
import enums from './enums';

/**
 * Class that represents an OpenPGP signature.
 */
export class Signature {
  /**
   * @param  {PacketList} packetlist The signature packets
   */
  constructor(packetlist) {
    this.packets = packetlist || new PacketList();
  }

  /**
   * Returns binary encoded signature
   * @returns {ReadableStream<Uint8Array>} binary signature
   */
  write() {
    return this.packets.write();
  }

  /**
   * Returns ASCII armored text of signature
   * @returns {ReadableStream<String>} ASCII armor
   */
  armor() {
    return armor(enums.armor.signature, this.write());
  }
}

/**
 * reads an (optionally armored) OpenPGP signature and returns a signature object
 * @param {String | ReadableStream<String>} armoredSignature armored signature to be parsed
 * @param {Uint8Array | ReadableStream<Uint8Array>} binarySignature binary signature to be parsed
 * @returns {Signature} new signature object
 * @async
 * @static
 */
export async function readSignature({ armoredSignature, binarySignature }) {
  let input = armoredSignature || binarySignature;
  if (!input) {
    throw new Error('readSignature: must pass options object containing `armoredSignature` or `binarySignature`');
  }
  if (armoredSignature) {
    const { type, data } = await unarmor(input);
    if (type !== enums.armor.signature) {
      throw new Error('Armored text not of type signature');
    }
    input = data;
  }
  const packetlist = new PacketList();
  await packetlist.read(input, { SignaturePacket });
  return new Signature(packetlist);
}
