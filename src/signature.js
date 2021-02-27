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

import { armor, unarmor } from './encoding/armor';
import { PacketList, SignaturePacket } from './packet';
import enums from './enums';
import defaultConfig from './config';

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
   * @param  {Object} config (optional) full configuration, defaults to openpgp.config
   * @returns {ReadableStream<String>} ASCII armor
   */
  armor(config = defaultConfig) {
    return armor(enums.armor.signature, this.write(), undefined, undefined, undefined, config);
  }
}

/**
 * reads an (optionally armored) OpenPGP signature and returns a signature object
 * @param {String | ReadableStream<String>} armoredSignature armored signature to be parsed
 * @param {Uint8Array | ReadableStream<Uint8Array>} binarySignature binary signature to be parsed
 * @param {Object} config (optional) custom configuration settings to overwrite those in [config]{@link module:config}
 * @returns {Signature} new signature object
 * @async
 * @static
 */
export async function readSignature({ armoredSignature, binarySignature, config }) {
  config = { ...defaultConfig, ...config };
  let input = armoredSignature || binarySignature;
  if (!input) {
    throw new Error('readSignature: must pass options object containing `armoredSignature` or `binarySignature`');
  }
  if (armoredSignature) {
    const { type, data } = await unarmor(input, config);
    if (type !== enums.armor.signature) {
      throw new Error('Armored text not of type signature');
    }
    input = data;
  }
  const packetlist = new PacketList();
  await packetlist.read(input, { SignaturePacket }, undefined, config);
  return new Signature(packetlist);
}
