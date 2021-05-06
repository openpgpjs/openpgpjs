/* eslint-disable class-methods-use-this */
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

import { armor } from '../encoding/armor';
import defaultConfig from '../config';
import enums from '../enums';
import Key from './key';

/**
 * Class that represents an OpenPGP key. Must contain a primary key.
 * Can contain additional subkeys, signatures, user ids, user attributes.
 * @borrows PublicKeyPacket#getKeyID as Key#getKeyID
 * @borrows PublicKeyPacket#getFingerprint as Key#getFingerprint
 * @borrows PublicKeyPacket#hasSameFingerprintAs as Key#hasSameFingerprintAs
 * @borrows PublicKeyPacket#getAlgorithmInfo as Key#getAlgorithmInfo
 * @borrows PublicKeyPacket#getCreationTime as Key#getCreationTime
 */
class PublicKey extends Key {
  /**
   * @param {PacketList} packetlist - The packets that form this key
   */
  constructor(packetlist) {
    super();
    if (packetlist) {
      this.packetListToStructure(packetlist, new Set([enums.packet.publicKey, enums.packet.publicSubkey]));
      if (!this.keyPacket) {
        throw new Error('Invalid key: need at least key packet');
      }
    }
  }

  /**
   * Returns true if this is a public key
   * @returns {Boolean}
   */
  // eslint-disable-next-line class-methods-use-this
  isPublic() {
    return true;
  }

  /**
   * Returns true if this is a private key
   * @returns {Boolean}
   */
  // eslint-disable-next-line class-methods-use-this
  isPrivate() {
    return false;
  }

  /**
   * Returns key as public key (shallow copy)
   * @returns {Key} New public Key
   */
  toPublic() {
    return this;
  }

  /**
   * Returns ASCII armored text of key
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {ReadableStream<String>} ASCII armor.
   */
  armor(config = defaultConfig) {
    return armor(enums.armor.publicKey, this.toPacketList().write(), undefined, undefined, undefined, config);
  }
}

export default PublicKey;

