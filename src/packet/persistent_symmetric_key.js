/** @access public */
// OpenPGP.js - An OpenPGP implementation in javascript
// Copyright (C) 2026 Proton AG
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

import SecretKeyPacket from './secret_key';
import enums from '../enums';
import defaultConfig from '../config';

/**
 * The Persistent Symmetric Key Packet (Type ID 40) has identical fields
 * to the Secret Key Packet (Type ID 5).
 * @extends SecretKeyPacket
 */
class PersistentSymmetricKeyPacket extends SecretKeyPacket {
  static get tag() {
    return enums.packet.persistentSymmetricKey;
  }

  /**
   * @param {Date} [date] - Creation date
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   */
  constructor(date = new Date(), config = defaultConfig) {
    super(date, config);

    // Only version 6 of the packet is defined.
    this.version = 6;
  }

  /**
   * Internal parser for persistent symmetric key packets as specified in
   * {@link https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-persistent-symmetric-keys-02#section-5|draft-ietf-openpgp-persistent-symmetric-keys section 5}
   * @param {Uint8Array} bytes - Input string to read the packet from
   * @async
   */
  async read(bytes, config = defaultConfig) {
    await super.read(bytes, config);

    // Only version 6 of the packet is defined. Earlier versions of the
    // Secret Key Packet format MUST NOT be used with the Persistent
    // Symmetric Key Packet.
    if (this.version < 6) {
      throw new Error('Persistent Symmetric Key packets can only be used with version 6');
    }

    // The Persistent Symmetric Key Packet MUST NOT be used with
    // asymmetric algorithms, i.e. any of the public key algorithms
    // defined in table 18 of [RFC9580]. It may only be used with the
    // persistent symmetric algorithm defined below, with special
    // algorithm ID value 0.
    if (this.algorithm !== enums.publicKey.aead) {
      throw new Error('Persistent Symmetric Key packets can only be used with algorithm 0');
    }

    // When storing encrypted symmetric key material in a Persistent
    // Symmetric Key Packet, AEAD encryption (S2K usage octet 253, see
    // section 3.7.2.1 of [RFC9580]) MUST be used, to ensure that the
    // secret key material is bound to the fingerprint. Implementations
    // MUST NOT decrypt symmetric key material in a Persistent Symmetric
    // Key Packet that was encrypted using a different method.
    if (this.s2kUsage && !this.usedModernAEAD) {
      throw new Error('Persistent Symmetric Key packets can only be encrypted with modern AEAD');
    }
  }

  /**
   * Writes a persistent symmetric key packet.
   * @returns {Uint8Array} A string of bytes containing the persistent symmetric key packet.
   */
  write() {
    // Sanity checks, same as above.
    if (this.version < 6) {
      throw new Error('Persistent Symmetric Key packets can only be used with version 6');
    }
    if (this.algorithm !== enums.publicKey.aead) {
      throw new Error('Persistent Symmetric Key packets can only be used with algorithm 0');
    }
    if (this.s2kUsage && !this.usedModernAEAD) {
      throw new Error('Persistent Symmetric Key packets can only be encrypted with modern AEAD');
    }
    return super.write();
  }
}

export default PersistentSymmetricKeyPacket;
