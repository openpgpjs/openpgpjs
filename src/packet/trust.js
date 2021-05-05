/* eslint class-methods-use-this: ["error", { "exceptMethods": ["read"] }] */

import enums from '../enums';
import { UnsupportedError } from './packet';

/**
 * Implementation of the Trust Packet (Tag 12)
 *
 * {@link https://tools.ietf.org/html/rfc4880#section-5.10|RFC4880 5.10}:
 * The Trust packet is used only within keyrings and is not normally
 * exported.  Trust packets contain data that record the user's
 * specifications of which key holders are trustworthy introducers,
 * along with other information that implementing software uses for
 * trust information.  The format of Trust packets is defined by a given
 * implementation.
 *
 * Trust packets SHOULD NOT be emitted to output streams that are
 * transferred to other users, and they SHOULD be ignored on any input
 * other than local keyring files.
 */
class TrustPacket {
  static get tag() {
    return enums.packet.trust;
  }

  /**
   * Parsing function for a trust packet (tag 12).
   * Currently not implemented as we ignore trust packets
   */
  read() {
    throw new UnsupportedError('Trust packets are not supported');
  }

  // eslint-disable-next-line class-methods-use-this
  write() {
    throw new UnsupportedError('Trust packets are not supported');
  }
}

export default TrustPacket;
