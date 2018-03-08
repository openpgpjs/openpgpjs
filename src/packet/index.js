/**
 * @fileoverview OpenPGP packet types
 * @see module:packet/all_packets
 * @see module:packet/packetlist
 * @see module:packet/clone
 * @module packet
 */

import * as packets from './all_packets.js';
import * as clone from './clone.js';
import List from './packetlist.js';

const mod = {
  /** @see module:packet/packetlist */
  List: List,
  /** @see module:packet/clone */
  clone: clone
};

for (const i in packets) {
  mod[i] = packets[i];
}

export default mod;
