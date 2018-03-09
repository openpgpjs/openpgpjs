/**
 * @fileoverview OpenPGP packet types
 * @see module:packet/all_packets
 * @see module:packet/packetlist
 * @see module:packet/clone
 * @module packet
 */

import * as packets from './all_packets';
import * as clone from './clone';
import List from './packetlist';

const mod = {
  List,
  clone
};

for (const i in packets) {
  mod[i] = packets[i];
}

export default mod;
