/**
 * @fileoverview OpenPGP packet types
 * @see module:packet/all_packets
 * @see module:packet/clone
 * @see module:packet.List
 * @module packet
 */

import * as packets from './all_packets';
import * as clone from './clone';
import List from './packetlist';

const mod = {
  List,
  clone
};

Object.assign(mod, packets);

export default mod;
