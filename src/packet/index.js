'use strict';

import * as packets from './all_packets.js';
import * as clone from './clone.js';
import List from './packetlist.js';
import { writeHeader } from './packet.js';

const mod = {
  /** @see module:packet/packetlist */
  List: List,
  /** @see module:packet/clone */
  clone: clone,
  /** @see module:packet */
  writeHeader: writeHeader
};

for (let i in packets) {
  mod[i] = packets[i];
}

export default mod;
