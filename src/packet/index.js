'use strict';

import * as packets from './all_packets.js';
import List from './packetlist.js';

const mod = {
  /**
   * @name module:packet.List
   * @see module:packet/packetlist
   */
  List: List
};

for (let i in packets) {
  mod[i] = packets[i];
}

export default mod;
