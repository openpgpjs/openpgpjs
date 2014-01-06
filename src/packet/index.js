var enums = require('../enums.js');

module.exports = {
  /**
   * @name module:packet.List
   * @see module:packet/packetlist
   */
  List: require('./packetlist.js')
};

var packets = require('./all_packets.js');

for (var i in packets)
  module.exports[i] = packets[i];
