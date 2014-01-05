var enums = require('../enums.js');

module.exports = {
  List: require('./packetlist.js')
};

var packets = require('./all_packets.js');

for (var i in packets)
  module.exports[i] = packets[i];
