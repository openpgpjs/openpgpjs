
var enums = require('../enums.js');

module.exports {
	list: require('./packetlist.js')
}

// This need to be invoked before we do stuff with individual packets.
for(var i in enums.packets) {
	var packet = require('./' + i + '.js');

	// Setting the tag in one place.
	packet.prototype.tag = enum.packets[i];
}
