
var enums = require('../enums.js');

// This is pretty ugly, but browserify needs to have the requires explicitly written.
module.exports = {
	compressed: require('./compressed.js'),
	sym_encrypted_integrity_protected: require('./sym_encrypted_integrity_protected.js'),
	public_key_encrypted_session_key: require('./public_key_encrypted_session_key.js'),
	sym_encrypted_session_key: require('./sym_encrypted_session_key.js'),
	literal: require('./literal.js'),
	public_key: require('./public_key.js'),
	symmetrically_encrypted: require('./symmetrically_encrypted.js'),
	marker: require('./marker.js'),
	public_subkey: require('./public_subkey.js'),
	user_attribute: require('./user_attribute.js'),
	one_pass_signature: require('./one_pass_signature.js'),
	secret_key: require('./secret_key.js'),
	userid: require('./userid.js'),
	secret_subkey: require('./secret_subkey.js'),
	signature: require('./signature.js'),
	trust: require('./trust.js')
}

for(var i in enums.packet) {
	var packetClass = module.exports[i];

	if(packetClass != undefined)
		packetClass.prototype.tag = enums.packet[i];
}
