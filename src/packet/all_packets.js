/**
 * @requires enums
 * @module packet
 */
var enums = require('../enums.js');

// This is pretty ugly, but browserify needs to have the requires explicitly written.

module.exports = {
  /** @see module:packet/compressed */
  compressed: require('./compressed.js'),
  /** @see module:packet/sym_encrypted_integrity_protected */
  sym_encrypted_integrity_protected: require('./sym_encrypted_integrity_protected.js'),
  /** @see module:packet/public_key_encrypted_session_key */
  public_key_encrypted_session_key: require('./public_key_encrypted_session_key.js'),
  /** @see module:packet/sym_encrypted_session_key */
  sym_encrypted_session_key: require('./sym_encrypted_session_key.js'),
  /** @see module:packet/literal */
  literal: require('./literal.js'),
  /** @see module:packet/public_key */
  public_key: require('./public_key.js'),
  /** @see module:packet/symmetrically_encrypted */
  symmetrically_encrypted: require('./symmetrically_encrypted.js'),
  /** @see module:packet/marker */
  marker: require('./marker.js'),
  /** @see module:packet/public_subkey */
  public_subkey: require('./public_subkey.js'),
  /** @see module:packet/user_attribute */
  user_attribute: require('./user_attribute.js'),
  /** @see module:packet/one_pass_signature */
  one_pass_signature: require('./one_pass_signature.js'),
  /** @see module:packet/secret_key */
  secret_key: require('./secret_key.js'),
  /** @see module:packet/userid */
  userid: require('./userid.js'),
  /** @see module:packet/secret_subkey */
  secret_subkey: require('./secret_subkey.js'),
  /** @see module:packet/signature */
  signature: require('./signature.js'),
  /** @see module:packet/trust */
  trust: require('./trust.js')
}

for (var i in enums.packet) {
  var packetClass = module.exports[i];

  if (packetClass != undefined)
    packetClass.prototype.tag = enums.packet[i];
}
