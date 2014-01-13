/**
 * @requires enums
 * @module packet
 */
var enums = require('../enums.js');

// This is pretty ugly, but browserify needs to have the requires explicitly written.

module.exports = {
  /** @see module:packet/compressed */
  Compressed: require('./compressed.js'),
  /** @see module:packet/sym_encrypted_integrity_protected */
  SymEncryptedIntegrityProtected: require('./sym_encrypted_integrity_protected.js'),
  /** @see module:packet/public_key_encrypted_session_key */
  PublicKeyEncryptedSessionKey: require('./public_key_encrypted_session_key.js'),
  /** @see module:packet/sym_encrypted_session_key */
  SymEncryptedSessionKey: require('./sym_encrypted_session_key.js'),
  /** @see module:packet/literal */
  Literal: require('./literal.js'),
  /** @see module:packet/public_key */
  PublicKey: require('./public_key.js'),
  /** @see module:packet/symmetrically_encrypted */
  SymmetricallyEncrypted: require('./symmetrically_encrypted.js'),
  /** @see module:packet/marker */
  Marker: require('./marker.js'),
  /** @see module:packet/public_subkey */
  PublicSubkey: require('./public_subkey.js'),
  /** @see module:packet/user_attribute */
  UserAttribute: require('./user_attribute.js'),
  /** @see module:packet/one_pass_signature */
  OnePassSignature: require('./one_pass_signature.js'),
  /** @see module:packet/secret_key */
  SecretKey: require('./secret_key.js'),
  /** @see module:packet/userid */
  Userid: require('./userid.js'),
  /** @see module:packet/secret_subkey */
  SecretSubkey: require('./secret_subkey.js'),
  /** @see module:packet/signature */
  Signature: require('./signature.js'),
  /** @see module:packet/trust */
  Trust: require('./trust.js'),
  /**
   * Allocate a new packet
   * @param {String} tag property name from {@link module:enums.packet}
   * @returns {Object} new packet object with type based on tag
   */
  newPacketFromTag: function (tag) {
    return new this[packetClassFromTagName(tag)]();
  },
  /**
   * Allocate a new packet from structured packet clone
   * See {@link http://www.w3.org/html/wg/drafts/html/master/infrastructure.html#safe-passing-of-structured-data}
   * @param {Object} packetClone packet clone
   * @returns {Object} new packet object with data from packet clone
   */
  fromStructuredClone: function(packetClone) {
    var tagName = enums.read(enums.packet, packetClone.tag)
    var packet = this.newPacketFromTag(tagName);
    for (var attr in packetClone) {
        if (packetClone.hasOwnProperty(attr)) {
          packet[attr] = packetClone[attr];
        }
      }
    if (packet.postCloneTypeFix) {
      packet.postCloneTypeFix();
    }
    return packet;
  }
};

/**
 * Convert tag name to class name
 * @param {String} tag property name from {@link module:enums.packet}
 * @returns {String}
 */
function packetClassFromTagName(tag) {
  return tag.substr(0, 1).toUpperCase() + tag.substr(1);
}
