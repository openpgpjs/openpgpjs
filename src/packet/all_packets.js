/**
 * @fileoverview Exports all OpenPGP packet types
 * @module packet/all_packets
 * @private
 */

export { default as CompressedDataPacket } from './compressed_data.js';
export { default as SymEncryptedIntegrityProtectedDataPacket } from './sym_encrypted_integrity_protected_data.js';
export { default as AEADEncryptedDataPacket } from './aead_encrypted_data.js';
export { default as PublicKeyEncryptedSessionKeyPacket } from './public_key_encrypted_session_key.js';
export { default as SymEncryptedSessionKeyPacket } from './sym_encrypted_session_key.js';
export { default as LiteralDataPacket } from './literal_data.js';
export { default as PublicKeyPacket } from './public_key.js';
export { default as SymmetricallyEncryptedDataPacket } from './symmetrically_encrypted_data.js';
export { default as MarkerPacket } from './marker.js';
export { default as PublicSubkeyPacket } from './public_subkey.js';
export { default as UserAttributePacket } from './user_attribute.js';
export { default as OnePassSignaturePacket } from './one_pass_signature.js';
export { default as SecretKeyPacket } from './secret_key.js';
export { default as UserIDPacket } from './userid.js';
export { default as SecretSubkeyPacket } from './secret_subkey.js';
export { default as SignaturePacket } from './signature.js';
export { default as TrustPacket } from './trust.js';

/**
 * Allocate a new packet
 * @function newPacketFromTag
 * @param {String} tag property name from {@link module:enums.packet}
 * @returns {Object} new packet object with type based on tag
 */
export function newPacketFromTag(tag, allowedPackets) {
  const className = packetClassFromTagName(tag);
  if (!allowedPackets[className]) {
    throw new Error('Packet not allowed in this context: ' + className);
  }
  return new allowedPackets[className]();
}

/**
 * Convert tag name to class name
 * @param {String} tag property name from {@link module:enums.packet}
 * @returns {String}
 * @private
 */
function packetClassFromTagName(tag) {
  return tag.substr(0, 1).toUpperCase() + tag.substr(1) + 'Packet';
}
