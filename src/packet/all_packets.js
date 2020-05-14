/**
 * @fileoverview Exports all OpenPGP packet types
 * @requires enums
 * @module packet/all_packets
 */

export {
  /** @see CompressedDataPacket */
  default as CompressedDataPacket
} from './compressed_data.js';
export {
  /** @see SymEncryptedIntegrityProtectedDataPacket */
  default as SymEncryptedIntegrityProtectedDataPacket
} from './sym_encrypted_integrity_protected_data.js';
export {
  /** @see SymEncryptedAEADProtectedDataPacket */
  default as SymEncryptedAEADProtectedDataPacket
} from './sym_encrypted_aead_protected_data.js';
export {
  /** @see PublicKeyEncryptedSessionKeyPacket */
  default as PublicKeyEncryptedSessionKeyPacket
} from './public_key_encrypted_session_key.js';
export {
  /** @see SymEncryptedSessionKeyPacket */
  default as SymEncryptedSessionKeyPacket
} from './sym_encrypted_session_key.js';
export {
  /** @see LiteralDataPacket */
  default as LiteralDataPacket
} from './literal_data.js';
export {
  /** @see PublicKeyPacket */
  default as PublicKeyPacket
} from './public_key.js';
export {
  /** @see SymmetricallyEncryptedDataPacket */
  default as SymmetricallyEncryptedDataPacket
} from './symmetrically_encrypted_data.js';
export {
  /** @see MarkerPacket */
  default as MarkerPacket
} from './marker.js';
export {
  /** @see PublicSubkeyPacket */
  default as PublicSubkeyPacket
} from './public_subkey.js';
export {
  /** @see UserAttributePacket */
  default as UserAttributePacket
} from './user_attribute.js';
export {
  /** @see OnePassSignaturePacket */
  default as OnePassSignaturePacket
} from './one_pass_signature.js';
export {
  /** @see SecretKeyPacket */
  default as SecretKeyPacket
} from './secret_key.js';
export {
  /** @see UserIDPacket */
  default as UserIDPacket
} from './userid.js';
export {
  /** @see SecretSubkeyPacket */
  default as SecretSubkeyPacket
} from './secret_subkey.js';
export {
  /** @see SignaturePacket */
  default as SignaturePacket
} from './signature.js';
export {
  /** @see TrustPacket */
  default as TrustPacket
} from './trust.js';

/**
 * Allocate a new packet
 * @function newPacketFromTag
 * @memberof module:packet
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
