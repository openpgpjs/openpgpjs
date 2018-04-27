/**
 * @fileoverview Exports all OpenPGP packet types
 * @requires enums
 * @module packet/all_packets
 */

import enums from '../enums.js';
import * as packets from './all_packets.js'; // re-import module to parse packets from tag

export {
  /** @see module:packet.Compressed */
  default as Compressed
} from './compressed.js';
export {
  /** @see module:packet.SymEncryptedIntegrityProtected */
  default as SymEncryptedIntegrityProtected
} from './sym_encrypted_integrity_protected.js';
export {
  /** @see module:packet.SymEncryptedAEADProtected */
  default as SymEncryptedAEADProtected
} from './sym_encrypted_aead_protected.js';
export {
  /** @see module:packet.PublicKeyEncryptedSessionKey */
  default as PublicKeyEncryptedSessionKey
} from './public_key_encrypted_session_key.js';
export {
  /** @see module:packet.SymEncryptedSessionKey */
  default as SymEncryptedSessionKey
} from './sym_encrypted_session_key.js';
export {
  /** @see module:packet.Literal */
  default as Literal
} from './literal.js';
export {
  /** @see module:packet.PublicKey */
  default as PublicKey
} from './public_key.js';
export {
  /** @see module:packet.SymmetricallyEncrypted */
  default as SymmetricallyEncrypted
} from './symmetrically_encrypted.js';
export {
  /** @see module:packet.Marker */
  default as Marker
} from './marker.js';
export {
  /** @see module:packet.PublicSubkey */
  default as PublicSubkey
} from './public_subkey.js';
export {
  /** @see module:packet.UserAttribute */
  default as UserAttribute
} from './user_attribute.js';
export {
  /** @see module:packet.OnePassSignature */
  default as OnePassSignature
} from './one_pass_signature.js';
export {
  /** @see module:packet.SecretKey */
  default as SecretKey
} from './secret_key.js';
export {
  /** @see module:packet.Userid */
  default as Userid
} from './userid.js';
export {
  /** @see module:packet.SecretSubkey */
  default as SecretSubkey
} from './secret_subkey.js';
export {
  /** @see module:packet.Signature */
  default as Signature
} from './signature.js';
export {
  /** @see module:packet.Trust */
  default as Trust
} from './trust.js';

/**
 * Allocate a new packet
 * @function newPacketFromTag
 * @memberof module:packet
 * @param {String} tag property name from {@link module:enums.packet}
 * @returns {Object} new packet object with type based on tag
 */
export function newPacketFromTag(tag) {
  return new packets[packetClassFromTagName(tag)]();
}

/**
 * Allocate a new packet from structured packet clone
 * @see {@link https://w3c.github.io/html/infrastructure.html#safe-passing-of-structured-data}
 * @function fromStructuredClone
 * @memberof module:packet
 * @param {Object} packetClone packet clone
 * @returns {Object} new packet object with data from packet clone
 */
export function fromStructuredClone(packetClone) {
  const tagName = enums.read(enums.packet, packetClone.tag);
  const packet = newPacketFromTag(tagName);
  Object.assign(packet, packetClone);
  if (packet.postCloneTypeFix) {
    packet.postCloneTypeFix();
  }
  return packet;
}

/**
 * Convert tag name to class name
 * @param {String} tag property name from {@link module:enums.packet}
 * @returns {String}
 * @private
 */
function packetClassFromTagName(tag) {
  return tag.substr(0, 1).toUpperCase() + tag.substr(1);
}
