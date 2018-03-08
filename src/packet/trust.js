/**
 * @requires enums
 * @module packet/trust
 */

import enums from '../enums.js';

/**
 * @constructor
 */
function Trust() {
  this.tag = enums.packet.trust;
}

/**
 * Parsing function for a trust packet (tag 12).
 * Currently not implemented as we ignore trust packets
 * @param {String} byptes payload of a tag 12 packet
 */
Trust.prototype.read = function () {}; // TODO

export default Trust;
