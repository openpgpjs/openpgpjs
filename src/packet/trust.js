/**
 * @requires enums
 * @module packet/trust
 */

module.exports = Trust;

var enums = require('../enums.js');

/**
 * @constructor
 */
function Trust() {
  this.tag = enums.packet.trust;
}

/**
 * Parsing function for a trust packet (tag 12).
 * Currently empty as we ignore trust packets
 * @param {String} byptes payload of a tag 12 packet
 */
Trust.prototype.read = function (bytes) {

};
