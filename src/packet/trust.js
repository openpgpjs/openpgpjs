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
