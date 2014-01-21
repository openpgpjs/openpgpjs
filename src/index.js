
module.exports = require('./openpgp.js');
/**
 * @see module:key
 * @name module:openpgp.key
 */
module.exports.key = require('./key.js');
/**
 * @see module:message
 * @name module:openpgp.message
 */
module.exports.message = require('./message.js');
/**
 * @see module:cleartext
 * @name module:openpgp.cleartext
 */
module.exports.cleartext = require('./cleartext.js');
/**
 * @see module:util
 * @name module:openpgp.util
 */
module.exports.util = require('./util.js');
/**
 * @see module:packet
 * @name module:openpgp.packet
 */
module.exports.packet = require('./packet');
/**
 * @see module:type/mpi
 * @name module:openpgp.MPI
 */
module.exports.MPI = require('./type/mpi.js');
/**
 * @see module:type/s2k
 * @name module:openpgp.S2K
 */
module.exports.S2K = require('./type/s2k.js');
/**
 * @see module:type/keyid
 * @name module:openpgp.Keyid
 */
module.exports.Keyid = require('./type/keyid.js');
/**
 * @see module:encoding/armor
 * @name module:openpgp.armor
 */
module.exports.armor = require('./encoding/armor.js');
/**
 * @see module:enums
 * @name module:openpgp.enums
 */
module.exports.enums = require('./enums.js');
/**
 * @see module:config/config
 * @name module:openpgp.config
 */
module.exports.config = require('./config/config.js');
/**
 * @see module:crypto
 * @name module:openpgp.crypto
 */
module.exports.crypto = require('./crypto');
/**
 * @see module:keyring
 * @name module:openpgp.Keyring
 */
module.exports.Keyring = require('./keyring');
/**
 * @see module:worker/async_proxy
 * @name module:openpgp.AsyncProxy
 */
module.exports.AsyncProxy = require('./worker/async_proxy.js');
