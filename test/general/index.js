module.exports = () => describe('General', function () {
  require('./util.js')();
  require('./biginteger.js')();
  require('./armor.js')();
  require('./packet.js')();
  require('./signature.js')();
  require('./key.js')();
  require('./openpgp.js')();
  require('./config.js')();
  require('./oid.js')();
  require('./ecc_nist.js')();
  require('./ecc_secp256k1.js')();
  require('./x25519.js')();
  require('./brainpool.js')();
  require('./decompression.js')();
  require('./streaming.js')();
});

