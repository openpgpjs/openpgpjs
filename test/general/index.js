module.exports = () => describe('General', function () {
  require('./util')();
  require('./biginteger')();
  require('./armor')();
  require('./packet')();
  require('./signature')();
  require('./key')();
  require('./openpgp')();
  require('./config')();
  require('./oid')();
  require('./ecc_nist')();
  require('./ecc_secp256k1')();
  require('./x25519')();
  require('./brainpool')();
  require('./decompression')();
  require('./streaming')();
});

