describe('General', function () {
  require('./util.js');
  require('./armor.js');
  require('./packet.js');
  require('./keyring.js');
  describe('[Sauce Labs Group 1]', function() {
    require('./signature.js');
    require('./key.js');
  });
  require('./openpgp.js');
  require('./hkp.js');
  require('./wkd.js');
  require('./oid.js');
  require('./ecc_nist.js');
  require('./x25519.js');
  require('./brainpool.js');
  require('./decompression.js');
  require('./streaming.js');
});

