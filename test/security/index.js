module.exports = () => describe('Security', function () {
  require('./message_signature_bypass')();
  require('./unsigned_subpackets')();
  require('./subkey_trust')();
  require('./preferred_algo_mismatch')();
});
