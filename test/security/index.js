import testMessageSignatureBypess from './message_signature_bypass.js';
import testUnsignedSubpackets from './unsigned_subpackets.js';
import testSubkeyTrust from './subkey_trust.js';
import testPreferredAlgoMismatch from './preferred_algo_mismatch.js';

export default () => describe('Security', function () {
  testMessageSignatureBypess();
  testUnsignedSubpackets();
  testSubkeyTrust();
  testPreferredAlgoMismatch();
});
