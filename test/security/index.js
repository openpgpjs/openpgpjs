import testMessageSignatureBypess from './message_signature_bypass';
import testUnsignedSubpackets from './unsigned_subpackets';
import testSubkeyTrust from './subkey_trust';
import testPreferredAlgoMismatch from './preferred_algo_mismatch';

export default () => describe('Security', function () {
  testMessageSignatureBypess();
  testUnsignedSubpackets();
  testSubkeyTrust();
  testPreferredAlgoMismatch();
});
