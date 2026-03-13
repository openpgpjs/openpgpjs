import testBlowfish from './blowfish.js';
import testCAST5 from './cast5.js';
import testDES from './des.js';
import testTwofish from './twofish.js';

export default () => describe('Cipher', function () {
  testBlowfish();
  testCAST5();
  testDES();
  testTwofish();
});
