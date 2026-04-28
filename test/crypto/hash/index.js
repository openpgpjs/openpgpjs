import testMD5 from './md5.js';
import testRipeMD from './ripemd.js';
import testSHA from './sha.js';

export default () => describe('Hash', function () {
  testMD5();
  testRipeMD();
  testSHA();
});
