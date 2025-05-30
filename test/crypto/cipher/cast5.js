import { expect } from 'chai';

import CAST5 from '../../../src/crypto/cipher/cast5.js';
import util from '../../../src/util.js';

export default () => it('CAST-128 cipher test with test vectors from RFC2144', function (done) {
  function test_cast(input, key, output) {
    const cast5 = new CAST5(key);
    const result = cast5.encrypt(input);

    return util.equalsUint8Array(new Uint8Array(result), new Uint8Array(output));
  }

  const testvectors = [[[0x01,0x23,0x45,0x67,0x12,0x34,0x56,0x78,0x23,0x45,0x67,0x89,0x34,0x56,0x78,0x9A],[0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF],[0x23,0x8B,0x4F,0xE5,0x84,0x7E,0x44,0xB2]]];

  for (let i = 0; i < testvectors.length; i++) {
    const res = test_cast(testvectors[i][1],testvectors[i][0],testvectors[i][2]);
    expect(res, 'vector with block ' + util.uint8ArrayToHex(testvectors[i][0]) +
                ' and key ' + util.uint8ArrayToHex(testvectors[i][1]) +
                ' should be ' + util.uint8ArrayToHex(testvectors[i][2])).to.be.true;
  }
  done();
});
