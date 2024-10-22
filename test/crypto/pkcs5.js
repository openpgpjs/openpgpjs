import { expect } from 'chai';

import * as pkcs5 from '../../src/crypto/pkcs5.js';

export default () => describe('PKCS5 padding', function() {
  it('Add and remove padding', function () {
    const m = new Uint8Array([0,1,2,3,4,5,6,7,8]);
    const padded = pkcs5.encode(m);
    const unpadded = pkcs5.decode(padded);
    expect(padded[padded.length - 1]).to.equal(7);
    expect(padded.length % 8).to.equal(0);
    expect(unpadded).to.deep.equal(m);
  });
});
