const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../dist/openpgp');

const expect = require('chai').expect;

describe('PKCS5 padding', function() {
  function repeat(pattern, count) {
    let result = '';
    for (let k = 0; k < count; ++k) {
      result += pattern;
    }
    return result;
  }
  const pkcs5 = openpgp.crypto.pkcs5;
  it('Add padding', function () {
    let s = '';
    while (s.length < 16) {
      const r = pkcs5.encode(s);
      // 0..7 -> 8, 8..15 -> 16
      const l = Math.ceil((s.length + 1) / 8) * 8;
      const c = l - s.length;
      expect(r.length).to.equal(l);
      expect(c).is.at.least(1).is.at.most(8);
      expect(r.substr(-1)).to.equal(String.fromCharCode(c));
      s += ' ';
    }
  });
  it('Remove padding', function () {
    for (let k = 1; k <= 8; ++k) {
      const s = repeat(' ', 8 - k);
      const r = s + repeat(String.fromCharCode(k), k);
      const t = pkcs5.decode(r);
      expect(t).to.equal(s);
    }
  });
  it('Invalid padding', function () {
    expect(function () { pkcs5.decode(' '); }).to.throw(Error, /Invalid padding/);
    expect(function () { pkcs5.decode(''); }).to.throw(Error, /Invalid padding/);
  });
});
