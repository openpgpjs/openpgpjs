'use strict';

var openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../dist/openpgp');

var expect = require('chai').expect;

describe('PKCS5 padding', function() {
  function repeat(pattern, count) {
    var result = '';
    for (var k=0; k<count; ++k) {
      result += pattern;
    }
    return result;
  }
  var pkcs5 = openpgp.crypto.pkcs5;
  it('Add padding', function () {
    var s = '';
    while (s.length < 16) {
      var r = pkcs5.encode(s);
      // 0..7 -> 8, 8..15 -> 16
      var l = Math.ceil((s.length+1)/8)*8;
      var c = l - s.length;
      expect(r.length).to.equal(l);
      expect(c).is.at.least(1).is.at.most(8);
      expect(r.substr(-1)).to.equal(String.fromCharCode(c));
      s += ' ';
    }
  });
  it('Remove padding', function () {
    for (var k=1; k<=8; ++k) {
      var s = repeat(' ', 8-k);
      var r = s + repeat(String.fromCharCode(k), k);
      var t = pkcs5.decode(r);
      expect(t).to.equal(s);
    }
  });
  it('Invalid padding', function () {
    expect(function () {pkcs5.decode(' ');}).to.throw(Error, /Invalid padding/);
    expect(function () {pkcs5.decode('');}).to.throw(Error, /Invalid padding/);
  });
});
