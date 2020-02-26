const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../dist/openpgp');

const chai = require('chai');

const { expect } = chai;

describe.skip('WKD unit tests', function() {
  this.timeout(60000);

  let wkd;

  beforeEach(function() {
    wkd = new openpgp.WKD();
  });

  afterEach(function() {});

  describe('lookup', function() {
    it('by email address should work', function() {
      return wkd.lookup({
        email: 'test-wkd@metacode.biz',
        rawBytes: true
      }).then(function(keys) {
        expect(keys).to.exist;
        expect(keys).to.be.an.instanceof(Uint8Array);
      });
    });

    it('by email address should work', function() {
      return wkd.lookup({
        email: 'test-wkd@metacode.biz'
      }).then(function(keys) {
        expect(keys).to.exist;
        expect(keys).to.have.length(1);
      });
    });

    it('by email address should not find a key', function() {
      return wkd.lookup({
        email: 'test-wkd-does-not-exist@metacode.biz'
      }).then(function(keys) {
        expect(keys).to.be.undefined;
      });
    });
  });

});
