'use strict';

var openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../dist/openpgp');

var expect = require('chai').expect;

describe('Oid tests', function() {
  var Oid = openpgp.Oid;
  var p256_oid = new Uint8Array([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]);
  var p384_oid = new Uint8Array([0x2B, 0x81, 0x04, 0x00, 0x22]);
  var p521_oid = new Uint8Array([0x2B, 0x81, 0x04, 0x00, 0x23]);
  it('Constructing', function() {
    var oids = [p256_oid, p384_oid, p521_oid];
    oids.forEach(function (data) {
      var oid = new Oid(data);
      expect(oid).to.exist;
      expect(oid.oid).to.exist;
      expect(oid.oid).to.have.length(data.length);
      expect(oid.oid).to.equal(openpgp.util.Uint8Array2str(data));
    });
  });
  it('Reading and writing', function() {
    var oids = [p256_oid, p384_oid, p521_oid];
    oids.forEach(function (data) {
      data = openpgp.util.concatUint8Array([new Uint8Array([data.length]), data]); 
      var oid = new Oid();
      expect(oid.read(data)).to.equal(data.length);
      expect(oid.oid).to.exist;
      expect(oid.oid).to.have.length(data.length-1);
      expect(oid.oid).to.equal(openpgp.util.Uint8Array2str(data.subarray(1)));
      var result = oid.write();
      expect(result).to.exist;
      expect(result).to.have.length(data.length);
      expect(result[0]).to.equal(data.length-1);
      expect(openpgp.util.Uint8Array2str(result.subarray(1))).to.equal(openpgp.util.Uint8Array2str(data.subarray(1)));
    });
  });
});
