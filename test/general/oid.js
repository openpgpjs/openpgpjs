const OID = require('../../src/type/oid');
const util = require('../../src/util');

const expect = require('chai').expect;

module.exports = () => describe('Oid tests', function() {
  const p256_oid = new Uint8Array([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]);
  const p384_oid = new Uint8Array([0x2B, 0x81, 0x04, 0x00, 0x22]);
  const p521_oid = new Uint8Array([0x2B, 0x81, 0x04, 0x00, 0x23]);
  it('Constructing', function() {
    const oids = [p256_oid, p384_oid, p521_oid];
    oids.forEach(function (data) {
      const oid = new OID(data);
      expect(oid).to.exist;
      expect(oid.oid).to.exist;
      expect(oid.oid).to.have.length(data.length);
      expect(oid.toHex()).to.equal(util.uint8ArrayToHex(data));
    });
  });
  it('Reading and writing', function() {
    const oids = [p256_oid, p384_oid, p521_oid];
    oids.forEach(function (data) {
      data = util.concatUint8Array([new Uint8Array([data.length]), data]);
      const oid = new OID();
      expect(oid.read(data)).to.equal(data.length);
      expect(oid.oid).to.exist;
      expect(oid.oid).to.have.length(data.length-1);
      expect(oid.toHex()).to.equal(util.uint8ArrayToHex(data.subarray(1)));
      const result = oid.write();
      expect(result).to.exist;
      expect(result).to.have.length(data.length);
      expect(result[0]).to.equal(data.length-1);
      expect(
        util.uint8ArrayToHex(result.subarray(1))
      ).to.equal(util.uint8ArrayToHex(data.subarray(1)));
    });
  });
});
