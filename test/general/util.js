const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../dist/openpgp');

const chai = require('chai');

const { expect } = chai;

describe('Util unit tests', function() {

  describe('isString', function() {
    it('should return true for type "string"', function() {
      const data = 'foo';
      expect(openpgp.util.isString(data)).to.be.true;
    });
    it('should return true for type String', function() {
      const data = String('foo');
      expect(openpgp.util.isString(data)).to.be.true;
    });
    it('should return true for inherited type of String', function() {
      function MyString() {}
      MyString.prototype = Object.create(String.prototype);
      const data = new MyString();
      expect(openpgp.util.isString(data)).to.be.true;
    });
    it('should return true for empty string', function() {
      const data = '';
      expect(openpgp.util.isString(data)).to.be.true;
    });
    it('should return false for undefined', function() {
      let data;
      expect(openpgp.util.isString(data)).to.be.false;
    });
    it('should return false for Object', function() {
      const data = {};
      expect(openpgp.util.isString(data)).to.be.false;
    });
  });

  describe('isArray', function() {
    it('should return true for []', function() {
      const data = [];
      expect(openpgp.util.isArray(data)).to.be.true;
    });
    it('should return true for type Array', function() {
      const data = Array();
      expect(openpgp.util.isArray(data)).to.be.true;
    });
    it('should return true for inherited type of Array', function() {
      function MyArray() {}
      MyArray.prototype = Object.create(Array.prototype);
      const data = new MyArray();
      expect(openpgp.util.isArray(data)).to.be.true;
    });
    it('should return false for undefined', function() {
      let data;
      expect(openpgp.util.isArray(data)).to.be.false;
    });
    it('should return false for Object', function() {
      const data = {};
      expect(openpgp.util.isArray(data)).to.be.false;
    });
  });

  describe('isUint8Array', function() {
    it('should return true for type Uint8Array', function() {
      const data = new Uint8Array();
      expect(openpgp.util.isUint8Array(data)).to.be.true;
    });
    it('should return true for inherited type of Uint8Array', function() {
      function MyUint8Array() {}
      MyUint8Array.prototype = new Uint8Array();
      const data = new MyUint8Array();
      expect(openpgp.util.isUint8Array(data)).to.be.true;
    });
    it('should return false for undefined', function() {
      let data;
      expect(openpgp.util.isUint8Array(data)).to.be.false;
    });
    it('should return false for Object', function() {
      const data = {};
      expect(openpgp.util.isUint8Array(data)).to.be.false;
    });
  });

  describe('isEmailAddress', function() {
    it('should return true for valid email address', function() {
      const data = 'test@example.com';
      expect(openpgp.util.isEmailAddress(data)).to.be.true;
    });
    it('should return true for valid email address', function() {
      const data = 'test@xn--wgv.xn--q9jyb4c';
      expect(openpgp.util.isEmailAddress(data)).to.be.true;
    });
    it('should return false for invalid email address', function() {
      const data = 'Test User <test@example.com>';
      expect(openpgp.util.isEmailAddress(data)).to.be.false;
    });
    it('should return false for invalid email address', function() {
      const data = 'test@examplecom';
      expect(openpgp.util.isEmailAddress(data)).to.be.false;
    });
    it('should return false for invalid email address', function() {
      const data = 'testexamplecom';
      expect(openpgp.util.isEmailAddress(data)).to.be.false;
    });
    it('should return false for empty string', function() {
      const data = '';
      expect(openpgp.util.isEmailAddress(data)).to.be.false;
    });
    it('should return false for undefined', function() {
      let data;
      expect(openpgp.util.isEmailAddress(data)).to.be.false;
    });
    it('should return false for Object', function() {
      const data = {};
      expect(openpgp.util.isEmailAddress(data)).to.be.false;
    });
  });

  describe('getTransferables', function() {
    let zero_copyVal;
    const buf1 = new Uint8Array(1);
    const buf2 = new Uint8Array(1);
    const obj = {
        data1: buf1,
        data2: buf1,
        data3: {
          data4: buf2
        }
      };

    beforeEach(function() {
      zero_copyVal = openpgp.config.zero_copy;
      openpgp.config.zero_copy = true;
    });

    afterEach(function() {
      openpgp.config.zero_copy = zero_copyVal;
    });

    it('should return undefined when zero_copy is false', function() {
      openpgp.config.zero_copy = false;
      expect(openpgp.util.getTransferables(obj)).to.be.undefined;
    });
    it('should return undefined for no input', function() {
      expect(openpgp.util.getTransferables()).to.be.undefined;
    });
    it('should return undefined for an empty oject', function() {
      expect(openpgp.util.getTransferables({})).to.be.undefined;
    });
    it('should return two buffers', function() {
      expect(openpgp.util.getTransferables(obj)).to.deep.equal([buf1.buffer, buf2.buffer]);
    });
  });

  describe("Misc.", function() {
    it('util.readNumber should not overflow until full range of uint32', function () {
      const ints = [Math.pow(2, 20), Math.pow(2, 25), Math.pow(2, 30), Math.pow(2, 32) - 1];
      for(let i = 0; i < ints.length; i++) {
        expect(openpgp.util.readNumber(openpgp.util.writeNumber(ints[i], 4))).to.equal(ints[i]);
      }
    });
  });

  describe("Zbase32", function() {
    it('util.encodeZBase32 encodes correctly', function() {
      const encoded = openpgp.util.encodeZBase32(openpgp.util.str_to_Uint8Array('test-wkd'));
      expect(encoded).to.equal('qt1zg7bpq7ise');
    })
  })

});
