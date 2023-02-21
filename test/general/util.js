const { expect } = require('chai');
const util = require('../../src/util');


module.exports = () => describe('Util unit tests', function() {

  describe('isString', function() {
    it('should return true for type "string"', function() {
      const data = 'foo';
      expect(util.isString(data)).to.be.true;
    });
    it('should return true for type String', function() {
      const data = String('foo');
      expect(util.isString(data)).to.be.true;
    });
    it('should return true for inherited type of String', function() {
      function MyString() {}
      MyString.prototype = Object.create(String.prototype);
      const data = new MyString();
      expect(util.isString(data)).to.be.true;
    });
    it('should return true for empty string', function() {
      const data = '';
      expect(util.isString(data)).to.be.true;
    });
    it('should return false for undefined', function() {
      let data;
      expect(util.isString(data)).to.be.false;
    });
    it('should return false for Object', function() {
      const data = {};
      expect(util.isString(data)).to.be.false;
    });
  });

  describe('isArray', function() {
    it('should return true for []', function() {
      const data = [];
      expect(util.isArray(data)).to.be.true;
    });
    it('should return true for type Array', function() {
      const data = Array(); // eslint-disable-line no-array-constructor
      expect(util.isArray(data)).to.be.true;
    });
    it('should return true for inherited type of Array', function() {
      function MyArray() {}
      MyArray.prototype = Object.create(Array.prototype);
      const data = new MyArray();
      expect(util.isArray(data)).to.be.true;
    });
    it('should return false for undefined', function() {
      let data;
      expect(util.isArray(data)).to.be.false;
    });
    it('should return false for Object', function() {
      const data = {};
      expect(util.isArray(data)).to.be.false;
    });
  });

  describe('isUint8Array', function() {
    it('should return true for type Uint8Array', function() {
      const data = new Uint8Array();
      expect(util.isUint8Array(data)).to.be.true;
    });
    it('should return true for inherited type of Uint8Array', function() {
      function MyUint8Array() {}
      MyUint8Array.prototype = new Uint8Array();
      const data = new MyUint8Array();
      expect(util.isUint8Array(data)).to.be.true;
    });
    it('should return false for undefined', function() {
      let data;
      expect(util.isUint8Array(data)).to.be.false;
    });
    it('should return false for Object', function() {
      const data = {};
      expect(util.isUint8Array(data)).to.be.false;
    });
  });

  describe('leftPad', function() {
    it('should not change the input if the length is correct', function() {
      const bytes = new Uint8Array([2, 1]);
      const padded = util.leftPad(bytes, 2);
      expect(padded).to.deep.equal(bytes);
    });
    it('should add leading zeros to input array', function() {
      const bytes = new Uint8Array([1, 2]);
      const padded = util.leftPad(bytes, 5);
      expect(padded).to.deep.equal(new Uint8Array([0, 0, 0, 1, 2]));
    });
  });

  describe('uint8ArrayToMPI', function() {
    it('should strip leading zeros', function() {
      const bytes = new Uint8Array([0, 0, 1, 2]);
      const mpi = util.uint8ArrayToMPI(bytes);
      expect(mpi).to.deep.equal(new Uint8Array([0, 9, 1, 2]));
    });
    it('should throw on array of all zeros', function() {
      const bytes = new Uint8Array([0, 0]);
      expect(() => util.uint8ArrayToMPI(bytes)).to.throw('Zero MPI');
    });
  });

  describe('isEmailAddress', function() {
    it('should return true for valid email address', function() {
      const data = 'test@example.com';
      expect(util.isEmailAddress(data)).to.be.true;
    });
    it('should return true for valid email address', function() {
      const data = 'test@xn--wgv.xn--q9jyb4c';
      expect(util.isEmailAddress(data)).to.be.true;
    });
    it('should return false for invalid email address', function() {
      const data = 'Test User <test@example.com>';
      expect(util.isEmailAddress(data)).to.be.false;
    });
    it('should return false for invalid email address', function() {
      const data = 'test@examplecom';
      expect(util.isEmailAddress(data)).to.be.false;
    });
    it('should return false for invalid email address', function() {
      const data = 'testexamplecom';
      expect(util.isEmailAddress(data)).to.be.false;
    });
    it('should return false for empty string', function() {
      const data = '';
      expect(util.isEmailAddress(data)).to.be.false;
    });
    it('should return false for undefined', function() {
      let data;
      expect(util.isEmailAddress(data)).to.be.false;
    });
    it('should return false for Object', function() {
      const data = {};
      expect(util.isEmailAddress(data)).to.be.false;
    });
  });

  describe('constant time select', function() {
    it('selectUint8Array should work for arrays of equal length', function () {
      const size = 10;
      const a = new Uint8Array(size).fill(1);
      const b = new Uint8Array(size).fill(2);
      expect(util.selectUint8Array(true, a, b)).to.deep.equal(a);
      expect(util.selectUint8Array(false, a, b)).to.deep.equal(b);
    });

    it('selectUint8Array should work for arrays of different length', function () {
      const size = 10;
      const a = new Uint8Array(size).fill(1);
      const b = new Uint8Array(2 * size).fill(2);
      expect(util.selectUint8Array(true, a, b)).to.deep.equal(a);
      expect(util.selectUint8Array(false, a, b)).to.deep.equal(b);
      expect(util.selectUint8Array(true, b, a)).to.deep.equal(b);
      expect(util.selectUint8Array(false, b, a)).to.deep.equal(a);
    });

    it('selectUint8 should return the expected value based on condition', function () {
      const a = 1;
      const b = 2;
      expect(util.selectUint8(true, a, b)).to.equal(a);
      expect(util.selectUint8(false, a, b)).to.equal(b);
    });
  });

  describe('Misc.', function() {
    it('util.readNumber should not overflow until full range of uint32', function () {
      const ints = [2 ** 20, 2 ** 25, 2 ** 30, 2 ** 32 - 1];
      for (let i = 0; i < ints.length; i++) {
        expect(util.readNumber(util.writeNumber(ints[i], 4))).to.equal(ints[i]);
      }
    });
  });

});
