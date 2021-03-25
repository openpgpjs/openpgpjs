const util = require('../../src/util');

const chai = require('chai');

const { expect } = chai;

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

  describe("Misc.", function() {
    it('util.readNumber should not overflow until full range of uint32', function () {
      const ints = [2 ** 20, 2 ** 25, 2 ** 30, 2 ** 32 - 1];
      for (let i = 0; i < ints.length; i++) {
        expect(util.readNumber(util.writeNumber(ints[i], 4))).to.equal(ints[i]);
      }
    });
  });

});
