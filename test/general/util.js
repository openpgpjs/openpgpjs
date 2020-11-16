const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../..');
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
      const data = Array();
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

  describe('parseUserID', function() {
    it('should parse email address', function() {
      const email = "TestName Test  <test@example.com>";
      const result = util.parseUserId(email);
      expect(result.name).to.equal('TestName Test');
      expect(result.email).to.equal('test@example.com');
    });
    it('should parse email address with @ in display name and comment', function() {
      const email = "Test@Name Test (a comment) <test@example.com>";
      const result = util.parseUserId(email);
      expect(result.name).to.equal('Test@Name Test');
      expect(result.email).to.equal('test@example.com');
      expect(result.comment).to.equal('a comment');
    });
  });

  describe("Misc.", function() {
    it('util.readNumber should not overflow until full range of uint32', function () {
      const ints = [Math.pow(2, 20), Math.pow(2, 25), Math.pow(2, 30), Math.pow(2, 32) - 1];
      for(let i = 0; i < ints.length; i++) {
        expect(util.readNumber(util.writeNumber(ints[i], 4))).to.equal(ints[i]);
      }
    });
  });

  describe("Zbase32", function() {
    it('util.encodeZBase32 encodes correctly', function() {
      const encoded = util.encodeZBase32(util.strToUint8Array('test-wkd'));
      expect(encoded).to.equal('qt1zg7bpq7ise');
    })
  })

});
