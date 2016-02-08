'use strict';

var openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../dist/openpgp');

var chai = require('chai'),
  expect = chai.expect;

describe('Util unit tests', function() {

  beforeEach(function() {});

  afterEach(function() {});

  describe('isString', function() {
    it('should return true for type "string"', function() {
      var data = 'foo';
      expect(openpgp.util.isString(data)).to.be.true;
    });
    it('should return true for type String', function() {
      var data = String('foo');
      expect(openpgp.util.isString(data)).to.be.true;
    });
    it('should return true for inherited type of String', function() {
      function MyString() {}
      MyString.prototype = Object.create(String.prototype);
      var data = new MyString();
      expect(openpgp.util.isString(data)).to.be.true;
    });
    it('should return true for empty string', function() {
      var data = '';
      expect(openpgp.util.isString(data)).to.be.true;
    });
    it('should return false for undefined', function() {
      var data;
      expect(openpgp.util.isString(data)).to.be.false;
    });
    it('should return false for Object', function() {
      var data = {};
      expect(openpgp.util.isString(data)).to.be.false;
    });
  });

  describe('isArray', function() {
    it('should return true for []', function() {
      var data = [];
      expect(openpgp.util.isArray(data)).to.be.true;
    });
    it('should return true for type Array', function() {
      var data = Array();
      expect(openpgp.util.isArray(data)).to.be.true;
    });
    it('should return true for inherited type of Array', function() {
      function MyArray() {}
      MyArray.prototype = Object.create(Array.prototype);
      var data = new MyArray();
      expect(openpgp.util.isArray(data)).to.be.true;
    });
    it('should return false for undefined', function() {
      var data;
      expect(openpgp.util.isArray(data)).to.be.false;
    });
    it('should return false for Object', function() {
      var data = {};
      expect(openpgp.util.isArray(data)).to.be.false;
    });
  });

  describe('isUint8Array', function() {
    it('should return true for type Uint8Array', function() {
      var data = new Uint8Array();
      expect(openpgp.util.isUint8Array(data)).to.be.true;
    });
    it('should return true for inherited type of Uint8Array', function() {
      function MyUint8Array() {}
      MyUint8Array.prototype = new Uint8Array();
      var data = new MyUint8Array();
      expect(openpgp.util.isUint8Array(data)).to.be.true;
    });
    it('should return false for undefined', function() {
      var data;
      expect(openpgp.util.isUint8Array(data)).to.be.false;
    });
    it('should return false for Object', function() {
      var data = {};
      expect(openpgp.util.isUint8Array(data)).to.be.false;
    });
  });

  describe('isEmailAddress', function() {
    it('should return true for valid email address', function() {
      var data = 'test@example.com';
      expect(openpgp.util.isEmailAddress(data)).to.be.true;
    });
    it('should return false for invalid email address', function() {
      var data = 'Test User <test@example.com>';
      expect(openpgp.util.isEmailAddress(data)).to.be.false;
    });
    it('should return false for invalid email address', function() {
      var data = 'test@examplecom';
      expect(openpgp.util.isEmailAddress(data)).to.be.false;
    });
    it('should return false for invalid email address', function() {
      var data = 'testexamplecom';
      expect(openpgp.util.isEmailAddress(data)).to.be.false;
    });
    it('should return false for empty string', function() {
      var data = '';
      expect(openpgp.util.isEmailAddress(data)).to.be.false;
    });
    it('should return false for undefined', function() {
      var data;
      expect(openpgp.util.isEmailAddress(data)).to.be.false;
    });
    it('should return false for Object', function() {
      var data = {};
      expect(openpgp.util.isEmailAddress(data)).to.be.false;
    });
  });

  describe('isUserId', function() {
    it('should return true for valid user id', function() {
      var data = 'Test User <test@example.com>';
      expect(openpgp.util.isUserId(data)).to.be.true;
    });
    it('should return false for invalid user id', function() {
      var data = 'Test User test@example.com>';
      expect(openpgp.util.isUserId(data)).to.be.false;
    });
    it('should return false for invalid user id', function() {
      var data = 'Test User <test@example.com';
      expect(openpgp.util.isUserId(data)).to.be.false;
    });
    it('should return false for invalid user id', function() {
      var data = 'Test User test@example.com';
      expect(openpgp.util.isUserId(data)).to.be.false;
    });
    it('should return false for empty string', function() {
      var data = '';
      expect(openpgp.util.isUserId(data)).to.be.false;
    });
    it('should return false for undefined', function() {
      var data;
      expect(openpgp.util.isUserId(data)).to.be.false;
    });
    it('should return false for Object', function() {
      var data = {};
      expect(openpgp.util.isUserId(data)).to.be.false;
    });
  });

});
