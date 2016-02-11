'use strict';

var openpgp = typeof window != 'undefined' && window.openpgp ? window.openpgp : require('openpgp');

var   config = openpgp.config,
  crypto = openpgp.crypto,
  enums = openpgp.enums,
  util = openpgp.util;

var chai = require('chai'),
	expect = chai.expect;

var repetitions = 10;
var plaintext_part = "This is the end, my only friend, the end.";
var plaintext = Array(repetitions + 1).join(plaintext_part);

describe("CFB Stream", function() {
  var symmAlgos = Object.keys(openpgp.enums.symmetric);
  symmAlgos = symmAlgos.filter(function(algo) {
    return algo !== 'idea' && algo !== 'plaintext';
  });

  symmAlgos.forEach(function(algo) {
    it("should work when calling write once (" + algo + ")", function(done) {
      var encrypted_data = new Uint8Array(0);

      var opts = {};
      opts.algo = algo;
      opts.key = crypto.generateSessionKey(opts.algo);
      opts.cipherFn = crypto.cipher[opts.algo];
      opts.prefixRandom = crypto.getPrefixRandom(opts.algo);

      var cs = new openpgp.stream.CipherFeedbackStream(opts);

      cs.setOnDataCallback(function(d) {
        var tmp = new Uint8Array(encrypted_data.length + d.length);
        tmp.set(encrypted_data, 0);
        tmp.set(d, encrypted_data.length);
        encrypted_data = tmp;
      });

      cs.setOnEndCallback(function() {
        var decrypted = crypto.cfb.decrypt(opts.algo, opts.key, util.bin2str(encrypted_data), true);
        expect(decrypted.join("")).equal(plaintext);
        done();
      });

      cs.write(util.str2Uint8Array(plaintext));

      cs.end();
    });

    it("should decrypt when calling write multiple times (" + algo + ")", function(done) {
      var encrypted_data = new Uint8Array(0);

      var opts = {};
      opts.algo = algo;
      opts.key = crypto.generateSessionKey(opts.algo);
      opts.cipherFn = crypto.cipher[opts.algo];
      opts.prefixRandom = crypto.getPrefixRandom(opts.algo);
    
      var cs = new openpgp.stream.CipherFeedbackStream(opts);

      cs.setOnDataCallback(function(d) {
        var tmp = new Uint8Array(encrypted_data.length + d.length);
        tmp.set(encrypted_data, 0);
        tmp.set(d, encrypted_data.length);
        encrypted_data = tmp;
      });

      cs.setOnEndCallback(function() {
        var decrypted = crypto.cfb.decrypt(opts.algo, opts.key, util.bin2str(encrypted_data), true);
        expect(decrypted.join("")).equal(plaintext);
        done();
      });

      for (var i = 0; i < repetitions; i++) {
        cs.write(util.str2Uint8Array(plaintext_part));
      }

      cs.end();
    });

    it("should work with resync set to false (" + algo + ")", function(done) {
      var encrypted_data = new Uint8Array(0);

      var opts = {};
      opts.algo = algo;
      opts.key = crypto.generateSessionKey(opts.algo);
      opts.cipherFn = crypto.cipher[opts.algo];
      opts.prefixRandom = crypto.getPrefixRandom(opts.algo);
      opts.resync = false;
    
      var cs = new openpgp.stream.CipherFeedbackStream(opts);

      cs.setOnDataCallback(function(d) {
        var tmp = new Uint8Array(encrypted_data.length + d.length);
        tmp.set(encrypted_data, 0);
        tmp.set(d, encrypted_data.length);
        encrypted_data = tmp;
      });

      cs.setOnEndCallback(function() {
        var decrypted = crypto.cfb.decrypt(opts.algo, opts.key, util.bin2str(encrypted_data), false);
        expect(decrypted.join("")).equal(plaintext);
        done();
      });

      for (var i = 0; i < repetitions; i++) {
        cs.write(util.str2Uint8Array(plaintext_part));
      }

      cs.end();
    });
  });
});
