'use strict';

var openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../dist/openpgp');

var enums = openpgp.enums,
  crypto = openpgp.crypto,
  util = openpgp.util,
  config = openpgp.config;


var chai = require('chai'),
	expect = chai.expect;

var bto8 = function(buffer) {
  var len = buffer.length;
  var arr = new Uint8Array(len);
  for (var i = 0; i < len; i++) {
    arr[i] = buffer[i];
  }
  return arr;
};

describe('CFB Stream', function() {

  it('should work when calling write once', function(done) {
    var opts = {};
    opts.algo = enums.read(enums.symmetric, enums.symmetric.aes256);
    opts.key = crypto.generateSessionKey(opts.algo);
    opts.cipherfn = crypto.cipher[opts.algo];
    opts.prefixrandom = crypto.getPrefixRandom(opts.algo);

    var plaintext_a = 'This is the end,';
    var plaintext_b = 'my only friend,';
    var plaintext_c = 'the end.';

    var encrypted_data = new Uint8Array([]);
    var cs = new openpgp.stream.CipherFeedbackStream(opts);

    cs.on('data', function(d) {
      encrypted_data = util.concatUint8Array([encrypted_data, bto8(d)]);
    });

    cs.on('end', function(d) {
      var decrypted = util.bin2str(crypto.cfb.decrypt(opts.algo, opts.key,
                                         encrypted_data, true));
      expect(decrypted).equal(plaintext_a+plaintext_b+plaintext_c);
      expect(encrypted_data.length).equal(cs.blockSize + (plaintext_a+plaintext_b+plaintext_c).length + 2);
      cs = undefined;
      done();
    });
    cs.write(plaintext_a+plaintext_b);
    cs.end(plaintext_c);

  });

  it('should decrypt when calling write multiple times', function(done) {
    var opts = {};
    opts['algo'] = enums.read(enums.symmetric, enums.symmetric.aes256);
    opts['key'] = crypto.generateSessionKey(opts['algo']);
    opts['cipherfn'] = crypto.cipher[opts['algo']];
    opts['prefixrandom'] = crypto.getPrefixRandom(opts['algo']);

    var plaintext_a = 'This is the end,';
    var plaintext_b = 'my only friend,';
    var plaintext_c = 'the end.';

    var encrypted_data = new Uint8Array([]);
    var cs = new openpgp.stream.CipherFeedbackStream(opts);

    cs.on('data', function(d) {
      encrypted_data = util.concatUint8Array([encrypted_data, bto8(d)]);
    });

    cs.on('end', function(d) {
      var decrypted = util.bin2str(crypto.cfb.decrypt(opts['algo'], opts['key'],
                                         encrypted_data, true));
      expect(decrypted).equal(plaintext_a+plaintext_b+plaintext_c);
      expect(encrypted_data.length).equal(cs.blockSize + (plaintext_a+plaintext_b+plaintext_c).length + 2);
      done();
    });
    cs.write(plaintext_a);
    cs.write(plaintext_b);
    cs.end(plaintext_c);

  });

  it("should decrypt when calling write and end with null", function(done) {
    var opts = {};
    opts['algo'] = enums.read(enums.symmetric, enums.symmetric.aes256);
    opts['key'] = crypto.generateSessionKey(opts['algo']);
    opts['cipherfn'] = crypto.cipher[opts['algo']];
    opts['prefixrandom'] = crypto.getPrefixRandom(opts['algo']);

    var plaintext_a = "This is the end,";
    var plaintext_b = "my only friend,";
    var plaintext_c = "the end.";

    var encrypted_data = new Uint8Array([]);
    var cs = new openpgp.stream.CipherFeedbackStream(opts);

    cs.on('data', function(d) {
      encrypted_data = util.concatUint8Array([encrypted_data, bto8(d)]);
    });

    cs.on('end', function(d) {
      var decrypted = util.bin2str(crypto.cfb.decrypt(opts['algo'], opts['key'],
                                         encrypted_data, true));
      expect(decrypted).equal(plaintext_a+plaintext_b+plaintext_c);
      expect(encrypted_data.length).equal(cs.blockSize + (plaintext_a+plaintext_b+plaintext_c).length + 2);
      done();
    });
    cs.write(plaintext_a+plaintext_b+plaintext_c);
    cs.end();

  });

  it("should work on UTF-8 characters", function(done) {
    var opts = {};
    opts['algo'] = enums.read(enums.symmetric, enums.symmetric.aes256);
    opts['key'] = crypto.generateSessionKey(opts['algo']);
    opts['cipherfn'] = crypto.cipher[opts['algo']];
    opts['prefixrandom'] = crypto.getPrefixRandom(opts['algo']);

    var plaintext_a = "实事求是。";
    var encrypted_data = new Uint8Array([]);
    var cs = new openpgp.stream.CipherFeedbackStream(opts);

    cs.on('data', function(d) {
      encrypted_data = util.concatUint8Array([encrypted_data, bto8(d)]);
    });

    cs.on('end', function(d) {
      var decrypted = util.bin2str(crypto.cfb.decrypt(opts['algo'], opts['key'],
                                         encrypted_data, true));
      expect(util.decode_utf8(decrypted)).equal(plaintext_a);
      expect(encrypted_data.length).equal(cs.blockSize + (Buffer.from(plaintext_a)).length + 2);
      done();
    });
    cs.write(plaintext_a);
    cs.end();

  });

  it("should work on byte buffers", function(done) {
    var opts = {};
    opts['algo'] = enums.read(enums.symmetric, enums.symmetric.aes256);
    opts['key'] = crypto.generateSessionKey(opts['algo']);
    opts['cipherfn'] = crypto.cipher[opts['algo']];
    opts['cipherType'] = 'binary';
    opts['prefixrandom'] = crypto.getPrefixRandom(opts['algo']);

    var buffer_a = Buffer.from([0x81, 0x02, 0xcc, 0x86, 0x92, 0xA9]);
    var encrypted_data = new Uint8Array([]);
    var cs = new openpgp.stream.CipherFeedbackStream(opts);

    cs.on('data', function(d) {
      encrypted_data = util.concatUint8Array([encrypted_data, bto8(d)]);
    });

    cs.on('end', function(d) {
      var decrypted = Buffer.from(crypto.cfb.decrypt(opts['algo'], opts['key'],
                                         encrypted_data, true));
      expect(decrypted.equals(buffer_a)).to.equal(true);
      expect(encrypted_data.length).equal(cs.blockSize + (buffer_a.length + 2));
      done();
    });
    cs.write(buffer_a);
    cs.end();

  });

  it("should work with resync set to false", function(done) {
    var opts = {};
    opts['algo'] = enums.read(enums.symmetric, enums.symmetric.aes256);
    opts['key'] = crypto.generateSessionKey(opts['algo']);
    opts['cipherfn'] = crypto.cipher[opts['algo']];
    opts['prefixrandom'] = crypto.getPrefixRandom(opts['algo']);
    opts['resync'] = false;

    var plaintext_a = "This is the end,";
    var plaintext_b = "my only friend,";
    var plaintext_c = "the end.";

    var encrypted_data = new Uint8Array([]);
    var cs = new openpgp.stream.CipherFeedbackStream(opts);

    cs.on('data', function(d) {
      encrypted_data = util.concatUint8Array([encrypted_data, bto8(d)]);
    });

    cs.on('end', function(d) {
      var decrypted = Buffer.from(crypto.cfb.decrypt(opts['algo'], opts['key'],
                                         encrypted_data, false), 'binary').toString('binary');
      expect(decrypted).equal(plaintext_a+plaintext_b+plaintext_c);
      expect(encrypted_data.length).equal(cs.blockSize + (plaintext_a+plaintext_b+plaintext_c).length + 2);
      done();
    });
    cs.write(plaintext_a+plaintext_b+plaintext_c);
    cs.end();

  });

});
