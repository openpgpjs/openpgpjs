'use strict';

var openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../dist/openpgp');

var enums = openpgp.enums,
  crypto = openpgp.crypto,
  util = openpgp.util;


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
  var opts, plaintext;
  beforeEach(function() {
    opts = {};
    opts.algo = enums.read(enums.symmetric, enums.symmetric.aes256);
    opts.sessionKey = crypto.generateSessionKey(opts.algo);
    opts.cipherfn = crypto.cipher[opts.algo];
    opts.prefixrandom = crypto.getPrefixRandom(opts.algo);
    opts.resync = true;

    plaintext = [
      'This is the end,',
      'my only friend,',
      'the end.'
    ];
  });

  function cipher(done) {

    var encrypted_data = new Uint8Array([]);
    var cs = new openpgp.stream.CipherFeedbackStream(opts);

    cs.on('data', function(d) {
      encrypted_data = util.concatUint8Array([encrypted_data, bto8(d)]);
    }).on('end', function() {
      var decrypted = Buffer.from(crypto.cfb.decrypt(opts.algo, opts.sessionKey, encrypted_data, opts.resync), 'binary').toString('binary');
      done(encrypted_data, decrypted);
    });

    return cs;
  }

  it('works when calling write once', function(done) {
    var text = plaintext.join('');
    var cs = cipher(function(encrypted_data, decrypted) {
      expect(decrypted).equal(text);
      expect(encrypted_data.length).equal(cs.blockSize + text.length + 2);
      done();
    });
    cs.write(plaintext[0]+plaintext[1]);
    cs.end(plaintext[2]);
  });

  it('decrypts when calling write multiple times', function(done) {
    var text = plaintext.join('');
    var cs = cipher(function(encrypted_data, decrypted) {
      expect(decrypted).equal(text);
      expect(encrypted_data.length).equal(cs.blockSize + text.length + 2);
      done();
    });
    cs.write(plaintext[0]);
    cs.write(plaintext[1]);
    cs.end(plaintext[2]);
  });

  it('decrypts when calling write and end with null', function(done) {
    var text = plaintext.join('');
    var cs = cipher(function(encrypted_data, decrypted) {
      expect(decrypted).equal(text);
      expect(encrypted_data.length).equal(cs.blockSize + text.length + 2);
      done();
    });
    cs.write(text);
    cs.end();
  });

  it('works on UTF-8 characters', function(done) {
    var text = "实事求是。";
    var cs = cipher(function(encrypted_data, decrypted) {
      expect(util.decode_utf8(decrypted)).equal(text);
      expect(encrypted_data.length).equal(cs.blockSize + (Buffer.from(text)).length + 2);
      done();
    });
    cs.write(text);
    cs.end();
  });

  it('works on byte buffers', function(done) {
    opts.cipherType = 'binary';
    var buffer = Buffer.from([0x81, 0x02, 0xcc, 0x86, 0x92, 0xA9]);
    var cs = cipher(function(encrypted_data, decrypted) {
      expect(Buffer.from(decrypted, 'binary').equals(buffer)).to.equal(true);
      expect(encrypted_data.length).equal(cs.blockSize + (buffer.length + 2));
      done();
    });
    cs.write(buffer);
    cs.end();
  });

  it('works with resync set to false', function(done) {
    opts.resync = false;
    var text = plaintext.join('');
    var cs = cipher(function(encrypted_data, decrypted) {
      expect(decrypted).to.equal(text);
      expect(encrypted_data.length).equal(cs.blockSize + text.length + 2);
      done();
    });
    cs.write(text);
    cs.end();
  });

});
