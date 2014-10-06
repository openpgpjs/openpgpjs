'use strict';

var util = require('../util'),
  stream = require('stream');

function CipherFeedback(opts) {
  stream.Transform.call(this, opts);
  this.prefixRandom = opts.prefixrandom;
  //crypto.getPrefixRandom(this.algo);
  this.cipher = new opts.cipherfn(opts.key);
  this.sessionKey = opts.key;
  this.resync = opts.resync || true;

  this.blockSize = this.cipher.blockSize;
  this.feedbackRegister = new Uint8Array(this.blockSize);
  this.feedbackRegisterEncrypted = new Uint8Array(this.blockSize);

  this._firstBlockEncrypted = false;
  this._previousChunk = new Uint8Array();

  //(prefixrandom, cipher, plaintext, key, resync)
  this._buffer = new Buffer(this.blockSize);
  this._offset = 0;
}
util.inherits(CipherFeedback, stream.Transform);

CipherFeedback.prototype._encryptFirstBlock = function(chunk) {
  var prefixrandom = this.prefixRandom;
  var resync = this.resync;
  var key = this.sessionKey;
  var block_size = this.blockSize;

  prefixrandom = prefixrandom + prefixrandom.charAt(block_size - 2) + prefixrandom.charAt(block_size - 1);
  var ciphertext = new Uint8Array(chunk.length + 2 + block_size * 2);
  var i, n, begin;
  var offset = resync ? 0 : 2;

  // 1.  The feedback register (FR) is set to the IV, which is all zeros.
  for (i = 0; i < block_size; i++) {
    this.feedbackRegister[i] = 0;
  }

  // 2.  FR is encrypted to produce FRE (FR Encrypted).  This is the
  //     encryption of an all-zero value.
  this.feedbackRegisterEncrypted = this.cipher.encrypt(this.feedbackRegister);
  // 3.  FRE is xored with the first BS octets of random data prefixed to
  //     the plaintext to produce C[1] through C[BS], the first BS octets
  //     of ciphertext.
  for (i = 0; i < block_size; i++) {
    ciphertext[i] = this.feedbackRegisterEncrypted[i] ^ prefixrandom.charCodeAt(i);
  }

  // 4.  FR is loaded with C[1] through C[BS].
  this.feedbackRegister.set(ciphertext.subarray(0, block_size));

  // 5.  FR is encrypted to produce FRE, the encryption of the first BS
  //     octets of ciphertext.
  this.feedbackRegisterEncrypted = this.cipher.encrypt(this.feedbackRegister);

  // 6.  The left two octets of FRE get xored with the next two octets of
  //     data that were prefixed to the plaintext.  This produces C[BS+1]
  //     and C[BS+2], the next two octets of ciphertext.
  ciphertext[block_size] = this.feedbackRegisterEncrypted[0] ^ prefixrandom.charCodeAt(block_size);
  ciphertext[block_size + 1] = this.feedbackRegisterEncrypted[1] ^ prefixrandom.charCodeAt(block_size + 1);

  if (resync) {
    // 7.  (The resync step) FR is loaded with C[3] through C[BS+2].
    this.feedbackRegister.set(ciphertext.subarray(2, block_size + 2));
  } else {
    this.feedbackRegister.set(ciphertext.subarray(0, block_size));
  }
  // 8.  FR is encrypted to produce FRE.
  this.feedbackRegisterEncrypted = this.cipher.encrypt(this.feedbackRegister);

  // 9.  FRE is xored with the first BS octets of the given plaintext, now
  //     that we have finished encrypting the BS+2 octets of prefixed
  //     data.  This produces C[BS+3] through C[BS+(BS+2)], the next BS
  //     octets of ciphertext.
  for (i = 0; i < block_size; i++) {
    ciphertext[block_size + 2 + i] = this.feedbackRegisterEncrypted[i + offset] ^ chunk[i];
  }
  this._previousChunk = ciphertext.subarray(block_size + 2 - offset, 2*block_size + 2 - offset);
  ciphertext = ciphertext.subarray(0, chunk.length + 2 + block_size);
  return ciphertext;
}

CipherFeedback.prototype._encryptBlock = function(chunk) {
  var ciphertext = new Uint8Array(chunk.length),
    block_size = this.blockSize,
    i, n, begin;
  for (n = 0; n < chunk.length; n += block_size) {
    // 10. FR is loaded with C[BS+3] to C[BS + (BS+2)] (which is C11-C18 for
    // an 8-octet block).
    this.feedbackRegister.set(this._previousChunk);

    // 11. FR is encrypted to produce FRE.
    this.feedbackRegisterEncrypted = this.cipher.encrypt(this.feedbackRegister);

    // 12. FRE is xored with the next BS octets of plaintext, to produce
    // the next BS octets of ciphertext. These are loaded into FR, and
    // the process is repeated until the plaintext is used up.
    for (i = 0; i < block_size; i++) {
      ciphertext[n + i] = this.feedbackRegisterEncrypted[i] ^ chunk[n + i];
    }
    this._previousChunk = ciphertext.subarray(n, n + block_size);
  }
  return ciphertext.subarray(0, chunk.length);
}

CipherFeedback.prototype.encryptBlock = function(chunk) {
  var ciphertext;
  if (!this._firstBlockEncrypted) {
    ciphertext = this._encryptFirstBlock(chunk);
    this._firstBlockEncrypted = true;
  } else {
    ciphertext = this._encryptBlock(chunk);
  }
  var buffer = new Buffer(ciphertext.length, 'binary');
  for (var i = 0; i < ciphertext.length; i++) {
    buffer[i] = ciphertext[i];
  }
  return buffer;
};

CipherFeedback.prototype._transform = function(chunk, encoding, cb) {
  var availableIn = chunk && chunk.length || 0;
  if (availableIn + this._offset + 1 < this.blockSize) {
    chunk.copy(this._buffer, this._offset);
    this._offset += availableIn;
  } else {
    var block = this._buffer.slice(0, this._offset);
    var needed = this.blockSize - block.length;
    var chunkOffset = 0;
    if (needed === 0) {
      var encrypted = this.encryptBlock(block);
      this.push(encrypted);
    }
    while (availableIn > needed && needed > 0) {
      block = Buffer.concat([block, 
                            chunk.slice(chunkOffset, chunkOffset + needed)]);
      chunkOffset += needed;
      this.push(this.encryptBlock(block));
      availableIn -= needed;
      needed = this.blockSize;
      block = new Buffer([], 'binary');
    }
    this._offset = availableIn;
    chunk.slice(chunkOffset).copy(this._buffer);
  }
  this.emit('encrypted', chunk);
  cb();
}

CipherFeedback.prototype._flush = function(cb) {
  var block = this._buffer.slice(0, this._offset);
  this.push(this.encryptBlock(block));
  this.emit('flushed', null);
  cb();
}

module.exports.CipherFeedback = CipherFeedback;
