'use strict';

import { Transform } from 'stream';
import util from 'util';
import _util from '../util.js';

const Buffer = _util.getNativeBuffer();

export default CipherFeedbackStream;

function CipherFeedbackStream(opts) {
  Transform.call(this, opts);
  this.prefixRandom = Buffer.from(opts.prefixrandom, 'binary');

  this.cipherType = opts.cipherType === 'binary' ? 'binary' : 'utf8';
  this.cipher = new opts.cipherfn(opts.key);
  this.sessionKey = opts.key;
  if (opts.resync === undefined) {
    opts.resync = true;
  }
  this.resync = opts.resync;

  this.blockSize = this.cipher.blockSize;
  this.feedbackRegister = Buffer.alloc(this.blockSize);
  this.feedbackRegisterEncrypted = Buffer.alloc(this.blockSize);

  this._firstBlockEncrypted = false;
  this._eof = false;
  this._previousCiphertext = Buffer.alloc(0);
  this._previousChunk = Buffer.alloc(0);

  this._buffer = Buffer.alloc(0);
  this._offset = 0;

}

util.inherits(CipherFeedbackStream, Transform);

CipherFeedbackStream.prototype.write = function(data) {
  if (!Buffer.isBuffer(data)) {
    data = Buffer.from(data, this.cipherType);
  }
  Transform.prototype.write.call(this, data);
};

CipherFeedbackStream.prototype._encryptFirstBlock = function(chunk) {
  var prefixrandom = this.prefixRandom;
  var resync = this.resync;
  var block_size = this.blockSize;
  var chunkLength = chunk.length;

  prefixrandom = Buffer.concat([prefixrandom, Buffer.from([prefixrandom[block_size - 2], prefixrandom[block_size - 1]])]);
  var ciphertext = Buffer.alloc(chunkLength + 2 + block_size * 2);
  var i;
  var offset = resync ? 0 : 2;

  // 1.  The feedback register (FR) is set to the IV, which is all zeros.
  this.feedbackRegister.fill(0, 0, block_size);

  // 2.  FR is encrypted to produce FRE (FR Encrypted).  This is the
  //     encryption of an all-zero value.
  this.feedbackRegisterEncrypted = this.cipher.encrypt(this.feedbackRegister);
  // 3.  FRE is xored with the first BS octets of random data prefixed to
  //     the plaintext to produce C[1] through C[BS], the first BS octets
  //     of ciphertext.
  for (i = 0; i < block_size; i++) {
    ciphertext[i] = this.feedbackRegisterEncrypted[i] ^ prefixrandom[i];
  }

  // 4.  FR is loaded with C[1] through C[BS].
  //this.feedbackRegister.set(ciphertext.slice(0, block_size));
  ciphertext.copy(this.feedbackRegister, 0, 0, block_size);

  // 5.  FR is encrypted to produce FRE, the encryption of the first BS
  //     octets of ciphertext.
  this.feedbackRegisterEncrypted = this.cipher.encrypt(this.feedbackRegister);

  // 6.  The left two octets of FRE get xored with the next two octets of
  //     data that were prefixed to the plaintext.  This produces C[BS+1]
  //     and C[BS+2], the next two octets of ciphertext.
  ciphertext[block_size] = this.feedbackRegisterEncrypted[0] ^ prefixrandom[block_size];
  ciphertext[block_size + 1] = this.feedbackRegisterEncrypted[1] ^ prefixrandom[block_size + 1];

  if (resync) {
    // 7.  (The resync step) FR is loaded with C[3] through C[BS+2].
    ciphertext.copy(this.feedbackRegister, 0, 2, block_size + 2);
  } else {
    ciphertext.copy(this.feedbackRegister, 0, 0, block_size);
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
  this._previousCiphertext = Buffer.from(ciphertext.slice(block_size + 2 - offset, 2*block_size + 2 - offset));
  this._previousChunk = Buffer.from(chunk);
  ciphertext = Buffer.from(ciphertext.slice(0, chunk.length + 2 + block_size - offset));
  return ciphertext;
};

CipherFeedbackStream.prototype._encryptBlock = function(chunk) {
  var chunkLength = chunk.length,
    ciphertext = Buffer.alloc(chunkLength + 2),
    block_size = this.blockSize,
    offset = this.resync ? 0 : 2,
    i, n, begin;
  for (n = 0; n < (chunkLength + offset); n += block_size) {
    begin = n;
    // 10. FR is loaded with C[BS+3] to C[BS + (BS+2)] (which is C11-C18 for
    // an 8-octet block).
    this._previousCiphertext.copy(this.feedbackRegister);

    // 11. FR is encrypted to produce FRE.
    this.feedbackRegisterEncrypted = this.cipher.encrypt(this.feedbackRegister);

    // 12. FRE is xored with the next BS octets of plaintext, to produce
    // the next BS octets of ciphertext. These are loaded into FR, and
    // the process is repeated until the plaintext is used up.
    for (i = 0; i < block_size; i++) {
      var byte;
      if ((n + i - offset) < 0) {
        byte = this._previousChunk[block_size + (n + i - offset)];
      } else {
        byte = chunk[n + i - offset];
      }
      ciphertext[begin + i] = this.feedbackRegisterEncrypted[i] ^ byte;
    }
    this._previousCiphertext = Buffer.from(ciphertext.slice(0, chunkLength));
  }
  this._previousChunk = Buffer.from(chunk);
  if (this._eof) {
    ciphertext = Buffer.from(ciphertext.slice(0, chunkLength + offset));
  } else {
    ciphertext = Buffer.from(ciphertext.slice(0, chunkLength));
  }
  return ciphertext;
};

CipherFeedbackStream.prototype.encryptBlock = function(chunk) {
  var ciphertext;
  if (!this._firstBlockEncrypted) {
    ciphertext = this._encryptFirstBlock(chunk);
    this._firstBlockEncrypted = true;
  } else {
    ciphertext = this._encryptBlock(chunk);
  }
  return ciphertext;
};

CipherFeedbackStream.prototype._transform = function(chunk, encoding, cb) {
  chunk = Buffer.from(chunk, encoding);
  var block;
  this._buffer = Buffer.concat([this._buffer, chunk]);
  if (this._buffer.length >= this.blockSize) {
    while (this._buffer.length >= this.blockSize) {
      block = Buffer.from(this._buffer.slice(0, this.blockSize));
      this.push(this.encryptBlock(block));
      this._buffer = this._buffer.slice(this.blockSize);
    }
  }
  this.emit('encrypted', chunk);
  cb();
};

CipherFeedbackStream.prototype._flush = function(cb) {
  this._eof = true;
  if (this._buffer.length) {
    this.push(this.encryptBlock(this._buffer));
  }
  this.emit('flushed', null);
  cb();
};
