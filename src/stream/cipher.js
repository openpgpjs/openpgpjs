'use strict';

import { Transform } from 'stream';
import util from 'util';
import _util from '../util.js';

const Buffer = _util.getNativeBuffer();

export default CipherFeedbackStream;

function CipherFeedbackStream({ prefixrandom, cipherfn, sessionKey, cipherType, resync }) {
  Transform.call(this, { objectMode: true });
  this.prefixRandom = Buffer.from(prefixrandom, 'binary');

  this.cipherType = cipherType === 'binary' ? 'binary' : 'utf8';
  this.cipher = new cipherfn(sessionKey);
  this.sessionKey = sessionKey;
  this.resync = resync === undefined ? true : resync;

  this.blockSize = this.cipher.blockSize;
  this.feedbackRegister = Buffer.alloc(this.blockSize);
  this.feedbackRegisterEncrypted = Buffer.alloc(this.blockSize);

  this._firstBlockEncrypted = false;
  this._eof = false;
  this._previousCiphertext = Buffer.alloc(0);
  this._previousChunk = Buffer.alloc(0);

  this._buffer = Buffer.alloc(0);

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
  var chunkLength = chunk.length;

  prefixrandom = Buffer.concat([prefixrandom, Buffer.from([prefixrandom[this.blockSize - 2], prefixrandom[this.blockSize - 1]])]);
  var ciphertext = Buffer.alloc(chunkLength + 2 + this.blockSize * 2);
  var i;
  var offset = resync ? 0 : 2;

  // 1.  The feedback register (FR) is set to the IV, which is all zeros.
  this.feedbackRegister.fill(0, 0, this.blockSize);

  // 2.  FR is encrypted to produce FRE (FR Encrypted).  This is the
  //     encryption of an all-zero value.
  this.feedbackRegisterEncrypted = this.cipher.encrypt(this.feedbackRegister);
  // 3.  FRE is xored with the first BS octets of random data prefixed to
  //     the plaintext to produce C[1] through C[BS], the first BS octets
  //     of ciphertext.
  for (i = 0; i < this.blockSize; i++) {
    ciphertext[i] = this.feedbackRegisterEncrypted[i] ^ prefixrandom[i];
  }

  // 4.  FR is loaded with C[1] through C[BS].
  //this.feedbackRegister.set(ciphertext.slice(0, this.blockSize));
  ciphertext.copy(this.feedbackRegister, 0, 0, this.blockSize);

  // 5.  FR is encrypted to produce FRE, the encryption of the first BS
  //     octets of ciphertext.
  this.feedbackRegisterEncrypted = this.cipher.encrypt(this.feedbackRegister);

  // 6.  The left two octets of FRE get xored with the next two octets of
  //     data that were prefixed to the plaintext.  This produces C[BS+1]
  //     and C[BS+2], the next two octets of ciphertext.
  ciphertext[this.blockSize] = this.feedbackRegisterEncrypted[0] ^ prefixrandom[this.blockSize];
  ciphertext[this.blockSize + 1] = this.feedbackRegisterEncrypted[1] ^ prefixrandom[this.blockSize + 1];

  if (resync) {
    // 7.  (The resync step) FR is loaded with C[3] through C[BS+2].
    ciphertext.copy(this.feedbackRegister, 0, 2, this.blockSize + 2);
  } else {
    ciphertext.copy(this.feedbackRegister, 0, 0, this.blockSize);
  }
  // 8.  FR is encrypted to produce FRE.
  this.feedbackRegisterEncrypted = this.cipher.encrypt(this.feedbackRegister);

  // 9.  FRE is xored with the first BS octets of the given plaintext, now
  //     that we have finished encrypting the BS+2 octets of prefixed
  //     data.  This produces C[BS+3] through C[BS+(BS+2)], the next BS
  //     octets of ciphertext.
  for (i = 0; i < this.blockSize; i++) {
    ciphertext[this.blockSize + 2 + i] = this.feedbackRegisterEncrypted[i + offset] ^ chunk[i];
  }
  this._previousCiphertext = ciphertext.slice(this.blockSize + 2 - offset, 2*this.blockSize + 2 - offset);
  this._previousChunk = chunk;
  ciphertext = ciphertext.slice(0, chunk.length + 2 + this.blockSize - offset);
  return ciphertext;
};

CipherFeedbackStream.prototype._encryptBlock = function(chunk) {
  var chunkLength = chunk.length,
    ciphertext = Buffer.alloc(chunkLength + 2),
    offset = this.resync ? 0 : 2,
    i, n;
  for (n = 0; n < (chunkLength + offset); n += this.blockSize) {
    // 10. FR is loaded with C[BS+3] to C[BS + (BS+2)] (which is C11-C18 for
    // an 8-octet block).
    this._previousCiphertext.copy(this.feedbackRegister);

    // 11. FR is encrypted to produce FRE.
    this.feedbackRegisterEncrypted = this.cipher.encrypt(this.feedbackRegister);

    // 12. FRE is xored with the next BS octets of plaintext, to produce
    // the next BS octets of ciphertext. These are loaded into FR, and
    // the process is repeated until the plaintext is used up.
    for (i = 0; i < this.blockSize; i++) {
      var byte;
      if ((n + i - offset) < 0) {
        byte = this._previousChunk[this.blockSize + (n + i - offset)];
      } else {
        byte = chunk[n + i - offset];
      }
      ciphertext[n + i] = this.feedbackRegisterEncrypted[i] ^ byte;
    }
    this._previousCiphertext = ciphertext.slice(0, this.blockSize);
  }
  this._previousChunk = chunk;
  if (this._eof) {
    ciphertext = ciphertext.slice(0, chunkLength + offset);
  } else {
    ciphertext = ciphertext.slice(0, chunkLength);
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
  var block, offset = 0;
  this._buffer = Buffer.concat([this._buffer, chunk]);
  if (this._buffer.length >= this.blockSize) {
    while (this._buffer.length >= offset + this.blockSize) {
      block = this._buffer.slice(offset, offset + this.blockSize);
      this.push(this.encryptBlock(block));
      offset += this.blockSize;
    }
    this._buffer = this._buffer.slice(offset);
  }
  this.emit('encrypted', chunk);
  cb();
};

CipherFeedbackStream.prototype._flush = function(cb) {
  this._eof = true;
  this.push(this.encryptBlock(this._buffer));
  this.emit('flushed', null);
  cb();
};
