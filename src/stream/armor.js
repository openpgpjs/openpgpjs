'use strict';

import HeaderPacketStream from './header.js';
import armor from '../encoding/armor.js';
import base64 from '../encoding/base64.js';
import util from 'util';
import _util from '../util.js';

const Buffer = _util.getNativeBuffer();

const ARMOR_HEADER = '-----BEGIN PGP MESSAGE-----\r\n';
const ARMOR_FOOTER = '\r\n-----END PGP MESSAGE-----\r\n';
const BYTE_LENGTH = 60 * 3;

export default function ArmorStream(message_stream) {
  if (!message_stream) {
    throw new Error('Message Stream is required to armor');
  }
  HeaderPacketStream.call(this);
  this.queue = Buffer.alloc(0);

  // replace message_stream.push to armor before pushing
  var push = message_stream.push.bind(message_stream);
  message_stream.push = this._push.bind(this);
  this.on('data', function(data) {
    push(data);
  });
  this.on('end', function() {
    push(null);
  });

}

util.inherits(ArmorStream, HeaderPacketStream);

ArmorStream.prototype._push = function(data) {
  if (data) {
    this.write(data);
  } else {
    this.end();
  }
};

ArmorStream.prototype.getHeader = function() {
  return ARMOR_HEADER + armor.addheader();
};

ArmorStream.prototype._transform = function(chunk, enc, callback) {
  var asc, size, slice;
  HeaderPacketStream.prototype._transform.call(this, chunk, enc);

  this.checksum = armor.createcrc24(chunk, this.checksum ? this.checksum : undefined);
  chunk = Buffer.from(chunk, enc);
  this.queue = Buffer.concat([this.queue, chunk]);
  size = this.queue.length - (this.queue.length % BYTE_LENGTH);
  if (size) {
    slice = this.queue.slice(0, size);
    asc = base64.encode(slice);
    this.push(asc);
    this.queue = this.queue.slice(size);
  }
  callback();
};

ArmorStream.prototype._flush = function(callback) {
  if (this.queue.length) {
    var data = base64.encode(this.queue);
    if (data[data.length-1] !== '\n') {
      data += '\r\n';
    }
    this.push(data);
  }
  this.push(this.getCheckSum());
  this.push(ARMOR_FOOTER);
  callback();
};

ArmorStream.prototype.getCheckSum = function() {
  var c = this.checksum.toString();
  var str = "" + String.fromCharCode(c >> 16) +
    String.fromCharCode((c >> 8) & 0xFF) +
    String.fromCharCode(c & 0xFF);
  return '=' + base64.encode(Buffer.from(str, 'binary'));
};
