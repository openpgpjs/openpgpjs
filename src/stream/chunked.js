'use strict';

import packet from '../packet';
import { Transform } from 'stream';
import util from 'util';

export default function ChunkedStream(opts) {
  Transform.call(this, opts);
  this.queue = Buffer.alloc(0);
  this.started = false;
}

util.inherits(ChunkedStream, Transform);

ChunkedStream.prototype._transform = function(data, encoding, callback) {
  this.queue = Buffer.concat([this.queue, data]);
  var len = this.queue.length;
  if (len >= 512 || this.started) {
    this.started = true;
    var chunkPower = len.toString(2).length - 1;
    if (chunkPower > 30) { chunkPower = 30; }
    var chunkSize = Math.pow(2, chunkPower),
        chunk = this.queue.slice(0, chunkSize);
    this.queue = this.queue.slice(chunkSize);
    this.push(Buffer.concat([Buffer.from(packet.packet.writePartialLength(chunkPower), 'binary'), chunk]));
  }
  callback();
};

ChunkedStream.prototype._flush = function(callback) {
  var chunk = Buffer.from(this.queue);
  this.queue = Buffer.alloc(0);
  this.push(Buffer.concat([Buffer.from(packet.packet.writeSimpleLength(chunk.length), 'binary'), chunk]));
  this.ended = true;
  callback();
};
