'use strict';

import { Transform } from 'stream';
import util from 'util';


export default function HeaderPacketStream(opts) {
  opts = opts || {};
  opts.objectMode = true;
  Transform.call(this, opts);
  this._headerWritten = false;
}

util.inherits(HeaderPacketStream, Transform);

HeaderPacketStream.prototype.getHeader = function() {};

HeaderPacketStream.prototype._transform = function() {
  if (!this._headerWritten) {
    this._headerWritten = true;
    var header = this.getHeader();
    if (header) { this.push(header); }
  }
};
