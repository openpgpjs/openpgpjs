var util = require('util'),
  stream = require('stream');

function HeaderPacketStream(opts) {
  stream.Transform.call(this, opts);
  this._headerWritten = false;
}
util.inherits(HeaderPacketStream, stream.Transform);

HeaderPacketStream.prototype.getHeader = function() {}
HeaderPacketStream.prototype._transform = function(chunk, encoding, cb) {
  if (!this._headerWritten) {
    this._headerWritten = true; 
    var header = this.getHeader();
    if (header) this.push(header);
  }
}

module.exports.HeaderPacketStream = HeaderPacketStream
