'use strict';

import HeaderPacketStream from './header.js';
import ChunkedStream from './chunked.js';
import packet from '../packet';
import enums from '../enums';
import zlib from 'zlib';
import util from 'util';

export default function CompressionStream(opts) {
  var self = this;
  opts = opts || {};
  this.algorithm = opts.algorithm || enums.compression.uncompressed;
  HeaderPacketStream.call(this);

  // set up chunked stream
  this.chunkedStream = new ChunkedStream({
    header: Buffer.from(packet.packet.writeTag(enums.packet.compressed), 'binary')
  });

  this.chunkedStream.on('data', function(data) {
    self.push(Buffer.from(data, 'binary'));
  });

  // set up zip stream
  if (this.algorithm === enums.compression.uncompressed) {
    this.zip = this.chunkedStream;
  } else {
    switch(this.algorithm) {
      case enums.compression.zlib:
        this.zip = zlib.createDeflate();
        break;
      // case enums.compression.zip:
      default:
        this.zip = zlib.createDeflateRaw();
    }
    this.zip.on('data', function(data) {
      self.chunkedStream.write(data);
    });
    this.zip.on('end', function() {
      self.chunkedStream.end();
    });
  }
}

util.inherits(CompressionStream, HeaderPacketStream);

CompressionStream.prototype.getHeader = function() {
  this.chunkedStream.write(Buffer.from([this.algorithm]));
};

CompressionStream.prototype._transform = function(chunk, encoding, callback) {
  HeaderPacketStream.prototype._transform.call(this, chunk, encoding);
  this.zip.write(chunk);
  callback();
};

CompressionStream.prototype._flush = function(callback) {
  this.chunkedStream.once('end', callback);
  this.zip.end();
};
