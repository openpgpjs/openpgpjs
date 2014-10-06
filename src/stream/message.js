var util = require('../util.js'),
  packet_stream = require('./packet.js'),
  crypto_stream = require('./crypto.js'),
  packet = require('../packet'),
  enums = require('../enums.js'),
  armor = require('../encoding/armor.js'),
  config = require('../config'),
  crypto = require('../crypto'),
  keyModule = require('../key.js'),
  message = require('../message.js');

function MessageStream(keys, file_length, filename, opts) {
  var self = this;
  filename = filename || 'msg.txt';
  filename = util.encode_utf8(filename);
  opts = opts || {};
  packet_stream.HeaderPacketStream.call(this, opts);

  opts['algo'] = enums.read(enums.symmetric, keyModule.getPreferredSymAlgo(keys));
  opts['key'] = crypto.generateSessionKey(opts['algo']);
  opts['cipherfn'] = crypto.cipher[opts['algo']];
  opts['prefixrandom'] = crypto.getPrefixRandom(opts['algo']);

  this.cipher = new crypto_stream.CipherFeedback(opts);
  this.fileLength = file_length;
  this.keys = keys;

  this._prefixWritten = false;
  this.prefix = Buffer(
    String.fromCharCode(enums.write(enums.literal, 'utf8')) + 
    String.fromCharCode(filename.length) +
    filename +
    util.writeDate(new Date()),
    'binary'
  )
  var prefix_header = new Buffer(packet.packet.writeHeader(enums.packet.literal, 
                                 this.prefix.length + this.fileLength), 'binary');
  this.prefix = Buffer.concat([
                  prefix_header,
                  this.prefix
  ]);

  this.cipher.on('data', function(data) {
    self.push(util.bin2str(data));
  });
}
util.inherits(MessageStream, packet_stream.HeaderPacketStream);

MessageStream.prototype.getHeader = function() {
  var that = this,
    packetList = new packet.List(),
    symAlgo = keyModule.getPreferredSymAlgo(this.keys);

  this.keys.forEach(function(key) {
    var encryptionKeyPacket = key.getEncryptionKeyPacket();
    if (encryptionKeyPacket) {
      var pkESKeyPacket = new packet.PublicKeyEncryptedSessionKey();
      pkESKeyPacket.publicKeyId = encryptionKeyPacket.getKeyId();
      pkESKeyPacket.publicKeyAlgorithm = encryptionKeyPacket.algorithm;
      pkESKeyPacket.sessionKey = that.cipher.sessionKey;
      pkESKeyPacket.sessionKeyAlgorithm = enums.read(enums.symmetric, symAlgo);
      pkESKeyPacket.encrypt(encryptionKeyPacket);
      packetList.push(pkESKeyPacket);
    } else {
      throw new Error('Could not find valid key packet for encryption in key ' + key.primaryKey.getKeyId().toHex());
    }
  });
  var packet_len = this.prefix.length + this.fileLength + this.cipher.blockSize + 2,
    first_packet_header = packet.packet.writeHeader(9, packet_len),
    header = packetList.write();

  return header + first_packet_header;
}

MessageStream.prototype._transform = function(chunk, encoding, cb) {
  packet_stream.HeaderPacketStream.prototype._transform.call(this, chunk, encoding);
  var self = this;
  chunk = new Buffer(chunk, 'binary');
  if (this.prefix) {
    chunk = Buffer.concat([this.prefix, chunk]);
    this.prefix = null;
  }
  this.cipher.once('encrypted', function(d) {
    cb();
  });
  this.cipher.write(chunk);
}

MessageStream.prototype._flush = function(cb) {
  this.cipher.once('flushed', function(d) {
    cb();
  });
  this.cipher.end();
}
module.exports.MessageStream = MessageStream;
