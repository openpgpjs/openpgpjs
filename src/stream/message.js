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
  if (config.integrity_protect) {
    var prefixrandom = opts['prefixrandom'];
    var prefix = prefixrandom + prefixrandom.charAt(prefixrandom.length - 2) + prefixrandom.charAt(prefixrandom.length - 1);
    opts['resync'] = false;
    this.hash = crypto.hash.forge_sha1.create();
    this.hash.update(prefix);
  }
  
  this.cipher = new crypto_stream.CipherFeedback(opts);
  this.fileLength = file_length;
  this.keys = keys;

  this.encrypted_packet_header = Buffer(
    String.fromCharCode(enums.write(enums.literal, 'utf8')) + 
    String.fromCharCode(filename.length) +
    filename +
    util.writeDate(new Date()),
    'binary'
  )
  this.encrypted_packet_header = Buffer.concat([
                  //new Buffer(String.fromCharCode(1)),
                  new Buffer(packet.packet.writeHeader(enums.packet.literal, 
                             this.encrypted_packet_header.length + this.fileLength), 'binary'),
                  this.encrypted_packet_header
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
  var packet_len = this.encrypted_packet_header.length + this.fileLength + this.cipher.blockSize + 2,
    header = packetList.write(),
    first_packet_header;

  if (config.integrity_protect) {
    packet_len += 2 + 20 + 1;
    first_packet_header = packet.packet.writeHeader(enums.packet.symEncryptedIntegrityProtected, packet_len) + String.fromCharCode(1);
  } else {
    first_packet_header = packet.packet.writeHeader(enums.packet.symmetricallyEncrypted, packet_len);
  }
  return header + first_packet_header;
}

MessageStream.prototype._transform = function(chunk, encoding, cb) {
  packet_stream.HeaderPacketStream.prototype._transform.call(this, chunk, encoding);
  chunk = new Buffer(chunk, 'binary');
  if (this.encrypted_packet_header) {
    chunk = Buffer.concat([this.encrypted_packet_header, chunk]);
    this.encrypted_packet_header = null;
  }
  this.cipher.once('encrypted', function(d) {
    cb();
  });
  if (config.integrity_protect) {
    this.hash.update(chunk.toString('binary'));
  }
  this.cipher.write(chunk);
}

MessageStream.prototype._flush = function(cb) {
  var self = this;
  this.cipher.once('flushed', function(d) {
    cb();
  });
  if (config.integrity_protect) {
    var mdc_header = String.fromCharCode(0xD3) + String.fromCharCode(0x14);
    this.hash.update(mdc_header);
    var hash_digest = this.hash.digest().getBytes();

    this.cipher.once('encrypted', function() {
      self.cipher.end();
    });
    this.cipher.write(
      new Buffer(mdc_header + hash_digest, 'binary')
    );
  } else {
    this.cipher.end();
  }
}
module.exports.MessageStream = MessageStream;
