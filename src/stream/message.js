'use strict';

import _util from '../util.js';
import HeaderPacketStream from './header';
import CipherFeedbackStream from './cipher';
import packet from '../packet';
import enums from '../enums';
import config from '../config';
import crypto from '../crypto';
import ArmorStream from './armor';
import Signature from './signature';
import * as keyModule from '../key.js';
import ChunkedStream from './chunked.js';
import CompressionStream from './compression.js';
import util from 'util';
import nodeCrypto from 'crypto';

const Buffer = _util.getNativeBuffer();

export default function MessageStream(keys, opts) {

  var self = this;

  opts = opts || {};
  HeaderPacketStream.call(this, opts);

  this.filename = _util.encode_utf8(opts.filename || '');
  this.privateKeys = opts.privateKeys;
  this.passwords = opts.passwords;
  opts.algo = enums.read(enums.symmetric, keyModule.getPreferredSymAlgo(keys));
  this.algo = opts.algo;
  opts.key = crypto.generateSessionKey(opts.algo);
  opts.cipherfn = crypto.cipher[opts.algo];
  opts.prefixrandom = Buffer.from(crypto.getPrefixRandom(opts.algo));
  opts.cipherType = 'binary';
  opts.chunks = opts.chunks || 1;

  let prefix;
  if (config.integrity_protect) {
    var prefixrandom = opts.prefixrandom;
    const repeat = Buffer.from([prefixrandom[prefixrandom.length - 2], prefixrandom[prefixrandom.length - 1]]);
    prefix = Buffer.concat([prefixrandom, repeat]);
    opts.resync = false;
    this.hash = nodeCrypto.createHash('sha1');
    this.hash.update(prefix);
  }

  this.encryptedPacket = new ChunkedStream({
    header: config.integrity_protect ?
      Buffer.from(packet.packet.writeTag(enums.packet.symEncryptedIntegrityProtected), 'binary') :
      Buffer.from(packet.packet.writeTag(enums.packet.symmetricallyEncrypted), 'binary')
  });

  this.literalPacket = new ChunkedStream({
    header: Buffer.from(packet.packet.writeTag(enums.packet.literal), 'binary')
  });

  this.cipher = new CipherFeedbackStream(opts);
  this.keys = keys;

  if (opts.armor) {
    this.armor = new ArmorStream(this);
  }

  if (opts.privateKeys) {
    this.signature = new Signature(opts.privateKeys);
  }

  this.encryptedPacket.on('data', function(data) {
    self.push(data);
  });

  this.literalPacket.once('end', function() {
    if (self.signature) {
      var write = self.compressionPacket ? self.compressionPacket.write.bind(self.compressionPacket) : self.cipher.write.bind(self.cipher);
      write(self.signature.signaturePackets());
    }
  });

  if (opts.compression) {
    this.compressionPacket = new CompressionStream({ algorithm: enums.write(enums.compression, opts.compression === true ? 'zip' : opts.compression) });
    this.compressionPacket.on('data', function(data) {
      self.cipher.write(Buffer.from(data));
    });
    this.dataPacket = this.compressionPacket;
    this.literalPacket.on('data', function(data) {
      self.compressionPacket.write(data);
    });
    this.literalPacket.on('end', function() {
      self.compressionPacket.end();
    });
  } else {
    this.literalPacket.on('data', function(data) {
      self.cipher.write(Buffer.from(data));
    });
    this.dataPacket = this.literalPacket;
  }


  if (config.integrity_protect) {
    var _cipherwrite = this.cipher.write.bind(this.cipher);
    self._all = Buffer.from(prefix);
    this.cipher.write = function(data) {
      var chunk;
      if (Buffer.isBuffer(data)) {
        chunk = Buffer.from(data);
      } else {
        chunk = Buffer.from(data, 'binary');
      }
      if (!self.ended) {
        self.hash.update(chunk);
      }
      _cipherwrite(chunk);
    };
    /*var _cipherend = this.cipher.end.bind(this.cipher);
    this.cipher.end = function() {
      var chunks = Math.floor(self.all.length / opts.chunks );
      var i;
      for(i = 0; i < chunks - 1; i++) {
        _cipherwrite(self.all.slice(i*chunks, (i+1)*chunks));
      }
      i++;
      _cipherwrite(self.all.slice(i*chunks));
      _cipherend();
    };*/
  }

  this.cipher.on('data', function(data) {
    self.encryptedPacket.write(data);
  });
}

util.inherits(MessageStream, HeaderPacketStream);

MessageStream.prototype.push = function(data, encoding) {
  if (data) {
    HeaderPacketStream.prototype.push.call(this, Buffer.from(data), encoding);
  } else {
    HeaderPacketStream.prototype.push.call(this, null);
  }
};

MessageStream.prototype.literalPacketHeader = function() {
  return Buffer.concat([
    Buffer.from([enums.write(enums.literal, 'utf8'), this.filename.length]),
    Buffer.from(this.filename),
    Buffer.from(_util.writeDate(new Date()))
  ]);
};

MessageStream.prototype.sessionKeyPackets = function() {
  var that = this,
    packetList = new packet.List();

  // write session key packets
  this.keys.forEach(function(key) {
    var encryptionKeyPacket = key.getEncryptionKeyPacket();
    if (encryptionKeyPacket) {
      var pkESKeyPacket = new packet.PublicKeyEncryptedSessionKey();
      pkESKeyPacket.publicKeyId = encryptionKeyPacket.getKeyId();
      pkESKeyPacket.publicKeyAlgorithm = encryptionKeyPacket.algorithm;
      pkESKeyPacket.sessionKey = that.cipher.sessionKey;
      pkESKeyPacket.sessionKeyAlgorithm = that.algo;
      pkESKeyPacket.encrypt(encryptionKeyPacket);
      delete pkESKeyPacket.sessionKey; // delete plaintext session key after encryption
      packetList.push(pkESKeyPacket);
    } else {
      throw new Error('Could not find valid key packet for encryption in key ' + key.primaryKey.getKeyId().toHex());
    }
  });
  return Buffer.from(packetList.write());
};

MessageStream.prototype.getHeader = function() {

  // write session key packets
  this.push(this.sessionKeyPackets());

  // write encryption-type packet header
  if (config.integrity_protect) {
    // integrity protection starts with a 1 after the length header, and the
    // length header is only written after some streaming is done
    this.encryptedPacket.write(Buffer.from([1]));
  }

  // write the one-pass signature packet,
  // which is now a subpacket of the encryption packet
  if (this.signature) {
    // some strange hack to add a marker packet so modification detection
    // doesn't fail
    var write = this.compressionPacket ? this.compressionPacket.write.bind(this.compressionPacket) : this.cipher.write.bind(this.cipher);
    write(Buffer.from(packet.packet.writeHeader(enums.packet.marker, 0), 'binary'));
    write(this.signature.onePassSignaturePackets());
  }

  // write the encrypted packet header inside the literal packet content
  this.literalPacket.write(this.literalPacketHeader());

};

MessageStream.prototype._transform = function(chunk, encoding, callback) {
  var data = Buffer.from(chunk, encoding);
  HeaderPacketStream.prototype._transform.call(this, data);
  if (this.signature) {
    this.signature.update(data);
  }
  this.literalPacket.write(data);
  callback();
};

MessageStream.prototype._flush = function(cb) {
  var self = this;
  this.cipher.once('flushed', function() {
    self.encryptedPacket.end();
    cb();
  });

  this.dataPacket.once('end', function() {
    if (config.integrity_protect) {
      var mdc_header = Buffer.from([0xD3, 0x14]);
      self.hash.update(mdc_header);
      var hash_digest = self.hash.digest();
      self.ended = true;
      self.cipher.write(Buffer.concat([mdc_header, Buffer.from(hash_digest)]));
    }
    self.cipher.end();
  });
  this.literalPacket.end();
};
