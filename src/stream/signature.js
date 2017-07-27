'use strict';

import enums from '../enums.js';
import crypto from '../crypto';
import config from '../config';
import packet from '../packet';


export default class Signature {

  constructor(privateKeys) {
    this.privateKeys = privateKeys || [];
    this.hash = crypto.hash.forge_sha256.create();
  }

  update(data) {
    if (typeof data !== 'string') {
      data = data.toString('binary');
    }
    this.hash.update(data);
  }

  onePassSignaturePackets() {
    var packetList = new packet.List();
    for (var i = 0; i < this.privateKeys.length; i++) {
      if (this.privateKeys[i].isPublic()) {
        throw new Error('Need private key for signing');
      }
      var onePassSig = new packet.OnePassSignature();
      onePassSig.type = enums.signature.binary;
      //TODO get preferred hash algo from key signature
      onePassSig.hashAlgorithm = config.prefer_hash_algorithm;
      var signingKeyPacket = this.privateKeys[i].getSigningKeyPacket();
      if (!signingKeyPacket) {
        throw new Error('Could not find valid key packet for signing in key ' + this.privateKeys[i].primaryKey.getKeyId().toHex());
      }
      onePassSig.publicKeyAlgorithm = signingKeyPacket.algorithm;
      onePassSig.signingKeyId = signingKeyPacket.getKeyId();
      if (i === this.privateKeys.length - 1) {
        onePassSig.flags = 1;
      }
      packetList.push(onePassSig);
    }
    return Buffer.from(packetList.write());
  }

  signaturePackets() {
    var signatureType = enums.signature.binary, signingKeyPacket;
    var packetList = new packet.List();

    for (var i = this.privateKeys.length - 1; i >= 0; i--) {
      var signaturePacket = new packet.Signature();
      signaturePacket.signatureType = signatureType;
      signingKeyPacket = this.privateKeys[i].getSigningKeyPacket();
      if (!signingKeyPacket) {
        throw new Error('Could not find valid key packet for signing in key ' + this.privateKeys[i].primaryKey.getKeyId().toHex());
      }
      signaturePacket.hashAlgorithm = config.prefer_hash_algorithm;
      signaturePacket.publicKeyAlgorithm = signingKeyPacket.algorithm;
      if (!signingKeyPacket.isDecrypted) {
        throw new Error('Private key is not decrypted.');
      }
      signaturePacket.sign(signingKeyPacket, this.hash, true);
      packetList.push(signaturePacket);
    }
    return Buffer.from(packetList.write());

  }

}
