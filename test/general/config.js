const { expect } = require('chai');

const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../..');

module.exports = () => describe('Custom configuration', function() {
  it('openpgp.generateKey', async function() {
    const v5KeysVal = openpgp.config.v5Keys;
    const preferHashAlgorithmVal = openpgp.config.preferHashAlgorithm;
    const showCommentVal = openpgp.config.showComment;
    openpgp.config.v5Keys = false;
    openpgp.config.preferHashAlgorithm = openpgp.enums.hash.sha256;
    openpgp.config.showComment = false;

    try {
      const opt = {
        userIds: { name: 'Test User', email: 'text@example.com' }
      };
      const { key, privateKeyArmored } = await openpgp.generateKey(opt);
      expect(key.keyPacket.version).to.equal(4);
      expect(privateKeyArmored.indexOf(openpgp.config.commentString) > 0).to.be.false;
      expect(key.users[0].selfCertifications[0].preferredHashAlgorithms[0]).to.equal(openpgp.config.preferHashAlgorithm);

      const config = {
        v5Keys: true,
        showComment: true,
        preferHashAlgorithm: openpgp.enums.hash.sha512
      };
      const opt2 = {
        userIds: { name: 'Test User', email: 'text@example.com' },
        config
      };
      const { key: key2, privateKeyArmored: privateKeyArmored2 } = await openpgp.generateKey(opt2);
      expect(key2.keyPacket.version).to.equal(5);
      expect(privateKeyArmored2.indexOf(openpgp.config.commentString) > 0).to.be.true;
      expect(key2.users[0].selfCertifications[0].preferredHashAlgorithms[0]).to.equal(config.preferHashAlgorithm);
    } finally {
      openpgp.config.v5Keys = v5KeysVal;
      openpgp.config.preferHashAlgorithm = preferHashAlgorithmVal;
      openpgp.config.showComment = showCommentVal;
    }
  });

  it('openpgp.reformatKey', async function() {
    const compressionVal = openpgp.config.compression;
    const preferHashAlgorithmVal = openpgp.config.preferHashAlgorithm;
    const showCommentVal = openpgp.config.showComment;
    openpgp.config.compression = openpgp.enums.compression.bzip2;
    openpgp.config.preferHashAlgorithm = openpgp.enums.hash.sha256;
    openpgp.config.showComment = false;

    try {
      const userIds = { name: 'Test User', email: 'text2@example.com' };
      const { key: origKey } = await openpgp.generateKey({ userIds });

      const opt = { privateKey: origKey, userIds };
      const { key: refKey, privateKeyArmored: refKeyArmored } = await openpgp.reformatKey(opt);
      const prefs = refKey.users[0].selfCertifications[0];
      expect(prefs.preferredCompressionAlgorithms[0]).to.equal(openpgp.config.compression);
      expect(prefs.preferredHashAlgorithms[0]).to.equal(openpgp.config.preferHashAlgorithm);
      expect(refKeyArmored.indexOf(openpgp.config.commentString) > 0).to.be.false;

      const config = {
        showComment: true,
        compression: openpgp.enums.compression.zip,
        preferHashAlgorithm: openpgp.enums.hash.sha512
      };
      const opt2 = { privateKey: origKey, userIds, config };
      const { key: refKey2, privateKeyArmored: refKeyArmored2 } = await openpgp.reformatKey(opt2);
      const prefs2 = refKey2.users[0].selfCertifications[0];
      expect(prefs2.preferredCompressionAlgorithms[0]).to.equal(config.compression);
      expect(prefs2.preferredHashAlgorithms[0]).to.equal(config.preferHashAlgorithm);
      expect(refKeyArmored2.indexOf(openpgp.config.commentString) > 0).to.be.true;
    } finally {
      openpgp.config.compression = compressionVal;
      openpgp.config.preferHashAlgorithm = preferHashAlgorithmVal;
      openpgp.config.showComment = showCommentVal;
    }
  });


  it('openpgp.revokeKey', async function() {
    const showCommentVal = openpgp.config.showComment;
    openpgp.config.showComment = false;

    try {
      const userIds = { name: 'Test User', email: 'text2@example.com' };
      const { key, revocationCertificate } = await openpgp.generateKey({ userIds });

      const opt = { key };
      const { privateKeyArmored: revKeyArmored } = await openpgp.revokeKey(opt);
      expect(revKeyArmored.indexOf(openpgp.config.commentString) > 0).to.be.false;

      const opt2 = { key, config: { showComment: true } };
      const { privateKeyArmored: revKeyArmored2 } = await openpgp.revokeKey(opt2);
      expect(revKeyArmored2.indexOf(openpgp.config.commentString) > 0).to.be.true;

      const opt3 = {
        key,
        revocationCertificate,
        config: { rejectHashAlgorithms: new Set([openpgp.enums.hash.sha256, openpgp.enums.hash.sha512]) }
      };
      await expect(openpgp.revokeKey(opt3)).to.be.rejectedWith(/Insecure hash algorithm/);
    } finally {
      openpgp.config.showComment = showCommentVal;
    }
  });

  it('openpgp.decryptKey', async function() {
    const userIds = { name: 'Test User', email: 'text2@example.com' };
    const passphrase = '12345678';

    const { key } = await openpgp.generateKey({ userIds, passphrase });
    key.keyPacket.makeDummy();

    const opt = {
      privateKey: await openpgp.readKey({ armoredKey: key.armor() }),
      passphrase,
      config: { rejectHashAlgorithms: new Set([openpgp.enums.hash.sha256, openpgp.enums.hash.sha512]) }
    };
    await expect(openpgp.decryptKey(opt)).to.be.rejectedWith(/Insecure hash algorithm/);
  });

  it('openpgp.encryptKey', async function() {
    const s2kIterationCountByteVal = openpgp.config.s2kIterationCountByte;
    openpgp.config.s2kIterationCountByte = 224;

    try {
      const passphrase = '12345678';
      const userIds = { name: 'Test User', email: 'text2@example.com' };
      const { key: privateKey } = await openpgp.generateKey({ userIds });

      const encKey = await openpgp.encryptKey({ privateKey, userIds, passphrase });
      expect(encKey.keyPacket.s2k.c).to.equal(openpgp.config.s2kIterationCountByte);

      const config = { s2kIterationCountByte: 123 };
      const encKey2 = await openpgp.encryptKey({ privateKey, userIds, passphrase, config });
      expect(encKey2.keyPacket.s2k.c).to.equal(config.s2kIterationCountByte);
    } finally {
      openpgp.config.s2kIterationCountByte = s2kIterationCountByteVal;
    }
  });

  it('openpgp.encrypt', async function() {
    const aeadProtectVal = openpgp.config.aeadProtect;
    const compressionVal = openpgp.config.compression;
    openpgp.config.aeadProtect = false;
    openpgp.config.compression = openpgp.enums.compression.uncompressed;

    try {
      const passwords = ['12345678'];
      const message = openpgp.Message.fromText("test");

      const armored = await openpgp.encrypt({ message, passwords });
      const encrypted = await openpgp.readMessage({ armoredMessage: armored });
      const { packets: [skesk, encData] } = encrypted;
      expect(skesk.version).to.equal(4); // cfb
      expect(encData.tag).to.equal(openpgp.enums.packet.symEncryptedIntegrityProtectedData);
      const { packets: [literal] } = await encrypted.decrypt(null, passwords, null, encrypted.fromStream, openpgp.config);
      expect(literal.tag).to.equal(openpgp.enums.packet.literalData);

      const config = {
        aeadProtect: true,
        compression: openpgp.enums.compression.zip,
        deflateLevel: 1
      };
      const armored2 = await openpgp.encrypt({ message, passwords, config });
      const encrypted2 = await openpgp.readMessage({ armoredMessage: armored2 });
      const { packets: [skesk2, encData2] } = encrypted2;
      expect(skesk2.version).to.equal(5);
      expect(encData2.tag).to.equal(openpgp.enums.packet.AEADEncryptedData);
      const { packets: [compressed] } = await encrypted2.decrypt(null, passwords, null, encrypted2.fromStream, openpgp.config);
      expect(compressed.tag).to.equal(openpgp.enums.packet.compressedData);
      expect(compressed.algorithm).to.equal("zip");
    } finally {
      openpgp.config.aeadProtect = aeadProtectVal;
      openpgp.config.compression = compressionVal;
    }
  });

  it('openpgp.sign', async function() {
    const userIds = { name: 'Test User', email: 'text2@example.com' };
    const { privateKeyArmored } = await openpgp.generateKey({ userIds });
    const key = await openpgp.readKey({ armoredKey: privateKeyArmored });

    const message = openpgp.Message.fromText("test");
    const opt = {
      message,
      privateKeys: key,
      config: { rejectHashAlgorithms: new Set([openpgp.enums.hash.sha256, openpgp.enums.hash.sha512]) }
    };
    await expect(openpgp.sign(opt)).to.be.rejectedWith(/Insecure hash algorithm/);
    opt.detached = true;
    await expect(openpgp.sign(opt)).to.be.rejectedWith(/Insecure hash algorithm/);

    const clearText = openpgp.CleartextMessage.fromText("test");
    const opt2 = {
      message: clearText,
      privateKeys: key,
      config: { rejectHashAlgorithms: new Set([openpgp.enums.hash.sha256, openpgp.enums.hash.sha512]) }
    };
    await expect(openpgp.sign(opt2)).to.be.rejectedWith(/Insecure hash algorithm/);
  });

  it('openpgp.verify', async function() {
    const userIds = { name: 'Test User', email: 'text2@example.com' };
    const { privateKeyArmored } = await openpgp.generateKey({ userIds });
    const key = await openpgp.readKey({ armoredKey: privateKeyArmored });
    const config = { rejectMessageHashAlgorithms: new Set([openpgp.enums.hash.sha256, openpgp.enums.hash.sha512]) };


    const message = openpgp.Message.fromText("test");
    const signed = await openpgp.sign({ message, privateKeys: key });
    const opt = {
      message: await openpgp.readMessage({ armoredMessage: signed }),
      publicKeys: key,
      config
    };
    const { signatures: [sig] } = await openpgp.verify(opt);
    await expect(sig.error).to.match(/Insecure message hash algorithm/);
    const armoredSignature = await openpgp.sign({ message, privateKeys: key, detached: true });
    const opt2 = {
      message,
      signature: await openpgp.readSignature({ armoredSignature }),
      publicKeys: key,
      config
    };
    const { signatures: [sig2] } = await openpgp.verify(opt2);
    await expect(sig2.error).to.match(/Insecure message hash algorithm/);

    const cleartext = openpgp.CleartextMessage.fromText("test");
    const signedCleartext = await openpgp.sign({ message: cleartext, privateKeys: key });
    const opt3 = {
      message: await openpgp.readCleartextMessage({ cleartextMessage: signedCleartext }),
      publicKeys: key,
      config
    };
    const { signatures: [sig3] } = await openpgp.verify(opt3);
    await expect(sig3.error).to.match(/Insecure message hash algorithm/);

  });

});
