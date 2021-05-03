const { expect } = require('chai');

const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../..');

module.exports = () => describe('Custom configuration', function() {
  it('openpgp.readMessage', async function() {
    const armoredMessage = await openpgp.encrypt({ message: await openpgp.createMessage({ text:"hello world" }), passwords: 'password' });
    const message = await openpgp.readMessage({ armoredMessage });
    message.packets.unshift(new openpgp.MarkerPacket()); // MarkerPacket is not allowed in the Message context

    const config = { tolerant: true };
    const parsedMessage = await openpgp.readMessage({ armoredMessage: message.armor(), config });
    expect(parsedMessage.packets.length).to.equal(2);

    config.tolerant = false;
    await expect(
      openpgp.readMessage({ armoredMessage: message.armor(), config })
    ).to.be.rejectedWith(/Packet not allowed in this context/);
  });

  it('openpgp.readSignature', async function() {
    const armoredSignature = `-----BEGIN PGP SIGNATURE-----

wnUEARYKAAYFAmCPyjwAIQkQk5xMVrwBTN4WIQT7kMrxk1s/unaTxxmTnExW
vAFM3jjrAQDgJPXsv8PqCrLGDuMa/2r6SgzYd03aw/xt1WM6hgUvhQD+J54Z
3KkV9TCnZibYM9OXuIvQpkoIKn4qbyFv7AaSIgs=
=hgTd
-----END PGP SIGNATURE-----`;

    const signature = await openpgp.readSignature({ armoredSignature });
    signature.packets.unshift(new openpgp.MarkerPacket()); // MarkerPacket is not allowed in the Signature context

    const config = { tolerant: true };
    const parsedSignature = await openpgp.readSignature({ armoredSignature: signature.armor(), config });
    expect(parsedSignature.packets.length).to.equal(1);

    config.tolerant = false;
    await expect(
      openpgp.readSignature({ armoredSignature: signature.armor(), config })
    ).to.be.rejectedWith(/Packet not allowed in this context/);
  });

  it('openpgp.readKey', async function() {
    const armoredKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEYI/KsBYJKwYBBAHaRw8BAQdAW2lu0r97hQztwP8+WbSF9N/QJ5hkevhm
CGJbM3HBvznNEHRlc3QgPHRlc3RAYS5pdD7CjAQQFgoAHQUCYI/KsAQLCQcI
AxUICgQWAAIBAhkBAhsDAh4BACEJEKgxHS8jVhd9FiEE8hy8OerCaNGuKPDw
qDEdLyNWF32XOQD/dq2/D394eW67VwUhvRpQl9gwToDf+SixATEFigok5JgA
/3ZeH9eXiZqo3rChfdQ+3VKTd7yoI2gM/pjbHupemYYAzjgEYI/KsBIKKwYB
BAGXVQEFAQEHQN/8mxAaro95FmvPQ4wlAfk3WKUHZtNvpaqzXo1K6WdMAwEI
B8J4BBgWCAAJBQJgj8qwAhsMACEJEKgxHS8jVhd9FiEE8hy8OerCaNGuKPDw
qDEdLyNWF30o6wD/fZYCV8aS4dAu2U3fpN5y5+PbuXFRYljA5gQ/1zrGN/UA
/3r62WsCVupzKdISZYOMPwEY5qN/4f9i6ZWxIynmVX0E
=6+P3
-----END PGP PUBLIC KEY BLOCK-----`;

    const keyPackets = (await openpgp.readKey({ armoredKey })).toPacketList();
    keyPackets.unshift(new openpgp.MarkerPacket()); // MarkerPacket is not allowed in the Signature context

    const config = { tolerant: true };
    const parsedKey = await openpgp.readKey({ binaryKey: keyPackets.write(), config });
    expect(parsedKey.toPacketList().length).to.equal(5);

    config.tolerant = false;
    await expect(
      openpgp.readKey({ binaryKey: keyPackets.write(), config })
    ).to.be.rejectedWith(/Packet not allowed in this context/);
  });


  it('openpgp.generateKey', async function() {
    const v5KeysVal = openpgp.config.v5Keys;
    const preferredHashAlgorithmVal = openpgp.config.preferredHashAlgorithm;
    const showCommentVal = openpgp.config.showComment;
    openpgp.config.v5Keys = false;
    openpgp.config.preferredHashAlgorithm = openpgp.enums.hash.sha256;
    openpgp.config.showComment = false;

    try {
      const opt = {
        userIDs: { name: 'Test User', email: 'text@example.com' }
      };
      const { key, privateKeyArmored } = await openpgp.generateKey(opt);
      expect(key.keyPacket.version).to.equal(4);
      expect(privateKeyArmored.indexOf(openpgp.config.commentString) > 0).to.be.false;
      expect(key.users[0].selfCertifications[0].preferredHashAlgorithms[0]).to.equal(openpgp.config.preferredHashAlgorithm);

      const config = {
        v5Keys: true,
        showComment: true,
        preferredHashAlgorithm: openpgp.enums.hash.sha512
      };
      const opt2 = {
        userIDs: { name: 'Test User', email: 'text@example.com' },
        config
      };
      const { key: key2, privateKeyArmored: privateKeyArmored2 } = await openpgp.generateKey(opt2);
      expect(key2.keyPacket.version).to.equal(5);
      expect(privateKeyArmored2.indexOf(openpgp.config.commentString) > 0).to.be.true;
      expect(key2.users[0].selfCertifications[0].preferredHashAlgorithms[0]).to.equal(config.preferredHashAlgorithm);
    } finally {
      openpgp.config.v5Keys = v5KeysVal;
      openpgp.config.preferredHashAlgorithm = preferredHashAlgorithmVal;
      openpgp.config.showComment = showCommentVal;
    }
  });

  it('openpgp.reformatKey', async function() {
    const preferredCompressionAlgorithmVal = openpgp.config.preferredCompressionAlgorithm;
    const preferredHashAlgorithmVal = openpgp.config.preferredHashAlgorithm;
    const showCommentVal = openpgp.config.showComment;
    openpgp.config.preferredCompressionAlgorithm = openpgp.enums.compression.bzip2;
    openpgp.config.preferredHashAlgorithm = openpgp.enums.hash.sha256;
    openpgp.config.showComment = false;

    try {
      const userIDs = { name: 'Test User', email: 'text2@example.com' };
      const { key: origKey } = await openpgp.generateKey({ userIDs });

      const opt = { privateKey: origKey, userIDs };
      const { key: refKey, privateKeyArmored: refKeyArmored } = await openpgp.reformatKey(opt);
      const prefs = refKey.users[0].selfCertifications[0];
      expect(prefs.preferredCompressionAlgorithms[0]).to.equal(openpgp.config.preferredCompressionAlgorithm);
      expect(prefs.preferredHashAlgorithms[0]).to.equal(openpgp.config.preferredHashAlgorithm);
      expect(refKeyArmored.indexOf(openpgp.config.commentString) > 0).to.be.false;

      const config = {
        showComment: true,
        preferredCompressionAlgorithm: openpgp.enums.compression.zip,
        preferredHashAlgorithm: openpgp.enums.hash.sha512,
        rejectPublicKeyAlgorithms: new Set([openpgp.enums.publicKey.eddsa]) // should not matter in this context
      };
      const opt2 = { privateKey: origKey, userIDs, config };
      const { key: refKey2, privateKeyArmored: refKeyArmored2 } = await openpgp.reformatKey(opt2);
      const prefs2 = refKey2.users[0].selfCertifications[0];
      expect(prefs2.preferredCompressionAlgorithms[0]).to.equal(config.preferredCompressionAlgorithm);
      expect(prefs2.preferredHashAlgorithms[0]).to.equal(config.preferredHashAlgorithm);
      expect(refKeyArmored2.indexOf(openpgp.config.commentString) > 0).to.be.true;
    } finally {
      openpgp.config.preferredCompressionAlgorithm = preferredCompressionAlgorithmVal;
      openpgp.config.preferredHashAlgorithm = preferredHashAlgorithmVal;
      openpgp.config.showComment = showCommentVal;
    }
  });


  it('openpgp.revokeKey', async function() {
    const showCommentVal = openpgp.config.showComment;
    openpgp.config.showComment = false;

    try {
      const userIDs = { name: 'Test User', email: 'text2@example.com' };
      const { key, revocationCertificate } = await openpgp.generateKey({ userIDs });

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
    const userIDs = { name: 'Test User', email: 'text2@example.com' };
    const passphrase = '12345678';

    const { key } = await openpgp.generateKey({ userIDs, passphrase });
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
      const userIDs = { name: 'Test User', email: 'text2@example.com' };
      const { key: privateKey } = await openpgp.generateKey({ userIDs });

      const encKey = await openpgp.encryptKey({ privateKey, userIDs, passphrase });
      expect(encKey.keyPacket.s2k.c).to.equal(openpgp.config.s2kIterationCountByte);

      const config = { s2kIterationCountByte: 123 };
      const encKey2 = await openpgp.encryptKey({ privateKey, userIDs, passphrase, config });
      expect(encKey2.keyPacket.s2k.c).to.equal(config.s2kIterationCountByte);
    } finally {
      openpgp.config.s2kIterationCountByte = s2kIterationCountByteVal;
    }
  });

  it('openpgp.encrypt', async function() {
    const aeadProtectVal = openpgp.config.aeadProtect;
    const preferredCompressionAlgorithmVal = openpgp.config.preferredCompressionAlgorithm;
    openpgp.config.aeadProtect = false;
    openpgp.config.preferredCompressionAlgorithm = openpgp.enums.compression.uncompressed;

    try {
      const passwords = ['12345678'];
      const message = await openpgp.createMessage({ text: "test" });

      const armored = await openpgp.encrypt({ message, passwords });
      const encrypted = await openpgp.readMessage({ armoredMessage: armored });
      const { packets: [skesk, encData] } = encrypted;
      expect(skesk.version).to.equal(4); // cfb
      expect(encData.constructor.tag).to.equal(openpgp.enums.packet.symEncryptedIntegrityProtectedData);
      const { packets: [literal] } = await encrypted.decrypt(null, passwords, null, encrypted.fromStream, openpgp.config);
      expect(literal.constructor.tag).to.equal(openpgp.enums.packet.literalData);

      const config = {
        aeadProtect: true,
        preferredCompressionAlgorithm: openpgp.enums.compression.zip,
        deflateLevel: 1
      };
      const armored2 = await openpgp.encrypt({ message, passwords, config });
      const encrypted2 = await openpgp.readMessage({ armoredMessage: armored2 });
      const { packets: [skesk2, encData2] } = encrypted2;
      expect(skesk2.version).to.equal(5);
      expect(encData2.constructor.tag).to.equal(openpgp.enums.packet.aeadEncryptedData);
      const { packets: [compressed] } = await encrypted2.decrypt(null, passwords, null, encrypted2.fromStream, openpgp.config);
      expect(compressed.constructor.tag).to.equal(openpgp.enums.packet.compressedData);
      expect(compressed.algorithm).to.equal("zip");

      const userIDs = { name: 'Test User', email: 'text2@example.com' };
      const { key } = await openpgp.generateKey({ userIDs });
      await expect(openpgp.encrypt({
        message, publicKeys: [key], config: { rejectPublicKeyAlgorithms: new Set([openpgp.enums.publicKey.ecdh]) }
      })).to.be.eventually.rejectedWith(/ecdh keys are considered too weak/);
    } finally {
      openpgp.config.aeadProtect = aeadProtectVal;
      openpgp.config.preferredCompressionAlgorithm = preferredCompressionAlgorithmVal;
    }
  });

  it('openpgp.decrypt', async function() {
    const plaintext = 'test';
    const message = await openpgp.createMessage({ text: plaintext });
    const userIDs = { name: 'Test User', email: 'text2@example.com' };
    const { key } = await openpgp.generateKey({ userIDs, type: 'rsa', rsaBits: 2048 });

    const armoredMessage = await openpgp.encrypt({ message, publicKeys:[key], privateKeys: [key] });
    const { data, signatures } = await openpgp.decrypt({
      message: await openpgp.readMessage({ armoredMessage }),
      privateKeys: [key],
      publicKeys: [key]
    });
    expect(data).to.equal(plaintext);
    expect(signatures[0].valid).to.be.true;

    const { data: data2, signatures: signatures2 } = await openpgp.decrypt({
      message: await openpgp.readMessage({ armoredMessage }),
      privateKeys: [key],
      publicKeys: [key],
      config: { minRSABits: 4096 }
    });
    expect(data2).to.equal(plaintext);
    expect(signatures2[0].valid).to.be.false;
    expect(signatures2[0].error).to.match(/keys shorter than 4096 bits are considered too weak/);

    const { data: data3, signatures: signatures3 } = await openpgp.decrypt({
      message: await openpgp.readMessage({ armoredMessage }),
      privateKeys: [key],
      publicKeys: [key],
      config: { rejectPublicKeyAlgorithms: new Set([openpgp.enums.publicKey.rsaEncryptSign]) }
    });
    expect(data3).to.equal(plaintext);
    expect(signatures3[0].valid).to.be.false;
    expect(signatures3[0].error).to.match(/rsaEncryptSign keys are considered too weak/);
  });

  it('openpgp.sign', async function() {
    const userIDs = { name: 'Test User', email: 'text2@example.com' };
    const { privateKeyArmored } = await openpgp.generateKey({ userIDs });
    const key = await openpgp.readKey({ armoredKey: privateKeyArmored });

    const message = await openpgp.createMessage({ text: "test" });
    const opt = {
      message,
      privateKeys: key,
      config: { rejectHashAlgorithms: new Set([openpgp.enums.hash.sha256, openpgp.enums.hash.sha512]) }
    };
    await expect(openpgp.sign(opt)).to.be.rejectedWith(/Insecure hash algorithm/);
    opt.detached = true;
    await expect(openpgp.sign(opt)).to.be.rejectedWith(/Insecure hash algorithm/);

    const clearText = await openpgp.createCleartextMessage({ text: "test" });
    const opt2 = {
      message: clearText,
      privateKeys: key,
      config: { rejectHashAlgorithms: new Set([openpgp.enums.hash.sha256, openpgp.enums.hash.sha512]) }
    };
    await expect(openpgp.sign(opt2)).to.be.rejectedWith(/Insecure hash algorithm/);

    await expect(openpgp.sign({
      message, privateKeys: [key], config: { rejectPublicKeyAlgorithms: new Set([openpgp.enums.publicKey.eddsa]) }
    })).to.be.eventually.rejectedWith(/eddsa keys are considered too weak/);
  });

  it('openpgp.verify', async function() {
    const userIDs = { name: 'Test User', email: 'text2@example.com' };
    const { privateKeyArmored } = await openpgp.generateKey({ userIDs });
    const key = await openpgp.readKey({ armoredKey: privateKeyArmored });
    const config = { rejectMessageHashAlgorithms: new Set([openpgp.enums.hash.sha256, openpgp.enums.hash.sha512]) };


    const message = await openpgp.createMessage({ text: "test" });
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

    const cleartext = await openpgp.createCleartextMessage({ text: "test" });
    const signedCleartext = await openpgp.sign({ message: cleartext, privateKeys: key });
    const opt3 = {
      message: await openpgp.readCleartextMessage({ cleartextMessage: signedCleartext }),
      publicKeys: key,
      config
    };
    const { signatures: [sig3] } = await openpgp.verify(opt3);
    await expect(sig3.error).to.match(/Insecure message hash algorithm/);

    const opt4 = {
      message: await openpgp.readMessage({ armoredMessage: signed }),
      publicKeys: [key],
      config: { rejectPublicKeyAlgorithms: new Set([openpgp.enums.publicKey.eddsa]) }
    };
    const { signatures: [sig4] } = await openpgp.verify(opt4);
    await expect(sig4.valid).to.be.false;
    await expect(sig4.error).to.match(/eddsa keys are considered too weak/);
  });

});
