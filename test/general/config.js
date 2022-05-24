const { expect } = require('chai');

const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../..');

module.exports = () => describe('Custom configuration', function() {
  it('openpgp.readMessage', async function() {
    const armoredMessage = await openpgp.encrypt({ message: await openpgp.createMessage({ text:'hello world' }), passwords: 'password' });
    const message = await openpgp.readMessage({ armoredMessage });
    message.packets.findPacket(openpgp.SymEncryptedSessionKeyPacket.tag).version = 1; // unsupported SKESK version

    const config = { ignoreUnsupportedPackets: true };
    const parsedMessage = await openpgp.readMessage({ armoredMessage: message.armor(), config });
    expect(parsedMessage.packets.length).to.equal(2);
    expect(parsedMessage.packets[0].tag).to.equal(openpgp.enums.packet.symEncryptedSessionKey);

    config.ignoreUnsupportedPackets = false;
    await expect(
      openpgp.readMessage({ armoredMessage: message.armor(), config })
    ).to.be.rejectedWith(/Version 1 of the SKESK packet is unsupported/);
    // writing of partially parsed message should succeed
    await expect(
      openpgp.readMessage({ armoredMessage: parsedMessage.armor(), config })
    ).to.be.rejectedWith(/Version 1 of the SKESK packet is unsupported/);
  });

  it('openpgp.readSignature', async function() {
    const armoredSignature = `-----BEGIN PGP SIGNATURE-----

wnUEARYKAAYFAmCPyjwAIQkQk5xMVrwBTN4WIQT7kMrxk1s/unaTxxmTnExW
vAFM3jjrAQDgJPXsv8PqCrLGDuMa/2r6SgzYd03aw/xt1WM6hgUvhQD+J54Z
3KkV9TCnZibYM9OXuIvQpkoIKn4qbyFv7AaSIgs=
=hgTd
-----END PGP SIGNATURE-----`;

    const signature = await openpgp.readSignature({ armoredSignature });
    signature.packets[0].signatureData[0] = 1; // set unsupported signature version

    const config = { ignoreUnsupportedPackets: true };
    const parsedSignature = await openpgp.readSignature({ armoredSignature: signature.armor(), config });
    expect(parsedSignature.packets.length).to.equal(1);
    expect(parsedSignature.packets[0].tag).to.equal(openpgp.enums.packet.signature);

    config.ignoreUnsupportedPackets = false;
    await expect(
      openpgp.readSignature({ armoredSignature: signature.armor(), config })
    ).to.be.rejectedWith(/Version 1 of the signature packet is unsupported/);
    // writing of partially parsed signature should succeed
    await expect(
      openpgp.readSignature({ armoredSignature: parsedSignature.armor(), config })
    ).to.be.rejectedWith(/Version 1 of the signature packet is unsupported/);
  });

  it('openpgp.readKey', async function() {
    const { privateKey: armoredKey } = await openpgp.generateKey({ userIDs:[{ name:'test', email:'test@a.it' }] });
    await expect(
      openpgp.readKey({ armoredKey, config: { ignoreUnsupportedPackets: false, maxUserIDLength: 2 } })
    ).to.be.rejectedWith(/User ID string is too long/);
    await expect(
      openpgp.readKey({ armoredKey, config: { ignoreUnsupportedPackets: true, maxUserIDLength: 2 } })
    ).to.be.rejectedWith(/User ID string is too long/);
  });

  it('openpgp.readKeys', async function() {
    // Valid v4 key followed by modified key declared as v3 (unsupported) and another valid v4 key.
    // When ignoring malfored/unsupported packets, we do not want the userID and subkey of the trailing key
    // to be associated with the leading one
    const partiallyUnsupportedKeyBlock = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEYotwYxYJKwYBBAHaRw8BAQdAQrm/H1rTYvBLV2mP0+6u+jVa5iOgPIgA
VkH1H7KipDrNDzx0ZXN0QHRlc3QuY29tPsKMBBAWCgAdBQJii3BjBAsJBwgD
FQgKBBYAAgECGQECGwMCHgEAIQkQLavVE0KkGtwWIQQv90VxLmdeWJRzEWUt
q9UTQqQa3L/3APwM4ypA9q/qml+ezCdVFilv9huZVSbPlQ06AN5E0ZclgwD9
FeCHPwKqDkcKvqSQGdTv3QSefwjrt9oO8DI71vKjWQjOOARii3BjEgorBgEE
AZdVAQUBAQdALl5wAhaoMgtlk7aV6v1DC3T+7kuNQVDZZPPPbxhaYwMDAQgH
wngEGBYIAAkFAmKLcGMCGwwAIQkQLavVE0KkGtwWIQQv90VxLmdeWJRzEWUt
q9UTQqQa3N16APwLtHt26M1o1yUtBfQ2yddFQb/Xi4Kq3PBG5ltUBj38EAD/
aNfrR+NWb3LWRTe+LDuU7M+8ucdZ00TeAAOHGF11UAXGMwNii3B7FgkrBgEE
AdpHDwEBB0CF7hJ4IhKdtYMa2hkA1ckjgBcZL5TaK/+A+laliBVh2s0WPGFu
b3RoZXJ0ZXN0QHRlc3QuY29tPsKMBBAWCgAdBQJii3B7BAsJBwgDFQgKBBYA
AgECGQECGwMCHgEAIQkQxKiJcMvjhmEWIQQgDYaTtkFIWF89hvXEqIlwy+OG
YWnWAQDVjVaF4FpjV9rwhqqQ+pLQYWSjFGEQV9u05YPzOZWs0AEA4stxQp1H
OtXx2S/tfY74d+I/QPTVHgB6TVcADtdKnQjOOARii3B7EgorBgEEAZdVAQUB
AQdAsAnhg90WUEy1raZ/DrJ1MI9g8f2SBxUtvNfCikBwpWMDAQgHwngEGBYI
AAkFAmKLcHsCGwwAIQkQxKiJcMvjhmEWIQQgDYaTtkFIWF89hvXEqIlwy+OG
Ya2ZAQC5fDrNXuyqvjaJiVomAl7YnuFwR4tLlgJTVDDNkTOfvAD+IJo8ptfg
/lzgTPMPLP8RgpGs8jU5cWhLlH6866UkAwXGMwRii3B/FgkrBgEEAdpHDwEB
B0AU3y3+X4mAYxFDz54RroBsES1YTufnIndjbljQ4UCpcs0dPGFub3RoZXJh
bm90aGVydGVzdEB0ZXN0LmNvbT7CjAQQFgoAHQUCYotwfwQLCQcIAxUICgQW
AAIBAhkBAhsDAh4BACEJEDc5RdIx+aTBFiEE6N7yK4zw3IhhDLIwNzlF0jH5
pMFQWwEAwUBNM2wHH3PexhLv4QpmteIg8I2wlYmuYk0w0GfAPywBAOuyKqxE
g4vye4Mfs2Ns3FEUQP0y+YbAkZhxhjVX3gYJzjgEYotwfxIKKwYBBAGXVQEF
AQEHQK1UDFW1ue61hhm1O57eSv29+A2gId5Zi9TEqP1mopgkAwEIB8J4BBgW
CAAJBQJii3B/AhsMACEJEDc5RdIx+aTBFiEE6N7yK4zw3IhhDLIwNzlF0jH5
pMH3oQEA/gjeM/XpBP/DIhqzQxAVtrDFlkKairQMRMVQfoU4vVcBAITA9cqc
n9/quqtmyOtYOA6gXNCw0Fal3iANKBmsPmYI
=O3ZV
-----END PGP PUBLIC KEY BLOCK-----
    `;
    await expect(
      openpgp.readKeys({ armoredKeys: partiallyUnsupportedKeyBlock, config: { ignoreUnsupportedPackets: false } })
    ).to.be.rejectedWith(/key packet is unsupported/);

    const parsedKeys = await openpgp.readKeys({ armoredKeys: partiallyUnsupportedKeyBlock, config: { ignoreUnsupportedPackets: true } });
    expect(parsedKeys.length).to.equal(2);
    expect(parsedKeys[0].subkeys.length).to.equal(1);
    expect(parsedKeys[0].subkeys[0].getKeyID().toHex()).to.equal('0861c76681a34407');
    expect(parsedKeys[0].users.length).to.equal(1);
    expect(parsedKeys[0].users[0].userID.email).to.equal('test@test.com');
    expect(await parsedKeys[0].getEncryptionKey().then(key => key.getKeyID().toHex())).to.equal('0861c76681a34407');

    expect(parsedKeys[1].subkeys.length).to.equal(1);
    expect(parsedKeys[1].subkeys[0].getKeyID().toHex()).to.equal('48050814f28f2263');
    expect(parsedKeys[1].users.length).to.equal(1);
    expect(parsedKeys[1].users[0].userID.email).to.equal('anotheranothertest@test.com');
    expect(await parsedKeys[1].getEncryptionKey().then(key => key.getKeyID().toHex())).to.equal('48050814f28f2263');
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
      const { privateKey: privateKeyArmored } = await openpgp.generateKey(opt);
      const key = await openpgp.readKey({ armoredKey: privateKeyArmored });
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
      const { privateKey: privateKeyArmored2 } = await openpgp.generateKey(opt2);
      const key2 = await openpgp.readKey({ armoredKey: privateKeyArmored2 });
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
      const { privateKey: origKey } = await openpgp.generateKey({ userIDs, format: 'object' });

      const opt = { privateKey: origKey, userIDs };
      const { privateKey: refKeyArmored } = await openpgp.reformatKey(opt);
      expect(refKeyArmored.indexOf(openpgp.config.commentString) > 0).to.be.false;
      const refKey = await openpgp.readKey({ armoredKey: refKeyArmored });
      const prefs = refKey.users[0].selfCertifications[0];
      expect(prefs.preferredCompressionAlgorithms[0]).to.equal(openpgp.config.preferredCompressionAlgorithm);
      expect(prefs.preferredHashAlgorithms[0]).to.equal(openpgp.config.preferredHashAlgorithm);

      const config = {
        showComment: true,
        preferredCompressionAlgorithm: openpgp.enums.compression.zip,
        preferredHashAlgorithm: openpgp.enums.hash.sha512,
        rejectPublicKeyAlgorithms: new Set([openpgp.enums.publicKey.eddsa]) // should not matter in this context
      };
      const opt2 = { privateKey: origKey, userIDs, config };
      const { privateKey: refKeyArmored2 } = await openpgp.reformatKey(opt2);
      expect(refKeyArmored2.indexOf(openpgp.config.commentString) > 0).to.be.true;
      const refKey2 = await openpgp.readKey({ armoredKey: refKeyArmored2 });
      const prefs2 = refKey2.users[0].selfCertifications[0];
      expect(prefs2.preferredCompressionAlgorithms[0]).to.equal(config.preferredCompressionAlgorithm);
      expect(prefs2.preferredHashAlgorithms[0]).to.equal(config.preferredHashAlgorithm);
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
      const { privateKey: key, revocationCertificate } = await openpgp.generateKey({ userIDs, format: 'object' });

      const opt = { key };
      const { privateKey: revKeyArmored } = await openpgp.revokeKey(opt);
      expect(revKeyArmored.indexOf(openpgp.config.commentString) > 0).to.be.false;

      const opt2 = { key, config: { showComment: true } };
      const { privateKey: revKeyArmored2 } = await openpgp.revokeKey(opt2);
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

    const { privateKey: key } = await openpgp.generateKey({ userIDs, passphrase, format: 'object' });
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
      const { privateKey } = await openpgp.generateKey({ userIDs, format: 'object' });

      const encKey = await openpgp.encryptKey({ privateKey, passphrase });
      expect(encKey.keyPacket.s2k.c).to.equal(openpgp.config.s2kIterationCountByte);

      const config = { s2kIterationCountByte: 123 };
      const encKey2 = await openpgp.encryptKey({ privateKey, passphrase, config });
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
      const message = await openpgp.createMessage({ text: 'test' });

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
      expect(compressed.algorithm).to.equal(openpgp.enums.compression.zip);

      const userIDs = { name: 'Test User', email: 'text2@example.com' };
      const { privateKey: key } = await openpgp.generateKey({ userIDs, format: 'object' });
      await expect(openpgp.encrypt({
        message, encryptionKeys: [key], config: { rejectPublicKeyAlgorithms: new Set([openpgp.enums.publicKey.ecdh]) }
      })).to.be.eventually.rejectedWith(/ecdh keys are considered too weak/);

      await expect(openpgp.encrypt({
        message, encryptionKeys: [key], config: { rejectCurves: new Set([openpgp.enums.curve.curve25519]) }
      })).to.be.eventually.rejectedWith(/Support for ecdh keys using curve curve25519 is disabled/);

      const echdEncrypted = await openpgp.encrypt({
        message, encryptionKeys: [key], config: { rejectCurves: new Set([openpgp.enums.curve.ed25519]) }
      });
      expect(echdEncrypted).to.match(/---BEGIN PGP MESSAGE---/);
    } finally {
      openpgp.config.aeadProtect = aeadProtectVal;
      openpgp.config.preferredCompressionAlgorithm = preferredCompressionAlgorithmVal;
    }
  });

  it('openpgp.decrypt', async function() {
    const plaintext = 'test';
    const message = await openpgp.createMessage({ text: plaintext });
    const userIDs = { name: 'Test User', email: 'text2@example.com' };
    const { privateKey: key } = await openpgp.generateKey({ userIDs, type: 'rsa', rsaBits: 2048, format: 'object' });

    const armoredMessage = await openpgp.encrypt({ message, encryptionKeys:[key], signingKeys: [key] });
    const { data, signatures } = await openpgp.decrypt({
      message: await openpgp.readMessage({ armoredMessage }),
      decryptionKeys: [key],
      verificationKeys: [key]
    });
    expect(data).to.equal(plaintext);
    expect(await signatures[0].verified).to.be.true;

    const { data: data2, signatures: signatures2 } = await openpgp.decrypt({
      message: await openpgp.readMessage({ armoredMessage }),
      decryptionKeys: [key],
      verificationKeys: [key],
      config: { minRSABits: 4096 }
    });
    expect(data2).to.equal(plaintext);
    await expect(signatures2[0].verified).to.be.rejectedWith(/keys shorter than 4096 bits are considered too weak/);

    const { data: data3, signatures: signatures3 } = await openpgp.decrypt({
      message: await openpgp.readMessage({ armoredMessage }),
      decryptionKeys: [key],
      verificationKeys: [key],
      config: { rejectPublicKeyAlgorithms: new Set([openpgp.enums.publicKey.rsaEncryptSign]) }
    });
    expect(data3).to.equal(plaintext);
    await expect(signatures3[0].verified).to.be.rejectedWith(/rsaEncryptSign keys are considered too weak/);
  });

  it('openpgp.sign', async function() {
    const userIDs = { name: 'Test User', email: 'text2@example.com' };
    const { privateKey: key } = await openpgp.generateKey({ userIDs, format: 'object' });

    const message = await openpgp.createMessage({ text: 'test' });
    const opt = {
      message,
      signingKeys: key,
      config: { rejectHashAlgorithms: new Set([openpgp.enums.hash.sha256, openpgp.enums.hash.sha512]) }
    };
    await expect(openpgp.sign(opt)).to.be.rejectedWith(/Insecure hash algorithm/);
    opt.detached = true;
    await expect(openpgp.sign(opt)).to.be.rejectedWith(/Insecure hash algorithm/);

    const clearText = await openpgp.createCleartextMessage({ text: 'test' });
    const opt2 = {
      message: clearText,
      signingKeys: key,
      config: { rejectHashAlgorithms: new Set([openpgp.enums.hash.sha256, openpgp.enums.hash.sha512]) }
    };
    await expect(openpgp.sign(opt2)).to.be.rejectedWith(/Insecure hash algorithm/);

    await expect(openpgp.sign({
      message, signingKeys: [key], config: { rejectPublicKeyAlgorithms: new Set([openpgp.enums.publicKey.eddsa]) }
    })).to.be.eventually.rejectedWith(/eddsa keys are considered too weak/);
    await expect(openpgp.sign({
      message, signingKeys: [key], config: { rejectCurves: new Set([openpgp.enums.curve.ed25519]) }
    })).to.be.eventually.rejectedWith(/Support for eddsa keys using curve ed25519 is disabled/);
  });

  it('openpgp.verify', async function() {
    const userIDs = { name: 'Test User', email: 'text2@example.com' };
    const { privateKey: key } = await openpgp.generateKey({ userIDs, format: 'object' });
    const config = { rejectMessageHashAlgorithms: new Set([openpgp.enums.hash.sha256, openpgp.enums.hash.sha512]) };


    const message = await openpgp.createMessage({ text: 'test' });
    const signed = await openpgp.sign({ message, signingKeys: key });
    const opt = {
      message: await openpgp.readMessage({ armoredMessage: signed }),
      verificationKeys: key,
      config
    };
    const { signatures: [sig] } = await openpgp.verify(opt);
    await expect(sig.verified).to.be.rejectedWith(/Insecure message hash algorithm/);
    const armoredSignature = await openpgp.sign({ message, signingKeys: key, detached: true });
    const opt2 = {
      message,
      signature: await openpgp.readSignature({ armoredSignature }),
      verificationKeys: key,
      config
    };
    const { signatures: [sig2] } = await openpgp.verify(opt2);
    await expect(sig2.verified).to.be.rejectedWith(/Insecure message hash algorithm/);

    const cleartext = await openpgp.createCleartextMessage({ text: 'test' });
    const signedCleartext = await openpgp.sign({ message: cleartext, signingKeys: key });
    const opt3 = {
      message: await openpgp.readCleartextMessage({ cleartextMessage: signedCleartext }),
      verificationKeys: key,
      config
    };
    const { signatures: [sig3] } = await openpgp.verify(opt3);
    await expect(sig3.verified).to.be.rejectedWith(/Insecure message hash algorithm/);

    const opt4 = {
      message: await openpgp.readMessage({ armoredMessage: signed }),
      verificationKeys: [key],
      config: { rejectPublicKeyAlgorithms: new Set([openpgp.enums.publicKey.eddsa]) }
    };
    const { signatures: [sig4] } = await openpgp.verify(opt4);
    await expect(sig4.verified).to.be.rejectedWith(/eddsa keys are considered too weak/);

    const opt5 = {
      message: await openpgp.readMessage({ armoredMessage: signed }),
      verificationKeys: [key],
      config: { rejectCurves: new Set([openpgp.enums.curve.ed25519]) }
    };
    const { signatures: [sig5] } = await openpgp.verify(opt5);
    await expect(sig5.verified).to.be.eventually.rejectedWith(/Support for eddsa keys using curve ed25519 is disabled/);
  });

  describe('detects unknown config property', async function() {
    const invalidConfig = { invalidProp: false };
    const fnNames = ['generateKey', 'encryptKey', 'decryptKey', 'reformatKey', 'revokeKey', 'sign', 'encrypt', 'verify', 'decrypt', 'generateSessionKey', 'encryptSessionKey', 'decryptSessionKeys'];
    fnNames.forEach(name => it(`openpgp.${name}`, async function() {
      await expect(openpgp[name]({ config: invalidConfig })).to.be.rejectedWith(/Unknown config property: invalidProp/);
    }));
  });
});
