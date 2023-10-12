/* eslint-disable max-lines */
const stream = require('@openpgp/web-stream-tools');
const stub = require('sinon/lib/sinon/stub');
const { use: chaiUse, expect } = require('chai');
chaiUse(require('chai-as-promised'));

const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../..');
const crypto = require('../../src/crypto');
const util = require('../../src/util');

const input = require('./testInputs');

function stringify(array) {
  if (stream.isStream(array)) {
    return stream.readToEnd(array).then(stringify);
  }

  if (!util.isUint8Array(array)) {
    throw new Error('Data must be in the form of a Uint8Array');
  }

  const result = [];
  for (let i = 0; i < array.length; i++) {
    result[i] = String.fromCharCode(array[i]);
  }
  return result.join('');
}

module.exports = () => describe('Packet', function() {
  const allAllowedPackets = util.constructAllowedPackets([...Object.values(openpgp).filter(packetClass => !!packetClass.tag)]);

  const armored_key =
      '-----BEGIN PGP PRIVATE KEY BLOCK-----\n' +
      'Version: GnuPG v2.0.19 (GNU/Linux)\n' +
      '\n' +
      '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\n' +
      'YRlci72GHhlyos8YHA==\n' +
      '=KXkj\n' +
      '-----END PGP PRIVATE KEY BLOCK-----';

  it('Symmetrically encrypted packet without integrity protection - allow decryption', async function() {
    const aeadProtectVal = openpgp.config.aeadProtect;
    const allowUnauthenticatedMessagesVal = openpgp.config.allowUnauthenticatedMessages;
    openpgp.config.aeadProtect = false;
    openpgp.config.allowUnauthenticatedMessages = true;

    const message = new openpgp.PacketList();
    const testText = input.createSomeMessage();

    const literal = new openpgp.LiteralDataPacket();
    literal.setText(testText);

    try {
      const enc = new openpgp.SymmetricallyEncryptedDataPacket();
      enc.packets = new openpgp.PacketList();
      enc.packets.push(literal);
      message.push(enc);

      const key = new Uint8Array([1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2]);
      const algo = openpgp.enums.symmetric.aes256;

      await enc.encrypt(algo, key, undefined, openpgp.config);

      const msg2 = new openpgp.PacketList();
      await msg2.read(message.write(), util.constructAllowedPackets([openpgp.SymmetricallyEncryptedDataPacket]));
      await msg2[0].decrypt(algo, key, undefined, openpgp.config);

      expect(await stringify(msg2[0].packets[0].data)).to.equal(stringify(literal.data));
    } finally {
      openpgp.config.aeadProtect = aeadProtectVal;
      openpgp.config.allowUnauthenticatedMessages = allowUnauthenticatedMessagesVal;
    }
  });

  it('Symmetrically encrypted packet without integrity protection - disallow decryption by default', async function() {
    const aeadProtectVal = openpgp.config.aeadProtect;
    openpgp.config.aeadProtect = false;

    try {
      const message = new openpgp.PacketList();
      const testText = input.createSomeMessage();

      const literal = new openpgp.LiteralDataPacket();
      literal.setText(testText);

      const enc = new openpgp.SymmetricallyEncryptedDataPacket();
      enc.packets = new openpgp.PacketList();
      enc.packets.push(literal);
      message.push(enc);

      const key = new Uint8Array([1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2]);
      const algo = openpgp.enums.symmetric.aes256;

      await enc.encrypt(algo, key, undefined, openpgp.config);

      const msg2 = new openpgp.PacketList();
      await msg2.read(message.write(), util.constructAllowedPackets([openpgp.SymmetricallyEncryptedDataPacket]));
      await expect(msg2[0].decrypt(algo, key, undefined, openpgp.config)).to.eventually.be.rejectedWith('Message is not authenticated.');
    } finally {
      openpgp.config.aeadProtect = aeadProtectVal;
    }
  });

  it('Sym. encrypted integrity protected packet', async function() {
    const key = new Uint8Array([1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2]);
    const algo = openpgp.enums.symmetric.aes256;
    const testText = input.createSomeMessage();

    const literal = new openpgp.LiteralDataPacket();
    const enc = new openpgp.SymEncryptedIntegrityProtectedDataPacket();
    enc.packets = new openpgp.PacketList();
    enc.packets.push(literal);
    const msg = new openpgp.PacketList();
    msg.push(enc);

    literal.setText(testText);
    await enc.encrypt(algo, key, undefined, openpgp.config);

    const msg2 = new openpgp.PacketList();
    await msg2.read(msg.write(), allAllowedPackets);
    await msg2[0].decrypt(algo, key, undefined, openpgp.config);

    expect(await stringify(msg2[0].packets[0].data)).to.equal(stringify(literal.data));
  });

  it('Sym. encrypted AEAD protected packet', function() {
    const aeadProtectVal = openpgp.config.aeadProtect;
    openpgp.config.aeadProtect = false;

    try {
      const key = new Uint8Array([1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2]);
      const algo = openpgp.enums.symmetric.aes256;
      const testText = input.createSomeMessage();
      const literal = new openpgp.LiteralDataPacket();
      literal.setText(testText);
      const enc = new openpgp.AEADEncryptedDataPacket();
      enc.packets = new openpgp.PacketList();
      enc.packets.push(literal);
      const msg = new openpgp.PacketList();
      msg.push(enc);

      const msg2 = new openpgp.PacketList();

      return enc.encrypt(algo, key, undefined, openpgp.config).then(async function() {
        await msg2.read(msg.write(), allAllowedPackets);
        return msg2[0].decrypt(algo, key);
      }).then(async function() {
        expect(await stream.readToEnd(msg2[0].packets[0].data)).to.deep.equal(literal.data);
      });
    } finally {
      openpgp.config.aeadProtect = aeadProtectVal;
    }
  });

  function cryptStub(webCrypto, method) {
    const crypt = webCrypto[method];
    const cryptStub = stub(webCrypto, method);
    let cryptCallsActive = 0;
    cryptStub.onCall(0).callsFake(async function() {
      cryptCallsActive++;
      try {
        return await crypt.apply(this, arguments); // eslint-disable-line no-invalid-this
      } finally {
        cryptCallsActive--;
      }
    });
    cryptStub.onCall(1).callsFake(function() {
      expect(cryptCallsActive).to.equal(1);
      return crypt.apply(this, arguments); // eslint-disable-line no-invalid-this
    });
    cryptStub.callThrough();
    return cryptStub;
  }

  it('Sym. encrypted AEAD protected packet is encrypted in parallel (AEAD, GCM)', async function() {
    const webCrypto = util.getWebCrypto();
    if (!webCrypto || util.getNodeCrypto()) return;
    const encryptStub = cryptStub(webCrypto, 'encrypt');
    const decryptStub = cryptStub(webCrypto, 'decrypt');

    const testText = input.createSomeMessage();

    const key = new Uint8Array([1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2]);
    const algo = openpgp.enums.symmetric.aes256;

    const literal = new openpgp.LiteralDataPacket();
    literal.setText(testText);
    const enc = new openpgp.AEADEncryptedDataPacket();
    enc.aeadAlgorithm = openpgp.enums.aead.experimentalGCM;
    enc.packets = new openpgp.PacketList();
    enc.packets.push(literal);
    const msg = new openpgp.PacketList();
    msg.push(enc);

    const msg2 = new openpgp.PacketList();

    try {
      await enc.encrypt(algo, key, { ...openpgp.config, aeadChunkSizeByte: 0 });
      await msg2.read(msg.write(), allAllowedPackets);
      await msg2[0].decrypt(algo, key);
      expect(await stream.readToEnd(msg2[0].packets[0].data)).to.deep.equal(literal.data);
      expect(encryptStub.callCount > 1).to.be.true;
      expect(decryptStub.callCount > 1).to.be.true;
    } finally {
      encryptStub.restore();
      decryptStub.restore();
    }
  });

  it('Sym. encrypted AEAD protected packet test vector (AEAD)', async function() {
    // From https://gitlab.com/openpgp-wg/rfc4880bis/commit/00b20923e6233fb6ff1666ecd5acfefceb32907d

    const nodeCrypto = util.getNodeCrypto();
    if (!nodeCrypto) return;

    const packetBytes = util.hexToUint8Array(`
      d4 4a 01 07 01 0e b7 32  37 9f 73 c4 92 8d e2 5f
      ac fe 65 17 ec 10 5d c1  1a 81 dc 0c b8 a2 f6 f3
      d9 00 16 38 4a 56 fc 82  1a e1 1a e8 db cb 49 86
      26 55 de a8 8d 06 a8 14  86 80 1b 0f f3 87 bd 2e
      ab 01 3d e1 25 95 86 90  6e ab 24 76
    `.replace(/\s+/g, ''));

    const iv = util.hexToUint8Array('b7 32 37 9f 73 c4 92 8d e2 5f ac fe 65 17 ec 10'.replace(/\s+/g, ''));
    const key = util.hexToUint8Array('86 f1 ef b8 69 52 32 9f 24 ac d3 bf d0 e5 34 6d'.replace(/\s+/g, ''));
    const algo = openpgp.enums.symmetric.aes128;

    const literal = new openpgp.LiteralDataPacket(0);
    literal.setBytes(util.stringToUint8Array('Hello, world!\n'), openpgp.enums.literal.binary);
    literal.filename = '';
    const enc = new openpgp.AEADEncryptedDataPacket();
    enc.packets = new openpgp.PacketList();
    enc.packets.push(literal);
    const msg = new openpgp.PacketList();
    msg.push(enc);

    const msg2 = new openpgp.PacketList();

    const randomBytesStub = stub(nodeCrypto, 'randomBytes');
    randomBytesStub.returns(iv);

    try {
      await enc.encrypt(algo, key, { ...openpgp.config, aeadChunkSizeByte: 14 });
      const data = msg.write();
      expect(await stream.readToEnd(stream.clone(data))).to.deep.equal(packetBytes);
      await msg2.read(data, allAllowedPackets);
      await msg2[0].decrypt(algo, key);
      expect(await stream.readToEnd(msg2[0].packets[0].data)).to.deep.equal(literal.data);
    } finally {
      randomBytesStub.restore();
    }
  });

  it('Sym. encrypted session key with a compressed packet', async function() {
    const msg =
        '-----BEGIN PGP MESSAGE-----\n' +
        'Version: GnuPG v2.0.19 (GNU/Linux)\n' +
        '\n' +
        'jA0ECQMCpo7I8WqsebTJ0koBmm6/oqdHXJU9aPe+Po+nk/k4/PZrLmlXwz2lhqBg\n' +
        'GAlY9rxVStLBrg0Hn+5gkhyHI9B85rM1BEYXQ8pP5CSFuTwbJ3O2s67dzQ==\n' +
        '=VZ0/\n' +
        '-----END PGP MESSAGE-----';

    const msgbytes = (await openpgp.unarmor(msg)).data;

    const parsed = new openpgp.PacketList();
    await parsed.read(msgbytes, allAllowedPackets);
    const [skesk, seip] = parsed;

    await skesk.decrypt('test');
    return seip.decrypt(skesk.sessionKeyAlgorithm, skesk.sessionKey).then(async () => {
      const compressed = seip.packets[0];

      const result = await stringify(compressed.packets[0].data);

      expect(result).to.equal('Hello world!\n');
    });
  });

  it('Public key encrypted symmetric key packet', function() {
    const rsa = openpgp.enums.publicKey.rsaEncryptSign;
    const keySize = 1024;

    return crypto.generateParams(rsa, keySize, 65537).then(function({ publicParams, privateParams }) {
      const enc = new openpgp.PublicKeyEncryptedSessionKeyPacket();
      const msg = new openpgp.PacketList();
      const msg2 = new openpgp.PacketList();

      enc.sessionKey = new Uint8Array([1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2]);
      enc.publicKeyAlgorithm = openpgp.enums.publicKey.rsaEncryptSign;
      enc.sessionKeyAlgorithm = openpgp.enums.symmetric.aes256;
      enc.publicKeyID.bytes = '12345678';
      return enc.encrypt({ publicParams, getFingerprintBytes() {} }).then(async () => {

        msg.push(enc);
        await msg2.read(msg.write(), allAllowedPackets);

        const privateKey = { algorithm: openpgp.enums.publicKey.rsaEncryptSign, publicParams, privateParams, getFingerprintBytes() {} };
        return msg2[0].decrypt(privateKey).then(() => {
          expect(stringify(msg2[0].sessionKey)).to.equal(stringify(enc.sessionKey));
          expect(msg2[0].sessionKeyAlgorithm).to.equal(enc.sessionKeyAlgorithm);
        });
      });
    });
  });

  it('Secret key packet (reading, unencrypted)', async function() {
    const armored_key =
        '-----BEGIN PGP PRIVATE KEY BLOCK-----\n' +
        'Version: GnuPG v2.0.19 (GNU/Linux)\n' +
        '\n' +
        'lQHYBFF33iMBBAC9YfOYahJlWrVj2J1TjQiZLunWljI4G9e6ARTyD99nfOkV3swh\n' +
        '0WaOse4Utj7BfTqdYcoezhCaQpuExUupKWZqmduBcwSmEBfNu1XyKcxlDQuuk0Vk\n' +
        'viGC3kFRce/cJaKVFSRU8V5zPgt6KQNv/wNz7ydEisaSoNbk51vQt5oGfwARAQAB\n' +
        'AAP5AVL8xWMuKgLj9g7/wftMH+jO7vhAxje2W3Y+8r8TnOSn0536lQvzl/eQyeLC\n' +
        'VK2k3+7+trgO7I4KuXCXZqgAbEi3niDYXDaCJ+8gdR9qvPM2gi9NM71TGXZvGE0w\n' +
        'X8gIZfqLTQWKm9TIS/3tdrth4nwhiye0ASychOboIiN6VIECAMbCQ4/noxGV6yTK\n' +
        'VezsGSz+iCMxz2lV270/Ac2C5WPk+OlxXloxUXeEkGIr6Xkmhhpceed2KL41UC8Y\n' +
        'w5ttGIECAPPsahniKGyqp9CHy6W0B83yhhcIbmLlaVG2ftKyUEDxIggzOlXuVrue\n' +
        'z9XRd6wFqwDd1QMFW0uUyHPDCIFPnv8CAJaDFSZutuWdWMt15NZXjfgRgfJuDrtv\n' +
        'E7yFY/p0el8lCihOT8WoHbTn1PbCYMzNBc0IhHaZKAtA2pjkE+wzz9ClP7QbR2Vv\n' +
        'cmdlIDxnZW9yZ2VAZXhhbXBsZS5jb20+iLkEEwECACMFAlF33iMCGwMHCwkIBwMC\n' +
        'AQYVCAIJCgsEFgIDAQIeAQIXgAAKCRBcqs36fwJCXRbvA/9LPiK6WFKcFoNBnLEJ\n' +
        'mS/CNkL8yTpkslpCP6+TwJMc8uXqwYl9/PW2+CwmzZjs6JsvTzMcR/ZbfZJuSW6Y\n' +
        'EsLNejsSpgcY9aiewGtE+53e5oKYnlmVMTWOPywciIgMvXlzdGhxcwqJ8u0hT+ug\n' +
        '9CjcAfuX9yw85LwXtdGwNh7J8Q==\n' +
        '=lKiS\n' +
        '-----END PGP PRIVATE KEY BLOCK-----';

    let key = new openpgp.PacketList();
    await key.read((await openpgp.unarmor(armored_key)).data, allAllowedPackets);
    key = key[0];

    const enc = new openpgp.PublicKeyEncryptedSessionKeyPacket();
    const secret = new Uint8Array([1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2]);

    enc.sessionKey = secret;
    enc.publicKeyAlgorithm = openpgp.enums.publicKey.rsaEncryptSign;
    enc.sessionKeyAlgorithm = openpgp.enums.symmetric.aes256;
    enc.publicKeyID.bytes = '12345678';

    return enc.encrypt(key).then(() => {
      return enc.decrypt(key).then(() => {
        expect(stringify(enc.sessionKey)).to.equal(stringify(secret));
      });
    });
  });

  it('Public key encrypted packet (reading, GPG)', async function() {
    const armored_key =
        '-----BEGIN PGP PRIVATE KEY BLOCK-----\n' +
        'Version: GnuPG v2.0.19 (GNU/Linux)\n' +
        '\n' +
        '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\n' +
        '=FSwA\n' +
        '-----END PGP PRIVATE KEY BLOCK-----';

    const armored_msg =
        '-----BEGIN PGP MESSAGE-----\n' +
        'Version: GnuPG v2.0.19 (GNU/Linux)\n' +
        '\n' +
        'hIwDFYET+7bfx/ABA/95Uc9942Tg8oqpO0vEu2eSKwPALM3a0DrVdAiFOIK/dJmZ\n' +
        'YrtPRw3EEwHZjl6CO9RD+95iE27tPbsICw1K43gofSV/wWsPO6vvs3eftQYHSxxa\n' +
        'IQbTPImiRaJ73Mf7iM3CNtQM4iUBsx1HnUGl+rtD0nz3fLm6i3CjwiNQWW42I9JH\n' +
        'AWv8EvvpxZ8X2ClFfSW3UVBoROHe9CAWHM/40nGutAZK8MIgmUI4xqkLFBbqqTyx\n' +
        '/cDSC4Q+sv65UX4urbfc7uJuk1Cpj54=\n' +
        '=iSaK\n' +
        '-----END PGP MESSAGE-----';

    let key = new openpgp.PacketList();
    await key.read((await openpgp.unarmor(armored_key)).data, allAllowedPackets);
    key = key[3];

    const msg = new openpgp.PacketList();
    await msg.read((await openpgp.unarmor(armored_msg)).data, allAllowedPackets);

    return msg[0].decrypt(key).then(async () => {
      await msg[1].decrypt(msg[0].sessionKeyAlgorithm, msg[0].sessionKey);

      const text = await stringify(msg[1].packets[0].packets[0].data);

      expect(text).to.equal('Hello world!');
    });
  });

  it('Sym. encrypted session key reading/writing (CFB)', async function() {
    const aeadProtectVal = openpgp.config.aeadProtect;
    openpgp.config.aeadProtect = false;

    try {
      const passphrase = 'hello';
      const algo = openpgp.enums.symmetric.aes256;
      const testText = input.createSomeMessage();

      const literal = new openpgp.LiteralDataPacket();
      literal.setText(testText);
      const skesk = new openpgp.SymEncryptedSessionKeyPacket();
      const seip = new openpgp.SymEncryptedIntegrityProtectedDataPacket();
      seip.packets = new openpgp.PacketList();
      seip.packets.push(literal);
      const msg = new openpgp.PacketList();

      msg.push(skesk);
      msg.push(seip);

      skesk.sessionKeyAlgorithm = algo;
      await skesk.encrypt(passphrase, openpgp.config);

      const key = skesk.sessionKey;
      await seip.encrypt(algo, key, undefined, openpgp.config);

      const msg2 = new openpgp.PacketList();
      await msg2.read(msg.write(), allAllowedPackets);

      await msg2[0].decrypt(passphrase);
      const key2 = msg2[0].sessionKey;
      await msg2[1].decrypt(msg2[0].sessionKeyAlgorithm, key2);

      expect(await stringify(msg2[1].packets[0].data)).to.equal(stringify(literal.data));
    } finally {
      openpgp.config.aeadProtect = aeadProtectVal;
    }
  });

  it('Sym. encrypted session key reading/writing (AEAD)', async function() {
    const aeadProtectVal = openpgp.config.aeadProtect;
    openpgp.config.aeadProtect = true;

    try {
      const passphrase = 'hello';
      const algo = openpgp.enums.symmetric.aes256;
      const testText = input.createSomeMessage();

      const literal = new openpgp.LiteralDataPacket();
      literal.setText(testText);
      const skesk = new openpgp.SymEncryptedSessionKeyPacket();
      const aeadEnc = new openpgp.AEADEncryptedDataPacket();
      aeadEnc.packets = new openpgp.PacketList();
      aeadEnc.packets.push(literal);
      const msg = new openpgp.PacketList();
      msg.push(skesk);
      msg.push(aeadEnc);

      skesk.sessionKeyAlgorithm = algo;
      await skesk.encrypt(passphrase, openpgp.config);

      const key = skesk.sessionKey;
      await aeadEnc.encrypt(algo, key, undefined, openpgp.config);

      const msg2 = new openpgp.PacketList();
      await msg2.read(msg.write(), allAllowedPackets);

      await msg2[0].decrypt(passphrase);
      const key2 = msg2[0].sessionKey;
      await msg2[1].decrypt(msg2[0].sessionKeyAlgorithm, key2);

      expect(await stringify(msg2[1].packets[0].data)).to.equal(stringify(literal.data));
    } finally {
      openpgp.config.aeadProtect = aeadProtectVal;
    }
  });

  it('Sym. encrypted session key reading/writing test vector (EAX, AEAD)', async function() {
    // From https://gitlab.com/openpgp-wg/rfc4880bis/blob/00b20923/back.mkd#sample-aead-eax-encryption-and-decryption

    const nodeCrypto = util.getNodeCrypto();
    if (!nodeCrypto) return;

    const aeadProtectVal = openpgp.config.aeadProtect;
    const aeadChunkSizeByteVal = openpgp.config.aeadChunkSizeByte;
    const s2kIterationCountByteVal = openpgp.config.s2kIterationCountByte;
    openpgp.config.aeadProtect = true;
    openpgp.config.aeadChunkSizeByte = 14;
    openpgp.config.s2kIterationCountByte = 0x90;

    const salt = util.hexToUint8Array('cd5a9f70fbe0bc65');
    const sessionKey = util.hexToUint8Array('86 f1 ef b8 69 52 32 9f 24 ac d3 bf d0 e5 34 6d'.replace(/\s+/g, ''));
    const sessionIV = util.hexToUint8Array('bc 66 9e 34 e5 00 dc ae dc 5b 32 aa 2d ab 02 35'.replace(/\s+/g, ''));
    const dataIV = util.hexToUint8Array('b7 32 37 9f 73 c4 92 8d e2 5f ac fe 65 17 ec 10'.replace(/\s+/g, ''));

    const randomBytesStub = stub(nodeCrypto, 'randomBytes');
    randomBytesStub.onCall(0).returns(salt);
    randomBytesStub.onCall(1).returns(sessionKey);
    randomBytesStub.onCall(2).returns(sessionIV);
    randomBytesStub.onCall(3).returns(dataIV);

    const packetBytes = util.hexToUint8Array(`
      c3 3e 05 07 01 03 08 cd  5a 9f 70 fb e0 bc 65 90
      bc 66 9e 34 e5 00 dc ae  dc 5b 32 aa 2d ab 02 35
      9d ee 19 d0 7c 34 46 c4  31 2a 34 ae 19 67 a2 fb
      7e 92 8e a5 b4 fa 80 12  bd 45 6d 17 38 c6 3c 36

      d4 4a 01 07 01 0e b7 32  37 9f 73 c4 92 8d e2 5f
      ac fe 65 17 ec 10 5d c1  1a 81 dc 0c b8 a2 f6 f3
      d9 00 16 38 4a 56 fc 82  1a e1 1a e8 db cb 49 86
      26 55 de a8 8d 06 a8 14  86 80 1b 0f f3 87 bd 2e
      ab 01 3d e1 25 95 86 90  6e ab 24 76
    `.replace(/\s+/g, ''));

    try {
      const passphrase = 'password';
      const algo = openpgp.enums.symmetric.aes128;

      const literal = new openpgp.LiteralDataPacket(0);
      literal.setBytes(util.stringToUint8Array('Hello, world!\n'), openpgp.enums.literal.binary);
      literal.filename = '';
      const skesk = new openpgp.SymEncryptedSessionKeyPacket();
      skesk.sessionKeyAlgorithm = algo;
      const encData = new openpgp.AEADEncryptedDataPacket();
      encData.packets = new openpgp.PacketList();
      encData.packets.push(literal);
      const msg = new openpgp.PacketList();
      msg.push(skesk);
      msg.push(encData);

      await skesk.encrypt(passphrase, openpgp.config);

      const key = skesk.sessionKey;
      await encData.encrypt(algo, key, undefined, openpgp.config);

      const data = msg.write();
      expect(await stream.readToEnd(stream.clone(data))).to.deep.equal(packetBytes);

      const msg2 = new openpgp.PacketList();
      await msg2.read(data, allAllowedPackets);

      await msg2[0].decrypt(passphrase);
      const key2 = msg2[0].sessionKey;
      await msg2[1].decrypt(msg2[0].sessionKeyAlgorithm, key2);

      expect(await stringify(msg2[1].packets[0].data)).to.equal(stringify(literal.data));
    } finally {
      openpgp.config.aeadProtect = aeadProtectVal;
      openpgp.config.aeadChunkSizeByte = aeadChunkSizeByteVal;
      openpgp.config.s2kIterationCountByte = s2kIterationCountByteVal;
      randomBytesStub.restore();
    }
  });

  it('Sym. encrypted session key reading/writing test vector (AEAD, OCB)', async function() {
    // From https://gitlab.com/openpgp-wg/rfc4880bis/blob/00b20923/back.mkd#sample-aead-ocb-encryption-and-decryption

    const nodeCrypto = util.getNodeCrypto();
    if (!nodeCrypto) return;

    const aeadProtectVal = openpgp.config.aeadProtect;
    const aeadChunkSizeByteVal = openpgp.config.aeadChunkSizeByte;
    const s2kIterationCountByteVal = openpgp.config.s2kIterationCountByte;
    openpgp.config.aeadProtect = true;
    openpgp.config.aeadChunkSizeByte = 14;
    openpgp.config.s2kIterationCountByte = 0x90;

    const salt = util.hexToUint8Array('9f0b7da3e5ea6477');
    const sessionKey = util.hexToUint8Array('d1 f0 1b a3 0e 13 0a a7 d2 58 2c 16 e0 50 ae 44'.replace(/\s+/g, ''));
    const sessionIV = util.hexToUint8Array('99 e3 26 e5 40 0a 90 93 6c ef b4 e8 eb a0 8c'.replace(/\s+/g, ''));
    const dataIV = util.hexToUint8Array('5e d2 bc 1e 47 0a be 8f 1d 64 4c 7a 6c 8a 56'.replace(/\s+/g, ''));

    const randomBytesStub = stub(nodeCrypto, 'randomBytes');
    randomBytesStub.onCall(0).returns(salt);
    randomBytesStub.onCall(1).returns(sessionKey);
    randomBytesStub.onCall(2).returns(sessionIV);
    randomBytesStub.onCall(3).returns(dataIV);

    const packetBytes = util.hexToUint8Array(`
      c3 3d 05 07 02 03 08 9f  0b 7d a3 e5 ea 64 77 90
      99 e3 26 e5 40 0a 90 93  6c ef b4 e8 eb a0 8c 67
      73 71 6d 1f 27 14 54 0a  38 fc ac 52 99 49 da c5
      29 d3 de 31 e1 5b 4a eb  72 9e 33 00 33 db ed

      d4 49 01 07 02 0e 5e d2  bc 1e 47 0a be 8f 1d 64
      4c 7a 6c 8a 56 7b 0f 77  01 19 66 11 a1 54 ba 9c
      25 74 cd 05 62 84 a8 ef  68 03 5c 62 3d 93 cc 70
      8a 43 21 1b b6 ea f2 b2  7f 7c 18 d5 71 bc d8 3b
      20 ad d3 a0 8b 73 af 15  b9 a0 98
    `.replace(/\s+/g, ''));

    try {
      const passphrase = 'password';
      const algo = openpgp.enums.symmetric.aes128;

      const literal = new openpgp.LiteralDataPacket(0);
      literal.setBytes(util.stringToUint8Array('Hello, world!\n'), openpgp.enums.literal.binary);
      literal.filename = '';
      const skesk = new openpgp.SymEncryptedSessionKeyPacket();
      skesk.sessionKeyAlgorithm = algo;
      const enc = new openpgp.AEADEncryptedDataPacket();
      enc.packets = new openpgp.PacketList();
      enc.packets.push(literal);
      enc.aeadAlgorithm = skesk.aeadAlgorithm = openpgp.enums.aead.ocb;
      const msg = new openpgp.PacketList();
      msg.push(skesk);
      msg.push(enc);

      await skesk.encrypt(passphrase, openpgp.config);

      const key = skesk.sessionKey;
      await enc.encrypt(algo, key, undefined, openpgp.config);

      const data = msg.write();
      expect(await stream.readToEnd(stream.clone(data))).to.deep.equal(packetBytes);

      const msg2 = new openpgp.PacketList();
      await msg2.read(data, allAllowedPackets);

      await msg2[0].decrypt(passphrase);
      const key2 = msg2[0].sessionKey;
      await msg2[1].decrypt(msg2[0].sessionKeyAlgorithm, key2);

      expect(await stringify(msg2[1].packets[0].data)).to.equal(stringify(literal.data));
    } finally {
      openpgp.config.aeadProtect = aeadProtectVal;
      openpgp.config.aeadChunkSizeByte = aeadChunkSizeByteVal;
      openpgp.config.s2kIterationCountByte = s2kIterationCountByteVal;
      randomBytesStub.restore();
    }
  });

  it('Secret key encryption/decryption test', async function() {
    const armored_msg =
        '-----BEGIN PGP MESSAGE-----\n' +
        'Version: GnuPG v2.0.19 (GNU/Linux)\n' +
        '\n' +
        'hIwD95D9aHS5fxEBA/98CwH54XZmwobOmHUcvWcDDQysBEC4uf7wASiGcRbejDaO\n' +
        'aJqcrK/3k8sBQMO7yOhvrCRqqpGDqnmx7IaaKLnZS7nYAZoHEsK9UyG0hDa8Cfbo\n' +
        'CP4xZVcgIvIfAW/in1LeT2td0QcQNbeewBmPea+vQEEvRgIP10tlE7MK8Ay48dJH\n' +
        'AagMgNYg7MBUjpuOCVrjM1pWja8uzbULfYhTq3IJ8H3QhbdT+k9khY9f0aJPEeYi\n' +
        'dVv6DK9uviMGc/DsVCw5K8lQRLlkcHc=\n' +
        '=pR+C\n' +
        '-----END PGP MESSAGE-----';

    const keyPackets = new openpgp.PacketList();
    await keyPackets.read((await openpgp.unarmor(armored_key)).data, allAllowedPackets);
    const keyPacket = keyPackets[3];
    await keyPacket.decrypt('test');

    const msg = new openpgp.PacketList();
    await msg.read((await openpgp.unarmor(armored_msg)).data, allAllowedPackets);

    return msg[0].decrypt(keyPacket).then(async () => {
      await msg[1].decrypt(msg[0].sessionKeyAlgorithm, msg[0].sessionKey);

      const text = await stringify(msg[1].packets[0].packets[0].data);

      expect(text).to.equal('Hello world!');
    });
  });

  it('Secret key reading with signature verification.', async function() {
    const packets = await openpgp.PacketList.fromBinary((await openpgp.unarmor(armored_key)).data, allAllowedPackets);
    const [keyPacket, userIDPacket, keySigPacket, subkeyPacket, subkeySigPacket] = packets;

    await keySigPacket.verify(
      keyPacket, openpgp.enums.signature.certGeneric, { userID: userIDPacket, key: keyPacket }
    );
    await subkeySigPacket.verify(
      keyPacket, openpgp.enums.signature.keyBinding, { key: keyPacket, bind: subkeyPacket }
    );
  });

  it('Reading a signed, encrypted message.', async function() {
    const armored_msg =
        '-----BEGIN PGP MESSAGE-----\n' +
        'Version: GnuPG v2.0.19 (GNU/Linux)\n' +
        '\n' +
        'hIwD95D9aHS5fxEBA/4/X4myvH+jB1HYNeZvdK+WsBNDMfLsBGOf205Rxr3vSob/\n' +
        'A09boj8/9lFaipqu+AEdQKEjCB8sZ+OY0WiQPEPpuhG+mVqDqEiPFkdpcqNtS0VV\n' +
        'pwqplHo6QnH2MHfxprZHYuwcEC9ynJCxJ6kSCD8Xs99h+PjxNNw7NhMjkF+N69LA\n' +
        'NwGPtbLx2/r2nR4gO8gV92A2RQCOwPP7ZV+6fXgWIs+mhyCHFP3xUP5DaFCNM8mo\n' +
        'PN97i659ucxF6IbOoK56FEaUbOPTD6xdyhWamxKfMsIb0UJgVUNhGaq+VlvOJxaB\n' +
        'iRcnY5UxsypKgtqfcKIseb21MIo4vcNdogyxBIDlAO472Zfxn0udzr6W2aQ77+NK\n' +
        'FE1O0kCXS+DTFOYYVD7X8rXGSglQsdXJmHd89sdYFQkO7D7bOLdRJuXgdgH2czCs\n' +
        'UBGuHZzsGbTdyKvpVBuS3rnyHHBk6oCnsm1Nl7eLs64VkZUxjEUbq5pb4dlr1pw2\n' +
        'ztpmpAnRcmM=\n' +
        '=htrB\n' +
        '-----END PGP MESSAGE-----';

    const packets = await openpgp.PacketList.fromBinary((await openpgp.unarmor(armored_key)).data, allAllowedPackets);
    const keyPacket = packets[0];
    const subkeyPacket = packets[3];
    await subkeyPacket.decrypt('test');

    const msg = new openpgp.PacketList();
    await msg.read((await openpgp.unarmor(armored_msg)).data, allAllowedPackets);
    const [pkesk, encData] = msg;

    return pkesk.decrypt(subkeyPacket).then(async () => {
      await encData.decrypt(pkesk.sessionKeyAlgorithm, pkesk.sessionKey);

      const payload = encData.packets[0].packets;
      payload.push(...await stream.readToEnd(payload.stream, arr => arr));
      const literal = payload[1];
      const signature = payload[2];

      await Promise.all([
        signature.verify(keyPacket, openpgp.enums.signature.binary, literal),
        stream.readToEnd(literal.getBytes())
      ]);
    });
  });

  it('Reading signersUserID from armored signature', async function() {
    const armoredSignature =
`-----BEGIN PGP SIGNATURE-----

iQFKBAEBCgA0FiEEdOyNPagqedqiXfEMa6Ve2Dq64bsFAlszXwQWHHRlc3Qtd2tk
QG1ldGFjb2RlLmJpegAKCRBrpV7YOrrhuw1PB/9KhFRR/M3OR6NmIent6ri1ekWn
vlcnVqj6N4Xqi1ahRVw19/Jx36mGyijxNwqqGrziqRiPCdT0pKfCfv7nXQf2Up1Z
LoR1StqpBMSDQfuF6JAJmJuB9T+mPQO8wYeUp+O63vQnm5CgqyoRlIoqX8MN6GTY
xK5PdTRjw6IEIGr9uLgSoUwTd0ECY1F9ptyuLGD5ET5ZtyUenQSbX+cw5WCGLFzi
7TwKTY+kGQpkwDJKZJSGpoP7ob6xdDfZx6dHV6IfIJg8/F9gtAXFp8uE51L90cV2
kePFjAnu9cpynKXu3usf8+FuBw2zLsg1Id1n7ttxoAte416KjBN9lFBt8mcu
=wEIR
-----END PGP SIGNATURE-----`;

    const signature = await openpgp.readSignature({ armoredSignature });

    expect(signature.packets[0].signersUserID).to.equal('test-wkd@metacode.biz');
  });

  it('Reading notations from armored key', async function() {
    const pubkey =
`-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBFzQOToBCADd0Pwh8edZ6gR3x49L1PaBPtiAQUr1QDUDWeNes8co5MTFl5hG
lHzptt+VD0JGucuIkvi34f5z2ZbInAV/xYDX3kSYefy6LB8XJD527I/o9bqY1P7T
PjtTZ4emcqNGkGhV2hNGV+hFcTevUS9Ty4vGg6P7X6RjfjeTrClHelJT8+9IiH+4
0h4X/Y1hwoijRWanYnZjuAUIrOXnG76iknXQRGc8th8iI0oIZfKQomfF0K5lXFhH
SU8Yvmik3vCTLHC6Ce0GVRCTIcU0/Xi2MK/Yrg9bGzSblHxomLU0NT6pee+2UjqR
BZXOAPLY66Lsh1oqxQ6ihVnOmbraU9glAGm1ABEBAAG0EFRlc3R0IDx0ZXN0QGV4
YT6JAYoEEwEIAHQCGwMFCQPCZwAFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AWIQQZ
jHIqS6wzbp2qrkRXnQGzq+FUDgUCXNA5VBoUgAAAAAAQAAF0ZXN0QGV4YW1wbGUu
Y29tMhoUgAAAAAAQAAF0ZXN0QGV4YW1wbGUuY29tMwAKCRBXnQGzq+FUDoLiCACn
ls1iy0hT59Xt3o3tmmxe1jLzkbQEprR6MMfZamtex5/BHViu2HPAu5i13mXyBRnJ
4Zvd/HUxJukP3tdQyJIlZFe8XwloMoRAA37KOZ5QGyKH8Jxq3LcAcQOOkFtWgr+Z
JbjUKF1IuqCsK6SYB8f7SVKgpZk/kqG3HE3gk72ONnqdvwOa9cIhAuZScdgZ+PLC
6W/0+IrnQIasvKeEWeK4u6/NYT35HUsUE/9Z6WKF+qxJnp5Pi2Q5cio6bFlGDNQb
+MiuiEb3Mzb3ev2PVg7WELBRXOg8QlCxrghqfi1SH791mmiyGK+GIQgnjRwMejTh
dNsnHYag/KAewag55AQvuQENBFzQOToBCADJD+auK+Opo1q3ZLxODMyw5//XHJH4
0vQPNawyBiOdBuneWHF3jfDwGa+lOftUx1abSwsq+Qs955THgLVSiJvivHWVy8pN
tPv0XLa9rMj2wh/OmckbcgzSMeJJIz09bTj095ONPGYW2D4AcpkOc+b5bkqV6r+N
yk9nopPJNCNqYYJtecTClDT5haRKBP5XjXRVsIXva/nHZGXKQLX8iWG2D5DOJNDP
ZkAEoIPg+7J85Q3u2iSFPnLPzKHlMAoQW8d9RAEYyJ6WqiILUIDShhvXg+RIkzri
wY/WkvhB/Kpj0r1SRbNhWRpmOWCR+0a2uHaLz9X0KTP7WMqQbmIdpRgZABEBAAGJ
ATwEGAEIACYWIQQZjHIqS6wzbp2qrkRXnQGzq+FUDgUCXNA5OgIbDAUJA8JnAAAK
CRBXnQGzq+FUDgI6B/9Far0CUR6rWvUiviBY4P5oe44I9P9P7ilWmum1cIQWxMyF
0sc5tRcVLpMomURlrDz0TR5GNs+nuGAHTRBfN7VO0Y+R/LyEd1Rf80ONObXOqzMp
vF9CdW3a7W4WicZwnGgUOImTICazR2VmR+RREdZshqrOCaOnuKmN3QwGH1zzFwJA
sTbLoNMdBv8SEARaRVOWPM1HwJ701mMYF48FqhHd5uinH/ZCeBhqrBfhmXa68FWx
xuyJz6ttl5Fp4nsB3waQdgPGZJ9NUrGfopLUZ44xDuJjBONd7rbYOh71TWbHd8wG
V+HOQJQxXJkVRYa3QrFUehiMzTeqqMdgC6ZqJy7+
=et/d
-----END PGP PUBLIC KEY BLOCK-----`;

    const key = await openpgp.readKey({ armoredKey: pubkey });

    const { notations, rawNotations } = key.users[0].selfCertifications[0];

    // Even though there are two notations with the same keys
    // the `notations` property reads only the single one:
    // the last one encountered during parse
    expect(Object.keys(notations).length).to.equal(1);
    expect(notations['test@example.com']).to.equal('3');

    // On the other hand `rawNotations` property provides access to all
    // notations, even non human-readable. The values are not deserialized
    // and they are byte-arrays.
    expect(rawNotations.length).to.equal(2);

    expect(rawNotations[0].name).to.equal('test@example.com');
    expect(rawNotations[0].value).to.deep.equal(new Uint8Array(['2'.charCodeAt(0)]));
    expect(rawNotations[0].humanReadable).to.equal(true);

    expect(rawNotations[1].name).to.equal('test@example.com');
    expect(rawNotations[1].value).to.deep.equal(new Uint8Array(['3'.charCodeAt(0)]));
    expect(rawNotations[1].humanReadable).to.equal(true);
  });

  it('Writing and encryption of a secret key packet (AEAD)', async function() {
    const rsa = openpgp.enums.publicKey.rsaEncryptSign;
    const { privateParams, publicParams } = await crypto.generateParams(rsa, 1024, 65537);

    const secretKeyPacket = new openpgp.SecretKeyPacket();
    secretKeyPacket.privateParams = privateParams;
    secretKeyPacket.publicParams = publicParams;
    secretKeyPacket.algorithm = openpgp.enums.publicKey.rsaSign;
    secretKeyPacket.isEncrypted = false;
    await secretKeyPacket.encrypt('hello', { ...openpgp.config, aeadProtect: true });
    expect(secretKeyPacket.s2kUsage).to.equal(253);

    const raw = new openpgp.PacketList();
    raw.push(secretKeyPacket);
    const packetList = await openpgp.PacketList.fromBinary(raw.write(), allAllowedPackets, openpgp.config);
    const secretKeyPacket2 = packetList[0];
    await secretKeyPacket2.decrypt('hello');

    expect(secretKeyPacket2.privateParams).to.deep.equal(secretKeyPacket.privateParams);
    expect(secretKeyPacket2.publicParams).to.deep.equal(secretKeyPacket.publicParams);
  });

  it('Writing of unencrypted v5 secret key packet', async function() {
    const originalV5KeysSetting = openpgp.config.v5Keys;
    openpgp.config.v5Keys = true;

    try {
      const packet = new openpgp.SecretKeyPacket();

      packet.privateParams = { key: new Uint8Array([1, 2, 3]) };
      packet.publicParams = { pubKey: new Uint8Array([4, 5, 6]) };
      packet.algorithm = openpgp.enums.publicKey.rsaSign;
      packet.isEncrypted = false;
      packet.s2kUsage = 0;

      const written = packet.write();
      expect(written.length).to.equal(28);

      /* The serialized length of private data */
      expect(written[17]).to.equal(0);
      expect(written[18]).to.equal(0);
      expect(written[19]).to.equal(0);
      expect(written[20]).to.equal(5);

      /**
       * The private data
       *
       * The 2 bytes missing here are the length prefix of the MPI
       */
      expect(written[23]).to.equal(1);
      expect(written[24]).to.equal(2);
      expect(written[25]).to.equal(3);
    } finally {
      openpgp.config.v5Keys = originalV5KeysSetting;
    }
  });

  it('Writing and encryption of a secret key packet (CFB)', async function() {
    const rsa = openpgp.enums.publicKey.rsaEncryptSign;
    const { privateParams, publicParams } = await crypto.generateParams(rsa, 1024, 65537);
    const secretKeyPacket = new openpgp.SecretKeyPacket();
    secretKeyPacket.privateParams = privateParams;
    secretKeyPacket.publicParams = publicParams;
    secretKeyPacket.algorithm = openpgp.enums.publicKey.rsaSign;
    secretKeyPacket.isEncrypted = false;
    await secretKeyPacket.encrypt('hello', { ...openpgp.config, aeadProtect: false });
    expect(secretKeyPacket.s2kUsage).to.equal(254);

    const raw = new openpgp.PacketList();
    raw.push(secretKeyPacket);
    const packetList = await openpgp.PacketList.fromBinary(raw.write(), allAllowedPackets, openpgp.config);
    const secretKeyPacket2 = packetList[0];
    await secretKeyPacket2.decrypt('hello');
  });

  it('Writing and verification of a signature packet', function() {
    const rsa = openpgp.enums.publicKey.rsaEncryptSign;
    const key = new openpgp.SecretKeyPacket();

    return crypto.generateParams(rsa, 1024, 65537).then(async ({ privateParams, publicParams }) => {
      const testText = input.createSomeMessage();

      key.publicParams = publicParams;
      key.privateParams = privateParams;
      key.algorithm = openpgp.enums.publicKey.rsaSign;
      await key.computeFingerprintAndKeyID();

      const signed = new openpgp.PacketList();
      const literal = new openpgp.LiteralDataPacket();
      const signature = new openpgp.SignaturePacket();

      literal.setText(testText);

      signature.hashAlgorithm = openpgp.enums.hash.sha256;
      signature.publicKeyAlgorithm = openpgp.enums.publicKey.rsaSign;
      signature.signatureType = openpgp.enums.signature.text;

      return signature.sign(key, literal).then(async () => {

        signed.push(literal);
        signed.push(signature);

        const raw = signed.write();

        const signed2 = new openpgp.PacketList();
        await signed2.read(raw, allAllowedPackets);
        signed2.push(...await stream.readToEnd(signed2.stream, arr => arr));

        await Promise.all([
          signed2[1].verify(key, openpgp.enums.signature.text, signed2[0]),
          stream.readToEnd(signed2[0].getBytes())
        ]);
      });
    });
  });

  describe('PacketList parsing', function () {
    it('Ignores unknown packet version with `config.ignoreUnsupportedPackets` enabled', async function() {
      const armoredSignature = `-----BEGIN PGP SIGNATURE-----

iQFKBAEBCgA0FiEEdOyNPagqedqiXfEMa6Ve2Dq64bsFAlszXwQWHHRlc3Qtd2tk
QG1ldGFjb2RlLmJpegAKCRBrpV7YOrrhuw1PB/9KhFRR/M3OR6NmIent6ri1ekWn
vlcnVqj6N4Xqi1ahRVw19/Jx36mGyijxNwqqGrziqRiPCdT0pKfCfv7nXQf2Up1Z
LoR1StqpBMSDQfuF6JAJmJuB9T+mPQO8wYeUp+O63vQnm5CgqyoRlIoqX8MN6GTY
xK5PdTRjw6IEIGr9uLgSoUwTd0ECY1F9ptyuLGD5ET5ZtyUenQSbX+cw5WCGLFzi
7TwKTY+kGQpkwDJKZJSGpoP7ob6xdDfZx6dHV6IfIJg8/F9gtAXFp8uE51L90cV2
kePFjAnu9cpynKXu3usf8+FuBw2zLsg1Id1n7ttxoAte416KjBN9lFBt8mcu
=wEIR
-----END PGP SIGNATURE-----`;

      const { packets: [signaturePacket] } = await openpgp.readSignature({ armoredSignature });
      const packets = new openpgp.PacketList();
      signaturePacket.signatureData[0] = 1;
      packets.push(signaturePacket);
      const bytes = packets.write();
      const parsed = await openpgp.PacketList.fromBinary(bytes, allAllowedPackets, { ...openpgp.config, ignoreUnsupportedPackets: true });
      expect(parsed.length).to.equal(1);
      expect(parsed[0].tag).to.equal(openpgp.enums.packet.signature);
    });

    it('Throws on unknown packet version with `config.ignoreUnsupportedPackets` disabled', async function() {
      const armoredSignature = `-----BEGIN PGP SIGNATURE-----

iQFKBAEBCgA0FiEEdOyNPagqedqiXfEMa6Ve2Dq64bsFAlszXwQWHHRlc3Qtd2tk
QG1ldGFjb2RlLmJpegAKCRBrpV7YOrrhuw1PB/9KhFRR/M3OR6NmIent6ri1ekWn
vlcnVqj6N4Xqi1ahRVw19/Jx36mGyijxNwqqGrziqRiPCdT0pKfCfv7nXQf2Up1Z
LoR1StqpBMSDQfuF6JAJmJuB9T+mPQO8wYeUp+O63vQnm5CgqyoRlIoqX8MN6GTY
xK5PdTRjw6IEIGr9uLgSoUwTd0ECY1F9ptyuLGD5ET5ZtyUenQSbX+cw5WCGLFzi
7TwKTY+kGQpkwDJKZJSGpoP7ob6xdDfZx6dHV6IfIJg8/F9gtAXFp8uE51L90cV2
kePFjAnu9cpynKXu3usf8+FuBw2zLsg1Id1n7ttxoAte416KjBN9lFBt8mcu
=wEIR
-----END PGP SIGNATURE-----`;

      const { packets: [signaturePacket] } = await openpgp.readSignature({ armoredSignature });
      const packets = new openpgp.PacketList();
      signaturePacket.signatureData[0] = 1;
      packets.push(signaturePacket);
      const bytes = packets.write();
      await expect(
        openpgp.PacketList.fromBinary(bytes, allAllowedPackets, { ...openpgp.config, ignoreUnsupportedPackets: false })
      ).to.be.rejectedWith(/Version 1 of the signature packet is unsupported/);
    });

    it('Ignores unknown signature algorithm only with `config.ignoreUnsupportedPackets` enabled', async function() {
      const binarySignature = util.hexToUint8Array('c2750401630a00060502628b8e2200210910f30ddfc2310b3560162104b9b0045c1930f842cb245566f30ddfc2310b35602ded0100bd69fe6a9f52499cd8b2fd2493dae91c997979890df4467cf31b197901590ff10100ead4c671487535b718a8428c8e6099e3873a41610aad9fcdaa06f6df5f404002');

      const parsed = await openpgp.PacketList.fromBinary(binarySignature, allAllowedPackets, { ...openpgp.config, ignoreUnsupportedPackets: true });
      expect(parsed.length).to.equal(1);
      expect(parsed[0]).instanceOf(openpgp.UnparseablePacket);
      expect(parsed[0].tag).to.equal(openpgp.enums.packet.signature);

      await expect(
        openpgp.PacketList.fromBinary(binarySignature, allAllowedPackets, { ...openpgp.config, ignoreUnsupportedPackets: false })
      ).to.be.rejectedWith(/Unknown signature algorithm/);
    });

    it('Ignores unknown key algorithm only with `config.ignoreUnsupportedPackets` enabled', async function() {
      const binaryKey = util.hexToUint8Array('c55804628b944e63092b06010401da470f01010740d01ab8619b6dc6a36da5bff62ff416a974900f5a8c74d1bd1760d717d0aad8d50000ff516f8e3190aa5b394597655d7c32e16392e638da0e2a869fb7b1f429d9de263d1062cd0f3c7465737440746573742e636f6d3ec28c0410160a001d0502628b944e040b0907080315080a0416000201021901021b03021e01002109104803e40df201fa5b16210496dc42e91cc585e2f5e331644803e40df201fa5b340b0100812c47b60fa509e12e329fc37cc9c437cc6a6500915caa03ad8703db849846f900ff571b9a0d9e1dcc087d9fae04ec2906e60ef40ca02a387eb07ce1c37bedeecd0a');

      const parsed = await openpgp.PacketList.fromBinary(binaryKey, allAllowedPackets, { ...openpgp.config, ignoreUnsupportedPackets: true });
      expect(parsed.length).to.equal(3);
      expect(parsed[0]).instanceOf(openpgp.UnparseablePacket);
      expect(parsed[0].tag).to.equal(openpgp.enums.packet.secretKey);

      await expect(
        openpgp.PacketList.fromBinary(binaryKey, allAllowedPackets, { ...openpgp.config, ignoreUnsupportedPackets: false })
      ).to.be.rejectedWith(/Unknown public key encryption algorithm/);
    });

    it('Ignores unknown PKESK algorithm only with `config.ignoreUnsupportedPackets` enabled', async function() {
      const binaryMessage = util.hexToUint8Array('c15e03c6a6737124ef0f5e63010740282956b4db64ea79e1b4b8e5c528241b5e1cf40b2f5df2a619692755d532353d30a8e044e7c96f51741c73e6c5c8f73db08daf66e49240afe90c9b50705d51e71ec2e7630c5bd86b002e1f6dbd638f61e2d23501830d9bb3711c66963363a6e5f8d9294210a0cd194174c3caa3f29865d33c6be4c09b437f906ca8d35e666f3ef53fd22e0d8ceade');

      const parsed = await openpgp.PacketList.fromBinary(binaryMessage, allAllowedPackets, { ...openpgp.config, ignoreUnsupportedPackets: true });
      expect(parsed.length).to.equal(2);
      expect(parsed[0]).instanceOf(openpgp.UnparseablePacket);
      expect(parsed[0].tag).to.equal(openpgp.enums.packet.publicKeyEncryptedSessionKey);

      await expect(
        openpgp.PacketList.fromBinary(binaryMessage, allAllowedPackets, { ...openpgp.config, ignoreUnsupportedPackets: false })
      ).to.be.rejectedWith(/Unknown public key encryption algorithm/);
    });

    it('Ignores unknown SKESK s2k only with `config.ignoreUnsupportedPackets` enabled', async function() {
      const binaryMessage = util.hexToUint8Array('c1c0cc037c2faa4df93c37b2010c009bb74119f098efa43c7924b2effc7d32fc6d7bf7f6952d2cab1722d3192cfb9b90448592770dcbaed4ef377f73a110a7e208a87a74c18fc4088c60bb0f3abcba32551c8b0e69f3505a0717cfd998261f8ffd166a5e029c504ccd58c100abef7be78aef9650df36b9757ae864b20dda598feb9799128d959a525eee6e1dd7a609117cdc922ab98dce5ea89b498005d609e54e4ec8ff330c648c375a1f56618ebd34c15db928775b6d0ec50316796ea384ebc224737ba861e3b0254817d53d0c26b517eba9ba79f56a9cae4d75b34144f752bea81fd4fbbb17fd36c9c2c387ddb23356e928b5ba47ef7164b6e2ccfe80662321add5c23dc162dc09eda77f2f4c4b04c1d59061bf8625d8c9705fc377cc8b9f9e746e62b0b0d990dd20a3ff8478101efc3e4329e66ce2f3e915657bccf94a77a357055c22a68b23cc8f563e0baef17904c488ea885e8d0cff6b27fbf5e609c2334d1c26ea7445b58a3f9182cdbad8cfd540237b4b495a24fb9bf59a96600c547141c22b4e5adc8dfa292719efeca1c3500409170861616161616161614141414161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161d20101');

      const parsed = await openpgp.PacketList.fromBinary(binaryMessage, allAllowedPackets, { ...openpgp.config, ignoreUnsupportedPackets: true });
      expect(parsed.length).to.equal(3);
      expect(parsed[1]).instanceOf(openpgp.UnparseablePacket);
      expect(parsed[1].tag).to.equal(openpgp.enums.packet.symEncryptedSessionKey);

      await expect(
        openpgp.PacketList.fromBinary(binaryMessage, allAllowedPackets, { ...openpgp.config, ignoreUnsupportedPackets: false })
      ).to.be.rejectedWith(/Unknown S2K type/);
    });

    it('Throws on disallowed packet even with tolerant mode enabled', async function() {
      const packets = new openpgp.PacketList();
      packets.push(new openpgp.LiteralDataPacket());
      const bytes = packets.write();
      await expect(openpgp.PacketList.fromBinary(bytes, {}, { ...openpgp.config, ignoreUnsupportedPackets: false, ignoreMalformedPackets: false })).to.be.rejectedWith(/Packet not allowed in this context/);
      await expect(openpgp.PacketList.fromBinary(bytes, {}, { ...openpgp.config, ignoreUnsupportedPackets: true, ignoreMalformedPackets: true })).to.be.rejectedWith(/Packet not allowed in this context/);
    });

    it('Throws on parsing errors `config.ignoreMalformedPackets` disabled', async function () {
      const packets = new openpgp.PacketList();
      packets.push(openpgp.UserIDPacket.fromObject({ name:'test', email:'test@a.it' }));
      const bytes = packets.write();
      await expect(
        openpgp.PacketList.fromBinary(bytes, allAllowedPackets, { ...openpgp.config, maxUserIDLength: 2, ignoreMalformedPackets: false })
      ).to.be.rejectedWith(/User ID string is too long/);
      const parsed = await openpgp.PacketList.fromBinary(bytes, allAllowedPackets, { ...openpgp.config, maxUserIDLength: 2, ignoreMalformedPackets: true });
      expect(parsed.length).to.equal(1);
      expect(parsed[0].tag).to.equal(openpgp.enums.packet.userID);
    });

    it('Allow parsing of additional packets provided in `config.additionalAllowedPackets`', async function () {
      const packets = new openpgp.PacketList();
      packets.push(new openpgp.LiteralDataPacket());
      packets.push(openpgp.UserIDPacket.fromObject({ name:'test', email:'test@a.it' }));
      const bytes = packets.write();
      const allowedPackets = { [openpgp.enums.packet.literalData]: openpgp.LiteralDataPacket };
      await expect(openpgp.PacketList.fromBinary(bytes, allowedPackets)).to.be.rejectedWith(/Packet not allowed in this context: userID/);
      const parsed = await openpgp.PacketList.fromBinary(bytes, allowedPackets, { ...openpgp.config, additionalAllowedPackets: [openpgp.UserIDPacket] });
      expect(parsed.length).to.equal(1);
      expect(parsed[0].constructor.tag).to.equal(openpgp.enums.packet.literalData);
      const otherPackets = await stream.readToEnd(parsed.stream, _ => _);
      expect(otherPackets.length).to.equal(1);
      expect(otherPackets[0].constructor.tag).to.equal(openpgp.enums.packet.userID);
    });
  });
});
