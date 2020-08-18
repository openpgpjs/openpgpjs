const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../dist/openpgp');

const stub = require('sinon/lib/sinon/stub');
const chai = require('chai');
chai.use(require('chai-as-promised'));

const { expect } = chai;
const input = require('./testInputs.js');

function stringify(array) {
  if (openpgp.util.isStream(array)) {
    return openpgp.stream.readToEnd(array).then(stringify);
  }

  if (!openpgp.util.isUint8Array(array)) {
    throw new Error('Data must be in the form of a Uint8Array');
  }

  const result = [];
  for (let i = 0; i < array.length; i++) {
    result[i] = String.fromCharCode(array[i]);
  }
  return result.join('');
}

describe("Packet", function() {
  const armored_key =
      '-----BEGIN PGP PRIVATE KEY BLOCK-----\n' +
      'Version: GnuPG v2.0.19 (GNU/Linux)\n' +
      '\n' +
      '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\n' +
      'YRlci72GHhlyos8YHA==\n' +
      '=KXkj\n' +
      '-----END PGP PRIVATE KEY BLOCK-----';

  it('Symmetrically encrypted packet', async function() {
    const message = new openpgp.packet.List();
    const testText = input.createSomeMessage();

    const literal = new openpgp.packet.Literal();
    literal.setText(testText);

    const enc = new openpgp.packet.SymmetricallyEncrypted();
    message.push(enc);
    enc.packets.push(literal);

    const key = new Uint8Array([1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2]);
    const algo = 'aes256';

    await enc.encrypt(algo, key);

    const msg2 = new openpgp.message.Message();
    await msg2.packets.read(message.write());
    msg2.packets[0].ignore_mdc_error = true;
    const dec = await msg2.decrypt(null, null, [{ algorithm: algo, data: key }]);

    expect(await stringify(dec.packets[0].data)).to.equal(stringify(literal.data));
  });

  it('Symmetrically encrypted packet - MDC error for modern cipher', async function() {
    const message = new openpgp.packet.List();
    const testText = input.createSomeMessage();

    const literal = new openpgp.packet.Literal();
    literal.setText(testText);

    const enc = new openpgp.packet.SymmetricallyEncrypted();
    message.push(enc);
    await enc.packets.push(literal);

    const key = new Uint8Array([1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2]);
    const algo = 'aes256';

    await enc.encrypt(algo, key);

    const msg2 = new openpgp.packet.List();
    await msg2.read(message.write());
    await expect(msg2[0].decrypt(algo, key)).to.eventually.be.rejectedWith('Decryption failed due to missing MDC.');
  });

  it('Sym. encrypted integrity protected packet', async function() {
    const key = new Uint8Array([1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2]);
    const algo = 'aes256';
    const testText = input.createSomeMessage();

    const literal = new openpgp.packet.Literal();
    const enc = new openpgp.packet.SymEncryptedIntegrityProtected();
    const msg = new openpgp.packet.List();

    msg.push(enc);
    literal.setText(testText);
    enc.packets.push(literal);
    await enc.encrypt(algo, key);

    const msg2 = new openpgp.packet.List();
    await msg2.read(msg.write());

    await msg2[0].decrypt(algo, key);

    expect(await stringify(msg2[0].packets[0].data)).to.equal(stringify(literal.data));
  });

  it('Sym. encrypted AEAD protected packet', function() {
    const key = new Uint8Array([1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2]);
    const algo = 'aes256';
    const testText = input.createSomeMessage();
    const literal = new openpgp.packet.Literal();
    const enc = new openpgp.packet.SymEncryptedAEADProtected();
    const msg = new openpgp.packet.List();

    msg.push(enc);
    literal.setText(testText);
    enc.packets.push(literal);

    const msg2 = new openpgp.packet.List();

    return enc.encrypt(algo, key).then(async function() {
      await msg2.read(msg.write());
      return msg2[0].decrypt(algo, key);
    }).then(async function() {
      expect(await openpgp.stream.readToEnd(msg2[0].packets[0].data)).to.deep.equal(literal.data);
    });
  });

  it('Sym. encrypted AEAD protected packet (AEAD)', async function() {
    let aead_protectVal = openpgp.config.aead_protect;
    openpgp.config.aead_protect = true;
    const testText = input.createSomeMessage();

    const key = new Uint8Array([1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2]);
    const algo = 'aes256';

    const literal = new openpgp.packet.Literal();
    const enc = new openpgp.packet.SymEncryptedAEADProtected();
    const msg = new openpgp.packet.List();

    msg.push(enc);
    literal.setText(testText);
    enc.packets.push(literal);

    const msg2 = new openpgp.packet.List();

    try {
      await enc.encrypt(algo, key);
      await msg2.read(msg.write());
      await msg2[0].decrypt(algo, key);
      expect(await openpgp.stream.readToEnd(msg2[0].packets[0].data)).to.deep.equal(literal.data);
    } finally {
      openpgp.config.aead_protect = aead_protectVal;
    }
  });

  function cryptStub(webCrypto, method) {
    const crypt = webCrypto[method];
    const cryptStub = stub(webCrypto, method);
    let cryptCallsActive = 0;
    cryptStub.onCall(0).callsFake(async function() {
      cryptCallsActive++;
      try {
        return await crypt.apply(this, arguments);
      } finally {
        cryptCallsActive--;
      }
    });
    cryptStub.onCall(1).callsFake(function() {
      expect(cryptCallsActive).to.equal(1);
      return crypt.apply(this, arguments);
    });
    cryptStub.callThrough();
    return cryptStub;
  }

  it('Sym. encrypted AEAD protected packet is encrypted in parallel (AEAD, GCM)', async function() {
    const webCrypto = openpgp.util.getWebCrypto();
    if (!webCrypto) return;
    const encryptStub = cryptStub(webCrypto, 'encrypt');
    const decryptStub = cryptStub(webCrypto, 'decrypt');

    let aead_protectVal = openpgp.config.aead_protect;
    let aead_chunk_size_byteVal = openpgp.config.aead_chunk_size_byte;
    openpgp.config.aead_protect = true;
    openpgp.config.aead_chunk_size_byte = 0;
    const testText = input.createSomeMessage();

    const key = new Uint8Array([1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2]);
    const algo = 'aes256';

    const literal = new openpgp.packet.Literal();
    const enc = new openpgp.packet.SymEncryptedAEADProtected();
    const msg = new openpgp.packet.List();
    enc.aeadAlgorithm = 'experimental_gcm';

    msg.push(enc);
    literal.setText(testText);
    enc.packets.push(literal);

    const msg2 = new openpgp.packet.List();

    try {
      await enc.encrypt(algo, key);
      await msg2.read(msg.write());
      await msg2[0].decrypt(algo, key);
      expect(await openpgp.stream.readToEnd(msg2[0].packets[0].data)).to.deep.equal(literal.data);
      expect(encryptStub.callCount > 1).to.be.true;
      expect(decryptStub.callCount > 1).to.be.true;
    } finally {
      openpgp.config.aead_protect = aead_protectVal;
      openpgp.config.aead_chunk_size_byte = aead_chunk_size_byteVal;
      encryptStub.restore();
      decryptStub.restore();
    }
  });

  it('Sym. encrypted AEAD protected packet test vector (AEAD)', async function() {
    // From https://gitlab.com/openpgp-wg/rfc4880bis/commit/00b20923e6233fb6ff1666ecd5acfefceb32907d

    let packetBytes = openpgp.util.hex_to_Uint8Array(`
      d4 4a 01 07 01 0e b7 32  37 9f 73 c4 92 8d e2 5f
      ac fe 65 17 ec 10 5d c1  1a 81 dc 0c b8 a2 f6 f3
      d9 00 16 38 4a 56 fc 82  1a e1 1a e8 db cb 49 86
      26 55 de a8 8d 06 a8 14  86 80 1b 0f f3 87 bd 2e
      ab 01 3d e1 25 95 86 90  6e ab 24 76
    `.replace(/\s+/g, ''));

    let aead_protectVal = openpgp.config.aead_protect;
    let aead_chunk_size_byteVal = openpgp.config.aead_chunk_size_byte;
    openpgp.config.aead_protect = true;
    openpgp.config.aead_chunk_size_byte = 14;

    const iv = openpgp.util.hex_to_Uint8Array('b7 32 37 9f 73 c4 92 8d e2 5f ac fe 65 17 ec 10'.replace(/\s+/g, ''));
    const key = openpgp.util.hex_to_Uint8Array('86 f1 ef b8 69 52 32 9f 24 ac d3 bf d0 e5 34 6d'.replace(/\s+/g, ''));
    const algo = 'aes128';

    const literal = new openpgp.packet.Literal(0);
    const enc = new openpgp.packet.SymEncryptedAEADProtected();
    const msg = new openpgp.packet.List();

    msg.push(enc);
    literal.setBytes(openpgp.util.str_to_Uint8Array('Hello, world!\n'), openpgp.enums.literal.binary);
    literal.filename = '';
    enc.packets.push(literal);

    const msg2 = new openpgp.packet.List();

    let randomBytesStub = stub(openpgp.crypto.random, 'getRandomBytes');
    randomBytesStub.returns(resolves(iv));

    try {
      await enc.encrypt(algo, key);
      const data = msg.write();
      expect(await openpgp.stream.readToEnd(openpgp.stream.clone(data))).to.deep.equal(packetBytes);
      await msg2.read(data);
      await msg2[0].decrypt(algo, key);
      expect(await openpgp.stream.readToEnd(msg2[0].packets[0].data)).to.deep.equal(literal.data);
    } finally {
      openpgp.config.aead_protect = aead_protectVal;
      openpgp.config.aead_chunk_size_byte = aead_chunk_size_byteVal;
      randomBytesStub.restore();
    }
  });

  it('Sym encrypted session key with a compressed packet', async function() {
    const msg =
        '-----BEGIN PGP MESSAGE-----\n' +
        'Version: GnuPG v2.0.19 (GNU/Linux)\n' +
        '\n' +
        'jA0ECQMCpo7I8WqsebTJ0koBmm6/oqdHXJU9aPe+Po+nk/k4/PZrLmlXwz2lhqBg\n' +
        'GAlY9rxVStLBrg0Hn+5gkhyHI9B85rM1BEYXQ8pP5CSFuTwbJ3O2s67dzQ==\n' +
        '=VZ0/\n' +
        '-----END PGP MESSAGE-----';

    const msgbytes = (await openpgp.armor.decode(msg)).data;

    const parsed = new openpgp.packet.List();
    await parsed.read(msgbytes);

    return parsed[0].decrypt('test').then(() => {
      const key = parsed[0].sessionKey;
      return parsed[1].decrypt(parsed[0].sessionKeyAlgorithm, key).then(async () => {
        const compressed = parsed[1].packets[0];

        const result = await stringify(compressed.packets[0].data);

        expect(result).to.equal('Hello world!\n');
      });
    });
  });

  it('Public key encrypted symmetric key packet', function() {
    const rsa = openpgp.crypto.publicKey.rsa;
    const keySize = openpgp.util.getWebCryptoAll() ? 2048 : 512; // webkit webcrypto accepts minimum 2048 bit keys

    return rsa.generate(keySize, "10001").then(function(mpiGen) {

      let mpi = [mpiGen.n, mpiGen.e, mpiGen.d, mpiGen.p, mpiGen.q, mpiGen.u];
      mpi = mpi.map(function(k) {
        return new openpgp.MPI(k);
      });

      const enc = new openpgp.packet.PublicKeyEncryptedSessionKey();
      const msg = new openpgp.packet.List();
      const msg2 = new openpgp.packet.List();

      enc.sessionKey = new Uint8Array([1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2]);
      enc.publicKeyAlgorithm = 'rsa_encrypt_sign';
      enc.sessionKeyAlgorithm = 'aes256';
      enc.publicKeyId.bytes = '12345678';
      return enc.encrypt({ params: mpi, getFingerprintBytes() {} }).then(async () => {

        msg.push(enc);

        await msg2.read(msg.write());

        return msg2[0].decrypt({ algorithm: 'rsa_encrypt_sign', params: mpi, getFingerprintBytes() {} }).then(() => {

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

    let key = new openpgp.packet.List();
    await key.read((await openpgp.armor.decode(armored_key)).data);
    key = key[0];

    const enc = new openpgp.packet.PublicKeyEncryptedSessionKey();
    const secret = new Uint8Array([1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2]);

    enc.sessionKey = secret;
    enc.publicKeyAlgorithm = 'rsa_encrypt_sign';
    enc.sessionKeyAlgorithm = 'aes256';
    enc.publicKeyId.bytes = '12345678';

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

    let key = new openpgp.packet.List();
    await key.read((await openpgp.armor.decode(armored_key)).data);
    key = key[3];

    const msg = new openpgp.packet.List();
    await msg.read((await openpgp.armor.decode(armored_msg)).data);

    return msg[0].decrypt(key).then(async () => {
      await msg[1].decrypt(msg[0].sessionKeyAlgorithm, msg[0].sessionKey);

      const text = await stringify(msg[1].packets[0].packets[0].data);

      expect(text).to.equal('Hello world!');
    });
  });

  it('Sym. encrypted session key reading/writing', async function() {
    const passphrase = 'hello';
    const algo = 'aes256';
    const testText = input.createSomeMessage();

    const literal = new openpgp.packet.Literal();
    const key_enc = new openpgp.packet.SymEncryptedSessionKey();
    const enc = new openpgp.packet.SymEncryptedIntegrityProtected();
    const msg = new openpgp.packet.List();

    msg.push(key_enc);
    msg.push(enc);

    key_enc.sessionKeyAlgorithm = algo;
    await key_enc.encrypt(passphrase);

    const key = key_enc.sessionKey;

    literal.setText(testText);
    enc.packets.push(literal);
    await enc.encrypt(algo, key);

    const msg2 = new openpgp.packet.List();
    await msg2.read(msg.write());

    await msg2[0].decrypt(passphrase);
    const key2 = msg2[0].sessionKey;
    await msg2[1].decrypt(msg2[0].sessionKeyAlgorithm, key2);

    expect(await stringify(msg2[1].packets[0].data)).to.equal(stringify(literal.data));
  });

  it('Sym. encrypted session key reading/writing (AEAD)', async function() {
    let aead_protectVal = openpgp.config.aead_protect;
    openpgp.config.aead_protect = true;

    try {
      const passphrase = 'hello';
      const algo = 'aes256';
      const testText = input.createSomeMessage();

      const literal = new openpgp.packet.Literal();
      const key_enc = new openpgp.packet.SymEncryptedSessionKey();
      const enc = new openpgp.packet.SymEncryptedAEADProtected();
      const msg = new openpgp.packet.List();

      msg.push(key_enc);
      msg.push(enc);

      key_enc.sessionKeyAlgorithm = algo;
      await key_enc.encrypt(passphrase);

      const key = key_enc.sessionKey;

      literal.setText(testText);
      enc.packets.push(literal);
      await enc.encrypt(algo, key);

      const msg2 = new openpgp.packet.List();
      await msg2.read(msg.write());

      await msg2[0].decrypt(passphrase);
      const key2 = msg2[0].sessionKey;
      await msg2[1].decrypt(msg2[0].sessionKeyAlgorithm, key2);

      expect(await stringify(msg2[1].packets[0].data)).to.equal(stringify(literal.data));
    } finally {
      openpgp.config.aead_protect = aead_protectVal;
    }
  });

  it('Sym. encrypted session key reading/writing test vector (EAX, AEAD)', async function() {
    // From https://gitlab.com/openpgp-wg/rfc4880bis/blob/00b20923/back.mkd#sample-aead-eax-encryption-and-decryption

    let aead_protectVal = openpgp.config.aead_protect;
    let aead_chunk_size_byteVal = openpgp.config.aead_chunk_size_byte;
    let s2k_iteration_count_byteVal = openpgp.config.s2k_iteration_count_byte;
    openpgp.config.aead_protect = true;
    openpgp.config.aead_chunk_size_byte = 14;
    openpgp.config.s2k_iteration_count_byte = 0x90;

    let salt = openpgp.util.hex_to_Uint8Array(`cd5a9f70fbe0bc65`);
    let sessionKey = openpgp.util.hex_to_Uint8Array(`86 f1 ef b8 69 52 32 9f 24 ac d3 bf d0 e5 34 6d`.replace(/\s+/g, ''));
    let sessionIV = openpgp.util.hex_to_Uint8Array(`bc 66 9e 34 e5 00 dc ae dc 5b 32 aa 2d ab 02 35`.replace(/\s+/g, ''));
    let dataIV = openpgp.util.hex_to_Uint8Array(`b7 32 37 9f 73 c4 92 8d e2 5f ac fe 65 17 ec 10`.replace(/\s+/g, ''));

    let randomBytesStub = stub(openpgp.crypto.random, 'getRandomBytes');
    randomBytesStub.onCall(0).returns(resolves(salt));
    randomBytesStub.onCall(1).returns(resolves(sessionKey));
    randomBytesStub.onCall(2).returns(resolves(sessionIV));
    randomBytesStub.onCall(3).returns(resolves(dataIV));

    let packetBytes = openpgp.util.hex_to_Uint8Array(`
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
      const algo = 'aes128';

      const literal = new openpgp.packet.Literal(0);
      const key_enc = new openpgp.packet.SymEncryptedSessionKey();
      const enc = new openpgp.packet.SymEncryptedAEADProtected();
      const msg = new openpgp.packet.List();

      msg.push(key_enc);
      msg.push(enc);

      key_enc.sessionKeyAlgorithm = algo;
      await key_enc.encrypt(passphrase);

      const key = key_enc.sessionKey;

      literal.setBytes(openpgp.util.str_to_Uint8Array('Hello, world!\n'), openpgp.enums.literal.binary);
      literal.filename = '';
      enc.packets.push(literal);
      await enc.encrypt(algo, key);

      const data = msg.write();
      expect(await openpgp.stream.readToEnd(openpgp.stream.clone(data))).to.deep.equal(packetBytes);

      const msg2 = new openpgp.packet.List();
      await msg2.read(data);

      await msg2[0].decrypt(passphrase);
      const key2 = msg2[0].sessionKey;
      await msg2[1].decrypt(msg2[0].sessionKeyAlgorithm, key2);

      expect(await stringify(msg2[1].packets[0].data)).to.equal(stringify(literal.data));
    } finally {
      openpgp.config.aead_protect = aead_protectVal;
      openpgp.config.aead_chunk_size_byte = aead_chunk_size_byteVal;
      openpgp.config.s2k_iteration_count_byte = s2k_iteration_count_byteVal;
      randomBytesStub.restore();
    }
  });

  it('Sym. encrypted session key reading/writing test vector (AEAD, OCB)', async function() {
    // From https://gitlab.com/openpgp-wg/rfc4880bis/blob/00b20923/back.mkd#sample-aead-ocb-encryption-and-decryption

    let aead_protectVal = openpgp.config.aead_protect;
    let aead_chunk_size_byteVal = openpgp.config.aead_chunk_size_byte;
    let s2k_iteration_count_byteVal = openpgp.config.s2k_iteration_count_byte;
    openpgp.config.aead_protect = true;
    openpgp.config.aead_chunk_size_byte = 14;
    openpgp.config.s2k_iteration_count_byte = 0x90;

    let salt = openpgp.util.hex_to_Uint8Array(`9f0b7da3e5ea6477`);
    let sessionKey = openpgp.util.hex_to_Uint8Array(`d1 f0 1b a3 0e 13 0a a7 d2 58 2c 16 e0 50 ae 44`.replace(/\s+/g, ''));
    let sessionIV = openpgp.util.hex_to_Uint8Array(`99 e3 26 e5 40 0a 90 93 6c ef b4 e8 eb a0 8c`.replace(/\s+/g, ''));
    let dataIV = openpgp.util.hex_to_Uint8Array(`5e d2 bc 1e 47 0a be 8f 1d 64 4c 7a 6c 8a 56`.replace(/\s+/g, ''));

    let randomBytesStub = stub(openpgp.crypto.random, 'getRandomBytes');
    randomBytesStub.onCall(0).returns(resolves(salt));
    randomBytesStub.onCall(1).returns(resolves(sessionKey));
    randomBytesStub.onCall(2).returns(resolves(sessionIV));
    randomBytesStub.onCall(3).returns(resolves(dataIV));

    let packetBytes = openpgp.util.hex_to_Uint8Array(`
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
      const algo = 'aes128';

      const literal = new openpgp.packet.Literal(0);
      const key_enc = new openpgp.packet.SymEncryptedSessionKey();
      const enc = new openpgp.packet.SymEncryptedAEADProtected();
      const msg = new openpgp.packet.List();
      enc.aeadAlgorithm = key_enc.aeadAlgorithm = 'ocb';

      msg.push(key_enc);
      msg.push(enc);

      key_enc.sessionKeyAlgorithm = algo;
      await key_enc.encrypt(passphrase);

      const key = key_enc.sessionKey;

      literal.setBytes(openpgp.util.str_to_Uint8Array('Hello, world!\n'), openpgp.enums.literal.binary);
      literal.filename = '';
      enc.packets.push(literal);
      await enc.encrypt(algo, key);

      const data = msg.write();
      expect(await openpgp.stream.readToEnd(openpgp.stream.clone(data))).to.deep.equal(packetBytes);

      const msg2 = new openpgp.packet.List();
      await msg2.read(data);

      await msg2[0].decrypt(passphrase);
      const key2 = msg2[0].sessionKey;
      await msg2[1].decrypt(msg2[0].sessionKeyAlgorithm, key2);

      expect(await stringify(msg2[1].packets[0].data)).to.equal(stringify(literal.data));
    } finally {
      openpgp.config.aead_protect = aead_protectVal;
      openpgp.config.aead_chunk_size_byte = aead_chunk_size_byteVal;
      openpgp.config.s2k_iteration_count_byte = s2k_iteration_count_byteVal;
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

    let key = new openpgp.packet.List();
    await key.read((await openpgp.armor.decode(armored_key)).data);
    key = key[3];
    await key.decrypt('test');

    const msg = new openpgp.packet.List();
    await msg.read((await openpgp.armor.decode(armored_msg)).data);

    return msg[0].decrypt(key).then(async () => {
      await msg[1].decrypt(msg[0].sessionKeyAlgorithm, msg[0].sessionKey);

      const text = await stringify(msg[1].packets[0].packets[0].data);

      expect(text).to.equal('Hello world!');
    });
  });

  it('Secret key reading with signature verification.', async function() {
    const key = new openpgp.packet.List();
    await key.read((await openpgp.armor.decode(armored_key)).data);
    return Promise.all([
      expect(key[2].verify(key[0],
        openpgp.enums.signature.cert_generic,
        {
            userId: key[1],
            key: key[0]
        })).to.eventually.be.true,
      expect(key[4].verify(key[0],
        openpgp.enums.signature.key_binding,
        {
            key: key[0],
            bind: key[3]
        })).to.eventually.be.true
    ]);
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

    const key = new openpgp.packet.List();
    await key.read((await openpgp.armor.decode(armored_key)).data);
    await key[3].decrypt('test');

    const msg = new openpgp.packet.List();
    await msg.read((await openpgp.armor.decode(armored_msg)).data);

    return msg[0].decrypt(key[3]).then(async () => {
      await msg[1].decrypt(msg[0].sessionKeyAlgorithm, msg[0].sessionKey);

      const payload = msg[1].packets[0].packets;
      payload.concat(await openpgp.stream.readToEnd(payload.stream, arr => arr));

      await Promise.all([
        expect(payload[2].verify(
          key[0], openpgp.enums.signature.binary, payload[1]
        )).to.eventually.be.true,
        openpgp.stream.pipe(payload[1].getBytes(), new WritableStream())
      ]);
    });
  });

  it('Reading signersUserId from armored signature', async function() {
    const armored_sig =
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

    const signature = await openpgp.signature.readArmored(armored_sig);

    expect(signature.packets[0].signersUserId).to.equal('test-wkd@metacode.biz');
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

    const key = (await openpgp.key.readArmored(pubkey)).keys[0];

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
    expect(rawNotations[0].value).to.deep.equal(Uint8Array.from(['2'.charCodeAt(0)]));
    expect(rawNotations[0].humanReadable).to.equal(true);

    expect(rawNotations[1].name).to.equal('test@example.com');
    expect(rawNotations[1].value).to.deep.equal(Uint8Array.from(['3'.charCodeAt(0)]));
    expect(rawNotations[1].humanReadable).to.equal(true);
  });

  it('Writing and encryption of a secret key packet.', function() {
    const key = new openpgp.packet.List();
    key.push(new openpgp.packet.SecretKey());

    const rsa = openpgp.crypto.publicKey.rsa;
    const keySize = openpgp.util.getWebCryptoAll() ? 2048 : 512; // webkit webcrypto accepts minimum 2048 bit keys

    return rsa.generate(keySize, "10001").then(async function(mpiGen) {
      let mpi = [mpiGen.n, mpiGen.e, mpiGen.d, mpiGen.p, mpiGen.q, mpiGen.u];
      mpi = mpi.map(function(k) {
        return new openpgp.MPI(k);
      });

      key[0].params = mpi;
      key[0].algorithm = "rsa_sign";
      key[0].isEncrypted = false;
      await key[0].encrypt('hello');

      const raw = key.write();

      const key2 = new openpgp.packet.List();
      await key2.read(raw);
      await key2[0].decrypt('hello');

      expect(key[0].params.toString()).to.equal(key2[0].params.toString());
    });
  });

  it('Writing and encryption of a secret key packet. (AEAD)', async function() {
    let aead_protectVal = openpgp.config.aead_protect;
    openpgp.config.aead_protect = true;

    const key = new openpgp.packet.List();
    key.push(new openpgp.packet.SecretKey());

    const rsa = openpgp.crypto.publicKey.rsa;
    const keySize = openpgp.util.getWebCryptoAll() ? 2048 : 512; // webkit webcrypto accepts minimum 2048 bit keys

    try {
      const mpiGen = await rsa.generate(keySize, "10001");
      let mpi = [mpiGen.n, mpiGen.e, mpiGen.d, mpiGen.p, mpiGen.q, mpiGen.u];
      mpi = mpi.map(function(k) {
        return new openpgp.MPI(k);
      });

      key[0].params = mpi;
      key[0].algorithm = "rsa_sign";
      key[0].isEncrypted = false;
      await key[0].encrypt('hello');

      const raw = key.write();

      const key2 = new openpgp.packet.List();
      await key2.read(raw);
      await key2[0].decrypt('hello');

      expect(key[0].params.toString()).to.equal(key2[0].params.toString());
    } finally {
      openpgp.config.aead_protect = aead_protectVal;
    }
  });

  it('Writing and verification of a signature packet.', function() {
    const key = new openpgp.packet.SecretKey();

    const rsa = openpgp.crypto.publicKey.rsa;
    const keySize = openpgp.util.getWebCryptoAll() ? 2048 : 512; // webkit webcrypto accepts minimum 2048 bit keys

    return rsa.generate(keySize, "10001").then(function(mpiGen) {
        let mpi = [mpiGen.n, mpiGen.e, mpiGen.d, mpiGen.p, mpiGen.q, mpiGen.u];
        mpi = mpi.map(function(k) {
          return new openpgp.MPI(k);
        });
        const testText = input.createSomeMessage();

        key.params = mpi;
        key.algorithm = "rsa_sign";

        const signed = new openpgp.packet.List();
        const literal = new openpgp.packet.Literal();
        const signature = new openpgp.packet.Signature();

        literal.setText(testText);

        signature.hashAlgorithm = 'sha256';
        signature.publicKeyAlgorithm = 'rsa_sign';
        signature.signatureType = 'text';

        return signature.sign(key, literal).then(async () => {

          signed.push(literal);
          signed.push(signature);

          const raw = signed.write();

          const signed2 = new openpgp.packet.List();
          await signed2.read(raw);
          signed2.concat(await openpgp.stream.readToEnd(signed2.stream, arr => arr));

          await Promise.all([
            expect(signed2[1].verify(key, openpgp.enums.signature.text, signed2[0])).to.eventually.be.true,
            openpgp.stream.pipe(signed2[0].getBytes(), new WritableStream())
          ]);
        });
    });
  });
});
