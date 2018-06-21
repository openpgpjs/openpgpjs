const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../dist/openpgp');

const stub = require('sinon/lib/sinon/stub');
const chai = require('chai');
chai.use(require('chai-as-promised'));

const { expect } = chai;

const { stream, util } = openpgp;

const pub_key =
  ['-----BEGIN PGP PUBLIC KEY BLOCK-----',
  'Version: GnuPG v2.0.19 (GNU/Linux)',
  '',
  'mI0EUmEvTgEEANyWtQQMOybQ9JltDqmaX0WnNPJeLILIM36sw6zL0nfTQ5zXSS3+',
  'fIF6P29lJFxpblWk02PSID5zX/DYU9/zjM2xPO8Oa4xo0cVTOTLj++Ri5mtr//f5',
  'GLsIXxFrBJhD/ghFsL3Op0GXOeLJ9A5bsOn8th7x6JucNKuaRB6bQbSPABEBAAG0',
  'JFRlc3QgTWNUZXN0aW5ndG9uIDx0ZXN0QGV4YW1wbGUuY29tPoi5BBMBAgAjBQJS',
  'YS9OAhsvBwsJCAcDAgEGFQgCCQoLBBYCAwECHgECF4AACgkQSmNhOk1uQJQwDAP6',
  'AgrTyqkRlJVqz2pb46TfbDM2TDF7o9CBnBzIGoxBhlRwpqALz7z2kxBDmwpQa+ki',
  'Bq3jZN/UosY9y8bhwMAlnrDY9jP1gdCo+H0sD48CdXybblNwaYpwqC8VSpDdTndf',
  '9j2wE/weihGp/DAdy/2kyBCaiOY1sjhUfJ1GogF49rC4jQRSYS9OAQQA6R/PtBFa',
  'JaT4jq10yqASk4sqwVMsc6HcifM5lSdxzExFP74naUMMyEsKHP53QxTF0Grqusag',
  'Qg/ZtgT0CN1HUM152y7ACOdp1giKjpMzOTQClqCoclyvWOFB+L/SwGEIJf7LSCEr',
  'woBuJifJc8xAVr0XX0JthoW+uP91eTQ3XpsAEQEAAYkBPQQYAQIACQUCUmEvTgIb',
  'LgCoCRBKY2E6TW5AlJ0gBBkBAgAGBQJSYS9OAAoJEOCE90RsICyXuqIEANmmiRCA',
  'SF7YK7PvFkieJNwzeK0V3F2lGX+uu6Y3Q/Zxdtwc4xR+me/CSBmsURyXTO29OWhP',
  'GLszPH9zSJU9BdDi6v0yNprmFPX/1Ng0Abn/sCkwetvjxC1YIvTLFwtUL/7v6NS2',
  'bZpsUxRTg9+cSrMWWSNjiY9qUKajm1tuzPDZXAUEAMNmAN3xXN/Kjyvj2OK2ck0X',
  'W748sl/tc3qiKPMJ+0AkMF7Pjhmh9nxqE9+QCEl7qinFqqBLjuzgUhBU4QlwX1GD',
  'AtNTq6ihLMD5v1d82ZC7tNatdlDMGWnIdvEMCv2GZcuIqDQ9rXWs49e7tq1NncLY',
  'hz3tYjKhoFTKEIq3y3Pp',
  '=h/aX',
  '-----END PGP PUBLIC KEY BLOCK-----'].join('\n');

const priv_key =
  ['-----BEGIN PGP PRIVATE KEY BLOCK-----',
  'Version: GnuPG v2.0.19 (GNU/Linux)',
  '',
  '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',
  '=lw5e',
  '-----END PGP PRIVATE KEY BLOCK-----'].join('\n');

const passphrase = 'hello world';

describe('Streaming', function() {
  it('Encrypt small message', async function() {
    const data = new ReadableStream({
      async start(controller) {
        controller.enqueue(util.str_to_Uint8Array('hello '));
        controller.enqueue(util.str_to_Uint8Array('world'));
        controller.close();
      }
    });
    const encrypted = await openpgp.encrypt({
      data,
      passwords: ['test'],
    });
    const msgAsciiArmored = await openpgp.stream.readToEnd(encrypted.data);
    const message = await openpgp.message.readArmored(msgAsciiArmored);
    const decrypted = await openpgp.decrypt({
      passwords: ['test'],
      message
    });
    expect(decrypted.data).to.equal('hello world');
  });

  it('Encrypt larger message', async function() {
    let plaintext = [];
    let i = 0;
    const data = new ReadableStream({
      async pull(controller) {
        await new Promise(setTimeout);
        if (i++ < 10) {
          let randomBytes = await openpgp.crypto.random.getRandomBytes(1024);
          controller.enqueue(randomBytes);
          plaintext.push(randomBytes);
        } else {
          controller.close();
        }
      }
    });
    const encrypted = await openpgp.encrypt({
      data,
      passwords: ['test'],
    });
    expect(await openpgp.stream.getReader(openpgp.stream.clone(encrypted.data)).readBytes(1024)).to.match(/^-----BEGIN PGP MESSAGE-----\r\n/);
    if (i > 10) throw new Error('Data did not arrive early.');
    const msgAsciiArmored = await openpgp.stream.readToEnd(encrypted.data);
    const message = await openpgp.message.readArmored(msgAsciiArmored);
    const decrypted = await openpgp.decrypt({
      passwords: ['test'],
      message,
      format: 'binary'
    });
    expect(decrypted.data).to.deep.equal(util.concatUint8Array(plaintext));
  });

  it('Input stream should be canceled when canceling encrypted stream', async function() {
    let plaintext = [];
    let i = 0;
    let canceled = false;
    const data = new ReadableStream({
      async pull(controller) {
        await new Promise(setTimeout);
        if (i++ < 10) {
          let randomBytes = await openpgp.crypto.random.getRandomBytes(1024);
          controller.enqueue(randomBytes);
          plaintext.push(randomBytes);
        } else {
          controller.close();
        }
      },
      cancel() {
        canceled = true;
      }
    });
    const encrypted = await openpgp.encrypt({
      data,
      passwords: ['test'],
    });
    const reader = openpgp.stream.getReader(encrypted.data);
    expect(await reader.readBytes(1024)).to.match(/^-----BEGIN PGP MESSAGE-----\r\n/);
    if (i > 10) throw new Error('Data did not arrive early.');
    reader.releaseLock();
    await openpgp.stream.cancel(encrypted.data);
    expect(canceled).to.be.true;
  });

  it('Sign: Input stream should be canceled when canceling encrypted stream', async function() {
    const privKey = (await openpgp.key.readArmored(priv_key)).keys[0];
    await privKey.decrypt(passphrase);

    let plaintext = [];
    let i = 0;
    let canceled = false;
    const data = new ReadableStream({
      async pull(controller) {
        await new Promise(setTimeout);
        if (i++ < 10) {
          let randomBytes = await openpgp.crypto.random.getRandomBytes(1024);
          controller.enqueue(randomBytes);
          plaintext.push(randomBytes);
        } else {
          controller.close();
        }
      },
      cancel() {
        canceled = true;
      }
    });
    const encrypted = await openpgp.sign({
      data,
      privateKeys: privKey
    });
    const reader = openpgp.stream.getReader(encrypted.data);
    expect(await reader.readBytes(1024)).to.match(/^-----BEGIN PGP MESSAGE-----\r\n/);
    if (i > 10) throw new Error('Data did not arrive early.');
    reader.releaseLock();
    await openpgp.stream.cancel(encrypted.data);
    expect(canceled).to.be.true;
  });

  it('Encrypt and decrypt larger message roundtrip', async function() {
    let plaintext = [];
    let i = 0;
    const data = new ReadableStream({
      async pull(controller) {
        if (i++ < 10) {
          let randomBytes = await openpgp.crypto.random.getRandomBytes(1024);
          controller.enqueue(randomBytes);
          plaintext.push(randomBytes);
        } else {
          controller.close();
        }
      }
    });
    const encrypted = await openpgp.encrypt({
      data,
      passwords: ['test'],
    });

    const msgAsciiArmored = encrypted.data;
    const message = await openpgp.message.readArmored(msgAsciiArmored);
    const decrypted = await openpgp.decrypt({
      passwords: ['test'],
      message,
      format: 'binary'
    });
    expect(util.isStream(decrypted.data)).to.be.true;
    expect(await openpgp.stream.getReader(openpgp.stream.clone(decrypted.data)).readBytes(1024)).to.deep.equal(plaintext[0]);
    if (i <= 10) throw new Error('Data arrived early.');
    expect(await openpgp.stream.readToEnd(decrypted.data)).to.deep.equal(util.concatUint8Array(plaintext));
  });

  it('Encrypt and decrypt larger message roundtrip (unsafe_stream=true)', async function() {
    let unsafe_streamValue = openpgp.config.unsafe_stream;
    openpgp.config.unsafe_stream = true;
    try {
      let plaintext = [];
      let i = 0;
      const data = new ReadableStream({
        async pull(controller) {
          await new Promise(setTimeout);
          if (i++ < 10) {
            let randomBytes = await openpgp.crypto.random.getRandomBytes(1024);
            controller.enqueue(randomBytes);
            plaintext.push(randomBytes);
          } else {
            controller.close();
          }
        }
      });
      const encrypted = await openpgp.encrypt({
        data,
        passwords: ['test'],
      });

      const msgAsciiArmored = encrypted.data;
      const message = await openpgp.message.readArmored(msgAsciiArmored);
      const decrypted = await openpgp.decrypt({
        passwords: ['test'],
        message,
        format: 'binary'
      });
      expect(util.isStream(decrypted.data)).to.be.true;
      expect(util.isStream(decrypted.signatures)).to.be.false;
      expect(await openpgp.stream.getReader(openpgp.stream.clone(decrypted.data)).readBytes(1024)).to.deep.equal(plaintext[0]);
      if (i > 10) throw new Error('Data did not arrive early.');
      expect(await openpgp.stream.readToEnd(decrypted.data)).to.deep.equal(util.concatUint8Array(plaintext));
      expect(await decrypted.signatures).to.exist.and.have.length(0);
    } finally {
      openpgp.config.unsafe_stream = unsafe_streamValue;
    }
  });

  it('Encrypt and decrypt larger message roundtrip using public keys (unsafe_stream=true)', async function() {
    let unsafe_streamValue = openpgp.config.unsafe_stream;
    openpgp.config.unsafe_stream = true;
    try {
      const pubKey = (await openpgp.key.readArmored(pub_key)).keys[0];
      const privKey = (await openpgp.key.readArmored(priv_key)).keys[0];
      await privKey.decrypt(passphrase);

      let plaintext = [];
      let i = 0;
      const data = new ReadableStream({
        async pull(controller) {
          await new Promise(setTimeout);
          if (i++ < 10) {
            let randomBytes = await openpgp.crypto.random.getRandomBytes(1024);
            controller.enqueue(randomBytes);
            plaintext.push(randomBytes);
          } else {
            controller.close();
          }
        }
      });
      const encrypted = await openpgp.encrypt({
        data,
        publicKeys: pubKey,
        privateKeys: privKey
      });

      const msgAsciiArmored = encrypted.data;
      const message = await openpgp.message.readArmored(msgAsciiArmored);
      const decrypted = await openpgp.decrypt({
        publicKeys: pubKey,
        privateKeys: privKey,
        message,
        format: 'binary'
      });
      expect(util.isStream(decrypted.data)).to.be.true;
      expect(await openpgp.stream.getReader(openpgp.stream.clone(decrypted.data)).readBytes(1024)).to.deep.equal(plaintext[0]);
      if (i > 10) throw new Error('Data did not arrive early.');
      expect(await openpgp.stream.readToEnd(decrypted.data)).to.deep.equal(util.concatUint8Array(plaintext));
    } finally {
      openpgp.config.unsafe_stream = unsafe_streamValue;
    }
  });

  it('Detect MDC modifications (unsafe_stream=true)', async function() {
    let unsafe_streamValue = openpgp.config.unsafe_stream;
    openpgp.config.unsafe_stream = true;
    try {
      let plaintext = [];
      let i = 0;
      const data = new ReadableStream({
        async pull(controller) {
          await new Promise(setTimeout);
          if (i++ < 10) {
            let randomBytes = await openpgp.crypto.random.getRandomBytes(1024);
            controller.enqueue(randomBytes);
            plaintext.push(randomBytes);
          } else {
            controller.close();
          }
        }
      });
      const encrypted = await openpgp.encrypt({
        data,
        passwords: ['test'],
      });

      const msgAsciiArmored = encrypted.data;
      const message = await openpgp.message.readArmored(openpgp.stream.transform(msgAsciiArmored, value => {
        if (value === '\n=' || value.length === 4) return; // Remove checksum
        if (value.length > 1000) return value.slice(0, 499) + 'a' + value.slice(500);
        return value;
      }));
      const decrypted = await openpgp.decrypt({
        passwords: ['test'],
        message,
        format: 'binary'
      });
      expect(util.isStream(decrypted.data)).to.be.true;
      expect(await openpgp.stream.getReader(openpgp.stream.clone(decrypted.data)).readBytes(1024)).not.to.deep.equal(plaintext[0]);
      if (i > 10) throw new Error('Data did not arrive early.');
      await expect(openpgp.stream.readToEnd(decrypted.data)).to.be.rejectedWith('Modification detected.');
      await decrypted.signatures;
    } finally {
      openpgp.config.unsafe_stream = unsafe_streamValue;
    }
  });

  it('Detect armor checksum error (unsafe_stream=true)', async function() {
    let unsafe_streamValue = openpgp.config.unsafe_stream;
    openpgp.config.unsafe_stream = true;
    try {
      const pubKey = (await openpgp.key.readArmored(pub_key)).keys[0];
      const privKey = (await openpgp.key.readArmored(priv_key)).keys[0];
      await privKey.decrypt(passphrase);

      let plaintext = [];
      let i = 0;
      const data = new ReadableStream({
        async pull(controller) {
          await new Promise(resolve => setTimeout(resolve, 100));
          if (i++ < 10) {
            let randomBytes = await openpgp.crypto.random.getRandomBytes(1024);
            controller.enqueue(randomBytes);
            plaintext.push(randomBytes);
          } else {
            controller.close();
          }
        }
      });
      const encrypted = await openpgp.encrypt({
        data,
        publicKeys: pubKey,
        privateKeys: privKey
      });

      const msgAsciiArmored = encrypted.data;
      const message = await openpgp.message.readArmored(openpgp.stream.transform(msgAsciiArmored, value => {
        if (value.length > 1000) return value.slice(0, 499) + 'a' + value.slice(500);
        return value;
      }));
      const decrypted = await openpgp.decrypt({
        publicKeys: pubKey,
        privateKeys: privKey,
        message,
        format: 'binary'
      });
      expect(util.isStream(decrypted.data)).to.be.true;
      expect(await openpgp.stream.getReader(openpgp.stream.clone(decrypted.data)).readBytes(10)).not.to.deep.equal(plaintext[0]);
      if (i > 10) throw new Error('Data did not arrive early.');
      await expect(openpgp.stream.readToEnd(decrypted.data)).to.be.rejectedWith('Ascii armor integrity check on message failed');
      expect(await decrypted.signatures).to.exist.and.have.length(0);
    } finally {
      openpgp.config.unsafe_stream = unsafe_streamValue;
    }
  });

  it('Detect armor checksum error when not passing public keys (unsafe_stream=true)', async function() {
    let unsafe_streamValue = openpgp.config.unsafe_stream;
    openpgp.config.unsafe_stream = true;
    try {
      const pubKey = (await openpgp.key.readArmored(pub_key)).keys[0];
      const privKey = (await openpgp.key.readArmored(priv_key)).keys[0];
      await privKey.decrypt(passphrase);

      let plaintext = [];
      let i = 0;
      const data = new ReadableStream({
        async pull(controller) {
          await new Promise(resolve => setTimeout(resolve, 100));
          if (i++ < 10) {
            let randomBytes = await openpgp.crypto.random.getRandomBytes(1024);
            controller.enqueue(randomBytes);
            plaintext.push(randomBytes);
          } else {
            controller.close();
          }
        }
      });
      const encrypted = await openpgp.encrypt({
        data,
        publicKeys: pubKey,
        privateKeys: privKey
      });

      const msgAsciiArmored = encrypted.data;
      const message = await openpgp.message.readArmored(openpgp.stream.transform(msgAsciiArmored, value => {
        if (value.length > 1000) return value.slice(0, 499) + 'a' + value.slice(500);
        return value;
      }));
      const decrypted = await openpgp.decrypt({
        privateKeys: privKey,
        message,
        format: 'binary'
      });
      expect(util.isStream(decrypted.data)).to.be.true;
      expect(await openpgp.stream.getReader(openpgp.stream.clone(decrypted.data)).readBytes(10)).not.to.deep.equal(plaintext[0]);
      if (i > 10) throw new Error('Data did not arrive early.');
      await expect(openpgp.stream.readToEnd(decrypted.data)).to.be.rejectedWith('Ascii armor integrity check on message failed');
      expect(await decrypted.signatures).to.exist.and.have.length(0);
    } finally {
      openpgp.config.unsafe_stream = unsafe_streamValue;
    }
  });

  it('Sign/verify: Detect armor checksum error (unsafe_stream=true)', async function() {
    let unsafe_streamValue = openpgp.config.unsafe_stream;
    openpgp.config.unsafe_stream = true;
    try {
      const pubKey = (await openpgp.key.readArmored(pub_key)).keys[0];
      const privKey = (await openpgp.key.readArmored(priv_key)).keys[0];
      await privKey.decrypt(passphrase);

      let plaintext = [];
      let i = 0;
      const data = new ReadableStream({
        async pull(controller) {
          await new Promise(resolve => setTimeout(resolve, 100));
          if (i++ < 10) {
            let randomBytes = await openpgp.crypto.random.getRandomBytes(1024);
            controller.enqueue(randomBytes);
            plaintext.push(randomBytes);
          } else {
            controller.close();
          }
        }
      });
      const encrypted = await openpgp.sign({
        data,
        privateKeys: privKey
      });

      const msgAsciiArmored = encrypted.data;
      const message = await openpgp.message.readArmored(openpgp.stream.transform(msgAsciiArmored, value => {
        if (value.length > 1000) return value.slice(0, 499) + 'a' + value.slice(500);
        return value;
      }));
      const decrypted = await openpgp.verify({
        publicKeys: pubKey,
        message
      });
      expect(util.isStream(decrypted.data)).to.be.true;
      expect(await openpgp.stream.getReader(openpgp.stream.clone(decrypted.data)).readBytes(10)).not.to.deep.equal(plaintext[0]);
      if (i > 10) throw new Error('Data did not arrive early.');
      await expect(openpgp.stream.readToEnd(decrypted.data)).to.be.rejectedWith('Ascii armor integrity check on message failed');
      expect(await decrypted.signatures).to.exist.and.have.length(0);
    } finally {
      openpgp.config.unsafe_stream = unsafe_streamValue;
    }
  });

  it('Encrypt and decrypt larger message roundtrip (draft04)', async function() {
    let aead_protectValue = openpgp.config.aead_protect;
    let aead_chunk_size_byteValue = openpgp.config.aead_chunk_size_byte;
    openpgp.config.aead_protect = true;
    openpgp.config.aead_chunk_size_byte = 4;
    try {
      let plaintext = [];
      let i = 0;
      const data = new ReadableStream({
        async pull(controller) {
          await new Promise(resolve => setTimeout(resolve, 10));
          if (i++ < 10) {
            let randomBytes = await openpgp.crypto.random.getRandomBytes(1024);
            controller.enqueue(randomBytes);
            plaintext.push(randomBytes);
          } else {
            controller.close();
          }
        }
      });
      const encrypted = await openpgp.encrypt({
        data,
        passwords: ['test'],
      });

      const msgAsciiArmored = encrypted.data;
      const message = await openpgp.message.readArmored(msgAsciiArmored);
      const decrypted = await openpgp.decrypt({
        passwords: ['test'],
        message,
        format: 'binary'
      });
      expect(util.isStream(decrypted.data)).to.be.true;
      expect(await openpgp.stream.getReader(openpgp.stream.clone(decrypted.data)).readBytes(1024)).to.deep.equal(plaintext[0]);
      if (i > 10) throw new Error('Data did not arrive early.');
      expect(await openpgp.stream.readToEnd(decrypted.data)).to.deep.equal(util.concatUint8Array(plaintext));
    } finally {
      openpgp.config.aead_protect = aead_protectValue;
      openpgp.config.aead_chunk_size_byte = aead_chunk_size_byteValue;
    }
  });

  it('stream.transformPair()', async function() {
    let plaintext = [];
    let i = 0;
    let canceled = false;
    const data = new ReadableStream({
      async pull(controller) {
        await new Promise(setTimeout);
        if (i++ < 10) {
          let randomBytes = await openpgp.crypto.random.getRandomBytes(1024);
          controller.enqueue(randomBytes);
          plaintext.push(randomBytes);
        } else {
          controller.close();
        }
      },
      cancel() {
        canceled = true;
      }
    });

    const transformed = stream.transformPair(stream.slice(data, 0, 5000), async (readable, writable) => {
      const reader = stream.getReader(readable);
      const writer = stream.getWriter(writable);
      try {
        while (true) {
          await writer.ready;
          const { done, value } = await reader.read();
          if (done) {
            await writer.close();
            break;
          }
          await writer.write(value);
        }
      } catch(e) {
        await writer.abort(e);
      }
    });
    await new Promise(resolve => setTimeout(resolve));
    await stream.cancel(transformed);
    expect(canceled).to.be.true;
  });

  it('Input stream should be canceled when canceling decrypted stream (draft04)', async function() {
    let aead_protectValue = openpgp.config.aead_protect;
    let aead_chunk_size_byteValue = openpgp.config.aead_chunk_size_byte;
    openpgp.config.aead_protect = true;
    openpgp.config.aead_chunk_size_byte = 4;
    try {
      let plaintext = [];
      let i = 0;
      let canceled = false;
      const data = new ReadableStream({
        async pull(controller) {
          await new Promise(resolve => setTimeout(resolve, 10));
          if (i++ < 10) {
            let randomBytes = await openpgp.crypto.random.getRandomBytes(1024);
            controller.enqueue(randomBytes);
            plaintext.push(randomBytes);
          } else {
            controller.close();
          }
        },
        cancel() {
          canceled = true;
        }
      });
      const encrypted = await openpgp.encrypt({
        data,
        passwords: ['test'],
      });

      const msgAsciiArmored = encrypted.data;
      const message = await openpgp.message.readArmored(msgAsciiArmored);
      const decrypted = await openpgp.decrypt({
        passwords: ['test'],
        message,
        format: 'binary'
      });
      expect(util.isStream(decrypted.data)).to.be.true;
      const reader = openpgp.stream.getReader(decrypted.data);
      expect(await reader.readBytes(1024)).to.deep.equal(plaintext[0]);
      if (i > 10) throw new Error('Data did not arrive early.');
      reader.releaseLock();
      await openpgp.stream.cancel(decrypted.data, new Error('canceled by test'));
      expect(canceled).to.be.true;
    } finally {
      openpgp.config.aead_protect = aead_protectValue;
      openpgp.config.aead_chunk_size_byte = aead_chunk_size_byteValue;
    }
  });

  it('Sign/verify: Input stream should be canceled when canceling decrypted stream (draft04)', async function() {
    let aead_protectValue = openpgp.config.aead_protect;
    let aead_chunk_size_byteValue = openpgp.config.aead_chunk_size_byte;
    openpgp.config.aead_protect = true;
    openpgp.config.aead_chunk_size_byte = 4;
    try {
      const pubKey = (await openpgp.key.readArmored(pub_key)).keys[0];
      const privKey = (await openpgp.key.readArmored(priv_key)).keys[0];
      await privKey.decrypt(passphrase);

      let plaintext = [];
      let i = 0;
      let canceled = false;
      const data = new ReadableStream({
        async pull(controller) {
          await new Promise(resolve => setTimeout(resolve, 10));
          if (i++ < 10) {
            let randomBytes = await openpgp.crypto.random.getRandomBytes(1024);
            controller.enqueue(randomBytes);
            plaintext.push(randomBytes);
          } else {
            controller.close();
          }
        },
        cancel() {
          canceled = true;
        }
      });
      const encrypted = await openpgp.sign({
        data,
        privateKeys: privKey
      });

      const msgAsciiArmored = encrypted.data;
      const message = await openpgp.message.readArmored(msgAsciiArmored);
      const decrypted = await openpgp.verify({
        publicKeys: pubKey,
        message
      });
      expect(util.isStream(decrypted.data)).to.be.true;
      const reader = openpgp.stream.getReader(decrypted.data);
      expect(await reader.readBytes(1024)).to.deep.equal(plaintext[0]);
      if (i > 10) throw new Error('Data did not arrive early.');
      reader.releaseLock();
      await openpgp.stream.cancel(decrypted.data, new Error('canceled by test'));
      expect(canceled).to.be.true;
      expect(await decrypted.signatures).to.exist.and.have.length(0);
    } finally {
      openpgp.config.aead_protect = aead_protectValue;
      openpgp.config.aead_chunk_size_byte = aead_chunk_size_byteValue;
    }
  });

  it("Don't pull entire input stream when we're not pulling encrypted stream", async function() {
    let plaintext = [];
    let i = 0;
    const data = new ReadableStream({
      async pull(controller) {
        if (i++ < 100) {
          let randomBytes = await openpgp.crypto.random.getRandomBytes(1024);
          controller.enqueue(randomBytes);
          plaintext.push(randomBytes);
        } else {
          controller.close();
        }
        await new Promise(setTimeout);
      }
    });
    const encrypted = await openpgp.encrypt({
      data,
      passwords: ['test'],
    });
    const reader = openpgp.stream.getReader(encrypted.data);
    expect(await reader.readBytes(1024)).to.match(/^-----BEGIN PGP MESSAGE-----\r\n/);
    if (i > 10) throw new Error('Data did not arrive early.');
    await new Promise(resolve => setTimeout(resolve, 3000));
    expect(i).to.be.lessThan(50);
  });

  it("Sign: Don't pull entire input stream when we're not pulling signed stream", async function() {
    const pubKey = (await openpgp.key.readArmored(pub_key)).keys[0];
    const privKey = (await openpgp.key.readArmored(priv_key)).keys[0];
    await privKey.decrypt(passphrase);

    let plaintext = [];
    let i = 0;
    const data = new ReadableStream({
      async pull(controller) {
        if (i++ < 100) {
          let randomBytes = await openpgp.crypto.random.getRandomBytes(1024);
          controller.enqueue(randomBytes);
          plaintext.push(randomBytes);
        } else {
          controller.close();
        }
        await new Promise(setTimeout);
      }
    });
    const encrypted = await openpgp.sign({
      data,
      privateKeys: privKey
    });
    const reader = openpgp.stream.getReader(encrypted.data);
    expect(await reader.readBytes(1024)).to.match(/^-----BEGIN PGP MESSAGE-----\r\n/);
    if (i > 10) throw new Error('Data did not arrive early.');
    await new Promise(resolve => setTimeout(resolve, 3000));
    expect(i).to.be.lessThan(50);
  });

  it("Don't pull entire input stream when we're not pulling decrypted stream (draft04)", async function() {
    let aead_protectValue = openpgp.config.aead_protect;
    let aead_chunk_size_byteValue = openpgp.config.aead_chunk_size_byte;
    openpgp.config.aead_protect = true;
    openpgp.config.aead_chunk_size_byte = 4;
    try {
      let plaintext = [];
      let i = 0;
      const data = new ReadableStream({
        async pull(controller) {
          if (i++ < 100) {
            let randomBytes = await openpgp.crypto.random.getRandomBytes(1024);
            controller.enqueue(randomBytes);
            plaintext.push(randomBytes);
          } else {
            controller.close();
          }
          await new Promise(setTimeout);
        }
      });
      const encrypted = await openpgp.encrypt({
        data,
        passwords: ['test'],
      });
      const msgAsciiArmored = encrypted.data;
      const message = await openpgp.message.readArmored(msgAsciiArmored);
      const decrypted = await openpgp.decrypt({
        passwords: ['test'],
        message,
        format: 'binary'
      });
      expect(util.isStream(decrypted.data)).to.be.true;
      const reader = openpgp.stream.getReader(decrypted.data);
      expect(await reader.readBytes(1024)).to.deep.equal(plaintext[0]);
      if (i > 10) throw new Error('Data did not arrive early.');
      await new Promise(resolve => setTimeout(resolve, 3000));
      expect(i).to.be.lessThan(50);
    } finally {
      openpgp.config.aead_protect = aead_protectValue;
      openpgp.config.aead_chunk_size_byte = aead_chunk_size_byteValue;
    }
  });

  it("Sign/verify: Don't pull entire input stream when we're not pulling verified stream (draft04)", async function() {
    let aead_protectValue = openpgp.config.aead_protect;
    let aead_chunk_size_byteValue = openpgp.config.aead_chunk_size_byte;
    openpgp.config.aead_protect = true;
    openpgp.config.aead_chunk_size_byte = 4;
    try {
      const pubKey = (await openpgp.key.readArmored(pub_key)).keys[0];
      const privKey = (await openpgp.key.readArmored(priv_key)).keys[0];
      await privKey.decrypt(passphrase);

      let plaintext = [];
      let i = 0;
      const data = new ReadableStream({
        async pull(controller) {
          if (i++ < 100) {
            let randomBytes = await openpgp.crypto.random.getRandomBytes(1024);
            controller.enqueue(randomBytes);
            plaintext.push(randomBytes);
          } else {
            controller.close();
          }
          await new Promise(setTimeout);
        }
      });
      const encrypted = await openpgp.sign({
        data,
        privateKeys: privKey
      });
      const msgAsciiArmored = encrypted.data;
      const message = await openpgp.message.readArmored(msgAsciiArmored);
      const decrypted = await openpgp.verify({
        publicKeys: pubKey,
        message
      });
      expect(util.isStream(decrypted.data)).to.be.true;
      const reader = openpgp.stream.getReader(decrypted.data);
      expect(await reader.readBytes(1024)).to.deep.equal(plaintext[0]);
      if (i > 10) throw new Error('Data did not arrive early.');
      await new Promise(resolve => setTimeout(resolve, 3000));
      expect(i).to.be.lessThan(50);
    } finally {
      openpgp.config.aead_protect = aead_protectValue;
      openpgp.config.aead_chunk_size_byte = aead_chunk_size_byteValue;
    }
  });
});
