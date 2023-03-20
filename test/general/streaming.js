/* eslint-disable max-lines */
const stream = require('@openpgp/web-stream-tools');
const stub = require('sinon/lib/sinon/stub');
const { use: chaiUse, expect } = require('chai');
chaiUse(require('chai-as-promised'));

const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../..');
const random = require('../../src/crypto/random');
const util = require('../../src/util');

const input = require('./testInputs');

const useNativeStream = (() => { try { new global.ReadableStream(); return true; } catch (e) { return false; } })(); // eslint-disable-line no-new
const NodeReadableStream = useNativeStream ? undefined : require('stream').Readable;

const detectNode = () => typeof globalThis.process === 'object' && typeof globalThis.process.versions === 'object';

const pub_key = [
  '-----BEGIN PGP PUBLIC KEY BLOCK-----',
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
  '-----END PGP PUBLIC KEY BLOCK-----'
].join('\n');

const priv_key = [
  '-----BEGIN PGP PRIVATE KEY BLOCK-----',
  'Version: GnuPG v2.0.19 (GNU/Linux)',
  '',
  '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',
  '=lw5e',
  '-----END PGP PRIVATE KEY BLOCK-----'
].join('\n');

const brainpoolPub = [
  '-----BEGIN PGP PUBLIC KEY BLOCK-----',
  '',
  'mHMEWq8ruRMJKyQDAwIIAQELAwMEhi/66JLo1vMhpytb1bYvBhd/aKHde2Zwke7r',
  'zWFTYBZQl/DUrpMrVAhkQhk5G3kqFWf98O/DpvVmY6EDr3IjmODWowNvGfC4Avc9',
  'rYRgV8GbMBUVLIS+ytS1YNpAKW4vtBlidW5ueSA8YnVubnlAYnVubnkuYnVubnk+',
  'iLAEExMKADgWIQSLliWLcmzBLxv2/X36PWTJvPM4vAUCWq8ruQIbAwULCQgHAwUV',
  'CgkICwUWAgMBAAIeAQIXgAAKCRD6PWTJvPM4vIcVAYCIO41QylZkb9W4FP+kd3bz',
  'b73xxwojWpCiw1bWV9Xe/dKA23DtCYhlmhF/Twjh9lkBfihHXs/negGMnqbA8TQF',
  'U1IvBflDcA7yj677lgLkze/yd5hg/ZVx7M8XyUzcEm9xi7h3BFqvK7kSCSskAwMC',
  'CAEBCwMDBCkGskA01sBvG/B1bl0EN+yxF6xPn74WQoAMm7K4n1PlZ1u8RWg+BJVG',
  'Kna/88ZGcT5BZSUvRrYWgqb4/SPAPea5C1p6UYd+C0C0dVf0FaGv5z0gCtc/+kwF',
  '3sLGLZh3rAMBCQmImAQYEwoAIBYhBIuWJYtybMEvG/b9ffo9ZMm88zi8BQJaryu5',
  'AhsMAAoJEPo9ZMm88zi8w1QBfR4k1d5ElME3ef7viE+Mud4qGv1ra56pKa86hS9+',
  'l262twTxe1hk08/FySeJW08P3wF/WrhCrE9UDD6FQiZk1lqekhd9bf84v6i5Smbi',
  'oml1QWkiI6BtbLD39Su6zQKR7u+Y',
  '=wB7z',
  '-----END PGP PUBLIC KEY BLOCK-----'
].join('\n');

const brainpoolPriv = [
  '-----BEGIN PGP PRIVATE KEY BLOCK-----',
  '',
  'lNYEWq8ruRMJKyQDAwIIAQELAwMEhi/66JLo1vMhpytb1bYvBhd/aKHde2Zwke7r',
  'zWFTYBZQl/DUrpMrVAhkQhk5G3kqFWf98O/DpvVmY6EDr3IjmODWowNvGfC4Avc9',
  'rYRgV8GbMBUVLIS+ytS1YNpAKW4v/gcDAtyjmSfDquSq5ffphtkwJ56Zz5jc+jSm',
  'yZaPgmnPOwcgYhWy1g7BcBKYFPNKZlajnV4Rut2VUWkELwWrRmchX4ENJoAKZob0',
  'l/zjgOPug3FtEGirOPmvi7nOkjDEFNJwtBlidW5ueSA8YnVubnlAYnVubnkuYnVu',
  'bnk+iLAEExMKADgWIQSLliWLcmzBLxv2/X36PWTJvPM4vAUCWq8ruQIbAwULCQgH',
  'AwUVCgkICwUWAgMBAAIeAQIXgAAKCRD6PWTJvPM4vIcVAYCIO41QylZkb9W4FP+k',
  'd3bzb73xxwojWpCiw1bWV9Xe/dKA23DtCYhlmhF/Twjh9lkBfihHXs/negGMnqbA',
  '8TQFU1IvBflDcA7yj677lgLkze/yd5hg/ZVx7M8XyUzcEm9xi5zaBFqvK7kSCSsk',
  'AwMCCAEBCwMDBCkGskA01sBvG/B1bl0EN+yxF6xPn74WQoAMm7K4n1PlZ1u8RWg+',
  'BJVGKna/88ZGcT5BZSUvRrYWgqb4/SPAPea5C1p6UYd+C0C0dVf0FaGv5z0gCtc/',
  '+kwF3sLGLZh3rAMBCQn+BwMC6RvzFHWyKqPlVqrm6+j797Y9vHdZW1zixtmEK0Wg',
  'lvQRpZF8AbpSzk/XolsoeQyic1e18C6ubFZFw7cI7ekINiRu/OXOvBnTbc5TdbDi',
  'kKTuOkL+lEwWrUTEwdshbJ+ImAQYEwoAIBYhBIuWJYtybMEvG/b9ffo9ZMm88zi8',
  'BQJaryu5AhsMAAoJEPo9ZMm88zi8w1QBfR4k1d5ElME3ef7viE+Mud4qGv1ra56p',
  'Ka86hS9+l262twTxe1hk08/FySeJW08P3wF/WrhCrE9UDD6FQiZk1lqekhd9bf84',
  'v6i5Smbioml1QWkiI6BtbLD39Su6zQKR7u+Y',
  '=uGZP',
  '-----END PGP PRIVATE KEY BLOCK-----'
].join('\n');

const brainpoolPass = '321';

const xPub = [
  '-----BEGIN PGP PUBLIC KEY BLOCK-----',
  '',
  'mDMEWkN+5BYJKwYBBAHaRw8BAQdAIGqj23Kp273IPkgjwA7ue5MDIRAfWLYRqnFy',
  'c2AFMcC0EUxpZ2h0IDxsaWdodEBzdW4+iJAEExYIADgWIQSGS0GuVELT3Rs0woce',
  'zfAmwCRYMAUCWkN+5AIbAwULCQgHAgYVCAkKCwIEFgIDAQIeAQIXgAAKCRAezfAm',
  'wCRYMLteAQCFZcl8kBxCH86wmqpc2+KtEA8l/hsfh7jd+JWuyFuuRAD7BOix8Vo1',
  'P/hv8qUYwSn3IRXPeGXucoWVoKGgxRd+zAO4OARaQ37kEgorBgEEAZdVAQUBAQdA',
  'L1KkHCFxtK1CgvZlInT/y6OQeCfXiYzd/i452t2ZR2ADAQgHiHgEGBYIACAWIQSG',
  'S0GuVELT3Rs0wocezfAmwCRYMAUCWkN+5AIbDAAKCRAezfAmwCRYMJ71AQDmoQTg',
  '36pfjrl82srS6XPRJxl3r/6lpWGaNij0VptB2wEA2V10ifOhnwILCw1qBle6On7a',
  'Ba257lrFM+cOSMaEsgo=',
  '=D8HS',
  '-----END PGP PUBLIC KEY BLOCK-----'
].join('\n');

const xPriv = [
  '-----BEGIN PGP PRIVATE KEY BLOCK-----',
  '',
  'lIYEWkN+5BYJKwYBBAHaRw8BAQdAIGqj23Kp273IPkgjwA7ue5MDIRAfWLYRqnFy',
  'c2AFMcD+BwMCeaL+cNXzgI7uJQ7HBv53TAXO3y5uyJQMonkFtQtldL8YDbNP3pbd',
  '3zzo9fxU12bWAJyFwBlBWJqkrxZN+0jt0ElsG3kp+V67MESJkrRhKrQRTGlnaHQg',
  'PGxpZ2h0QHN1bj6IkAQTFggAOBYhBIZLQa5UQtPdGzTChx7N8CbAJFgwBQJaQ37k',
  'AhsDBQsJCAcCBhUICQoLAgQWAgMBAh4BAheAAAoJEB7N8CbAJFgwu14BAIVlyXyQ',
  'HEIfzrCaqlzb4q0QDyX+Gx+HuN34la7IW65EAPsE6LHxWjU/+G/ypRjBKfchFc94',
  'Ze5yhZWgoaDFF37MA5yLBFpDfuQSCisGAQQBl1UBBQEBB0AvUqQcIXG0rUKC9mUi',
  'dP/Lo5B4J9eJjN3+Ljna3ZlHYAMBCAf+BwMCvyW2D5Yx6dbujE3yHi1XQ9MbhOY5',
  'XRFFgYIUYzzi1qmaL+8Gr9zODsUdeO60XHnMXOmqVa6/sdx32TWo5s3sgS19kRUM',
  'D+pbxS/aZnxvrYh4BBgWCAAgFiEEhktBrlRC090bNMKHHs3wJsAkWDAFAlpDfuQC',
  'GwwACgkQHs3wJsAkWDCe9QEA5qEE4N+qX465fNrK0ulz0ScZd6/+paVhmjYo9Fab',
  'QdsBANlddInzoZ8CCwsNagZXujp+2gWtue5axTPnDkjGhLIK',
  '=wo91',
  '-----END PGP PRIVATE KEY BLOCK-----'
].join('\n');

const xPass = 'sun';


let privKey;
let pubKey;
let plaintext;
let data;
let i;
let canceled;
let expectedType;
let dataArrived;

function tests() {
  it('Encrypt small message', async function() {
    dataArrived(); // Do not wait until data arrived.
    const data = global.ReadableStream ? new global.ReadableStream({
      start(controller) {
        controller.enqueue(util.stringToUint8Array('hello '));
        controller.enqueue(util.stringToUint8Array('world'));
        controller.close();
      }
    }) : new NodeReadableStream({
      read() {
        this.push(util.stringToUint8Array('hello '));
        this.push(util.stringToUint8Array('world'));
        this.push(null);
      }
    });
    const encrypted = await openpgp.encrypt({
      message: await openpgp.createMessage({ binary: data }),
      passwords: ['test']
    });
    const msgAsciiArmored = await stream.readToEnd(encrypted);
    const message = await openpgp.readMessage({ armoredMessage: msgAsciiArmored });
    const decrypted = await openpgp.decrypt({
      passwords: ['test'],
      message
    });
    expect(decrypted.data).to.equal('hello world');
  });

  it('Encrypt larger message', async function() {
    const encrypted = await openpgp.encrypt({
      message: await openpgp.createMessage({ binary: data }),
      passwords: ['test']
    });
    const reader = stream.getReader(encrypted);
    expect(await reader.peekBytes(1024)).to.match(/^-----BEGIN PGP MESSAGE-----\n/);
    dataArrived();
    reader.releaseLock();
    const msgAsciiArmored = await stream.readToEnd(encrypted);
    const message = await openpgp.readMessage({ armoredMessage: msgAsciiArmored });
    const decrypted = await openpgp.decrypt({
      passwords: ['test'],
      message,
      format: 'binary'
    });
    expect(decrypted.data).to.deep.equal(util.concatUint8Array(plaintext));
  });

  it('Input stream should be canceled when canceling encrypted stream', async function() {
    const encrypted = await openpgp.encrypt({
      message: await openpgp.createMessage({ binary: data }),
      passwords: ['test']
    });
    const reader = stream.getReader(encrypted);
    expect(await reader.readBytes(1024)).to.match(/^-----BEGIN PGP MESSAGE-----\n/);
    dataArrived();
    reader.releaseLock();
    await stream.cancel(encrypted);
    expect(canceled).to.be.true;
  });

  it('Sign: Input stream should be canceled when canceling encrypted stream', async function() {
    const signed = await openpgp.sign({
      message: await openpgp.createMessage({ binary: data }),
      signingKeys: privKey,
      config: { minRSABits: 1024 }
    });
    const reader = stream.getReader(signed);
    expect(await reader.readBytes(1024)).to.match(/^-----BEGIN PGP MESSAGE-----\n/);
    dataArrived();
    reader.releaseLock();
    await stream.cancel(signed);
    expect(canceled).to.be.true;
  });

  it('Encrypt and decrypt larger message roundtrip', async function() {
    const aeadProtectValue = openpgp.config.aeadProtect;
    openpgp.config.aeadProtect = false;
    const encrypted = await openpgp.encrypt({
      message: await openpgp.createMessage({ binary: data }),
      passwords: ['test'],
      format: 'binary'
    });
    expect(stream.isStream(encrypted)).to.equal(expectedType);

    const message = await openpgp.readMessage({ binaryMessage: encrypted });
    setTimeout(dataArrived, 3000); // Do not wait until data arrived, but wait a bit to check that it doesn't arrive early.
    const decrypted = await openpgp.decrypt({
      passwords: ['test'],
      message,
      format: 'binary'
    });
    expect(stream.isStream(decrypted.data)).to.equal(expectedType);
    const reader = stream.getReader(decrypted.data);
    expect(await reader.peekBytes(1024)).to.deep.equal(plaintext[0]);
    if (i <= 10) throw new Error('Data arrived early.');
    expect(await reader.readToEnd()).to.deep.equal(util.concatUint8Array(plaintext));
    openpgp.config.aeadProtect = aeadProtectValue;
  });

  it('Encrypt and decrypt larger message roundtrip (allowUnauthenticatedStream=true)', async function() {
    const aeadProtectValue = openpgp.config.aeadProtect;
    const allowUnauthenticatedStreamValue = openpgp.config.allowUnauthenticatedStream;
    openpgp.config.aeadProtect = false;
    openpgp.config.allowUnauthenticatedStream = true;
    try {
      const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ binary: data }),
        passwords: ['test'],
        format: 'binary'
      });
      expect(stream.isStream(encrypted)).to.equal(expectedType);

      const message = await openpgp.readMessage({ binaryMessage: encrypted });
      const decrypted = await openpgp.decrypt({
        passwords: ['test'],
        message,
        format: 'binary'
      });
      expect(stream.isStream(decrypted.data)).to.equal(expectedType);
      expect(stream.isStream(decrypted.signatures)).to.be.false;
      const reader = stream.getReader(decrypted.data);
      expect(await reader.peekBytes(1024)).to.deep.equal(plaintext[0]);
      dataArrived();
      expect(await reader.readToEnd()).to.deep.equal(util.concatUint8Array(plaintext));
      expect(decrypted.signatures).to.exist.and.have.length(0);
    } finally {
      openpgp.config.aeadProtect = aeadProtectValue;
      openpgp.config.allowUnauthenticatedStream = allowUnauthenticatedStreamValue;
    }
  });

  it('Encrypt and decrypt larger message roundtrip using public keys (allowUnauthenticatedStream=true)', async function() {
    const allowUnauthenticatedStreamValue = openpgp.config.allowUnauthenticatedStream;
    openpgp.config.allowUnauthenticatedStream = true;
    try {
      const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ binary: data }),
        encryptionKeys: pubKey,
        signingKeys: privKey,
        format: 'binary',
        config: { minRSABits: 1024 }
      });
      expect(stream.isStream(encrypted)).to.equal(expectedType);

      const message = await openpgp.readMessage({ binaryMessage: encrypted });
      const decrypted = await openpgp.decrypt({
        verificationKeys: pubKey,
        decryptionKeys: privKey,
        message,
        format: 'binary'
      });
      expect(stream.isStream(decrypted.data)).to.equal(expectedType);
      const reader = stream.getReader(decrypted.data);
      expect(await reader.peekBytes(1024)).to.deep.equal(plaintext[0]);
      dataArrived();
      expect(await reader.readToEnd()).to.deep.equal(util.concatUint8Array(plaintext));
    } finally {
      openpgp.config.allowUnauthenticatedStream = allowUnauthenticatedStreamValue;
    }
  });

  it('Encrypt and decrypt larger message roundtrip using curve x25519 (allowUnauthenticatedStream=true)', async function() {
    const allowUnauthenticatedStreamValue = openpgp.config.allowUnauthenticatedStream;
    openpgp.config.allowUnauthenticatedStream = true;
    const pub = await openpgp.readKey({ armoredKey: xPub });
    const priv = await openpgp.decryptKey({
      privateKey: await openpgp.readKey({ armoredKey: xPriv }),
      passphrase: xPass
    });

    try {
      const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ binary: data }),
        encryptionKeys: pub,
        signingKeys: priv,
        format: 'binary'
      });
      expect(stream.isStream(encrypted)).to.equal(expectedType);

      const message = await openpgp.readMessage({ binaryMessage: encrypted });
      const decrypted = await openpgp.decrypt({
        verificationKeys: pub,
        decryptionKeys: priv,
        message,
        format: 'binary'
      });
      expect(stream.isStream(decrypted.data)).to.equal(expectedType);
      const reader = stream.getReader(decrypted.data);
      expect(await reader.peekBytes(1024)).to.deep.equal(plaintext[0]);
      dataArrived();
      expect(await reader.readToEnd()).to.deep.equal(util.concatUint8Array(plaintext));
    } finally {
      openpgp.config.allowUnauthenticatedStream = allowUnauthenticatedStreamValue;
    }
  });

  it('Encrypt and decrypt larger message roundtrip using curve brainpool (allowUnauthenticatedStream=true)', async function() {
    const allowUnauthenticatedStreamValue = openpgp.config.allowUnauthenticatedStream;
    openpgp.config.allowUnauthenticatedStream = true;
    const pub = await openpgp.readKey({ armoredKey: brainpoolPub });
    const priv = await openpgp.decryptKey({
      privateKey: await openpgp.readKey({ armoredKey: brainpoolPriv }),
      passphrase: brainpoolPass
    });

    try {
      const config = { rejectCurves: new Set() };
      const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ binary: data }),
        encryptionKeys: pub,
        signingKeys: priv,
        format: 'binary',
        config
      });
      expect(stream.isStream(encrypted)).to.equal(expectedType);

      const message = await openpgp.readMessage({ binaryMessage: encrypted });
      const decrypted = await openpgp.decrypt({
        verificationKeys: pub,
        decryptionKeys: priv,
        message,
        format: 'binary',
        config
      });
      expect(stream.isStream(decrypted.data)).to.equal(expectedType);
      const reader = stream.getReader(decrypted.data);
      expect(await reader.peekBytes(1024)).to.deep.equal(plaintext[0]);
      dataArrived();
      expect(await reader.readToEnd()).to.deep.equal(util.concatUint8Array(plaintext));
    } finally {
      openpgp.config.allowUnauthenticatedStream = allowUnauthenticatedStreamValue;
    }
  });

  it('Detect MDC modifications (allowUnauthenticatedStream=true)', async function() {
    const aeadProtectValue = openpgp.config.aeadProtect;
    openpgp.config.aeadProtect = false;
    const allowUnauthenticatedStreamValue = openpgp.config.allowUnauthenticatedStream;
    openpgp.config.allowUnauthenticatedStream = true;
    try {
      const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ binary: data, filename: 'msg.bin' }),
        passwords: ['test']
      });
      expect(stream.isStream(encrypted)).to.equal(expectedType);

      const message = await openpgp.readMessage({
        armoredMessage: stream[expectedType === 'node' ? 'webToNode' : global.ReadableStream === stream.ReadableStream ? 'toStream' : 'toNativeReadable'](stream.transform(encrypted, value => {
          value += '';
          if (value === '=' || value.length === 5) return; // Remove checksum
          const newlineIndex = value.indexOf('\n', 500);
          if (value.length > 1000) return value.slice(0, newlineIndex - 1) + (value[newlineIndex - 1] === 'a' ? 'b' : 'a') + value.slice(newlineIndex);
          return value;
        }), { encoding: 'utf8' })
      });
      const decrypted = await openpgp.decrypt({
        passwords: ['test'],
        message,
        format: 'binary'
      });
      expect(stream.isStream(decrypted.data)).to.equal(expectedType);
      const reader = stream.getReader(decrypted.data);
      expect(await reader.peekBytes(1024)).not.to.deep.equal(plaintext[0]);
      dataArrived();
      await expect(reader.readToEnd()).to.be.rejectedWith('Modification detected.');
      expect(decrypted.signatures).to.exist.and.have.length(0);
    } finally {
      openpgp.config.aeadProtect = aeadProtectValue;
      openpgp.config.allowUnauthenticatedStream = allowUnauthenticatedStreamValue;
    }
  });

  it('Detect armor checksum error (allowUnauthenticatedStream=true)', async function() {
    const allowUnauthenticatedStreamValue = openpgp.config.allowUnauthenticatedStream;
    openpgp.config.allowUnauthenticatedStream = true;
    try {
      const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ binary: data }),
        encryptionKeys: pubKey,
        signingKeys: privKey,
        config: { minRSABits: 1024 }
      });
      expect(stream.isStream(encrypted)).to.equal(expectedType);

      const message = await openpgp.readMessage({
        armoredMessage: stream[expectedType === 'node' ? 'webToNode' : global.ReadableStream === stream.ReadableStream ? 'toStream' : 'toNativeReadable'](stream.transform(encrypted, value => {
          value += '';
          const newlineIndex = value.indexOf('\n', 500);
          if (value.length > 1000) return value.slice(0, newlineIndex - 1) + (value[newlineIndex - 1] === 'a' ? 'b' : 'a') + value.slice(newlineIndex);
          return value;
        }), { encoding: 'utf8' })
      });
      const decrypted = await openpgp.decrypt({
        verificationKeys: pubKey,
        decryptionKeys: privKey,
        message,
        format: 'binary'
      });
      expect(stream.isStream(decrypted.data)).to.equal(expectedType);
      const reader = stream.getReader(decrypted.data);
      expect(await reader.peekBytes(1024)).not.to.deep.equal(plaintext[0]);
      dataArrived();
      await expect(reader.readToEnd()).to.be.rejectedWith('Ascii armor integrity check failed');
      expect(decrypted.signatures).to.exist.and.have.length(1);
    } finally {
      openpgp.config.allowUnauthenticatedStream = allowUnauthenticatedStreamValue;
    }
  });

  it('Detect armor checksum error when not passing public keys (allowUnauthenticatedStream=true)', async function() {
    const allowUnauthenticatedStreamValue = openpgp.config.allowUnauthenticatedStream;
    openpgp.config.allowUnauthenticatedStream = true;
    try {
      const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ binary: data }),
        encryptionKeys: pubKey,
        signingKeys: privKey,
        config: { minRSABits: 1024 }
      });
      expect(stream.isStream(encrypted)).to.equal(expectedType);

      const message = await openpgp.readMessage({
        armoredMessage: stream[expectedType === 'node' ? 'webToNode' : global.ReadableStream === stream.ReadableStream ? 'toStream' : 'toNativeReadable'](stream.transform(encrypted, value => {
          value += '';
          const newlineIndex = value.indexOf('\n', 500);
          if (value.length > 1000) return value.slice(0, newlineIndex - 1) + (value[newlineIndex - 1] === 'a' ? 'b' : 'a') + value.slice(newlineIndex);
          return value;
        }), { encoding: 'utf8' })
      });
      const decrypted = await openpgp.decrypt({
        decryptionKeys: privKey,
        message,
        format: 'binary'
      });
      expect(stream.isStream(decrypted.data)).to.equal(expectedType);
      const reader = stream.getReader(decrypted.data);
      expect(await reader.peekBytes(1024)).not.to.deep.equal(plaintext[0]);
      dataArrived();
      await expect(reader.readToEnd()).to.be.rejectedWith('Ascii armor integrity check failed');
      expect(decrypted.signatures).to.exist.and.have.length(1);
      await expect(decrypted.signatures[0].verified).to.be.eventually.rejectedWith(/Could not find signing key/);
    } finally {
      openpgp.config.allowUnauthenticatedStream = allowUnauthenticatedStreamValue;
    }
  });

  it('Sign/verify: Detect armor checksum error', async function() {
    const signed = await openpgp.sign({
      message: await openpgp.createMessage({ binary: data }),
      signingKeys: privKey,
      config: { minRSABits: 1024 }
    });
    expect(stream.isStream(signed)).to.equal(expectedType);

    const message = await openpgp.readMessage({
      armoredMessage: stream[expectedType === 'node' ? 'webToNode' : global.ReadableStream === stream.ReadableStream ? 'toStream' : 'toNativeReadable'](stream.transform(signed, value => {
        value += '';
        const newlineIndex = value.indexOf('\n', 500);
        if (value.length > 1000) return value.slice(0, newlineIndex - 1) + (value[newlineIndex - 1] === 'a' ? 'b' : 'a') + value.slice(newlineIndex);
        return value;
      }), { encoding: 'utf8' })
    });
    const verified = await openpgp.verify({
      verificationKeys: pubKey,
      message,
      format: 'binary',
      config: { minRSABits: 1024 }
    });
    expect(stream.isStream(verified.data)).to.equal(expectedType);
    const reader = stream.getReader(verified.data);
    expect(await reader.peekBytes(1024)).not.to.deep.equal(plaintext[0]);
    dataArrived();
    await expect(reader.readToEnd()).to.be.rejectedWith('Ascii armor integrity check failed');
    expect(verified.signatures).to.exist.and.have.length(1);
  });

  it('stream.transformPair()', async function() {
    dataArrived(); // Do not wait until data arrived.
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
      } catch (e) {
        await writer.abort(e);
      }
    });
    await new Promise(resolve => { setTimeout(resolve); });
    await stream.cancel(transformed);
    await new Promise(resolve => { setTimeout(resolve); });
    expect(canceled).to.be.true;
  });

  it('Sign/verify: Input stream should be canceled when canceling verified stream', async function() {
    const signed = await openpgp.sign({
      message: await openpgp.createMessage({ binary: data }),
      signingKeys: privKey,
      config: { minRSABits: 1024 }
    });
    expect(stream.isStream(signed)).to.equal(expectedType);

    const message = await openpgp.readMessage({ armoredMessage: signed });
    const verified = await openpgp.verify({
      verificationKeys: pubKey,
      message,
      format: 'binary',
      config: { minRSABits: 1024 }
    });
    expect(stream.isStream(verified.data)).to.equal(expectedType);
    const reader = stream.getReader(verified.data);
    expect(await reader.readBytes(1024)).to.deep.equal(plaintext[0]);
    dataArrived();
    reader.releaseLock();
    await stream.cancel(verified.data, new Error('canceled by test'));
    expect(canceled).to.be.true;
    expect(verified.signatures).to.exist.and.have.length(1);
    await expect(verified.signatures[0].verified).to.be.rejectedWith('canceled');
  });

  it("Don't pull entire input stream when we're not pulling encrypted stream", async function() {
    const encrypted = await openpgp.encrypt({
      message: await openpgp.createMessage({ binary: data }),
      passwords: ['test']
    });
    expect(stream.isStream(encrypted)).to.equal(expectedType);

    const reader = stream.getReader(encrypted);
    expect(await reader.readBytes(1024)).to.match(/^-----BEGIN PGP MESSAGE-----\n/);
    dataArrived();
    await new Promise(resolve => { setTimeout(resolve, 3000); });
    expect(i).to.be.lessThan(expectedType === 'web' ? 50 : 100);
  });

  it("Sign: Don't pull entire input stream when we're not pulling signed stream", async function() {
    const signed = await openpgp.sign({
      message: await openpgp.createMessage({ binary: data }),
      signingKeys: privKey,
      config: { minRSABits: 1024 }
    });
    expect(stream.isStream(signed)).to.equal(expectedType);

    const reader = stream.getReader(signed);
    expect(await reader.readBytes(1024)).to.match(/^-----BEGIN PGP MESSAGE-----\n/);
    dataArrived();
    await new Promise(resolve => { setTimeout(resolve, 3000); });
    expect(i).to.be.lessThan(expectedType === 'web' ? 50 : 100);
  });

  it("Sign/verify: Don't pull entire input stream when we're not pulling verified stream", async function() {
    const signed = await openpgp.sign({
      message: await openpgp.createMessage({ binary: data }),
      signingKeys: privKey,
      config: { minRSABits: 1024 }
    });
    expect(stream.isStream(signed)).to.equal(expectedType);
    const message = await openpgp.readMessage({ armoredMessage: signed });
    const verified = await openpgp.verify({
      verificationKeys: pubKey,
      message,
      format: 'binary'
    });
    expect(stream.isStream(verified.data)).to.equal(expectedType);
    const reader = stream.getReader(verified.data);
    expect(await reader.readBytes(1024)).to.deep.equal(plaintext[0]);
    dataArrived();
    await new Promise(resolve => { setTimeout(resolve, 3000); });
    expect(i).to.be.lessThan(expectedType === 'web' ? 50 : 250);
  });

  it('Detached sign small message', async function() {
    dataArrived(); // Do not wait until data arrived.
    const data = global.ReadableStream ? new global.ReadableStream({
      start(controller) {
        controller.enqueue(util.stringToUint8Array('hello '));
        controller.enqueue(util.stringToUint8Array('world'));
        controller.close();
      }
    }) : new NodeReadableStream({
      read() {
        this.push(util.stringToUint8Array('hello '));
        this.push(util.stringToUint8Array('world'));
        this.push(null);
      }
    });
    const signed = await openpgp.sign({
      message: await openpgp.createMessage({ binary: data }),
      signingKeys: privKey,
      detached: true,
      config: { minRSABits: 1024 }
    });
    expect(stream.isStream(signed)).to.equal(expectedType);
    const armoredSignature = await stream.readToEnd(signed);
    const signature = await openpgp.readSignature({ armoredSignature });
    const verified = await openpgp.verify({
      signature,
      verificationKeys: pubKey,
      message: await openpgp.createMessage({ text: 'hello world' }),
      config: { minRSABits: 1024 }
    });
    expect(verified.data).to.equal('hello world');
    expect(verified.signatures).to.exist.and.have.length(1);
    expect(await verified.signatures[0].verified).to.be.true;
  });

  it('Detached sign small message using brainpool curve keys', async function() {
    dataArrived(); // Do not wait until data arrived.
    const data = global.ReadableStream ? new global.ReadableStream({
      start(controller) {
        controller.enqueue(util.stringToUint8Array('hello '));
        controller.enqueue(util.stringToUint8Array('world'));
        controller.close();
      }
    }) : new NodeReadableStream({
      read() {
        this.push(util.stringToUint8Array('hello '));
        this.push(util.stringToUint8Array('world'));
        this.push(null);
      }
    });
    const pub = await openpgp.readKey({ armoredKey: brainpoolPub });
    const priv = await openpgp.decryptKey({
      privateKey: await openpgp.readKey({ armoredKey: brainpoolPriv }),
      passphrase: brainpoolPass
    });
    const config = { rejectCurves: new Set() };

    const signed = await openpgp.sign({
      message: await openpgp.createMessage({ binary: data }),
      signingKeys: priv,
      detached: true,
      config
    });
    expect(stream.isStream(signed)).to.equal(expectedType);
    const armoredSignature = await stream.readToEnd(signed);
    const signature = await openpgp.readSignature({ armoredSignature });
    const verified = await openpgp.verify({
      signature,
      verificationKeys: pub,
      message: await openpgp.createMessage({ text: 'hello world' }),
      config
    });
    expect(verified.data).to.equal('hello world');
    expect(verified.signatures).to.exist.and.have.length(1);
    expect(await verified.signatures[0].verified).to.be.true;
  });

  it('Detached sign small message using curve25519 keys (legacy format)', async function() {
    dataArrived(); // Do not wait until data arrived.
    const data = global.ReadableStream ? new global.ReadableStream({
      async start(controller) {
        controller.enqueue(util.stringToUint8Array('hello '));
        controller.enqueue(util.stringToUint8Array('world'));
        controller.close();
      }
    }) : new NodeReadableStream({
      read() {
        this.push(util.stringToUint8Array('hello '));
        this.push(util.stringToUint8Array('world'));
        this.push(null);
      }
    });
    const pub = await openpgp.readKey({ armoredKey: xPub });
    const priv = await openpgp.decryptKey({
      privateKey: await openpgp.readKey({ armoredKey: xPriv }),
      passphrase: xPass
    });

    const signed = await openpgp.sign({
      message: await openpgp.createMessage({ binary: data }),
      signingKeys: priv,
      detached: true
    });
    expect(stream.isStream(signed)).to.equal(expectedType);
    const armoredSignature = await stream.readToEnd(signed);
    const signature = await openpgp.readSignature({ armoredSignature });
    const verified = await openpgp.verify({
      signature,
      verificationKeys: pub,
      message: await openpgp.createMessage({ text: 'hello world' })
    });
    expect(verified.data).to.equal('hello world');
    expect(verified.signatures).to.exist.and.have.length(1);
    expect(await verified.signatures[0].verified).to.be.true;
  });

  it("Detached sign is expected to pull entire input stream when we're not pulling signed stream", async function() {
    const signed = await openpgp.sign({
      message: await openpgp.createMessage({ binary: data }),
      signingKeys: privKey,
      detached: true,
      config: { minRSABits: 1024 }
    });
    expect(stream.isStream(signed)).to.equal(expectedType);
    const reader = stream.getReader(signed);
    expect((await reader.readBytes(30)).toString('utf8')).to.equal('-----BEGIN PGP SIGNATURE-----\n');
    dataArrived();
    await new Promise(resolve => { setTimeout(resolve, 3000); });
    expect(i).to.equal(expectedType === 'web' ? 100 : 500);
  });

  it('Detached sign: Input stream should be canceled when canceling signed stream', async function() {
    const signed = await openpgp.sign({
      message: await openpgp.createMessage({ binary: data }),
      signingKeys: privKey,
      detached: true,
      config: { minRSABits: 1024 }
    });
    expect(stream.isStream(signed)).to.equal(expectedType);
    const reader = stream.getReader(signed);
    expect((await reader.readBytes(30)).toString('utf8')).to.equal('-----BEGIN PGP SIGNATURE-----\n');
    dataArrived();
    reader.releaseLock();
    await stream.cancel(signed, new Error('canceled by test'));
    expect(canceled).to.be.true;
  });

  describe('AEAD', function() {
    let aeadProtectValue;
    let aeadChunkSizeByteValue;
    beforeEach(function() {
      aeadProtectValue = openpgp.config.aeadProtect;
      aeadChunkSizeByteValue = openpgp.config.aeadChunkSizeByte;
      openpgp.config.aeadProtect = true;
      openpgp.config.aeadChunkSizeByte = 4;
    });
    afterEach(function() {
      openpgp.config.aeadProtect = aeadProtectValue;
      openpgp.config.aeadChunkSizeByte = aeadChunkSizeByteValue;
    });


    it('Encrypt and decrypt larger message roundtrip (AEAD)', async function() {
      const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ binary: data }),
        passwords: ['test'],
        format: 'binary'
      });
      expect(stream.isStream(encrypted)).to.equal(expectedType);

      const message = await openpgp.readMessage({ binaryMessage: encrypted });
      const decrypted = await openpgp.decrypt({
        passwords: ['test'],
        message,
        format: 'binary'
      });
      expect(stream.isStream(decrypted.data)).to.equal(expectedType);
      const reader = stream.getReader(decrypted.data);
      expect(await reader.peekBytes(1024)).to.deep.equal(plaintext[0]);
      dataArrived();
      expect(await reader.readToEnd()).to.deep.equal(util.concatUint8Array(plaintext));
    });

    it('Encrypt and decrypt larger text message roundtrip (AEAD)', async function() {
      openpgp.config.aeadChunkSizeByte = 0;

      const plaintext = [];
      let i = 0;
      const data = global.ReadableStream ? new global.ReadableStream({
        async pull(controller) {
          await new Promise(resolve => { setTimeout(resolve, 10); });
          if (i++ < 10) {
            const randomData = input.createSomeMessage();
            controller.enqueue(randomData);
            plaintext.push(randomData);
          } else {
            controller.close();
          }
        }
      }) : new NodeReadableStream({
        encoding: 'utf8',
        async read() {
          while (true) {
            await new Promise(resolve => { setTimeout(resolve, 10); });
            if (i++ < 10) {
              const randomData = input.createSomeMessage();
              plaintext.push(randomData);
              if (!this.push(randomData)) break;
            } else {
              return this.push(null);
            }
          }
        }
      });
      const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ text: data }),
        passwords: ['test']
      });
      expect(stream.isStream(encrypted)).to.equal(expectedType);

      const message = await openpgp.readMessage({ armoredMessage: encrypted });
      const decrypted = await openpgp.decrypt({
        passwords: ['test'],
        message
      });
      expect(stream.isStream(decrypted.data)).to.equal(expectedType);
      const reader = stream.getReader(decrypted.data);
      expect((await reader.peekBytes(plaintext[0].length * 4)).toString('utf8').substr(0, plaintext[0].length)).to.equal(plaintext[0]);
      dataArrived();
      expect((await reader.readToEnd()).toString('utf8')).to.equal(util.concat(plaintext));

    });

    it("Don't pull entire input stream when we're not pulling decrypted stream (AEAD)", async function() {
      let coresStub;
      if (detectNode()) {
        coresStub = stub(require('os'), 'cpus');
        coresStub.returns(new Array(2));
        // Object.defineProperty(require('os'), 'cpus', { value: () => [,], configurable: true });
      } else {
        Object.defineProperty(navigator, 'hardwareConcurrency', { value: 1, configurable: true });
      }
      try {
        const encrypted = await openpgp.encrypt({
          message: await openpgp.createMessage({ binary: data }),
          passwords: ['test']
        });
        expect(stream.isStream(encrypted)).to.equal(expectedType);
        const message = await openpgp.readMessage({ armoredMessage: encrypted });
        const decrypted = await openpgp.decrypt({
          passwords: ['test'],
          message,
          format: 'binary'
        });
        expect(stream.isStream(decrypted.data)).to.equal(expectedType);
        const reader = stream.getReader(decrypted.data);
        expect(await reader.readBytes(1024)).to.deep.equal(plaintext[0]);
        dataArrived();
        await new Promise(resolve => { setTimeout(resolve, 3000); });
        expect(i).to.be.lessThan(expectedType === 'web' ? 50 : 300);
      } finally {
        if (detectNode()) {
          coresStub.restore();
        } else {
          delete navigator.hardwareConcurrency;
        }
      }
    });

    it('Input stream should be canceled when canceling decrypted stream (AEAD)', async function() {
      const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ binary: data }),
        passwords: ['test']
      });

      const message = await openpgp.readMessage({ armoredMessage: encrypted });
      const decrypted = await openpgp.decrypt({
        passwords: ['test'],
        message,
        format: 'binary'
      });
      expect(stream.isStream(decrypted.data)).to.equal(expectedType);
      const reader = stream.getReader(decrypted.data);
      expect(await reader.readBytes(1024)).to.deep.equal(plaintext[0]);
      dataArrived();
      reader.releaseLock();
      await stream.cancel(decrypted.data, new Error('canceled by test'));
      await new Promise(setTimeout);
      expect(canceled).to.be.true;
    });
  });
}

module.exports = () => describe('Streaming', function() {
  let currentTest = 0;

  before(async function() {
    pubKey = await openpgp.readKey({ armoredKey: pub_key });
    privKey = await openpgp.decryptKey({
      privateKey: await openpgp.readKey({ armoredKey: priv_key }),
      passphrase: 'hello world'
    });

    await stream.loadStreamsPonyfill();
  });

  beforeEach(function() {
    const test = ++currentTest;

    const dataArrivedPromise = new Promise(resolve => {
      dataArrived = resolve;
    });
    plaintext = [];
    i = 0;
    canceled = false;
    data = global.ReadableStream ? new global.ReadableStream({
      async pull(controller) {
        await new Promise(setTimeout);
        if (test === currentTest && i < (expectedType === 'web' ? 100 : 500)) {
          i++;
          if (i === 4) await dataArrivedPromise;
          const randomBytes = random.getRandomBytes(1024);
          controller.enqueue(randomBytes);
          plaintext.push(randomBytes);
        } else {
          controller.close();
        }
      },
      cancel() {
        canceled = true;
      }
    }, new ByteLengthQueuingStrategy({
      highWaterMark: 1024
    })) : new NodeReadableStream({
      highWaterMark: 1024,
      async read() {
        while (true) {
          await new Promise(setTimeout);
          if (test === currentTest && i < (expectedType === 'web' ? 100 : 500)) {
            i++;
            if (i === 4) await dataArrivedPromise;
            const randomBytes = random.getRandomBytes(1024);
            plaintext.push(randomBytes);
            if (!this.push(randomBytes)) break;
          } else {
            return this.push(null);
          }
        }
      },
      destroy() {
        canceled = true;
      }
    });
    expectedType = global.ReadableStream ? 'web' : 'node';
  });

  tests();

  if (detectNode()) {
    const fs = require('fs');

    it('Node: Encrypt and decrypt text message roundtrip', async function() {
      dataArrived(); // Do not wait until data arrived.
      const plaintext = fs.readFileSync(__filename.replace('streaming.js', 'openpgp.js'), 'utf8'); // eslint-disable-line no-sync
      const data = fs.createReadStream(__filename.replace('streaming.js', 'openpgp.js'), { encoding: 'utf8' });
      const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ text: data }),
        passwords: ['test']
      });
      expect(stream.isStream(encrypted)).to.equal('node');

      const message = await openpgp.readMessage({ armoredMessage: encrypted });
      const decrypted = await openpgp.decrypt({
        passwords: ['test'],
        message
      });
      expect(stream.isStream(decrypted.data)).to.equal('node');
      expect(await stream.readToEnd(decrypted.data)).to.equal(plaintext);
    });

    it('Node: Encrypt and decrypt binary message roundtrip', async function() {
      dataArrived(); // Do not wait until data arrived.
      const plaintext = fs.readFileSync(__filename.replace('streaming.js', 'openpgp.js')); // eslint-disable-line no-sync
      const data = fs.createReadStream(__filename.replace('streaming.js', 'openpgp.js'));
      const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ binary: data }),
        passwords: ['test'],
        format: 'binary'
      });
      expect(stream.isStream(encrypted)).to.equal('node');

      const message = await openpgp.readMessage({ binaryMessage: encrypted });
      const decrypted = await openpgp.decrypt({
        passwords: ['test'],
        message,
        format: 'binary'
      });
      expect(stream.isStream(decrypted.data)).to.equal('node');
      expect(await stream.readToEnd(decrypted.data)).to.deep.equal(plaintext);
    });
  }
});
