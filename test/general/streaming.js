const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../dist/openpgp');

const stub = require('sinon/lib/sinon/stub');
const chai = require('chai');
chai.use(require('chai-as-promised'));

const { expect } = chai;

const { Stream, util } = openpgp;

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
    const msgAsciiArmored = util.Uint8Array_to_str(await encrypted.data.readToEnd());
    const message = openpgp.message.readArmored(msgAsciiArmored);
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
    const msgAsciiArmored = util.Uint8Array_to_str(await encrypted.data.readToEnd());
    const message = openpgp.message.readArmored(msgAsciiArmored);
    const decrypted = await openpgp.decrypt({
      passwords: ['test'],
      message,
      format: 'binary'
    });
    expect(decrypted.data).to.deep.equal(util.concatUint8Array(plaintext));
  });
});
