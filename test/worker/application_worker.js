/* globals tryTests: true */

const chai = require('chai');

const { expect } = chai;

tryTests('Application Worker', tests, {
  if: typeof window !== 'undefined' && window.Worker && window.MessageChannel
});

function tests() {

  it('Should support loading OpenPGP.js from inside a Web Worker', async function() {
    if (/Edge/.test(navigator.userAgent)) {
      this.skip(); // Old Edge doesn't support crypto.getRandomValues inside a Worker.
    }
    try {
      eval('(async function() {})');
    } catch (e) {
      console.error(e);
      this.skip();
    }
    const worker = new Worker('./worker/worker_example.js');
    async function delegate(action, message) {
      return new Promise((resolve, reject) => {
        const channel = new MessageChannel();
        channel.port1.onmessage = function({ data }) {
          if (data.error !== undefined) {
            reject(new Error(data.error));
          } else {
            resolve(data.result);
          }
        };
        worker.postMessage({ action, message }, [channel.port2]);
      });
    }
    const encrypted = await delegate('encrypt', 'Hello World!');
    const decrypted = await delegate('decrypt', encrypted);
    expect(decrypted).to.equal('Hello World!');
    worker.terminate();
  });

}
