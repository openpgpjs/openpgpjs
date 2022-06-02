/* eslint-disable no-console */
const assert = require('assert');
const path = require('path');
const { writeFileSync, unlinkSync } = require('fs');
const { fork } = require('child_process');
const openpgp = require('../..');

/**
 * Benchmark max memory usage recorded during execution of the given function.
 * This spawns a new v8 instance and runs the code there in isolation, to avoid interference between tests.
 * @param {Funtion} function to benchmark (can be async)
 * @returns {NodeJS.MemoryUsage} memory usage snapshot with max RSS (sizes in bytes)
 */
const benchmark = async function(fn) {
  const tmpFileName = path.join(__dirname, 'tmp.js');
  // the code to execute must be written to a file
  writeFileSync(tmpFileName, `
const assert = require('assert');
const openpgp = require('../..');
let maxMemoryComsumption;
let activeSampling = false;

function sampleOnce() {
  const memUsage = process.memoryUsage();
  if (!maxMemoryComsumption || memUsage.rss > maxMemoryComsumption.rss) {
    maxMemoryComsumption = memUsage;
  }
}

function samplePeriodically() {
  setImmediate(() => {
    sampleOnce();
    activeSampling && samplePeriodically();
  });
}

// main body
(async () => {
  maxMemoryComsumption = null;
  activeSampling = true;
  samplePeriodically();
  await (${fn.toString()})();
  // setImmediate is run at the end of the event loop, so we need to manually collect the latest sample
  sampleOnce();
  process.send(maxMemoryComsumption);
  process.exit(); // child process doesn't exit otherwise
})();
`);

  const maxMemoryComsumption = await new Promise((resolve, reject) => {
    const child = fork(tmpFileName);
    child.on('message', function (message) {
      resolve(message);
    });
    child.on('error', function (err) {
      reject(err);
    });
  });

  unlinkSync(tmpFileName);
  return maxMemoryComsumption;
};

const onError = err => {
  console.error('The memory benchmark tests failed by throwing the following error:');
  console.error(err);
  // eslint-disable-next-line no-process-exit
  process.exit(1);
};

class MemoryBenchamrkSuite {
  constructor() {
    this.tests = [];
  }

  add(name, fn) {
    this.tests.push({ name, fn });
  }

  async run() {
    const stats = [];
    for (const { name, fn } of this.tests) {
      const memoryUsage = await benchmark(fn).catch(onError);
      // convert values to MB
      Object.entries(memoryUsage).forEach(([name, value]) => {
        memoryUsage[name] = (value / 1024 / 1024).toFixed(2);
      });
      const { rss, ...usageDetails } = memoryUsage;
      // raw entry format accepted by github-action-pull-request-benchmark
      stats.push({
        name,
        value: rss,
        range: Object.entries(usageDetails).map(([name, value]) => `${name}: ${value}`).join(', '),
        unit: 'MB',
        biggerIsBetter: false
      });
    }
    return stats;
  }
}

/**
 * Memory usage tests.
 * All the necessary variables must be declared inside the test function.
 */
(async () => {
  const suite = new MemoryBenchamrkSuite();

  suite.add('empty test (baseline)', () => {});

  suite.add('openpgp.encrypt/decrypt (CFB, binary)', async () => {
    const ONE_MEGABYTE = 1000000;
    const passwords = 'password';
    const config = { aeadProtect: false, preferredCompressionAlgorithm: openpgp.enums.compression.uncompressed };
    const plaintextMessage = await openpgp.createMessage({ binary: new Uint8Array(ONE_MEGABYTE) });

    const armoredEncryptedMessage = await openpgp.encrypt({ message: plaintextMessage, passwords, config });
    const encryptedMessage = await openpgp.readMessage({ armoredMessage: armoredEncryptedMessage });
    assert.ok(encryptedMessage.packets[1] instanceof openpgp.SymEncryptedIntegrityProtectedDataPacket);
    await openpgp.decrypt({ message: encryptedMessage, passwords, config });
  });

  suite.add('openpgp.encrypt/decrypt (CFB, text)', async () => {
    const ONE_MEGABYTE = 1000000;
    const passwords = 'password';
    const config = { aeadProtect: false, preferredCompressionAlgorithm: openpgp.enums.compression.uncompressed };
    const plaintextMessage = await openpgp.createMessage({ text: 'a'.repeat(ONE_MEGABYTE / 2) }); // two bytes per character

    const armoredEncryptedMessage = await openpgp.encrypt({ message: plaintextMessage, passwords, config });
    const encryptedMessage = await openpgp.readMessage({ armoredMessage: armoredEncryptedMessage });
    assert.ok(encryptedMessage.packets[1] instanceof openpgp.SymEncryptedIntegrityProtectedDataPacket);
    await openpgp.decrypt({ message: encryptedMessage, passwords, config });
  });

  suite.add('openpgp.encrypt/decrypt (AEAD, binary)', async () => {
    const ONE_MEGABYTE = 1000000;
    const passwords = 'password';
    const config = { aeadProtect: true, preferredCompressionAlgorithm: openpgp.enums.compression.uncompressed };
    const plaintextMessage = await openpgp.createMessage({ binary: new Uint8Array(ONE_MEGABYTE) });

    const armoredEncryptedMessage = await openpgp.encrypt({ message: plaintextMessage, passwords, config });
    const encryptedMessage = await openpgp.readMessage({ armoredMessage: armoredEncryptedMessage });
    assert.ok(encryptedMessage.packets[1] instanceof openpgp.AEADEncryptedDataPacket);
    await openpgp.decrypt({ message: encryptedMessage, passwords, config });
  });

  suite.add('openpgp.encrypt/decrypt (AEAD, text)', async () => {
    const ONE_MEGABYTE = 1000000;
    const passwords = 'password';
    const config = { aeadProtect: true, preferredCompressionAlgorithm: openpgp.enums.compression.uncompressed };
    const plaintextMessage = await openpgp.createMessage({ text: 'a'.repeat(ONE_MEGABYTE / 2) }); // two bytes per character

    const armoredEncryptedMessage = await openpgp.encrypt({ message: plaintextMessage, passwords, config });
    const encryptedMessage = await openpgp.readMessage({ armoredMessage: armoredEncryptedMessage });
    assert.ok(encryptedMessage.packets[1] instanceof openpgp.AEADEncryptedDataPacket);
    await openpgp.decrypt({ message: encryptedMessage, passwords, config });
  });

  // streaming tests
  suite.add('openpgp.encrypt/decrypt (CFB, binary, with streaming)', async () => {
    const ONE_MEGABYTE = 1000000;
    function* largeDataGenerator({ chunk, numberOfChunks }) {
      for (let chunkNumber = 0; chunkNumber < numberOfChunks; chunkNumber++) {
        yield chunk;
      }
    }

    const passwords = 'password';
    const config = { aeadProtect: false, preferredCompressionAlgorithm: openpgp.enums.compression.uncompressed };
    const inputStream = require('stream').Readable.from(largeDataGenerator({ chunk: new Uint8Array(ONE_MEGABYTE), numberOfChunks: 1 }));
    const plaintextMessage = await openpgp.createMessage({ binary: inputStream });
    assert(plaintextMessage.fromStream);

    const armoredEncryptedMessage = await openpgp.encrypt({ message: plaintextMessage, passwords, config });
    const encryptedMessage = await openpgp.readMessage({ armoredMessage: armoredEncryptedMessage });
    assert.ok(encryptedMessage.packets[1] instanceof openpgp.SymEncryptedIntegrityProtectedDataPacket);
    const { data: decryptedData } = await openpgp.decrypt({ message: encryptedMessage, passwords, config });
    // read out output stream to trigger decryption
    await new Promise(resolve => {
      decryptedData.pipe(require('fs').createWriteStream('/dev/null'));
      decryptedData.on('end', resolve);
    });
  });

  suite.add('openpgp.encrypt/decrypt (CFB, text, with streaming)', async () => {
    const ONE_MEGABYTE = 1000000;
    function* largeDataGenerator({ chunk, numberOfChunks }) {
      for (let chunkNumber = 0; chunkNumber < numberOfChunks; chunkNumber++) {
        yield chunk;
      }
    }

    const passwords = 'password';
    const config = { aeadProtect: false, preferredCompressionAlgorithm: openpgp.enums.compression.uncompressed };
    const inputStream = require('stream').Readable.from(largeDataGenerator({ chunk: 'a'.repeat(ONE_MEGABYTE / 2), numberOfChunks: 1 }));
    const plaintextMessage = await openpgp.createMessage({ text: inputStream });
    assert(plaintextMessage.fromStream);

    const armoredEncryptedMessage = await openpgp.encrypt({ message: plaintextMessage, passwords, config });
    const encryptedMessage = await openpgp.readMessage({ armoredMessage: armoredEncryptedMessage });
    assert.ok(encryptedMessage.packets[1] instanceof openpgp.SymEncryptedIntegrityProtectedDataPacket);
    const { data: decryptedData } = await openpgp.decrypt({ message: encryptedMessage, passwords, config });
    // read out output stream to trigger decryption
    await new Promise(resolve => {
      decryptedData.pipe(require('fs').createWriteStream('/dev/null'));
      decryptedData.on('end', resolve);
    });
  });

  suite.add('openpgp.encrypt/decrypt (AEAD, binary, with streaming)', async () => {
    const ONE_MEGABYTE = 1000000;
    function* largeDataGenerator({ chunk, numberOfChunks }) {
      for (let chunkNumber = 0; chunkNumber < numberOfChunks; chunkNumber++) {
        yield chunk;
      }
    }

    const passwords = 'password';
    const config = { aeadProtect: true, preferredCompressionAlgorithm: openpgp.enums.compression.uncompressed };
    const inputStream = require('stream').Readable.from(largeDataGenerator({ chunk: new Uint8Array(ONE_MEGABYTE), numberOfChunks: 1 }));
    const plaintextMessage = await openpgp.createMessage({ binary:inputStream });
    assert(plaintextMessage.fromStream);

    const armoredEncryptedMessage = await openpgp.encrypt({ message: plaintextMessage, passwords, config });
    const encryptedMessage = await openpgp.readMessage({ armoredMessage: armoredEncryptedMessage });
    assert.ok(encryptedMessage.packets[1] instanceof openpgp.AEADEncryptedDataPacket);
    const { data: decryptedData } = await openpgp.decrypt({ message: encryptedMessage, passwords, config });
    // read out output stream to trigger decryption
    await new Promise(resolve => {
      decryptedData.pipe(require('fs').createWriteStream('/dev/null'));
      decryptedData.on('end', resolve);
    });
  });

  suite.add('openpgp.encrypt/decrypt (AEAD, text, with streaming)', async () => {
    const ONE_MEGABYTE = 1000000;
    function* largeDataGenerator({ chunk, numberOfChunks }) {
      for (let chunkNumber = 0; chunkNumber < numberOfChunks; chunkNumber++) {
        yield chunk;
      }
    }

    const passwords = 'password';
    const config = { aeadProtect: true, preferredCompressionAlgorithm: openpgp.enums.compression.uncompressed };
    const inputStream = require('stream').Readable.from(largeDataGenerator({ chunk: 'a'.repeat(ONE_MEGABYTE / 2), numberOfChunks: 1 }));
    const plaintextMessage = await openpgp.createMessage({ text: inputStream });
    assert(plaintextMessage.fromStream);

    const armoredEncryptedMessage = await openpgp.encrypt({ message: plaintextMessage, passwords, config });
    const encryptedMessage = await openpgp.readMessage({ armoredMessage: armoredEncryptedMessage });
    assert.ok(encryptedMessage.packets[1] instanceof openpgp.AEADEncryptedDataPacket);
    const { data: decryptedData } = await openpgp.decrypt({ message: encryptedMessage, passwords, config });
    // read out output stream to trigger decryption
    await new Promise(resolve => {
      decryptedData.pipe(require('fs').createWriteStream('/dev/null'));
      decryptedData.on('end', resolve);
    });
  });

  suite.add('openpgp.encrypt/decrypt (CFB, text @ 10MB, with streaming)', async () => {
    const ONE_MEGABYTE = 1000000;
    function* largeDataGenerator({ chunk, numberOfChunks }) {
      for (let chunkNumber = 0; chunkNumber < numberOfChunks; chunkNumber++) {
        yield chunk;
      }
    }

    const passwords = 'password';
    const config = { aeadProtect: false, preferredCompressionAlgorithm: openpgp.enums.compression.uncompressed };
    const inputStream = require('stream').Readable.from(largeDataGenerator({ chunk: 'a'.repeat(ONE_MEGABYTE / 2), numberOfChunks: 20 }));
    const plaintextMessage = await openpgp.createMessage({ text: inputStream });
    assert(plaintextMessage.fromStream);

    const armoredEncryptedMessage = await openpgp.encrypt({ message: plaintextMessage, passwords, config });
    const encryptedMessage = await openpgp.readMessage({ armoredMessage: armoredEncryptedMessage });
    assert.ok(encryptedMessage.packets[1] instanceof openpgp.SymEncryptedIntegrityProtectedDataPacket);
    const { data: decryptedData } = await openpgp.decrypt({ message: encryptedMessage, passwords, config });
    // read out output stream to trigger decryption
    await new Promise(resolve => {
      decryptedData.pipe(require('fs').createWriteStream('/dev/null'));
      decryptedData.on('end', resolve);
    });
  });

  suite.add('openpgp.encrypt/decrypt (CFB, text @ 10MB, with unauthenticated streaming)', async () => {
    const ONE_MEGABYTE = 1000000;
    function* largeDataGenerator({ chunk, numberOfChunks }) {
      for (let chunkNumber = 0; chunkNumber < numberOfChunks; chunkNumber++) {
        yield chunk;
      }
    }

    const passwords = 'password';
    const config = { aeadProtect: false, preferredCompressionAlgorithm: openpgp.enums.compression.uncompressed };
    const inputStream = require('stream').Readable.from(largeDataGenerator({ chunk: 'a'.repeat(ONE_MEGABYTE / 2), numberOfChunks: 20 }));
    const plaintextMessage = await openpgp.createMessage({ text: inputStream });
    assert(plaintextMessage.fromStream);

    const armoredEncryptedMessage = await openpgp.encrypt({ message: plaintextMessage, passwords, config });
    const encryptedMessage = await openpgp.readMessage({ armoredMessage: armoredEncryptedMessage });
    assert.ok(encryptedMessage.packets[1] instanceof openpgp.SymEncryptedIntegrityProtectedDataPacket);
    const { data: decryptedData } = await openpgp.decrypt({
      message: encryptedMessage,
      passwords,
      config: { ...config, allowUnauthenticatedStream: true }
    });
    // read out output stream to trigger decryption
    await new Promise(resolve => {
      decryptedData.pipe(require('fs').createWriteStream('/dev/null'));
      decryptedData.on('end', resolve);
    });
  });

  suite.add('openpgp.encrypt/decrypt (AEAD, text @ 10MB, with streaming)', async () => {
    const ONE_MEGABYTE = 1000000;
    function* largeDataGenerator({ chunk, numberOfChunks }) {
      for (let chunkNumber = 0; chunkNumber < numberOfChunks; chunkNumber++) {
        yield chunk;
      }
    }

    const passwords = 'password';
    const config = { aeadProtect: true, preferredCompressionAlgorithm: openpgp.enums.compression.uncompressed };
    const inputStream = require('stream').Readable.from(largeDataGenerator({ chunk: 'a'.repeat(ONE_MEGABYTE / 2), numberOfChunks: 20 }));
    const plaintextMessage = await openpgp.createMessage({ text: inputStream });
    assert(plaintextMessage.fromStream);

    const armoredEncryptedMessage = await openpgp.encrypt({ message: plaintextMessage, passwords, config });
    const encryptedMessage = await openpgp.readMessage({ armoredMessage: armoredEncryptedMessage });
    assert.ok(encryptedMessage.packets[1] instanceof openpgp.AEADEncryptedDataPacket);
    const { data: decryptedData } = await openpgp.decrypt({ message: encryptedMessage, passwords, config });
    // read out output stream to trigger decryption
    await new Promise(resolve => {
      decryptedData.pipe(require('fs').createWriteStream('/dev/null'));
      decryptedData.on('end', resolve);
    });
  });

  const stats = await suite.run();
  // Print JSON stats to stdout
  console.log(JSON.stringify(stats, null, 4));
})();
