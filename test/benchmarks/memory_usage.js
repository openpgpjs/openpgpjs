/* eslint-disable no-console */
const stream = require('@openpgp/web-stream-tools');
const openpgp = require('../..');

const onError = err => {
  console.error('The memory benchmark tests failed by throwing the following error:');
  console.error(err);
  // eslint-disable-next-line no-process-exit
  process.exit(1);
};


/**
 * Benchmark max memory usage recorded during execution of the given function
 * @param {Funtion} function to benchmark (can be async)
 * @returns {NodeJS.MemoryUsage} memory usage snapshot with max recorded usedHeap + arrayBuffers (sizes in bytes)
 */
const benchmark = (() => {
  let maxMemoryComsumption;
  let activeSampling = false;

  function sampleOnce() {
    const memUsage = process.memoryUsage();
    // We don't look at the RSS because it includes some `external` memory which cannot be released by forcing the GC:
    // https://nodejs.org/api/process.html#process_process_memoryusage
    if (memUsage.arrayBuffers + memUsage.heapUsed > maxMemoryComsumption.arrayBuffers + memUsage.heapUsed) {
      maxMemoryComsumption = memUsage;
    }
  }

  function samplePeriodically() {
    setImmediate(() => {
      sampleOnce();
      activeSampling && samplePeriodically();
    });
  }

  return async function(fn) {
    if (activeSampling) {
      throw new Error('Concurrent memory benchmarks are not supported');
    }
    maxMemoryComsumption = { heapUsed: 0, arrayBuffers: 0 };
    activeSampling = true;
    // force garbage colleciton to clean-up data from previous tests
    global.gc();
    samplePeriodically();
    await fn();
    // setImmediate is run at the end of the event loop, so we need to manually collect the latest sample
    sampleOnce();
    activeSampling = false;
    return maxMemoryComsumption;
  };
})();

class MemoryBenchamrkSuite {
  constructor() {
    this.tests = [];
  }

  add(name, fn) {
    this.tests.push({ name, fn });
  }

  async run() {
    const stats = []; // the size of this data is negligible compared to the tests
    for (const { name, fn } of this.tests) {
      const memoryUsage = await benchmark(fn).catch(onError);
      // Convert values to MB
      const heapUsed = memoryUsage.heapUsed / 1024 / 1024;
      const arrayBuffers = memoryUsage.arrayBuffers / 1024 / 1024;

      // raw entry format accepted by github-action-pull-request-benchmark
      stats.push({
        name,
        value: (heapUsed + arrayBuffers).toFixed(2),
        range: `heap: ${heapUsed.toFixed(2)}, buffers: ${arrayBuffers.toFixed(2)}`,
        unit: 'MB',
        biggerIsBetter: false
      });
    }
    return stats;
  }
}

/**
 * Memory usage tests.
 * These are run sequentially, and the garbage collector is run in-between.
 */
(async () => {
  const suite = new MemoryBenchamrkSuite();

  suite.add('empty test (initial baseline)', () => {});

  suite.add('openpgp.encrypt/decrypt (CFB, binary)', async () => {
    const passwords = 'password';
    const config = { aeadProtect: false, preferredCompressionAlgorithm: openpgp.enums.compression.uncompressed };
    const plaintextMessage = await openpgp.createMessage({ binary: new Uint8Array(1000000).fill(1) });

    const armoredEncryptedMessage = await openpgp.encrypt({ message: plaintextMessage, passwords, config });
    await openpgp.decrypt({ message: await openpgp.readMessage({ armoredMessage: armoredEncryptedMessage }), passwords, config });
  });

  suite.add('openpgp.encrypt/decrypt (CFB, text)', async () => {
    const passwords = 'password';
    const config = { aeadProtect: false, preferredCompressionAlgorithm: openpgp.enums.compression.uncompressed };
    const plaintextMessage = await openpgp.createMessage({ text: 'a'.repeat(100000) });

    const armoredEncryptedMessage = await openpgp.encrypt({ message: plaintextMessage, passwords, config });
    await openpgp.decrypt({ message: await openpgp.readMessage({ armoredMessage: armoredEncryptedMessage }), passwords, config });
  });

  suite.add('openpgp.encrypt/decrypt (AEAD, binary)', async () => {
    const passwords = 'password';
    const config = { aeadProtect: true, preferredCompressionAlgorithm: openpgp.enums.compression.uncompressed };
    const plaintextMessage = await openpgp.createMessage({ binary: new Uint8Array(1000000).fill(1) });

    const armoredEncryptedMessage = await openpgp.encrypt({ message: plaintextMessage, passwords, config });
    await openpgp.decrypt({ message: await openpgp.readMessage({ armoredMessage: armoredEncryptedMessage }), passwords, config });
  });

  suite.add('empty test (final baseline)', () => {});


  // suite.add('openpgp.encrypt/decrypt (AEAD)', async () => {

  // });

  // suite.add('openpgp.encrypt/decrypt (CFB, streaming)', async () => {

  // });


  // suite.add('openpgp.encrypt/decrypt (AEAD, streaming)', async () => {

  // });

  const stats = await suite.run();
  // Print JSON stats to stdout
  console.log(JSON.stringify(stats, null, 4));

})();

// async function getTestData() {
//   const armoredKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

// xVgEYS4KIRYJKwYBBAHaRw8BAQdAOl5Ij0p8llEOLqalwRM8+YWKXELm+Zl1
// arT2orL/42MAAP9SQBdl+A/i4AtIOr33rn6OKzmXQ2EQH0xoSPJcVxX7BA5U
// zRR0ZXN0IDx0ZXN0QHRlc3QuY29tPsKMBBAWCgAdBQJhLgohBAsJBwgDFQgK
// BBYAAgECGQECGwMCHgEAIQkQ2RFo4G/cGHQWIQRL9hTrZduw8+42e1rZEWjg
// b9wYdEi3AP91NftBKXLfcMRz/g540cQ/0+ax8pvsiqFSb+Sqz87YPwEAkoYK
// 8I9rVAlVABIhy/g7ZStHu/u0zsPbiquZFKoVLgPHXQRhLgohEgorBgEEAZdV
// AQUBAQdAqY5VZYX6axscpfVN3EED83T3WO3+Hzxfq31dXJXKrRkDAQgHAAD/
// an6zziN/Aw0ruIxuZTjmkYriDW34hys8F2nRR23PO6gPjsJ4BBgWCAAJBQJh
// LgohAhsMACEJENkRaOBv3Bh0FiEES/YU62XbsPPuNnta2RFo4G/cGHQjlgEA
// gbOEmauiq2avut4e7pSJ98t50zai2dzNies1OpqTU58BAM1pWI99FxM6thX9
// aDa+Qhz0AxhA9P+3eQCXYTZR7CEE
// =LPl8
// -----END PGP PRIVATE KEY BLOCK-----`;

//   const privateKey = await openpgp.readKey({ armoredKey });
//   const publicKey = privateKey.toPublic();
//   const plaintextMessage = await openpgp.createMessage({ text: 'plaintext' });
//   const armoredEncryptedMessage = await openpgp.encrypt({ message: plaintextMessage, encryptionKeys: publicKey });
//   const armoredSignedMessage = await openpgp.sign({ message: await openpgp.createMessage({ text: 'plaintext' }), signingKeys: privateKey });

//   return {
//     armoredKey,
//     privateKey,
//     publicKey,
//     armoredEncryptedMessage,
//     armoredSignedMessage
//   };
// }

