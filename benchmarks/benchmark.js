const Benchmark = require('benchmark');
const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../');

const wrapAsync = func => ({
  fn: async deferred => {
    await func();
    deferred.resolve();
  },
  defer: true
});

function runBenchmarks() {
  const suite = new Benchmark.Suite();

  suite.add('some test case', wrapAsync(async () => {
    await openpgp.generateKey({ userIDs: { email: 'test@test.it' } });
    await openpgp.generateKey({ userIDs: { email: 'test@test.it' } });
  }));

  suite.on('cycle', event => {
    // Output benchmark result by converting benchmark result to string
    console.log(String(event.target));
  }).run({ 'async': true });
}

runBenchmarks();
