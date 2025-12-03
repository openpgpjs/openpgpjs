export default {
  nodeResolve: true, // to resolve npm module imports in `unittests.html`
  files: './test/unittests.html',
  protocol: 'http:',
  hostname: '127.0.0.1',
  testsStartTimeout: 45000,
  browserStartTimeout: 120000,
  testsFinishTimeout: 600000,
  concurrentBrowsers: 3,
  concurrency: 1, // see https://github.com/modernweb-dev/web/issues/2706
  coverage: false,
  groups: []
};
