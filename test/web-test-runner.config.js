import { playwrightLauncher } from '@web/test-runner-playwright';

const sharedPlaywrightCIOptions = {
  // createBrowserContext: ({ browser }) => browser.newContext({ ignoreHTTPSErrors: true }),
  headless: true
};

export default {
  nodeResolve: true, // to resolve npm module imports in `unittests.html`
  files: './test/unittests.html',
  protocol: 'http:',
  hostname: '127.0.0.1',
  testsStartTimeout: 45000,
  browserStartTimeout: 120000,
  testsFinishTimeout: 450000,
  concurrentBrowsers: 3,
  concurrency: 1, // see https://github.com/modernweb-dev/web/issues/2706
  coverage: false,
  groups: [
    { name: 'local' }, // group meant to be used with either --browser or --manual options via CLI
    {
      name: 'headless:ci',
      browsers: [
        playwrightLauncher({
          ...sharedPlaywrightCIOptions,
          product: 'chromium'
        }),
        playwrightLauncher({
          ...sharedPlaywrightCIOptions,
          product: 'firefox'
        })
      ]
    }
  ]
};
