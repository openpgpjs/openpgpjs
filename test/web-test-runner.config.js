import { playwrightLauncher } from '@web/test-runner-playwright';

const sharedPlaywrightCIOptions = {
  // createBrowserContext: ({ browser }) => browser.newContext({ ignoreHTTPSErrors: true }),
  headless: true
};

const getCommonBrowsers = ({ firefoxBeta = false }) => [
  playwrightLauncher({
    ...sharedPlaywrightCIOptions,
    product: 'chromium'
  }),
  playwrightLauncher({
    ...sharedPlaywrightCIOptions,
    product: 'firefox',
    launchOptions: firefoxBeta ? { channel: 'firefox-beta' } : {}
  })
];

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
  groups: [
    { name: 'local' }, // group meant to be used with either --browser or --manual options via CLI
    {
      name: 'headless',
      browsers: [
        ...getCommonBrowsers({ firefoxBeta: false }),
        playwrightLauncher({
          ...sharedPlaywrightCIOptions,
          product: 'webkit'
        })
      ]
    },
    {
      name: 'headless:ci',
      browsers: [
        ...getCommonBrowsers({ firefoxBeta: true }),
        playwrightLauncher({
          ...sharedPlaywrightCIOptions,
          product: 'webkit'
        })
      ]
    },
    {
      // WebKit is skipped on Windows (see .github/workflows/tests.yml)
      name: 'headless:ci:no-webkit',
      browsers: getCommonBrowsers({ firefoxBeta: true })
    }
  ]
};
