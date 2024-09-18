import { browserstackLauncher } from '@web/test-runner-browserstack';

const sharedBrowserstackCapabilities = {
  'browserstack.user': process.env.BROWSERSTACK_USERNAME,
  'browserstack.key': process.env.BROWSERSTACK_ACCESS_KEY,

  project: `openpgpjs/${process.env.GITHUB_EVENT_NAME || 'push'}${process.env.LIGHTWEIGHT ? '/lightweight' : ''}`,
  name: process.env.GITHUB_WORKFLOW,
  build: process.env.GITHUB_SHA,
  timeout: 450
};

export default {
  nodeResolve: true, // to resolve npm module imports in `unittests.html`
  files: './test/unittests.html',

  groups: [
    { name: 'local' }, // group meant to be used with either --browser or --manual options via CLI
    {
      name: 'browserstack',
      browsers: process.env.BROWSERSTACK_USERNAME && [
        browserstackLauncher({
          capabilities: {
            ...sharedBrowserstackCapabilities,
            browserName: 'Safari',
            browser_version: 'latest', // Webkit and Safari can differ in behavior
            os: 'OS X',
            os_version: 'Ventura'
          }
        }),
        browserstackLauncher({
          capabilities: {
            ...sharedBrowserstackCapabilities,
            browserName: 'Safari',
            browser_version: '14', // min supported version
            os: 'OS X',
            os_version: 'Big Sur'
          }
        }),
        browserstackLauncher({
          capabilities: {
            ...sharedBrowserstackCapabilities,
            device: 'iPhone 12',
            real_mobile: true,
            os: 'ios',
            os_version: '14'
          }
        })
      ]
    }
  ]
};
