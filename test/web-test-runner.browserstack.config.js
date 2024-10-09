import { browserstackLauncher } from '@web/test-runner-browserstack';
import wtrConfig from './web-test-runner.config.js';

const sharedBrowserstackCapabilities = {
  'browserstack.user': process.env.BROWSERSTACK_USERNAME,
  'browserstack.key': process.env.BROWSERSTACK_ACCESS_KEY,

  project: `openpgpjs/${process.env.GITHUB_EVENT_NAME || 'push'}${process.env.LIGHTWEIGHT ? '/lightweight' : ''}`,
  name: process.env.GITHUB_WORKFLOW || 'local',
  build: process.env.GITHUB_SHA || 'local',
  'browserstack.acceptInsecureCerts': true
};

export default {
  ...wtrConfig,
  protocol: 'https:',
  http2: true,
  sslKey: './127.0.0.1-key.pem',
  sslCert: './127.0.0.1.pem',
  testsStartTimeout: 45000,
  browserStartTimeout: 120000,
  testsFinishTimeout: 450000,
  concurrentBrowsers: 3,
  concurrency: 1, // see https://github.com/modernweb-dev/web/issues/2706
  coverage: false,
  groups: [], // overwrite the field coming from `wrtConfig`
  browsers: [
    browserstackLauncher({
      capabilities: {
        ...sharedBrowserstackCapabilities,
        browserName: 'Safari iOS 14',
        device: 'iPhone 12',
        real_mobile: true,
        os: 'ios',
        os_version: '14' // min supported version (iOS/Safari < 14 does not support native BigInts)
      }
    }),
    browserstackLauncher({
      capabilities: {
        ...sharedBrowserstackCapabilities,
        browserName: 'Safari iOS latest',
        device: 'iPhone 16',
        real_mobile: true,
        os: 'ios',
        os_version: 'latest'
      }
    })
  ]
};
