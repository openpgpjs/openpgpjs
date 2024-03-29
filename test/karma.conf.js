/* eslint-disable no-process-env */
const { chromium, firefox, webkit } = require('playwright');

process.env.CHROME_BIN = chromium.executablePath();
process.env.FIREFOX_BIN = firefox.executablePath();
process.env.WEBKIT_HEADLESS_BIN = webkit.executablePath();

module.exports = function(config) {
  config.set({

    // base path that will be used to resolve all patterns (eg. files, exclude)
    basePath: '..',

    // hostname for local
    hostname: '127.0.0.1',

    // frameworks to use
    // available frameworks: https://npmjs.org/browse/keyword/karma-adapter
    frameworks: ['mocha'],

    // plugins
    plugins: [
      'karma-mocha',
      'karma-chrome-launcher',
      'karma-firefox-launcher',
      'karma-webkit-launcher',
      'karma-mocha-reporter',
      'karma-browserstack-launcher'
    ],

    client: {
      mocha: {
        timeout: 30000,
        grep: process.env.LIGHTWEIGHT ? '@lightweight' : undefined
      }
    },

    // list of files / patterns to load in the browser
    files: [
      {
        pattern: 'test/lib/unittests-bundle.js',
        type: 'module'
      },
      {
        pattern: 'dist/**/*',
        included: false
      },
      {
        pattern: 'test/**/*',
        included: false
      }
    ],

    proxies: {
      '/lib': '/base/test/lib',
      '/worker': '/base/test/worker',
      '/dist': '/base/dist'
    },

    // list of files to exclude
    exclude: [
    ],

    // preprocess matching files before serving them to the browser
    // available preprocessors: https://npmjs.org/browse/keyword/karma-preprocessor
    preprocessors: {
    },

    // test results reporter to use
    // possible values: 'dots', 'progress'
    // available reporters: https://npmjs.org/browse/keyword/karma-reporter
    reporters: ['mocha', 'BrowserStack'],

    // web server host and port
    port: 9876,

    // enable / disable colors in the output (reporters and logs)
    colors: true,

    // level of logging
    // possible values: config.LOG_DISABLE || config.LOG_ERROR || config.LOG_WARN || config.LOG_INFO || config.LOG_DEBUG
    logLevel: config.LOG_INFO,

    // enable / disable watching file and executing tests whenever any file changes
    autoWatch: false,

    browserStack: {
      username: process.env.BROWSERSTACK_USERNAME,
      accessKey: process.env.BROWSERSTACK_ACCESS_KEY,
      build: process.env.GITHUB_SHA,
      name: process.env.GITHUB_WORKFLOW,
      project: `openpgpjs/${process.env.GITHUB_EVENT_NAME || 'push'}${process.env.LIGHTWEIGHT ? '/lightweight' : ''}`,
      timeout: 450
    },

    // define browsers
    customLaunchers: {
      bs_safari_latest: { // Webkit and Safari can differ in behavior
        base: 'BrowserStack',
        browser: 'Safari',
        browser_version: 'latest',
        os: 'OS X',
        os_version: 'Ventura'
      },
      bs_safari_13_1: { // no BigInt support
        base: 'BrowserStack',
        browser: 'Safari',
        browser_version: '13.1',
        os: 'OS X',
        os_version: 'Catalina'
      },
      bs_ios_14: {
        base: 'BrowserStack',
        device: 'iPhone 12',
        real_mobile: true,
        os: 'ios',
        os_version: '14'
      }
    },

    captureTimeout: 6e5,
    browserDisconnectTolerance: 0,
    browserDisconnectTimeout: 6e5,
    browserSocketTimeout: 3e5,
    browserNoActivityTimeout: 6e5,

    // start these browsers
    // available browser launchers: https://npmjs.org/browse/keyword/karma-launcher
    browsers: ['ChromeHeadless', 'FirefoxHeadless', 'WebkitHeadless'],

    // Continuous Integration mode
    // if true, Karma captures browsers, runs the tests and exits
    singleRun: true

  });
};
