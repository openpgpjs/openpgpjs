/* eslint-disable no-process-env */

module.exports = function(config) {
  config.set({

    // base path that will be used to resolve all patterns (eg. files, exclude)
    basePath: '..',

    // hostname for local
    hostname: 'localhost',

    // frameworks to use
    // available frameworks: https://npmjs.org/browse/keyword/karma-adapter
    frameworks: ['mocha'],

    // plugins
    plugins: ['karma-mocha', 'karma-mocha-reporter', 'karma-browserstack-launcher'],

    client: {
      mocha: {
        reporter: 'html',
        ui: 'bdd',
        timeout: 10000,
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
      accessKey: process.env.BROWSERSTACK_KEY,
      build: process.env.GITHUB_SHA,
      name: process.env.GITHUB_WORKFLOW,
      project: `openpgpjs/${process.env.GITHUB_EVENT_NAME || 'push'}${process.env.LIGHTWEIGHT ? '/lightweight' : ''}`
    },

    // define browsers
    customLaunchers: {
      bs_firefox_68: {
        base: 'BrowserStack',
        browser: 'Firefox',
        browser_version: '68.0',
        os: 'OS X',
        os_version: 'High Sierra'
      },
      bs_chrome_68: {
        base: 'BrowserStack',
        browser: 'Chrome',
        browser_version: '68.0',
        os: 'OS X',
        os_version: 'High Sierra'
      },
      bs_safari_11_1: {
        base: 'BrowserStack',
        browser: 'Safari',
        browser_version: '11.1',
        os: 'OS X',
        os_version: 'High Sierra'
      },
      bs_ios_12: {
        base: 'BrowserStack',
        device: 'iPhone 8 Plus',
        real_mobile: true,
        os: 'ios',
        os_version: '12'
      }
    },

    captureTimeout: 6e5,
    browserDisconnectTolerance: 0,
    browserDisconnectTimeout: 6e5,
    browserSocketTimeout: 3e5,
    browserNoActivityTimeout: 6e5,

    // start these browsers
    // available browser launchers: https://npmjs.org/browse/keyword/karma-launcher
    browsers: [
      'bs_firefox_68',
      'bs_chrome_68',
      'bs_safari_11_1',
      'bs_ios_12'
    ],

    // Continuous Integration mode
    // if true, Karma captures browsers, runs the tests and exits
    singleRun: true

  });
};
