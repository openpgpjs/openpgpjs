module.exports = function(grunt) {

  var version = grunt.option('release');
  var fs = require('fs');
  var browser_capabilities;

  if (process.env.SELENIUM_BROWSER_CAPABILITIES !== undefined) {
    browser_capabilities = JSON.parse(process.env.SELENIUM_BROWSER_CAPABILITIES);
  }

  var getSauceKey = function getSaucekey () {
    return '60ffb656-2346-4b77-81f3-bc435ff4c103';
  };

  // Project configuration.
  const dev = !!grunt.option('dev');
  const compat = !!grunt.option('compat');
  const lightweight = !!grunt.option('lightweight');
  const plugins = compat ? [
    "transform-async-to-generator",
    "syntax-async-functions",
    "transform-regenerator",
    "transform-runtime"
  ] : [];
  const presets = [[require.resolve('babel-preset-env'), {
    targets: {
      browsers: compat ? [
        'IE >= 11',
        'Safari >= 9',
        'Last 2 Chrome versions',
        'Last 2 Firefox versions',
        'Last 2 Edge versions'
      ] : [
        'Last 2 Chrome versions',
        'Last 2 Firefox versions',
        'Last 2 Safari versions',
        'Last 2 Edge versions'
      ]
    }
  }]];
  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),
    browserify: {
      openpgp: {
        files: {
          'dist/openpgp.js': ['./src/index.js']
        },
        options: {
          browserifyOptions: {
            fullPaths: dev,
            debug: dev,
            standalone: 'openpgp'
          },
          cacheFile: 'browserify-cache' + (compat ? '-compat' : '') + '.json',
          // Don't bundle these packages with openpgp.js
          external: ['crypto', 'zlib', 'node-localstorage', 'node-fetch', 'asn1.js', 'stream', 'buffer'].concat(
            compat ? [] : [
              'whatwg-fetch',
              'core-js/fn/array/fill',
              'core-js/fn/array/find',
              'core-js/fn/array/includes',
              'core-js/fn/array/from',
              'core-js/fn/promise',
              'core-js/fn/typed/uint8-array',
              'core-js/fn/string/repeat',
              'core-js/fn/symbol',
              'core-js/fn/object/assign',
            ],
            lightweight ? [
              'elliptic'
            ] : []
          ),
          transform: [
            ["babelify", {
              global: true,
              // Only babelify web-streams-polyfill, web-stream-tools, asmcrypto, email-addresses and seek-bzip in node_modules
              only: /^(?:.*\/node_modules\/@mattiasbuelens\/web-streams-polyfill\/|.*\/node_modules\/web-stream-tools\/|.*\/node_modules\/asmcrypto\.js\/|.*\/node_modules\/email-addresses\/|.*\/node_modules\/seek-bzip\/|(?!.*\/node_modules\/)).*$/,
              ignore: ['*.min.js'],
              plugins,
              presets
            }]
          ],
          plugin: ['browserify-derequire']
        }
      },
      worker: {
        files: {
          'dist/openpgp.worker.js': ['./src/worker/worker.js']
        },
        options: {
          cacheFile: 'browserify-cache-worker.json'
        }
      },
      unittests: {
        files: {
          'test/lib/unittests-bundle.js': ['./test/unittests.js']
        },
        options: {
          cacheFile: 'browserify-cache-unittests.json',
          external: ['buffer', 'openpgp', '../../dist/openpgp', '../../../dist/openpgp'],
          transform: [
            ["babelify", {
              global: true,
              // Only babelify chai-as-promised in node_modules
              only: /^(?:.*\/node_modules\/chai-as-promised\/|(?!.*\/node_modules\/)).*$/,
              ignore: ['*.min.js'],
              plugins,
              presets
            }]
          ]
        }
      }
    },
    replace: {
      openpgp: {
        src: ['dist/openpgp.js'],
        dest: ['dist/openpgp.js'],
        replacements: [{
          from: /OpenPGP.js VERSION/g,
          to: 'OpenPGP.js v<%= pkg.version %>'
        }]
      },
      openpgp_min: {
        src: ['dist/openpgp.min.js'],
        dest: ['dist/openpgp.min.js'],
        replacements: [{
          from: "openpgp.worker.js",
          to: "openpgp.worker.min.js"
        }]
      },
      worker_min: {
        src: ['dist/openpgp.worker.min.js'],
        dest: ['dist/openpgp.worker.min.js'],
        replacements: [{
          from: "openpgp.js",
          to: "openpgp.min.js"
        }]
      },
      lightweight_build: {
        src: [
          'dist/openpgp.js',
          'dist/openpgp.js'
        ],
        overwrite: true,
        replacements: lightweight ? [
          {
            from: "USE_INDUTNY_ELLIPTIC = true",
            to: "USE_INDUTNY_ELLIPTIC = false"
          }
        ] : []
      },
      full_build: {
        src: [
          'dist/openpgp.js',
          'dist/openpgp.js'
        ],
        overwrite: true,
        replacements: [
          {
            from: "USE_INDUTNY_ELLIPTIC = false",
            to: "USE_INDUTNY_ELLIPTIC = true"
          }
        ]
      }
    },
    terser: {
      openpgp: {
        files: {
          'dist/openpgp.min.js' : ['dist/openpgp.js'],
          'dist/openpgp.worker.min.js' : ['dist/openpgp.worker.js']
        },
        options: {
          safari10: true
        },
      }
    },
    header: {
      openpgp: {
        options: {
            text: '/*! OpenPGP.js v<%= pkg.version %> - ' +
                '<%= grunt.template.today("yyyy-mm-dd") %> - ' +
                'this is LGPL licensed code, see LICENSE/our website <%= pkg.homepage %> for more information. */'
        },
        files: {
          'dist/openpgp.min.js': 'dist/openpgp.min.js',
          'dist/openpgp.worker.min.js': 'dist/openpgp.worker.min.js'
        }
      }
    },
    jsbeautifier: {
      files: ['src/**/*.js'],
      options: {
        indent_size: 2,
        preserve_newlines: true,
        keep_array_indentation: false,
        keep_function_indentation: false,
        wrap_line_length: 120
      }
    },
    eslint: {
      target: ['src/**/*.js'],
      options: { configFile: '.eslintrc.js' }
    },
    jsdoc: {
      dist: {
        src: ['README.md', 'src'],
        options: {
          configure: '.jsdocrc.js',
          destination: 'doc',
          recurse: true
        }
      }
    },
    mocha_istanbul: {
      coverage: {
        src: 'test',
        options: {
          root: '.',
          timeout: 240000
        }
      }
    },
    mochaTest: {
      unittests: {
        options: {
          reporter: 'spec',
          timeout: 120000,
          grep: lightweight ? 'lightweight' : undefined
        },
        src: ['test/unittests.js']
      }
    },
    copy: {
      browsertest: {
        expand: true,
        flatten: true,
        cwd: 'node_modules/',
        src: ['mocha/mocha.css', 'mocha/mocha.js'],
        dest: 'test/lib/'
      },
      openpgp_compat: {
        expand: true,
        cwd: 'dist/',
        src: ['*.js'],
        dest: 'dist/compat/'
      },
      openpgp_lightweight: {
        expand: true,
        cwd: 'dist/',
        src: ['*.js'],
        dest: 'dist/lightweight/'
      }
    },
    clean: ['dist/'],
    connect: {
      dev: {
        options: {
          port: 3001,
          base: '.',
          keepalive: true
        }
      },
      test: {
        options: {
          port: 3000,
          base: '.'
        }
      }
    },
    'saucelabs-mocha': {
      all: {
        options: {
          username: 'openpgpjs',
          key: getSauceKey,
          urls: lightweight ? [
            'http://localhost:3000/test/unittests.html?saucelabs=true&grep=' + encodeURIComponent('@lightweight')
          ] : [
            'http://localhost:3000/test/unittests.html?saucelabs=true&grep=' + encodeURIComponent('Sauce Labs Group 1'),
            'http://localhost:3000/test/unittests.html?saucelabs=true&grep=' + encodeURIComponent('Sauce Labs Group 2'),
            'http://localhost:3000/test/unittests.html?saucelabs=true&grep=' + encodeURIComponent('^(?!.*Sauce Labs Group [1-2])')
          ],
          build: process.env.TRAVIS_BUILD_ID,
          testname: 'Sauce Unit Test for openpgpjs',
          browsers: [browser_capabilities],
          public: "public",
          maxRetries: 3,
          throttled: 3,
          pollInterval: 10000,
          sauceConfig: {maxDuration: 1800, commandTimeout: 600, idleTimeout: 1000},
          statusCheckAttempts: 200
        }
      }
    },
    watch: {
      src: {
        files: ['src/**/*.js'],
        tasks: ['browserify:openpgp', 'browserify:worker']
      },
      test: {
        files: ['test/*.js', 'test/crypto/**/*.js', 'test/general/**/*.js', 'test/worker/**/*.js'],
        tasks: ['browserify:unittests']
      }
    }
  });

  // Load the plugin(s)
  grunt.loadNpmTasks('grunt-browserify');
  grunt.loadNpmTasks('grunt-terser');
  grunt.loadNpmTasks('grunt-header');
  grunt.loadNpmTasks('grunt-text-replace');
  grunt.loadNpmTasks('grunt-jsbeautifier');
  grunt.loadNpmTasks('grunt-jsdoc');
  grunt.loadNpmTasks('gruntify-eslint');
  grunt.loadNpmTasks('grunt-mocha-istanbul');
  grunt.loadNpmTasks('grunt-mocha-test');
  grunt.loadNpmTasks('grunt-contrib-copy');
  grunt.loadNpmTasks('grunt-contrib-clean');
  grunt.loadNpmTasks('grunt-contrib-connect');
  grunt.loadNpmTasks('grunt-saucelabs');
  grunt.loadNpmTasks('grunt-contrib-watch');

  grunt.registerTask('set_version', function() {
    if (!version) {
      throw new Error('You must specify the version: "--release=1.0.0"');
    }

    patchFile({
      fileName: 'package.json',
      version: version
    });

    patchFile({
      fileName: 'npm-shrinkwrap.json',
      version: version
    });

    patchFile({
      fileName: 'bower.json',
      version: version
    });
  });

  function patchFile(options) {
    var path = './' + options.fileName,
      file = require(path);

    if (options.version) {
      file.version = options.version;
    }

    fs.writeFileSync(path, JSON.stringify(file, null, 2) + '\n');
  }

  // Build tasks
  grunt.registerTask('version', ['replace:openpgp']);
  grunt.registerTask('replace_min', ['replace:openpgp_min', 'replace:worker_min']);
  grunt.registerTask('build', ['browserify:openpgp', 'browserify:worker', 'replace:lightweight_build', 'version', 'terser', 'header', 'replace_min']);
  grunt.registerTask('documentation', ['jsdoc']);
  grunt.registerTask('default', ['build']);
  // Test/Dev tasks
  grunt.registerTask('test', ['eslint', 'mochaTest']);
  grunt.registerTask('coverage', ['mocha_istanbul:coverage']);
  grunt.registerTask('saucelabs', ['build', 'browserify:unittests', 'copy:browsertest', 'connect:test', 'saucelabs-mocha']);
  grunt.registerTask('browsertest', ['build', 'browserify:unittests', 'copy:browsertest', 'connect:test', 'watch']);

};
