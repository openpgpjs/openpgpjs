'use strict';

module.exports = function(grunt) {

  var lintFiles = [
    'src/config/*.js',
    'src/crypto/cipher/aes.js',
    'src/crypto/cipher/blowfish.js',
    'src/crypto/cipher/cast5.js',
    'src/crypto/cipher/des.js',
    'src/crypto/cipher/index.js',
    'src/crypto/hash/md5.js',
    'src/crypto/public_key/dsa.js',
    'src/crypto/public_key/elgamal.js',
    'src/crypto/public_key/index.js',
    'src/crypto/public_key/rsa.js',
    'src/crypto/cfb.js',
    'src/crypto/crypto.js',
    'src/crypto/index.js',
    'src/crypto/pkcs1.js',
    'src/crypto/random.js',
    'src/crypto/signature.js',
    'src/encoding/*.js',
    'src/hkp/*.js',
    'src/keyring/*.js',
    'src/packet/all_packets.js',
    'src/packet/compressed.js',
    'src/packet/index.js',
    'src/packet/literal.js',
    'src/packet/marker.js',
    'src/packet/one_pass_signature.js',
    'src/packet/packet.js',
    'src/packet/public_key.js',
    'src/packet/public_key_encrypted_session_key.js',
    'src/packet/public_subkey.js',
    'src/packet/secret_key.js',
    'src/packet/secret_subkey.js',
    'src/packet/sym_encrypted_integrity_protected.js',
    'src/packet/sym_encrypted_session_key.js',
    'src/packet/symmetrically_encrypted.js',
    'src/packet/trust.js',
    'src/packet/user_attribute.js',
    'src/packet/userid.js',
    'src/type/*.js',
    'src/worker/async_proxy.js',
    'src/*.js',
  ]; // add more over time ... goal should be 100% coverage

  var version = grunt.option('release');
  var fs = require('fs');
  var browser_capabilities;

  if (process.env.SELENIUM_BROWSER_CAPABILITIES !== undefined) {
    browser_capabilities = JSON.parse(process.env.SELENIUM_BROWSER_CAPABILITIES);
  }

  // Project configuration.
  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),
    browserify: {
      openpgp: {
        files: {
          'dist/openpgp.js': [ './src/index.js' ]
        },
        options: {
          browserifyOptions: {
            standalone: 'openpgp'
          },
          external: [ 'crypto', 'buffer', 'node-localstorage', 'node-fetch' ]
        }
      },
      openpgp_debug: {
        files: {
          'dist/openpgp_debug.js': [ './src/index.js' ]
        },
        options: {
          browserifyOptions: {
            debug: true,
            standalone: 'openpgp'
          },
          external: [ 'crypto', 'buffer', 'node-localstorage', 'node-fetch' ]
        }
      },
      worker: {
        files: {
          'dist/openpgp.worker.js': [ './src/worker/worker.js' ]
        }
      },
      worker_min: {
        files: {
          'dist/openpgp.worker.min.js': [ './src/worker/worker.js' ]
        }
      },
      unittests: {
        files: {
          'test/lib/unittests-bundle.js': [ './test/unittests.js' ]
        },
        options: {
          external: [ 'crypto', 'buffer' , 'node-localstorage', 'node-fetch', 'openpgp', '../../dist/openpgp', '../../../dist/openpgp' ]
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
      openpgp_debug: {
        src: ['dist/openpgp_debug.js'],
        dest: ['dist/openpgp_debug.js'],
        replacements: [{
          from: /OpenPGP.js VERSION/g,
          to: 'OpenPGP.js v<%= pkg.version %>'
        }]
      },
      worker_min: {
        src: ['dist/openpgp.worker.min.js'],
        dest: ['dist/openpgp.worker.min.js'],
        replacements: [{
          from: "importScripts('openpgp.js')",
          to: "importScripts('openpgp.min.js')"
        }]
      }
    },
    uglify: {
      openpgp: {
        files: {
          'dist/openpgp.min.js' : [ 'dist/openpgp.js' ],
          'dist/openpgp.worker.min.js' : [ 'dist/openpgp.worker.min.js' ]
        }
      },
      options: {
        banner: '/*! OpenPGPjs.org  this is LGPL licensed code, see LICENSE/our website for more information.- v<%= pkg.version %> - ' +
          '<%= grunt.template.today("yyyy-mm-dd") %> */'
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
    jshint: {
      src: lintFiles,
      build: ['Gruntfile.js', '*.json'],
      options: {
        jshintrc: '.jshintrc'
      }
    },
    jscs: {
      src: lintFiles,
      build: ['Gruntfile.js'],
      options: {
        config: ".jscsrc",
        esnext: false, // If you use ES6 http://jscs.info/overview.html#esnext
        verbose: true, // If you need output with rule names http://jscs.info/overview.html#verbose
      }
    },
    jsdoc: {
      dist: {
        src: ['README.md', 'src'],
        options: {
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
          timeout: 240000,
        }
      }
    },
    mochaTest: {
      unittests: {
        options: {
          reporter: 'spec',
          timeout: 120000
        },
        src: [ 'test/unittests.js' ]
      }
    },
    copy: {
      browsertest: {
        expand: true,
        flatten: true,
        cwd: 'node_modules/',
        src: ['mocha/mocha.css', 'mocha/mocha.js', 'chai/chai.js', 'whatwg-fetch/fetch.js'],
        dest: 'test/lib/'
      },
      zlib: {
        expand: true,
        cwd: 'node_modules/zlibjs/bin/',
        src: ['rawdeflate.min.js','rawinflate.min.js','zlib.min.js'],
        dest: 'src/compression/'
      }
    },
    clean: ['dist/'],
    connect: {
      dev: {
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
          key: '60ffb656-2346-4b77-81f3-bc435ff4c103',
          urls: ['http://127.0.0.1:3000/test/unittests.html'],
          build: process.env.TRAVIS_BUILD_ID,
          testname: 'Sauce Unit Test for openpgpjs',
          browsers: [browser_capabilities],
          public: "public",
          maxRetries: 3,
          throttled: 2,
          pollInterval: 4000,
          statusCheckAttempts: 200
        }
      },
    }
  });

  // Load the plugin(s)
  grunt.loadNpmTasks('grunt-browserify');
  grunt.loadNpmTasks('grunt-contrib-uglify');
  grunt.loadNpmTasks('grunt-text-replace');
  grunt.loadNpmTasks('grunt-jsbeautifier');
  grunt.loadNpmTasks('grunt-contrib-jshint');
  grunt.loadNpmTasks('grunt-jscs');
  grunt.loadNpmTasks('grunt-jsdoc');
  grunt.loadNpmTasks('grunt-mocha-istanbul');
  grunt.loadNpmTasks('grunt-mocha-test');
  grunt.loadNpmTasks('grunt-contrib-copy');
  grunt.loadNpmTasks('grunt-contrib-clean');
  grunt.loadNpmTasks('grunt-contrib-connect');
  grunt.loadNpmTasks('grunt-saucelabs');

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

  grunt.registerTask('default', 'Build OpenPGP.js', function() {
    grunt.task.run(['clean', 'copy:zlib', 'browserify', 'replace', 'uglify']);
    //TODO jshint is not run because of too many discovered issues, once these are addressed it should autorun
    grunt.log.ok('Before Submitting a Pull Request please also run `grunt jshint`.');
  });

  grunt.registerTask('documentation', ['jsdoc']);

  // Test/Dev tasks
  grunt.registerTask('test', ['jshint', 'jscs', 'copy:zlib', 'mochaTest']);
  grunt.registerTask('coverage', ['copy:zlib', 'mocha_istanbul:coverage']);
  grunt.registerTask('saucelabs', ['default', 'copy:browsertest', 'connect', 'saucelabs-mocha']);
};
