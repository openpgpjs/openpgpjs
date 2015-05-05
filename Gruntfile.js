module.exports = function(grunt) {

  var version = grunt.option('release');

  // Project configuration.
  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),
    browserify: {
      openpgp: {
        files: {
          'dist/openpgp.js': [ './src/index.js' ]
        },
        options: {
          standalone: 'openpgp',
          external: [ 'crypto', 'node-localstorage' ]
        }
      },
      openpgp_debug: {
        files: {
          'dist/openpgp_debug.js': [ './src/index.js' ]
        },
        options: {
          debug: true,
          standalone: 'openpgp',
          external: [ 'crypto', 'node-localstorage' ]
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
          'test/openpgp.js': [ './test/src/index.js' ],
          'test/lib/unittests-bundle.js': [ './test/unittests.js' ]
        },
        options: {
          external: [ 'openpgp', 'crypto', 'node-localstorage']
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
      all: ['src/**/*.js']
    },
    jsdoc: {
      dist: {
        src: ['README.md', 'src'],
        options: {
          destination: 'doc',
          recurse: true,
          template: 'jsdoc.template'
        }
      }
    },
    mocha_istanbul: {
      coverage: {
        src: 'test',
        options: {
          root: 'node_modules/openpgp',
          timeout: 120000,
        }
      },
      coveralls: {
        src: ['test'],
        options: {
          root: 'node_modules/openpgp',
          timeout: 120000,
          coverage: true,
          reportFormats: ['cobertura','lcovonly']
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
      npm: {
        expand: true,
        flatten: true,
        cwd: 'node_modules/',
        src: ['mocha/mocha.css', 'mocha/mocha.js', 'chai/chai.js'],
        dest: 'test/lib/'
      },
      unittests: {
        expand: true,
        flatten: false,
        cwd: './',
        src: ['src/**'],
        dest: 'test/'
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
          port: 9000,
          base: '.'
        }
      }
    },
    'saucelabs-mocha': {
      all: {
        options: {
          username: 'openpgpjs',
          key: '60ffb656-2346-4b77-81f3-bc435ff4c103',
          urls: ['http://127.0.0.1:9000/test/unittests.html'],
          build: process.env.TRAVIS_JOB_ID,
          testname: 'Sauce Unit Test for openpgpjs',
          browsers: [
            { browserName:"firefox", version:"38.0", platform:"Linux" },
            { browserName:"firefox", version:"42.0", platform:"OS X 10.10" },
            { browserName:"firefox", version:"beta", platform:"Windows 10" },
            { browserName:"chrome", version:"38.0", platform:"Linux" },
            { browserName:"chrome", version:"46.0", platform:"OS X 10.10" },
            { browserName:"chrome", version:"beta", platform:"Windows 10" },
            { browserName:"internet explorer", version:"11", platform:"Windows 10" },
            { browserName:"microsoftEdge", version:"20.10240", platform:"Windows 10" },
            { browserName:"safari", version:"8", platform:"OS X 10.10" },
            { browserName:"safari", version:"9", platform:"OS X 10.11" },
            { browserName:"android", version:"4.4", deviceName: "Android Emulator", platform: "Linux" },
            { browserName:"android", version:"5.1", deviceName: "Android Emulator", platform: "Linux" },
            { browserName: "iphone", version:"7.0", deviceName: "iPad Simulator", "device-orientation": "portrait", platform:"OS X 10.10" },
            { browserName: "iphone", version:"9.1", deviceName: "iPad Simulator", "device-orientation": "portrait", platform:"OS X 10.10" }
          ],
          public: "public",
          'max-duration': 360,
          maxRetries: 1,
          throttled: 3,
          pollInterval: 2000,
          statusCheckAttempts: 360
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
      fileName: 'bower.json',
      version: version
    });
  });

  function patchFile(options) {
    var fs = require('fs'),
      path = './' + options.fileName,
      file = require(path);

    if (options.version) {
      file.version = options.version;
    }

    fs.writeFileSync(path, JSON.stringify(file, null, 2));
  }

  grunt.registerTask('default', 'Build OpenPGP.js', function() {
    grunt.task.run(['clean', 'copy:zlib', 'browserify', 'replace', 'uglify', 'npm_pack']);
    //TODO jshint is not run because of too many discovered issues, once these are addressed it should autorun
    grunt.log.ok('Before Submitting a Pull Request please also run `grunt jshint`.');
  });

  grunt.registerTask('documentation', ['jsdoc']);

  // Alias the `npm_pack` task to run `npm pack`
  grunt.registerTask('npm_pack', 'npm pack', function () {
    var done = this.async();
    var npm = require('child_process').exec('npm pack ../', { cwd: 'dist'}, function (err, stdout) {
      var package = stdout;
      if (err === null) {
        var install = require('child_process').exec('npm install dist/' + package, function (err) {
          done(err);
        });
        install.stdout.pipe(process.stdout);
        install.stderr.pipe(process.stderr);
      } else {
        done(err);
      }
    });
    npm.stdout.pipe(process.stdout);
    npm.stderr.pipe(process.stderr);
  });

  grunt.event.on('coverage', function(lcov, done){
    require('coveralls').handleInput(lcov, function(err){
      if (err) {
        return done(err);
      }
    done();
    });
  });

  // Test/Dev tasks
  grunt.registerTask('test', ['copy:npm', 'copy:unittests', 'mochaTest']);
  grunt.registerTask('coverage', ['default', 'copy:npm', 'copy:unittests', 'mocha_istanbul:coverage']);
  grunt.registerTask('coveralls', ['default', 'copy:npm', 'copy:unittests', 'mocha_istanbul:coveralls']);
  grunt.registerTask('saucelabs', ['default', 'copy:npm', 'copy:unittests', 'connect', 'saucelabs-mocha']);
  grunt.registerTask('test_travis_mocha_coveralls', ['copy:npm', 'copy:unittests', 'mocha_istanbul:coveralls']);
  grunt.registerTask('test_travis_mocha_saucelabs', ['copy:npm', 'copy:unittests', 'connect', 'saucelabs-mocha']);

};
