module.exports = function(grunt) {

  // Project configuration.
  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),
    browserify: {
      openpgp: {
        files: {
          'resources/openpgp.js': []
        },
        options: {
          alias: './src/:openpgp'
        }
      },
      openpgp_debug: {
        files: {
          'resources/openpgp.debug.js': []
        },
        options: {
          debug: true,
          alias: './src/:openpgp'
        }
      },
      keyring: {
        files: {
          'resources/keyring.js': []
        },
        options: {
          alias: './src/keyring/:keyring',
          external: [ 'openpgp' ]
        }
      },
      keyring_debug: {
        files: {
          'resources/keyring.debug.js': []
        },
        options: {
          debug: true,
          alias: './src/keyring/:keyring',
          external: [ 'openpgp' ]
        }
      },
      unittests: {
        files: {
          'test/lib/test-bundle.js': []
        },
        options: {
          debug: true,
          alias: './test/test-all.js:unittests',
          external: [ 'openpgp', 'keyring' ]
        }
      },
      ci_tests: {
        files: {
          'test/lib/ci-tests-bundle.js': []
        },
        options: {
          debug: true,
          alias: './test/ci-tests-all.js:ci-tests',
          external: [ 'openpgp', 'keyring' ]
        }
      }
    },
    replace : {
      openpgpjs: {
        src: ['resources/openpgp.js'],
        dest: ['resources/openpgp.js'],
        replacements: [{
          from: /OpenPGP.js VERSION/g,
          to: 'OpenPGP.js v<%= pkg.version %>.<%= grunt.template.today("yyyymmdd") %>'
        }]
      }
    },
    uglify: {
      openpgpjs: {
        files: {
          "resources/openpgp.min.js" : [ "resources/openpgp.js" ],
          "resources/keyring.min.js" : [ "resources/keyring.js" ]
        }
      },
      options: {
        banner: '/*! OpenPGPjs.org  this is LGPL licensed code, see LICENSE/our website for more information.- v<%= pkg.version %> - ' +
          '<%= grunt.template.today("yyyy-mm-dd") %> */'
      }
    },
    jsbeautifier : {
      files : ["src/**/*.js"],
      options : {
        indent_size: 2,
        preserve_newlines: true,
        keep_array_indentation: false,
        keep_function_indentation: false,
        wrap_line_length: 120
      }
    },
    jshint : {
      all : ["src/**/*.js"]
    },
    jsdoc : {
      dist : {
        src: ["src/**/*.js"],
        options: {
          destination: "doc"
        }
      }
    },

    copy: {
      npm: {
        expand: true,
        flatten: true,
        cwd: 'node_modules/',
        src: ['mocha/mocha.css', 'mocha/mocha.js', 'chai/chai.js', 'sinon/pkg/sinon.js'],
        dest: 'test/lib/'
      },
      openpgp: {
        expand: true,
        cwd: 'resources/',
        src: ['openpgp.debug.js', 'keyring.debug.js', 'jquery.min.js'],
        dest: 'test/lib/'
      }
    }
  });

  // Load the plugin that provides the "uglify" task.
  grunt.loadNpmTasks('grunt-browserify');
  grunt.loadNpmTasks('grunt-contrib-uglify');
  grunt.loadNpmTasks('grunt-text-replace');
  grunt.loadNpmTasks('grunt-jsbeautifier');
  grunt.loadNpmTasks('grunt-contrib-jshint');
  grunt.loadNpmTasks('grunt-jsdoc');

  grunt.registerTask('default', 'Build OpenPGP.js', function() {
    grunt.task.run(['browserify', 'replace', 'uglify']);
    //TODO jshint is not run because of too many discovered issues, once these are addressed it should autorun
    grunt.log.ok('Before Submitting a Pull Request please also run `grunt jshint`.');
  });
  grunt.registerTask('documentation', ['jsdoc']);

  // Load the plugin(s)
  grunt.loadNpmTasks('grunt-contrib-copy');

  // Alias the `mocha_phantomjs` task to run `mocha-phantomjs`
  grunt.registerTask('mocha_phantomjs', 'mocha-phantomjs', function () {
    var done = this.async();
    require('child_process').exec('node_modules/mocha-phantomjs/bin/mocha-phantomjs ./test/ci-tests.html', function (err, stdout) {
      grunt.log.write(stdout);
      done(err);
    });
  });

  // Test/Dev tasks
  grunt.registerTask('test', ['copy', 'mocha_phantomjs']);
};
