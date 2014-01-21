module.exports = function(grunt) {

  // Project configuration.
  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),
    browserify: {
      openpgp_nodebug: {
        files: {
          'dist/openpgp_nodebug.js': [ './src/index.js' ]
        },
        options: {
          standalone: 'openpgp',
          external: [ 'crypto', 'node-localstorage' ]
        }
      },
      openpgp: {
        files: {
          'dist/openpgp.js': [ './src/index.js' ]
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
      unittests: {
        files: {
          'test/lib/unittests-bundle.js': []
        },
        options: {
          debug: true,
          alias: './test/unittests.js:unittests',
          external: [ 'openpgp' ]
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
      openpgp_nodebug: {
        src: ['dist/openpgp_nodebug.js'],
        dest: ['dist/openpgp_nodebug.js'],
        replacements: [{
          from: /OpenPGP.js VERSION/g,
          to: 'OpenPGP.js v<%= pkg.version %>'
        }]
      }
    },
    uglify: {
      openpgp: {
        files: {
          'dist/openpgp.min.js' : [ 'dist/openpgp_nodebug.js' ]
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
    mochaTest: {
      unittests: {
        options: {
          reporter: 'spec'
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
      }
    },
    clean: ['dist/']
  });

  // Load the plugin(s)
  grunt.loadNpmTasks('grunt-browserify');
  grunt.loadNpmTasks('grunt-contrib-uglify');
  grunt.loadNpmTasks('grunt-text-replace');
  grunt.loadNpmTasks('grunt-jsbeautifier');
  grunt.loadNpmTasks('grunt-contrib-jshint');
  grunt.loadNpmTasks('grunt-jsdoc');
  grunt.loadNpmTasks('grunt-mocha-test');
  grunt.loadNpmTasks('grunt-contrib-copy');
  grunt.loadNpmTasks('grunt-contrib-clean');

  grunt.registerTask('default', 'Build OpenPGP.js', function() {
    grunt.task.run(['clean', 'browserify', 'replace', 'uglify', 'npm_pack']);
    //TODO jshint is not run because of too many discovered issues, once these are addressed it should autorun
    grunt.log.ok('Before Submitting a Pull Request please also run `grunt jshint`.');
  });

  grunt.registerTask('documentation', ['jsdoc']);

  // Alias the `mocha_phantomjs` task to run `mocha-phantomjs`
  grunt.registerTask('mocha_phantomjs', 'mocha-phantomjs', function () {
    var done = this.async();
    var mocha = require('child_process').exec('node_modules/mocha-phantomjs/bin/mocha-phantomjs ./test/unittests.html', function (err) {
      done(err);
    });
    mocha.stdout.pipe(process.stdout);
    mocha.stderr.pipe(process.stderr);
  });

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

    // Test/Dev tasks
  grunt.registerTask('test', ['copy', 'mochaTest', 'mocha_phantomjs']);
};
