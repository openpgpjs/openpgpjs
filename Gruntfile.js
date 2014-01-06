module.exports = function(grunt) {

  // Project configuration.
  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),
    browserify: {
      openpgp_nodebug: {
        files: {
          'resources/openpgp_nodebug.js': []
        },
        options: {
          alias: './src/:openpgp'
        }
      },
      openpgp: {
        files: {
          'resources/openpgp.js': []
        },
        options: {
          debug: true,
          alias: './src/:openpgp'
        }
      },
      keyring_nodebug: {
        files: {
          'resources/keyring_nodebug.js': []
        },
        options: {
          alias: './src/keyring/:keyring',
          external: [ 'openpgp' ]
        }
      },
      keyring: {
        files: {
          'resources/keyring.js': []
        },
        options: {
          debug: true,
          alias: './src/keyring/:keyring',
          external: [ 'openpgp' ]
        }
      },
      unittests: {
        files: {
          'test/lib/unittests-bundle.js': []
        },
        options: {
          debug: true,
          alias: './test/unittests.js:unittests',
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
      },
      openpgpjs_nodebug: {
        src: ['resources/openpgp_nodebug.js'],
        dest: ['resources/openpgp_nodebug.js'],
        replacements: [{
          from: /OpenPGP.js VERSION/g,
          to: 'OpenPGP.js v<%= pkg.version %>.<%= grunt.template.today("yyyymmdd") %>'
        }]
      }
    },
    uglify: {
      openpgpjs: {
        files: {
          "resources/openpgp.min.js" : [ "resources/openpgp_nodebug.js" ],
          "resources/keyring.min.js" : [ "resources/keyring_nodebug.js" ]
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
        src: ["README.md", "src"],
        options: {
          destination: "doc",
          recurse: true,
          template: "jsdoc.template"
        }
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
    var mocha = require('child_process').exec('node_modules/mocha-phantomjs/bin/mocha-phantomjs ./test/unittests.html', function (err) {
      done(err);
    });
    mocha.stdout.pipe(process.stdout);
    mocha.stderr.pipe(process.stderr);
  });

  // Test/Dev tasks
  grunt.registerTask('test', ['copy', 'mocha_phantomjs']);
};
