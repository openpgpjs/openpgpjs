module.exports = function(grunt) {

  const version = grunt.option('release');
  const fs = require('fs');

  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),
    nyc: {
      cover: {
        options: {
          include: ['dist/**'],
          reporter: ['text-summary'],
          reportDir: 'coverage'
        },
        cmd: false,
        args: ['grunt', 'mochaTest'],
        sourceMap: true
      },
      report: {
        options: {
          reporter: 'text'
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
      target: ['src/**/*.js', './Gruntfile.js', './eslintrc.js', 'test/crypto/**/*.js'],
      options: {
        configFile: '.eslintrc.js',
        fix: !!grunt.option('fix')
      }
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
      },
      indutny_elliptic: {
        expand: true,
        flatten: true,
        src: ['./node_modules/elliptic/dist/elliptic.min.js'],
        dest: 'dist/lightweight/'
      }
    },
    clean: {
      dist: ['dist/'],
      js: ['dist/*.js']
    },
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
    }
  });

  // Load the plugin(s)
  grunt.loadNpmTasks('grunt-text-replace');
  grunt.loadNpmTasks('grunt-jsbeautifier');
  grunt.loadNpmTasks('grunt-jsdoc');
  grunt.loadNpmTasks('gruntify-eslint');
  grunt.loadNpmTasks('grunt-mocha-test');
  grunt.loadNpmTasks('grunt-contrib-copy');
  grunt.loadNpmTasks('grunt-contrib-clean');
  grunt.loadNpmTasks('grunt-contrib-connect');
  grunt.loadNpmTasks('grunt-contrib-watch');
  grunt.loadNpmTasks('grunt-simple-nyc');

  grunt.registerTask('set_version', function() {
    if (!version) {
      throw new Error('You must specify the version: "--release=1.0.0"');
    }

    patchFile({
      fileName: 'package.json',
      version: version
    });

    patchFile({
      fileName: 'package-lock.json',
      version: version
    });

    patchFile({
      fileName: 'bower.json',
      version: version
    });
  });

  function patchFile(options) {
    const path = './' + options.fileName;
    //eslint-disable-next-line
    const file = require(path);

    if (options.version) {
      file.version = options.version;
    }
    //eslint-disable-next-line
    fs.writeFileSync(path, JSON.stringify(file, null, 2) + '\n');
  }

  // Build tasks
  grunt.registerTask('version', ['replace:openpgp']);
  grunt.registerTask('documentation', ['jsdoc']);
  grunt.registerTask('default', ['build']);
  // Test/Dev tasks
  grunt.registerTask('test', ['eslint', 'mochaTest']);
  grunt.registerTask('coverage', ['nyc']);
  grunt.registerTask('browsertest', ['build', 'browserify:unittests', 'copy:browsertest', 'connect:test', 'watch']);
};
