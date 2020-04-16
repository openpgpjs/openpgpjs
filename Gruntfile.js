module.exports = function(grunt) {

  const version = grunt.option('release');
  const fs = require('fs');

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
          cacheFile: 'browserify-cache' + (compat ? '-compat' : '') + (lightweight ? '-lightweight' : '') + '.json',
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
              'core-js/fn/object/assign'
            ],
            lightweight ? [
              'elliptic',
              'elliptic.min.js'
            ] : []
          ),
          transform: [
            ["babelify", {
              global: true,
              // Only babelify web-streams-polyfill, web-stream-tools, asmcrypto, email-addresses and seek-bzip in node_modules
              only: /^(?:.*\/node_modules\/web-streams-polyfill\/|.*\/node_modules\/web-stream-tools\/|.*\/node_modules\/asmcrypto\.js\/|.*\/node_modules\/email-addresses\/|.*\/node_modules\/seek-bzip\/|(?!.*\/node_modules\/)).*$/,
              ignore: ['*.min.js'],
              plugins,
              presets
            }]
          ],
          plugin: ['browserify-derequire']
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
    replace: {
      openpgp: {
        src: ['dist/openpgp.js'],
        dest: ['dist/openpgp.js'],
        replacements: [{
          from: /OpenPGP.js VERSION/g,
          to: 'OpenPGP.js v<%= pkg.version %>'
        }]
      },
      lightweight_build: {
        src: ['dist/openpgp.js'],
        overwrite: true,
        replacements: [
          {
            from: "external_indutny_elliptic: false",
            to: "external_indutny_elliptic: true"
          }
        ]
      },
      indutny_global: {
        src: ['dist/elliptic.min.js'],
        overwrite: true,
        replacements: [
          {
            from: 'b.elliptic=a()',
            to: 'b.openpgp.elliptic=a()'
          }
        ]
      }
    },
    terser: {
      openpgp: {
        files: {
          'dist/openpgp.min.js' : ['dist/openpgp.js']
        },
        options: {
          output: {
            comments: `/^!/`
          },
          sourceMap: dev ? {
            content: 'inline',
            url: 'inline'
          } : {},
          safari10: true
        }
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
          'dist/openpgp.js': 'dist/openpgp.js'
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
        dest: 'dist/'
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
    },
    watch: {
      src: {
        files: ['src/**/*.js'],
        tasks: lightweight ? ['browserify:openpgp', 'replace:lightweight_build'] : ['browserify:openpgp']
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
  grunt.registerTask('build', function() {
    if (lightweight) {
      grunt.task.run(['copy:indutny_elliptic', 'browserify:openpgp', 'replace:lightweight_build', 'replace:indutny_global', 'version', 'header', 'terser']);
      return;
    }
    grunt.task.run(['browserify:openpgp', 'version', 'header', 'terser']);
  }
  );
  grunt.registerTask('documentation', ['jsdoc']);
  grunt.registerTask('default', ['build']);
  // Test/Dev tasks
  grunt.registerTask('test', ['eslint', 'mochaTest']);
  grunt.registerTask('coverage', ['nyc']);
  grunt.registerTask('browsertest', ['build', 'browserify:unittests', 'copy:browsertest', 'connect:test', 'watch']);
};
