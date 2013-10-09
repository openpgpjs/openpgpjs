module.exports = function(grunt) {

  // Project configuration.
  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),
    browserify: {
      dist: {
        files: {
          'resources/openpgp.js': ['src/**/*.js']
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
          "resources/openpgp.min.js" : [ "resources/openpgp.js" ]
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
    grunt.task.run(['jsbeautifier', 'browserify', 'replace', 'uglify']);
    //TODO jshint is not run because of too many discovered issues, once these are addressed it should autorun
    grunt.log.ok('Before Submitting a Pull Request please also run `grunt jshint`.');
  });
  grunt.registerTask('documentation', ['jsdoc']);
};
