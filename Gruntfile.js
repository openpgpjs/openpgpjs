module.exports = function(grunt) {
    'use strict';

    // Project configuration.
    grunt.initConfig({
        connect: {
            dev: {
                options: {
                    port: 8680,
                    base: '.',
                    keepalive: true
                }
            },
            test: {
                options: {
                    port: 8681,
                    base: '.'
                }
            }
        },

        mocha: {
            all: {
                options: {
                    urls: ['http://localhost:<%= connect.test.options.port %>/test/integration/index.html'],
                    run: false,
                    reporter: 'Spec'
                }
            }
        },

        copy: {
            npm: {
                expand: true,
                flatten: true,
                cwd: 'node_modules/',
                src: ['requirejs/require.js', 'mocha/mocha.css', 'mocha/mocha.js', 'chai/chai.js', 'sinon/pkg/sinon.js'],
                dest: 'test/integration/lib/'
            }
        }
    });

    // Load the plugin(s)
    grunt.loadNpmTasks('grunt-contrib-copy');
    grunt.loadNpmTasks('grunt-contrib-connect');
    grunt.loadNpmTasks('grunt-mocha');

    // Test/Dev tasks
    grunt.registerTask('dev', ['connect:dev']);
    grunt.registerTask('test', ['copy', 'connect:test', 'mocha']);

};