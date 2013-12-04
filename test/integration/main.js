'use strict';

// config require.js
require.config({
    baseUrl: './',
    paths: {
        openpgp: '../../resources/openpgp',
        jquery: '../../resources/jquery.min'
    },
    shim: {
        openpgp: {
            exports: 'window'
        },
        jquery: {
            exports: 'window'
        }
    }
});

// start mocha tests
mocha.setup('bdd');
require(
    [
        'pgp-test'
    ], function() {
        // require modules loaded -> run tests
        mocha.run();
    }
);
