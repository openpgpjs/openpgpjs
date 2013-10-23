'use strict';

// config require.js
require.config({
    baseUrl: './',
    paths: {
        openpgp: '../../resources/openpgp.min'
    },
    shim: {
        openpgp: {
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