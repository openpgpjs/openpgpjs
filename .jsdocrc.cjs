const pkg = require('./package.json');

module.exports = {
    plugins: [
        'plugins/markdown',
        'node_modules/better-docs/typedef-import'
    ],
    markdown: {
        idInHeadings: true
    },
    templates: {
        default: {
            includeDate: false,
            outputSourceFiles: false,
            externalSourceLinks: {
                urlPrefix: `${pkg.repository.url}/blob/v${pkg.version}/src/`
            }
        }
    }
};
