const pkg = require('./package.json');

module.exports = {
    plugins: ['plugins/markdown'],
    markdown: {
        idInHeadings: true
    },
    templates: {
        default: {
            outputSourceFiles: false,
            externalSourceLinks: {
                urlPrefix: `${pkg.repository.url}/blob/v${pkg.version}/src/`
            }
        }
    }
};
