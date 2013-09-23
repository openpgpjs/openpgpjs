default: help

help:
	@echo "update         - get latest sources"
	@echo "minify         - makes JavaScript download and run faster"
	@echo "lint           - checks JavaScript files for style issues"
	@echo "test           - runs JavaScript unit tests"
	@echo "example        - creates a simple example"
	@echo "ext-chr-gmail  - creates the Google Chrome / Google Mail extension"
	@echo "documentation  - generates documentation. Requires jsdoc (3.2) in PATH"

update: update-me update-deps

update-me:
	@git pull

update-deps:
	@git submodule foreach git pull

example:
	@mkdir -p build
	@rm -f build/openpgpjs-0.x.zip
	@zip -j build/openpgpjs-0.x.zip resources/example.* resources/openpgp.min.js resources/jquery.min.js
	@echo "Have a look at build/openpgpjs-0.x.zip"

ext-chr-gmail:
	@./scripts/create_extension.sh

lint:
	@echo See http://code.google.com/closure/utilities/
	@./scripts/lint.sh

minify:
	@echo See http://code.google.com/closure/compiler/
	@./scripts/minimize.sh

test:
	@echo to be implemented
	@echo Open test/index.html instead

documentation:
	@jsdoc src -r -d doc
