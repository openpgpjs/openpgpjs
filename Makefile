default: help

help:
	@echo "update         - get latest sources"
	@echo "bundle         - makes JavaScript download and run faster"
	@echo "lint           - checks JavaScript files for style issues"
	@echo "test           - runs JavaScript unit tests"
	@echo "example        - creates a simple example"
	@echo "documentation  - generates documentation. Requires jsdoc (3.2) in PATH"

update: update-me update-deps

update-me:
	@git pull

update-deps:
	@git submodule foreach git pull

bundle:
	@grunt

lint:
	@grunt jshint

test:
	@npm test

example:
	@mkdir -p build
	@rm -f build/openpgpjs-0.x.zip
	@zip -j build/openpgpjs-0.x.zip resources/example.* resources/openpgp.min.js resources/jquery.min.js
	@echo "Have a look at build/openpgpjs-0.x.zip"

documentation:
	@grunt jsdoc
