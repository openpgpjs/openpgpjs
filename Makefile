default: help

help:
	@echo "minify         - makes JavaScript download and run faster"
	@echo "lint           - checks JavaScript files for style issues"
	@echo "test           - runs JavaScript unit tests"
	@echo "example        - creates a simple example"
	@echo "ext-chr-gmail  - creates the Google Chrome / Google Mail extension"

example:
	@mkdir -p build
	@rm -f build/example.zip
	@zip -j build/example.zip resources/example.* resources/openpgp.min.js resources/jquery.min.js

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
