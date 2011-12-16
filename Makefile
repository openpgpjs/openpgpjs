default: help

help:
	@echo "minify  - makes JavaScript download and run faster"
	@echo "lint    - checks JavaScript files for style issues"
	@echo "test    - runs JavaScript unit tests"

lint:
	@echo See http://code.google.com/closure/utilities/
	@./scripts/lint.sh

minify:
	@echo See http://code.google.com/closure/compiler/
	@./scripts/minimize.sh

test:
	@echo to be implemented
