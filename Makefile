all:
	env NODE_ENV=development npm start

BROWSER=chromium-browser
.PHONY: test test-develop
test:
	npm run prebrowsertest
	( sleep 2 && $(BROWSER) "http://localhost:8080/test/unittests.html" ) &
	npm start

test-develop:
	npm run prebrowsertest
	( sleep 2 && $(BROWSER) "http://localhost:8080/test/unittests.html" ) &
	 npm run build-test-watch
