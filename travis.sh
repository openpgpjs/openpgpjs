#!/bin/bash

set -e

if [ $OPENPGPJSTEST = "coverage" ]; then
  echo "Running OpenPGP.js unit tests on node.js with code coverage."
  grunt coverage
  codeclimate-test-reporter < coverage/lcov.info

elif [ $OPENPGPJSTEST = "unit" ]; then
  echo "Running OpenPGP.js unit tests on node.js."
  npm test

elif [ $OPENPGPJSTEST = "saucelabs" ]; then
  echo "Running OpenPGP.js browser unit tests on Saucelabs."

  export SELENIUM_BROWSER_CAPABILITIES="{\"browserName\":\"$BROWSER\", \"version\":\"$VERSION\", \"platform\":\"$PLATFORM\", \"extendedDebugging\":true}"
  echo "SELENIUM_BROWSER_CAPABILITIES='$SELENIUM_BROWSER_CAPABILITIES'"
  grunt saucelabs --compat=$COMPAT &
  background_process_pid=$!

  # https://github.com/travis-ci/travis-ci/issues/4190
  minutes=0
  limit=30
  while kill -0 $background_process_pid >/dev/null 2>&1; do
    echo -n -e " \b" # never leave evidences!

    if [ $minutes == $limit ]; then
      exit 1
    fi

    minutes=$((minutes+1))

    sleep 60
  done

  wait $background_process_pid

  exit $? # were comes the status of the background_process :)
fi
