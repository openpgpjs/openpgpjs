#!/bin/bash

set -e

if [ $OPENPGPJSTEST = "coverage" ]; then
  echo "Running OpenPGP.js unit tests on node.js with code coverage."
  grunt coverage
  codeclimate-test-reporter < coverage/lcov.info

elif [ $OPENPGPJSTEST = "unit" ]; then
  echo "Running OpenPGP.js unit tests on node.js."
  npm test

elif [[ $OPENPGPJSTEST =~ ^end2end-.* ]]; then
  echo "Running OpenPGP.js browser unit tests on Saucelabs."

  declare -a capabilities=(
    "export SELENIUM_BROWSER_CAPABILITIES='{\"browserName\":\"firefox\", \"version\":\"38.0\", \"platform\":\"Linux\"}'"
    "export SELENIUM_BROWSER_CAPABILITIES='{\"browserName\":\"firefox\", \"version\":\"42.0\", \"platform\":\"OS X 10.10\"}'"
    "export SELENIUM_BROWSER_CAPABILITIES='{\"browserName\":\"chrome\", \"version\":\"38.0\", \"platform\":\"Linux\"}'"
    "export SELENIUM_BROWSER_CAPABILITIES='{\"browserName\":\"chrome\", \"version\":\"46.0\", \"platform\":\"OS X 10.10\"}'"
    "export SELENIUM_BROWSER_CAPABILITIES='{\"browserName\":\"internet explorer\", \"version\":\"11\", \"platform\":\"Windows 10\"}'"
    "export SELENIUM_BROWSER_CAPABILITIES='{\"browserName\":\"microsoftEdge\", \"version\":\"20.10240\", \"platform\":\"Windows 10\"}'"
    "export SELENIUM_BROWSER_CAPABILITIES='{\"browserName\":\"safari\", \"version\":\"8\", \"platform\":\"OS X 10.10\"}'"
    "export SELENIUM_BROWSER_CAPABILITIES='{\"browserName\":\"safari\", \"version\":\"9\", \"platform\":\"OS X 10.11\"}'"
    "export SELENIUM_BROWSER_CAPABILITIES='{\"browserName\":\"android\", \"version\": \"4.4\", \"deviceName\": \"Android Emulator\", \"platform\": \"Linux\"}'"
    "export SELENIUM_BROWSER_CAPABILITIES='{\"browserName\":\"android\", \"version\": \"5.1\", \"deviceName\": \"Android Emulator\", \"platform\": \"Linux\"}'"
    "export SELENIUM_BROWSER_CAPABILITIES='{\"browserName\": \"iPhone\", \"version\": \"7.1\", \"deviceName\": \"iPad Simulator\", \"device-orientation\": \"portrait\", \"platform\":\"OS X 10.10\"}'"
    "export SELENIUM_BROWSER_CAPABILITIES='{\"browserName\": \"iPhone\", \"version\": \"9.1\", \"deviceName\": \"iPad Simulator\", \"device-orientation\": \"portrait\", \"platform\":\"OS X 10.10\"}'"
  )

  testkey=$(echo $OPENPGPJSTEST | cut -f2 -d-)

  ## now loop through the above array
  capability=${capabilities[${testkey}]}

  echo "Testing Configuration: ${testkey}"
  eval $capability
  grunt saucelabs &
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
