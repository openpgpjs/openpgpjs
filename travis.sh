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
    "export SELENIUM_BROWSER_CAPABILITIES='{\"browserName\":\"Firefox\", \"version\":\"34\", \"platform\":\"OS X 10.12\", \"maxDuration\":\"7200\", \"commandTimeout\":\"600\", \"idleTimeout\":\"270\"}'"
    "export SELENIUM_BROWSER_CAPABILITIES='{\"browserName\":\"Firefox\", \"version\":\"54\", \"platform\":\"OS X 10.12\", \"maxDuration\":\"7200\", \"commandTimeout\":\"600\", \"idleTimeout\":\"270\"}'"
    "export SELENIUM_BROWSER_CAPABILITIES='{\"browserName\":\"Chrome\", \"version\":\"37\",  \"platform\":\"OS X 10.12\", \"maxDuration\":\"7200\", \"commandTimeout\":\"600\", \"idleTimeout\":\"270\"}'"
    "export SELENIUM_BROWSER_CAPABILITIES='{\"browserName\":\"Chrome\", \"version\":\"59\", \"platform\":\"OS X 10.12\", \"maxDuration\":\"7200\", \"commandTimeout\":\"600\", \"idleTimeout\":\"270\"}'"
    "export SELENIUM_BROWSER_CAPABILITIES='{\"browserName\":\"Internet Explorer\", \"version\":\"11.103\", \"platform\":\"Windows 10\", \"maxDuration\":\"7200\", \"commandTimeout\":\"600\", \"idleTimeout\":\"270\"}'"
    "export SELENIUM_BROWSER_CAPABILITIES='{\"browserName\":\"MicrosoftEdge\", \"version\":\"15.15063\", \"platform\":\"Windows 10\", \"maxDuration\":\"7200\", \"commandTimeout\":\"600\", \"idleTimeout\":\"270\"}'"
    "export SELENIUM_BROWSER_CAPABILITIES='{\"browserName\":\"Safari\", \"version\":\"8\", \"platform\":\"OS X 10.10\", \"maxDuration\":\"7200\", \"commandTimeout\":\"600\", \"idleTimeout\":\"270\"}'"
    "export SELENIUM_BROWSER_CAPABILITIES='{\"browserName\":\"Safari\", \"version\":\"10\", \"platform\":\"macOS 10.12\", \"maxDuration\":\"7200\", \"commandTimeout\":\"600\", \"idleTimeout\":\"270\"}'"
    "export SELENIUM_BROWSER_CAPABILITIES='{\"browserName\":\"Browser\", \"platformName\":\"Android\", \"platformVersion\": \"4.4\", \"deviceName\": \"Android Emulator\", \"deviceOrientation\": \"portrait\", \"maxDuration\":\"7200\", \"commandTimeout\":\"600\", \"idleTimeout\":\"270\"}'"
    "export SELENIUM_BROWSER_CAPABILITIES='{\"browserName\":\"Chrome\", \"platformName\":\"Android\", \"platformVersion\": \"6.0\", \"deviceName\": \"Android Emulator\", \"deviceOrientation\": \"portrait\", \"maxDuration\":\"7200\", \"commandTimeout\":\"600\", \"idleTimeout\":\"270\"}'"
    "export SELENIUM_BROWSER_CAPABILITIES='{\"browserName\": \"Safari\", \"platformName\":\"iOS\", \"platformVersion\": \"8.1\", \"deviceName\": \"iPad Simulator\", \"deviceOrientation\": \"portrait\", \"maxDuration\":\"7200\", \"commandTimeout\":\"600\", \"idleTimeout\":\"270\"}'"
    "export SELENIUM_BROWSER_CAPABILITIES='{\"browserName\": \"Safari\", \"platformName\":\"iOS\", \"platformVersion\": \"11.0\", \"deviceName\": \"iPad Air 2 Simulator\", \"deviceOrientation\": \"portrait\", \"maxDuration\":\"7200\", \"commandTimeout\":\"600\", \"idleTimeout\":\"270\"}'"
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
