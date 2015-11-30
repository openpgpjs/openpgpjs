#!/bin/bash

set -e

if [ $OPENPGPJSTEST = "unit" ]; then
  echo "Running OpenPGP.js unit-tests"
  grunt coveralls

elif [[ $OPENPGPJSTEST =~ ^end2end-.* ]]; then
  echo "Running browser-testing on Saucelabs"

  declare -a capabilities=(
    "export SELENIUM_BROWSER_CAPABILITIES='{\"browserName\":\"firefox\", \"version\":\"38.0\", \"platform\":\"Linux\"}'"
    "export SELENIUM_BROWSER_CAPABILITIES='{\"browserName\":\"firefox\", \"version\":\"42.0\", \"platform\":\"OS X 10.10\"}'"
    "export SELENIUM_BROWSER_CAPABILITIES='{\"browserName\":\"firefox\", \"version\":\"beta\", \"platform\":\"Windows 10\"}'"
    "export SELENIUM_BROWSER_CAPABILITIES='{\"browserName\":\"chrome\", \"version\":\"38.0\", \"platform\":\"Linux\"}'"
    "export SELENIUM_BROWSER_CAPABILITIES='{\"browserName\":\"chrome\", \"version\":\"46.0\", \"platform\":\"OS X 10.10\"}'"
    "export SELENIUM_BROWSER_CAPABILITIES='{\"browserName\":\"chrome\", \"version\":\"beta\", \"platform\":\"Windows 10\"}'"
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
  grunt saucelabs
fi
