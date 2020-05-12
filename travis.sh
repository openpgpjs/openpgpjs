#!/bin/bash

set -e

if [ $OPENPGPJSTEST = "coverage" ]; then
  echo "Running OpenPGP.js unit tests on node.js with code coverage."
  npm run coverage
  codeclimate-test-reporter < coverage/lcov.info

elif [ $OPENPGPJSTEST = "unit" ]; then
  echo "Running OpenPGP.js unit tests on node.js."
  npm test ${LIGHTWEIGHT+ -- --grep lightweight}

elif [ $OPENPGPJSTEST = "browserstack" ]; then
  echo "Running OpenPGP.js browser unit tests on Browserstack."

  npm run build-test
  echo -n "Using config: "
  echo "{\"browsers\": [$BROWSER], \"test_framework\": \"mocha\", \"test_path\": [\"test/unittests.html?ci=true${LIGHTWEIGHT+&lightweight=true&grep=lightweight}\"], \"timeout\": 1800, \"exit_with_fail\": true, \"project\": \"openpgpjs/${TRAVIS_EVENT_TYPE:-push}${LIGHTWEIGHT:+/lightweight}\"}" > browserstack.json
  cat browserstack.json

  result=0
  count=1
  while [ $count -le 3 ]; do
    [ $result -ne 0 ] && {
      echo -e "\nThe command failed. Retrying, $count of 3.\n" >&2
    }

    browserstack-runner &
    background_process_pid=$!

    # https://github.com/travis-ci/travis-ci/issues/4190
    seconds=0
    limit=2000
    while kill -0 $background_process_pid >/dev/null 2>&1; do
      echo -n -e " \b" # never leave evidences!

      if [ $seconds == $limit ]; then
        echo -e "\nThe tests timed out.\n" >&2
        exit 1
      fi

      seconds=$((seconds+1))

      sleep 1
    done

    wait $background_process_pid && { result=0 && break; } || result=$?

    [ $result -eq 0 ] && break
    [ $seconds -gt 10 ] && break # If the tests took <10 seconds, assume they failed to launch and try again.
    count=$(($count + 1))
  done

  [ $count -gt 3 ] && {
    echo -e "\nThe command failed 3 times.\n" >&2
  }

  exit $result
fi
