#!/bin/bash

set -e

npm link 
cd ..
git clone https://gitlab.com/sequoia-pgp/sop-openpgp-js.git
cd sop-openpgp-js
npm install yargs
npm link openpgp
bash test/run