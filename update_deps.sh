#!/bin/sh

# go to root
cd `dirname $0`

# clear shrinkwrapped node_modules
rm npm-shrinkwrap.json
rm -rf node_modules/

# abort if tests fail
set -e

# install dependencies
npm install

# build and test
npm test

# shrinkwrap production and dev dependencies
npm shrinkwrap --dev

# Add build files to git
git add npm-shrinkwrap.json
git commit -m "Update npm dependencies and shrinkwrap"
