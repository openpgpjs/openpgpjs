#!/bin/sh

# go to root
cd `dirname $0`

# clear shrinkwrapped node_modules
rm package-lock.json
rm -rf node_modules/

# abort if tests fail
set -e

# install dependencies
npm install

# build and test
npm test

# Add build files to git
git add package-lock.json
git commit -m "Update npm dependencies and package lock"
