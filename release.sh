#!/bin/sh

# abort if tests fail
set -e

# go to root
cd `dirname $0`

if [ "$#" -ne 1 ] ; then
    echo 'Usage: ./release.sh 0.0.0'
    exit 0
fi

# install dependencies
rm -rf node_modules
npm install

# set version
grunt set_version --release=$1

# build and test
rm -rf dist
rm -f browserify-cache*
npm run build
grunt test

# Add build files to git
git add --force dist/ bower.json package-lock.json package.json
git commit -m "Release new version"
git tag v$1
git push
git push --tag

# publish to npm
npm publish #--tag old-version
