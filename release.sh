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
rm -rf node_modules/
npm install

# set version
grunt set_version --release=$1

# build and test
npm test

# Add build files to git
sed -i "" '/^dist\/$/d' .gitignore
git add dist/ *.json
git commit -m "Release new version"
git checkout .gitignore
git tag v$1
git push
git push --tag

# publish to npm
npm publish
