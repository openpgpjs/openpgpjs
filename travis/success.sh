#!/bin/bash
if [ "${TRAVIS_NODE_VERSION}" == "0.10" -a "${TRAVIS_BRANCH}" == "master" -a "${TRAVIS_PULL_REQUEST}" == "false" ]; then
    grunt jsdoc
    zip -r dist/docs.zip doc
    git clone --branch gh-pages https://github.com/${TRAVIS_REPO_SLUG}.git travis/github
    cd travis/github
    export GIT_ASKPASS=/bin/true
    git config user.name "Travis Build"
    git config user.email "nobody@travis-ci.org"
    git config credential.https://github.com.username ${GITHUB_TOKEN}
    rm -rf doc
    cp -r ../../doc .
    git add --all doc
    git commit -m "Travis CI Docs build ${TRAVIS_BUILD_NUMBER}"
    git push
    cd ../..
    rm -rf travis/github
    node travis/make-release.js
fi
