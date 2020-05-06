cd ../openpgp-interoperability-test-suite-binary
sudo apt install -y nettle-dev
touch config.json
echo '{"drivers": [{"driver": "sop", "path": "../sop-openpgp-js/sop-openpgp"}]}' > config.json
./target/release/openpgp-interoperability-test-suite > $TRAVIS_BUILD_DIR/report.html