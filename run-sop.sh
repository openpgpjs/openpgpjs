cd ../openpgp-interoperability-test-suite-binary
touch config.json
echo '{"drivers": [{"driver": "sop", "path": "../sop-openpgp-js/sop-openpgp"}]}' > config.json
./target/release/openpgp-interoperability-test-suite > report.html