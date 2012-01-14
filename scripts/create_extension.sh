#!/bin/bash
################################################################################
# OpenPGP.js browser extension build script
#
# @author   Alex
################################################################################

echo "Setup..."
dir_extension="plugins/chrome/"
dir_webcode="webmail/googlemail.com/"
dir_target="`mktemp -d browserext.XXX`"
dir_build="build/";
sh_pack="./scripts/pack.sh"
file_key="resources/openpgpjs.pem"
file_extension="build/openpgpjs.crx"
mkdir -p "$dir_build"

echo "Copying files..."
cp -R "$dir_extension"/* "$dir_target"
cp -R "$dir_webcode"/* "$dir_target"

echo "Creating extension..."
$sh_pack "$dir_target" "$file_key"

echo "Cleaning up..."
rm -rf "$dir_target"
mv "$dir_target".crx "$file_extension"
