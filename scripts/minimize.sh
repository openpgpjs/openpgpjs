#!/bin/bash

echo "Setup..."
_src="src";
_tmp="resources/openpgp.js.tmp";
_raw="resources/openpgp.js";
_min="resources/openpgp.min.js";
_compiler="resources/compiler.jar";
_majorVersion=".1"
:>"$_raw"
:>"$_min"

echo "Concatenating..."
find "$_src" -name "*.js" | sort | xargs cat > "$_tmp"
sed "s/OpenPGP.js VERSION/OpenPGP.js v$_majorVersion.$(date +%Y%m%d)/g" "$_tmp" > "$_raw";
rm "$_tmp";

echo "Minimizing..."
java -jar "$_compiler" --js "$_raw" --js_output_file "$_min"
