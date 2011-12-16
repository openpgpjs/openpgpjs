#!/bin/bash

echo "Setup..."
_src="src";
_raw="resources/openpgp.js";
_min="resources/openpgp.min.js";
_compiler="resources/compiler.jar";
:>"$_raw"
:>"$_min"

echo "Concatenating..."
find "$_src" -name "*.js" -exec cat "{}" >> "$_raw" \;

echo "Minimizing..."
java -jar "$_compiler" --js "$_raw" --js_output_file "$_min"
