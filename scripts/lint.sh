#!/bin/bash

echo "Setup..."
_src="src";

echo "Analyzing..."
find "$_src" -name "*.js" -exec gjslint "{}" \;
