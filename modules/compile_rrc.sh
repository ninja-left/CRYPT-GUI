#!/bin/bash

PREFIX="design"
INPUT_FILE="$PREFIX/resources.qrc"
OUTPUT_FILE="$PREFIX/resources_rc.py"
pyside6-rcc -o $OUTPUT_FILE $INPUT_FILE && echo "Compiled $INPUT_FILE" && exit 0
echo "Error compiling $INPUT_FILE"
exit 1

