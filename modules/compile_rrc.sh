#!/bin/bash

OUTPUT_FILE='resources_rc.py'
INPUT_FILE='resources.qrc'
pyside6-rcc -o $OUTPUT_FILE $INPUT_FILE && echo "Compiled $INPUT_FILE" && exit 0
echo "Error compiling $INPUT_FILE"
exit 1

