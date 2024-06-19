#!/bin/bash
OUTPUT_FILE='resources_rc.py'
INPUT_FILE='resources.qrc'
source ../venv/bin/activate && pyside6-rcc -o $OUTPUT_FILE $INPUT_FILE && deactivate && echo "Compiled $INPUT_FILE"
