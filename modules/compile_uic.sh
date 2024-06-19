#!/bin/bash
INPUT_FILE='design.ui'
OUTPUT_FILE='main_ui.py'
source ../venv/bin/activate && pyside6-uic -o $OUTPUT_FILE $INPUT_FILE && deactivate && echo "Compiled $INPUT_FILE"
