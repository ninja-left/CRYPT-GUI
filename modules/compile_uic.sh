#!/bin/bash
INPUT_FILE='design.ui'
OUTPUT_FILE='main_ui.py'
pyside6-uic -o $OUTPUT_FILE $INPUT_FILE && echo "Compiled $INPUT_FILE"
