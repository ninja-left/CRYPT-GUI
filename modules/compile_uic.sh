#!/bin/bash
INPUT_FILE='main.ui'
INPUT_FILE2='bf.ui'
OUTPUT_FILE='main_ui.py'
OUTPUT_FILE2='bf_ui.py'
pyside6-uic -o $OUTPUT_FILE $INPUT_FILE && echo "Compiled $INPUT_FILE"
pyside6-uic -o $OUTPUT_FILE2 $INPUT_FILE2 && echo "Compiled $INPUT_FILE2"
exit 0

