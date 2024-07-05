#!/bin/bash
INPUT_FILE='main.ui'
INPUT_FILE2='bf.ui'
INPUT_FILE3='config.ui'
OUTPUT_FILE='main_ui.py'
OUTPUT_FILE2='bf_ui.py'
OUTPUT_FILE3='config_ui.py'
pyside6-uic -o $OUTPUT_FILE $INPUT_FILE && echo "Compiled $INPUT_FILE"
pyside6-uic -o $OUTPUT_FILE2 $INPUT_FILE2 && echo "Compiled $INPUT_FILE2"
pyside6-uic -o $OUTPUT_FILE3 $INPUT_FILE3 && echo "Compiled $INPUT_FILE3"
exit 0

