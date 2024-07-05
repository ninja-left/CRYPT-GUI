#!/bin/bash
PREFIX="design"
INPUT_FILE="$PREFIX/main.ui"
INPUT_FILE2="$PREFIX/bf.ui"
INPUT_FILE3="$PREFIX/config.ui"
OUTPUT_FILE="$PREFIX/main_ui.py"
OUTPUT_FILE2="$PREFIX/bf_ui.py"
OUTPUT_FILE3="$PREFIX/config_ui.py"
pyside6-uic -o $OUTPUT_FILE $INPUT_FILE && echo "Compiled $INPUT_FILE"
pyside6-uic -o $OUTPUT_FILE2 $INPUT_FILE2 && echo "Compiled $INPUT_FILE2"
pyside6-uic -o $OUTPUT_FILE3 $INPUT_FILE3 && echo "Compiled $INPUT_FILE3"
exit 0

