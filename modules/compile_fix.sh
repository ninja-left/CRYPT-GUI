#!/bin/bash

PREFIX="design"
INPUT_FILE="$PREFIX/main_ui.py"
INPUT_FILE2="$PREFIX/bf_ui.py"
INPUT_FILE3="$PREFIX/config_ui.py"

sed "s/import resources_rc//" $INPUT_FILE >tmp && mv tmp $INPUT_FILE && echo "Fixed $INPUT_FILE"
sed "s/import resources_rc//" $INPUT_FILE2 >tmp && mv tmp $INPUT_FILE2 && echo "Fixed $INPUT_FILE2"
sed "s/import resources_rc//" $INPUT_FILE3 >tmp && mv tmp $INPUT_FILE3 && echo "Fixed $INPUT_FILE3"

