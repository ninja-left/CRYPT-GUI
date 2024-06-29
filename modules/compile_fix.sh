#!/bin/bash

INPUT_FILE='main_ui.py'
INPUT_FILE2='bf_ui.py'

sed "s/import resources_rc//" $INPUT_FILE >tmp && mv tmp $INPUT_FILE && echo "Fixed $INPUT_FILE"
sed "s/import resources_rc//" $INPUT_FILE2 >tmp && mv tmp $INPUT_FILE2 && echo "Fixed $INPUT_FILE2"

