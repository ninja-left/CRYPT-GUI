#!/bin/bash

source ./venv/bin/activate 
cd ./modules
./compile_rrc.sh
./compile_uic.sh
./compile_fix.sh
deactivate
cd ..
exit 0

