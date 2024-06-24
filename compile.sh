#!/bin/bash

source ./venv/bin/activate 
cd ./modules
./compile_rrc.sh
./compile_uic.sh
deactivate
cd ..
exit 0

