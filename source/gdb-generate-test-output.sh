#!/bin/bash
#runs a program in gdb, prints result afterwards using runtest script

gdb -quiet -batch -x source/gdb-scripts -ex 'runtest' --args ${@:1} \
    | grep -A 9999999999 "= state ========" \
    | tail -n +2 \



