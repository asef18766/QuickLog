#!/bin/bash

gcc -mmmx -msse2 -msse  -maes -march=native -o quick_verify  verify-bench.c -lm -g
make
chmod +x  verify_run.sh
sed -i -e 's/\r$//' verify_run.sh