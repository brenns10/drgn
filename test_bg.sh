#!/bin/bash

for ((i = 1;; i++)); do
	echo "Run $i" > qemu.log
	python -m vmtest.vm -k 5.8.0-rc7-vmtest1 true < /dev/null &>> qemu.log || exit 1
done
