#!/bin/bash

trap 'kill $!; wait' EXIT
(while true; do sleep 540; echo Keep alive; done) &
./rrsh.py -v client osandov.com bash -i
