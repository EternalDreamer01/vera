#!/bin/bash

find exploit docker -iname makefile -exec sh -c 'cd {} && make clean' \;
