#!/bin/bash

find exploit docker -maxdepth 4 -iname makefile -execdir make clean \;

find exploit docker -maxdepth 4 \
	-name a.out \
	-o -type f -name "poc-*" \
	-o -type f -name "poc" \
	-delete