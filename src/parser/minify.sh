#!/bin/sh
################################################################################
# @file      minify.sh
# @brief     
# @date      Mo Jul 2025
# @author    
# 
# PROJECT:   CVE checker
# 
# MODIFIED:  Tue Jul 08 2025
# BY:        
# 
# Copyright (c) 2025 
# 
################################################################################

usage() {
	echo "Usage: $(basename "$0") <file> [<strip python>]" >&2
	echo "  <strip python> expects a boolean (false/0/true/1) whether python dependencies should be removed"
}
if [ -z "$1" ]; then
	echo "Error: No input file specified" >&2
	usage
	exit 1
elif [ ! -f "$1" ]; then
	echo "Error: Invalid file '$1'" >&2
	usage
	exit 1
fi

input="$1"
strip_python="${2:-false}"
output_file="${1%.*}.min.csv"

sort -u "$input" | grep ' ' | "$(realpath "$(dirname "$0")/utils/begin-minify.sed")" > "$output_file"

"$(realpath "$(dirname "$0")/utils/recursive-minify.py")" "$strip_python" "$output_file" "$output_file.tmp" # | "$(realpath "$(dirname "$0")/sed/recursive-minify.sed")"
mv "$output_file.tmp" "$output_file"
