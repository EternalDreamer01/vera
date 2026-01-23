#!/bin/bash
################################################################################
# @file      ff.sh
# @brief     
# @date      Mo Jul 2025
# @author    Dimitri Simon
# 
# PROJECT:   CVE checker
# 
# MODIFIED:  Tue Jul 08 2025
# BY:        Dimitri Simon
# 
# Copyright (c) 2025 Dimitri Simon
# 
################################################################################

usage() {
	echo "Usage: $(basename "$0") IMAGE..." >&2
}

print_users() {
	local image="$1"
	docker run \
		--rm \
		-it \
		-u 0 \
		--entrypoint /bin/sh \
		"$image" \
		-c 'cat /etc/passwd | grep -E "sh$"' \
		| sed 's/^/  /'
}

images=("$@")

for ((i=0; i<${#images[@]}-1; i++)); do
	image="${images[i]}"
	echo -e "\e[36;1m$image\e[0m"
	print_users "$image"
	echo
done

# Handle the last one separately
last="${images[-1]}"
echo -e "\e[36;1m$last\e[0m"
print_users "$last"