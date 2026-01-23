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

print_selinux() {
	local image="$1"
	docker run \
		--rm \
		-it \
		-u 0 \
		--entrypoint /bin/sh \
		"$image" \
		-c 'if command -v sestatus 2>&1 >/dev/null; then grep "^SELINUX" /etc/selinux/config; sestatus | sed -E "s/ \s+/ /g" || echo "SELinux: $(getenforce)"; else echo "SELinux not installed"; fi' \
		| sed 's/^/  /'
}

images=("$@")

for ((i=0; i<${#images[@]}-1; i++)); do
	image="${images[i]}"
	echo -e "\e[36;1m$image\e[0m"
	print_selinux "$image"
	echo
done

# Handle the last one separately
last="${images[-1]}"
echo -e "\e[36;1m$last\e[0m"
print_selinux "$last"
