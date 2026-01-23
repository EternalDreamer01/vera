#!/bin/bash
################################################################################
# @file      run.sh
# @brief     
# @date      Fr Jul 2025
# @author    Dimitri Simon
# 
# PROJECT:   VERA
# 
# MODIFIED:  Fri Jul 11 2025
# BY:        Dimitri Simon
# 
# Copyright (c) 2025 Dimitri Simon
# 
################################################################################


# echo "$@"
default_cmd="bash"

if [ -z "$1" ] || [ "$1" = "h" ] || [ "$1" = "help" ]; then
	echo "Usage: $(basename "$0") { DOCKER-IMAGE | FILE-IMAGE } [CMD] [ARGS...]"
	echo "  Default CMD: $default_cmd"
	echo "  when it isn't provided or equal '-'"
	exit 0
fi

image_name="$1"
cmd="$2"

other=("$@")
other=("${other[@]:2}")


if [ -z "$cmd" ] || [ "$cmd" == - ]; then
	cmd="$default_cmd"
fi

if [[ "${image_name: -6}" == ".qcow2" ]]; then
	qemu-system-x86_64 \
	-cpu host -machine type=q35,accel=kvm \
		-m 12288 \
		-device qxl-vga,vgamem_mb=256 \
		-snapshot \
		-netdev id=net00,type=user,hostfwd=tcp::2222-:22 \
		-device virtio-net-pci,netdev=net00 \
		-drive if=virtio,format=qcow2,file=$image_name

else
	SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

	docker run \
		-it \
		--rm \
		--privileged \
		--cgroupns=host \
		-v /sys/fs/cgroup:/sys/fs/cgroup:ro \
		-v "$SCRIPT_DIR/exploit:/exploit:rw" \
		-w /exploit \
		"${other[@]}" \
		"$image_name" "$cmd"
fi