#!/bin/sh

filepath="auto-osbuild-qemu-autosd9-qa-regular-x86_64-1944701195.f3dd2029.raw"

xz -d "./${filepath}.xz"

sudo=""

if [ $EUID -ne 0 ]; then
	sudo="sudo"
fi

$sudo apt install libguestfs-tools
$sudo virt-tar-out -a "./${filepath}" / - | docker import - automotive-sig