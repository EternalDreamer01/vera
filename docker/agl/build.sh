#!/bin/bash
################################################################################
# @file      build.sh
# @brief     
# @date      We Jul 2025
# @author    Dimitri Simon
# 
# PROJECT:   agl
# 
# MODIFIED:  Wed Jul 09 2025
# BY:        Dimitri Simon
# 
# Copyright (c) 2025 Dimitri Simon
# 
################################################################################

filepath="agl-ivi-demo-qt-qemux86-64.wic.vmdk.xz"
wget "https://download.automotivelinux.org/AGL/release/salmon/latest/qemux86-64/deploy/images/qemux86-64/${filepath}"

sudo=""

if [ $EUID -ne 0 ]; then
	sudo="sudo"
fi

$sudo apt install libguestfs-tools
$sudo virt-tar-out -a "./${filepath}" / - | gzip > rootfs.tar.gz

gunzip -c rootfs.tar.gz | docker import - agl