#!/bin/sh

filepath="auto-osbuild-qemu-autosd9-qa-regular-x86_64-1944701195.f3dd2029.raw.xz"
link_image="https://download.autosd.sig.centos.org/AutoSD-9/nightly/raw-images/$filepath"

# Image
wget "$link_image"
# Signature
wget "$link_image.sha256"

sha256sum -c "./${filepath}.sha256"
