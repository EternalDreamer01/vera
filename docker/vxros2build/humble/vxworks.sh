#!/bin/bash

sudo=""
if [ $EUID -ne 0 ]; then
	sudo=""
fi

dir="$(realpath "$(dirname "$0")/")"
# exit 0

# As root
$sudo docker build --no-cache -t vxbuild:22.04 $dir/22.04/vxbuild/.
$sudo docker build --no-cache -t vxros2build:humble $dir/22.04/vxros2build/.

$sudo docker run -ti -h vxros2 -e UID=0 -e GID=0 -v ~/Downloads/wrsdk:/wrsdk -v $dir:/work vxros2build:humble
