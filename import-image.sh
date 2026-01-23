#!/bin/bash

if [ $# -lt 2 ]; then
	echo "Usage: $0 <path-to-vmdk> <image-name>" >&2
	echo "Imports a VMDK image into Docker" >&2
	exit 1
fi

sudo=""
if [ "$EUID" -ne 0 ]; then
	sudo="sudo"
fi

filepath="$1"

GREEN="\033[32m"
RED="\033[31m"
BLUE="\033[34m"
YELLOW="\033[33m"
NC="\033[0m" # No Color

# SUCCESS="${GREEN}[+]"
# INFO="${BLUE}[*]"
# FAIL="${RED}[-]"


while true; do
	if [ "${filepath: -3}" == ".xz" ]; then
		xz -d "$filepath"
		filepath="${filepath%.xz}"
	elif [ "${filepath: -4}" == ".tar" ]; then
		tar -xvf "$filepath"
		filepath="${filepath%.tar}"
	elif [ "${filepath: -3}" == ".gz" ]; then
		gunzip "$filepath"
		filepath="${filepath%.gz}"
	elif [ "${filepath: -4}" == ".zip" ]; then
		unzip "$filepath"
		filepath="${filepath%.zip}"
	else
		break
	fi
done

echo -e "${BLUE}[*] Target image: ${filepath} ${NC}"

rootfs=""
if [ "${filepath: -5}" == ".vmdk" ]; then
	rootfs="rootfs.tar.gz"
	$sudo virt-tar-out -a "$filepath" / - | gzip > "$rootfs"
	if [ $? -ne 0 ]; then
		echo -e "${RED}[-] Export to tar.gz failed${NC}" >&2
		exit 1
	fi
	echo -e "${GREEN}[+] Export to tar.gz succeed${NC}"
	# exit 0
	gunzip -c "$rootfs" | docker import - "$2"

elif [ "${filepath: -4}" == ".raw" ]; then
	VBoxManage "${filepath}" "${filepath%raw}vdi"

elif [ "${filepath: -6}" == ".qcow2" ]; then
	qemu-img convert -f qcow2 "$filepath" -O vmdk "${filepath%qcow2}vmdk"

elif [ "${filepath: -4}" == ".img" ]; then
	# rootfs="rootfs.tar"
	# tmpraw="${filepath%.img}.raw"
	$sudo virt-tar-out -a "${filepath}" / - | docker import - "$2"
	# qemu-img convert -f raw -O vmdk "$filepath" "$tmpraw"
	# ./import-image.sh "$tmpraw" "$2"
	# tar -c "$tmpraw" > "$rootfs"
	
	if [ "$(docker image ls --format json -f "reference=$2" | jq -r .Size)" = "0B" ]; then
		docker image rm "$2" > /dev/null
		echo -e "${RED}[-] Export to docker failed${NC}" >&2
		exit 1
	fi
	# echo -e "${BLUE}[*] Export to tar succeed${NC}"
	# #rm "$tmpraw"
	# docker import "$rootfs" "$2"
	# exit 0
else
	echo -e "${RED}[-] Unsupported file format '${filepath##*.}' ($filepath)" >&2
	exit 1
fi

if [ $? -ne 0 ]; then
	echo -e "${RED}[-] Docker import failed" >&2
	exit 1
fi
echo -e "${GREEN}[+] Docker import succeed${NC}"

# rm "$rootfs"
