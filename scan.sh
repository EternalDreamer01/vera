#!/bin/bash
################################################################################
# @file      scan.sh
# @brief     
# @date      Su Aug 2025
# @author    Dimitri Simon
# 
# PROJECT:   VERA
# 
# MODIFIED:  Sun Aug 17 2025
# BY:        Dimitri Simon
# 
# Copyright (c) 2025 Dimitri Simon
# 
################################################################################

scanner="$1"

getprop() { adb shell getprop $1; }

succeed() { echo -e "\e[32;1m[+]\e[0m $@"; }
info() { echo -e "\e[34;1m[*]\e[0m $@"; }
fail() { echo -e "\e[31;1m[-]\e[0m $@" >&2; }

cbt_args="cve-bin-tool"
# cbt_args="python3 -m cve_bin_tool"
cbt_path=
# if [ -d $HOME/Documents/cve-bin-tool/cve_bin_tool ]; then
# 	cbt_path="$HOME/Documents/cve-bin-tool"
# elif [ -d $HOME/cve-bin-tool/cve_bin_tool ]; then
# 	cbt_path="$HOME/cve-bin-tool"
# else
# 	cbt_args="cve-bin-tool"
# fi

exec_cbt() {
	if [ -n "$cbt_path" ]; then
		cd "$cbt_path"
	fi
	echo $cbt_args $@ #"$scan_dir" --exploits --metrics -f json -o "$out_dir/raw.cbt.json"
	$cbt_args $@ #"$scan_dir" --exploits --metrics -f json -o "$out_dir/raw.cbt.json"
	if [ -n "$cbt_path" ]; then
		cd -
	fi
}

if [[ -z $scanner ]]; then
	echo "Usage: $0 SCANNER IMAGE..." >&2
	echo "Available scanners: cbt, osv, grype, trivy" >&2
	exit 1

elif [[ $scanner == "cbt" && -z "$2" || "$2" == "-e" || "$2" == "--emulator" ]]; then
	info "Scanning using ADB..."

	scan_dir="$HOME/.cache/vera/emulator"
	adb_path="$(adb shell find / -type d -name lib -o -name lib64 -o -name "*.apk" 2> /dev/null)" #"$(adb shell 'echo "/data/:$PATH"' | tr ':' '\n' | sed -r 's/(\/\w+).+/\1/' | sort -u | tr '\n' ' ')"
	
	emulos=net.bt.name				# Android
	hardware_type=ro.hardware.type	# '' or 'Automotive'
	arch=ro.product.cpu.abi			# x86_64
	sdk=ro.build.version.sdk		# API, e.g 30

	devname="$(getprop $hardware_type)"
	if [ -n "$devname" ]; then
		devname="-$devname"
	fi
	devname="$(getprop $emulos)$devname/$(getprop $sdk)/$(getprop $arch)"
	devname="${devname,,}"
	scan_dir="$scan_dir/$devname"
	info "Scanning $devname"

	if ! [ -d "$scan_dir" ]; then
		info "Pulling directories..."
		adb root
		mkdir -p "$scan_dir"
		for dir in $adb_path; do
			echo "  Pulling $dir"
			mkdir -p "$scan_dir$dir"
			adb pull "$dir" "$scan_dir$dir"
		done
	fi

	info "Removing all symlinks and JNI libraries..."
	find "$scan_dir" -type l -o -name "*jni*.so" -delete

	info "Extracting all APKs..."
	find "$scan_dir" -type f -name "*.apk" -exec unzip -o -q -d '{}.extracted' '{}' \;
	
	info "Removing all non-libraries..."
	find "$scan_dir" -type f ! -name "*.so" -delete

	# info "Removing all non-ELF..."
	# find "$scan_dir" -type f -exec sh -c '
	# 	for f; do
	# 		if file -b "$f" | grep -q "^ELF"; then
	# 			continue  # keep ELF
	# 		fi
	# 		# Symlink, OR not ELF
	# 		rm -f "$f"
	# 	done
	# ' sh '{}' +

	out_dir="out/os/$devname"
	mkdir -p "$out_dir"
	exec_cbt "$scan_dir" --exploits --metrics -f json -o "$out_dir/raw.cbt.json"
	exit 0
fi

shift

for image_name in "$@"; do
	cmd="bash"
	os_path="${image_name//:/\/}"
	scan_bin_path="os/${os_path}"
	basename="raw"
	if [[ $image_name == *-upgraded ]]; then
		basename="upgraded"
		os_path="${os_path%-*}"
	fi

	echo "Output: out/os/$os_path/$basename.$scanner.json"
	output_filepath="out/os/$os_path/$basename.$scanner.json"
	# exit 1

	if [[ $scanner == "cbt" ]]; then
		container_name="tmp-copy"
		docker rm $(docker ps -a -q --filter=name=$container_name) 2> /dev/null
		docker create --rm --name "$container_name" "$image_name" sh
		if [ $? -ne 0 ]; then
			echo "Error: docker run failed" >&2
			exit 1
		fi
		# docker start "$container_name"

		mkdir -p "$scan_bin_path"
		# docker ps -a --filter "id=${container_id:0:12}" --format "Container {{.ID}} created from image {{.Image}}"
		echo "Extracting binaries from container $container_name..."
		# docker exec "$container_name" find /usr/bin /usr/lib -type l -delete
		# docker cp "$container_name:/usr/bin" - > "/tmp/bin.tar"
		docker cp "$container_name:/usr/lib" - > "/tmp/lib.tar"
		if [ $? -ne 0 ]; then
			echo "Error: docker cp failed" >&2
			exit 1
		fi
		docker rm $(docker ps -a -q --filter=name=$container_name)

		echo "Scanning binary path: $scan_bin_path"
		# tar -xf "/tmp/bin.tar" -C "$scan_bin_path"
		tar -xf "/tmp/lib.tar" -C "$scan_bin_path"
		# rm "$scan_bin_path/bin.tar" "$scan_bin_path/lib.tar"
		find "$scan_bin_path" -type l -delete
		
		# find "$scan_bin_path" \
		# 	-name '*jni*.so' \
		# 	-o -name "*.tar" \
		# 	-o -name "*.py" \
		# 	-o -name "*.sh"
				# exit 0
		# scan_bin_path="$image_name"
		info "Removing all non-libraries..."
		find "$scan_bin_path" -type f -a ! -name "*.so" -delete

		exec_cbt "$scan_bin_path/lib" --exploits --metrics -f json -o "$output_filepath"

	elif [[ $scanner == "osv" ]]; then
		osv-scanner scan image -f json --verbosity warn --output "$output_filepath" "$image_name"
	
	elif [[ $scanner == "grype" ]]; then
		args=""
		if [[ "$image_name" == agl || "$image_name" == agl:* ]]; then
			args="--distro"
			exit 1
		fi
		grype "$image_name" --scope all-layers -o json --file "$output_filepath"
	
	elif [[ $scanner == "trivy" ]]; then
		trivy image --scanners vuln -f json -o "$output_filepath" "$image_name"
		
	else
		echo "Error: unknown scanner '$scanner'" >&2
		exit 1
	fi
done
