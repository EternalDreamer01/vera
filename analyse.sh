#!/bin/bash
################################################################################
# @file      analyse.sh
# @brief     
# @date      Sa Jul 2025
# @author    Dimitri Simon
# 
# PROJECT:   VERA
# 
# MODIFIED:  Sat Jul 19 2025
# BY:        Dimitri Simon
# 
# Copyright (c) 2025 Dimitri Simon
# 
################################################################################

usage() {
	echo "Usage: $0 { c | se | sc | sx | sy | u } ARGS..."
}

path="$(realpath "$(dirname "$0")/src/analyser/")"
option="$1"

shift

case "$option" in
	adb-maps|am)
		pid="$1"
		shift
		if ! [[ "$pid" =~ ^[0-9]+$ ]]; then
			pid=$(adb shell pidof "$pid" | tr -d '\r')
		fi
		adb shell cat "/proc/$pid/maps" | grep $@
		;;
	adb-ps-search|aps)
		adb shell 'for p in /proc/[0-9]*; do
			if grep -E -q "'"$1"'" $p/maps 2>/dev/null; then
				pid=$(basename $p)
				name="$(tr "\0" " " < $p/cmdline 2>/dev/null | xargs)"
				user=$(ls -ld $p 2>/dev/null | awk "{print \$3}")
				printf "\x1b[36m% 5s\x1b[0m %-15s %s\n" "$pid" "$user" "$name" | sed -r '\''s/(u0_[a-z0-9]+)/\e[2m\1\e[0m/i'\''
			fi
		done'
		;;
	adb-trace-server|ats)
		adb root | grep production
		adb push src/analyser/utils/frida-server-16.7.19-android-x86_64 /data/local/frida-server
		adb shell chmod +x /data/local/frida-server
		echo "Listening..."
		adb shell /data/local/frida-server
		echo "Connection lost" >&2
		;;
	adb-trace|at)
		name="$(adb shell getprop ro.kernel.qemu.avd_name)"
		type="$(adb shell getprop ro.product.vendor.name | sed 's/sdk_g//; s/_dd//; s/_/-/')"
		sdk="$(adb shell getprop ro.vendor.build.version.sdk)"
		subdir="$name-$type-$sdk"
		process="$1"
		pid="$1"
		filter="${2}"

		if [ -z "$pid" ]; then
			echo "Error: process or PID required" >&2
			exit 1
		elif [ -z "$filter" ]; then
			echo "Error: filter required" >&2
			exit 1
		fi
		if [[ "$1" =~ ^[0-9]+$ ]]; then
			process=$(adb shell cat "/proc/$1/cmdline")
		else
			pid=$(adb shell pidof "$1" | tr -d '\r')
		fi
		mkdir -p "adb-log/$subdir/${process//:/\/}"
		frida-trace -U -f "$process" -i "$filter" >&2 >> "./adb-log/$subdir/$process/$filter.log" &
		# libpath="/data/local/files/usr/bin"
		# adb shell LD_LIBRARY_PATH=$libpath $libpath/ltrace -C -p "$pid" -f -s 256 -u 0 -tt -e sqlite3_open,sqlite3_prepare_v2,sqlite3_step,sqlite3_finalize 2>> "./adb-log/$subdir/$1.log"
		;;
	adb-log|al)
		grep "ms  " "$1" | cut '-d ' -f5 | sort -u
		;;
	adb-symbol|as)
		filename="$1"
		filename="/tmp/${filename##*/}"
		# echo "$filename"
		output="$(adb pull "$1" "$filename" 2>&1)"
		if [ "$?" -ne 0 ]; then
			echo "$output" >&2
			exit 1
		fi
		shift
		if [ -z "$1" ]; then
			objdump -T "$filename"
		else
			objdump -T "$filename" | grep $@
		fi
		;;
	adb-import-exploits|aie)
		adb push exploits /data/local/
		;;
	serve)
		server_root="${1:-exploit/}"
		ip -4 -br --color=always a
		echo
		echo "root is at '$server_root'"
		cd "$server_root" && sudo python3 -m http.server 80
		;;
	search-callers|sc)
		# for CONTAINER in $(docker ps -q); do
		# 	PID=$(docker inspect -f '{{.State.Pid}}' $CONTAINER)
		# 	echo "Attaching to container $CONTAINER (PID $PID)"
		# 	bpftrace -e "
		# 		uprobe:/proc/$PID/root/usr/lib/libfoo.so:symbol_name
		# 		{
		# 			printf(\"container=$CONTAINER %s (%d)\n\", comm, pid);
		# 		}"
		# done

		"$path/search-callers.py" "$@"
		;;
	search-symbol|sy)
		"$path/search-symbol.py" "$@"
		;;
	changelog|c)
		"$path/changelog.py" "$@"
		;;
	search-sxid|sx)
		for image in "$@"; do
			echo -e "\e[36;1m$image\e[0m"
			result="$(docker run -it --rm $image find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -maxdepth 8 -printf '%M %u %g %p\n' 2>&1)"
			if [[ $? -ne 0 && "$result" != *Permission\ denied* ]]; then
				echo "$result" | head -n 2 >&2
				echo >&2
				continue
			fi
			echo "$result" | grep -E '^-' | "$path/sxid-colour.sed"
			echo
		done
		;;
	selinux|se)
		"$path/selinux.sh" "$@"
		;;
	users|u)
		"$path/users.sh" "$@"
		;;
	help|h|"")
		usage
		echo
		echo "Options:"
		echo "  c, changelog           Look for a CVE within changelog"
		echo "  se, selinux            View SELinux configuration"
		echo "  sc, search-callers     Search for callers of a function in all binaries"
		echo "  sx, search-sxid        Search for SUID/SGID files"
		echo "  sy, search-symbol      Search for a symbol in all binaries"
		echo "  u, users               List users"
		echo
		;;
	*)
		echo "Invalid option '$option'"
		usage >&2
		;;
esac