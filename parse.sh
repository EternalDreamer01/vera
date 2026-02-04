#!/bin/bash
################################################################################
# @file      parser.sh
# @brief     
# @date      Sa Jul 2025
# @author    
# 
# PROJECT:   VERA
# 
# MODIFIED:  Sat Jul 19 2025
# BY:        
# 
# Copyright (c) 2025 
# 
################################################################################

usage() {
	echo "Usage: $0 { f | m | t } ARGS..."
}

path="$(realpath "$(dirname "$0")/src/parser/")"
option="${1,,}"

shift

case "$option" in
	formatted|f)
		"$path/formatted.sh" "$@"
		;;
	minify|m)
		"$path/minify.sh" "$@"
		;;
	table|t)
		"$path/table.sh" "$@"
		;;
	inspect|i)
		"$path/inspect.sh" "$@"
		;;
	-*)
		"$path/inspect.sh" "$option" "$@"
		;;
	cve)
		"$path/cve.sh" "$@"
		;;
	cve-*|asb-*|pub-*)
		"$path/cve.sh" "$option" "$@"
		;;
	cpe)
		grep --color=auto -i "$@" "$(realpath "$(dirname "$0")/src/asset/cpe.csv")"
		;;
	cpe-versions|cpev)
		grep -i "$@" official-cpe-dictionary_v2.3.xml | grep '<cpe-item' | cut '-d"' -f2 
		;;
	compress|c)
		if [ -f "$1" ]; then
			"$path/compress.sh" "$1" > "$1.tmp"
			mv "$1.tmp" "$1"
		elif [ -d "$1" ]; then
			find "$1" -iname "*.json" -exec sh -c "$path/compress.sh '{}' > '{}.tmp' && mv '{}' '{}.bak' && mv '{}.tmp' '{}' && echo '{}'" \;
		else
			echo "Error: unknown file type"
			exit 1
		fi
		;;
	search|s)
		if [ -z "$1" ]; then
			echo "Error: Product missing" >&2
		fi
		grep --color=auto -rni "$@" "$(realpath "$(dirname "$0")/cvelistV5/cves/")"
		;;
	help|h|"")
		usage
		echo
		echo "Options:"
		echo "  c, compress    Compress a json file, or through a directory recursively"
		echo "  cve            Show CVE details for a given CVE ID"
		echo "  cpe            Search for a CPE"
		echo "  cpev, cpe-versions  Search for a CPE and its version"
		echo "  i, inspect     Show details about a file containing the result"
		echo "  f, formatted   Show total number of registered CVEs, total number of formatted CVEs, valid and ones"
		echo "  m, minify      Minify a file containing a list of package=version"
		echo "  s, search      Search for a product in the CVE List V5"
		echo "  t, table       Overview CVEs for each OS as a table"
		echo "  h, help        Show this help"
		echo
		echo "If the first argument starts by:"
		echo "  - CVE-, it will be passed to the cve command,"
		echo "  - a dash (-) or is a valid inspect command, it will be treated as so."
		;;
	*)
		res="$("$path/inspect.sh" "$option" 2> /dev/null)"

		if [ $? -eq 0 ]; then
			echo "$res"
		else
			echo "Invalid option '$option'"
			usage >&2
		fi
		;;
esac