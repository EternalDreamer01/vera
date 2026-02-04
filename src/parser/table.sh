#!/bin/bash
################################################################################
# @file      table.sh
# @brief     
# @date      Tu Jul 2025
# @author    
# 
# PROJECT:   CVE checker
# 
# MODIFIED:  Tue Jul 08 2025
# BY:        
# 
# Copyright (c) 2025 
# 
################################################################################

result=""
DEFAULT_SCANNER=true
SCANNER="*"
FILTER=

if [[ -n "$1" && "$1" != -* ]]; then
	SCANNER="$1"
	DEFAULT_SCANNER=false
	shift
fi

if [ -n "$1" ]; then
	FILTER="$1"
	shift
fi


count_cvss() {
	local min=${1:--1}
	local max=${2:-11}
	
	echo -n "$result" | awk -F: -v min="$min" -v max="$max" '{
		score = $1 + 0
		if (score >= min && score < max) print
	}' | grep -c '^'
}

filter_cvss_product() {
	local min=${1:--1}
	local max=${2:-11}
	echo -n "$result" | awk -F: -v min="$min" -v max="$max" '{ 
		score = $1 + 0
		if (score >= min && score < max) print 
	}' | sed -E 's/^-1:/?:/; s/^([0-9]):/\1.0:/; s/^10\.0:/10:/; s/=([0-9]):/=\1;/' | column -ts : -c 3 | sort -k1,1 -n -t' '
}

count_cves() {
	echo -n "$result" | grep -c '^'
}

count_products() {
	echo -n "$result" | awk -F: '{print $3 ":" $2}' | sort -u | grep -c '^'
}

FIRST_COL_LEN=15
print_row() {
	os="$(printf "%-${FIRST_COL_LEN}s" "$3")"
	result=""
	i=0

	if [ "$SCANNER" != "*" ]; then
		analysis=".$SCANNER"
	fi
	# echo "$SCANNER :: $analysis"

	for f in out/${2}/${1}${analysis}.json; do
		resultfile="$f"
		if [[ "$f" == *.trivy.json ]]; then
			# echo "$f skipped"
			continue
		fi

		if [ -f "$resultfile" ]; then
			result="$(src/parser/utils/read-report.sh "$resultfile" 1 0)"
			((i++))
		fi
	done

	cbt=
	# Merging with CVE Binary Tool results
	if [ "$SCANNER" != "grype" ] && [ "$SCANNER" != "cbt" ] && [ -f "out/${2}/${1}.cbt.json" ]; then
		# echo "fixed:"
		# echo "$result" | grep :fixed

		source src/parser/utils/merge.sh

		cbt="$(merge_results "$result" "out/${2}/${1}.cbt.json" "$FILTER")"

		# echo "CBT applied"
		((i++))
	fi
	result="$(echo -n "$result" | grep -vE ":fixed(:|$)|^$" | sort -u -t: -k5,5)"

	# echo "$result" | grep :not-fix
	# echo "$FILTER"
	if [ "$FILTER" = "--sdv" ]; then
		# echo "filtering..."
		result="$(echo -n "$result" | src/parser/utils/filter-sdv.sh)"
		cbt="$(echo -n "$cbt" | src/parser/utils/filter-sdv.sh)"
		# echo "$result" | sort -u
	fi
	# echo "$result" | head -n 30
	# echo "$cbt" | grep -E 'CVE-2025-6965|CVE-2025-5914'
	
	total=$(count_cves)

	result="$(src/parser/utils/get_online_exploits_multiple.py "$result")"
	cbt="$(src/parser/utils/get_online_exploits_multiple.py "$cbt")"
	# echo "$result" | cut -d: -f7 | sort -u
	# exit 1

	total_epss=$(echo "$result" | cut -d: -f2 | grep -viE 'null|-1|^$' | grep -c '^')
	total_epss_cbt=$(echo "$cbt" | cut -d: -f2 | grep -viE 'null|-1|^$' | grep -c '^')
	total_kev=$(echo -n "$result" | cut -d: -f7 | grep -E '^X$' | grep -c '^')
	total_kev_cbt=$(echo -n "$cbt" | cut -d: -f7 | grep -E '^X$' | grep -c '^')
	total_exploits=$(echo -n "$result" | cut -d: -f9 | grep -E '^[0-9]+\*|P|E$' | grep -c '^')
	total_exploits_cbt=$(echo -n "$cbt" | cut -d: -f9 | grep -E '^[0-9]+\*|P|E$' | grep -c '^')

	critical=$(count_cvss 9)
	high=$(count_cvss 7 9)
	medium=$(count_cvss 4 7)
	low=$(count_cvss 0 4)
	unknown=$(count_cvss -1 0)

	result="$cbt"
	total_cbt=$(count_cves)
	critical_cbt=$(count_cvss 9)
	high_cbt=$(count_cvss 7 9)
	medium_cbt=$(count_cvss 4 7)
	low_cbt=$(count_cvss 0 4)
	unknown_cbt=$(count_cvss -1 0)

	if [ -n "$cbt" ]; then
		if [ $total_cbt -gt 0 ]; then
			total="$total + $total_cbt"
		fi
		if [ $total_epss_cbt -gt 0 ]; then
			total_epss="$total_epss + $total_epss_cbt"
		fi
		if [ $total_kev_cbt -gt 0 ]; then
			total_kev="$total_kev + $total_kev_cbt"
		fi
		if [ $total_exploits_cbt -gt 0 ]; then
			total_exploits="$total_exploits + $total_exploits_cbt"
		fi
		if [ $critical_cbt -gt 0 ]; then
			critical="$critical + $critical_cbt"
		fi
		if [ $high_cbt -gt 0 ]; then
			high="$high + $high_cbt"
		fi
		if [ $medium_cbt -gt 0 ]; then
			medium="$medium + $medium_cbt"
		fi
		if [ $low_cbt -gt 0 ]; then
			low="$low + $low_cbt"
		fi
		if [ $unknown_cbt -gt 0 ]; then
			unknown="$unknown + $unknown_cbt"
		fi
	fi

	printf "\e[1m| $os $i "
	printf "\e[0;1;2m| %-9s \e[1;2;33m| %-9s \e[0;1;33m| %-9s \e[1;31m| %-9s \e[1;35m| %-9s |" \
		"$unknown" "$low" "$medium" "$high" "$critical"
	printf "\e[0;1m %-9s |\e[0m %-9s \e[1;31m| %-9s \e[0;36m| %-9s |\e[0m\n" \
		"$total" "$total_epss" "$total_kev" "$total_exploits"
}

result_os() {
	print_row "$cves_type" "os/$@"
}

result_fw() {
	print_row "$cves_type" "fw/$@"
}

printf "\e[1m| %-${FIRST_COL_LEN}s   \e[1;2m| *Unknown* \e[1;2;33m| LOW       \e[0;1;33m| MEDIUM    \e[1;31m| HIGH      \e[1;35m| CRITICAL  |\e[0;1m TOTAL     |\e[0m EPSS      \e[1;31m| KEV       \e[0;36m| Exploits  |\e[0m\n" \
	"OS"
printf "\e[1m|:-%-${FIRST_COL_LEN}s  \e[1;2m|:-:        \e[1;2;33m|:-:        \e[0;1;33m|:-:        \e[1;31m|:-:        \e[1;35m|:-:        |\e[0;1m:-:        |\e[0m:-:        \e[1;31m|:-:        \e[0;36m|:-:        |\e[0m\n"

cves_type=upgraded
if [ "$DEFAULT_SCANNER" = true ]; then
	SCANNER=grype
fi
if [ "$SCANNER" = "grype" ]; then
	result_os "eclipse-sdv/158" "Eclipse S-CORE"
	result_os "ubuntu/22.04" "Ubuntu 22.04"
	result_os "ubuntu/22.04" "Ubuntu 20.04"
	result_os "vxbuild/22.04" "VxWorks 7"
	result_os "vxros2build/humble" "VxWorks 7 ROS2"
	result_os "qnxros2/rolling" "QNX Neutrino"
	result_os "zephyr/latest" "Zephyr"
	result_os "teslaos/amd-5.4" TeslaOS
	result_os "automotive-sig/9-qemux86_64" "AutoSD"
	result_os "ros/humble-perception-jammy" ROS2
fi

cves_type=raw
if [ "$DEFAULT_SCANNER" = true ]; then
	SCANNER=vanir
fi
if [ "$SCANNER" = "vanir" ] || [ "$SCANNER" = "cbt" ]; then
	result_os "aaos/34-ext9" "AAOS 34"
	result_os "android/32" "Android 32"
	result_os "android/30/x86_64" "Android 30"
fi

if [ "$DEFAULT_SCANNER" = true ]; then
	SCANNER=yocto
fi
if [ "$SCANNER" = "yocto" ] || [ "$SCANNER" = "cbt" ]; then
	result_os "agl/20.0.1-trout-agl-ivi-demo-qt-qemux86_64" "AGL"
fi


# echo
# echo "\e[1m| Framework                      \e[0m| Version $^1$           | Release $^2$   \e[1;2m| *Unknown* \e[1;2;33m| LOW  \e[1;33m| MEDIUM \e[1;31m| HIGH \e[1;35m| CRITICAL |\e[0;1m TOTAL |\e[0m Aff. Pkg. |"
# echo "\e[1m|:-                              \e[0m|:-                      |:-              \e[1;2m|:-:        \e[1;2;33m|:-:   \e[1;33m|:-:     \e[1;31m|:-:   \e[1;35m|:-:       |\e[0;1m:-:    |\e[0m:-:        |"

# result_fw "nvidia/cuda/11.4.3-cudnn8-runtime-ubi8" "NVIDIA CUDA" "11.4.3 /8.9"
