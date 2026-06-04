#!/bin/bash
################################################################################
# @file      table.sh
# @brief     
# @date      Tu Jul 2025
# @author    Dimitri Simon
# 
# PROJECT:   CVE checker
# 
# MODIFIED:  Tue Jul 08 2025
# BY:        Dimitri Simon
# 
# Copyright (c) 2025 Dimitri Simon
# 
################################################################################

result=""
DEFAULT_SCANNER=true
SCANNER="*"
FILTER=
OUT_TYPE=""

# $0 [<scanner> [<filter>]]

if [[ -n "$1" && "$1" != -* ]]; then
	SCANNER="$1"
	DEFAULT_SCANNER=false
	shift
fi

if [ -n "$1" ]; then
	FILTER="$1"
	shift
fi

if [ -n "$1" ]; then
	OUT_TYPE="$1"
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

	if [ -f out/${2}/${1}${analysis}.json ]; then
		resultfile="out/${2}/${1}${analysis}.json"
		# if [[ "$f" == *.trivy.json ]]; then
		# 	# echo "$f skipped"
		# 	continue
		# fi

		if [ -f "$resultfile" ]; then
			result="$(src/parser/utils/read-report.sh "$resultfile" 1 0)"
			((i++))
		fi
	fi

	# echo 1

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
	# echo 2
	if [ "$FILTER" = "--sdv" ]; then
		# echo "filtering..."
		result="$(echo -n "$result" | src/parser/utils/filter-sdv.sh)"
		cbt="$(echo -n "$cbt" | src/parser/utils/filter-sdv.sh)"
		# echo "$result" | sort -u
	fi
	# echo 3
	# echo 1
	# echo "$result" | head -n 30
	# echo "$cbt" | grep -E 'CVE-2025-6965|CVE-2025-5914'
	
	total=$(count_cves)
	# echo 4

	result="$(src/parser/utils/get_online_exploits_multiple.py "$result" 1)"
	# echo 4.1
	cbt="$(src/parser/utils/get_online_exploits_multiple.py "$cbt" 1)"
	# echo "$result" | cut -d: -f7 | sort -u
	# exit 1
	# echo 5

	total_epss=$(echo -n "$result" | cut -d: -f2 | grep -viE 'null|-1|^$' | grep -c '^')
	total_epss_cbt=$(echo -n "$cbt" | cut -d: -f2 | grep -viE 'null|-1|^$' | grep -c '^')
	total_kev=$(echo -n "$result" | cut -d: -f7 | grep -E '^X$' | grep -c '^')
	total_kev_cbt=$(echo -n "$cbt" | cut -d: -f7 | grep -E '^X$' | grep -c '^')
	total_exploits=$(echo -n "$result" | cut -d: -f9 | grep -E '^[0-9]+\*|P|E$' | grep -c '^')
	total_exploits_cbt=$(echo -n "$cbt" | cut -d: -f9 | grep -E '^[0-9]+\*|P|E$' | grep -c '^')

	total_rce=$(echo "$result" | cut -d: -f6 | grep -i "rce" | grep -c '^')
	total_rce_cbt=$(echo "$cbt" | cut -d: -f6 | grep -i "rce" | grep -c '^')
	total_lpe=$(echo "$result" | cut -d: -f6 | grep -i "lpe" | grep -c '^')
	total_lpe_cbt=$(echo "$cbt" | cut -d: -f6 | grep -i "lpe" | grep -c '^')
	total_id=$(echo "$result" | cut -d: -f6 | grep -i "id" | grep -c '^')
	total_id_cbt=$(echo "$cbt" | cut -d: -f6 | grep -i "id" | grep -c '^')
	total_dos=$(echo "$result" | cut -d: -f6 | grep -i "dos" | grep -c '^')
	total_dos_cbt=$(echo "$cbt" | cut -d: -f6 | grep -i "dos" | grep -c '^')
	total_unknown=$(echo "$result" | cut -d: -f6 | grep -i "?" | grep -c '^')
	total_unknown_cbt=$(echo "$cbt" | cut -d: -f6 | grep -i "?" | grep -c '^')
	# echo "$cbt"

	total_rce_num=
	total_lpe_num=
	total_id_num=
	total_dos_num=
	total_unknown_num=

	total_num=$total
	total_epss_num=$total_epss

	critical=$(count_cvss 9)
	high=$(count_cvss 7 9)
	medium=$(count_cvss 4 7)
	low=$(count_cvss 0 4)
	unknown=$(count_cvss -1 0)

	critical_num=$critical
	high_num=$high
	medium_num=$medium

	result="$cbt"
	total_cbt=$(count_cves)
	critical_cbt=$(count_cvss 9)
	high_cbt=$(count_cvss 7 9)
	medium_cbt=$(count_cvss 4 7)
	low_cbt=$(count_cvss 0 4)
	unknown_cbt=$(count_cvss -1 0)

	if [ -n "$cbt" ]; then
		if [ $total_cbt -gt 0 ]; then
			total_num=$((total + total_cbt))
			total="$total + $total_cbt"
		fi
		if [ $total_epss_cbt -gt 0 ]; then
			total_epss_num=$((total_epss + total_epss_cbt))
			total_epss="$total_epss + $total_epss_cbt"
		fi
		if [ $total_kev_cbt -gt 0 ]; then
			total_kev="$total_kev + $total_kev_cbt"
		fi
		if [ $total_exploits_cbt -gt 0 ]; then
			total_exploits="$total_exploits + $total_exploits_cbt"
		fi
		if [ $critical_cbt -gt 0 ]; then
			critical_num=$((critical + critical_cbt))
			critical="$critical + $critical_cbt"
		fi
		if [ $high_cbt -gt 0 ]; then
			high_num=$((high + high_cbt))
			high="$high + $high_cbt"
		fi
		if [ $medium_cbt -gt 0 ]; then
			medium_num=$((medium + medium_cbt))
			medium="$medium + $medium_cbt"
		fi
		if [ $low_cbt -gt 0 ]; then
			low="$low + $low_cbt"
		fi
		if [ $unknown_cbt -gt 0 ]; then
			unknown="$unknown + $unknown_cbt"
		fi

		if [ $total_rce_cbt -gt 0 ]; then
			total_rce_num=$((total_rce + total_rce_cbt))
			total_rce="$total_rce + $total_rce_cbt"
		fi
		if [ $total_lpe_cbt -gt 0 ]; then
			total_lpe_num=$((total_lpe + total_lpe_cbt))
			total_lpe="$total_lpe + $total_lpe_cbt"
		fi
		if [ $total_id_cbt -gt 0 ]; then
			total_id_num=$((total_id + total_id_cbt))
			total_id="$total_id + $total_id_cbt"
		fi
		if [ $total_dos_cbt -gt 0 ]; then
			total_dos_num=$((total_dos + total_dos_cbt))
			total_dos="$total_dos + $total_dos_cbt"
		fi
		if [ $total_unknown_cbt -gt 0 ]; then
			total_unknown_num=$((total_unknown + total_unknown_cbt))
			total_unknown="$total_unknown + $total_unknown_cbt"
		fi
	fi

	printf "\e[1m| $os $i "
	if [ "$OUT_TYPE" = "--types" ]; then
		printf "\e[1;35m| %-9s \e[1;31m| %-9s \e[1;33m| %-9s \e[1;34m| %-9s \e[0;1;2m| %-9s \e[0;1m| %-9s |\e[0m\n" \
			"$total_rce ($total_rce_num)" "$total_lpe ($total_lpe_num)" "$total_id ($total_id_num)" "$total_dos ($total_dos_num)" "$total_unknown ($total_unknown_num)" "$total ($total_num)"
		echo $((total_rce_num + total_lpe_num + total_id_num + total_dos_num + total_unknown_num))
	else
		printf "\e[0;1;2m| %-9s \e[1;2;33m| %-9s \e[0;1;33m| %-9s \e[1;31m| %-9s \e[1;35m| %-9s |" \
			"$unknown" "$low" "$medium ($medium_num)" "$high ($high_num)" "$critical ($critical_num)"
		printf "\e[0;1m %-15s %s |\e[0m %-15s \e[1;31m| %-9s \e[0;36m| %-9s |\e[0m\n" \
			"$total ($total_num)" $((high_num + critical_num)) "$total_epss ($total_epss_num)" "$total_kev" "$total_exploits"
	fi
}

result_os() {
	print_row "$cves_type" "os/$@"
}

result_fw() {
	print_row "$cves_type" "fw/$@"
}

if [ "$OUT_TYPE" = "--types" ]; then
	printf "\e[1m| %-${FIRST_COL_LEN}s   \e[1;35m| RCE       \e[1;31m| LPE       \e[0;1;33m| ID        \e[1;34m| DoS       \e[0;1;2m| *UNKNOWN* |\e[0;1m\n" \
		"OS"
	printf "\e[1m|:-%-${FIRST_COL_LEN}s  \e[1;35m|:-:        \e[1;31m|:-:        \e[0;1;33m|:-:        \e[1;34m|:-:        \e[0;1;2m|:-:        |\e[0;1m\n"
else
	printf "\e[1m| %-${FIRST_COL_LEN}s   \e[1;2m| *Unknown* \e[1;2;33m| LOW       \e[0;1;33m| MEDIUM    \e[1;31m| HIGH      \e[1;35m| CRITICAL  |\e[0;1m TOTAL           |\e[0m EPSS            \e[1;31m| KEV       \e[0;36m| Exploits  |\e[0m\n" \
		"OS"
	printf "\e[1m|:-%-${FIRST_COL_LEN}s  \e[1;2m|:-:        \e[1;2;33m|:-:        \e[0;1;33m|:-:        \e[1;31m|:-:        \e[1;35m|:-:        |\e[0;1m:-:              |\e[0m:-:              \e[1;31m|:-:        \e[0;36m|:-:        |\e[0m\n"
fi

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
