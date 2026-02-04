#!/bin/bash
################################################################################
# @file      result.sh
# @brief     
# @date      Mo Jul 2025
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


usage() {
	echo "Usage: $(basename "$0") [option] FILE" >&2
}

default_resultfile="$(realpath "$(dirname "$0")/../../out/os")"
resultfile="$default_resultfile"
result=
result_cbt=

parse_args() {
	default_resultfile="$1"
	resultfile="$default_resultfile"

	if [ ! -e "$resultfile" ]; then
		if [[ "$resultfile" == *:* ]]; then
			resultfile="${resultfile/:/\/}"
		fi
		if [ -e "out/os/$resultfile" ]; then
			resultfile="out/os/$resultfile"
		fi
	fi

	if [[ "$resultfile" != *.json && -f "$resultfile.json" ]]; then
		resultfile="$resultfile.json"
	fi

	if [ $# -gt 0 ] && [ -f "${!#}" ]; then
		resultfile="${!#}"
	fi

	if [ ! -f "$resultfile" ] && [ ! -d "$resultfile" ]; then
		echo "Error: File '$resultfile' doesn't exist" >&2
		exit 1
	fi
}



ARGS="$@"
severity=
severity_min=-1
severity_max=11
pkg_type=
FILTER_CVE=
CUSTOM_FILTER=
CUSTOM_FILTER_OUT=
help=false
show_filename=false
filename="*"
no_ignore_dir=false
PREVIEW_EXPLOIT=false
cves_sort=cvss
unify=false
csv_format=false
merge_cbt=false
any_state=0
FILTER_OUT_IMPACT=
SHOW_VENDOR=true

scanner=()
exclude=()
include=()

join_by() {
	local d=${1-} f=${2-}
	if shift 2; then
		printf %s "$f" "${@/#/$d}"
	fi
}

count_cvss() {
	local min=${1:--1}
	local max=${2:-11}
	
	echo "$result" | awk -F: -v min="$min" -v max="$max" '{ 
		score = $1 + 0
		if (score >= min && score < max) print 
	}' | wc -l
}

filter_cvss_product() {
	local min=${1:--1}
	local max=${2:-11}
	output="$(echo "$result" | awk -F: -v min="$min" -v max="$max" '{ 
		score = $1 + 0
		if (score >= min && score < max) print 
	}' | sed -E 's/^-1:/?:/; s/^([0-9]):/\1.0:/; s/^10\.0:/10:/; s/=([0-9]):/=\1;/' | sort_option_switch)"
	# echo "$result" | head -n 5

	if [ "$csv_format" = true ]; then
		echo "$output"
	else
		echo "$output" | column -ts : -c 3 | sort -k1,1 -n -t' '
	fi
}

count_cves() {
	echo "$result" | wc -l
}

print_overview() {
	if [ -z "$severity" ]; then
		total=$(count_cves)

		total_epss=$(echo "$result" | cut -d: -f2 | grep -viE 'null|-1|^$' | grep -c '^')
		total_epss_cbt=$(echo "$result_cbt" | cut -d: -f2 | grep -viE 'null|-1|^$' | grep -c '^')
		total_kev=$(echo -n "$result" | cut -d: -f7 | grep -E '^X$' | grep -c '^')
		total_kev_cbt=$(echo -n "$result_cbt" | cut -d: -f7 | grep -E '^X$' | grep -c '^')
		total_exploits=$(echo -n "$result" | cut -d: -f6 | grep -E '^[0-9]+\*|P|E$' | grep -c '^')
		total_exploits_cbt=$(echo -n "$result_cbt" | cut -d: -f6 | grep -E '^[0-9]+\*|P|E$' | grep -c '^')

		critical=$(count_cvss 9)
		high=$(count_cvss 7 9)
		medium=$(count_cvss 4 7)
		low=$(count_cvss 0 4)
		unknown=$(count_cvss -1 0)

		result="$result_cbt"
		total_cbt=$(count_cves)
		critical_cbt=$(count_cvss 9)
		high_cbt=$(count_cvss 7 9)
		medium_cbt=$(count_cvss 4 7)
		low_cbt=$(count_cvss 0 4)
		unknown_cbt=$(count_cvss -1 0)

		if [ -n "$result_cbt" ]; then
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
		# echo -e "\e[4mAffected packages:\e[0m $(echo "$result" | awk -F: '{print $3 ":" $2}' | sort -u | wc -l)"
		echo -e "\e[4mCVEs:           \e[0m $total"
		echo -e "\e[4mKEVs:           \e[0m $total_kev"
		echo -e "\e[4mExploits:       \e[0m $total_exploits"
		echo
		echo -e "  \e[35mCRITICAL:      $critical\e[0m"
		echo -e "  \e[31mHIGH:          $high\e[0m"
		echo -e "  \e[33mMEDIUM:        $medium\e[0m"
		echo -e "  \e[2;33mLOW:           $low\e[0m"
		echo -e "  \e[1;2mUNKNOWN:       $unknown\e[0m"

	elif [ "$severity" = "-A" ] || [ "$severity" = "--all" ]; then
		colour=""
		if [ $csv_format = true ]; then
			colour="cat"
		else
			colour="$(realpath $(dirname "$0")/utils/score-colour.sed)"
		fi
		filter_cvss_product | $colour

	elif [ "$severity" = "-C" ] || [ "$severity" = "--critical" ]; then
		filter_cvss_product 9

	elif [ "$severity" = "-H" ] || [ "$severity" = "--high" ]; then
		filter_cvss_product 7 9

	elif [ "$severity" = "-M" ] || [ "$severity" = "--medium" ]; then
		filter_cvss_product 4 7

	elif [ "$severity" = "-L" ] || [ "$severity" = "--low" ]; then
		filter_cvss_product 0 4

	elif [ "$severity" = "-U" ] || [ "$severity" = "--unknown" ]; then
		filter_cvss_product -1 0

	elif [ "$severity" = "custom" ]; then
		filter_cvss_product $severity_min $severity_max

	fi
}


cves_sort_options=(cvss epss risk)

while [[ "$#" -gt 0 ]]; do
# for i in "$@"; do
	case $1 in
		--all|--critical|--high|--medium|--low|--unknown|-A|-C|-H|-M|-L|-U)
			severity="$1"
			;;
		--gui|--cli|--lib|--network-gui|--sdv|-g|-t|-l|-ng|--network|-n)
			pkg_type="$1"
			;;
		--min)
			severity="custom"
			severity_min="$2"
			shift
			;;
		--min=*)
			severity="custom"
			severity_min="${1#*=}"
			;;
		--max)
			severity="custom"
			severity_max="$2"
			shift
			;;
		--max=*)
			severity="custom"
			severity_max="${1#*=}"
			;;

		--exclude|-e)
			if [[ "$2" == *,* ]]; then
				readarray -td, a <<<"$2,"; unset 'a[-1]'; # declare -p a;
				exclude+=("${a[@]}")
			else
				exclude+=("$2")
			fi
			shift
			;;
		--exclude=*|-e=*)
			param="${1#*=}"
			if [[ "$param" == *,* ]]; then
				readarray -td, a <<<"$param,"; unset 'a[-1]'; # declare -p a;
				exclude+=("${a[@]}")
			else
				exclude+=("$param")
			fi
			;;
		--include|-i)
			include+=("$2")
			shift
			;;
		--include=*|-i=*)
			include+=("${1#*=}")
			;;
		--filter)
			CUSTOM_FILTER="$2"
			shift
			;;
		--filter=*)
			CUSTOM_FILTER="${1#*=}"
			;;
		--filter-out)
			CUSTOM_FILTER_OUT="$2"
			shift
			;;
		--filter-out=*)
			CUSTOM_FILTER_OUT="${1#*=}"
			;;
		--any-state)
			any_state=1
			;;
		--scanner=*|-s=*)
			param="${1#*=}"
			if [[ "$param" == *,* ]]; then
				readarray -td, a <<<"$param,"; unset 'a[-1]'; # declare -p a;
				scanner+=("${a[@]}")
			else
				scanner+=("$param")
			fi
			;;
		--scanner|-s)
			if [[ "$2" == *,* ]]; then
				readarray -td, a <<<"$2,"; unset 'a[-1]'; # declare -p a;
				scanner+=("${a[@]}")
			else
				scanner+=("$2")
			fi
			shift
			;;
		--upgraded|--raw)
			if [[ "$filename" == "*" ]]; then
				filename="${1:2}"
			fi
			;;
		--no-ignore)
			no_ignore_dir=true
			;;
		--cve)
			pkg_type="$1"
			FILTER_CVE="$2"
			no_ignore_dir=true
			shift
			;;
		--cve=*)
			pkg_type="${1%=*}"
			FILTER_CVE="${1#*=}"
			no_ignore_dir=true
			;;
		--exploit)
			PREVIEW_EXPLOIT=true
			;;
		--sort=*)
			cves_sort="${1#*=}"
			if ! [[ " ${cves_sort_options[*]} " =~ " ${cves_sort} " ]]; then
				echo "Error: invalid sort option '$cves_sort'" >&2
				exit 1
			fi
			;;
		--sort|-s)
			cves_sort="$2"
			if ! [[ " ${cves_sort_options[*]} " =~ " ${cves_sort} " ]]; then
				echo "Error: invalid sort option '$cves_sort'" >&2
				exit 1
			fi
			shift
			;;
		--no-vendor)
			SHOW_VENDOR=false
			;;
		--unify|-u)
			unify=true
			;;
		--csv)
			csv_format=true
			;;
		--cbt)
			merge_cbt=true
			;;
		--help|-h)
			help=true
			break
			;;
		-*)
			echo "Error: Invalid arg '$1'" >&2
			usage
			exit 1
			;;
		*)
			parse_args "$1"
			# echo "Error: Invalid arg '$option'" >&2
			# usage
			# exit 1
			;;
	esac
	shift
done


if $help; then
	usage
	echo
	echo "Scoring:"
	echo "  -A, --all          All CVSS"
	echo "  -C, --critical     Critical CVSS"
	echo "  -H, --high         High CVSS"
	echo "  -M, --medium       Medium CVSS"
	echo "  -L, --low          Low CVSS"
	echo "  -U, --unknown      Unknown CVSS"
	echo "      --min=MIN      CVSS must be superior or equal to MIN"
	echo "      --max=MAX      CVSS must be strictly inferior to MAX"
	echo "      --sort={$(join_by ', ' ${cves_sort_options[*]})}"
	echo "                       Sort by CVSS, EPSS or Risk (CVSS * EPSS)"
	echo
	echo "Package:"
	echo "  -g, --gui          Graphical"
	echo "  -t, --cli          CLI/commands"
	echo "  -n, --network      Network"
	echo "  -ng,--network-gui  Network + GUI"
	echo "  -l, --lib          Librairies"
	echo
	echo "OS:"
	echo "  -e, --exclude=OS   Exclude OS. Accept multiple separated by comma, and wildcards"
	echo "      --upgraded     Only upgraded OS"
	echo "      --raw          Only raw OS"
	echo
	echo "Other:"
	echo "  -s, --scanner=SC   Filter by scanner SC"
	echo "      --no-ignore    Do not apply ignore directory"
	echo "      --filter=STR   Filter by STR:"
	echo "                       Package, vendor, ecosystem, impact"
	echo "      --filter-out=STR Filter out STR"
	echo "      --any-state    Include fixed CVE"
	echo "      --cve=CVE      Search for a CVE"
	echo "      --exploit      Online exploit status (only for: $(printf "CVSS ≥ %s; EPSS ≥ %s%%" $(grep -E '^(CVSS|EPSS)_THRESHOLD\s*=\s*' src/parser/utils/get_online_exploits_multiple.py | sort | sed -r 's/.+=//; s/0\.([0-9]{,2})([0-9]{,3})/\1.\2/; s/00\./0./')))"
	echo "  -u, --unify        "
	echo "      --cbt          Merge with CVE Binary Tool"
	echo "  -h, --help         Show this help"
	echo
	echo "Possible impacts (--filter/--filter-out):"
	echo "  RCE  Remote Code Execution"
	echo "  LPE  Local Privilege Escalation"
	echo "  ID   Information Disclosure"
	echo "  DoS  Denial of Service"
	echo "  ?    Unknown"
	echo
	echo "Exploits (--exploit):"
	echo "  x*  GitHub repo with highest star count"
	echo "  E   Exploit-db"
	echo "  P   Other potential exploit or PoC"
	echo "  -   None found"
	echo "      Unknown"
	echo
	echo "Exclude all CVEs from any file in the directory 'inspectignore'"
	echo "  # comment allowed"

	exit 0
fi


parse_args "$default_resultfile" "$ARGS"

ARGS="$(join_by ' ' $(echo "$ARGS" | sed -r 's/--sort(=|\s+)[a-z]+|--no-vendor//g; s/\s+/\n/g' | grep -E '^-'))"

if [ -z "$severity" ]; then
	ARGS="-A $ARGS"
fi

create_impact_filter() {
	local _FILTER="$1"
	if [ -n "$_FILTER" ]; then
		local _ARGS="$2"
		grep $_ARGS -iE '(^|:)('"$( \
			echo -n "$_FILTER" \
			| sed -r 's/^[\\/+:;, ]+|[\\/+:;, ]+$//g; s/[\\/+:;, ]+/|/g' \
		)"')(:|$)'
	else
		cat
	fi
}
show_results() {
	filepath="$1"
	shift

	result="$("$0" "$filepath" $ARGS --any-state --csv)"

	result_cbt=
	if [ "$merge_cbt" = true ] && [ -f "$resultfile/raw.cbt.json" ]; then
		source src/parser/utils/merge.sh
		result_cbt="$(merge_results "$result" "$resultfile/raw.cbt.json")"

		if [ "$PREVIEW_EXPLOIT" = true ]; then
			result_cbt="$(src/parser/utils/get_online_exploits_multiple.py "$result_cbt")"
		fi
	fi
	if [ -z "$severity" ]; then
		result="$(echo -en "$result" \
			| grep -vE '^$' \
			| create_impact_filter "$CUSTOM_FILTER" \
			| create_impact_filter "$CUSTOM_FILTER_OUT" -v \
			| sort -u -t: -k5,5
		)"
		result_cbt="$(echo -en "$result_cbt" \
			| grep -vE '^$' \
			| create_impact_filter "$CUSTOM_FILTER" \
			| create_impact_filter "$CUSTOM_FILTER_OUT" -v \
			| sort -u -t: -k5,5
		)"
	else
		result="$(echo -en "$result\n$result_cbt" \
			| grep -vE '^$' \
			| create_impact_filter "$CUSTOM_FILTER" \
			| create_impact_filter "$CUSTOM_FILTER_OUT" -v \
			| sort -u -t: -k5,5
		)"
		if [ $SHOW_VENDOR = false ]; then
			result="$(echo -n "$result" | cut -d: -f1-3,5-)"
		fi
		if [ $cves_sort = epss ]; then
			result="$(echo -n "$result" | awk -F: 'BEGIN{OFS=":"} { tmp=$1; $1=$2; $2=tmp; print }')"
		fi
	fi
	
	if [ $any_state -eq 0 ]; then
		result="$(echo -n "$result" | grep -vE ":fixed(:|$)" | cut -d: -f1-7,9)"
	fi
	if [ -z "$severity" ]; then
		# Let this way ?
		result="$result
$result_cbt"
		result_cbt=
		print_overview
	else
		echo "$result" | column -ts : -c 3 | sort -k1,1 -n -t' ' | src/parser/utils/score-colour.sed
	fi
}

if [ -f "$resultfile/raw.vanir.json" ]; then
	show_results "$resultfile/raw.vanir.json"

elif [ -f "$resultfile/raw.yocto.json" ]; then
	show_results "$resultfile/raw.yocto.json"

elif [ -f "$resultfile/raw.grype.json" ]; then
	show_results "$resultfile/raw.grype.json"

elif [ -d "$resultfile" ]; then
	if [ -z "$severity" ]; then
		ARGS="$ARGS -A"
	fi
	exclude="$(join_by " -prune -o -iname " "${exclude[@]}")"
	include="$(join_by "/*' -o -ipath '*/" "${include[@]}")"
	if [ -n "$exclude" ]; then
		exclude="-not ( -iname $exclude -prune )"
	fi
	if [ -n "$include" ]; then
		include="-ipath '*/$include/*'"
		if [ -n "$exclude" ]; then
			include="-o $include"
		fi
	fi
	
	if [ -n "$scanner" ]; then
		scanner="( -iname *.$(join_by ".json -o -iname $filename." "${scanner[@]}").json )"
		filename="$scanner"
		# echo "$filename"
	elif [[ "$filename" != "*" ]]; then
		filename="-iname $filename*.json"

	elif [ -f "$resultfile/raw.vanir.json" ]; then
		filename="( -iname raw.vanir.json -o -iname raw.cbt.json -o -iname raw.json )"

	elif [ -f "$resultfile/raw.yocto.json" ]; then
		filename="( -iname raw.yocto.json -o -iname raw.cbt.json -o -iname raw.json )"

	elif [ -f "$resultfile/upgraded.grype.json" ]; then
		filename="( -iname upgraded.grype.json -o -iname upgraded.grype.json -o -iname upgraded.json )"

	else
		filename= #'-iname *.json'
	fi

	if [ "$unify" = true ]; then
		unify="sort -u"
		csv_format="--csv"
	else
		unify="cat"
		csv_format=""
	fi

__inspect() {
	local filepath="$(echo "$1" | sed -E 's/(.+\/){0,1}out\/os\/|\.json$//g')"
	# echo "$(realpath $PWD/src/parser/inspect.sh)" "$@" >&2
	local result="$("$(realpath $PWD/src/parser/inspect.sh)" "$@")"

	if [ -z "$result" ]; then
		return
	
	elif [[ "$4" == --cve && "$unify" == cat ]]; then
		echo -e "\x1b[32;1m\u2714\e[0m \e[36m$filepath\e[0m"
		return
	
	elif [[ "$unify" == cat ]]; then
		echo
		echo -e "\e[36m$filepath\e[0m"
	fi
	echo "$result"
}
	export -f __inspect

	# echo "$pkg_type"
	# echo find "$resultfile" $exclude -type f $include $filename -exec bash -c "unify='$unify' __inspect '{}' --min=$severity_min --max=$severity_max $pkg_type $severity $PREVIEW_EXPLOIT $cves_sort $csv_format $no_ignore_dir" \;
	output="$(find "$resultfile" $exclude -type f $include $filename -exec bash -c "unify='$unify' __inspect '{}' $ARGS" \;)"

	if [[ "$cves_sort" == "--sort=risk" ]]; then
		output="$(echo "$output" | sed -E '/^[0-9\.]+:[a-zA-Z\.].+/d')"
	fi
	# echo "recursive" 
	if [[ $unify == "cat" ]]; then
		echo "$output"
	else
		echo "$output" | sort -k5,5 -t: -u | sort -k1,1 -n -t: |  column -ts : -c 3 | "$(realpath $(dirname "$0")/utils/score-colour.sed)"
	fi
else


__no_gui() {
	grep -viE "lib|firefox|chrome|chromium|spotify|whatsapp|telegram|discord|messenger|android|ios|safari|edge|google-(maps?|sheets|translate|cloudstorage)|qt"
}

__only_gui() {
	grep -viE "lib|pypi|vim|wget|curl|apt|dnf|yum|dpkg|rpm|sudo|nano|less|tar|zip|bzip2|gzip|git|zsh|z(cat|grep|diff)|xz|php|perl|python|node|gcc|clang|go|ruby|rust|docker|shadow|systemd|pam|openssl|libssl|(bin|core|elf)utils|bison|openssh|kernel|ttf|socat|jinja|bash|jq|awk|sed"
}

__only_network_gui() {
	grep -iE "firefox|chrome|chromium|spotify|whatsapp|telegram|discord|messenger|safari|edge|bluez|wpa" #|openssl|libssl"
}

__only_network() {
	grep -iE "apt|dnf|yum|dpkg|rpm|cargo|npm|openssl|socat|gnupg|wpa|blue|hostapd|libpcap|busybox|tcpdump"
}

__only_libs() {
	grep -iE "(lib[a-z0-9_\-]+|gcc|clang|node|python|perl|php|ruby|rust|go|java|openssl|pypi|npm|cargo|pip)="
}

__filter_sdv() {
	src/parser/utils/filter-sdv.sh
}

__filter() {
	grep -iE "$CUSTOM_FILTER"
}

__filter_out() {
	grep -viE "$CUSTOM_FILTER_OUT"
}

case "$pkg_type" in
	--gui|-g)
		pkg_type="__only_gui"
		;;
	--cli|-t)
		pkg_type="__no_gui"
		;;
	--lib|-l)
		pkg_type="__only_libs"
		;;
	--network|-n)
		pkg_type="__only_network"
		;;
	--network-gui|-ng)
		pkg_type="__only_network_gui"
		;;
	--sdv)
		pkg_type="__filter_sdv"
		;;
	--filter|--cve)
		if [[ "$pkg_type" == "--cve" ]]; then
			# echo "Warning: --cve is deprecated, use --filter instead" >&2
			FILTER_CVE="\\b$FILTER_CVE\\b"
		fi
		pkg_type="__filter"
		;;
	--reverse-filter)
		pkg_type="__filter_out"
		;;
	"")
		pkg_type="cat"
		;;
esac


sort_option_switch() {
	case $cves_sort in
		# cvss)
		# 	cat
		# 	;;
		# risk)
		# 	echo -n "\(.risk // -1):\(.cvss // -1):\(.epss // -1):\(.percentile // -1)"
		# 	;;
		epss)
			awk -F: 'BEGIN{OFS=":"} { tmp=$1; $1=$2; $2=tmp; print }'
			;;
		*)
			cat
			;;
	esac
}

result="$(src/parser/utils/read-report.sh "$resultfile" --filter-out-impact "$FILTER_OUT_IMPACT" $any_state | $pkg_type)"


if ! [ "$no_ignore_dir" = true ]; then
	# echo "Ignoring ! $no_ignore_dir"
	ignore="$(eval cat "$(realpath "$(dirname "$0")/../../inspectignore/*")" 2> /dev/null | cut '-d#' -f1  | sed -Ez 's/\s*\n\s*/|/g; s/^\||\|$//g' | xargs)"
	# echo "$ignore"

	if [ -n "$ignore" ]; then
		result="$(echo "$result" | grep -viE "$ignore")"
	fi
fi

if [ "$PREVIEW_EXPLOIT" = true ]; then
	result="$(src/parser/utils/get_online_exploits_multiple.py "$(echo -n "$result" | cut -d: -f1-6 | grep -vE '^[0-5](\.[0-9]+)?:|:0\.000[0-2][0-9]*:')")"
fi

print_overview

fi