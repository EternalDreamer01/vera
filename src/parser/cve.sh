#!/bin/bash
################################################################################
# @file      cve.sh
# @brief     
# @date      Tu Jul 2025
# @author    Dimitri Simon
# 
# PROJECT:   parser
# 
# MODIFIED:  Tue Jul 22 2025
# BY:        Dimitri Simon
# 
# Copyright (c) 2025 Dimitri Simon
# 
################################################################################

usage() {
	echo "Usage: $(basename "$0") CVE-ID [option | path]"
}
help() {
	usage
	echo
	echo "Options:"
	echo "  a, aff, affected      Show affected products (online query: NVD)"
	echo "  d, desc, description  Show description"
	echo "  i, info               Show information about a CVE"
	echo "  e, exploit            Search online exploits"
	echo "  r, ref, reference     Show references"
	echo "  s, score              Show scores (online query when CVSS is missing locally: NVD)"
	echo "  h, help               Show this help message"
	echo
	echo "Exploit option:"
	echo "  i, import             Import exploit repository into 'exploit'"
	echo
	echo "If no option is provided, the full JSON content of the CVE entry will be shown."
}

# Convert unicode dash to ASCII dash
cveId="$(echo "${1^^}" | sed 's/\xe2\x80\x91/-/g')"
path="${2:-.}"

shift
if [ -n "$2" ]; then
	shift
fi

if [[ "$cveId" == ASB-* || "$cveId" == PUB-* ]]; then
	cveAlias="$( \
		unzip -p android.zip "$cveId.json" \
		| jq -r 'first(.aliases[] | select(startswith("CVE-")))' \
	)"
	if [[ -n "$cveAlias" && "$1" != "nr" && "$1" != "not-recursive" ]]; then
		if [[ "$path" =~ ^e(xploit)?|s(core)?$ ]]; then
			"$0" "$cveAlias" "$path" $@
		fi
		
	# elif [ -n "$1" ]; then
	# 	shift
	fi
	# exit 0
elif [ -z "$cveId" ] || [ "${#cveId}" -lt 6 ] || [[ "$cveId" != *-* ]]; then
	usage >&2
	exit 1

elif [ "${cveId:0:4}" != "CVE-" ]; then
	cveId="CVE-$cveId"
fi

args=("$@")
# echo "$cveId $path $args"

if [[ "$path" == "d" || "$path" == "desc" || "$path" == "description" ]]; then
	if [[ "$cveId" != CVE-* ]]; then
		path=".details"
	else
		path=".containers.cna.descriptions[]?.value"
	fi
	args=(-r)

elif [[ "$path" == "e" || "$path" == "exploit" ]]; then
	if [[ "$cveId" == CVE-* ]] && \
		[[ "$(jq --arg cve "$cveId" 'any(.vulnerabilities[]; .cveID == $cve)' cisa.json)" == true ]]; then
		echo -e "\x1b[1;31mKnown Exploited Vulnerability in the wild\x1b[0m\n"
	fi
	exploits="$(src/parser/utils/get-online-exploits.sh "$cveId")"
	exploits="$(echo "$exploits" | sed -r '/^\s*$/d' | sort -u | sort -k1,1 -rnt\;)"
	exploit_option="$1"
	exploits_num=$(echo -n "$exploits" | grep -c '^')
	echo -e "Found: \x1b[1;36m$exploits_num\x1b[0m potential exploit(s) for \x1b[1;36m$cveId\x1b[0m"
	if [[ "$exploits_num" -ne 0 ]]; then
		echo "$exploits" | sed -r 's/([0-9]+);/\x1b[36m\1\x1b[0m;/' | column -ts\; -l2 -R1
		echo
	fi

	if [[ "$exploit_option" == "i" || "$exploit_option" == "import" ]]; then
		echo
		check_exploits="$(find exploit -maxdepth 2 -name "$cveId")"
		
		if [ -n "$check_exploits" ]; then
			echo "Exploit already imported:"
			echo "$check_exploits" | sed 's/^/  /'
			exit 0
		fi

		exploit_repo="$(echo -n "$exploits" | head -n 1 | grep 'https://github.com/')"
		if [ -n "$exploit_repo" ]; then
			exploit_repo_text="$(echo -n "$exploit_repo" | sed -r 's/([0-9]+);https:\/\/github.com\/(.+)/\2 (\1*)/')"
			exploit_repo_link="$(echo -n "$exploit_repo" | cut -d\; -f2-)"
			product="$("$0" "$cveId" .containers.cna.affected[0].product -r | tr '[:upper:]' '[:lower:]')"
			if [[ -z "$product" || "$product" =~ ^n/?a$ ]]; then
				product="$(
					curl --no-progress-meter "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$cveId" \
					| jq -r '.vulnerabilities[0].cve.configurations[0].nodes[0].cpeMatch[0].criteria' \
					| sed -r 's/cpe:[0-3\.]+:[aho]:[a-z0-9_\\/\-]+:([a-z0-9_\\/\-]+):.+/\1/'
				)"
				
				if [ -z "$product" ]; then
					product=
				fi
			fi

			if [ -n "$product" ]; then
				product="$product/"
			fi

			while true; do
				read -p "Import $exploit_repo_text into 'exploit/$product$cveId' ? [Yn] " yn
				case $yn in
					[Yy]* ) git clone "$exploit_repo_link" "exploit/$product$cveId"; break;;
					[Nn]* ) echo "Aborted.";;
					* );;
				esac
			done
		else
			echo "No repo to import" >&2
			exit 1
		fi
	fi

	exit 0

	# echo "Sploitus: $(echo "$sploitus" | jq length)"
	echo -n "$sploitus" | jq -r '.[].href' | sed 's/^/  /' | avgrep $github | sort -u
	# echo

	# echo "CVE News: $([[ -n "$cve_news" ]] && echo 1 || echo 0)"
	[[ -n "$cve_news" ]] && echo "  https://www.cve.news/${cveId,,}/"

	exit 0

elif [[ "$path" == "i" || "$path" == "info" ]]; then
	"$0" "$cveId" score
	echo
	"$0" "$cveId" description not-recursive
	echo
	echo
	"$0" "$cveId" exploit
	exit 0

elif [[ "$path" == "a" || "$path" == "aff" || "$path" == "affected" ]]; then
	# https://nvd.nist.gov/vuln/data-feeds#divJson20Feeds
	# jq '.vulnerabilities[].cve | select(.id == "CVE-2025-32462")' nvdcve-2.0-2025.json
	res="$(curl --no-progress-meter "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$cveId")"
	echo "$res" | jq -r '
.vulnerabilities[]
| .cve.configurations[]
| .nodes[]
| .cpeMatch[]
| (.criteria | split(":")) as $cpe
| (
    if has("versionStartIncluding") then ">=\(.versionStartIncluding)"
    elif has("versionStartExcluding") then ">\(.versionStartExcluding)"
    elif $cpe[5] != "*" then ">=\($cpe[5])"
    else "" end
  ) as $min
| (
    if has("versionEndIncluding") then "<=\(.versionEndIncluding)"
    elif has("versionEndExcluding") then "<\(.versionEndExcluding)"
    else "" end
  ) as $max
| $cpe[3] + ":" + $cpe[4] + ":" +
  (if $min != "" then " " + $min else "" end) +
  (if $min != "" and $max != "" then ", " else " " end) +
  (if $max != "" then $max else "" end)
'
	exit 0
	# args=(-r)
# elif [[ "$path" == "p" || "$path" == "product" ]]; then
# 	path=".containers.cna.affected[]?.product"
# 	args=(-r)
elif [[ "$path" == "r" || "$path" == "ref" || "$path" == "reference" ]]; then
	if [[ "$cveId" != CVE-* ]]; then
		data="$(unzip -p android.zip "$cveId.json")"
		echo -n "$data" | jq -r '
			# vanir signatures source
			( .affected[]? // empty
				| (.ecosystem_specific.vanir_signatures[]? // empty)
				| if type=="object" then
					.source?
				else
					.
				end
			),

			# references
			(.references[]? // empty | .url?),

			# fixes
			( .affected[]? // empty
				| (.ecosystem_specific.fixes[]? // empty)
			)
			' \
			| sort -u -k2,2 -t: \
			| sed -r 's/(https:\/\/android\.googlesource\.com\/.+\/\+\/[0-9a-f]{40})/\1\^\!\//'
		# get on the diff page by appending '^!/'
		
		echo -n "$data" | jq -r '
			# vanir signatures source + target
			( .affected[]? // empty
				| (.ecosystem_specific.vanir_signatures[]? // empty)
				| if type=="object" then
					(.target?.file // "") + (if .target?.function? then ":" + .target.function else "" end)
				else
					.
				end
			)
			' \
			| sort -ru | sort -u -k1,1 -t:
		exit
	fi
	path=".containers.cna.references[]?.url"
	args=(-r)

elif [[ "$path" == "s" || "$path" == "score" ]]; then
	if [[ "$cveId" != CVE-* ]]; then
		data="$("$0" "$cveId" ".affected[]?.ecosystem_specific" -r)"
		echo "Severity: $(echo -n "$data" | jq -r .severity | head -n 1 | src/parser/utils/score-colour.sed)"
		echo -n "$data" | jq -rs '"Type:     " + (
			[
				.. | .types? // empty | .[]?
				| select(type=="string")
				| ascii_upcase
			]
			| unique
			| join(",")
		)'
		exit 0

	else
		epss_entries="$(grep -im 1 "$cveId," epss_scores.csv | cut -d, -f2-)"
		echo "EPSS:       $(echo "$epss_entries" | cut -d, -f1 | src/parser/utils/score-colour.sed)"
		echo "Percentile: $(echo "$epss_entries" | cut -d, -f2 | src/parser/utils/score-colour.sed)"
		echo
		output="$("$0" "$cveId" '
	.containers.cna.metrics // [] 
	| .[]
	| select(type == "object")
	| if has("format") and .format == "other" and (.other.content.text? // empty) != "" then
		"Other:      \(.other.content.text)"
		else
			to_entries[]
			| select(.value | type == "object" and .baseScore? != null)
			| "\(.key | sub("_"; ".") | sub("cvssV"; "CVSS ")):   \(.value.baseScore)"
		end
	' -r)"
		if [ -z "$output" ]; then
			curl --no-progress-meter "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$cveId" \
			| jq -r '.vulnerabilities[].cve.metrics
				| to_entries[]
				| select(.key | test("cvssMetric"))          # only process cvssMetric* keys
				| .value[]                                   # iterate over array elements
				| "CVSS \(.cvssData.version): \(.cvssData.baseScore)    \(.source)"
			'
		else
			echo "$output"
		fi
		exit 0
	fi
	args=(-r)
elif [[ "$path" == "h" || "$path" == "help" ]]; then
	help
	exit 0
fi


if [[ "$cveId" != CVE-* ]]; then
	unzip -p android.zip "$cveId.json" | jq "$path" $args

else
	year=$(echo "$cveId" | cut -d'-' -f2)
	num=$(echo "$cveId" | cut -d'-' -f3)
	cve_prefix="0"

	if [ ${#num} -gt 3 ]; then
		cve_prefix="${num:0:${#num}-3}"
	else
		num=$(printf "%04d" "$num")
	fi
# echo "Year: $year"
# echo "Num: $num"
# echo "CVE Prefix: $cve_prefix"

	# echo "$args"
	jq "$path" $args "$(realpath "$(dirname "$0")/../../cvelistV5/cves/$year/${cve_prefix}xxx/CVE-$year-$num.json")"
fi
