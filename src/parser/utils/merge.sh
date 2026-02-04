#!/bin/sh
################################################################################
# @file      merge.sh
# @brief     
# @date      Tu Jan 2026
# @author    
# 
# PROJECT:   utils
# 
# MODIFIED:  Tue Jan 06 2026
# BY:        
# 
# Copyright (c) 2026 
# 
################################################################################


merge_results() {
	result="$1"
	merging_filepath="$2"
	filter="$3"

	# Extract CVEs marked fixed from fileA
	fixed_cves=$(echo "$result" \
		| awk -F: '$8=="fixed" {print $5}' \
		| sort -u)

	# echo "$fixed_cves"

	# Convert fileB JSON to CVSS:CVE and sort
	cbt_cves="$(src/parser/utils/read-report.sh "$merging_filepath" 1 1)"

	# echo "$cbt_cves"

	if [ "$filter" = "--sdv" ]; then
		cbt_cves="$(echo -n "$cbt_cves" | src/parser/utils/filter-sdv.sh)"
	fi

	# Remove from fileB any CVE found in fileA as "fixed"
	cbt_fixed=$(comm -1 -2 \
		<(echo "$cbt_cves" | cut -d: -f5 | sort -u) \
		<(echo "$fixed_cves"))

	cbt="$(echo "$cbt_cves" | while IFS= read -r line; do
		cve="$(echo "$line" | cut -d: -f5)"  # extract CVE after the colon
		if ! echo "$cbt_fixed" | grep -q -F "$cve"; then
			echo "$line"
		fi
	done)"

	echo "$cbt"
}