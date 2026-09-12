#!/bin/sh
################################################################################
# @file      merge.sh
# @brief     
# @date      Tu Jan 2026
# @author    Dimitri Simon
# 
# PROJECT:   utils
# 
# MODIFIED:  Tue Jan 06 2026
# BY:        Dimitri Simon
# 
# Copyright (c) 2026 Dimitri Simon
# 
################################################################################


merge_results() {
    local result="$1"
    local merging_filepath="$2"
    local filter="$3"
    # Using an absolute path reference is safer
    local PROJECT_ROOT="$(realpath "$(dirname "$0")/../../")"

    # 1. Extract CVEs marked fixed from fileA
    local fixed_cves=$(echo "$result" | awk -F: '$8=="fixed" {print $5}' | sort -u)

    # 2. Convert fileB JSON to CVSS:CVE and sort
    local cbt_cves_raw=""
    cbt_cves_raw="$("$PROJECT_ROOT/src/parser/utils/read-report.sh" "$merging_filepath" 1 1)"

    # 3. Conditional Filtering
    local cbt_cves=""
    if [ "$filter" = "--sdv" ]; then
        cbt_cves=$(echo "$cbt_cves_raw" | "$PROJECT_ROOT/src/parser/utils/filter-sdv.sh")
    else
        cbt_cves="$cbt_cves_raw"
    fi

    # 4. Identify common fixed CVEs (CVEs in both sets)
    local cbt_fixed
    cbt_fixed=$(comm -1 -2 \
            <(echo "$cbt_cves" | cut -d: -f5 | sort -u) \
            <(echo "$fixed_cves"))

    # 5. Final Filtering Logic (The fix)
    # Initialize a temporary array or variable to hold the results
    local cbt=""
    
    # Use a while read loop with a Here-String (<<<)
    # This reads the content of $cbt_cves line by line safely.
    while IFS= read -r line; do
        # Extract the CVE (the 5th field, delimited by :)
        local cve="$(echo "$line" | cut -d: -f5)"
        
        # Check if the extracted CVE is NOT in the list of fixed CVEs
        if ! echo "$cbt_fixed" | grep -q -F "$cve"; then
            # Append the entire line to the result variable, followed by a newline character
            cbt+="$line"$'\n'
        fi
    done <<< "$cbt_cves"

    # Use echo -e to interpret the stored newlines and print the final result
    echo -e "${cbt}"
}