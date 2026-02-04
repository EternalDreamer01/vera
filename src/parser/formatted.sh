#!/bin/sh
################################################################################
# @file      formatted.sh
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


printf "Total:     %6s\n" "$(find cvelistV5/cves/ -name 'CVE-*.json' | wc -l)"

#formatted="$(grep -rnw cvelistV5/cves/ -Ee '"valid":')"
#total_formatted=$(echo "$formatted" | grep -E '"valid": (false|true)' | wc -l)
valid=$(jq -r '.[][].cveId' cves.json | sort -u | wc -l)
#invalid=$((total_formatted - valid))

#printf "Formatted: %6s\n" "$total_formatted"
printf "Valid:     %6s\n" "$valid"
#printf "Invalid:   %6s\n" "$invalid"
