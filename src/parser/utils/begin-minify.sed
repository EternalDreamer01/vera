#!/usr/bin/env -S sed -Ef
################################################################################
# @file      begin-minify.sed
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

# On RedHat lists
## Remove the end
s/\s+\@[a-zA-Z0-9.-]+\s*$//

## Replace space between package and version by a comma
s/\s\s+/,/

## Remove package suffix
s/\.[a-z0-9_]+,/,/

# Remove version-like in name
# s/([0-9]+(\.[0-9-])+)(.*),\1/\2,\1/g

# Remove release info
s/\/[a-z,-]+ /,/

# Remove arch info
s/( (all|amd64|i386)){0,1}( \[.*\]){0,1}$//

# Remove version prefix
s/,([0-9]+:){0,1}/,/
# ...and suffix
s/((~|\+|-)+[a-z0-9._+~-]*|([a-z]{4,}\.){1,}[0-9]{4,}\.[0-9]{4,})$//
