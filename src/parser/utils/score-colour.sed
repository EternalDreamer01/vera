#!/usr/bin/env -S sed -Ef
################################################################################
# @file      score-colour.sed
# @brief     
# @date      Mo Jul 2025
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

# Unknwon
s/^(\?{0,2}\s.+)$/\x1b[1;2m\1\x1b[0m/

# Low
s/^(Low|[0-3](\.[0-9]){0,2}\s.+)$/\x1b[0;2;33m\1\x1b[0m/
s/^(0\.000[0-2][0-9]*.+)$/\x1b[0;2;32m\1\x1b[0m/

# Medium
s/^(Medium|Moderate|[4-6](\.[0-9]){0,2}\s.+)$/\x1b[0;33m\1\x1b[0m/
s/^(0\.0003[0-9]*.+)$/\x1b[0;2;33m\1\x1b[0m/
s/^(0\.(00[1-3]|000[4-9])[0-9]*.+)$/\x1b[0;33m\1\x1b[0m/

# High
s/^(High|[7-8](\.[0-9]){0,2}\s.+)$/\x1b[0;31m\1\x1b[0m/
s/^(0\.(0[1-7]|00[4-9])[0-9]*.+)$/\x1b[0;31m\1\x1b[0m/

# Critical
s/^(Critical|(9|10)(\.[0-9]){0,2}\s.+)$/\x1b[0;35m\1\x1b[0m/
s/^(0\.([1-9]|0[89])[0-9]*.+)$/\x1b[0;35m\1\x1b[0m/


s/(\x1b\[[0-9;]+m)(.*)(n\/a|unknown|unspecified|null)/\1\2\x1b[0;2m\3\1/

