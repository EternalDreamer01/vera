#!/usr/bin/env -S sed -rf
################################################################################
# @file      reformulate-vuln-type.sed
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


s/\b(rce|lpe|leak)\b/\n\U\1\n/gi
s/elevation\s+of\s+privileges?|privilege\s+escalation|escalate\s+privileges?|auth(entication|\.)\s+bypass|bypass\s+auth(entication|\.)/\nLPE\n/gi
s/remote(\scode)?\s+execution|execute\s+(arbitraty|code)+remotely/\nRCE\n/gi
s/(arbitraty|code)+\s+execution|execute\s+(arbitraty|code)+/\nACE\n/gi
s/denial\s*of\s*service|dos|crash/\nDoS\n/gi
s/undef(ined|\.)?\s+behav(ior)?|neighbour(ing|\.)?\s+var(iable|\.)?/\nUNDEF\n/gi

s/disclos(ure|e)|(access|read)\s+memory|buffer\s+over-read|out-of-bounds\s+read/\nLEAK\n/gi
s/out-of-bounds\s+write/\nACE\n/gi
s/NULL\s+pointer\s+dereference/\nNPD\n/gi
s/commands?\s+injections?/\nInj.\n/gi
