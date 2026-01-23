#!/bin/bash
################################################################################
# @file      extract-function.sh
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

grep -E '^(_+[a-z0-9]+|[a-zA-Z]+_[A-Za-z0-9_]*[a-z]+[A-Za-z0-9_]+|[a-z]+[0-9]*[A-Z][a-zA-Z0-9]+|[a-zA-Z0-9]+\(\))$'