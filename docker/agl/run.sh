#!/bin/bash
################################################################################
# @file      run.sh
# @brief     
# @date      We Jul 2025
# @author    Dimitri Simon
# 
# PROJECT:   agl
# 
# MODIFIED:  Wed Jul 09 2025
# BY:        Dimitri Simon
# 
# Copyright (c) 2025 Dimitri Simon
# 
################################################################################


find . -type f -name "*.zip" -exec unzip {} \;

find . -type f -name "*.bz2" -exec mv {} meta-renesas/ +