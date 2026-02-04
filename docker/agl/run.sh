#!/bin/bash
################################################################################
# @file      run.sh
# @brief     
# @date      We Jul 2025
# @author    
# 
# PROJECT:   agl
# 
# MODIFIED:  Wed Jul 09 2025
# BY:        
# 
# Copyright (c) 2025 
# 
################################################################################


find . -type f -name "*.zip" -exec unzip {} \;

find . -type f -name "*.bz2" -exec mv {} meta-renesas/ +