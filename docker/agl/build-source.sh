#!/bin/bash
################################################################################
# @file      build.sh
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

AGL_BRANCH="trout"
AGL_MACHINE="qemux86-64"
AGL_FEATURE="agl-all-features"
AGL_RECIPE="agl-ivi-image"

mkdir -p os/$AGL_BRANCH && cd os/$AGL_BRANCH
repo init --depth 1 -u https://gerrit.automotivelinux.org/gerrit/AGL/AGL-repo
repo sync -f -c -j1 --fail-fast

# exit 0

source meta-agl/scripts/aglsetup.sh -m ${AGL_MACHINE} ${AGL_FEATURE}

cd build 2>/dev/null

# sed -Ei '/^(PARALLEL_MAKE|BB_NUMBER_THREADS).*/d' conf/local.conf
# echo "PARALLEL_MAKE = \"-j 12\"" >> conf/local.conf
# echo "BB_NUMBER_THREADS = \"12\"" >> conf/local.conf
# cat conf/local.conf

source ./agl-init-build-env
bitbake ${AGL_RECIPE}
