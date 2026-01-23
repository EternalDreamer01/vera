#!/bin/bash

export AOSP_BRANCH="android14-release"
#export PRODUCT="aosp_cf_x86_64_auto-trunk_staging-userdebug"

mkdir -p os && cd os

# repo init --partial-clone --no-use-superproject -b android-latest-release -u https://android.googlesource.com/platform/manifest
# repo sync -c -j2

. build/envsetup.sh && lunch aosp_cf_x86_64_auto-trunk_staging-userdebug && m -j32
