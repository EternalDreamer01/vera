#!/bin/sh


grep "aosp_.*-userdebug" "$(realpath "$(dirname "$0")/os/device/google/cuttlefish/AndroidProducts.mk")"
