#!/bin/bash
echo "
******************************************************************
*
*     Welcome to QNX ROS2 ${ROS2DIST} development environment
*     -------------------------------------------------------
*
* Default password for user is \"password\".
*
* Export CPU to x86_64 or aarch64 to build for a specific architecture.
* Unset CPU to build for all architectures.
*
* To build ROS2 run the following:
*
*   1- export CPU=x86_64
*      # or 
*      export CPU=aarch64
*      # or 
*      unset CPU
*   3- . ./env/bin/activate
*   4- cd ros2_${ROS2DIST}
*   5- ./build-ros2.sh
*
******************************************************************
"

# Setup environment variables
echo "QNX Environment variables are set to:"
source $HOME/qnx800/qnxsdp-env.sh
echo ""
