#!/usr/bin/env bash
################################################################################
# @file      reformulate-vuln-type.sed
# @brief     Filtering irrelevant packages in the context of next-gen vehicles
# @desc      Filtering is made on predefined pattern regarding packages that 
#              would be meaningless in the context of next-gen vehicles,
#              especially ;
#               - non-sudo command-line utilities,
#                   or softwares that can't lead to a privilege escalation,
#                   RCE or ACE through GUI (e.g apt, curl, git, ssh)
#               - script interpreters and compilers (e.g gcc, cmake, perl)
#              
#            Remaining packages are typically libraries, related to kernel,
#                bluetooth, wifi, and GUI applications.
#              
# @note      These OS didn't have any open ports when we tested, so the 
#              filtering exclude Git and SSH
# @note      GCC/Clang are excluded, but they might be useful when a CVE is
#              found in a compiled binary by them
#
# @date      Mo Jul 2025
# @author    Dimitri Simon
# 
# PROJECT:   VERA
# 
# MODIFIED:  Tue Jul 08 2025
# BY:        Dimitri Simon
# 
# Copyright (c) 2025 Dimitri Simon
# 
################################################################################


join_by() {
	local d=${1-} f=${2-}
	if shift 2; then
		printf %s "$f" "${@/#/$d}"
	fi
}

exclude_bin=(

# Package manager
	apt
	dnf
	yum
	dpkg
	rpm
	npm

# Editor
	"vim(-common)?"
	"emacs(-filesystem)?"
	nano

# Interpreters and compilers
	bison
	"c?make"
	"ninja(-build)?"
	"g?awk"
	perl
	ruby
	lua
	"node(js|-.+)?"
	gdb
	jq
	go
	"python3?(\.[0-9]+|-.+)?"
	"pip3?"
	"(gcc|clang|llvm)(-.+)?"
	bash
	numpy
	json-c

# networks utilities
	git
	ftp
	samba
	dnsmasq
	bind
	"(open|lib)?ssh(-server)?"
	# curl # can be libcurl
	wget
	scp
	traceroute
	ncurses
	tcpdump=.+ # tcpdump is also the vendor of libpcap
	iperf3
	sharutils
	apache	# Likely no service
	nginx	# Likely no service
	# conmon	# might lead to LPE through podman
	buildah
	thrift
	xerces-c
	cppcheck
	intel-mediasdk
	"gnupg2?"

# binary utils
	binutils
	coreutils # no suid binaries from it
	# util-linux # manage mount/umount (suid)
	file
	elfutils
	rsync
	# socat # not only exploitable through an open port
	
# File encoding
	tar
	xz
	"(un)?zip"
	# busybox # might be suid
	patch
	x264

# Coding
	doxygen

# Hardware
	Snapdragon.*
)

exclude_sys=(
	Go
	golang
	PyPI
)

grep -vE "(:|^)((.+/)?($(join_by '|' ${exclude_bin[*]}))(=.+)?|($(join_by '|' ${exclude_sys[*]})))(:|$)"
