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

# Normal
s#^(.+ /usr/.+/(g?passwd|ch(sh|fn|age)|su(do)?|pkexec|polkit-agent-helper-1|ssh-keysign|dbus-daemon-launch-helper|unix_chkpwd|pam_extrausers_chkpwd|pam_timestamp_check|fusermount3))#\x1b[32;2m\1\x1b[0m#

s#^(-rwx(r|-)-s(r|-)-x root (shadow /usr/.+/expiry|_?ssh /usr/.+/ssh-agent|tty /usr/.+/write|utmp /usr/.+/utempter))#\x1b[32;2m\1\x1b[0m#

# Policy dependent
s#^(.+ /usr/.+/(u?mount(\.nfs)?|grub2-set-bootflag|newgrp))#\x1b[33m\1\x1b[0m#

# Uncommon
s#^(-.+)#\x1b[31m\1\x1b[0m#
