#!/usr/bin/env python3
################################################################################
# @file      main.py
# @brief     
# @date      Mo Jul 2025
# @author    
# 
# PROJECT:   CVE checker
# 
# MODIFIED:  Tue Jul 08 2025
# BY:        
# 
# Copyright (c) 2025 
# 
################################################################################

import os
import argparse
import argcomplete
import traceback
from dask import compute
import json

from src import *


def main():
	CVE_YEARS = get_cve_years(f"{CVELIST_DIRECTORY}/cves")
	if len(CVE_YEARS) == 0:
		from datetime import datetime
		wprint("No CVE directory")
		CVE_YEARS = [1999, datetime.now().year]
	assert IMPERFECT_MATCH_VERSION_MARGIN, "IMPERFECT_MATCH_VERSION_MARGIN is undefined. Expected a number between ] 0 ; 1 ["
	assert IMPERFECT_MATCH_VERSION_MARGIN > 0 and IMPERFECT_MATCH_VERSION_MARGIN < 1, \
		f"IMPERFECT_MATCH_VERSION_MARGIN invalid value {IMPERFECT_MATCH_VERSION_MARGIN}. Expected a number between ] 0 ; 1 ["

	def check_year(value):
		if hasattr(parser, '_skip_year_validation'):
			return int(value)
		value = int(value)
		if value < CVE_YEARS[0] or value > CVE_YEARS[-1]:
			raise argparse.ArgumentTypeError(f"{value} is invalid. Expect a number between {CVE_YEARS[0]} and {CVE_YEARS[-1]}")
		return value
	def check_pkg(value):
		parts = list(filter(None, value.split("=")))
		if len(parts) != 2:
			raise argparse.ArgumentTypeError ("Invalid line: " + value)
		pkg = parts[0].strip()
		version = parts[1].strip()
		if not pkg:
			raise argparse.ArgumentTypeError (f"Invalid package name: {pkg}")
		elif not version:
			raise argparse.ArgumentTypeError (f"Invalid version '{version}' of package '{pkg}'")
		return value
	def check_depth(value):
		value = int(value)
		if value < 0:
			raise argparse.ArgumentTypeError(f"{value} is invalid. Expect a positive number. 0 means limitless")
		return value

	def set_update_flag(option, opt_str, value, parser):
		global UPDATE_FLAG
		UPDATE_FLAG = True
		setattr(parser.values, option.dest, True)

	parser = argparse.ArgumentParser(
		usage=argparse.SUPPRESS,
		description="\x1b[4mUsage:\x1b[0m \x1b[36m%(prog)s\x1b[0m [OPTIONS] [ --pkg | --docker ] SOURCE...\n\nCheck vulnerabilities within a list of package=version",
		formatter_class=argparse.RawTextHelpFormatter,
		add_help=False
	)
	parser.add_argument('SOURCE', nargs="*", help=argparse.SUPPRESS)
	source_group = parser.add_argument_group("\x1b[4mSource\x1b[0m", description="Only one option can be used at a time.\nDefault is from a file containing a list of package=version")
	source_group.add_argument(
		'-p', '--pkg',
		# type=check_pkg,
		action="store_true",
		dest="PKG",
		help="SOURCE as package/version to check. Expect PKG_NAME=VERSION..."
    )
	source_group.add_argument(
		'-d', '--docker',
		# type=check_docker_dest,
		type=str.lower,
		choices=DOCKER_DEST,
		# metavar="TYPE",
		dest="DOCKER_DEST",
		default="",
		help="""SOURCE as Docker(s) to test. Docker type as parameter:
    fw: Framework(s)
    os: OS
  Supports OS using apt/apt-get, dnf or yum as package manager"""
	)
	option_group = parser.add_argument_group("\x1b[4mOptions\x1b[0m")
	option_group.add_argument(
		'-s', '--strict',
		action="store_true",
		dest="STRICT",
		default=False,
		help="""Perfect match only when specified
  Note: Higher accuracy take less time, but can be incomplete
  Default: Disabled""")
# 	option_group.add_argument(
# 		'-s', '--strict',
# 		choices=[str(e.value) for e in Strict],
# 		dest="STRICT",
# 		default=1,
# 		help="""0: Flexible
# 1: Check vendor flexibly and description WITH OR WITHOUT eventual 2nd part. Looking for the prefix anywhere
# Perfect match only when specified
# Note: Higher accuracy take less time, but can be incomplete
# Default: Disabled""")
	option_group.add_argument(
		'-y', '--year',
		type=check_year,
		dest="YEAR",
		default=DEFAULT_START_YEAR,
		help=f"""Look for CVEs since this year
Expect a number between {CVE_YEARS[0]} and {CVE_YEARS[-1]}
Default: {DEFAULT_START_YEAR}""")
	option_group.add_argument(
		'-u', '--update',
		action=UpdateAction,
		nargs=0,
		dest="UPDATE",
		help="""Format/update CVEs.
Argument -y/--year applies"""
    )
	option_group.add_argument(
		'--format-only',
		action="store_true",
		dest="FORMAT_ONLY",
		help="""Format CVEs.
Argument -y/--year applies"""
    )
	option_group.add_argument(
		'--depth',
		type=check_depth,
		dest="DEPTH",
		default=0,
		help="""Depth of submodules to check, in addition to the full-one.
  Cannot be used with -s/--strict
  0 means limitless.
  Default: 0"""
    )
	option_group.add_argument(
		'-t', '--test',
		action="store_true",
		dest="TEST",
		help="Launch test"
    )
	option_group.add_argument(
		'-k', '--keep-spaces',
		action="store_true",
		dest="SPACE",
		help="""Keep products containing spaces
You might want to enable this for products rather than packages"""
    )
	option_group.add_argument(
		'--scanner',
		type=str.lower,
		choices=["osv", "cbt", "grype", "trivy"],
		dest="SCANNER",
		metavar="SCANNER",
		help=f"""Scan using a different scanner:
  {command_exists('osv-scanner')}  osv: OSV-Scanner
  {command_exists('cve-bin-tool')}  cbt: CVE Binary Tool
  {command_exists('grype')}  grype: Grype
  {command_exists('trivy')}  trivy: Trivy"""
    )
	PLATFORM = ["linux", "windows", "macos", "ios", "android"]
	ARCHITECTURE = ["i386", "amd64", "arm", "arm64", "any"]
	non_docker_group = parser.add_argument_group("\x1b[4mNon-Docker specific\x1b[0m")
	# non_docker_group.add_argument(
	# 	'-l', '--platform',
	# 	metavar="PLATFORM",
	# 	choices=PLATFORM,
	# 	dest="PLATFORM",
	# 	help=""""""
    # )
	# non_docker_group.add_argument(
	# 	'-a', '--arch',
	# 	metavar="ARCHITECTURE",
	# 	choices=ARCHITECTURE,
	# 	dest="ARCHITECTURE",
	# 	help=""""""
    # )
	non_docker_group.add_argument(
		'-o', '--out',
		type=str,
		dest="OUT",
		default=DEFAULT_OUT,
		help=f"Output file\nDefault: '{DEFAULT_OUT}'")
	non_docker_group.add_argument(
		'-f', '--force',
		action="store_true",
		dest="FORCE",
		help="Force overwrite"
    )

	docker_group = parser.add_argument_group("\x1b[4mDocker specific\x1b[0m")
	docker_group.add_argument(
		'--pip',
		type=str.lower,
		choices=["yes", "no", "only"],
		dest="PIP",
		help="yes: Test pip dependencies (default)\nno: Do not test pip dependencies\nonly: Test only pip dependencies, not OS dependencies"
	)
	# docker_group.add_argument(
	# 	'--review-changelogs',
	# 	type=str,
	# 	dest="REVIEW_CHANGELOG",
	# 	help="Check changelogs for each CVE within the folder REVIEW_CHANGELOG, and modify reports in-place accordingly"
	# )
	# docker_group.add_argument(
	# 	'--exploit-only',
	# 	action="store_true",
	# 	dest="EXPLOIT_ONLY",
	# 	help="Try exploits only"
	# )
	docker_group.add_argument(
		'--upgrade',
		choices=ArgEnum.choices(Upgrade),
		metavar="UPGRADE",
		dest="UPGRADE",
		default=Upgrade.BOTH,
		help="""  0 / RAW:  Raw only (fast)
  1 / UP:   Upgrade only
  2 / BOTH: Both (default)"""
	)

	non_docker_group.add_argument(
		'--resolve',
		type=str,
		dest="RESOLVE",
		help="Resolve all unknown CVSS score within the folder RESOLVE"
	)

	non_docker_group.add_argument(
		'--allow-local',
		type=str.lower,
		choices=["yes", "no", "only"],
		dest="ALLOW_LOCAL",
		help="""yes:  Use local database (MITRE) and remote if not found
no:   Use remote databases only
only: Use local database only (MITRE)"""
	)

	option_group.add_argument('-h', '--help', action='help', help='Show this help message and exit')
	argcomplete.autocomplete(parser)
	args = parser.parse_args()

	# print(args)
 
	try:
		##### UPDATE CVEs LIST #####
		if args.UPDATE:
			if not args.FORMAT_ONLY:
				revert_and_pull(CVE_SUBMODULE_URL, CVE_SUBMODULE_PATH)
			cves_init(args.YEAR, args.SPACE, True)
			oprint("CVEs formatted successfully")
			return 0
		if args.RESOLVE is not None:
			resolve_unknown_scores(args.RESOLVE, args.ALLOW_LOCAL)
			return 0
		# if args.REVIEW_CHANGELOG is not None:
		# 	review_changelogs(args.REVIEW_CHANGELOG)
		# 	return 0

		### PREPARE ###
  
		# Setup ENV TEST
		if args.TEST:
			args.YEAR = DEFAULT_TEST_YEAR
			if not args.PKG and not args.SOURCE:
				args.SOURCE.append(DEFAULT_TEST_INPUT_FILE)
			args.OUT = DEFAULT_TEST_OUTPUT_FILE

		if args.DOCKER_DEST:
			process_dockers(args.SOURCE, args.DOCKER_DEST, args.UPGRADE, args.YEAR, args.PIP, False, args.DEPTH)			
		elif args.SCANNER:
			subprocess.run(f"./src/scan.sh {args.SCANNER} { ' '.join(args.SOURCE)}", shell = True, executable="/bin/bash")
		else:
			# .json missing
			if not args.OUT.endswith(".json"):
				args.OUT += ".json"

			# OUT dest already exist
			if not args.FORCE and os.path.isfile(args.OUT):
				answer = input(f"'{args.OUT}' already exist, do you want to overwrite it ? (y/N) ")
				if answer[0].lower() != "y":
					print("Aborted.")
					return 1

			##### CHALLENGE PKG PASSED THRU CLI #####
			if args.PKG:
				# print(args)
				cves_init(args.YEAR, args.SPACE)
				tasks = make_tasks(args.SOURCE, args.STRICT, args.DEPTH)
				with CustomProgressBar():
					results = compute(*tasks)
				with open(args.OUT, "w", encoding="utf-8") as out:
					out.write(json.dumps(results, default=serialize))
			
			##### CHALLENGE PKG IN FILES #####
			elif args.SOURCE:
				cves_init(args.YEAR, args.SPACE)
				process_csv(args.SOURCE[0], args.SOURCE[0], args.OUT, args.STRICT, args.DEPTH)

			else:
				parser.error("You must provide either at least one source or --pkg/-p argument.")
   
	except KeyboardInterrupt:
		pass
	except Exception as e:
		traceback.print_exception(type(e), e, e.__traceback__)
		return 1

if __name__ == "__main__":
	main()
