################################################################################
# @file      challenge.py
# @brief     
# @date      Sa Jul 2025
# @author    Dimitri Simon
# 
# PROJECT:   src
# 
# MODIFIED:  Sat Jul 19 2025
# BY:        Dimitri Simon
# 
# Copyright (c) 2025 Dimitri Simon
# 
################################################################################


import re
import traceback
import json
from .version import *
from packaging.version import InvalidVersion
from benedict import benedict
from dask import delayed, compute
import gc
from .load import load_cves
from .constants import *
from .utils import *


env = {
	"CVEs": []
}

def cves_init(start_year: int, keep_spaces: bool = False, write_out: bool = False):
	env["CVEs"] = load_cves(
		f"{'Formatting' if write_out else 'Loading'} CVEs since {start_year}",
		start_year,
		keep_spaces,
		write_out
	)

def slice_pkg(pkg: str, n: int) -> str:
	# Split and keep separators
	parts = re.split(r'([-_ ])', pkg)
	result = ''
	word_count = 0
	for part in parts:
		result += part
		if part not in '-_ ':
			word_count += 1
			if word_count == n:
				break
	return result

# Not to test if it's the result of splits:
invalid_product = [
	"base",
	"build",
	"pkg",
	"package",
	"product",
	"python3",
	"python",
	"lib",
	"ros",
	"ros-humble",
	"util",
	"utils",
	"all",
	"ubuntu",
	"deb"
	"debian",
	"linux",
	"core",
	"auto",
	"js",
	"json",
	"common",
	"at",
	"os",
	"session"
]

# out_pkg_list = [] # Contains only package names
 
def make_tasks(
	pkg_list: list[str],
	strict: bool,
	depth: int
) -> list:

	tasks = []
	out_pkg_list = []

	if depth == 0 or depth > 20:
		depth = 20 # We consider 20 as maximum depth

	for line in pkg_list:
		if not line or not isinstance(line, str) or not '=' in line:
			raise ValueError("Invalid line: " + str(line))
		line = line.strip()

		try:
			parts = list(filter(None, line.split("=")))
			if len(parts) != 2:
				raise ValueError ("Invalid line: " + line)
			pkg = parts[0].lower().strip()
			version = parts[1].strip()
			if not pkg:
				raise ValueError (f"Invalid package name: {pkg}")
			elif not version:
				raise ValueError (f"Invalid version '{version}' of package '{pkg}'")
		
			if pkg in out_pkg_list:
				# print(f"NOT testing package: {testing_pkg} (split {i + 1}/{max_split})")
				continue
			out_pkg_list.append(pkg)
			tasks.append(delayed(test_pkg)(pkg, version, depth, strict))
					
		except Exception as err:
			# if bar is not None:
			# 	bar.write(err)
			# else:
			traceback.print_exception(type(err), err, err.__traceback__)

	del out_pkg_list
	gc.collect()

	return tasks


def write_data(data: dict, affected: dict | list[dict] | None = None) -> dict:
	# Get the highest CVSS score
	if not isinstance(data.get("cvssMaxScore"), float) or data.get("cvssMaxScore") == -1:
		data["cvssMaxScore"] = get_cve_data(data["cveId"], False)[0]
	return {
		"cveId": data["cveId"],
		"cpe": {
			"product": affected.get("product") if isinstance(affected, dict) else None,
			"vendor": affected.get("vendor") if isinstance(affected, dict) else None,
			# "type": "application",
			"versions": affected
		},
		# "description": data["containers"]["cna"].get("descriptions", [{}])[0].get("value"),
		"cvss": {
			"maxScore": data["cvssMaxScore"],
			# "metrics": data["cvss"]["metrics"]
		}
	}

def test_container(data: dict, affected: list[dict], version: str, perfect_match: bool) -> dict | bool:
	# Package is affected
	# Check if the version is affected
	try:
		if is_affected(affected.get("versions", []), version, perfect_match):
			return write_data(data, affected)
		# print("Unaffected by "+data["cveId"])
	except InvalidVersion as e:
		traceback.print_exception(type(e), e, e.__traceback__)
		# print(f"Invalid version for {data["cveId"]}:", affected.get("versions", []))
	except VersionException:
		# print("version difference too wide")
		pass
	return None

def test_pkg(pkg: str, version: str, depth: int, strict: bool) -> dict:
	cves_matching = []

	try:
		max_split = max_split = pkg.count('-') + pkg.count('_') + pkg.count(' ') + 1

		for i in range(max_split):
			if i > depth or (i != 0 and strict):
				break
			testing_pkg = slice_pkg(pkg, (max_split - i))

			if i != 0:
				if len(testing_pkg) < 2 or testing_pkg in invalid_product: # or testing_pkg in out_pkg_list:
					continue
				# out_pkg_list.append(testing_pkg)

			slight_mod_testing_pkg = re.sub(SLIGHT_FORMAT, "", testing_pkg)
			formatted_pkg = re.sub(IGNORED_PREFIX+r"|"+SLIGHT_FORMAT, "", testing_pkg, flags=re.IGNORECASE)
			perfect_match = False

			# print(formatted_pkg)

			if slight_mod_testing_pkg in env["CVEs"]:
				cves_all = env["CVEs"][slight_mod_testing_pkg]
				perfect_match = True

			# Match after IGNORED_PREFIX removal
			elif formatted_pkg in env["CVEs"]:
				if len(formatted_pkg) < 2:
					continue
				# Check vendor with prefix ?
				if strict:
					# continue
					try:
						prefix = re.match(IGNORED_PREFIX, testing_pkg).group()[0:-1]
					except Exception:
						continue
					affected_list: list[dict] | dict = env["CVEs"][formatted_pkg][0].get("affected", [])
					# print(affected_list)
					def is_wanted(affected: dict, wanted: str) -> bool:
						vendor = affected.get("vendor", "").lower()
						if vendor:
							if wanted == vendor or \
								(wanted == "python3" and vendor == "python"):
								return True
						return False
					if isinstance(affected_list, dict):
						if not is_wanted(affected_list, prefix):
							continue
					elif isinstance(affected_list, list):
						found = False
						for affected in affected_list:
							if is_wanted(affected, prefix):
								found = True
								break
						if not found:
							continue
					else:
						continue
				cves_all = env["CVEs"][formatted_pkg]

			else:
				continue

			# print("perfect_match:", cves_all)

			# print(json.dumps(env["CVEs"][slight_mod_testing_pkg][1].get("affected"), default=serialize))

			for cve_data in cves_all:
				# if data["cveId"] != "CVE-2024-52007":
				# 	continue
				# print(data, data["affected"])
				if cve_data["affected"]:
					res = test_container(cve_data, cve_data["affected"], version, perfect_match)
					if res:
						cves_matching.append(res)
						# print("Appending "+cve_data["cveId"])
						# continue
					# else:
					# 	print("Did not append for None result: "+cve_data["cveId"])
				# else:
				# 	print("Did not append for affected field missing: "+cve_data["cveId"])

			if cves_matching:
				break

			# sleep(0.2)

		# if not strict:
		# 	unprefixed_pkg = re.sub(IGNORED_PREFIX, "", pkg)
		# 	if unprefixed_pkg != pkg:
		# 		test_pkg(unprefixed_pkg, version, depth, strict, False)
	except Exception as err:
		traceback.print_exception(type(err), err, err.__traceback__)

	# sleep(4)
	return {
		"product": pkg,
		"version": version,
		"cves": cves_matching
	}
