#!/usr/bin/python3
################################################################################
# @file      utils.py
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


from __future__ import annotations
from dask.diagnostics import ProgressBar
# from dask.utils import format_time
from functools import reduce
import sys
import time
import contextlib
import shutil
from packaging.version import Version
from .constants import VERSION_KEY, CVELIST_DIRECTORY
import traceback

import git
import os
import re
import requests
from rich import console, progress


def max_score(metrics: list[dict]) -> float:
	highest_cvss_score = -1
	for cvss in metrics:
		metric = firstval(cvss)
		if isinstance(metric, dict):
			score = metric.get("baseScore", -1)
			if score > highest_cvss_score:
				highest_cvss_score = score
	return highest_cvss_score

class VersionException(Exception):
	"""When large difference in major"""
 
 
def format_time(n: float) -> str:
    """format integers as time

    >>> from dask.utils import format_time
    >>> format_time(1)
    '1 s'
    >>> format_time(0.001234)
    '1 ms'
    >>> format_time(0.00012345)
    '123 us'
    >>> format_time(123.456)
    '123 s'
    >>> format_time(1234.567)
    '20m 34s'
    >>> format_time(12345.67)
    '3hr 25m'
    >>> format_time(123456.78)
    '34hr 17m'
    >>> format_time(1234567.89)
    '14d 6hr'
    """
    if n > 24 * 60 * 60 * 2:
        d = int(n / 3600 / 24)
        h = int((n - d * 3600 * 24) / 3600)
        return f"{d}d {h}hr"
    if n > 60 * 60 * 2:
        h = int(n / 3600)
        m = int((n - h * 3600) / 60)
        return f"{h}hr {m}m"
    if n > 60 * 10:
        m = int(n / 60)
        s = int(n - m * 60)
        return f"{m}m {s}s"
    if n >= 1:
        return "%.0f s" % n
    if n >= 1e-3:
        return "%.0f ms" % (n * 1e3)
    return "%.0f us" % (n * 1e6)

class CustomProgressBar(ProgressBar):
	desc = ""
	_columns = -1

	def __init__(self, desc: str = "", minimum: int = 8, dt: float = 0.1, out: object | None = None):
		super().__init__(minimum, minimum, dt, out)
		if desc:
			self.desc = desc+": "
		self._width = minimum
		self._update_bar_length()

	def _update_bar_length(self):
		try:
			columns = shutil.get_terminal_size((80, 20)).columns
		except:
			columns = 80
		if self._columns == columns:
			return self._width
		self._columns = columns

		fixed_elements = len("\r{0}{3}%\u2595{1:<{2}}\u258f {4} | {5} ".format(
			self.desc, 0, 0, 100, (20*60+59)*(60+59)*1000, (20*60+59)*(60+59)*1000
		))
		# print(self._minimum, columns, fixed_elements)
		self._width = max(self._minimum, columns - fixed_elements)
		return self._width

	def _draw_bar(self, frac: float, elapsed: float):
		bar = "\u2588" * int(self._width * frac)
		percent = int(100 * frac)
		remaining =  "?" if frac == 0 else format_time((elapsed * (1.0-frac) / frac))
		elapsed = format_time(elapsed)
		msg = "\r{0}{3}%\u2595{1}\u258f {4} | {5} ".format(
			self.desc, bar + " "*(self._update_bar_length()-len(bar)), "", percent, elapsed, remaining
		)
		with contextlib.suppress(ValueError):
			if self._file is not None:
				self._file.write(msg)
				self._file.flush()
				
def sleep(ms: int):
	time.sleep(ms/1000)

def flatten(l: list[list]) -> list:
	return [item for sublist in l for item in sublist]

def get_nested(obj: dict, path: str, default: dict | list | None = None) -> dict | list:
	"""
	@brief Get a nested value from a dict using a dot-separated path.
	@param obj dict: The dict to search.
	@param path str: The dot-separated path to the value.
	@return list: The value at the specified path
	"""
	try:
		if not obj:
			return default
		if not path:
			return obj
		if '.' not in path:
			return obj.get(path, default)

		res = reduce(dict.get, path.split("."), obj)
		return default if res is None else res
	except Exception as e:
		return default

def eprint(*args, **kwargs):
    print("\x1b[31m[-]\x1b[0m", *args, file=sys.stderr, **kwargs)

def wprint(*args, **kwargs):
    print("\x1b[33m[!]\x1b[0m", *args, file=sys.stderr, **kwargs)

def oprint(*args, **kwargs):
    print("\x1b[32m[+]\x1b[0m", *args, **kwargs)

def iprint(*args, **kwargs):
    print("\x1b[34m[*]\x1b[0m", *args, **kwargs)

def serialize(obj: str | Version) -> str | dict:
	"""JSON serializer for objects not serializable by default json code"""
	if isinstance(obj, Version):
		return { VERSION_KEY: str(obj) }
	return obj.__dict__

def deserialize(obj: dict) -> Version | dict:
	"""JSON serializer for objects not serializable by default json code"""
	if VERSION_KEY in obj and isinstance(obj[VERSION_KEY], str):
		return Version(obj[VERSION_KEY])
	return obj

def firstval(d: dict, e: object = None) -> object:
	try:
		return next(iter(d.values()), e)
	except TypeError:
		return e

class CustomRemoteProgress(git.RemoteProgress):
	OP_CODES = [
		"BEGIN",
		"CHECKING_OUT",
		"COMPRESSING",
		"COUNTING",
		"END",
		"FINDING_SOURCES",
		"RECEIVING",
		"RESOLVING",
		"WRITING",
	]
	OP_CODE_MAP = {
		getattr(git.RemoteProgress, _op_code): _op_code for _op_code in OP_CODES
	}
	progressbar = None

	def __init__(self) -> None:
		super().__init__()
		self.progressbar = progress.Progress(
			progress.SpinnerColumn(),
			# *progress.Progress.get_default_columns(),
			progress.TextColumn("[progress.description]{task.description}"),
			progress.BarColumn(),
			progress.TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
			"eta",
			progress.TimeRemainingColumn(),
			progress.TextColumn("{task.fields[message]}"),
			console=console.Console(),
			transient=False,
		)
		self.progressbar.start()
		self.active_task = None

	def __del__(self) -> None:
		# logger.info("Destroying bar...")
		if self.progressbar is not None:
			self.progressbar.stop()
			self.progressbar = None
			# logger.info("Bar destroyed.")
		else:
			# logger.warning("Bar already destroyed.")
			pass

	@classmethod
	def get_curr_op(cls, op_code: int) -> str:
		"""Get OP name from OP code."""
		# Remove BEGIN- and END-flag and get op name
		op_code_masked = op_code & cls.OP_MASK
		return cls.OP_CODE_MAP.get(op_code_masked, "?").title()

	def update(
		self,
		op_code: int,
		cur_count: str | float,
		max_count: str | float | None = None,
		message: str | None = "",
	) -> None:
		# Start new bar on each BEGIN-flag
		if op_code & self.BEGIN:
			self.curr_op = self.get_curr_op(op_code)
			# logger.info("Next: %s", self.curr_op)
			self.active_task = self.progressbar.add_task(
				description=self.curr_op,
				total=max_count,
				message=message,
			)

		self.progressbar.update(
			task_id=self.active_task,
			completed=cur_count,
			message=message,
		)

		# End progress monitoring on each END-flag
		if op_code & self.END:
			# logger.info("Done: %s", self.curr_op)
			self.progressbar.update(
				task_id=self.active_task,
				message=f"[bright_black]{message}",
			)

def revert_and_pull(url, path):
	try:
		if os.path.exists(path):
			repo = git.Repo(path)
			repo.remotes.origin.pull(progress=CustomRemoteProgress())
		else:
			git.Repo.clone_from(url=url, to_path=path, depth=1, progress=CustomRemoteProgress())

		oprint("CVEs updated successfully")
	except Exception as e:
		traceback.print_exception(type(e), e, e.__traceback__)
		# eprint(f"An error occurred: {e}")

def command_exists(name: str) -> str:
	"""Check whether `name` is on PATH and marked as executable."""
	return ("\x1b[32;1m\u2714" if shutil.which(name) is not None else "\x1b[31;1m\u2a2f")+"\x1b[0m"

# Better to not precompute
# https://docs.redhat.com/en/documentation/red_hat_security_data_api/1.0/html-single/red_hat_security_data_api/index#retrieve_a_cve
# https://access.redhat.com/hydra/rest/securitydata/cve/CVE-0000-0000.json
REDHAT_API = "https://access.redhat.com/hydra/rest/securitydata/cve/{}.json"
NIST_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"
GITHUB_SEARCH = "https://github.com/advisories?query={}"
OSV_VULN = "https://osv.dev/vulnerability/UBUNTU-{}"
OSV_ANDROID = "https://api.osv.dev/v1/vulns/{}"

def get_cve_data(cveid: str, ecosystem_id: str|None, allow_local: str = "yes") -> (
		float,
		str,
		str,
		list[str]
	):
	"""
		@param cveid CVE
		@param allow_local Local lookup #

		@return (
			cvss: float,
			cvss_scoring: str,
			package: str,
			cwes: list[str]
		)
	"""
	from benedict import benedict

	if allow_local != "no":

		# Android
		if isinstance(ecosystem_id, str):
			import zipfile, json

			try:
				archive = zipfile.ZipFile('android.zip', 'r')

				raw = archive.read(ecosystem_id + '.json')
				parsed = json.loads(raw)
				data = benedict(parsed, format="json") \
					.get("affected[0]")

				return [
					data.get("ecosystem_specific.severity"),
					','.join(data.get("ecosystem_specific.types")),
					data.get("package.name"),
					[]
				]
			except KeyError:
				pass
		
		year = 0
		num = 0
		cve_prefix = ""
		if cveid.startswith("CVE-"):
			year, num = cveid.split("-")[1:]
			cve_prefix = ""
			if len(num) < 3:
				cve_prefix = "0"
				num = "%04d" % int(num)
			else:
				cve_prefix = num[:-3]


		# MITRE
		filepath = f"{CVELIST_DIRECTORY}/cves/{year}/{cve_prefix}xxx/CVE-{year}-{num}.json"
		if os.path.isfile(filepath):
			data = benedict.from_json(filepath)
			def extract(cvss, version):
				return [
					float(cvss.get("baseScore") or cvss.get("score")),
					cvss.get("vectorString"),
					# "version": version,
				]

			# if data.find(path) is not None:
			candidates = []
			cvss_keys = ["cvssV2_0", "cvssV3_0", "cvssV3_1", "cvssV4_0"]

			# CNA metrics
			for metric in data.get("containers.cna.metrics", []):
				for cvss_key in cvss_keys:
					cvss = metric.get(cvss_key)
					if cvss and isinstance(cvss.get("baseScore") or cvss.get("score"), (int, float)):
						candidates.append(extract(cvss, cvss_key))

			# ADP metrics
			for adp in data.get("containers.adp", []):
				# adp = benedict(adp)
				for metric in adp.get("metrics", []):
					for cvss_key in cvss_keys:
						cvss = metric.get(cvss_key)
						if cvss and isinstance(cvss.get("baseScore") or cvss.get("score"), (int, float)):
							candidates.append(extract(cvss, cvss_key))

			highest = max(candidates, key=lambda x: x[0], default=None)
			# print(highest)
			# sys.exit(1)

			if highest is not None:
				def extract_all_cwe_ids(data):
					all_cwe_ids = []

					# Handle 'cna' object
					problem_types = data.get('containers.cna.problemTypes', [])
					for problem in problem_types:
						descriptions = problem.get('descriptions', [])
						for desc in descriptions:
							cwe_id = desc.get('cweId')
							if cwe_id:
								all_cwe_ids.append(cwe_id)

					# Handle 'adp' list
					adp_list = data.get('containers.adp', [])
					for adp in adp_list:
						problem_types = adp.get('problemTypes', [])
						for problem in problem_types:
							descriptions = problem.get('descriptions', [])
							for desc in descriptions:
								cwe_id = desc.get('cweId')
								if cwe_id:
									all_cwe_ids.append(cwe_id)

					return list(set(all_cwe_ids))  # remove duplicates

				product = data.get("containers.cna.affected[0].product")
				if not product or product == "n/a":
					product = "?"
				return highest + [
					data.get("containers.cna.affected[0].product"),
					extract_all_cwe_ids(data)
				]
	
	if allow_local == "only":
		return [-1, "", "", []]

	def __request(url: str, cveid: str, default_path: str | None = None) -> tuple[dict | None, float]:
		try:
			obj = benedict(url.format(cveid), format="json")
			if not default_path:
				return obj
			return obj[default_path]
		except:
			return {}


	# Gave up with Grype's database
	# RedHat
	# data = __request(
	# 		REDHAT_API,
	# 		cveid,
	# )
	# if "message" not in data:
	# 	metrics = data.get("cvss3", {}) | data.get("cvss", {})
	# 	if metrics:
	# 		cvss3 = float(metrics.get("cvss3_base_score", -1))
	# 		cvss2 = float(metrics.get("cvss_base_score", -1))
	# 		cvss3_scoring = metrics.get("cvss3_scoring_vector", -1)
	# 		cvss2_scoring = metrics.get("cvss_scoring_vector", -1)
	# 		highest_cvss = [cvss3, cvss3_scoring] \
	# 			if cvss3 > cvss2 else \
	# 				[cvss2, cvss2_scoring]
	# 		# metrics["source"] = f"https://access.redhat.com/hydra/rest/securitydata/cve/{cveid}.json"
	# 		if highest_cvss[0] != -1:
	# 			package_name = data.get("package_state[0].package_name", "")
	# 			cwe = [data.get("cwe", "")]
	# 			return highest_cvss + [package_name, cwe]

	# # NIST
	# data = __request(
	# 	NIST_API,
	# 	cveid,
	# 	"vulnerabilities[0].cve"
	# )
	# metrics = data.get("metrics", {})
	# if isinstance(metrics, dict):
	# 	highest_cvss = -1
	# 	highest_scoring_vector = -1
	# 	for cvss in metrics:
	# 		for i in range(len(metrics[cvss])):
	# 			score = float(metrics[cvss][i].get("cvssData.baseScore"))
	# 			scoring_vector = metrics[cvss][i].get("cvssData.vectorString")
	# 			if score > highest_cvss:
	# 				highest_cvss = score
	# 				highest_scoring_vector = scoring_vector
	# 	# metrics["source"] = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cveid}"
	# 	if highest_cvss != -1:
	# 		def extract_all_cwe_ids_nist(data):
	# 			d = benedict(data, keypath_separator='.')

	# 			cwe_ids = set()

	# 			vulnerabilities = d.get('vulnerabilities', [])
	# 			for vuln in vulnerabilities:
	# 				cve = vuln.get('cve', {})
	# 				weaknesses = cve.get('weaknesses', [])

	# 				for weakness in weaknesses:
	# 					descriptions = weakness.get('description', [])
	# 					for desc in descriptions:
	# 						value = desc.get('value')
	# 						if isinstance(value, str) and value.startswith('CWE-'):
	# 							cwe_ids.add(value)
	# 			return list(cwe_ids)


	# 		product = data.get("configurations[0].nodes[0].cpeMatch[0]criteria", "::::").split(":")[3]
	# 		cwes = extract_all_cwe_ids_nist(data)
	# 		return [
	# 			highest_cvss,
	# 			highest_scoring_vector,
	# 			product,
	# 			cwes
	# 		]

	# GitHub Advisories
	response = requests.get(GITHUB_SEARCH.format(cveid))
	match = re.search(r'href="(/advisories/[^"]+)"', response.text)
	if match:
		link = "https://github.com" + match.group(1)
		response = requests.get(link)
		match = re.search(r'Button-label">([0-9.]+)<', response.text)
		if match:
			return [float(match.group(1)), "", "", []]

	# OSV
	response = requests.get(OSV_VULN.format(cveid))
	match = re.search(r'severity-level [a-z-]+">([0-9.]+)', response.text)
	if match:
		score = match.group(1)
		if score:
			return [float(match.group(1)), "", "", []]
	return [-1, "", "", []]
