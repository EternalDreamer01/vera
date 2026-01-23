#!/usr/bin/env python3
import os, sys
import docker, re, json
from .utils import *
from dask import delayed, compute


AVAILABLE = [
	[
		"apt -h && apt-get -h",	# Test
		"apt-get changelog"
	],
	[
		"dnf",
		"dnf changelog"
	],
	[
		"yum",
		"yum changelog"
	]
]
def determine_cmd(container: object) -> str | None:
	for i in range(len(AVAILABLE)):
		exit_code, _ = container.exec_run(AVAILABLE[i][0])
		if exit_code == 0:
			return AVAILABLE[i][1]
	return None

def read_cves(filepath: str) -> dict[list[str]]:
	data = {}
	result = {}

	with open(filepath, 'r') as file:
		data = json.load(file)

	for entry in data:
		pkg = entry.get("name", "")
		cve_id = entry.get("cveId", "")
		if pkg and cve_id:
			if pkg in result:
				result[pkg].append(cve_id)
			else:
				result[pkg] = [cve_id]
	return data, result

def rreplace(s, old, new, occurrence):
	li = s.rsplit(old, occurrence)
	return new.join(li)

def review_changelogs(path: str):
	onlyfiles = [os.path.join(path, f) for f in os.listdir(path) if f.endswith(".json") and os.path.isfile(os.path.join(path, f))]
	if len(onlyfiles) == 0:
		for f in os.listdir(path):
			if os.path.isdir(os.path.join(path, f)):
				review_changelogs(os.path.join(path, f))
		return

	image = path
	if image.startswith("./"):
		path = path[2:]
	if image.startswith("out/os/") or image.startswith("out/fw/"):
		image = image[7:]
	elif image.startswith("out/"):
		image = image[4:]

	image = rreplace(image, os.sep, ':', 1)

	client = docker.from_env()


	try:
		# print(f"[*] Searching inside container {container.short_id}...")
		cve_data = {}
		files_raw = [f for f in onlyfiles if f.split(os.sep)[-1].startswith("raw.")]
		if len(files_raw) != 0:
			container = client.containers.run(
				image,
				"sleep infinity",
				detach=True,
				user=0,
				tty=True
			)
			cmd_changelog = determine_cmd(container)
			if cmd_changelog is None:
				raise ValueError("Could not determine package manager")

			files_raw_content = {}
			iprint("Reading reports for raw OS:", files_raw)
			for filepath in files_raw:
				data, next_cves = read_cves(filepath)
				files_raw_content[filepath] = data
				for pkg in next_cves:
					if pkg in cve_data:
						cve_data[pkg].extend(next_cves[pkg])
					else:
						cve_data[pkg] = next_cves[pkg]

			# total = len(cve_data)
			# reviewed = 0
			# fixed = 0

			def check_changelogs(pkg: str, cve_ids: list[str]):
				exit_code, output = container.exec_run(f"{cmd_changelog} {pkg}")
				cves_fixed = re.findall(r'\b(CVE(?:-|\xe2\x80\x91)\d{4}(?:-|\xe2\x80\x91)\d{4,})\b', output.decode("utf-8"), flags=re.UNICODE|re.IGNORECASE)
				
				return (pkg, list(set(cves_fixed) - set(cve_ids)))

			tasks = [
				delayed(check_changelogs)(pkg, cve_ids)
				for pkg, cve_ids
				in cve_data.items()
				if not pkg.startswith(".../") 
			]

			with CustomProgressBar():
				results = compute(*tasks)

			print(results)
			for pkg, cves_fixed in results:
				if len(cves_fixed) == 0:
					continue
				for filepath in files_raw_content:
					updated = False
					for entry in files_raw_content[filepath]:
						if entry.get("name", "") == pkg:
							cve_id = entry.get("cveId", "")
							if cve_id in cves_fixed:
								entry["status"] = "fixed"
								updated = True
					if updated:
						with open(filepath, 'w') as file:
							json.dump(files_raw_content[filepath], file, indent=4)

				iprint(f"Package '{pkg}': {len(cves_fixed)}/{len(cve_data[pkg])} CVEs fixed in changelog")
				
		# cmd_changelog = determine_cmd(container)
		# if cmd_changelog is None:
		# 	raise ValueError("Could not determine package manager")

		# exit_code, output = container.exec_run(
		# 	cmd_changelog,
		# 	environment=[
		# 		"PAGER=cat"
		# 	]
		# )
		# # print("done")
  
		# adjust = len(max(cve_ids, key=len))
  
		# # output.decode("utf-8").splitlines()

		# for line in output.decode("utf-8").splitlines():
		# 	for cve_id in cve_ids[:]:
		# 		if re.compile(rf'\b{cve_id}\b').search(line):
		# 			print(f"\x1b[32;1m{cve_id.ljust(adjust, ' ')} fixed \u2714\x1b[0m")
		# 			cve_ids.remove(cve_id)

		# for cve_id in cve_ids:
		# 	print(f"\x1b[31;1m{cve_id.ljust(adjust, ' ')} not fixed \u2a2f\x1b[0m")

	except ValueError as e:
		print(e)

	except docker.errors.ContainerError:
		print("\x1b[31mDoes not appear in changelog !\x1b[0m")

