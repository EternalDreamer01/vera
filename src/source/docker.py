#!/usr/bin/python3
################################################################################
# @file      docker.py
# @brief     
# @date      Sa Jul 2025
# @author    Dimitri Simon
# 
# PROJECT:   challenge
# 
# MODIFIED:  Sat Jul 19 2025
# BY:        Dimitri Simon
# 
# Copyright (c) 2025 Dimitri Simon
# 
################################################################################

import os
import sys
import docker
import subprocess
from ..challenge import cves_init
from .file import process_csv
from ..docker import *
from ..utils import eprint, oprint, iprint
from ..arg import Upgrade
from dask import delayed, compute


# https://docker-py.readthedocs.io/en/stable/index.html
# https://docker-py.readthedocs.io/en/stable/containers.html

def process_dockers(dockers: list[str], dest: str, shall_upgrade: int, year: int, pip: str, exploit_only: bool, depth: int):
    
	os.makedirs(HOST_CACHE_PATH, exist_ok=True)

	# current_mode = stat.S_IMODE(os.lstat(HOST_CACHE_PATH).st_mode)
	# desired_mode = stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO  # 0o777

	# if current_mode != desired_mode:
	# 	os.chmod(HOST_CACHE_PATH, desired_mode)
	# 	oprint(f"Permissions updated for '{HOST_CACHE_PATH}' to {oct(desired_mode)}")
    # print(shall_upgrade)
	if isinstance(shall_upgrade, str):
		shall_upgrade = Upgrade[shall_upgrade]
	elif isinstance(shall_upgrade, int):
		shall_upgrade = Upgrade[shall_upgrade]

	client = docker.from_env()

	OUT_RAW = "raw"
	OUT_FULL_UPGRADE = "fup"

	RP_RAW = f"/{OUT_RAW}/{OUT_RAW}.csv"
	RP_RAW_MIN = f"/{OUT_RAW}/{OUT_RAW}.min.csv"
	RP_FULL_UPGRADE = f"/{OUT_FULL_UPGRADE}/{OUT_FULL_UPGRADE}.csv"
	RP_FULL_UPGRADE_MIN = f"/{OUT_FULL_UPGRADE}/{OUT_FULL_UPGRADE}.min.csv"

	if pip != "only" and not exploit_only:
		iprint("CVE minimal year:  {}".format(year))
		iprint("Depth:             {}".format("Limitless" if depth == 0 else depth))

		cves_init(year, False)
	strip_py = pip == "yes"

	def process_image(image: str):
		try:
			name = image.split(" ")[-1].strip()
			# raise Exception("OK")
			print()
			iprint(name+"::")
			# abs_path = os.path.dirname(os.path.realpath(__file__))+"/os/"+name
			rel_path = f"out/{dest}/{name.replace(':', '/')}"
			container = client.containers.run(
				name,
				command="sleep infinity",
				user=0,
				detach=True,
				privileged=True,
				remove=True,
				tty=True,
				# stdin_open=True,
				volumes={
					"/sys/fs/cgroup": {
						"bind": "/sys/fs/cgroup",
						"mode": "ro"
					},
					os.path.expanduser("~/.cache/cve-bin-tool"): {
						"bind": "/root/.cache/cve-bin-tool",
						"mode": "rw"
					}
				},
				cgroupns="host"
			)
			
			exit_code, output = container.exec_run("python3 -V")

			# If Python isn't installed, do not check pip packages, eventually the ones from apt
			py_has = exit_code != 127
			py_version = ""
			if py_has:
				py_version = output.decode('unicode_escape').split(" ")[1]

			header_len, list_installed, install_pip_dep, update, upgrade, autoremove = determine_pkg_mngr(container)
			if pip != "only" and not exploit_only:
				if not list_installed:
					raise Exception("Unsupported package manager")
				# Raw
				if shall_upgrade != Upgrade.UP or upgrade == UPGRADE_NON_AVAILABLE:
					output = container_exec_run(container, list_installed, stderr=False)
					# assert exit_code == 0, output
					aptlist = "\n".join(output.decode("unicode_escape").split("\n")[header_len:])
					os.makedirs(f"{rel_path}/{OUT_RAW}", exist_ok=True)
					with open(rel_path + RP_RAW, "w", encoding="utf-8") as f:
						f.write(aptlist)
					subprocess.run([os.path.dirname(os.path.realpath(__file__))+"/../parser/minify.sh", rel_path + RP_RAW, str(strip_py and py_has)])
					process_csv(rel_path + RP_RAW_MIN, f"RAW {name}", f"{rel_path}/{OUT_RAW}/flex.json", False, depth)
					process_csv(rel_path + RP_RAW_MIN, f"RAW {name}", f"{rel_path}/{OUT_RAW}/strict.json", True, depth)

				# Full upgrade
				if shall_upgrade != Upgrade.RAW and upgrade != UPGRADE_NON_AVAILABLE:
					output = container_exec_run(
						container, [
							update,
							upgrade,
							autoremove,
							list_installed
						],
						good_status=[0,100], # RedHat exit status on update
						desc = "Upgrading",
						stderr_on_last=False
					)
					aptlist = "\n".join(output.decode("unicode_escape").split("\n")[header_len:])
	
					os.makedirs(f"{rel_path}/{OUT_FULL_UPGRADE}", exist_ok=True)
					with open(rel_path+RP_FULL_UPGRADE, "w", encoding="utf-8") as f:
						f.write(aptlist)
					subprocess.run([os.path.dirname(os.path.realpath(__file__))+"/../parser/minify.sh", rel_path+RP_FULL_UPGRADE, str(strip_py and py_has)])
					process_csv(rel_path + RP_FULL_UPGRADE_MIN, f"Upgrade {name}", f"{rel_path}/{OUT_FULL_UPGRADE}/flex.json", False, depth)
					process_csv(rel_path + RP_FULL_UPGRADE_MIN, f"Upgrade {name}", f"{rel_path}/{OUT_FULL_UPGRADE}/strict.json", True, depth)

			try:
				if py_has:
					if pip != "no" and not exploit_only:
						cves_json = pip_audit(container, update, install_pip_dep, py_version)
						with open(rel_path+"/pip.json", "w", encoding="utf-8") as f:
							f.write(json.dumps(cves_json))
				else:
					print("  \x1b[2mPython not installed. Skipping pip-audit\x1b[0m")
				# if not pip_only:
				# 	exploit(container, py_has)
			except Exception as e:
				exc_type, exc_obj, exc_tb = sys.exc_info()
				fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
				eprint(exc_type, fname, exc_tb.tb_lineno, e)
		except Exception as e:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			eprint(f"{type(e).__name__} at \x1b[4m{fname}:{exc_tb.tb_lineno}\x1b[0m, while testing \x1b[4m{name}\x1b[0m:\n  {e}")
	# tasks = []
	for image in dockers:
			process_image(image)
	# with CustomProgressBar():
	# 	compute(*tasks_pip)
