#!/usr/bin/env python3
import os
import subprocess
import sys
from pathlib import Path
import tarfile
import io
import argparse

# Detect if running inside a container
INSIDE_CONTAINER = os.environ.get("INSIDE_CONTAINER") == "1"

# Always define HAS_DOCKER
HAS_DOCKER = False

# Import Docker SDK only on host
if not INSIDE_CONTAINER:
	try:
		import docker
		HAS_DOCKER = True
	except ImportError:
		HAS_DOCKER = False

# Try to import Dask (both host and container)
try:
	from dask import bag as db
	from dask.diagnostics import ProgressBar
	USE_DASK = True
except ImportError:
	USE_DASK = False

DEFAULT_DIRS = [
	"/lib",
	"/usr/lib",
	str(Path.home() / ".local/lib"),
	"/usr/local/lib",
	"/var/lib",
	"/opt",
]

DEFAULT_DIRS_ANDROID = [
	"/apex",
	"/data",
	"/dev/memcg"
	"/product",
	"/system",
	"/system_dklm/lib/modules",
	"/system_ext/lib64",
	"/vendor",
]

AVAILABLE = [
	[
		"apt -h && apt-get -h", (	# Test
			"apt-get update -y",	# Update
			"apt-get install -y binutils python3 python3-pip",	# Install dependencies for pip
	)],
	[
		"dnf", (					# Test
			"dnf check-update -y",	# Update
			"dnf install -y binutils python3 python3-pip",	# Install dependencies for pip
	)],
	[
		"yum", (					# Test
			"yum check-update -y",	# Update
			"yum install -y binutils python3 python3-pip",	# Install dependencies for pip
	)],
	[
		"apk version", (
			"apk update",
			"apk add binutils python3 py3-pip",
		)
	]
]

def eprint(*args, **kwargs):
    print("\x1b[31m[-]\x1b[0m", *args, file=sys.stderr, **kwargs)

def wprint(*args, **kwargs):
    print("\x1b[33m[!]\x1b[0m", *args, file=sys.stderr, **kwargs)

def oprint(*args, **kwargs):
    print("\x1b[32m[+]\x1b[0m", *args, **kwargs)

def iprint(*args, **kwargs):
    print("\x1b[34m[*]\x1b[0m", *args, **kwargs)

def determine_pkg_mngr(container: object):
	"""Determine package manager inside the container."""
	for i in range(len(AVAILABLE)):
		exit_code, _ = container.exec_run(AVAILABLE[i][0])
		if exit_code == 0:
			return AVAILABLE[i][1]
	return None, None

def has_symbol(lib_path, symbol):
	"""Return True if 'symbol' is defined in 'lib_path'."""
	try:
		proc = subprocess.run(
			["readelf", "-Ws", lib_path],
			capture_output=True, text=True, check=False
		)
		for line in proc.stdout.splitlines():
			parts = line.split()
			if not parts:
				continue
			sym_name = parts[-1]
			sym_base = sym_name.split('@')[0]  # strip version
			if sym_base == symbol:
				return True
	except Exception:
		pass
	return False

def find_symbol_in_dirs(dirs, symbol):
	"""Search for 'symbol' in shared libraries under 'dirs', skipping symlinks."""
	files = []
	for base_dir in dirs:
		if os.path.islink(base_dir):
			continue
		for root, _, fnames in os.walk(base_dir):
			if os.path.islink(root):
				continue
			for fname in fnames:
				fullpath = os.path.join(root, fname)
				if os.path.islink(fullpath):
					continue
				if fname.endswith(".so") or ".so." in fname:
					files.append(fullpath)

	if USE_DASK:
		bag = db.from_sequence(files, partition_size=20)
		with ProgressBar():
			results = bag.map(lambda f: f if has_symbol(f, symbol) else None).compute()
		return [r for r in results if r is not None]
	else:
		if not INSIDE_CONTAINER:
			iprint("Dask not installed, running sequentially...")
		results = []
		for f in files:
			if has_symbol(f, symbol):
				results.append(f)
		return results

def run_in_docker(image, symbol, directories):
	"""Copy the script into a container and run it there."""
	if not HAS_DOCKER:
		eprint("Docker SDK not installed on host. Run: pip install docker")
		sys.exit(1)

	client = docker.from_env()
	container = client.containers.run(image, "sleep infinity", detach=True, user=0)

	try:
		# Copy this script into container
		script_path = os.path.realpath(__file__)
		with open(script_path, "rb") as f:
			data = f.read()
		tarstream = io.BytesIO()
		with tarfile.open(fileobj=tarstream, mode="w") as tar:
			info = tarfile.TarInfo(name="script.py")
			info.size = len(data)
			tar.addfile(info, io.BytesIO(data))
		tarstream.seek(0)
		container.put_archive("/tmp", tarstream)

		# Install dependencies inside container
		exit_code, output = container.exec_run("python3 && pip3")
		if exit_code != 0:
			iprint("Installing dependencies inside container...")
			pkg_updates, pkg_install = determine_pkg_mngr(container)
			if not pkg_updates or not pkg_install:
				eprint("No supported package manager found in container.")
				return
			exit_code, output = container.exec_run(pkg_updates)
			exit_code, output = container.exec_run(pkg_install)
			if exit_code != 0:
				eprint("Failed to install dependencies in container.")
				return
			oprint("Dependencies installed.")
				
		exit_code, output = container.exec_run("pip3 install dask")
		if exit_code != 0:
			wprint("Failed to install dask")

		# Run the script inside container
		cmd = ["python3", "/tmp/script.py", symbol, *directories]
		exec_res = container.exec_run(
			cmd, stdout=True, stderr=True, environment={"INSIDE_CONTAINER": "1"}
		)
		print(f"\n\x1b[36;1m{image}\x1b[0m\n")
		print(exec_res.output.decode())

	finally:
		container.kill()
		container.remove()

def main():
	parser = argparse.ArgumentParser(
		description="Find which shared library defines a symbol (supports Docker)"
	)
	parser.add_argument("symbol", help="Function/symbol name to search for")
	parser.add_argument("-e", "--adb", action="store_true", help="Search within connected Android device")
	parser.add_argument(
		"docker_images", nargs="*", help="Docker images to run the scan inside (optional)"
	)
	args = parser.parse_args()

	# print(args)
	# find / -type f -name "*.so*" 2> /dev/null | sed -E 's/(.+)\/.+/\1/' | sort -u
	# return 0

	if args.adb:
		proc = subprocess.run(["adb", "shell", "find / -type f -name '*.so' 2> /dev/null"],
							  capture_output=True, text=True, check=False)
		for line in proc.stdout.splitlines():
			print(line)
		return 0

	directories = DEFAULT_DIRS

	if args.docker_images and not INSIDE_CONTAINER:
		# Run scan inside each Docker image from host
		for image in args.docker_images:
			run_in_docker(image, args.symbol, directories)

	else:
		# Run scan locally (or inside container)
		matches = find_symbol_in_dirs(directories, args.symbol)
		if matches:
			oprint(f"'{args.symbol}' is defined in:")
			for m in matches:
				print("  ", m)

			# shortest_libpath = min(directories, key=len)
			# answer = input(f"Do you want to search callers of the symbol '{args.symbol}' through '{shortest_libpath}' ? (Y/n) ")
			# if answer[0].lower() != "y":
			# 	return 0
			
			# local_scan_for_symbol(
			# 	shortest_libpath,
			# 	None,
			# 	args.symbol
			# )
		else:
			oprint(f"'{args.symbol}' not found.")

if __name__ == "__main__":
	main()
