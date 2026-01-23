#!/usr/bin/env python3

import subprocess
import re
import os
import sys
import argparse
from collections import defaultdict, deque
from pathlib import Path

# Optional Dask
try:
	import logging
	for name in list(logging.root.manager.loggerDict.keys()):
		if name.startswith("androguard"):
			logging.getLogger(name).disabled = True
except ImportError:
	pass

try:
	from dask import delayed, compute
	from dask.diagnostics import ProgressBar
	USE_DASK = True
except ImportError:
	USE_DASK = False

# Regexes
FUNC_HEADER_RE = re.compile(r"^[0-9a-f]+ <([^>]+)>:")
CALL_RE = re.compile(r"\s+callq?\s+(?:[0-9a-fx]+ <([^>]+)>)")
OBJDUMP_OPTS = [["-T"], ["-t"], ["-x"]]

EMULATOR_TMP_DIR_ROOT = str(Path.home()) + "/.cache/vera/emulator/"


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

def is_text_file(path):
	"""Simple heuristic to detect text/script files."""
	try:
		with open(path, "rb") as f:
			chunk = f.read(512)
			return b'\0' not in chunk  # null byte indicates binary
	except Exception:
		return False

def collect_text_files(root):
	text_files = []
	for dir in root:
		if not os.path.exists(dir):
			continue
		elif os.path.islink(dir):
			continue
		elif os.path.isdir(dir):
			for dirpath, _, filenames in os.walk(dir):
				for f in filenames:
					path = os.path.join(dirpath, f)
					if os.path.islink(path):
						continue
					if os.path.isfile(path) and is_text_file(path):
						text_files.append(path)
		elif os.path.isfile(dir) and is_text_file(dir):
			text_files.append(dir)
	return text_files


def filter_files_by_function(files, func_name):
	"""Return only files containing func_name as a substring."""
	matching = []
	for path in files:
		try:
			with open(path, "r", errors="ignore") as f:
				if func_name in f.read():
					matching.append(path)
		except Exception:
			continue
	return matching

# -------- Local scan functions --------
def normalize_func_name(name):
	"""
	Strip @ or @@ suffixes from function names.
	"""
	# Remove double @@ first
	name = name.split('@@')[0]
	# Remove single @ if any remains
	name = name.split('@')[0]
	return name

def build_call_graph(shared_lib: str):
	"""
	Build a call graph (callee -> list of callers) and collect all functions
	from a shared library. This includes:
	  - Functions from dynamic symbol table (objdump -T)
	  - Functions from static symbol table (objdump -t)
	  - Functions from disassembly of .text section (objdump -d)
	Returns:
		call_graph: dict mapping callee -> list of callers
		all_functions: set of all normalized function names
	"""
	call_graph = defaultdict(list)
	all_functions = set()

	# Step 1: Collect dynamic and static symbols
	for opts in [["-T"], ["-t"]]:
		try:
			proc = subprocess.run(["objdump"] + opts + [shared_lib],
								  capture_output=True, text=True, check=False)
			for line in proc.stdout.splitlines():
				line = line.strip()
				if not line or line.startswith("SYMBOL TABLE"):
					continue
				parts = line.split()
				if len(parts) < 1:
					continue
				name = parts[-1]
				name = normalize_func_name(name)
				if name:
					# print("'" + name + "'")
					all_functions.add(normalize_func_name(name))
		except Exception:
			continue

	# Step 2: Disassemble .text section to detect call relationships
	try:
		proc = subprocess.run(["objdump", "-d", shared_lib],
							  capture_output=True, text=True, check=False)
		current_func = None
		for line in proc.stdout.splitlines():
			# Function header
			m = FUNC_HEADER_RE.match(line)
			if m:
				func_name = normalize_func_name(m.group(1))
				if func_name.startswith((".init", ".fini")):
					current_func = None
				else:
					current_func = func_name
					all_functions.add(current_func)
				continue
			# Call instructions inside current function
			if current_func:
				m = CALL_RE.search(line)
				if m:
					callee = normalize_func_name(m.group(1))
					if callee:
						call_graph[callee].append(current_func)
	except Exception:
		pass

	# print("inflateGetHeader" in all_functions)
	return call_graph, all_functions

def recursive_callers(call_graph, target_func, max_depth=None):
	visited = set()
	queue = deque([(target_func, 0)])
	all_callers = set()
	while queue:
		func, depth = queue.popleft()
		if max_depth is not None and max_depth != 0 and depth >= max_depth:
			continue
		for caller in call_graph.get(func, []):
			if caller not in visited:
				visited.add(caller)
				all_callers.add(caller)
				queue.append((caller, depth + 1))
	return all_callers

def is_elf(path):
	try:
		with open(path, "rb") as f:
			return f.read(4) == b"\x7fELF"
	except Exception:
		return False

def is_dex(path):
	try:
		with open(path, "rb") as f:
			return f.read(8) == b"dex\x0a035\0"
	except Exception:
		return False

def is_elf_or_dex(path):
	try:
		with open(path, "rb") as f:
			magic = f.read(8)
			return magic.startswith(b"\x7fELF") or magic == b"dex\x0a035\0"
	except Exception:
		return False

def collect_binaries(root):
	import zipfile
	binaries = []
	# print(root)
	for dir in root:
		if not os.path.exists(dir):
			continue
		elif os.path.islink(dir):
			continue
		elif os.path.isdir(dir):
			# print(dir)
			for dirpath, _, filenames in os.walk(dir):
				# if filenames:
				# 	print(dir, filenames)
				for f in filenames:
					path = os.path.join(dirpath, f)
					if os.path.islink(path):
						continue
					# print(path)
					if os.path.isfile(path) and f.endswith(".apk"):
						with zipfile.ZipFile(path, 'r') as zip_ref:
							zip_ref.extractall(path + ".extracted")
						binaries.extend(collect_binaries([path + ".extracted"]))
					
					elif os.access(path, os.R_OK) and is_elf_or_dex(path):
						binaries.append(path)

		elif os.access(dir, os.R_OK) and is_elf_or_dex(path):
			binaries.append(dir)

	return binaries

def scan_binary(path, functions_of_interest, scan_all=False):
	matches = set()
	if path.endswith(".dex"):
		# import logging
		# logging.disable(logging.ERROR)
		# sys.stdout = open('/dev/null', 'w')
		# sys.stderr = open('/dev/null', 'w')

		# from androguard.misc import AnalyzeAPK
		native_methods = []
		try:
			out = subprocess.run(["dexdump", "-d", path],
				capture_output=True, text=True)

			method = None
			is_native = False

			for line in out.stdout.splitlines():
				line = line.strip()
				if line.startswith(".method"):
					method = line
					is_native = "native" in line
				elif is_native and method:
					# Simple JNI name check
					m = re.match(r"\.method.*\s+([a-zA-Z0-9_]+)\(", method)
					for target_so_function in functions_of_interest:
						if m and target_so_function.endswith("_" + m.group(1)):
							native_methods.append(method)
							if not scan_all:
								return (path, sorted(native_methods))
		except Exception:
			pass
		
		# sys.stdout = sys.__stdout__
		# sys.stderr = sys.__stderr__
		
		return (path, sorted(native_methods))

	for opts in OBJDUMP_OPTS:
		try:
			proc = subprocess.run(
				["objdump"] + opts + [path],
				capture_output=True, text=True, check=False
			)
		except Exception:
			continue
		for line in proc.stdout.splitlines():
			for func in functions_of_interest:
				if func in line:
					matches.add(func)
					if not scan_all:
						return (path, sorted(matches))

	return (path, sorted(matches))

def scan_binary_dependencies(path, libname):
	proc = subprocess.run(
		["readelf", "-d", path],
		capture_output=True,
		text=True,
		check=False
	)
	for line in proc.stdout.splitlines():
		parts = re.split(r"[\(\)\[\]]", line)
		if len(parts) != 5 or parts[1] != "NEEDED":
			continue
		# print("'"+parts[3]+"', '"+libname+"'")
		if parts[3] == libname:
			return (path, True)
	return (path, False)

# -------- Docker scanning --------
def find_symbol_in_dirs(dirs, symbol):
	"""Search for 'symbol' in shared libraries under 'dirs', skipping symlinks."""
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
		from dask import bag as db
		bag = db.from_sequence(files, partition_size=20)
		with ProgressBar():
			results = bag.map(lambda f: f if has_symbol(f, symbol) else None).compute()
		return [r for r in results if r is not None]
	else:
		INSIDE_CONTAINER = os.environ.get("INSIDE_CONTAINER") == "1"
		if not INSIDE_CONTAINER:
			iprint("Dask not installed, running sequentially...")
		results = []
		for f in files:
			if has_symbol(f, symbol):
				results.append(f)
		return results

def scan_in_docker(image, script_path, shared_lib, target_func, directory, all_functions=False, text_only=False, depth=None):
	import docker
	import io
	import tarfile

	client = docker.from_env()
	script_name = os.path.basename(script_path)

	# Create tar archive of the script
	tarstream = io.BytesIO()
	with tarfile.open(fileobj=tarstream, mode='w') as tar:
		tar.add(script_path, arcname=script_name)
	tarstream.seek(0)

	# Run container detached
	container = client.containers.run(image, "sleep 300", detach=True, user=0, tty=True)
	try:
		# Copy script into container
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
				eprint("Failed to install dependencies in container:")
				print("    "+output.decode(), file=sys.stderr)
				return
			oprint("Dependencies installed.")
				
		exit_code, output = container.exec_run("pip3 install dask")
		if exit_code != 0:
			wprint("Failed to install dask")

		# Run script inside container with live output
		cmd = ["python3", f"/tmp/{script_name}", shared_lib, target_func]
		if all_functions:
			cmd.append("--all-functions")
		if directory is not None:
			from itertools import chain
			cmd.extend(chain.from_iterable(("--directory", item) for item in directory))
		if depth is not None:
			cmd += ["--depth", str(depth)]
		if text_only:
			cmd.append("--text-only")

		# print(cmd)
		print(f"\n\x1b[36;1m{image}\x1b[0m:\n")
		exec_id = container.exec_run(cmd, stream=True)
		for line in exec_id.output:
			print(line.decode(), end="")

		# Check exit code
		exit_code = container.exec_run(cmd).exit_code
		# if exit_code != 0:
		# 	print(f"\nScript exited with code {exit_code}")

	finally:
		container.remove(force=True)

def local_scan_for_symbol(shared_libpath: str, directories: list, symbol: str, all_functions: bool = False, text_only: bool = False, depth: int = None):
	if text_only:
		if directories is None:
			from pathlib import Path
			directories = ["/bin", "/sbin", "/lib", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", str(Path.home())+"/.local/bin", "/boot", "/etc", "/opt"]

		if not symbol:
			eprint("Error: --text-only requires a function name to search for")
			sys.exit(1)

		iprint(f"Scanning text files in {directories} containing '{symbol}' ...")
		files = collect_text_files(directories)

		# Filter files containing the target function name
		matching_files = filter_files_by_function(files, symbol)
		if matching_files:
			oprint(f"Found {len(matching_files)} files containing '{symbol}':")
			for f in matching_files:
				print("  "+f)
		else:
			oprint("No text/script files containing the function were found.")
		return 0
	
	# Local scan
	if directories is None:
		from pathlib import Path
		directories = ["/bin", "/sbin", "/lib", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/local/bin", "/usr/local/bin", "/usr/local/sbin", str(Path.home())+"/.local/bin", str(Path.home())+"/.local/lib", "/usr/local/lib", "/boot", "/opt"]
	
	dependent_funcs = set()
	if symbol is not None:
		if not os.path.exists(shared_libpath):
			eprint(f"Error: shared library '{shared_libpath}' does not exist")
			sys.exit(1)

		if not os.path.isfile(shared_libpath):
			eprint(f"Error: '{shared_libpath}' is not a file")
			sys.exit(1)

		iprint(f"Parsing shared library: {shared_libpath} ...")
		call_graph, all_lib_funcs = build_call_graph(shared_libpath)

		# Verify the target function exists
		# all_lib_funcs = set(call_graph.keys()) | set(f for callers in call_graph.values() for f in callers)
		# print(all_lib_funcs)
		if symbol not in all_lib_funcs:
			eprint(f"Error: function '{symbol}' not found in {shared_libpath}")
			sys.exit(1)

		dependent_funcs = recursive_callers(call_graph, symbol, max_depth=depth)
		dependent_funcs.add(symbol)

		filtered_dependent_funcs = [item for item in dependent_funcs if symbol != item]
		if not filtered_dependent_funcs:
			iprint(f"No function depends on {symbol}")
		else:
			iprint(f"Found {len(filtered_dependent_funcs)} functions depending on {symbol}")
			# for f in sorted(filtered_dependent_funcs):
			# 	print(f"  {f}")

	binaries = collect_binaries(directories)
	if not binaries:
		eprint("No ELF/DEX binaries found in", directories)
		return

	iprint(f"Scanning {len(binaries)} ELF/DEX binaries in {directories}...")

	if USE_DASK:
		from dask import delayed, compute
		from dask.diagnostics import ProgressBar
		import shutil, contextlib
		from dask.utils import format_time

		class CustomProgressBar(ProgressBar):
			desc = ""
			_columns = -1
			_last_elapsed = 0.0

			def __init__(self, desc: str = "", minimum: int = 60, dt: float = 0.1, out = None):
				super().__init__(minimum, minimum, dt, out)
				if desc:
					self.desc = desc+": "
				self._width = minimum

			def _draw_bar(self, frac: float, elapsed: float):
				bar = "\u2588" * int(self._width * frac)
				percent = int(100 * frac)
				elapsed = format_time(elapsed)
				msg = "\r{0}{2}%\u2595{1}\u258f {3}".format(
					self.desc, bar + (" " * (self._width - len(bar))), percent, elapsed
				)
				with contextlib.suppress(ValueError):
					if self._file is not None:
						self._file.write(msg)
						self._file.flush()

		libname = os.path.basename(shared_libpath)
		tasks = \
				[delayed(scan_binary_dependencies)(b, libname) for b in binaries] \
			if symbol is None else \
				[delayed(scan_binary)(b, dependent_funcs, all_functions) for b in binaries]

		with ProgressBar():
			results = compute(*tasks)
		# print(results)
	else:
		results = []
		for i, b in enumerate(binaries, 1):
			res = scan_binary(b, dependent_funcs, all_functions)
			results.append(res)
			iprint(f"\rScanned {i}/{len(binaries)} binaries...", end="", flush=True)
		print()

	results = {path: funcs for path, funcs in results if funcs}
	if results:
		oprint("Binaries that reference dependent functions:")
		remove_tmp_root = shared_libpath.startswith(EMULATOR_TMP_DIR_ROOT)
		emul_tmp_dir = len(os.sep.join(shared_libpath.split(os.sep)[:7])) if remove_tmp_root else 0
		if all_functions:
			for path, funcs in results.items():
				print(f"  {path[emul_tmp_dir:]}: {', '.join(funcs)}")
		else:
			for path, funcs in results.items():
				print("  "+path[emul_tmp_dir:])
	else:
		oprint("No binaries reference those functions.")

# -------- Main CLI --------
def main():
	parser = argparse.ArgumentParser(
		description="Scan ELF/DEX binaries for functions depending on a target function in a shared library"
	)
	parser.add_argument("shared_lib", help="Shared library path to inspect")
	parser.add_argument("target_func", nargs="?", help="Function to search for")
	parser.add_argument("docker_images", nargs="*", default=[], help="Optional Docker images to run inside")
	parser.add_argument("--directory", "-d", default=None, action="append", help="Directory to scan binaries (default: /usr/bin, /boot)")
	parser.add_argument("--depth", type=int, default=None, help="Max depth for recursive call scan (default: unlimited)")
	parser.add_argument(
		"-a", "--all-functions",
		action="store_true",
		help="List all functions."
	)
	parser.add_argument(
		"-t", "--text-only",
		action="store_true",
		help="Check text files only."
	)
	parser.add_argument(
		"-e", "--emulator",
		action="store_true",
		help="Check all files on emulator through ADB (Android Debug Bridge)."
	)
	parser.add_argument(
		"-c", "--continue",
		type=str.lower,
		choices=["overwrite", "skip-pull", "no"],
		default="no",
		help="Scan existing pulled data if exists."
	)

	args = parser.parse_args()


	# print(args)
	# return 0

	if args.docker_images:
		if args.emulator:
			eprint("Error: --docker-images and --emulator cannot be used together.")
			sys.exit(1)
		# elif args.target_func is None:
		# 	eprint("Error: target function must be specified when using --docker-images.")
		# 	sys.exit(1)
		script_path = os.path.abspath(sys.argv[0])
		for image in args.docker_images:
			scan_in_docker(image, script_path, args.shared_lib, args.target_func, args.directory, args.all_functions, args.text_only, args.depth)

	elif args.emulator:
		import shutil

		EMULATOR_NAME = "net.bt.name"
		EMULATOR_TYPE = "ro.hardware.type"
		EMULATOR_ARCH = "ro.product.cpu.abi"
		EMULATOR_SDK = "ro.build.version.sdk"


		# iprint("Checking emulator properties via ADB...")
		process = subprocess.Popen(["adb", "shell", "getprop", EMULATOR_NAME],
			text=True,
			stdout=subprocess.PIPE,
			stderr=subprocess.DEVNULL
		)
		emulator_name = process.stdout.readline().strip()
		process = subprocess.Popen(["adb", "shell", "getprop", EMULATOR_TYPE],
			text=True,
			stdout=subprocess.PIPE,
			stderr=subprocess.DEVNULL
		)
		emulator_type = process.stdout.readline().strip()
		if emulator_type:
			emulator_name = "-"+emulator_type
		process = subprocess.Popen(["adb", "shell", "getprop", EMULATOR_ARCH],
			text=True,
			stdout=subprocess.PIPE,
			stderr=subprocess.DEVNULL
		)
		emulator_arch = process.stdout.readline().strip()
		process = subprocess.Popen(["adb", "shell", "getprop", EMULATOR_SDK],
			text=True,
			stdout=subprocess.PIPE,
			stderr=subprocess.DEVNULL
		)
		emulator_sdk = process.stdout.readline().strip()

		emulator_name = f"{emulator_name}/{emulator_sdk}/{emulator_arch}"
		oprint(f"Emulator: {emulator_name}")

		EMULATOR_TMP_DIR = EMULATOR_TMP_DIR_ROOT + emulator_name

		def adb_pull():
			process = subprocess.Popen(["adb", "root"],
				text=True,
				stdout=subprocess.PIPE
			)
			output = process.stdout.readline()
			if "unable to connect" in output:
				eprint("No emulator running.")
				sys.exit(1)
			elif "adbd cannot run as root in production builds" in output:
				eprint("Emulator cannot be root.")
				sys.exit(1)
			else:
				oprint("adbd is root")

			iprint("Pulling files into '"+EMULATOR_TMP_DIR+"'")
			unique_processed = set()
			process = subprocess.Popen(["adb", "shell", 'echo "/data/:$PATH"'],
				text=True,
				stdout=subprocess.PIPE
			)

			for part in process.stdout.readline().split(':'):
				match = re.match(r'(\/\w+).+', part)
				result = match.group(1) if match else part
				unique_processed.add(result)

			shutil.rmtree(EMULATOR_TMP_DIR, ignore_errors=True)
			os.makedirs(EMULATOR_TMP_DIR, exist_ok=True)

			for dir in unique_processed:
				print(f"  Pulling {dir}")
				subprocess.run(["adb", "pull", dir, EMULATOR_TMP_DIR], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
				outdir = EMULATOR_TMP_DIR + "/" + dir
				if not os.path.isdir(outdir) or len(os.listdir(outdir)) == 0:
					eprint(f"Failed to pull {dir}, skipping...")
					sys.exit(1)
			# subprocess.run(["adb", "pull", "/", EMULATOR_TMP_DIR], check=True, stdout=True, stderr=subprocess.DEVNULL)
		
		if os.path.isdir(EMULATOR_TMP_DIR):
			if args.__dict__["continue"] == "no":
				eprint(f"Directory '{EMULATOR_TMP_DIR}' already exists. Use --continue to reuse.")
				sys.exit(1)
			elif args.__dict__["continue"] == "skip-pull":
				oprint(f"Reusing existing directory '{EMULATOR_TMP_DIR}'")
			else:
				adb_pull()
		else:
			adb_pull()
		
		# sys.stderr = open('/dev/null', 'w')

		directories = [EMULATOR_TMP_DIR] if args.directory is None else [EMULATOR_TMP_DIR + d for d in args.directory]
		local_scan_for_symbol(
			EMULATOR_TMP_DIR+"/"+args.shared_lib,
			directories,
			args.target_func,
			all_functions=args.all_functions,
			text_only=args.text_only,
			depth=args.depth
		)
		# subprocess.run(["rm", "-rf", EMULATOR_TMP_DIR], check=True)
		# sys.stderr = sys.__stderr__

	else:
		# if args.target_func is None:
		# 	eprint("Error: target function must be specified when scanning local system.")
		# 	sys.exit(1)
		local_scan_for_symbol(
			args.shared_lib,
			args.directory,
			args.target_func,
			all_functions=args.all_functions,
			text_only=args.text_only,
			depth=args.depth
		)

if __name__ == "__main__":
	main()
