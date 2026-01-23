#!/usr/bin/env python3
"""
adb_frida_trace_auto.py

Usage:
	python3 adb_frida_trace_auto.py <process-or-pid> <filter> [--interval N]

Behavior:
- Keeps using 'frida-trace' CLI.
- Polls `adb shell pidof <target>` every `interval` seconds (default 2s).
- For each new PID seen, launches: frida-trace -U -p <pid> -i "<filter>"
- Appends stdout to adb-log/<subdir>/<process>/<filter>.log and leaves frida-trace stderr in the terminal.
- Tracks launched frida-trace processes and attempts to clean them up on exit.
"""
import argparse
import os
import shlex
import signal
import shutil
import subprocess
import sys
import time
from datetime import datetime

from src.utils import eprint, wprint, iprint, oprint


LOG_DIR = "adb-log"

def run_cmd(cmd: list | str, check: bool = True):
	if isinstance(cmd, str):
		cmd = shlex.split(cmd)
	result = subprocess.run(["adb", "shell"] + cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	if check and result.returncode != 0:
		raise RuntimeError(f"Command {' '.join(cmd)} failed: {result.stderr.decode(errors='replace')}")
	return result.stdout.decode('utf-8', errors='replace')

def get_adb_prop(prop: str) -> str:
	try:
		return run_cmd(["getprop", prop]).strip()
	except RuntimeError:
		return ""

def ensure_tools():
	if shutil.which("adb") is None:
		eprint("adb not found in PATH"); sys.exit(2)
	if shutil.which("frida-trace") is None:
		eprint("frida-trace not found in PATH"); sys.exit(2)

def read_remote_cmdline(pid: str) -> str:
	try:
		raw = run_cmd(["cat", f"/proc/{pid}/cmdline"])
		return raw.replace("\x00", " ").strip()
	except RuntimeError:
		return ""

def sanitize_path_component(s: str) -> str:
	# Replace ':' with os.sep to mirror original bash behavior `${process//:/\/}`
	return s.replace("_", os.sep).replace(":", os.sep)

def start_logcat(subdir: str) -> None | subprocess.Popen:
	log_dir = os.path.join(LOG_DIR, subdir)
	os.makedirs(log_dir, exist_ok=True)
	log_file_path = os.path.join(log_dir, f"{str(datetime.now())[:19]}-full.log")

	try:
		log_fh = open(log_file_path, "a")
	except OSError as e:
		eprint(f"Error opening log file {log_file_path}: {e}")
		return None

	try:
		proc = subprocess.Popen(["adb", "logcat"], stdout=log_fh, stderr=None)
	except OSError as e:
		eprint(f"Failed to start frida-trace for PID {pid}: {e}")
		log_fh.close()
		return None
	log_fh.close()
	return proc

def start_frida_for_pid(pid, process_name_for_path, filter_str, subdir):
	"""Start frida-trace for a single PID, append stdout to file, stderr to terminal."""
	safe_path = sanitize_path_component(process_name_for_path)
	log_dir = os.path.join(LOG_DIR, subdir, safe_path)
	os.makedirs(log_dir, exist_ok=True)

	# sanitize filter for filename
	filter_filename = filter_str.replace(os.sep, "_")
	log_file_path = os.path.join(log_dir, f"{str(datetime.now())[:19]}-{filter_filename}-{pid}.log")
	err_file_path = os.path.join(log_dir, f"exception_trace-{pid}.err")

	frida_trace_cmd = ["frida-trace", "-U", "-p", pid, "-i", filter_str]
	frida_cmd = ["frida", "-U", "-p", pid, "-l", "src/analyser/utils/segfault_trace.js"]

	try:
		log_fh = open(log_file_path, "a")
	except OSError as e:
		eprint(f"Error opening log file {log_file_path}: {e}")
		return (None, None)
	try:
		err_fh = open(err_file_path, "a")
	except OSError as e:
		eprint(f"Error opening err file {err_file_path}: {e}")
		return (None, None)

	try:
		proc1 = subprocess.Popen(frida_trace_cmd, stdout=log_fh, stderr=None)
	except OSError as e:
		eprint(f"Failed to start frida-trace for PID {pid}: {e}")
		log_fh.close()
		return (None, None)
	log_fh.close()
	oprint(f"Launched frida-trace for PID {pid}. Logs: {log_file_path}")

	proc2 = None
	# try:
	# 	proc2 = subprocess.Popen(frida_cmd, stdout=err_fh, stderr=None)
	# except OSError as e:
	# 	eprint(f"Failed to start frida for PID {pid}: {e}")
	# 	err_fh.close()
	# 	return (None, None)
	# # close our reference to the file (child keeps it open)
	# err_fh.close()
	# oprint(f"Launched frida for PID {pid}. Logs: {err_file_path}")

	return (proc1, proc2)

def pidof(target: str, all_subprocess: bool = True) -> dict:
	"""Return a list of PIDs (strings) returned by `adb shell pidof <target>`"""
	try:
		result = run_cmd("ps", check=False).strip()
		pids = {}

		# Parse each line
		for line in result.splitlines():
			if line.startswith("USER") or not line.strip():
				continue  # skip header line

			parts = line.split()
			# print(parts)
			if len(parts) < 9:
				continue  # not a valid ps line

			user, pid, ppid, vsize, rss, wchan, pc, state, name = parts[:9]
			if all_subprocess:
				if name.endswith("_zygote") or ":sandbox" in name:
					continue
				if name.startswith(target):
					pids[pid] = name
			else:
				if name == target:
					pids[pid] = name

		return pids
	except Exception:
		return {}

def frida_server_reachable() -> bool:
	p = subprocess.run('echo "quit" | frida -U -n system_server -e "console.log(\'hello from frida\');"', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
	return p.returncode == 0


def main():
	parser = argparse.ArgumentParser(description="Wrapper around frida-trace that polls for new PIDs and launches frida-trace (keeps using Frida CLI).")
	parser.add_argument("process_or_pid", nargs="?", help="Process name or PID")
	parser.add_argument("filter", nargs="?", help="Frida trace filter (e.g. 'Java.*open')")
	# parser.add_argument("--all-subprocesses", action="store_true", help="")
	parser.add_argument("--interval", type=float, default=0.1, help="Polling interval in seconds (default 0.1)")
	parser.add_argument("--non-root", action="store_true", help="Only adb logcat")
	args = parser.parse_args()

	ensure_tools()

	# device / directory info (mirror original script)
	name = get_adb_prop("ro.kernel.qemu.avd_name")
	vendor = get_adb_prop("ro.product.vendor.name")
	sdk = get_adb_prop("ro.vendor.build.version.sdk")

	type_field = vendor.replace("sdk_g", "").replace("_dd", "").replace("_", "-")
	subdir = f"{name}-{type_field}-{sdk}".strip("-")

	inp = (args.process_or_pid or "").strip()
	filter_str = args.filter
	interval = max(0.1, args.interval)

	# print(args)
	if not args.non_root:
		if not inp:
			eprint("process or PID required"); sys.exit(1)
		if not filter_str and not args.non_root:
			eprint("filter required"); sys.exit(1)
		if not frida_server_reachable():
			eprint("frida-server unreacheable. Use --non-root or run frida-server on Android device: ./analyse.sh adb-trace-server")
			sys.exit(1)


	# Determine match target for pidof
	is_digit = inp.isdigit()
	if is_digit:
		# get cmdline to derive a human-readable process name for logging dir, and to decide pidof target
		cmdline = read_remote_cmdline(inp)
		if cmdline:
			# take first token of cmdline (reasonable for Android package / binary)
			match_name = cmdline.split()[0]
			process_name_for_path = cmdline
		else:
			# fallback: use pid as name
			match_name = inp
			process_name_for_path = inp
	else:
		match_name = inp
		process_name_for_path = inp
		# run_cmd(["pm", "clear", inp])

	print(f"Target name: '{match_name}'")
	# print(f"Process path component for logs: '{process_name_for_path}'")
	print(f"Polling interval: {interval}s")
	print("Press Ctrl+C to stop and terminate launched instances.\n")

	seen_pids = set()
	frida_procs = {}  # pid -> Popen object
	logcat_proc = start_logcat(subdir)

	def terminate(p: list):
		try:
			p[0].terminate()
		except Exception:
			pass
		try:
			p[1].terminate()
		except Exception:
			pass
	def kill(p: list):
		try:
			p[0].kill()
		except Exception:
			pass
		try:
			p[1].kill()
		except Exception:
			pass
	# Signal handler to terminate child frida-trace procs on exit
	def shutdown(signum, frame):
		print()
		iprint("Stopping... terminating frida processes...")
		terminate(logcat_proc)
		for p in list(frida_procs.values()):
			terminate(p)
		# give them a moment, then kill if still alive
		time.sleep(0.5)
		kill(logcat_proc)
		for p in list(frida_procs.values()):
			kill(p)
		sys.exit(0)

	signal.signal(signal.SIGINT, shutdown)
	signal.signal(signal.SIGTERM, shutdown)

	# Main poll loop
	try:
		def remove_if_exited(pid: str, other: object = None):
			if other is None and pid in frida_procs:
				p = frida_procs[pid]
				terminate(p)
				frida_procs.pop(pid, None)
				seen_pids.discard(pid)
				iprint("Discarded PID "+pid)

		if args.non_root:
			while True:
				time.sleep(2)
		else:


			# If user provided a digit (specific PID), attempt to start tracing it immediately
			if is_digit:
				if inp not in seen_pids:
					proc = start_frida_for_pid(inp, process_name_for_path, filter_str, subdir)
					if proc:
						seen_pids.add(inp)
						frida_procs[inp] = proc

			while True:
				pids = pidof(match_name)
				# pidof may return multiple PIDs; attach to each new one
				for p, pname in pids.items():
					if p and p not in seen_pids:
						# Extra check: if user originally gave a PID and we found same pid, ensure we're not double-starting
						proc1, proc2 = start_frida_for_pid(p, pname, filter_str, subdir)
						if proc1: #and proc2:
							seen_pids.add(p)
							frida_procs[p] = (proc1, proc2)
				# reap finished frida-trace processes and remove from tracking
				for p, popen in list(frida_procs.items()):
					if popen[0].poll() is not None:
						iprint(f"[frida-trace] tracing for PID {p} exited with code {popen[0].returncode}")
						frida_procs[p] = (None, popen[1])
						remove_if_exited(p, None)
						if popen[0].returncode != 0:
							if not frida_server_reachable():
								raise RuntimeError("lost connection to frida-server")
					# if popen[1].poll() is not None:
					# 	iprint(f"[frida] exception handler for PID {p} exited with code {popen[1].returncode}")
					# 	remove_if_exited(p, None)
						# keep seen_pids to avoid relaunching on PID reuse (you may decide to remove it)

			time.sleep(interval)
	except Exception as e:
		eprint(e)
		shutdown(None, None)
		sys.exit(1)

	except KeyboardInterrupt:
		shutdown(None, None)

if __name__ == "__main__":
	main()
