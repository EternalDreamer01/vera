#!/usr/bin/env python3
import os
import sys
import docker
import re

def usage():
	prog = os.path.basename(sys.argv[0])
	print(f"Usage: {prog} IMAGE PKG CVE-ID...", file=sys.stderr)
	print("To look for any package, type '', '-' or '*' instead of PKG", file=sys.stderr)

AVAILABLE = [
	[
		"apt -h && apt-get -h",	# Test
		("apt-get changelog {}", "apt-get changelog * 2> /dev/null")
	],
	[
		"dnf",
		("dnf changelog {}", "dnf changelog")
	],
	[
		"yum",
		("yum changelog {}", "yum changelog")
	]
]
def determine_cmd(container: object, pkg: str) -> str | None:
	for i in range(len(AVAILABLE)):
		exit_code, _ = container.exec_run(AVAILABLE[i][0])
		if exit_code == 0:
			if pkg in ['', '-', '*']:
				return AVAILABLE[i][1][1]
			return AVAILABLE[i][1][0].format(pkg)
	return None

def main():
	if len(sys.argv) < 4:
		usage()
		sys.exit(1)

	image = sys.argv[1]
	pkg = sys.argv[2]
	cve_ids = sys.argv[3:]

	client = docker.from_env()


	try:
		# print(f"[*] Searching inside container {container.short_id}...")
		container = client.containers.run(
			image,
			"sleep 600",
			detach=True,
			user=0,
			tty=True
		)
		cmd_changelog = determine_cmd(container, pkg)
		if cmd_changelog is None:
			raise ValueError("Could not determine package manager")

		exit_code, output = container.exec_run(
			cmd_changelog,
			environment=[
				"PAGER=cat"
			]
		)
		# print("done")
  
		adjust = len(max(cve_ids, key=len))
  
		# output.decode("utf-8").splitlines()

		for line in output.decode("utf-8").splitlines():
			for cve_id in cve_ids[:]:
				if re.compile(rf'\b{cve_id}\b').search(line):
					print(f"\x1b[32;1m{cve_id.ljust(adjust, ' ')} fixed \u2714\x1b[0m")
					cve_ids.remove(cve_id)

		for cve_id in cve_ids:
			print(f"\x1b[31;1m{cve_id.ljust(adjust, ' ')} not fixed \u2a2f\x1b[0m")

	except ValueError as e:
		print(e)
	except docker.errors.ContainerError:
		print("\x1b[31mDoes not appear in changelog !\x1b[0m")

if __name__ == "__main__":
	main()
