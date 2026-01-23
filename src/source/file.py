#!/usr/bin/python3
################################################################################
# @file      challenge copy.py
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


from dask import compute
import gc
import json
from ..constants import *
from ..utils import *
from ..challenge import make_tasks

def process_csv(file: str, file_desc: str, outfile: str, strict: bool, depth: int):
	"""Process a list of SRC files to check package vulnerabilities."""
	if not file:
		eprint("No file provided.")
		return

	# client = Client()
	try:
		# shorten_file = file
		# if shorten_file.startswith("os/") or shorten_file.startswith("fw/"):
		# 	shorten_file = shorten_file[3:]
		# if shorten_file.endswith("raw/raw.min.csv") or shorten_file.endswith("fup/fup.min.csv"):
		# 	shorten_file = shorten_file[:-12]
		with open(file, "r", encoding="utf-8") as csvfile:
			lines = [line.strip() for line in csvfile if "=" in line]

		if not lines:
			raise ValueError(f"No line or no valid line within '{file}'")

		tasks = make_tasks(lines, strict, depth)
		results = []
		with CustomProgressBar(f"{'Strict' if strict else 'Flexible'} {file_desc}"):
			results = compute(*tasks)

		with open(outfile, "w", encoding="utf-8") as out:
			out.write(json.dumps(results, default=serialize))

		del tasks
		del results
		del lines
		gc.collect()
    
	except FileNotFoundError as e:
		eprint(f"File not found: {e}")
	except KeyboardInterrupt:
		# eprint("\nProcess interrupted by user.")
		# answer = input(f"Do you want to save what has been computed ? (Y/n) ")
		# if answer[0].lower() == "n":
		print("Aborted.")
	except ValueError as e:
		eprint(f"Error: {e}")
