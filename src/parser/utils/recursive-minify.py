#!/usr/bin/python3
################################################################################
# @file      recursive-minify.py
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


#!/usr/bin/env python3

from sys import argv, exit
import csv
from tqdm import tqdm
import re

if len(argv) != 4:
	print(f"Usage: {argv[0]} <strip python> <input> <output>")
	exit(1)

strip_python = argv[1] == "1" or argv[1].lower() == "true"
input_file = argv[2]
output_file = argv[3]

def filter_shortest_consecutive_names(pairs):
	"""
	@desc Given a list of (name, version) pairs,
		for consecutive entries with the same version,
		keep only the shortest name among them.
	"""
	if not pairs:
		return []

	result = []
	i = 0
	n = len(pairs)
	while i < n:
		current_version = pairs[i][1]
		group = [pairs[i]]
		j = i + 1
		# Collect all consecutive with the same version
		while j < n and pairs[j][1] == current_version:
			group.append(pairs[j])
			j += 1
		# Keep only the one with the shortest name
		shortest = min(group, key=lambda x: len(x[0]))
		result.append(shortest)
		i = j
	return result

# Group rows by base name (before first '-')
def extract_base(name):
    m = re.match(r"^(python3?|(ros|linux|golang|r|ruby)-[a-z]+)-|(nvidia|microsoft)(\s+|-)", name)
    if m:
        # If there's a group 2 (e.g., "-foo"), use prefix + next part, else just prefix
        return m.group(0)
    return name.split('-')[0]

groups = {}
with open(input_file, newline='') as f:
	reader = csv.reader(f)
	for row in reader:
		name = row[0]
		version_like = re.search(r"-?[0-9]+(\.[0-9]+)+-?", name)
		if version_like:
			vl = version_like.group()
			name = name[:-len(vl)] if name.endswith(vl) \
				else name.replace(version_like.group(), "-")

		base = extract_base(name)
		groups.setdefault(base, []).append((name, row))

# For each group, keep only the shortest name (the base itself if present)
filtered = []
for base, variants in groups.items():
	# Find the shortest name (prefer exact base match)
	shortest = min(variants, key=lambda x: len(x[0]))
	filtered.append(shortest[1])

filtered = filter_shortest_consecutive_names(filtered)

with open(output_file, "w", newline='') as f:
	writer = csv.writer(f, delimiter="=")
	for row in filtered:
		if strip_python and re.match(r"^python3?-", row[0]):
			continue
		# row[0] = re.sub(r"-(docs?|dev|utils?|common|bin)$", "", row[0])
		writer.writerow(row)