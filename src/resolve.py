
import json, os
from pathlib import Path
from .utils import *
from rich.progress import Progress, BarColumn, TimeRemainingColumn, TextColumn
import csv
import sqlite3
from cvss import CVSS2, CVSS3, CVSS4


def get_grype_database() -> dict[tuple[str, float]]:
	db_path = str(Path.home()) + "/.cache/grype/db/6/vulnerability.db"

	if not os.path.isfile(db_path):
		wprint("Grype database not found")
		return {}

	conn = sqlite3.connect(db_path)
	cursor = conn.cursor()

	# -------------------------
	# Load EPSS data
	# -------------------------
	cursor.execute("SELECT cve, epss, percentile FROM epss_handles")
	epss_data = {
		cve: {"epss": epss, "percentile": percentile}
		for cve, epss, percentile in cursor.fetchall()
	}

	# -------------------------
	# Load KEV data
	# -------------------------
	cursor.execute("SELECT cve FROM known_exploited_vulnerability_handles")
	kev_set = {row[0] for row in cursor.fetchall()}

	# -------------------------
	# Load CVSS data
	# -------------------------
	cursor.execute("""
		SELECT COUNT(id)
		FROM blobs
		WHERE value LIKE '%"CVSS"%'
	""")
	total = cursor.fetchone()[0]
 
	cursor.execute("""
		SELECT value
		FROM blobs
		WHERE value LIKE '%"CVSS"%'
	""")

	cve_data = {}

	CVSS_FUNC = {
		"4": CVSS4,
		"3": CVSS3,
		"2": CVSS2
	}
 
	def to_float(f) -> float:
		return float(f) if f is not None else None


	with Progress(
		TextColumn("[bold]Loading CVEs"),
		BarColumn(),
		"[progress.percentage]{task.percentage:>3.1f}%",
		TimeRemainingColumn(),
	) as progress:

		task = progress.add_task("Parsing CVSS data", total=total)

		for (value,) in cursor.fetchall():
			data = json.loads(value)
			cve_id = data.get("id")
			if not cve_id:
				progress.advance(task)
				continue

			for sev in data.get("severities", []):
				if sev.get("scheme") != "CVSS":
					continue

				vector = sev["value"]["vector"]
				version = sev["value"]["version"]

				# Parse CVSS score
				try:
					cvss_score = CVSS_FUNC[version[0]](vector).base_score
				except Exception:
					cvss_score = None

				cve_data[cve_id] = {
					"vector": vector,
					"cvss": to_float(cvss_score),
					"epss": to_float(epss_data.get(cve_id, {}).get("epss")),
					"percentile": to_float(epss_data.get(cve_id, {}).get("percentile")),
					"kev": cve_id in kev_set
				}
			progress.advance(task)

	conn.close()

	print()

	return cve_data

def resolve_unknown_scores(path: str, allow_local: str):
	cache_cve = get_grype_database()
	def add_cve(cve_id: str, update: dict):
		if cve_id not in cache_cve:
			cache_cve[cve_id] = update
		else:
			cache_cve[cve_id] |= update

	def _get(cve_id: str) -> dict:
		d = cache_cve.get(cve_id, {})
		if not isinstance(d, dict):
			return {}
		return d

	def resolve_unknown_score_file(file_path: str):
		data = []
		with open(file_path, "r", encoding="utf-8") as f:
			data = json.load(f)
		
		if not isinstance(data, list) and any((not isinstance(data[i], str)) for i in data):
			eprint(f"Unexpected format for file '{file_path}'. Skipped.")
			return

		modified = 0
		not_found = 0
		total = sum(1 for d in data
			if isinstance(d, dict) and (
				(d.get("state") is None or d["state"].lower() != "fixed") and (
				# d.get("score") is not None or
				d.get("name") is None or
					# d.get("vendor") is None or
					# d.get("ecosystem") is None or
				d.get("cvss") is None or (isinstance(d["cvss"], str) and d["cvss"].lower() in ["unknown", "low", "moderate", "high", "critical"]) or float(d["cvss"]) <= 0 or float(d["cvss"]) >= 10 or
				d.get("scoring_vector") is None or
				d.get("epss") is None or d.get("epss") == -1 or
				d.get("percentile") is None or d.get("percentile") == -1 or
				d.get("kev") is None
				# or d.get("cwe") is None
			))
		)
		
		if total == 0:
			iprint(f"{file_path} good")
			return
		iprint(f"Testing {file_path}")

		# with Progress() as progress:
		# 	task = progress.add_task('/'.join(file_path.split('/')), total=total)
		for obj in data:
			cvss = obj.get("cvss", -1)
			try:
				cvss = float(cvss)
			except:
				pass
			scoring_vector = obj.get("scoring_vector")
			epss = obj.get("epss", -1)
			try:
				epss = float(epss)
			except:
				pass
			percentile = obj.get("percentile", -1)
			try:
				percentile = float(percentile)
			except:
				pass
			score = obj.get("score")
			cve_id = obj.get("cveId")
			state = obj.get("state", "")
			ecosystem_id = obj.get("id") # android specific
			kev = obj.get("kev")

			product = obj.get("name")
			# cwe = obj.get("cwe")

			tmp_modified = False
			tmp_not_found = False

			if cve_id is None or state == "fixed":
				continue

			# rename
			if score is not None and cvss == -1:
				add_cve(cve_id, {
					"cvss": float(score)
				})
				obj["cvss"] = float(score)
				del obj["score"]
				tmp_modified = True

			entry = None
			if cvss is None or not isinstance(cvss, float) or cvss <= 0 or cvss > 10 \
				or scoring_vector is None \
				or product is None \
				or kev is None: # \
				# or cwe is None:
				# print(obj)
				# name = obj.get("name", "")
				# version = obj.get("version", "")
				# ecosystem = obj.get("ecosystem", "")
				# iprint(f"Looking for {cve_id}: {name}={version} {ecosystem}")
				if cache_cve.get(cve_id) is None:
					add_cve(cve_id, get_cve_data(cve_id, ecosystem_id, allow_local))
				entry = _get(cve_id)
				if cache_cve[cve_id] is not None:
					if cvss is None or not isinstance(cvss, float) or cvss < 0 or cvss > 10:
						obj["cvss"] = entry.get("cvss")
						tmp_modified = True
					if not scoring_vector:
						obj["scoring_vector"] = entry.get("vector")
						tmp_modified = True
					if not product:
						obj["name"] = entry.get("name")
						tmp_modified = True
					# if not cwe is None:
					# 	obj["cwe"] = entry.get("")
					# 	tmp_modified = True
					# obj["cvss"], obj["scoring_vector"], obj["name"], obj["cwe"] = cache_cve[cve_id]
				else:
					tmp_not_found = True
			
			if cache_cve.get(cve_id) is None:
				add_cve(cve_id, get_cve_data(cve_id, ecosystem_id, allow_local))

			if cache_cve.get(cve_id) is not None:
				if entry is None:
					entry = _get(cve_id)
				if kev is None:
					obj["kev"] = entry.get("kev", False)
					tmp_modified = True

				if	not isinstance(epss, float) or epss is None \
						or epss < 0.0 or epss > 1.0 or \
					percentile is None \
						or percentile < 0.0 or percentile > 1.0:
					obj["epss"] = entry.get("epss", -1)
					obj["percentile"] = entry.get("percentile", -1)
					tmp_modified = True
			
			if tmp_modified:
				modified += 1
			if tmp_not_found:
				not_found += 1

			print(f"\r{modified}/{total} modified | {not_found}/{total} incomplete", end='')
			# progress.update(task, advance=1/total)
		print()
		if modified != 0:
			with open(file_path, "w", encoding="utf-8") as f:
				json.dump(data, f)
			oprint(f"  saved")
		else:
			iprint(f"  no score found, nothing to update")

	if os.path.isdir(path):
		json_dir = Path(path)
		json_files = json_dir.rglob("*.json")
		for file_path in json_files:
			try:
				resolve_unknown_score_file(file_path)
			except KeyboardInterrupt:
				print()
				iprint("Abort.")
				return

			except json.JSONDecodeError as e:
				eprint(f"Skipping {file_path}, invalid JSON: {e}")

	else:
		try:
			resolve_unknown_score_file(path)
		except json.JSONDecodeError as e:
			eprint(f"Invalid JSON: {e}")
