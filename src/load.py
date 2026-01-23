################################################################################
# @file      load.py
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


import os
import re
import traceback
import json
from .version import *
from dask import delayed, compute
from .constants import *
from .utils import *


def are_any_words_in_list_case_insensitive(words_to_check: list[str], string_list: list[str]) -> bool:
	for word in words_to_check:
		pattern = r'\b' + re.escape(word) + r'\b'
		for string in string_list:
			if re.search(pattern, string, flags=re.IGNORECASE):
				return True
	return False

def filter_invalid_products(affected: list, keep_spaces: bool = False, debug: bool = False) -> list:
	if not affected or affected is None:
		return []
	total_affected = len(affected)
	if total_affected != 0:
		j = 0
		while j < total_affected:
			platforms = affected[j].get("platforms", [])
			if platforms:
				if not are_any_words_in_list_case_insensitive(["linux", "all"], platforms):
					affected.pop(j)
					total_affected -= 1
					continue
			product = affected[j].get("product", "n/a")
			product = re.sub(
# Apply separators
				r"\s*(,|;|:)\s*|\s+and\s+",
				",",
				product
			)
			product = re.sub(
# Trim and replace white space formats
				r"\s*(\\(r|n|t))\s*",
				" ",
				product
			)
			product = re.sub(
# Remove symbols and vendor prefix for affected_product
				SLIGHT_FORMAT + r"|(.+)/"+ (r"|\s" if not keep_spaces else r""),
				"",
				product
			).strip().lower().split(",")


			vendor = affected[j].get("vendor", "").lower().strip()
			# if debug:
			# 	print("\n", vendor, product, (product in KNOWN_PRODUCT_VENDOR and 
			# 		vendor not in KNOWN_PRODUCT_VENDOR[product]
			# 	), product in KNOWN_PRODUCT_VENDOR, vendor not in KNOWN_PRODUCT_VENDOR.get(product, []))

			total_product = len(product)
			k = 0
			if total_product != 0:
				# print(product, vendor, total_product)
				while k < total_product:
					if product[k] in ["n/a", "unspecified", "unknown"] or \
						(product[k] in KNOWN_PRODUCT_VENDOR and 
							vendor not in KNOWN_PRODUCT_VENDOR[product[k]]
						):
						# print(product[k])
						product.pop(k)
						total_product -= 1
					else:
						k += 1
			if total_product == 0:
				affected.pop(j)
				total_affected -= 1
			else:
				affected[j]["product"] = product
				affected[j]["vendor"] = vendor
				# affected[j]["product"] = affected[j]["product"].replace(" ", "-")
				affected[j]["versions"] = make_struct_version_list(affected[j].get("versions", []), vendor, "/".join(product))
				if not affected[j]["versions"] or not affected[j]["versions"][0]:
					affected.pop(j)
					total_affected -= 1
				else:
					j += 1
	return affected

def load_cves(desc: str, start_year: int, keep_spaces: bool = False, write_out: bool = False) -> list[dict]:
	def perform_scandir(dirpath: str, filenames: str) -> list:
		result = {}
		
		# CVE id file
		for filename in filenames:
			if not filename.endswith(".json"):# or filename != "CVE-2018-6508.json":
				continue
			valid = False
			with open(f"{dirpath}/{filename}", 'r') as file:
				data = json.load(file, object_hook=deserialize)
			affected = []
			# if write_out:
				# if data.get("valid") is None:
			cna_affected = filter_invalid_products(get_nested(data, "containers.cna.affected", []).copy(), keep_spaces or write_out)#, data["cveMetadata"]["cveId"] == "CVE-2018-6508")
			data["affected"] = []
			data["cvss"] = {
				"maxScore": -1,
				"metrics": []
			}
			if cna_affected:
				ctnr = data["containers"]["cna"].copy()
				ctnr["descriptions"][0]["value"] = \
					ctnr["descriptions"][0]["value"].lower()
				data["affected"] = cna_affected
				data["cvss"]["metrics"] = ctnr.get("metrics", [])
				valid = True
			total_adp = len(get_nested(data, "containers.adp", []))
			if total_adp != 0:
				ctnr = data["containers"]["adp"].copy()
				i = 0
				while i < total_adp:
					adp_affected = filter_invalid_products(ctnr[i].get("affected", []), keep_spaces or write_out)#, data["cveMetadata"]["cveId"] == "CVE-2018-6508")
					if not adp_affected:
						ctnr.pop(i)
						total_adp -= 1
						pass
					else:
						data["affected"].extend(adp_affected)
						data["cvss"]["metrics"].extend(ctnr[i].get("metrics", []))
						valid = True
						i += 1
					# data["valid"] = valid
					# with open(f"{dirpath}/{filename}", 'w') as file:
					# 	file.write(json.dumps(data, default=serialize))
			
			if valid and data.get("affected"):
				affected = {}
				# print(data["containers"]["cna"])
				affected = dict.fromkeys(flatten([
					a["product"]
					for a in data["affected"]
				]), [])

				def get_first_matching_product(affected_product: list[dict], wanted_product: str, default=[]) -> dict:
					if not affected_product:
						return default
					def __get_wanted_product_data(ap: dict) -> dict:
						for item in ap.get("product", []):
							# if data["cveMetadata"]["cveId"] == "CVE-2024-52007":
							# 	print(item, wanted_product)
							if item == wanted_product:
								return ap.copy()
						return {}

					if isinstance(affected_product, list):
						for ap in affected_product:
							# print(ap)
							res = __get_wanted_product_data(ap)
							if res:
								return res
					elif isinstance(affected_product, dict):
						res = __get_wanted_product_data(affected_product)
						if res:
							return res
							
					return default
				# affected = list(set(affected))
				for p in affected:
					result[p] = dict(data)
					result[p]["affected"] = {}

					# if data["cveMetadata"]["cveId"] == "CVE-2024-52007":
					# 	print(p, data["affected"])
					if isinstance(data["affected"], dict):
						result[p]["affected"] = dict(data["affected"])
					else:
						len_affected = len(data["affected"])
						if len_affected == 1:
							result[p]["affected"] = dict(data["affected"][0])
						elif len_affected > 1:
							match = get_first_matching_product(data["affected"].copy(), p, dict(data["affected"][0]))
							# if data["cveMetadata"]["cveId"] == "CVE-2024-52007":
							# 	print(match)
							result[p]["affected"] = match
					result[p]["cveId"] = result[p]["cveMetadata"]["cveId"]
					result[p]["cvssMaxScore"] = max_score(result[p]["cvss"]["metrics"])
					result[p].pop("dataType", None)
					result[p].pop("dataVersion", None)
					result[p].pop("cveMetadata", None)
					result[p].pop("containers", None)
					result[p].pop("cvss", None)
					# if data["cveMetadata"]["cveId"] == "CVE-2024-52007":
					# 	print(data["affected"])
					
					# if data["cveMetadata"]["cveId"] == "CVE-2024-52007":
					# 	print(result[p]["affected"])
				# print(result)
			# sleep(2)
		return result
	result = {}
	if write_out:
		with os.scandir(f"{CVELIST_DIRECTORY}/cves/") as year_entries:
			tasks = [
				delayed(perform_scandir)(dirpath, filenames)
				for entry in year_entries
				if entry.is_dir() and int(entry.name) >= start_year
				for dirpath, _, filenames in os.walk(f"{CVELIST_DIRECTORY}/cves/{entry.name}/")
				if dirpath.endswith("xxx")
			]
		tasks_result = []
		with CustomProgressBar(desc):
			tasks_result = compute(*tasks)
		# if write_out:
		# 	return None

		for tsk in tasks_result:
			for product in tsk:
				# if product == "org.hl7.fhir.core":
				# 	print(tsk[product])
				if product in result:
					result[product].append(tsk[product])
				else:
					result[product] = [tsk[product]]

		# print("\ncuda-toolkit:", result.get("cuda-toolkit"))
		# print("\ncuda toolkit:", result.get("cuda toolkit"))
		# print()
		# sys.exit(1)
		# print(result.get("kjd/idna"))
		with open("./cves.json", 'w') as file:
			file.write(json.dumps(result, default=serialize))

	else:
		with open("./cves.json", "r") as file:
			result = json.load(file, object_hook=deserialize)

	return result
