#!/usr/bin/python3
################################################################################
# @file      version.py
# @brief     
# @date      Mo Jul 2025
# @author    
# 
# PROJECT:   CVE checker
# 
# MODIFIED:  Tue Jul 08 2025
# BY:        
# 
# Copyright (c) 2025 
# 
################################################################################


import re
import os
from packaging.version import Version, InvalidVersion
import importlib.util
from fnmatch import fnmatch
# from .llm import is_lexical_version_vulnerable
from .constants import *
from .utils import VersionException, firstval


def matching_parts(v1: str|object, v2: str|object) -> str | None:
	"""Returns matching major, minor and patch. Replace non-matching parts by 0"""
	try:
		if not isinstance(v1, str) or not isinstance(v2, str):
			return None
		v1_parts = Version(v1).base_version.split('.')
		v2_parts = Version(v2).base_version.split('.')
		max_len = max(len(v1_parts), len(v2_parts))
		v1_parts += ['0'] * (max_len - len(v1_parts))
		v2_parts += ['0'] * (max_len - len(v2_parts))
		result = []
		mismatch_found = False
		for i, (p1, p2) in enumerate(zip(v1_parts, v2_parts)):
			if mismatch_found:
				result.append('0')
			elif p1 == p2:
				result.append(p1)
			else:
				if i == 0:
					# Major mismatch: discard v1, use v2's major + all zeroes
					result = [v2_parts[0]] + ['0'] * (max_len - 1)
					break
				else:
					result.append('0')
					mismatch_found = True
		return '.'.join(result)
	except InvalidVersion:
		pass

def make_struct_version_list(affected_versions: list[dict], vendor: str, product: str) -> list[dict]:
	if not affected_versions:
		return []
	result = []

	last_less_than = None
	for a in affected_versions:
		status = a.get("status", "affected").lower()
		if status != "affected" and status != "unaffected":
			continue
		version_equality = "equal"
		has_lt = "lessThan" in a or "lessThanOrEqual" in a
		if has_lt:
			version_equality = "greaterThanOrEqual"
		elif status == "unaffected":
			version_equality = "lessThan"
		# print(a)
		version_glob, ver_formatted, struct_version = version_format(a.get("version"), vendor, product, version_equality)
		less_than, lt_formatted, struct_lt = version_format(a.get("lessThan"), vendor, product, "lessThan")
		less_than_or_equal, lte_formatted, struct_lte = version_format(a.get("lessThanOrEqual"), vendor, product, "lessThanOrEqual")

		# print(version_glob, less_than, less_than_or_equal)
		if version_glob is None and less_than is None and less_than_or_equal is None:
			continue

		# Parse 'version' field only
		fulfill_version_only = False
		# 'version' field keys number
		len_ver = len(struct_version) if isinstance(struct_version, list) else 0
		if len_ver == 0:
			struct_version = [{}]
		if len_ver <= 1:
			len_lt = len(struct_lt) if isinstance(struct_lt, list) else 0
			len_lte = len(struct_lte) if isinstance(struct_lte, list) else 0
			if len_lt == 1:
				if len(struct_lt[0].keys()) == 1:
					struct_version[0] |= struct_lt[0]
					lt_val = firstval(struct_lt[0])
					gte = matching_parts(lt_val, last_less_than)
					if gte is not None:
						struct_version[0] |= {"greaterThanOrEqual": gte}
						last_less_than = lt_val

					# fulfill_version_only = False
			elif len_lte == 1:
				if len(struct_lte[0].keys()) == 1:
					struct_version[0] |= struct_lte[0]
					lte_val = firstval(struct_lte[0])
					gte = matching_parts(lte_val, last_less_than)
					if gte is not None:
						struct_version[0] |= {"greaterThanOrEqual": gte}
						last_less_than = lte_val
					# fulfill_version_only = False

			# It can't be fulfill via lt or lte
			elif len_lt == 0 and len_lte == 0:
				fulfill_version_only = True
			
		if not fulfill_version_only:
			# print(struct_lt, struct_lte)
			for i in range(len(struct_version)):
				if lt_formatted and struct_lt:
					# print(struct_lt)
					for d in struct_lt:
						struct_version[i] |= d
						# lt_val = firstval(d)
						# if last_less_than is not None:
						# 	struct_version[i] |= {"greaterThanOrEqual": matching_parts(lt_val, last_less_than)}
						# last_less_than = lt_val
				elif lte_formatted and struct_lte:
					for d in struct_lte:
						struct_version[i] |= d
						# lte_val = firstval(d)
						# if last_less_than is not None:
						# 	struct_version[i] |= {"greaterThanOrEqual": matching_parts(lte_val, last_less_than)}
						# last_less_than = lte_val

		if struct_version:
			result.extend(struct_version)

	# print(struct_version)
	return result

def make_struct_version(version: str, default_key: str) -> list[{"greaterThan": str, "greaterThanOrEqual": str, "lessThan": str, "lessThanOrEqual": str, "equal": str}]:
	"""
	Parse a version string into a structured format.

	:param version: The version string to parse.
	:return: List of dictionaries describing te affected versions:
		- greaterThan
		- greaterThanOrEqual
		- lessThan
		- lessThanOrEqual
		- equal
	"""
	if version is None:
		return []
	# Possibly continuous when >/>= is found
	element = {}
	result = []
	# print(f"version: {version}")
	for e in re.split(r',|;', version):
		ranges = re.split(r' - |\u2013|->', e)
		len_ranges = len(ranges) # Supposed to be 1 or 2 at most
		
		if len_ranges == 1:
			e = ranges[0].strip()
			if len(e) < 3:
				continue
			if e[0] == '>':
				if element:
					# Wasn't continuous, append
					result.append(element)
					# This new one might be
					element = {}
				if e.startswith('>='):
					element["greaterThanOrEqual"] = version_rm_suffix_and_parse(e[2:])
				else:
					element["greaterThan"] = version_rm_suffix_and_parse(e[1:])
				continue
				
			elif e.startswith('<='):
				element["lessThanOrEqual"] = version_rm_suffix_and_parse(e[2:])
			elif e[0] == '<':
				element["lessThan"] = version_rm_suffix_and_parse(e[1:])
			else:
				e = e.replace('=', '')
				element[default_key] = version_rm_suffix_and_parse(e)
			
		elif len_ranges == 2:
			e = e.strip()
			if len(ranges[0]) < 3 or len(ranges[1]) < 3:
				continue
			# Wasn't continuous
			if element:
				result.append(element)
				element = {}
			e = ranges[0].replace('>=', '').replace('=', '') # Suppress default
			if e.startswith('>'):
				element["greaterThan"] = version_rm_suffix_and_parse(e[1:])
			else:
				element["greaterThanOrEqual"] = version_rm_suffix_and_parse(e)

			e = ranges[1].replace('<=', '').replace('=', '') # Suppress default
			if e.startswith('<'):
				element["lessThan"] = version_rm_suffix_and_parse(e[1:])
			else:
				element["lessThanOrEqual"] = version_rm_suffix_and_parse(e)
		else:
			# raise ValueError(f"Invalid range {ranges}")
			continue
		result.append(element)
	# print(result)
	return result

def version_format(original: str|None, vendor: str, product: str, default_key: str = "equal") -> tuple[str|None, bool, list[dict]|None]:
	"""
	Attempt to format a version string into a more standardized format.
	:todo Add confidence score to the returned string.
	:param original: The version string to format.
	:return: Tuple:
		- string: result
		- bool: True if result isn't lexical
		- list[dict]|None: structured version for parsing, or None if result is still lexical
	"""
	if not original or re.search(version_invalid, original) is not None:
		return (None, False, None)
	version = original.lower() # Remove the prefix if present
	if ':' in version:
		version = version.partition(':')[2]
	version = original.lower() # Remove the prefix if present
	version = re.sub(r"\.x+", ".*", version) # '.x' is suposed to be a wildcard
	version = version.replace("=>", ">=").replace("=<", "<=") # '<' and '>' are always before '='
	version = version.replace("\u2264", "<=").replace("\u2265", ">=").replace(" \u2013 ", " - ") # Replace possible unicode
	version = re.sub(r"(?:all|any|versions?|affect(?:ing|s)?|only)\s+", "", version).strip() # Pointless to precise 'all versions (...)'

	def subversion_range(match) -> str:
		gte = match.group("gte")
		lte = match.group("lte")
		def invalid_range() -> str:
			return gte + match.group('rng') + lte
		pg = gte.count('.')
		pl = lte.count('.')
		if pg > pl:
			return invalid_range()
		vg = version_rm_suffix_and_parse(gte)
		vl = version_rm_suffix_and_parse(lte)
		if not isinstance(vg, Version) or not isinstance(vl, Version) or vg > vl:
			return invalid_range()
		return f">={gte},<={lte}"
	## version1 - version2
	version = re.sub(rf"{VER('gte')}(?P<rng>\s*-\s*){VER('lte')}", subversion_range, version).strip() # Pointless to precise 'all versions (...)'

	# It possibly doesn't need lexical parsing
	if re.search(VERSION_LEXICAL, version) is None:
		return (version, True, make_struct_version(version, default_key))

	def subversion(match) -> str:
		def get_first_group(base_name, maxindex):
			"""Return the first non-None group value for base_name + index (e.g., gte1, gte2, ...)."""
			for i in range(1, maxindex+1):
				value = match.group(f"{base_name}{i}") if f"{base_name}{i}" in match.groupdict() else None
				if value is not None:
					return value
			return None
		result = []
		gte = get_first_group("gte", 6)
		gt = get_first_group("gt", 4)
		lte = get_first_group("lte", 7)
		lt = get_first_group("lt", 5)
		if gte is not None:
			result.append(f">={gte}")
		elif gt is not None:
			result.append(f">{gt}")
		
		if lte is not None:
			result.append(f"<={lte}")
		elif lt is not None:
			result.append(f"<{lt}")

		if match.group("eq") is not None:
			result.append(match.group('eq'))

		return ','.join(result)


	rule_vendor_product = re.split(r"\.|\+|\*|\!|\?|-|_|,|;|\s|\&|\\|\/|\(|\)|\[|\]|\{|\}|\|| ", vendor+"/"+product)
	rule_vendor_product = list(set(rule_vendor_product))
	rule_vendor_product = [s for s in rule_vendor_product if s and not any(char.isdigit() for char in s)]
	if len(rule_vendor_product) != 0:
		rule_vendor_product = r"\b(?:"+("|".join(rule_vendor_product))+r")\b"
		# print(":",rule_vendor_product)
		version = re.sub(rule_vendor_product, "", version) # Pointless to precise vendor and product
		version = re.sub(r"\s+", " ", version).strip()

	version = re.sub(r"\bv"+VER("ver"), r"\g<ver>", version)

	# Fixed in...
	# Only '<' or '<='
	version = re.sub(
		rf"(?:FIXED|UNAFFECTED)(?:-|\s+)(?:{PROLOG}\s+)?"
		rf"((?:{GREATER_THAN_OR_EQUAL})\s+{VER('lt1')}|(?:{GREATER_THAN})\s+{VER('lte1')})"

		rf"|(?:{PROLOG}\s+)?("
	# Ranges
	# '>' or '>=', AND '<' or '<='
	## After... and before...
		rf"(?:{GREATER_THAN_OR_EQUAL})\s+{VER('gte1')}\s+(?:and|or)\s+(?:{LESS_THAN_OR_EQUAL})?\s+{VER('lte2')}"
		fr"|(?:{GREATER_THAN_OR_EQUAL})\s+{VER('gte2')}\s+(?:and|or)\s+(?:{LESS_THAN})?\s+{VER('lt2')}"

		rf"|(?:{GREATER_THAN})\s+{VER('gt1')}\s+(?:and|or)\s+(?:{LESS_THAN_OR_EQUAL})?\s+{VER('lte3')}"
		rf"|(?:{GREATER_THAN})\s+{VER('gt2')}\s+(?:and|or)\s+(?:{LESS_THAN})?\s+{VER('lt3')}"

	## Between... and...
		rf"|BETWEEN\s+{VER('gte3')}\s+(?:and)?(?:\s+(?:before|below))?\s+{VER('lte4')}"
	## ... through...
		rf"|{VER('gte4')}\s+(?:through|(?:up(?:-|\s+))?to)\s+{VER('lte5')}"

	# ...and above/below
	# '<=' or '>=' (included)
		rf"|{VER('gte5')}\s+(?:and|or)\s+(?:{GREATER_THAN_OR_EQUAL})"
		rf"|{VER('lte6')}\s+(?:and|or)\s+(?:{LESS_THAN_OR_EQUAL})"
	# '<' or '>' (excluded)
		rf"|{VER('gt3')}\s+(?:and|or)\s+(?:{GREATER_THAN})"
		rf"|{VER('lt4')}\s+(?:and|or)\s+(?:{LESS_THAN})"

	# Above/Below...
		rf"|(?:{GREATER_THAN_OR_EQUAL})\s+{VER('gte6')}"
		rf"|(?:{GREATER_THAN})\s+{VER('gt4')}"
		rf"|(?:{LESS_THAN_OR_EQUAL})\s+{VER('lte7')}"
		rf"|(?:{LESS_THAN})\s+{VER('lt5')}"

		r")"+ EPILOG +
	# Equal...
		rf"|(?:(is|only|solely|equal(?:(?:-|\s+)to)?)+)\s+{VER('eq')}"
		, subversion, version, flags=re.IGNORECASE)
	
	if re.search(VERSION_LEXICAL, version) is not None:
		return (version, False, None)
	return (version, True, make_struct_version(version, default_key))

# Implement grammar
# https://github.com/dabeaz/ply
def version_rm_suffix_and_parse(version: str) -> Version | str:
	"""
	@brief Parse a version string to a standardized format.
	@param version str: The version string to parse.
	@return str: The parsed version string, or an empty string if invalid.
	"""
	if not version or re.match(r"[_.-]", version):
		return ""
	if re.match(r"^[a-zA-Z]", version):
		return version
	def subrelease(match) -> str:
		release = sum(
			ord(char) - ord('a') + 1
			for char in match.group("release").lower()
		)
		if match.group('build') is None:
			return f".{release}"
		return f".{release}.{match.group('build')}"
	version = re.sub(r"(\+|~).*|[^\x2a-\x7a]", "", version)
	version = re.sub(r"-|:|_", ".", version)
	version = re.sub(r"(?:\.*)(?P<release>[a-z]+)(?:\.*(?P<build>[0-9\.]+))?", subrelease, version, flags=re.IGNORECASE)
	version = re.sub(r"^(?:\*|\.)+([0-9])|([0-9])(?:\*|\.)+$", r"\1\2", version) \
		.replace("..", ".") \
		.replace("..", ".") \
		.strip()

	if re.match(r"^[0-9.]+$", version) is None:
		return version
	return Version(version)

def VER(grp: str) -> re:
	return fr"(?P<{grp}>[0-9]+\.[a-z0-9_\.-]+)"
# Cannot determine affected version
version_invalid = r"^(?:unspecified|n/a|unknown)$|^(?:sha\d+:|https://|github.com/|git (?:master|main|commit) \w+$|commit)"
# Matches all versions
WS = r"(\s|\\(?:r|n|t))+"
# version_all = fr"^\*|(?:ALL|ANY)(?:{WS}VERSIONS?)?$"

# Optional
UNIVERSAL	= r"(?:IS|ONLY|AFFECT(?:S|ING|ED)?|VERSIONS?)*"
PROLOG		= fr"(?:(?:IS{WS})?{UNIVERSAL}(?:IN{WS})?(?:(?:ALL|ANY){WS})?(?:VERSIONS?{WS})?)?"
EPILOG		= UNIVERSAL

# Conjunctions
AND_OR	= r"(?:AND|OR)"+ WS
NOT		= r"NOT"+ WS
TO		= fr"(?:(?:{WS}|-)TO)?"
THAN	= fr"(?:{WS}THAN)?"

# Prepositions
EQUAL_TO	= fr"EQUAL(?:S|{TO})?"
ONLY		= fr"(?:AND{WS})ONLY"
INCLUDING	= fr"(?:{AND_OR})?(?:{EQUAL_TO}|INCLUD(?:ING|E(D)?))"
EXCLUDING	= fr"{NOT}{EQUAL_TO}|EXCLUD(?:ING|E(?:D)?)"
UP_TO		= r"UP"+ TO
EQUAL		= fr"{EQUAL_TO}|{INCLUDING}"
AND_INCLUDING = fr"(?:(?:AND{WS})?{INCLUDING})"
AND_EXCLUDING = fr"(?:(?:(?:AND|BUT){WS})?{EXCLUDING}|(?:BUT{WS})?NOT{WS}{INCLUDING})"


# Comparisons
## Exclude
LESS_THAN 			= fr"BELOW|UNDER(?:TOW)?|BEFORE|(?:UP|PRIOR){TO}|(?:LESS|OLDER|LOWER|EARLIER){THAN}"
LESS_THAN_OR_EQUAL	= r"(?:UNTIL|"+LESS_THAN+r")"+WS+AND_INCLUDING
GREATER_THAN 		= r"ABOVE|BEYOND|AFTER|(?:LATER|NEWER|HIGHER)"+ THAN
GREATER_THAN_OR_EQUAL = fr"FROM|SINCE|STARTING(?:{WS}FROM|{WS}WITH)?|(?:"+GREATER_THAN+r")"+WS+AND_INCLUDING


# After parsing, is it still a lexical version?
	# If it contain 2 consecutive words, the first ending by any letter,
	# and the second starting by any letter starts with a letter
VERSION_LEXICAL = r"[a-z]\s+[a-z]"

# .containers.cna.affected[].versions
# .containers.adp[].affected[].versions
def is_affected(affected_versions: list[dict], tested_version: str, perfect_match: bool = True) -> bool:

	len_affected_versions = len(affected_versions)

	# No affected versions specified
	if len_affected_versions == 0:
		return False

	def get_major(v: str | int) -> int:
		return (
			int(v.split(".")[0])
			if isinstance(v, str)
				and re.match(r"^[0-9.]+$", v) is not None
			else v
		)

	parsed_test_version = version_rm_suffix_and_parse(tested_version)

	def test_structured_version(
		parsed_struct_version: {"greaterThan": str, "greaterThanOrEqual": str, "lessThan": str, "lessThanOrEqual": str, "equal": str},
		parsed_test_version: str
	) -> bool:
		equal = parsed_struct_version.get("equal")
		if not perfect_match:
			ver1 = firstval(parsed_struct_version, -1)
			major1 = ver1.major if isinstance(ver1, Version) else get_major(ver1)
			major2 = parsed_test_version.major if isinstance(parsed_test_version, Version) else get_major(parsed_test_version)
			if isinstance(major1, int) and isinstance(major2, int):
				if major1 > major2:
					if major2 < int(major1 * IMPERFECT_MATCH_VERSION_MARGIN):
						raise VersionException()
				else:
					if major1 < int(major2 * IMPERFECT_MATCH_VERSION_MARGIN):
						raise VersionException()
			elif equal is None:
				raise VersionException()
					
		if equal is not None:
			return (
				fnmatch(str(parsed_test_version), str(equal))
				if isinstance(equal, str) or isinstance(parsed_test_version, str)
				else parsed_test_version == equal
			)
		fulfilled = True
		greaterThan = parsed_struct_version.get("greaterThan")
		greaterThanOrEqual = parsed_struct_version.get("greaterThanOrEqual")
		lessThan = parsed_struct_version.get("lessThan")
		lessThanOrEqual = parsed_struct_version.get("lessThanOrEqual")

		if greaterThan is not None:
			fulfilled = (
				fnmatch(str(parsed_test_version), str(greaterThan))
				if isinstance(greaterThan, str) or isinstance(parsed_test_version, str)
				else parsed_test_version > greaterThan
			)
		elif greaterThanOrEqual is not None:
			fulfilled = (
				fnmatch(str(parsed_test_version), str(greaterThanOrEqual))
				if isinstance(greaterThanOrEqual, str) or isinstance(parsed_test_version, str)
				else parsed_test_version >= greaterThanOrEqual
			)
		if fulfilled:
			if lessThan is not None:
				return (
					fnmatch(str(parsed_test_version), str(lessThan))
					if isinstance(lessThan, str) or isinstance(parsed_test_version, str)
					else parsed_test_version < lessThan
				)
			elif lessThanOrEqual is not None:
				return (
					fnmatch(str(parsed_test_version), str(lessThanOrEqual))
					if isinstance(lessThanOrEqual, str) or isinstance(parsed_test_version, str)
					else parsed_test_version <= lessThanOrEqual
				)
		return False

	def challenge_struct_version(affected_list: list[dict], tested_version: str) -> bool:
		"""returns True if any item of the list have matched"""
		for a in affected_list:
			if test_structured_version(a, tested_version):
				return True
		return False

	return challenge_struct_version(affected_versions, parsed_test_version)

def is_ollama_installed() -> bool:
	return importlib.util.find_spec("ollama") is not None