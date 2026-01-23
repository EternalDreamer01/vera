#!/usr/bin/python3
################################################################################
# @file      constants.py
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


from dotenv import load_dotenv
import os

load_dotenv()

CVE_SUBMODULE_PATH = os.getenv("CVE_SUBMODULE_PATH", "./cvelistV5")
CVE_SUBMODULE_URL = os.getenv("CVE_SUBMODULE_URL", "https://github.com/CVEProject/cvelistV5.git")

DEFAULT_START_YEAR = int(os.getenv("DEFAULT_START_YEAR", "2017"))
DEFAULT_TEST_YEAR = int(os.getenv("DEFAULT_TEST_YEAR"))
DEFAULT_TEST_INPUT_FILE = os.getenv("DEFAULT_TEST_INPUT_FILE")
DEFAULT_TEST_OUTPUT_FILE = os.getenv("DEFAULT_TEST_OUTPUT_FILE")

IMPERFECT_MATCH_VERSION_MARGIN = float(os.getenv("IMPERFECT_MATCH_VERSION_MARGIN", "0.8"))
CVELIST_DIRECTORY = os.getenv("CVELIST_DIRECTORY", "./cvelistV5")
IGNORED_PREFIX = r"^(python3?|(ros|linux|golang|r|ruby)-[a-z]+)-|(nvidia|microsoft)(\s+|-)"
SLIGHT_FORMAT = r"-|_|\&| "
DEFAULT_OUT = "out.json"
UPGRADE_NON_AVAILABLE = "true" # N/A upgrade value
HOST_CACHE_PATH = os.path.expanduser("~/.cache/cve-bin-tool")

VERSION_KEY = "_version"


def get_cve_years(cve_directory):
    if not os.path.exists(cve_directory):
        return []
    try:
        return sorted(list(map(int, filter(str.isdigit, os.listdir(cve_directory)))))
    except (ValueError, TypeError):
        return []

CVE_YEARS = []
DOCKER_DEST = ["fw", "os"]

# Lowercase
KNOWN_PRODUCT_VENDOR = {
	"python": ["python", "n/a"],
	"ros": ["open robotics"],
	"linux": ["linux", "n/a"],
	"apt": ["debian"],
	"yum": ["yum"],
	"dnf": ["dnf"],
	# "golang": "Google",
	# "r": "r_project",
	# "ruby": ["ruby-lang", "n/a"],
	"dash": ["debian", "dash"],
	"gzip": ["gzip", "gnu", "n/a"],
	"login": ["linux", "debian", "n/a"],
	"dpkg": ["debian"],
	"git": ["git"],
	# "nvidia": "NVIDIA Corporation",
	# "microsoft": "Microsoft Corporation"
}
