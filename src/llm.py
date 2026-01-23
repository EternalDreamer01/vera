#!/usr/bin/python3
################################################################################
# @file      llm.py
# @brief     
# @date      Su Jul 2025
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


import ollama
import unittest
import os, json
# from .constants import CVELIST_DIRECTORY

CVE_SUBMODULE_PATH = os.getenv("CVE_SUBMODULE_PATH", "./cvelistV5")

SYSTEM_PROMPT = """You are a classification model.
You are a classification model. You must reply with exactly one token: Yes, No, or NEI. Never add explanations, punctuation, or extra words.
Known graphics/decompression libraries include: libjpeg, libjpeg-turbo, libpng, libtiff, libwebp, zlib, libarchive, ffmpeg codecs, ImageMagick codecs.
"""

USER_PROMPT_TEMPLATE = """
Task: Given the "Description" text below, decide whether the vulnerability matches one of the three categories defined. 
Your answer MUST be exactly one token: "Yes", "No", or "NEI" (without quotes), and nothing else.

Definitions (apply these strictly):
1. Network-exploitable — Only if ALL these hold:
	- The flaw is intended to be exploited remotely over a network, AND
	- It targets a **client program** (a user-side application, e.g., web browser, mail client, messaging app, network-enabled desktop app), **NOT a server or daemon**.
	- Exploitation does NOT require open TCP/UDP ports or running daemons.
	- Affects a network protocol implementation, web browser, mail/messaging client, or other client-side protocol handler.

2. Library — Only if ALL these hold:
	- The vulnerable component is a library, AND
	- The library is related to archives/compressed folders, decompression/decoding operations, or is a common graphics/media library, AND
	- The issue affects decompression, decoding, or parsing of data (not compression).

   Common examples include: libjpeg, libjpeg-turbo, libpng, libtiff, libwebp, zlib, libarchive, libbzip2, xz-utils, ffmpeg, ImageMagick codecs, etc.

3. Else (escalation/exec) — If not matching the above but describes privilege escalation or command execution as another user under default configuration.

Output rules:
If the description matches any of the three categories above, reply "Yes".
If the description clearly does NOT match any category, reply "No".
If there is insufficient information to apply the rules (e.g., unknown target, unknown component type, or missing key details), reply "NEI".
Output exactly one of: Yes, No, NEI
Do not explain.

Description:
"""

PROGRAMS_INTERESTING_FOR_SDV = [
# Libraries
    "openssl",
	"libjpeg",
	"libjpeg-turbo",
	"libpng",
	"libtiff",
	"libwebp",
	"zlib",
	"libarchive",
	"libbzip2",
	"xz-utils",
	"ffmpeg",
	"ImageMagick",
	"glib(c|2)?",

# Client GUI programs
	"firefox",
	"chrome",
	"chromium",
	"safari",
	"edge",
	"thunderbird",
	"evolution",
]

PROGRAMS_NOT_INTERESTING_FOR_SDV = [
# Server/daemon programs
	# "nginx",
	# "apache",
	# "mysql",
	# "postgresql",
	"ssh",
	"ftp",
	"samba",
	"dnsmasq",
	"bind",
	"docker",
	"kubernetes",
	"openssh",
	"openssh-server",

# Command-line tools
	"curl",
	"wget",
	"scp",
	"rsync",
	"vim",
	"emacs",
	"emacs-filesystem",
	"nano",
	"vim-common",
	"binutils",
	"gcc",
	"gdb",
	"jq",
	"go"
	"python",
	"perl",
	"ruby",
	"lua",
	"traceroute",
	"ncurses",
	"rpm",
	"tar",
	"zip",
	"unzip",
	"tcpdump",
	"sharutils",
]

def get_description(cve_id: str) -> str | None:
	_, year, num = cve_id.split("-")
	cve_prefix = "0"

	if len(num) > 3:
		cve_prefix = num[:-3]
	else:
		num = f"{int(num):04d}"  # Zero-pad to 4 digits
	file_path = f"{CVE_SUBMODULE_PATH}/cves/{year}/{cve_prefix}xxx/CVE-{year}-{num}.json"
	# print(file_path)
	with open(file_path, "r", encoding="utf-8") as f:
		data = json.load(f)
		return data["containers"]["cna"]["descriptions"][0]["value"]

def is_exploitable_sdv(cve_id: str) -> bool | None:
	desc = get_description(cve_id)
	response = ollama.generate(
		model='mistral-nemo:12b',
		system=SYSTEM_PROMPT,
		prompt=USER_PROMPT_TEMPLATE+desc,
		options={
			"temperature": 0.0,
			"num_predict": 3,
			"seed": 16,
			"top_p": 0.9,
			"stop": ["\n", ".", " "]
		}
	).response[0:3].lower().strip()
	print("LLM response:", response)
	if response == "nei":
		return None
	return response == "yes"
	# if response == "yes":
	# 	return True
	# elif response == "no":
	# 	return False
	# return None

class TestLLM(unittest.TestCase):
	def test_OpenSSL_c_rehash(self):
		print("OpenSSL c_rehash")
		self.assertTrue(is_exploitable_sdv("CVE-2022-2068"), "OpenSSL c_rehash")

	def test_ZLib_inflateGetHeader(self):
		print("ZLib inflateGetHeader")
		self.assertTrue(is_exploitable_sdv("CVE-2022-37434"), "ZLib inflateGetHeader")

	# def test_Sudoedit(self):
	# 	self.assertTrue(is_exploitable_sdv("""In Sudo before 1.9.12p2, the sudoedit (aka -e) feature mishandles extra arguments passed in the user-provided environment variables (SUDO_EDITOR, VISUAL, and EDITOR), allowing a local attacker to append arbitrary entries to the list of files to process. This can lead to privilege escalation. Affected versions are 1.8.0 through 1.9.12.p1. The problem exists because a user-specified editor may contain a "--" argument that defeats a protection mechanism, e.g., an EDITOR='vim -- /path/to/extra/file' value."""), "Sudoedit")

	def test_SSH_PermitRootLogin(self):
		print("SSH PermitRootLogin")
		self.assertEqual(is_exploitable_sdv("CVE-2025-48416"), False, "SSH PermitRootLogin")

	# def test_Libarchive(self):
	# 	self.assertTrue(is_exploitable_sdv("A vulnerability has been identified in the libarchive library. This flaw can lead to a heap buffer over-read due to the size of a filter block potentially exceeding the Lempel-Ziv-Storer-Schieber (LZSS) window. This means the library may attempt to read beyond the allocated memory buffer, which can result in unpredictable program behavior, crashes (denial of service), or the disclosure of sensitive information from adjacent memory regions."), "Libarchive")

	def test_libjpeg(self):
		print("libjpeg")
		self.assertTrue(is_exploitable_sdv("CVE-2020-14152"), "libjpeg")
  
	def test_libjpeg_turbo(self):
		print("libjpeg-turbo")
		self.assertTrue(is_exploitable_sdv("CVE-2020-17541"), "libjpeg-turbo")
  
	def test_libexpat(self):
		print("libexpat")
		self.assertIsNone(is_exploitable_sdv("CVE-2022-25235"), "libexpat")

	def test_GCC(self):
		print("GCC")
		self.assertEqual(is_exploitable_sdv("CVE-2021-37322"), False, "GCC")

	def test_iperf3(self):
		print("iperf3")
		self.assertEqual(is_exploitable_sdv("CVE-2023-38403"), False, "iperf3")

	def test_DNSSEC(self):
		print("DNSSEC")
		self.assertTrue(is_exploitable_sdv("CVE-2020-25681"), "DNSSEC")

	def test_chrome(self):
		print("Chrome")
		self.assertTrue(is_exploitable_sdv("CVE-2023-4863"), "Chrome")

if __name__ == "__main__":
	# print(get_description("CVE-2023-4863"))
	unittest.main()
