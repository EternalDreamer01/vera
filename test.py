#!/usr/bin/python3
################################################################################
# @file      test.py
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

import unittest
from src.utils import *
from src.version import *
# from main import process_line


class TestStringMethods(unittest.TestCase):
	# def test_affected_versions(self):
	# 	def expect_vulnerable(affected_list: list, version: str):
	# 		self.assertTrue(is_affected(
	# 				affected_list,
	# 				version
	# 			),
	# 			f"Expect {version} vulnerable"
	# 		)
	# 	def expect_not_vulnerable(affected_list: list, version: str):
	# 		self.assertFalse(is_affected(
	# 				affected_list,
	# 				version
	# 			),
	# 			f"Expect {version} NOT vulnerable"
	# 		)
	# 	expect_vulnerable([{
	# 				"version": "1.2.5"
	# 			}],
	# 			"1.2.5.9"
	# 		)
	# 	expect_vulnerable([{
	# 				"version": "1.2.5"
	# 			}, {
	# 				"version": "1.2.6"
	# 			}],
	# 			"1.2.6"
	# 		)
	# 	expect_vulnerable([{
	# 				# "greaterThan": "5.2.2",
	# 				"lessThan": "5.2.5"
	# 			}, {
	# 				# "greaterThan": "5.4.2",
	# 				"lessThan": "5.4.5"
	# 			}],
	# 			"5.4.4"
	# 		)
	# 	expect_not_vulnerable([{
	# 				# "greaterThan": "5.2.2",
	# 				"lessThan": "5.2.5"
	# 			}, {
	# 				# "greaterThan": "5.4.2",
	# 				"lessThan": "5.4.5"
	# 			}],
	# 			"5.4.5"
	# 		)
	# 	expect_vulnerable([{
	# 				# "greaterThan": "5.2.2",
	# 				"lessThan": "5.2.5"
	# 			}, {
	# 				# "greaterThan": "5.4.2",
	# 				"lessThanOrEqual": "5.4.5"
	# 			}],
	# 			"5.4.5"
	# 		)
	# 	expect_not_vulnerable([{
	# 				"version": "5.2.2",
	# 				"lessThan": "5.2.*"
	# 			}, {
	# 				"version": "5.4.2",
	# 				"lessThanOrEqual": "5.4.*"
	# 			}],
	# 			"5.4.1"
	# 		)
	# 	expect_vulnerable([{
	# 				"version": "5.2.2",
	# 				"lessThan": "5.2.*"
	# 			}, {
	# 				"version": "5.4.2",
	# 				"lessThanOrEqual": "5.4.*"
	# 			}],
	# 			"5.4.2"
	# 		)
	# 	expect_vulnerable([{
	# 				"version": "between 5.2.2 and 5.2.14",
	# 			}, {
	# 				"version": "between 5.4.2 and 5.4.14",
	# 			}],
	# 			"5.4.12.2"
	# 		)
	# 	expect_vulnerable([{
	# 				"version": "5.4.2 through 5.4.14",
	# 			}],
	# 			"5.4.12.2"
	# 		)
	# 	expect_not_vulnerable([{
	# 				"version": "5.4.2 through 5.4.14",
	# 			}],
	# 			"5.4.15.2"
	# 		)
	# 	expect_vulnerable([{
	# 			"version": "5.4.2",
	# 			"status": "unaffected"
	# 		}],
	# 		"5.4.1"
	# 	)
	# 	expect_not_vulnerable([{
	# 			"lessThan": "3.4.88",
	# 			"version": "3.4.14",
	# 		}],
	# 		"3.4.13"
	# 	)
	# 	expect_vulnerable([{
	# 			"lessThan": "3.4.88",
	# 			"version": "3.4.14",
	# 		}],
	# 		"3.4.14"
	# 	)
	# 	expect_not_vulnerable([{
	# 			"lessThan": "3.4.88",
	# 			"version": "3.4.14",
	# 		}],
	# 		"3.4.89"
	# 	)

	def test_version_parse(self):
		ver, formatted, struct = version_format("All versions prior to CUDA Toolkit v12.2", "nvidia", "cuda toolkit")
		# print(struct)
		self.assertTrue(formatted)
		struct = make_struct_version_list([
						{
							"status": "affected",
							"version": "12.2.5-12.2.9"
						}
					], "Oracle Corporation", "Oracle Applications Framework")
		# print(struct)
		self.assertEqual(struct, [{'greaterThanOrEqual': Version('12.2.5'), 'lessThanOrEqual': Version('12.2.9')}])
		ver, formatted, struct = version_format("All Jetson Linux versions prior to r32.6.1", "nvidia", "Jetson AGX Xavier series, Jetson Xavier NX, Jetson TX2 series, Jetson TX2 NX, Jetson Nano, Jetson Nano 2GB, Jetson TX1")
		# self.assertTrue(formatted)
		# ver, formatted, struct = version_format("12.2.14", "Oracle Corporation", "Oracle Applications Framework", "lessThanOrEqual")
		# print(struct)
		# self.assertTrue(formatted)

	def test_pkg_suffix(self):
		pkg = "xz-utils"
		self.assertEqual(slice_pkg(pkg, 0), pkg)
		self.assertEqual(slice_pkg(pkg, 1), "xz")
		self.assertEqual(pkg.count('-') + pkg.count('_') + 1, 2)

if __name__ == "__main__":
	unittest.main()
