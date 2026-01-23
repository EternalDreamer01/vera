#!/usr/bin/python3
################################################################################
# @file      arg.py
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


import argparse
from enum import Enum

class ArgEnum(Enum):
	def __str__(self):
		return self.value

	@staticmethod
	def check(cls: object):
		def __from_string(value: str) -> int:
			try:
				return cls[value]
			except KeyError:
				ivalue = int(value)
				for e in cls:
					if e.value == ivalue:
						return ivalue
				raise argparse.ArgumentTypeError(f"Invalid value '{value}'. Choose from {', '.join(cls.__members__)}, {', '.join(str(e.value) for e in cls)}.")
		return __from_string

	def choices(cls: object):
		return list(cls.__members__) + list(str(e.value) for e in cls)


class Strict(Enum):
	FLEX = 0
	STRICT_VDP = 1
	STRICT_VP = 2
	STRICT_P = 3

class Upgrade(ArgEnum):
	RAW = 0
	UP = 1
	BOTH = 2

	# def __contains__(self, value):
	# 	return value in ArgEnum.choices(Upgrade)

	# def __iter__(self):
	# 	return iter(ArgEnum.choices(Upgrade))

	def __str__(self):
		return "{ "+(' | '.join(ArgEnum.choices(Upgrade)))+" }"

class UpdateAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        # Set the UPDATE flag to True
        setattr(namespace, self.dest, True)
        # Also store the fact that we're updating to skip year validation
        parser._skip_year_validation = True