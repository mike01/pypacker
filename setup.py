#!/usr/bin/env python

import pypacker

from distutils.core import setup

setup(name="pypacker",
	version="2.4",
	author="Michael Stahn",
	author_email="michael.stahn.42(at)gmail.com",
	url="https://github.com/mike01/pypacker",
	description="Pypacker: The fast and simple packet creating and parsing module",
	license="BSD",
	packages=[
		"pypacker",
		"pypacker.layer12",
		"pypacker.layer3",
		"pypacker.layer4",
		"pypacker.layer567"
	]
)
