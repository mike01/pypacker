#!/usr/bin/env python

from distutils.core import setup
import pypacker
import setuptools

setup(name="pypacker",
	version="1.8",
	author="Michael Stahn",
	author_email="michael.stahn.42(at)gmail.com",
	url="",
	description="pypacker: Fast and simple packet creation and parsing module",
	license="BSD",
	packages=[ "pypacker",
		"pypacker.layer12",
		"pypacker.layer3",
		"pypacker.layer4",
		"pypacker.layer567"]
	)
