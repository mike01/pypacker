#!/usr/bin/env python

try:
	from setuptools import setup, Command
except ImportError:
	from distutils.core import setup, Command

setup(name="pypacker",
	version="4.0",
	author="Michael Stahn",
	author_email="michael.stahn.42@gmail.com",
	url="https://github.com/mike01/pypacker",
	description="Pypacker: The fast and simple packet creating and parsing module",
	license="BSD",
	packages=[
		"pypacker",
		"pypacker.layer12",
		"pypacker.layer3",
		"pypacker.layer4",
		"pypacker.layer567"
	],
	package_data={"pypacker": ["oui_stripped.txt"]},
	classifiers=[
		"Development Status :: 6 - Mature",
		"Intended Audience :: Developers",
		"License :: OSI Approved :: BSD License",
		"Natural Language :: English",
		"Programming Language :: Python :: 3.3",
		"Programming Language :: Python :: 3.4",
		"Programming Language :: Python :: 3.5",
		"Programming Language :: Python :: 3.6",
		"Programming Language :: Python :: Implementation :: CPython",
		"Programming Language :: Python :: Implementation :: PyPy"
	],
	python_requires=">=3.3.*"
)
