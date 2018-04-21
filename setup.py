#!/usr/bin/env python

try:
	from setuptools import setup
except ImportError:
	from distutils.core import setup

with open('requirements.txt') as f:
    required = f.read().splitlines()
install_requires = [r for r in required if r and r[0] != '#' and not r.startswith('git')]

setup(name="pypacker27",
	version="4.2",
	author="Michael Stahn",
	author_email="michael.stahn.42@gmail.com",
	url="https://github.com/mike01/pypacker/tree/python27",
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
		"Programming Language :: Python :: 2.7",
		"Programming Language :: Python :: 3.6",
		"Programming Language :: Python :: Implementation :: CPython",
		"Programming Language :: Python :: Implementation :: PyPy"
	],
    install_requires=install_requires,
    python_requires=">=2.7"
)
