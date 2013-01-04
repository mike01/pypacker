#!/usr/bin/env python

from distutils.core import setup
import dpkt
# fix: https://code.google.com/p/dpkt/issues/attachmentText?id=63
import setuptools

# fix: https://code.google.com/p/dpkt/issues/detail?id=82
setup(name='dpkt',
      version='1.0',
      author='Michael Stahn <michael.stahn@gmail.com>',
      url='',
      description='Fast, simple packet creation and parsing module',
      packages=[ 'pypacker' ])
