#! /usr/bin/env python
#
# simple script to calculate HTROOT from ROOT_OFFSET.  Pass ROOT_OFFSET in on
# the command line

from __future__ import print_function
import sys
import os

if sys.argv[1] == '.':
    print('.')
else:
    print(os.sep.join(['..'] * len(sys.argv[1].split(os.sep))))
