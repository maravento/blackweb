#!/usr/bin/env python
import sys

try:
    a = set(line.strip().lower() for line in open('blackweb.txt').readlines())
    b = set(line.strip().lower() for line in open('sqerror.txt').readlines())
    open("final.txt", "w").write("\n".join(sorted(a.difference(b))))
except FileNotFoundError as e:
    print("Error: %s" % e)
    sys.exit(1)
