#!/usr/bin/env python

# Debugging squid_error

a=set(line.strip().lower() for line in open('blackweb.txt').readlines())
b=set(line.strip().lower() for line in open('sqerror.txt').readlines())
open("final.txt", "w").write("\n".join(a.difference(b)))
