#!/usr/bin/env python
a=set(line.strip().lower() for line in open('blackweb.txt').readlines())
b=set(line.strip().lower() for line in open('SquidError.txt').readlines())
open("final", "w").write("\n".join(a.difference(b)))
