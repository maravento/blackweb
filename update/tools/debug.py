#!/usr/bin/env python
a=set(line.strip().lower() for line in open('blacklist.txt').readlines())
b=set(line.strip().lower() for line in open('whitelist.txt').readlines())
open("out.txt", "w").write("\n".join(a.difference(b)))
