#!/usr/bin/env python
# from https://github.com/lsemel/python-parse-domain/blob/master/parse_domain.py
# fix by novatoz

from urlparse import urlparse
import re

def parse_domain(url, levels=2):
    """
    Given a URL or hostname, returns the domain to the given level (level 1 is the top-level domain).
    Uses a list of active top-level domains to ensure long TLD's such as ".co.uk" are correctly treated as a single TLD.
    If the domain has an unrecognizable TLD, assumes it is one level.
    """
    if levels < 1 or not url:
        return None

    # Parse the hostname from the url
    parsed = urlparse(url)
    hostname = getattr(parsed,'hostname',url)

    partial_domains = []
    partial_domain = ""
    if hostname is None:
        return None
    for section in reversed(hostname.split(".")):
        partial_domain = "." + section + partial_domain
        partial_domains.append(partial_domain)

    # Find the longest matching TLD, recording its index
    tld_idx = 0
    for idx, item in enumerate(partial_domains):
        if item in clean:
            tld_idx = idx

    # Add the desired number of levels to the tld index,
    # counting the TLD itself as the first level
    try:
        domain = partial_domains[tld_idx + levels - 1]
    except IndexError:
        domain = partial_domains[-1]

    # Remove the initial dot
    return domain[1:]

clean = set(d.strip() for d in open("tlds.txt").readlines())
valid = set(d.strip() for d in open('urls.txt').readlines())

filename = 'capture'
domains  = [d.strip('.\n') for d in file(filename).readlines()]
domains = [d for d in domains if '.'+d not in valid]

D = dict()
for domain in domains:
  D[parse_domain('http://'+domain)] = 0

for d in D:
  if d: print d
