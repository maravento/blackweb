#!/usr/bin/env python3
import sys

def is_subdomain_of_another(domain, domain_set):
    """Check if 'domain' is a subdomain of another domain in 'domain_set'"""
    parts = domain.lstrip('.').split('.')
    for i in range(1, len(parts)):
        candidate = '.' + '.'.join(parts[i:])
        if candidate != domain and candidate in domain_set:
            return True
    return False

try:
    with open('blackweb.txt', encoding='utf-8') as f:
        a = {line.strip().lower() for line in f if line.strip()}

    with open('sqerror.txt', encoding='utf-8') as f:
        b = {line.strip().lower() for line in f if line.strip()}
        b = {x if x.startswith('.') else '.' + x for x in b}

    # domains from sqerror.txt that have a parent in blackweb.txt -> these must be excluded
    a_excluir = {d for d in b if d in a and is_subdomain_of_another(d, a)}

    result = a - a_excluir
    with open('final.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(result)) + '\n')
except FileNotFoundError as e:
    print("Error: %s" % e)
    sys.exit(1)
