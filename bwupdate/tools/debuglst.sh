#!/bin/bash
infile="allowurls.txt"
echo "Start debug..."
sed '/^$/d; /#/d' $infile | sed 's/^\.//g' > clean
rm dnslookup* step* fault.txt hit.txt >/dev/null 2>&1
# DNS LOCKUP
# pp = parallel processes (high resource consumption!)
pp="400"
echo "Step 1..."
if [ -s dnslookup ] ; then
		awk 'FNR==NR {seen[$2]=1;next} seen[$1]!=1' dnslookup clean
	else
		cat clean
fi | xargs -I {} -P $pp sh -c "if host {} >/dev/null; then echo HIT {}; else echo FAULT {}; fi" >> dnslookup
sed '/^FAULT/d' dnslookup | awk '{print $2}' | awk '{print "."$1}' | sort -u > hit.txt
sed '/^HIT/d' dnslookup | awk '{print $2}' | awk '{print "."$1}' | sort -u >> fault.txt
sort -o fault.txt -u fault.txt
echo "OK"
echo "Step 2..."
sed 's/^\.//g' fault.txt | sort -u > step2
if [ -s dnslookup2 ] ; then
		awk 'FNR==NR {seen[$2]=1;next} seen[$1]!=1' dnslookup2 step2
	else
		cat step2
fi | xargs -I {} -P $pp sh -c "if host {} >/dev/null; then echo HIT {}; else echo FAULT {}; fi" >> dnslookup2
sed '/^FAULT/d' dnslookup2 | awk '{print $2}' | awk '{print "."$1}' | sort -u >> hit.txt
sed '/^HIT/d' dnslookup2 | awk '{print $2}' | awk '{print "."$1}' | sort -u > fault.txt
comm -23 <(sort $infile) <(sort hit.txt) > outdiff
echo "Done"
