#!/bin/bash
### BEGIN INIT INFO
# Provides:	         httpstatus
# Required-Start:    $local_fs $remote_fs $network
# Required-Stop:     $local_fs $remote_fs $network
# Should-Start:      $named
# Should-Stop:       $named
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Start daemon at boot time
# Description:       Enable service provided by daemon
### END INIT INFO

# https://stackoverflow.com/questions/6136022/script-to-get-the-http-status-code-of-a-list-of-urls
# modified by:	maravento and novatoz

# PATH FILE (change path to your list)
bwlst=$(pwd)/blackweb.txt

# CLEAN LIST
sed -e '/^#/d' $bwlst | sed -r '/^.\W+/d' | sed 's/^.//g' | sed '/[A-Z]/d' | sort -u > cleanlst

# Use HTTPSTATUS (1 or 2) depending on your network. The results may differ

# HTTPSTATUS 1 (default)
while read LINE; do
        curl -o /dev/null --silent --head --write-out '%{http_code}' "$LINE"
        echo " $LINE"
done < cleanlst > tmplst
sed '/^000/d' tmplst | awk '{print $2}' | awk '{print "."$1}' | sort -u > out

# HTTPSTATUS 2
#fping -a -q -f cleanlst > out && sort -o out -u out

# REPLACE BLACKWEB
sudo cp out $bwlst

echo Done
