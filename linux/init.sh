

awk -F: ‘{ if ($3 > 1000) print “usermod -s /bin/nologin “ $1 }’ /etc/passwd > output.sh
