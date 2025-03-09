#!/bin/bash

echo "#################################################"
echo "Showing Prestashop access log"
echo "#################################################"

tail -f /var/log/httpd/access_log | grep -v "/prestashop/index.php\"\|/prestashop/index.php " 