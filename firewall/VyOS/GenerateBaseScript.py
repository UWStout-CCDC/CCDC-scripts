#!/usr/bin/env python3
#
# SecureBaseScript.py 
# Copyright (C) 2025 doshowipospf
#
# Distributed under terms of the MIT license.
#      _                _                           _
#     | |              | |                         (_)                                _____
#   __| |  ___    _____| |       ___  ___       __  _  _____    ___    _____ ____    /  ___\
#  / _` | / _ \  /   _/| |___   / _ \ \  \  _  /  /| | | __ \  / _ \  /  __/|  _ \  _| |_    
# | (_| || |_| | \  \  |  __ \ | |_| | |  \/ \/  | | | | |_| || |_| | \  \  | |_| |[_   _]
#  \__,_| \___/ |____/ |_,| |_| \___/   \___/\__/  |_| | ___/  \___/ |____/ | ___/   | |
#                                                      | |                  | |      |_|
#                                                      |_|                  |_|

# Version 1.0.0

# Recomended to use curl to get script on VyOS
# Script should be ran prior to competition and added to github
with open("vyosconfig.sh", "w") as command_file:
  commands="""
#!/bin/vbash
if [ "$(id -g -n)" != 'vyattacfg' ] ; then
  exec sg vyattacfg -c "/bin/vbash $(readlink -f $0) $@"
fi
configure
commit

save
"""
  command_file.write(commands)
  print("File is written to vyosconfig.sh")
  print("Issue 'curl -Lo tinyurl.com/notmadeyet' on VyOS Router\nThen run the script with 'sg vyattacfg -c ./vyosconfig.sh'")