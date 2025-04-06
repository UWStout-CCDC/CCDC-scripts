#!/usr/bin/env python3
# Version 1.0.0
# Run this script proior to competition and put the config txt file on GitHub.
# This will do a basic configuration of the Cisco Firepower.
#      _                _                           _
#     | |              | |                         (_)                                _____
#   __| |  ___    _____| |       ___  ___       __  _  _____    ___    _____ ____    /  ___\
#  / _` | / _ \  /   _/| |___   / _ \ \  \  _  /  /| | | __ \  / _ \  /  __/|  _ \  _| |_    
# | (_| || |_| | \  \  |  __ \ | |_| | |  \/ \/  | | | | |_| || |_| | \  \  | |_| |[_   _]
#  \__,_| \___/ |____/ |_,| |_| \___/   \___/\__/  |_| | ___/  \___/ |____/ | ___/   | |
#                                                      | |                  | |      |_|
#                                                      |_|                  |_|

team_num = input("Please enter the Team Number (+ Internal subnet number if applicable):")
team_num = str(team_num)
# Team number for varaibles

permitted_ip = input("Please enter the Ubuntu Workstation IP: ")
permitted_ip = str(permitted_ip)
# Set Static IP for Ubuntu Workstation
# Permit only the Ubuntu Workstation IP and the CiscoFirepower IP


with open("FPConfig.txt", "w") as command_file:
  commands="""
configure ssh-access-list 172.20.242.0/24
configure https-access-list 172.20.242.0/24
configure password
system lockdown-sensor
"""
  command_file.write(commands)
  print("File is written to FPConfig.txt")
print("Copy and paste the output of the script.")

# Before script run 'username admin password <password> privilege 15end' and 'wr mem' to save the configuration

# TODO: Figure out more console commands to add to the script. FirePower kind of is a pain to work with for CLI though.