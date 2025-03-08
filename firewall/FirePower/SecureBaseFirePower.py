#!/usr/bin/env python3
# Version 1.0.0
# Run this script proior to competition and put the config txt file on GitHub.
# This will do a basic configuration of the Cisco Firepower.

team_num = input("Please enter the Team Number (+ Internal subnet number if applicable):")
team_num = str(team_num)
# Team number for varaibles

permitted_ip = input("Please enter the Ubuntu Workstation IP: ")
permitted_ip = str(permitted_ip)
# Set Static IP for Ubuntu Workstation
# Permit only the Ubuntu Workstation IP and the CiscoFirepower IP


with open("FPConfig.txt", "w") as command_file:
  commands="""
configure terminal
line vty 0 15
transport input ssh
end
treat-detection basic-threat-detection
end
write memory
"""
  command_file.write(commands)
  print("File is written to FPConfig.txt")
print("Copy and paste the output of the script.")

# Before script run 'username admin password <password> privilege 15end' and 'wr mem' to save the configuration