#!/bin/bash

if [ $(whoami) != "root" ];then
  echo "THIS SCRIPT MUST BE RUN AS ROOT!"
  exit
fi

find / -name .bashrc > temp4 &
md5sum /etc/passwd /etc/group /etc/profile md5sum /etc/sudoers /etc/hosts /etc/ssh/ssh_config /etc/ssh/sshd_config > temp2
ls -a /etc/ /usr/ /sys/ /home/ /bin/ /etc/ssh/ >> temp2
while true;
do	
	netstat -n -A inet | grep ESTABLISHED > temp
	incoming_ftp=$(cat temp | cut -d ':' -f2 | grep "^21" | wc -l)
	outgoing_ftp=$(cat temp | cut -d ':' -f3 | grep "^21" | wc -l)
	
	incoming_ssh=$(cat temp | cut -d ':' -f2 | grep "^22" | wc -l)
	outgoing_ssh=$(cat temp | cut -d ':' -f3 | grep "^22" | wc -l)

	

	outgoing_telnet=$(cat temp | cut -d ':' -f2 | grep "^23" | wc -l)
	incoming_telnet=$(cat temp | cut -d ':' -f3 | grep "^23" | wc -l)

	incoming_telnet=$(cat temp | cut -d ':' -f2 | grep "^^23" | wc -l)
	outgoing_telnet=$(cat temp | cut -d ':' -f3 | grep "^^23" | wc -l)

	
	echo "ACTIVE NETWORK CONNECTIONS:"
	echo "---------------------------"
	if [ $outgoing_telnet -gt 0 ]; then
		echo $outgoing_telnet successful outgoing telnet connection.
	fi
	
	if [ $incoming_telnet -gt 0 ]; then
		echo $incoming_telnet successful incoming telnet session.
	fi

	if [ $outgoing_ssh -gt 0 ]; then
		echo $outgoing_ssh successful outgoing ssh connection.
	fi
	
	if [ $incoming_ssh -gt 0 ]; then
		echo $incoming_ssh successful incoming ssh session.
	fi
	
	
	if [ $outgoing_ftp -gt 0 ]; then
		echo $outgoing_ftp successful outgoing ftp connection.
	fi
	
	if [ $incoming_ftp -gt 0 ]; then
		echo $incoming_ftp successful incoming ftp session.
	fi

	if [ $incoming_ftp -gt 0 ]; then
		echo $incoming_ftp successful incoming ftp session.
	fi
	cat temp
	sleep 5
	clear

	echo "CURRENT LOGIN SESSIONS:"
	echo "-----------------------"
	w
	echo
	echo "RECENT LOGIN SESSIONS:"
	echo "----------------------"
	last | head -n5
	sleep 5
	clear

	sleepingProcs=$(pstree | grep sleep)
	if [[ ! -z "$sleepingProcs" ]];then
	  echo "SLEEP PROCESSES:"
	  echo "----------------"
	  sleep 5
	  clear
	fi

	#Check for changes to important files.
	
	md5sum /etc/passwd /etc/group /etc/profile md5sum /etc/sudoers /etc/hosts /etc/ssh/ssh_config /etc/ssh/sshd_config > temp3
	ls -a /etc/ /usr/ /sys/ /home/ /bin/ /etc/ssh/ >> temp3
	fileChanges=$(diff temp2 temp3)
	if [[ ! -z "$fileChanges" ]];then
  	  echo CHANGE TRACKER:
	  echo -e "\n"
	  echo "$fileChanges"
	  sleep 5
	  clear
	fi

	echo "CRON JOBS:"
	echo "Found Cronjobs for the following users:"
	echo "---------------------------------------"
	ls /var/spool/cron/crontabs
	echo
	echo "Cronjobs in cron.d:"
	echo "-------------------"
	ls /etc/cron.d/
	sleep 5
	clear

	echo "ALIASES:"
	echo "--------"
	alias
	echo
	echo ".BASHRC LOCATIONS:"
	echo "------------------"
	cat temp4 | while read line
	do
		echo $line
	done
	sleep 5
	clear

	echo "USERS ABLE TO LOGIN:"
	echo "--------------------"
	grep -v -e "/bin/false" -e "/sbin/nologin" /etc/passwd | cut -d ':' -f1
	sleep 5
	clear

	echo "CURRENT PROCESS TREE:"
	echo "---------------------"
	pstree
	sleep 7
	clear
  
  	if type aide > /dev/null
  	then
    		echo "AIDE:"
    		echo "-----------"
		echo "If used on Splunk there will be noise from Splunk logs"
    		aide --check > /aide_log.txt
		head /aide_log.txt
		echo "Use 'vi /aide_log.txt' to get more detailed info" 
		sleep 7
		clear
   	fi
  
done


exit

if [[ $EUID -ne 0 ]]
then
  printf 'Must be run as root, exiting!\n'
  exit 1
fi

SAVE_FILE="temp_save"
LAST_FILE="temp_last"
touch $SAVE_FILE

verify_packaged_files() {
  # This take a while, should do it in a seperate screen session
  if type dpkg
  then
    dpkg -V
  elif type rpm
  then
    rpm -V
  else
    echo "Unknown Package manager"
  fi
}

locate_added_files() {
  EXTRA_FILES="/ccdc/log/extra_files"
  echo "" > $EXTRA_FILES
  for LINE in $(echo $PATH | sed -e 's/:/\n/g' | head -10)
  do
    for FILE in $(ls -Ap -w 1 $LINE)
    do
      dpkg -S $LINE/$FILE || echo "$LINE/$FILE" >> $EXTRA_FILES
    done
  done
}

while true
do
  mv $SAVE_FILE $LAST_FILE
  # Run checks > $SAVE_FILE

  # List active connections, filters out ports 80, 443, 53, 123
  echo "Active Connections:" >> $SAVE_FILE
	netstat -n -A inet | grep ESTABLISHED | grep -vP ":(80|443|53|123)" >> $SAVE_FILE
  
  echo "\nActive Logins:" >> $SAVE_FILE
  # Manually print header & tell w not to print a header
  echo "USER\tTTY\tFROM\tLOGIN@\tIDLE\tJCPU\tPCPU\tWHAT" >> $SAVE_FILE
	w -h >> $SAVE_FILE

  echo "\nFailed Logins:" >> $SAVE_FILE
	lastb >> $SAVE_FILE

  echo "\nSuccessful Logins:" >> $SAVE_FILE
	last >> $SAVE_FILE
  
  # `pstree` `ps -aux` ??

  echo "\nUser Crontabs:" >> $SAVE_FILE
	ls /var/spool/cron/crontabs >> $SAVE_FILE

  echo "\nSystem Crontabs:" >> $SAVE_FILE
	ls /etc/cron.d/ >> $SAVE_FILE

  echo "\nUsers able to login:" >> $SAVE_FILE
	grep -v -e "/bin/false" -e "/sbin/nologin" /etc/passwd | cut -d ':' -f1 >> $SAVE_FILE

  echo "\nFiles changed:" >> $SAVE_FILE
  aide --check >> $SAVE_FILE

  echo "\nSetuid Files:" >> $SAVE_FILE
  find / -perm /u+s,u+g >> $SAVE_FILE

  # diff will print the full list of changes to stdout, while wall will print across ALL active sessions
  if diff $SAVE_FILE $LAST_FILE
  then
    wall ">>>> Something has changed <<<<"
  fi

  sleep 20
done

