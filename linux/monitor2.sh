#!/bin/bash

if [[ $EUID -ne 0 ]]
then
  printf 'Must be run as root, exiting!\n'
  exit 1
fi

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
  for LINE in $(echo $PATH | sed -e 's/:/\n/g')
  do
    for FILE in $(ls -Ap -w 1 $LINE)
    do
      dpkg -S $LINE/$FILE || echo "$LINE/$FILE" >> $EXTRA_FILES
    done
  done
}

case $1
  verify_packages) verify_packaged_files; exit;;
  list_added) locate_added_files; exit;;
esac

SAVE_FILE="temp_save"
LAST_FILE="temp_last"
touch $SAVE_FILE


while true
do
  mv $SAVE_FILE $LAST_FILE
  # Run checks > $SAVE_FILE

  # List active connections, filters out ports 80, 443, 53, 123
  echo "Active Connections:" >> $SAVE_FILE
	netstat -n -A inet | grep ESTABLISHED | grep -vP ":(80|443|53|123)" >> $SAVE_FILE
  echo "========================================" >> $SAVE_FILE
  echo "" >> $SAVE_FILE
  
  echo "Active Logins:" >> $SAVE_FILE
  # Manually print header & tell w not to print a header
  echo "USER	TTY	FROM	LOGIN@	IDLE	JCPU	PCPU	WHAT" >> $SAVE_FILE
	w -h >> $SAVE_FILE
  echo "========================================" >> $SAVE_FILE
  echo "" >> $SAVE_FILE

  echo "Failed Logins:" >> $SAVE_FILE
	lastb >> $SAVE_FILE
  echo "========================================" >> $SAVE_FILE
  echo "" >> $SAVE_FILE

  echo "Successful Logins:" >> $SAVE_FILE
	last >> $SAVE_FILE
  echo "========================================" >> $SAVE_FILE
  echo "" >> $SAVE_FILE
  
  # `pstree` `ps -aux` ??

  echo "User Crontabs:" >> $SAVE_FILE
	ls /var/spool/cron/crontabs >> $SAVE_FILE
  echo "========================================" >> $SAVE_FILE
  echo "" >> $SAVE_FILE

  echo "System Crontabs:" >> $SAVE_FILE
	ls /etc/cron.d/ >> $SAVE_FILE
  echo "========================================" >> $SAVE_FILE
  echo "" >> $SAVE_FILE

  echo "Users able to login:" >> $SAVE_FILE
	grep -v -e "/bin/false" -e "/sbin/nologin" /etc/passwd | cut -d ':' -f1 >> $SAVE_FILE
  echo "========================================" >> $SAVE_FILE
  echo "" >> $SAVE_FILE

  echo "Files changed:" >> $SAVE_FILE
  aide --check >> $SAVE_FILE
  echo "========================================" >> $SAVE_FILE
  echo "" >> $SAVE_FILE

  echo "Setuid Files:" >> $SAVE_FILE
  find / -perm /u+s,u+g >> $SAVE_FILE
  echo "========================================" >> $SAVE_FILE
  echo "" >> $SAVE_FILE

  # diff will print the full list of changes to stdout, while wall will print across ALL active sessions
  if diff $SAVE_FILE $LAST_FILE
  then
    wall ">>>> Something has changed <<<<"
  fi

  sleep 20
done

