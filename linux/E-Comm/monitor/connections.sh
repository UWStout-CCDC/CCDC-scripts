#!/bin/bash
while true
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

        echo "Netstat listening ports:"
        echo "------------------------"
        netstat -tulpn

        cat temp
        sleep 5
        clear
    done