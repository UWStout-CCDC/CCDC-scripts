#!/bin/bash
# 
# fire-gen.sh
# 
# Generate firepower api calls based on input
# run by main script. Not meant for stand-alone
# 
# Kaicheng Ye
# Mar. 2025

printf "${info}Starting fire-gen script${reset}\n"

# Use colors, but only if connected to a terminal
# and if the terminal supports colors
if which tput >/dev/null 2>&1
then
    ncolors=$(tput colors)
fi
if [[ -t 1 ]] && [[ -n "$ncolors" ]] && [[ "$ncolors" -ge 8 ]]
then
    export info=$(tput setaf 2)
    export error=$(tput setaf 1)
    export warn=$(tput setaf 3)
    export reset=$(tput sgr0)
else
    export info=""
    export error=""
    export warn=""
    export reset=""
fi

# $1 is the string to look for
# $2 is the list of strings
contains () {
    contain="false"
    if echo "$1" | grep -q " "; then
        # multiple (grep found a space)
        for inp in $1; do
            for word in $2; do
                if [[ "$inp" == "$word" ]]; then
                    contain="true"
                    break
                fi
                contain="false"
            done
            # if one is missing at all then quit immediately
            if [[ "$contain" == "false" ]]; then
                break
            fi
        done
    else
        # single
        for word in $2; do
            if [[ "$1" == "$word" ]]; then
                contain="true"
                break
            fi
        done
    fi
    echo "$contain"
    return 0
}

# duplicate from fire-base1.sh
# $1 pairs of name and type
make_json() {
    count=0
    json=""
    for item in $1; do
        # even means name
        # odd means type corresponding to the name
        if [[ $((count % 2)) -eq 0 ]]; then
            # name
            json+="{\"name\": \"$item\","
        else
            # type
            json+="\"type\": \"$item\"},"
        fi
        count=$((count+1))
    done
    # remove trailing comma
    json=`echo $json | sed 's/.$//'`
    echo $json
    return 0
}

# clear old fire-gen.txt file
rm -rf ./fire-gen.txt

# zone names (find on web console after password change)
if [[ "$ZONES" == "" ]]; then
    printf "${info}Enter zone names found on web console. CAPITALIZATION MATTERS!${reset}\n"
    printf "Separate each one by a single space: "
    read ZONES
else
    printf "${info}Zone names already aquired${reset}\n"
    echo $ZONES
fi


# objects

# priv & pub ips
# Loop until finished
printf "\n${info}Create Network Objects${reset}\n"
input="placeholder"
while [[ "$input" != "" ]]
do
    name=""
    ip=""

    # Get name of object
    printf "Name of object: "
    read input

    # move on if empty
    if [[ "$input" == "" ]]
    then
        break
    fi
    name=$input

    # Get IP address
    printf "(CIDR not supported) IP: "
    read input

    if [[ "$input" == "" ]]
    then
        # invalidate the name entered and try again
        input="placeholder" # set input so we don't quit this loop
        printf "${warn}No Address entered. Invalidated $name${reset}\n\n"
        continue
    fi
    ip=$input

    # last check before writing the rule down
    printf "${info}================================================================${reset}\n"
    printf "${info}Name:${reset} $name\n"
    printf "${info}  IP:${reset} $ip\n"
    printf "${info}================================================================${reset}\n"
    printf "Add rule?[y/n]: "
    read input

    if [[ "$input" == "N" || "$input" == "n" || "$input" == "" ]]; then
        input="n" # set input to "n" so we don't quit this loop
        printf "${warn}Discarding $name...${reset}\n\n"
        continue
    fi


    # add command
    printf "curl -k -X POST -H 'Content-Type: application/json' -H \"Authorization: Bearer \$TOKEN\" -H 'Accept: application/json' -d '{\"name\": \"$name\", \"description\": \"\", \"subType\": \"HOST\", \"value\": \"$IP\", \"isSystemDefined\": false, \"dnsResolution\": \"IPV4_ONLY\", \"type\": \"networkobject\"}' \"https://\$IP/api/fdm/latest/object/networks\"\n" >> ./fire-gen.txt
    printf "${info}Added: $name:$ip${reset}\n\n"
done

# service (port)
# Loop until finished
printf "\n${info}Create Port Objects${reset}\n"
input="placeholder"
while [[ "$input" != "" ]]
do
    name=""
    port=""
    protocol=""

    # Get name of object
    printf "Name of Port (CAPITAL LETTERS ONLY): "
    read input

    # move on if empty
    if [[ "$input" == "" ]]
    then
        break
    fi
    name=$input

    # Get port number
    printf "Port Number: "
    read input

    if [[ "$input" == "" ]]
    then
        # invalidate the name entered and try again
        input="placeholder" # set input so we don't quit this loop
        printf "${warn}No Port entered. Invalidated $name${reset}\n\n"
        continue
    fi
    port=$input

    # Get protocol
    printf "Protocol [(t)cp/(u)dp]: "
    read input

    if [[ "$input" == "" ]]
    then
        # invalidate the name entered and try again
        input="placeholder" # set input so we don't quit this loop
        printf "${warn}No Protocol entered. Invalidated $name${reset}\n\n"
        continue
    fi

    # fix shortcuts for tcp and udp
    # as well as do simple error check
    if [[ "$input" == "t" ]]; then
        protocol="tcp"
    elif [[ "$input" == "u" ]]; then
        protocol="udp"
    elif [[ "$input" == "tcp" || "$input" == "udp" ]]; then
        protocol=$input
    else
        # quit because it wasn't tcp or udp
        input="placeholder" # set input so we don't quit this loop
        printf "${warn}Unknown Protocol Entered. Invalidated $name${reset}\n\n"
        continue
    fi

    # last check before writing the rule down
    printf "${info}================================================================${reset}\n"
    printf "${info}    Name:${reset} $name\n"
    printf "${info}    Port:${reset} $port\n"
    printf "${info}Protocol:${reset} $protocol\n"
    printf "${info}================================================================${reset}\n"
    printf "Add rule?[y/n]: "
    read input

    if [[ "$input" == "N" || "$input" == "n" || "$input" == "" ]]; then
        input="n" # set input to "n" so we don't quit this loop
        printf "${warn}Discarding $name...${reset}\n\n"
        continue
    fi


    # add command
    # different based on tcp or udp
    if [[ "$protocol" == "tcp" ]]; then
        printf "curl -k -X POST -H 'Content-Type: application/json' -H \"Authorization: Bearer \$TOKEN\" -H 'Accept: application/json' -d '{\"name\": \"$name\",\"description\": null,\"isSystemDefined\": false,\"port\": \"$port\",\"type\": \"tcpportobject\"}' \"https://\$IP/api/fdm/latest/object/tcpports\"\n" >> ./fire-gen.txt
    else
        printf "curl -k -X POST -H 'Content-Type: application/json' -H \"Authorization: Bearer \$TOKEN\" -H 'Accept: application/json' -d '{\"name\": \"$name\",\"description\": null,\"isSystemDefined\": false,\"port\": \"$port\",\"type\": \"udpportobject\"}' \"https://\$IP/api/fdm/latest/object/udpports\"\n" >> ./fire-gen.txt
    fi
    printf "${info}Added: $name:$port:$protocol${reset}\n\n"
done


# Security rules
# Loop until finished
printf "\n${info}Create Security Rules${reset}\n"
input="placeholder"
while [[ "$input" != "" ]]
do
    name=""
    s_zone=""
    s_addr=""
    d_zone=""
    d_addr=""
    app=""
    s_ports=""
    d_ports=""
    action=""

    # Get name of rule
    printf "Name of rule: "
    read input

    # move on if empty
    if [[ "$input" == "" ]]
    then
        break
    fi
    name=$input

    # source zone
    printf "Source Zone [$ZONES]: "
    read input

    # see if input is in the list of zones
    contain=`contains "$input" "$ZONES"`

    # short for any
    if [[ "$input" == "a" || "$input" == "any" ]]; then
        input="any"
        contain="true"

    # normal check
    elif [[ "$input" == "" || "$contain" == "false" ]]; then
        # invalidate the name entered and try again
        input="placeholder" # set input so we don't quit this loop
        printf "${warn}Bad Zone. Invalidated $name${reset}\n\n"
        continue
    fi

    if [[ "$input" == "any" ]]; then
        s_zone=""
    else
        s_zone=$input
    fi

    # source address
    printf "Source Address: "
    read input

    # short for any
    if [[ "$input" == "a" ]]; then
        input="any"

    # normal check
    elif [[ "$input" == "" ]]
    then
        # invalidate the name entered and try again
        input="placeholder" # set input so we don't quit this loop
        printf "${warn}No Address entered. Invalidated $name${reset}\n\n"
        continue
    fi

    if [[ "$input" == "any" ]]; then
        s_addr=""
    else
        s_addr=$input
    fi


    # destination zone
    printf "Destination Zone [$ZONES]: "
    read input

    # see if input is in the list of zones
    contain=`contains "$input" "$ZONES"`

    # short for any
    if [[ "$input" == "a" || "$input" == "any" ]]; then
        input="any"
        contain="true"

    # normal check
    elif [[ "$input" == "" || "$contain" == "false" ]]
    then
        # invalidate the name entered and try again
        input="placeholder" # set input so we don't quit this loop
        printf "${warn}Bad Zone. Invalidated $name${reset}\n\n"
        continue
    fi

    if [[ "$input" == "any" ]]; then
        d_zone=""
    else
        d_zone=$input
    fi


    # destination address
    printf "Destination Address: "
    read input

    # short for any
    if [[ "$input" == "a" ]]; then
        input="any"

    # normal check
    elif [[ "$input" == "" ]]
    then
        # invalidate the name entered and try again
        input="placeholder" # set input so we don't quit this loop
        printf "${warn}No Address entered. Invalidated $name${reset}\n\n"
        continue
    fi

    if [[ "$input" == "any" ]]; then
        d_addr=""
    else
        d_addr=$input
    fi


    # application
    printf "Application: "
    read input

    # short for any
    if [[ "$input" == "a" ]]; then
        input="any"

    # normal check
    elif [[ "$input" == "" ]]
    then
        # invalidate the name entered and try again
        input="placeholder" # set input so we don't quit this loop
        printf "${warn}No Application entered. Invalidated $name${reset}\n\n"
        continue
    fi

    if [[ "$input" == "any" ]]; then
        app=""
    else
        app=$input
    fi


    # destination ports 
    printf "\nFormat for this: NAME t NAME u   (for tcp and udp)\n"
    printf "Destination Ports: "
    read input

    # short for application-default
    if [[ "$input" == "a" || "$input" == "any" ]]; then
        input="any"

    # normal check
    elif [[ "$input" == "" ]]
    then
        # invalidate the name entered and try again
        input="placeholder" # set input so we don't quit this loop
        printf "${warn}No Application entered. Invalidated $name${reset}\n\n"
        continue
    fi

    d_ports=$input
    if [[ "$input" == "any" ]]; then
        d_ports=""
    else
        d_ports=$input
    fi


    # action
    printf "Action [PERMIT DENY]: "
    read input

    # short for PERMIT
    if [[ "$input" == "P" || "$input" == "p" ]]; then
        input="PERMIT"
    fi

    # short for DENY
    if [[ "$input" == "D" || "$input" == "d" ]]; then
        input="DENY"
    fi

    # check for allow deny or drop
    if [[ "$input" != "PERMIT" && "$input" != "DENY" ]]; then
        # invalidate the name entered and try again
        input="placeholder" # set input so we don't quit this loop
        printf "${warn}Invalid Action. Invalidated $name${reset}\n\n"
        continue
    fi

    action=$input


    # last check before writing the rule down
    printf "${info}================================================================${reset}\n"
    printf "${info}            Name:${reset} $name\n"
    printf "${info}     Source Zone:${reset} $s_zone\n"
    printf "${info}     Source Addr:${reset} $s_addr\n"
    printf "${info}Destination Zone:${reset} $d_zone\n"
    printf "${info}Destination Addr:${reset} $d_addr\n"
    printf "${info}     Application:${reset} $app\n"
    printf "${info}Destination Port:${reset} $d_ports\n"
    printf "${info}          Action:${reset} $action\n"
    printf "${info}================================================================${reset}\n"
    printf "Add rule?[y/n]: "
    read input

    if [[ "$input" == "N" || "$input" == "n" || "$input" == "" ]]; then
        input="n" # set input to "n" so we don't quit this loop
        printf "${warn}Discarding $name...${reset}\n\n"
        continue
    fi

    log="LOG_BOTH"

    # format input
    temp=""
    for generic in $s_zone; do
        temp+="$generic securityzone "
    done
    s_zone=$temp

    temp=""
    for generic in $s_addr; do
        temp+="$generic networkobject "
    done
    s_addr=$temp

    temp=""
    for generic in $d_zone; do
        temp+="$generic securityzone "
    done
    d_zone=$temp

    temp=""
    for generic in $d_addr; do
        temp+="$generic networkobject "
    done
    d_addr=$temp

    temp=""
    for generic in $app; do
        temp+="$generic application "
    done
    app=$temp

    s_ports=`echo $s_ports | sed 's/t/tcpportobject/g'`
    s_ports=`echo $s_ports | sed 's/u/udpportobject/g'`

    d_ports=`echo $d_ports | sed 's/t/tcpportobject/g'`
    d_ports=`echo $d_ports | sed 's/u/udpportobject/g'`


    # add command
    s_zone=`make_json "$s_zone"`
    s_addr=`make_json "$s_addr"`
    d_zone=`make_json "$d_zone"`
    d_addr=`make_json "$d_addr"`
    if [[ "$app" != "" ]]; then
        app=`make_json "$app"`
    fi
    s_ports=`make_json "$s_ports"`
    d_ports=`make_json "$d_ports"`

    if [[ "$app" != "" ]]; then
        printf "curl -k -X POST -H 'Content-Type: application/json' -H \"Authorization: Bearer \$TOKEN\" -H 'Accept: application/json' -d '{\"name\": \"$name\",\"sourceZones\": [$s_zone],\"destinationZones\": [$d_zone],\"sourceNetworks\": [$s_addr],\"destinationNetworks\": [$d_addr],\"sourcePorts\": [$s_ports],\"destinationPorts\": [$d_ports],\"ruleAction\": \"$action\",\"eventLogAction\": \"$log\",\"embeddedAppFilter\": {\"applications\": [$app],\"type\": \"embeddedappfilter\"},\"type\": \"accessrule\"}' \"https://\$IP/api/fdm/latest/policy/accesspolicies/\$P_ID/accessrules\"\n" >> ./fire-gen.txt
    else
        printf "curl -k -X POST -H 'Content-Type: application/json' -H \"Authorization: Bearer \$TOKEN\" -H 'Accept: application/json' -d '{\"name\": \"$name\",\"sourceZones\": [$s_zone],\"destinationZones\": [$d_zone],\"sourceNetworks\": [$s_addr],\"destinationNetworks\": [$d_addr],\"sourcePorts\": [$s_ports],\"destinationPorts\": [$d_ports],\"ruleAction\": \"$action\",\"eventLogAction\": \"$log\",\"embeddedAppFilter\": null,\"type\": \"accessrule\"}' \"https://\$IP/api/fdm/latest/policy/accesspolicies/\$P_ID/accessrules\"\n" >> ./fire-gen.txt
    fi

    printf "${info}Added: $name:$action${reset}\n\n"
done

printf "${info}Finished fire-gen script${reset}\n"

exit 0
