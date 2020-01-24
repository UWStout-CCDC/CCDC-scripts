#!/bin/bash

function get_screen_name_prompt() {
	if [ -n $STY ]; then
		printf " (%s:%s)" $WINDOW "$(screen -ls | grep -P -o "\t\d+\.\K.+(?=\t\(Attached\))")"
	fi
}
function get_screen_name_prompt_color() {
	if [[ $STY != "" ]]; then
		printf " (%b%s:%s%b)" "\001\033[36m\002" $WINDOW $(screen -p $WINDOW -Q title) "\001\033[0m\002"
	fi
}
