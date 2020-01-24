set_bash_prompt(){
	echo -ne "\033]0;${PWD/#$HOME/\~} \007"
}

PROMPT_COMMAND=set_bash_prompt
case ${TERM} in
	xterm*|rxvt*|Eterm|aterm|kterm|gnome*|screen*)
PS1='\[\033[01;32m\]\u@\H\[\033[01;36m\]:\W\[\033[01;32m\]$(get_screen_name_prompt_color)\[\033[00m\]\$ '
		;;
	*)
echo "Didn't do thefuck"
		;;
esac

LS_COLORS="ex=01;33:di=01;36"

