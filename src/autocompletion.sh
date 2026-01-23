#!/bin/bash

list_available() {
	find "out/$1/" -mindepth 2 -maxdepth 6 -iname "*.json" -o -type d | \
		cut -d/ -f3- | \
		# sed -E "s/\.json//" | \
		sort -u
}
list_os() {
	list_available "os"
}
list_fw() {
	list_available "fw"
}
list_all_available() {
	list_os
	list_fw
}

_parser_completions() {
	local cur prev opts
	cur="${COMP_WORDS[COMP_CWORD]}"
	prev="${COMP_WORDS[COMP_CWORD-1]}"
	parse_option="${COMP_WORDS[0]}"
	echo "$parse_option"
	opts_empty="
cve
cpe
cpev cpe-versions
i inspect
f formatted
m minify
s search
t table
h help"
opts_inspect="
-? --help   

-A --all    
-C --critical
-H --high   
-M --medium 
-L --low    
-U --unknown

-g --gui
-t --cli
-b --lib
-ng --network-gui
-n --network
--sdv

-e --exclude
--filter
--reverse-filter
--no-ignore
--cve
-u --unify
--cbt
--any-state
"

	# When no arguments are provided, show the available options
	if [[ $COMP_CWORD -eq 1 ]]; then
		COMPREPLY=($(compgen -W "${opts_empty}" -- "$cur"))
	else
		local inspect_arg_passed=false
		for arg in "${COMP_WORDS[@]}"; do
			if [[ $arg == "i" || $arg == "inspect" ]]; then
				inspect_arg_passed=true
				break
			fi
		done
		# Generate completions based on the current word
		if [[ $inspect_arg_passed == true ]]; then
			if [[ $prev == "i" || $prev == "inspect" ]]; then
				COMPREPLY=($(compgen -W "${opts_inspect} $(list_all_available)" -- "$cur"))
			else
				COMPREPLY=($(compgen -W "$(list_all_available)" -- "$cur"))
			fi
		elif [[ $prev == "t" || $prev == "table" ]]; then
			COMPREPLY=($(compgen -W "$(list_all_available)" -- "$cur"))
		fi
	fi
}

complete -F _parser_completions parse.sh


list_docker_images() {
	docker images -a --format "{{.Repository}}:{{.Tag}}"
}
_main_completions() {
	local cur prev opts
	cur="${COMP_WORDS[COMP_CWORD]}"
	prev="${COMP_WORDS[COMP_CWORD-1]}"
	opts_empty="
-d --docker
-p --pkg
-s --strict
-y --year
-u --update
--format-only
--depth
-t --test
-k --keep-spaces
-h --help

-o --out
-f --force

--pip-only
--upgrade
--resolve"

	# When no arguments are provided, show the available options
	if [[ $COMP_CWORD -eq 1 ]]; then
		COMPREPLY=($(compgen -W "${opts_empty}" -- "$cur"))

	# Generate completions based on the current word
	elif [[ $prev == "--resolve" ]]; then
		COMPREPLY=($(compgen -f -- "$cur"))

	elif [[ $prev == "-y" || $prev == "--year" ]]; then
		COMPREPLY=($(compgen -W "$(find cvelistV5/cves/* -maxdepth 0 -type d | sed 's/cvelistV5\/cves\///')" -- "$cur"))
	elif [[ $prev == "--depth" || $prev == "-o" || $prev == "--out" || $prev == "-p" || $rev == "--pkg" ]]; then
		COMPREPLY=()
	elif [[ $prev == "-d" || $prev == "--docker" ]]; then
		COMPREPLY=($(compgen -W "os fw" -- "$cur"))
	else
		local docker_arg_passed=false
		for arg in "${COMP_WORDS[@]}"; do
			if [[ "$arg" == "-d" || "$arg" == "--docker" ]]; then
				docker_arg_passed=true
				break
			fi
		done

		if [[ $docker_arg_passed == true ]]; then
			COMPREPLY=($(compgen -W "$(list_docker_images) ${opts_empty}" -- "$cur"))
		else
			COMPREPLY=($(compgen -W "${opts_empty}" -- "$cur"))
		fi
	fi
}

complete -F _main_completions main.py

_run_completions() {
	local cur prev opts
	cur="${COMP_WORDS[COMP_CWORD]}"
	prev="${COMP_WORDS[COMP_CWORD-1]}"

	COMPREPLY=($(compgen -W "$(list_docker_images) ${opts_empty}" -- "$cur"))
}

complete -F _run_completions run.sh
complete -F _run_completions scan.sh

complete -F _run_completions analyse.sh

docker-analysed() {
	while read -r image; do
		if [ -d "$image" ]; then
			echo "$image" | sed -E 's/^out\/os\///; s/(.+)\//\1:/'
		fi
	done < <(docker images -a --format "{{.Repository}}:{{.Tag}}" | sed -E 's/:/\//; s/^/out\/os\//' | sort -u)
}

strings-version() {
	for file in "$@"; do
		if [ -f "$file" ]; then
			if [ -n "$2" ]; then
				echo -e "\x1b[35m$file:\x1b[0m"
			fi
			# echo "strings \"$file\" | grep -Eo '[\"'\''>^][0-9]+(\.[0-9]+)*[\"'\''<$]' | sort -u"
			strings "$file" | grep -Eo '[0-9]+(\.[0-9]+)*' | sort -u 
		else
			echo "Error: '$file' is not a valid file" >&2
		fi
	done
}
alias lsb='sh -c '\''ls $@ | sed -r "s/_[a-z0-9_-]+|\.dylib//g" | tr [[:upper:]] [[:lower:]] | sort -u'\'' _'

export ANDROID_PATH_RW=/sdcard/Download
export ANDROID_PATH_RWX=/data/local
