#! /bin/sh
#
# prepare.sh
# Copyright (C) 2021 matthew <matthew@matthew-ubuntu>
#
# Distributed under terms of the MIT license.
#
# Conversion scirpt to remove comments from PA config scirpts
# 
# Note: only handles single line comments (and it has to be the only thing on the line)

if [ ! -f "$1" -o -z "$1" ]
then
  echo "Usage: ./prepare.sh [file]"
else
  sed '/^\s*#/d' $1 > $1_prepared
fi

