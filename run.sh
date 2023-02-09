#!/bin/bash

MUTEX="/tmp/json-diff-mutex-$3"

if test -f $MUTEX;
then
	exit
else
	touch $MUTEX
	/usr/bin/python3 ./json-diff.py $1 $2
	rm $MUTEX
fi
