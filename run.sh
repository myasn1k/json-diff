#!/bin/bash

MUTEX="/tmp/json-diff-mutex-$1"

if test -f $MUTEX;
then
	exit
else
	touch $MUTEX
	docker-compose up --abort-on-container-exit
	rm $MUTEX
fi
