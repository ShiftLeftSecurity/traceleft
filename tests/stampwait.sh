#!/bin/bash

function stampwait {
    touch $1
    # wait until the file is removed by run.sh
    while [ -f $1 ]; do
        sleep 1
    done
}
