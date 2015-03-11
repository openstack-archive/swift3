#!/bin/bash
# Copyright (c) 2015 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

PROXY_CONF=$1

if [ ! -e ${TEST_DIR} ]; then
    mkdir -p ${TEST_DIR}/etc ${TEST_DIR}/log
fi

if [ -e $PROXY_PID ]; then
    kill -HUP `cat $PROXY_PID`
    rm $PROXY_PID
else
    kill -HUP $proxy_pid
fi

if [ -e .coverage ]; then
    coverage combine
    mv .coverage .coverage.tmp
fi

_start()
{
    local name=$1; shift

    "$@" > ${TEST_DIR}/log/${name}.log 2>&1 &
    echo $! > $PROXY_PID
    local cnt
    for cnt in `seq 60`; do # wait at most 60 seconds
        grep 'Started child' ${TEST_DIR}/log/${name}.log > /dev/null
        if [ $? == 0 ]; then
            return
        fi
        sleep 1
    done

    cat ${TEST_DIR}/log/${name}.log
    echo "Cannot restart ${name}-server."
    exit 1
}

_start proxy coverage run --branch --include=../../*  --omit=./* \
    ./run_daemon.py proxy 8080 $PROXY_CONF -v
