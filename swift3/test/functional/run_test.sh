#!/bin/bash

cd $(readlink -f $(dirname $0))

. ./common.config

CONF_DIR=$(readlink -f ./conf)

rm -rf $TEST_DIR
mkdir -p ${TEST_DIR}/etc ${TEST_DIR}/log
mkdir -p ${TEST_DIR}/sda ${TEST_DIR}/sdb ${TEST_DIR}/sdc
mkdir -p ${TEST_DIR}/certs ${TEST_DIR}/private

# create config files
if [ "$AUTH" == 'keystone' ]; then
    MIDDLEWARE="s3token authtoken keystoneauth"
elif [ "$AUTH" == 'tempauth' ]; then
    MIDDLEWARE="tempauth"
else
    _fatal "unknown auth: $AUTH"
fi

for server in keystone proxy-server object-server container-server account-server; do
    sed -e "s#%MIDDLEWARE%#${MIDDLEWARE}#g" \
	-e "s#%USER%#`whoami`#g" \
	-e "s#%TEST_DIR%#${TEST_DIR}#g" \
	-e "s#%CONF_DIR%#${CONF_DIR}#g" \
	conf/${server}.conf.in \
	> conf/${server}.conf
done

# setup keystone
if [ "$AUTH" == 'keystone' ]; then
    . ./setup_keystone
fi


# build ring
rm -f *.builder *.ring.gz
rm -rf backups/

swift-ring-builder object.builder create 0 3 0
swift-ring-builder container.builder create 0 3 0
swift-ring-builder account.builder create 0 3 0

swift-ring-builder object.builder add z0-127.0.0.1:6000/sda 1
swift-ring-builder object.builder add z1-127.0.0.1:6000/sdb 1
swift-ring-builder object.builder add z2-127.0.0.1:6000/sdc 1
swift-ring-builder container.builder add z0-127.0.0.1:6001/sda 1
swift-ring-builder container.builder add z1-127.0.0.1:6001/sdb 1
swift-ring-builder container.builder add z2-127.0.0.1:6001/sdc 1
swift-ring-builder account.builder add z0-127.0.0.1:6002/sda 1
swift-ring-builder account.builder add z1-127.0.0.1:6002/sdb 1
swift-ring-builder account.builder add z2-127.0.0.1:6002/sdc 1

swift-ring-builder object.builder rebalance
swift-ring-builder container.builder rebalance
swift-ring-builder account.builder rebalance

cp *.ring.gz ${TEST_DIR}/etc/

# start swift servers

_start()
{
    local name=$1; shift

    echo Start ${name}-server.
    "$@" > ${TEST_DIR}/log/${name}.log 2>&1 &
    export ${name}_pid=$!

    local cnt
    for cnt in `seq 60`; do # wait at most 60 seconds
	grep 'Started child' ${TEST_DIR}/log/${name}.log > /dev/null
	if [ $? == 0 ]; then
	    return
	fi
	sleep 1
    done

    _fatal "Cannot start ${name}-server."
}

_start account ./run_daemon.py account 6002 conf/account-server.conf -v
_start container ./run_daemon.py container 6001 conf/container-server.conf -v
_start object ./run_daemon.py object 6000 conf/object-server.conf -v

coverage erase
_start proxy coverage run --branch --include=../../*  --omit=./* \
    ./run_daemon.py proxy 8080 conf/proxy-server.conf -v

# run tests
./check "$@"
rvalue=$?

# cleanup
kill -HUP $proxy_pid $account_pid $container_pid $object_pid $keystone_pid

# show report
sleep 3
coverage report
coverage html

exit $rvalue
