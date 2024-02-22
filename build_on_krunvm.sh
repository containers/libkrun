#!/bin/sh

# This is a helper script for building init/init (a Linux ELF binary) in
# a lightweight VM using krunvm.

KRUNVM=`which krunvm`
if [ -z "$KRUNVM" ]; then
	echo "Couldn't find krunvm binary"
	exit -1
fi

SCRIPTPATH=`realpath $0`
WORKDIR=`dirname $SCRIPTPATH`
krunvm create fedora --name libkrun-builder -v $WORKDIR:/work -w /work
if [ $? != 0 ]; then
	echo "Error creating lightweight VM"
	exit -1
fi

krunvm start libkrun-builder /usr/bin/dnf -- install -y glibc-static gcc make
if [ $? != 0 ]; then
    krunvm delete libkrun-builder
	echo "Error running command on VM"
	exit -1
fi

krunvm start libkrun-builder /usr/bin/make -- init/init
if [ $? != 0 ]; then
    krunvm delete libkrun-builder
	echo "Error running command on VM"
	exit -1
fi

krunvm delete libkrun-builder

if [ ! -e "init/init" ]; then
	echo "There was a problem building init/init in the VM"
	exit -1
fi

exit 0
