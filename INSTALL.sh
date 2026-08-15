#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2025 Tree Davies

UDON_DIR=/usr/bin/udon.d

PYTHON=`which python3`
if [ "$PYTHON" = "" ] ; then
	echo 'Error: python3 path no found'
	exit 1
fi
echo "[FOUND] python3 at $PYTHON"

PIP=`which pip`
if [ "$PIP" = "" ] ; then
	echo 'Error: 'pip' path no found'
	exit 1
fi
echo "[FOUND] pip at $PIP"

EID=`id -u`
if [ $EID -ne 0 ] ; then
	echo 'INSTALL.sh must be run as the root user.'
	exit 1
fi

if [ ! -e $UDON_DIR ] ; then
	mkdir $UDON_DIR
fi


install -m 755 -o root ./src/udon $UDON_DIR
if [ $? -ne 0 ] ; then
	echo "Error: install failed - src/udon"
	exit 1
fi

install -m 755 -o root ./src/udon_init.py $UDON_DIR
if [ $? -ne 0 ] ; then
	echo "Error: install failed - src/udon_init.py"
	exit 1
fi

install -m 444 -o root ./src/libudon.py $UDON_DIR
if [ $? -ne 0 ] ; then
	echo "Error: install failed - src/libudon.py"
	exit 1
fi

install -m 444 -o root ./src/udon.proto $UDON_DIR
if [ $? -ne 0 ] ; then
	echo "Error: install failed - src/udon.proto"
	exit 1
fi

install -m 755 -o root ./src/test_libudon.py $UDON_DIR
if [ $? -ne 0 ] ; then
	echo "Error: install failed src/test_libudon.py"
	exit 1
fi

ln -s $UDON_DIR/udon /usr/bin/udon

mkdir -p -m 755 $UDON_DIR/modules
mkdir -p -m 755 $UDON_DIR/modules/hello
for file in `find ./src/modules/` ; do
    install -m 555 -o root $file $UDON_DIR/modules/hello
done

# VERIFY VENV MODULE IS INSTALLED
$PYTHON -c "import venv"
if [ $? -ne 0 ] ; then
	echo "python venv module not installed"
	exit 1
fi
echo "[Found] Python module: virtualenv"

if [ ! -e "/usr/bin/udon/udon-venv" ] ; then
	$PYTHON -m venv /usr/bin/udon.d/udon-venv
	if [ $? -ne 0 ] ; then
		echo "python venv creation failed. Is the venv module installed?"
		exit 1
	fi
fi
echo "[DONE] Created: /usr/bin/udon.d/udon-venv"

# INSTALL DEPENDENCIES TO VIRTUAL ENVIRONMENT
/usr/bin/udon.d/udon-venv/bin/python3 -m pip install beautifulsoup4
/usr/bin/udon.d/udon-venv/bin/python3 -m pip install cffi
/usr/bin/udon.d/udon-venv/bin/python3 -m pip install config
/usr/bin/udon.d/udon-venv/bin/python3 -m pip install cryptography
/usr/bin/udon.d/udon-venv/bin/python3 -m pip install google
/usr/bin/udon.d/udon-venv/bin/python3 -m pip install grpcio-tools
/usr/bin/udon.d/udon-venv/bin/python3 -m pip install protobuf
/usr/bin/udon.d/udon-venv/bin/python3 -m pip install pycparser
/usr/bin/udon.d/udon-venv/bin/python3 -m pip install setuptools
/usr/bin/udon.d/udon-venv/bin/python3 -m pip install soupsieve
/usr/bin/udon.d/udon-venv/bin/python3 -m pip install python-daemon
/usr/bin/udon.d/udon-venv/bin/python3 -m pip install psutil

# BUILD PROTOS
PROTO_PATH='/usr/bin/udon.d/'
/usr/bin/udon.d/udon-venv/bin/python3 -m grpc_tools.protoc --proto_path=$PROTO_PATH udon.proto --python_out=$PROTO_PATH --grpc_python_out=$PROTO_PATH

exit 0

