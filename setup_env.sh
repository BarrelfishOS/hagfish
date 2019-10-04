#!/bin/bash

HAGFISH=${3:-$(pwd)}
EDK2=${1:-${HAGFISH}/../edk2}
EDK2_LIBC=${2:-${EDK2}/../edk2-libc}

echo "HAGFISH: ${HAGFISH}"
echo "EDK2: ${EDK2}"
echo "EDK2_LIBC: ${EDK2_LIBC}"

export WORKSPACE=$EDK2
export PACKAGES_PATH=${EDK2_LIBC}:${HAGFISH}/..
export EDK_TOOLS_PATH=${EDK2}/BaseTools

# edksetup doesn't want any arguments
set --
. ${EDK2}/edksetup.sh

export GCC5_AARCH64_PREFIX=aarch64-linux-gnu-
