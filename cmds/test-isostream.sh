#!/bin/bash
. ./wvtest/wvtest.sh


IS=./host-isostream

WVSTART "isostream test"

# verify that isostream ends when a timeout is set.
TIMEOUT=1
WVPASS alarm $(($TIMEOUT+1)) $IS -b 1 -t $TIMEOUT 127.0.0.1
