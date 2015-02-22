#!/bin/sh
# cli_test.sh
# This file tests the rudimentary CLI versions of the API for Thursday's (2/12/2015) demo
#
# Run via
#     sh cli_test.sh
#

RESOURCE="/tempZone/home/rods/test1.txt"
GROUP="Hydroshare"
USER="rods"

# ensure no errors when called in correct order

./share_with_group $RESOURCE $GROUP
./unshare_with_group $RESOURCE $GROUP

./share_with_user $RESOURCE $GROUP
./unshare_with_user $RESOURCE $GROUP

./add_to_group $GROUP $USER
./remove_from_group $GROUP $USER

# ensure usage errors when bad arguments

./share_with_group
./unshare_with_group

./share_with_user
./unshare_with_user 

./add_to_group
./remove_from_group
