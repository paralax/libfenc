#!/bin/bash
# Description: The purpose of this script is to demonstrate the capabilities of the ABE tools, exercise
#   the itnerface and show the user what options are available to each tool, and finally serve as a 
#   point of reference for comparison.

# Using Unix indirection so we can keep a log.

# Create master secret and public params of ABE system (requires 'd224.param' in same dir).
if [ -e 00_ABE_LOG ]
then
echo Skipping ABE Setup...
else
./abe-setup > 00_ABE_SETUP_txt
fi


# Generate a key based on a user's attribute list. (for now, requires secret and public 
#   params in same dir)
./abe-keygen -a ONE,TWO,THREE,FOUR,FIVE -o 01_user_priv.key > 00_ABE_KEYGEN_txt


# How to encrypt (for now, requires public params in same dir).
# This is an output rather than an input.
./abe-enc -d "Protect my Hello World Script" -o 01_file_txt -p "((ONE and TWO) or THREE)" > 00_ABE_KEYENC_txt


# How to decrypt with the appropriate key.
./abe-dec -k 01_user_priv.key -f 01_file_txt > 00_ABE_KEYDEC_txt


if [ -e 00_ABE_SETUP_txt ]
then
cat 00_ABE_SETUP_txt 00_ABE_KEYGEN_txt 00_ABE_KEYENC_txt 00_ABE_KEYDEC_txt > 00_ABE_LOG
rm 00_ABE_SETUP_txt 00_ABE_KEYGEN_txt 00_ABE_KEYENC_txt 00_ABE_KEYDEC_txt
else
cat 00_ABE_KEYGEN_txt 00_ABE_KEYENC_txt 00_ABE_KEYDEC_txt >> 00_ABE_LOG
rm 00_ABE_KEYGEN_txt 00_ABE_KEYENC_txt 00_ABE_KEYDEC_txt
fi