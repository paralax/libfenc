#!/bin/bash
# Description: the purpose of this script is to demonstrate the capabilities of the ABE tools. Also, it exercises the interface and shows the user what options are available to each tool.

# Create master secret and public params of ABE system (requires 'd224.param' in same dir)
./abe-setup 

# Generate a key based on a user's attribute list. 
#(for now, requires secret and public params in same dir)
./abe-keygen -a ONE,TWO,THREE,FOUR,FIVE -o usr_priv.key

# How to encrypt
#(for now, requires public params in same dir).
./abe-enc -d "some text here" -p "((ONE and TWO) or THREE)" -o outfile 

# How to decrypt
./abe-dec -k usr_priv.key -f outfile.abe

echo "Exit code: $?"

exit 0
