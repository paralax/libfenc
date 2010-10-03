#!/bin/bash
# Description: the purpose of this script is to demonstrate the capabilities of the ABE tools. 
# Also, it exercises the interface and shows the user what options are available to each tool.

# Bash Arguments:
# bash test.sh CP || bash test.sh KP

echo ""

if [ $# -lt 1 ]; then
        echo "You have not provided any arguments, please execute with arguments CP or KP."
        exit -1

elif [ "$1" == "CP" ]; then
	# Create master secret and public params of ABE system (requires 'd224.param' in same dir)
	echo "##################################################"
	echo "./abe-setup -m CP"
	./abe-setup -m CP

	# Generate a key based on a user's attribute list. 
	#(for now, requires secret and public params in same dir)
	echo "##################################################"
	echo "./abe-keygen -m CP -a 'ONE,TWO,THREE,FOUR,FIVE' -o usr_privCP.key"
	./abe-keygen -m CP -a 'ONE,TWO,THREE,FOUR,FIVE' -o usr_privCP.key

	# How to encrypt
	#(for now, requires public params in same dir).
	echo "##################################################"
	echo "./abe-enc -m CP -d 'some text here' -p '((ONE and TWO) or THREE)' -o outfile" 
	./abe-enc -m CP -d "some text here" -p "((ONE and TWO) or THREE)" -o outfile 

	# How to decrypt
	echo "##################################################"
	echo "./abe-dec -m CP -k usr_privCP.key -f outfile.cpabe"
	./abe-dec -m CP -k usr_privCP.key -f outfile.cpabe

	echo "Exit code: $?"

elif [ "$1" == "KP" ]; then
	# Create master secret and public params of ABE system (requires 'd224.param' in same dir)
	echo "##################################################"
	echo "./abe-setup -m KP"
	./abe-setup -m KP

	# Generate a key with a policy. 
	echo "##################################################"
	echo "./abe-keygen -m KP -p '((ONE and TWO) or THREE)' -o usr_privKP.key"
	./abe-keygen -m KP -p "((ONE and TWO) or THREE)" -o usr_privKP.key

	# How to encrypt
	echo "##################################################"
	echo "./abe-enc -m KP -d 'some text here' -a 'ONE,TWO,THREE,FOUR,FIVE' -o outfile" 
	./abe-enc -m KP -d "some text here" -a "ONE,TWO,THREE,FOUR,FIVE" -o outfile 

	# How to decrypt
	echo "##################################################"
	echo "./abe-dec -m KP -k usr_privKP.key -f outfile.kpabe"
	./abe-dec -m KP -k usr_privKP.key -f outfile.kpabe

	echo "Exit code: $?"

elif [ "$1" == "CP-complex" ]; then
	# Create master secret and public params of ABE system (requires 'd224.param' in same dir)
	echo "##################################################"
	echo "./abe-setup -m CP"
	./abe-setup -m CP

	# Generate a key based on a user's attribute list. 
	#(for now, requires secret and public params in same dir)
	echo "##################################################"
	echo "./abe-keygen -m CP -a 'ONE,TWO,THREE,FOUR,FIVE=5' -o usr_privCP.key"
	./abe-keygen -m CP -a 'ONE,TWO,THREE,FOUR,FIVE=5' -o usr_privCP.key

	# How to encrypt
	#(for now, requires public params in same dir).
	echo "##################################################"
	echo "./abe-enc -m CP -d 'some text here' -p '((ONE and FIVE < 10) or THREE)' -o outfile" 
	./abe-enc -m CP -d "some text here" -p "((ONE and FIVE < 10) or THREE)" -o outfile 

	# How to decrypt
	echo "##################################################"
	echo "./abe-dec -m CP -k usr_privCP.key -f outfile.cpabe"
	./abe-dec -m CP -k usr_privCP.key -f outfile.cpabe

	echo "Exit code: $?"

elif [ "$1" == "KP-complex" ]; then
	# Create master secret and public params of ABE system (requires 'd224.param' in same dir)
	echo "##################################################"
	echo "./abe-setup -m KP"
	./abe-setup -m KP

	# Generate a key with a policy. 
	echo "##################################################"
	echo "./abe-keygen -m KP -p '((ONE and !TWO) and THREE)' -o usr_privKP.key"
	./abe-keygen -m KP -p '((ONE and !TWO) and THREE)' -o usr_privKP.key

	# How to encrypt
	echo "##################################################"
	echo "./abe-enc -m KP -d 'some text here' -a 'ONE,!TWO,THREE,FOUR,FIVE' -o outfile" 
	./abe-enc -m KP -d "some text here" -a 'ONE,!TWO,THREE,FOUR,FIVE' -o outfile 

	# How to decrypt
	echo "##################################################"
	echo "./abe-dec -m KP -k usr_privKP.key -f outfile.kpabe"
	./abe-dec -m KP -k usr_privKP.key -f outfile.kpabe

	echo "Exit code: $?"
fi

# remove created files
rm -rf outfile.* usr_priv*.key secret.param* public.param*
exit 0
