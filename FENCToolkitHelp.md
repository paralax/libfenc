Provides commands for how to use fenc toolkit to encrypt/decrypt files

# Commands #

The following sample commands apply to the ciphertext-policy **CP-ABE scheme**:

Create master secret and public parameters

**abe-setup -m CP**

Generate key for user's attributes

**abe-keygen -m CP -a 'ONE,TWO,THREE,FOUR,FIVE' -o userCP.key**

Encrypt an input file under a given policy

**abe-enc -m CP -i filename.txt -p "((ONE and TWO) or THREE)" -o outfile**

Decrypt a file given the user's secret key

**abe-dec -m CP -k userCP.key -f outfile.cpabe**


The following sample commands apply to the key-policy **KP-ABE scheme**:

Create master secret and public parameters

**abe-setup -m KP**

Generate a key with a given policy

**abe-keygen -m KP -p "((ONE and TWO) or THREE)" -o userKP.key**

Encrypt an input file under a set of attributes

**abe-enc -m KP -i filename.txt -a "ONE,TWO,THREE,FOUR,FIVE" -o outfile**

Decrypt a file given the user's secret key

