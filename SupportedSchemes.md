# Introduction #

The following is a list of the cryptographic schemes currently supported by libfenc.

# Supported Cryptosystems #

**FENC\_SCHEME\_LSW**

This is a KP-ABE scheme over non-monotonic access structures.  It's based on Section 6.1 of the following paper.

Lewko, Sahai and Waters: Revocation Systems with Very Small Private Keys.
Available at: http://eprint.iacr.org/2008/309.pdf

**FENC\_SCHEME\_WATERSCP**

This is a CP-ABE scheme.  It's based on the relatively recent scheme described in Appendix C of the following paper (security assumption: parallel q-DBDHE).  The sole disadvantage of this scheme is the relatively high number of pairings that must be computed during the decryption process (2 + N) for N attributes matching in the key.

Waters: Ciphertext-Policy Attribute-Based Encryption: An Expressive, Ecient, and Provably Secure Realization.
http://eprint.iacr.org/2008/290.pdf

**FENC\_SCHEME\_WATERSSIMPLECP**

This is a variant of the CP-ABE scheme above.  It's based on the scheme in Appendix D of that paper, but employs a random oracle for efficiencly (security assumption: q-DBDHE).  Note that an early version of Waters paper described the construction with a random oracle.  This scheme has some disadvantages, for instance: keys cannot be delegated.  However, it requires only a constant number of pairings (3) to decrypt, regardless of the complexity of the policy.  This can be a huge advantage for complex policies on slow devices such as mobile phones.

Waters: Ciphertext-Policy Attribute-Based Encryption: An Expressive, Ecient, and Provably Secure Realization.
http://eprint.iacr.org/2008/290.pdf


# Schemes We Intend to Support Soon #

Lewko, Waters: Decentralizing Attribute-Based Encryption.
http://eprint.iacr.org/2010/351