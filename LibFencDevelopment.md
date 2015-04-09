# Overview #

Welcome to the Functional Attribute-Based Encryption Library wiki page. This document serves as a way to track features currently in development and to discuss features being considered for the library. This page will also provide information on how to build the library for various operating systems such as Mac OS X, Linux and maybe even Windows (i.e. cygwin). In addition, a quick tutorial for how to setup and use the ABE tools.

# Table of Contents #

  1. Improvements and Bug Fixes.
  1. Tool chain.
  1. Long-Term Features.
  1. Build process.

## Improvements and Bug Fixes ##

  * Write autoconf script to cleanup build. (DONE)
  * Complete export and import of private-keys -- this includes key-policy. (DONE)
  * The way bison currently parses less than or greater than is broken somewhere, and probably better in the long run to role out our own for the sake of stability. (DONE).
  * Write a separate parser for key/ciphertext import.  Unlike the main policy parser, this must not re-organize or "clean up" the tree.  I think this will fix the CP decryption bugs. (DONE/NOT NEEDED).
  * Choose random IV for AES encryption and stick it in ciphertext (IV || C1, C2, C3, …, CN). (DONE)
  * Clean up all of the warnings --- it turns out that some of these are really errors disguised as warnings and they're causing some of our instability.
  * Clean up multiple memory leaks.
  * Slightly redesign API -- it's inconsistent in where it requires callers to do memory allocation, some of the calls are confusing.
  * Document library API. Use Doxygen utility to create HTML documents of API and man pages for ABE tools.

## Tool Chain ##

  * Key Generator -- needs key export implemented. Parse user's attributes and verify they are serialized properly to the buffer. (DONE)
  * Encryption -- policy parser needs to properly handle policies with less than and greater than operators. (DONE)
  * Decryption -- needs key import implemented. Parse user's key to make sure secret parameters are set properly. (DONE)

## Long-Term Features ##

  * Multi-authority ABE

## Build Process ##

  * Add documentation for building libpbc, libgmp, and libcrypto for different operating environments: Mac OS X, iPhone (ARM), and Linux.

...More to come!