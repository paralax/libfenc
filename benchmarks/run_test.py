#!/usr/bin/python

import string, sys
import os

max_attrs = 15

def gen_attributes():
    attrs = []
    for i in range(max_attrs):
	attrs.append("attr%d" % i);
    return attrs	

def gen_policies():
    attrs = gen_attributes()
    pol = []
    for i in range(1,max_attrs):
	str = attrs[0]
	for j in range(1, i+1):
	    str += " and %s" % attrs[j]
	pol.append(str)	
    return pol 

def gen_private_key():
    attrs = gen_attributes()
    cmd = "../tools/abe-keygen -a %s" % attrs[0]
    for i in range(len(attrs)):
	cmd += ",%s" % attrs[i] 
    cmd += " -o private.key"
    print cmd
    os.system(cmd)
    return None

def gen_benchmark():
    pols = gen_policies()
    for i in range(len(pols)):
	cmd = "./benchmark '%s' WCP outfile.txt" % (pols[i])   
	print cmd
	os.system(cmd)



### main ###

print "Generating Private Key..."
gen_private_key()

print "Benchmarking..."
gen_benchmark()

