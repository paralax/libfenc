#!/usr/bin/python

import string, sys
import os

max_attrs = 100

def gen_attributes():
    attrs = []
    for i in range(1 , max_attrs+1):
	    attrs.append("attr%d" % i);
    return attrs	

def gen_policies():
    attrs = gen_attributes()
    pol = [attrs[0]]
    for i in range(1,max_attrs):
	    str = attrs[0]
	    for j in range(1, i+1):
	        str += " and %s" % attrs[j]
	    pol.append(str)	
    return pol 

def gen_private_key(mode):
    attrs = gen_attributes()
    cmd = "../tools/abe-keygen -m %s -a %s" % (mode, attrs[0])
    for i in range(len(attrs)):
        cmd += ",%s" % attrs[i] 
    cmd += " -o private-%s.key" % (mode.lower())
    print cmd
    os.system(cmd)
    return None

def gen_benchmark(pol_num, scheme, result):
    pols = gen_policies()
    if pol_num < 0:
       for i in range(len(pols)):
	       cmd = "./benchmark '%s' %s %s" % (pols[i],scheme,result)   
	       print cmd
	       os.system(cmd)
    else:
        cmd = "./benchmark '%s' %s %s" % (pols[pol_num], scheme, result)
        print cmd
        os.system(cmd)

def input_data(filename):
    f = open(filename, 'r')
    text = f.read()
    # print "Debug: %s" % text
    f.close()
    return text.split('\n')

def output_data(str, filename):
    f = open(filename, 'a')
    f.write(str)
    f.close()
    return None

def summarize(num_leaves, scheme, input):
    sum = 0.0
    total = 0 
    avg = 0.0
    ms = 1000 # convert to milliseconds here?
    length = len(input)
    for i in range(length):
        ans = input[i].split(':')
        if ans[0] == scheme:
            print "%s => Leaves: %s Time: %s" % (scheme, ans[1], ans[2])
            if num_leaves == int(ans[1]):
               sum += float(ans[2]) # record the time
               total += 1
    result = ""
    if sum > 0.0:
        avg = float(sum / total)
        result = "%s %s\n" % (num_leaves, avg * ms)
    return result

### main ###
# option: "KP", "CP", "SCP"
mode = [ "CP", "SCP" ]
result = [ "outfile_cp.txt", "outfile_scp.txt" ]
final = [ "msmt_cp.dat", "msmt_scp.dat" ]

#input = input_data(result[0])
#output_cp = summarize(3, mode[0], input)
#output_scp = summarize(3, mode[1], input)
#print "CP => %s" % output_cp
#print "SCP => %s" % output_scp

#exit(0)
#print "Generating Private Key..."
#gen_private_key(mode[0])
#gen_private_key(mode[1])

print "Benchmarking..."
trial = 5
num_pol = max_attrs

#gen_benchmark(mode[0], result[0])
#gen_benchmark(mode[1], result[1])
# For each policy (from 1 to 100)
for i in range(num_pol):
    # Run the benchmark for each policy "trial" times
    for j in range(trial):
        gen_benchmark(i, mode[0], result[0])
        gen_benchmark(i, mode[1], result[1])
        
input_cp = input_data(result[0])
input_scp = input_data(result[1])
for i in range(num_pol):
    output_cp =  summarize(i, mode[0], input_cp)
    output_scp = summarize(i, mode[1], input_scp)
    output_data(output_cp, final[0])
    output_data(output_scp, final[1])
    
