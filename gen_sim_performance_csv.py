import json
import csv
import pandas as pd
import numpy
import os 
import collections 
import glob
import sys
from os.path import dirname, basename, isfile, join
import shutil


rootdir = os.getcwd()
results_dir = rootdir + '/gpgpusim_results'
if not os.path.exists(results_dir):
# 	shutil.rmtree(results_dir, ignore_errors=True)
    os.mkdir(results_dir)

configs = []

if (len(sys.argv) > 1):
    for i in range(1,len(sys.argv)):
	    configs.append(str(sys.argv[i]))
else:
	print "Please enter GPGPU-SIM config"
	exit()

for config in configs:

    reportspath = rootdir + '/gpgpusim_runs/' + config

    benchmarks = []
    performance_dict = collections.OrderedDict()

    for dirname in os.listdir(reportspath):
        benchmarks.append(dirname[:-16])

    for benchmark in benchmarks:
        f = open((reportspath + '/' + benchmark + '_performance' + '.log'), 'r')
        x = f.readlines()
        kernel_count = 0
        baseline = collections.OrderedDict()
        for each in range(len(x)):
            x[each] = x[each].replace(" ", "")
        for each in range(len(x)):
            if (x[each].find('kernel_name') != -1):
                kernel_count += 1
                key,value = x[each+7].split('=')
                value = value.rstrip('\n')
                baseline[(key)] = float(value)
            if (x[each].find('L2_total_cache_accesses') != -1):
                for stat in range(0,3):
                    key,value = x[each+stat].split('=')
                    value = value.rstrip('\n')
                    baseline[(key)] = float(value)
        performance_dict[benchmark] = baseline

    os.chdir(results_dir)
    df = pd.DataFrame.from_dict(performance_dict, orient='index')
    # print(df)
    cwd = 'gpgpusim_performance_' + config + '.csv'
    df.to_csv(cwd)
    os.chdir(rootdir)
