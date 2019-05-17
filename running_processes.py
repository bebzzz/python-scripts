#!/usr/bin/python

from credentials import *
from tms_api import *
import argparse
import re


dc = get_dc_name()
env = get_env_name()
mm_user = get_mm_creds()[0]
mm_pass = get_mm_creds()[1]
mm_uri = get_mm_uri(env, dc)
core_pod_labels = get_corepods_labels(mm_uri, mm_user, mm_pass)

labels_options = []
for i in range(0, len(core_pod_labels)):
    labels_options.append(str(core_pod_labels[i]))


def script_usage():
    return "\
\nScript usage: \n\
running_processes.py --host "  + env + "-beapp-1." + dc + ".cloud.com" + " --corepodLabel " + labels_options[0] + " \n\
"

try:
    arg = sys.argv[1]
except IndexError:
    print '\nNo arguments passed.\n', script_usage(), '\nExiting...'
    sys.exit(1)

parser = argparse.ArgumentParser()
parser.add_argument('--host', dest="be_host", action="store", required=True, help="BE host like: " + env + "-beapp-1" + dc + ".cloud.com", mvar='')
parser.add_argument('--corepodLabel', dest="corepodLabel", action="store", required=True, help="Label of corePod like on of: " + str(labels_options), mvar='')

command_line_options = parser.parse_args()
be_host = command_line_options.be_host
corepodLabel = command_line_options.corepodLabel

if corepodLabel not in labels_options:
    print("unknown corepodLabel, please set one of " + str(labels_options))
    sys.exit(1)

beRegex = re.compile(env + "\-beapp\-([1-9][0-9]*)\." + dc + "\.cloud\.com$")
if not re.match(beRegex, be_host):
    print("unknown host for the POD, please set like: " + env + "-beapp-1." + dc + ".cloud.com")
    sys.exit(1)

nodes = get_BEnodes_list(mm_uri, mm_user, mm_pass, corepodLabel)

if be_host in nodes:
    procs_dict = get_processes_on_be(mm_uri, mm_user, mm_pass, corepodLabel, be_host)
    for host in procs_dict:
        print(host + ":" + procs_dict[host])
else:
    print("There is no host " + be_host + " in the POD " + corepodLabel)
