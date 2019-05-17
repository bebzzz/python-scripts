#!/usr/bin/env python
import requests
import argparse
import urllib3
import getpass
import sys
import re
import paramiko
from termcolor import colored
import time
import socket
from timeouts import *

sys.path.append('/var/www/utils/pod-cfg')
from config import *


def cleanLastLine():
    sys.stdout.write("\033[F")  # back to previous line
    sys.stdout.write("\033[K")  # clear line

# Enter your SSH pass for following operations
SSHpass = getpass.getpass("SSH password:")
cleanLastLine()

# Disable warning output about insecure request
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)



# Get and process Parameters
parser = argparse.ArgumentParser(description="Restarting selected instance and PM")
parser.add_argument('-i', '--instance', dest='inst', mvar='', required=True, type=str,  help='Instance name, for example test1234 or app1234')
inst = parser.parse_args().inst


# Determine name of DataCenter 
with open('/var/www/utils/pod-cfg/DC', 'r') as DCfile:
    dc = DCfile.read().rstrip()

# Determine name of DataCenter 
with open('/var/www/utils/pod-cfg/ENVR', 'r') as ENVfile:
    env = ENVfile.read().rstrip()

# Generate MMA_URI according to ENV and DC
if (env == 'demo'):
    mma_uri = "https://demo/manager"
elif (env == 'test'):
    mma_uri = "https://" + dc + ".cloud.com/tst"
elif (env == 'prod'):
    mma_uri = "https://" + dc + ".cloud.com/ds"



# Find all BE hosts of POD in _hosts file and create list "BElist"
BElist = []
with open('/var/www/hosts/'+env+'_cfe_'+dc+'_cloud_com_by_group.cfg', 'r') as BEfile:
    pattern = env+'\-beapp\-(.*)\.'+dc+'\.cloud\.com'
    regex = re.compile(pattern)
    for line in BEfile:
        if re.match(regex, line):
            BElist.append(str(line).rstrip())



# Get all available parameters for INSTANCE from TMS
def getParams():
    print("Getting instance parameters")
    global instParams
    headers = {'content-type': 'application/json'}
    url = mma_uri+"/v1/parameters?instances="+inst
    response = requests.get(url, auth=(mma_user, mma_pass), headers=headers, verify=False)
    instParams = response.json()
    cleanLastLine()
    return instParams


# Getting sysuser from loaded instance parameters
# to call a funtion use:  getSysUser(getParams())
def getSysUser():
    global sysuser
    sysuser = (instParams[inst]["instanceParameters"]["system_username"])
    return sysuser


def getVersion():
    global version
    version = (instParams[inst]["instanceParameters"]["instance_version"])
    return version


# Connecting via SSH to all BE hosts from "BElist" and searching for running processes app_server and search_agent
def findBEpair():
    # Connect via SSH to all BE hosts and check processes
    print("Looking for BE hosts, where processes are running")
    global BEpair
    getParams()
    sysuser = getSysUser()
    version = getVersion()
    BEpair = {"app_server" : '',
              "app_server_secondary" : '',
              "search_agent": '',
              "configuration_server": ''
             }
    find_process = "ps aux | grep " + sysuser + " |grep -v grep"
    # Checking if BEhosts are already found and skip searching if the are
    for BEhost in BElist:
        if BEpair['app_server'] and BEpair['app_server_secondary'] and BEpair['search_agent'] and BEpair['configuration_server']:
            break
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(hostname=BEhost,password=SSHpass)
        except paramiko.ssh_exception.AuthenticationException as error:
            print(error)
            return
        except:
            print("Connection failed to " + BEhost)
            return
        session = ssh.get_transport().open_session()
        session.set_combine_stderr(True)
        session.get_pty()
        session.exec_command("sudo bash -c \"" + find_process + "\"")
        stdin = session.makefile('wb', -1)
        stdout = session.makefile('rb', -1)
        stdin.write(SSHpass + '\n')
        stdin.flush()
        output = stdout.read().decode("utf-8")
        filterMainProc = re.compile('/var/www/pkg/platform-(.*)/binaries/bin/app_server/app_server -F')
        filterSlaveProc = re.compile('/var/www/pkg/platform-(.*)/binaries/bin/app_server/app_server_secondary -F')
        filterSearchProc = re.compile('/var/www/pkg/platform-(.*)/binaries/bin/search_agent/search_agent -F')
        filterConfigProc = re.compile('/var/www/pkg/platform-(.*)/binaries/bin/app_server/configuration_server -F')
        matchMasterProc = filterMainProc.search(output)
        matchSlaveProc = filterSlaveProc.search(output)
        matchSeacrhProc = filterSearchProc.search(output)
        matchConfigProc = filterConfigProc.search(output)
        if matchMasterProc:
            BEpair['app_server'] = BEhost
        if matchSlaveProc:
            BEpair['app_server_secondary'] = BEhost
        if matchSeacrhProc:
            BEpair['search_agent'] = BEhost
        if matchConfigProc:
            BEpair['configuration_server'] = BEhost
    cleanLastLine()
    return BEpair


def getProcessState(procName):
    headers = {'content-type': 'application/json'}
    url = mma_uri + "/v1/instances/" + sysuser + "/processes/" + procName
    response = requests.get(url, auth=(mma_user, mma_pass), headers=headers, verify=False)
    global state
    state = response.json()
    return state


def printProcState(procName):
    getProcessState(procName)
    if state['available'] == 'true':
        print(procName), colored("\t\tRUNNING", "green")
    elif state['available'] == 'false':
        print(procName), colored("\t\tDOWN", "red")
    else:
        print(procName), colored("\t\tUNKNOWN", "yellow")


def printAllProcState():
    print("Getting processes state")
    cleanLastLine()
    for processName in ("app_server",  "search_agent", "app_server_secondary", "configuration_server"):
        printProcState(processName)
    return


def printInstanceInfo():
    global sysuser
    global version
    getParams()
    sysuser = getSysUser()
    version = getVersion()
    print colored("Instance   ", 'yellow'), (inst)
    print colored("Sysuser   ", 'yellow'), (sysuser)
    print colored("Version   ", 'yellow'), (version + "\n")


def changeProcessState(procName, action):
    getProcessState(procName)
    if action == "stop":
        if state['available'] == 'true':
            headers = {'content-type': 'application/json'}
            url = mma_uri + "/v1/instances/" + sysuser + "/processes/" + procName + "/actions/" + action
            response = requests.patch(url, auth=(mma_user, mma_pass), headers=headers, verify=False)
            print(procName + " has been stopped")
            cleanLastLine()
        elif state['available'] == 'false':
            print(procName + " is already stopped")
            cleanLastLine()
        else:
            print(procName + " is in unknown status")
            cleanLastLine()
    elif action == "start":
        if state['available'] == 'true':
            print(procName + " is already started")
            cleanLastLine()
        elif state['available'] == 'false':
            headers = {'content-type': 'application/json'}
            url = mma_uri + "/v1/instances/" + sysuser + "/processes/" + procName + "/actions/" + action
            response = requests.patch(url, auth=(mma_user, mma_pass), headers=headers, verify=False)
            print(procName + " has been started")
            cleanLastLine()
        else:
            print(procName + " is in unknown status")
            cleanLastLine()


# Connecting via SSH only to BEpair and performing an action
def remoteExecution(host, command):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname=host, password=SSHpass)
    except paramiko.ssh_exception.AuthenticationException as error:
        print(error)
        return
    except socket.error, e:
        print("BEhost might not be determined")
        return
    except:
        print("Connection failed to " + host)
        return
    session = ssh.get_transport().open_session()
    session.set_combine_stderr(True)
    session.get_pty()
    session.exec_command("sudo bash -c \"" + command + "\"")
    stdin = session.makefile('wb', -1)
    stdout = session.makefile('rb', -1)
    stdin.write(SSHpass + '\n')
    stdin.flush()
    output = stdout.read().decode("utf-8")
    output = str(output).rsplit("\n",1)[-1]
    return output


def main():
    printInstanceInfo()
    printAllProcState()
    for pr in ("app_server", "app_server_secondary", "search_agent", "configuration_server"):
        changeProcessState(pr, "stop")
    time.sleep(timeout[inst])
    printAllProcState()
    findBEpair()
    for pr in ("app_server", "app_server_secondary", "search_agent", "configuration_server"):
        if BEpair[pr]:
            print("Killing stuck process " + pr + " with coredump")
            remoteExecution(BEpair[pr], "ps aux | grep " + sysuser + " | grep -v grep | grep '" + pr + " -F' | awk '{print $2}' | xargs sudo kill -5")
            time.sleep(2)
            cleanLastLine()
            print("Restarting PM on the " + BEpair[pr])
            remoteExecution(BEpair[pr], "systemctl restart ProcessMonitor")
            time.sleep(20)
            cleanLastLine()

    print("Starting instance")
    for pr in ("app_server", "app_server_secondary", "search_agent", "configuration_server"):
        changeProcessState(pr, "start")
    time.sleep(timeout[inst])
    printAllProcState()


#main()

def restart_instance(inst, dc, env, mma_uri, mma_user, mma_pass, SSHuser, SSHpass):


