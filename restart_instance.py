#!/usr/bin/env python
import requests
import urllib3
import re
import paramiko
import time
import socket
import datetime

# Disable warning output about insecure request
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def writeLogs(pathToLogFile, logString):
    with open(pathToLogFile, 'ab') as log:
        log.write(logString + "\n")



def getDC():
    # Determine name of DataCenter
    with open('/var/www/utils/pod-cfg/DC', 'r') as DCfile:
        dc = DCfile.read().rstrip()
    return dc

def getENV():
    # Determine name of DataCenter
    with open('/var/www/utils/pod-cfg/ENVR', 'r') as ENVfile:
        env = ENVfile.read().rstrip()
    return env


def getBElist(env, dc, HostsRepo):
    # Find all BE hosts of POD in _hosts file and create list "BElist"
    BElist = []
    with open(HostsRepo + env + '_admcfe_1__' + dc + '_cloud_com_by_group.cfg', 'r') as BEfile:
        pattern = env + '\-beapp\-(.*)\.' + dc + '\.cloud\.com'
        regex = re.compile(pattern)
        for line in BEfile:
            if re.match(regex, line):
                BElist.append(str(line).rstrip())
    return BElist



# Get all available parameters for INSTANCE from TMS
def getParams(inst, mma_uri, mma_user, mma_pass, pathToLogFile):
    #writeLogs(pathToLogFile, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\t" + "[" + inst + "] " + "Getting instance parameters")
    headers = {'content-type': 'application/json'}
    url = mma_uri + "/v1/parameters?instances=" + inst
    response = requests.get(url, auth=(mma_user, mma_pass), headers=headers, verify=False)
    instParams = response.json()
    return instParams


# Getting sysuser from loaded instance parameters
# to call a funtion use:  getSysUser(getParams())
def getSysUser(inst, mma_uri, mma_user, mma_pass, pathToLogFile):
    instParams = getParams(inst, mma_uri, mma_user, mma_pass, pathToLogFile)
    sysuser = (instParams[inst]["instanceParameters"]["system_username"])
    return sysuser


def getVersion(inst, mma_uri, mma_user, mma_pass, pathToLogFile):
    instParams = getParams(inst, mma_uri, mma_user, mma_pass, pathToLogFile)
    version = (instParams[inst]["instanceParameters"]["instance_version"])
    return version


# Connecting via SSH to all BE hosts from "BElist" and searching for running processes app_server and search_agent
def findBEpair(inst, mma_uri, mma_user, mma_pass, SSHuser, SSHpass, pathToLogFile, env, dc, HostsRepo):
    # Connect via SSH to all BE hosts and check processes
    writeLogs(pathToLogFile, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\t" + "[" + inst + "] " + "Looking for BE hosts, where processes are running")
    sysuser = getSysUser(inst, mma_uri, mma_user, mma_pass, pathToLogFile)
    version = getVersion(inst, mma_uri, mma_user, mma_pass, pathToLogFile)
    BElist = getBElist(env, dc, HostsRepo)
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
            ssh.connect(hostname=BEhost, username=SSHuser, password=SSHpass)
        except paramiko.ssh_exception.AuthenticationException as error:
            writeLogs(pathToLogFile, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\t" + "[" + inst + "] " + error)
            return
        except:
            writeLogs(pathToLogFile, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\t" + "[" + inst + "] " + "Connection failed to " + BEhost)
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
    return BEpair


def getProcessState(sysuser, mma_uri, mma_user, mma_pass, procName):
    headers = {'content-type': 'application/json'}
    url = mma_uri + "/v1/instances/" + sysuser + "/processes/" + procName
    response = requests.get(url, auth=(mma_user, mma_pass), headers=headers, verify=False)
    state = response.json()
    return state


def printProcState(inst, sysuser, mma_uri, mma_user, mma_pass, procName, pathToLogFile, final):
    state = getProcessState(sysuser, mma_uri, mma_user, mma_pass, procName)

    if state['available'] == 'true':
        writeLogs(pathToLogFile, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\t" + "[" + inst + "] " +  procName + "\t\tRUNNING")
        final['running_processes'][procName] = 'true'
    elif state['available'] == 'false':
        writeLogs(pathToLogFile, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\t" + "[" + inst + "] " +  procName + "\t\tDOWN")
        final['running_processes'][procName] = 'false'
    else:
        writeLogs(pathToLogFile, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\t" + "[" + inst + "] " +  procName + "\t\tUNKNOWN")
        final['running_processes'][procName] = 'unknown'
    return final


def printAllProcState(inst, sysuser, mma_uri, mma_user, mma_pass, pathToLogFile, final):
    writeLogs(pathToLogFile, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\t" + "[" + inst + "] " + "Getting processes state")
    for processName in ("app_server",  "search_agent", "app_server_secondary", "configuration_server"):
        printProcState(inst, sysuser, mma_uri, mma_user, mma_pass, processName, pathToLogFile, final)
    return


def printInstanceInfo(inst, mma_uri, mma_user, mma_pass, pathToLogFile):
    sysuser = getSysUser(inst, mma_uri, mma_user, mma_pass, pathToLogFile)
    version = getVersion(inst, mma_uri, mma_user, mma_pass, pathToLogFile)
    writeLogs(pathToLogFile, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\t" + "Instance " + inst)
    writeLogs(pathToLogFile, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\t" + "Sysuser " + sysuser)
    writeLogs(pathToLogFile, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\t" + "Version " + version)


def changeProcessState(inst, sysuser, mma_uri, mma_user, mma_pass, procName, action, pathToLogFile):
    state = getProcessState(sysuser, mma_uri, mma_user, mma_pass, procName)
    if action == "stop":
        if state['available'] == 'true':
            headers = {'content-type': 'application/json'}
            url = mma_uri + "/v1/instances/" + sysuser + "/processes/" + procName + "/actions/" + action
            response = requests.patch(url, auth=(mma_user, mma_pass), headers=headers, verify=False)
            writeLogs(pathToLogFile, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\t" + "[" + inst + "] " + procName + " has been stopped")
        elif state['available'] == 'false':
            writeLogs(pathToLogFile, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\t" + "[" + inst + "] " + procName + " is already stopped")
        else:
            writeLogs(pathToLogFile, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\t" + "[" + inst + "] " + procName + " is in unknown status")
    elif action == "start":
        if state['available'] == 'true':
            writeLogs(pathToLogFile, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\t" + "[" + inst + "] " + procName + " is already started")
        elif state['available'] == 'false':
            headers = {'content-type': 'application/json'}
            url = mma_uri + "/v1/instances/" + sysuser + "/processes/" + procName + "/actions/" + action
            response = requests.patch(url, auth=(mma_user, mma_pass), headers=headers, verify=False)
            writeLogs(pathToLogFile, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\t" + "[" + inst + "] " + procName + " has been started")
        else:
            writeLogs(pathToLogFile, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\t" + "[" + inst + "] " + procName + " is in unknown status")


# Connecting via SSH only to BEpair and performing an action
def remoteExecution(host, SSHuser, SSHpass, command, pathToLogFile):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname=host, username=SSHuser, password=SSHpass)
    except paramiko.ssh_exception.AuthenticationException as error:
        writeLogs(pathToLogFile, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\t" + "[" + sysuser + "] "  + error)
        return
    except socket.error, e:
        writeLogs(pathToLogFile, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\t" + "[" + sysuser + "] "  + "BEhost might not be determined")
        return
    except:
        writeLogs(pathToLogFile, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\t" + "[" + sysuser + "] "  + "Connection failed to " + host)
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


def restart_instance(inst, dc, env, mma_uri, mma_user, mma_pass, SSHuser, SSHpass, killmode, timeoutForRestart, pathToLogFile, HostsRepo):
    writeLogs(pathToLogFile, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\t" + "[" + inst + "] " + "Getting instance parameters")
    sysuser = getSysUser(inst, mma_uri, mma_user, mma_pass, pathToLogFile)
    version = getVersion(inst, mma_uri, mma_user, mma_pass, pathToLogFile)
    final = {
        "instance": '',
        "sysuser": '',
        "version": '',
        "killed_processes": {
            "app_server": 'false',
            "app_server_secondary": 'false',
            "search_agent": 'false',
            "configuration_server": 'false'
        },
        "pm_restarted": [],
        "running_processes": {
            "app_server": 'false',
            "app_server_secondary": 'false',
            "search_agent": 'false',
            "configuration_server": 'false'
        }
    }
    BElist = getBElist(env, dc, HostsRepo)
    final['instance'] = inst
    final['sysuser'] = sysuser
    final['version'] = version

    BEpair = findBEpair(inst, mma_uri, mma_user, mma_pass, SSHuser, SSHpass, pathToLogFile, env, dc, HostsRepo)
    printInstanceInfo(inst, mma_uri, mma_user, mma_pass, pathToLogFile)
    printAllProcState(inst, sysuser, mma_uri, mma_user, mma_pass, pathToLogFile, final)
    for pr in ("app_server", "app_server_secondary", "search_agent", "configuration_server"):
        changeProcessState(inst, sysuser, mma_uri, mma_user, mma_pass, pr, "stop", pathToLogFile)
    time.sleep(timeoutForRestart)
    printAllProcState(inst, sysuser, mma_uri, mma_user, mma_pass, pathToLogFile, final)
    BEpair = findBEpair(inst, mma_uri, mma_user, mma_pass, SSHuser, SSHpass, pathToLogFile, env, dc, HostsRepo)
    for pr in ("app_server", "app_server_secondary", "search_agent", "configuration_server"):
        if BEpair[pr]:
            writeLogs(pathToLogFile, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\t" + "[" + inst + "] " + "Killing stuck process " + pr + " with/without coredump, killmode is (" + killmode + ")")
            remoteExecution(BEpair[pr], SSHuser, SSHpass, "ps aux | grep " + sysuser + " | grep -v grep | grep '" + pr + " -F' | awk '{print $2}' | xargs sudo kill " + killmode, pathToLogFile)
            final['killed_processes'][pr] = 'true'
            time.sleep(2)
            writeLogs(pathToLogFile, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\t" + "[" + inst + "] "  + "Restarting PM on the " + BEpair[pr])
            remoteExecution(BEpair[pr], SSHuser, SSHpass, "systemctl restart ProcessMonitor.service", pathToLogFile)
            final['pm_restarted'].append(BEpair[pr])
            time.sleep(20)

    writeLogs(pathToLogFile, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\t" + "[" + inst + "] "  + "Starting instance")
    for pr in ("app_server", "app_server_secondary", "search_agent", "configuration_server"):
        changeProcessState(inst, sysuser, mma_uri, mma_user, mma_pass, pr, "start", pathToLogFile)
    time.sleep(timeoutForRestart)
    printAllProcState(inst, sysuser, mma_uri, mma_user, mma_pass, pathToLogFile, final)
    return final

