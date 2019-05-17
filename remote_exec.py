from find_be_hosts import *
import paramiko

#   to call:   find_be_pair("test1331", "dc2", "test", SSHuser, SSHpass)
#   returns a dictionary like this:
#   {
#       'configuration_server': 'beapp-4',
#       'app_server_secondary': 'beapp-4',
#       'search_agent': 'beapp-4',
#       'app_server': 'beapp-3'
#   }
# Connecting via SSH to all BE hosts from "BElist" and searching for running processes app_server, search_agent, app_server_slave and configuration_server
def find_be_pair(sysuser, dc, env, SSHuser, SSHpass):
    # Connect via SSH to all BE hosts and check processes
    print("Looking for BE hosts, where processes are running")
    BEpair = {"app_server" : '',
              "app_server_secondary" : '',
              "search_agent": '',
              "configuration_server": ''
             }
    BElist = find_be_hosts(dc, env)
    find_process = "ps aux | grep " + sysuser + " |grep -v grep"
    # Checking if BEhosts are already found and skip searching if the are
    for BEhost in BElist:
        if BEpair['app_server'] and BEpair['app_server_secondary'] and BEpair['search_agent'] and BEpair['configuration_server']:
            break
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(hostname=BEhost, username=SSHuser ,password=SSHpass)
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
    return BEpair




# to call : remote_sudo_execution("beapp-1", SSHuser, SSHpass, "mkdir ~/test")
# returnt nothing,  just executes remote comman
# Connecting via SSH only to BEpair and performing an action
def remote_sudo_execution(host, SSHuser, SSHpass, command):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname=host, username=SSHuser, password=SSHpass)
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

